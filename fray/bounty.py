#!/usr/bin/env python3
"""
Fray Bounty — Bug Bounty Platform Integration

Usage:
    fray bounty --platform hackerone --program <handle>
    fray bounty --platform bugcrowd --program <handle>
    fray bounty --urls urls.txt
    fray bounty --program <handle> --categories xss,sqli --max 20

Integrates with HackerOne and Bugcrowd to:
    1. Fetch public program scope (in-scope URLs/domains) — NO API KEY NEEDED
    2. Auto-detect WAF on each target
    3. Run payload tests across scope
    4. Generate consolidated bounty report

HackerOne: Uses public GraphQL API (no auth for public programs)
Bugcrowd: Uses public program page API (no auth for public programs)

Zero external dependencies — stdlib only.
"""

import http.client
import json
import os
import re
import ssl
import sys
import base64
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── API Clients (stdlib only) ────────────────────────────────────────────────

# GraphQL query for HackerOne public program scope
_H1_SCOPE_QUERY = """query PolicySearchStructuredScopesQuery($handle: String!) {
  team(handle: $handle) {
    id
    name
    structured_scopes(first: 100, archived: false) {
      edges {
        node {
          asset_type
          asset_identifier
          eligible_for_submission
          eligible_for_bounty
          instruction
        }
      }
    }
  }
}"""


class HackerOnePublic:
    """Fetch public HackerOne program scope via GraphQL — NO API KEY NEEDED."""

    HOST = "hackerone.com"

    def _request(self, body: bytes) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.HOST, 443, context=ctx, timeout=30)
        conn.request("POST", "/graphql", body=body, headers={
            "Content-Type": "application/json",
            "User-Agent": f"Fray/{__version__}",
        })
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope assets for a public HackerOne program."""
        body = json.dumps({
            "operationName": "PolicySearchStructuredScopesQuery",
            "variables": {"handle": handle},
            "query": _H1_SCOPE_QUERY,
        }).encode("utf-8")

        status, data = self._request(body)

        if status != 200:
            return False, [{"error": f"HTTP {status}"}]

        team = data.get("data", {}).get("team")
        if not team:
            errors = data.get("errors", [])
            msg = errors[0].get("message", "Program not found") if errors else "Program not found"
            return False, [{"error": msg}]

        scopes = []
        edges = team.get("structured_scopes", {}).get("edges", [])

        for edge in edges:
            node = edge.get("node", {})
            if not node.get("eligible_for_submission", False):
                continue
            asset_type = node.get("asset_type", "")
            identifier = node.get("asset_identifier", "")
            instruction = node.get("instruction", "")
            bounty = node.get("eligible_for_bounty", False)
            scopes.append({
                "type": asset_type,
                "identifier": identifier,
                "bounty": bounty,
                "instruction": (instruction or "")[:200],
                "eligible": True,
            })

        return True, scopes


class BugcrowdPublic:
    """Fetch public Bugcrowd program scope — NO API KEY NEEDED."""

    HOST = "bugcrowd.com"

    def _request(self, path: str) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.HOST, 443, context=ctx, timeout=30)
        conn.request("GET", path, headers={
            "Accept": "application/json",
            "User-Agent": f"Fray/{__version__}",
        })
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope targets for a public Bugcrowd program."""
        path = f"/{handle}.json"
        status, data = self._request(path)

        if status != 200:
            return False, [{"error": f"Program '{handle}' not found (HTTP {status})"}]

        scopes = []
        target_groups = data.get("target_groups", [])
        if not target_groups:
            # Try alternate structure
            targets = data.get("targets", data.get("scope", []))
            if isinstance(targets, list):
                for t in targets:
                    name = t.get("name", t.get("uri", ""))
                    category = t.get("category", t.get("type", ""))
                    if name:
                        scopes.append({
                            "type": category.upper() if category else "URL",
                            "identifier": name,
                            "bounty": True,
                            "instruction": "",
                            "eligible": True,
                        })
            return bool(scopes), scopes

        for group in target_groups:
            targets = group.get("targets", [])
            for target in targets:
                name = target.get("name", "")
                uri = target.get("uri", "")
                category = target.get("category", "")
                if category.lower() in ("website", "api", "domain", "url", ""):
                    scopes.append({
                        "type": category.upper() or "URL",
                        "identifier": uri or name,
                        "bounty": True,
                        "instruction": "",
                        "eligible": True,
                    })

        return bool(scopes), scopes


# ── Scope Analysis ────────────────────────────────────────────────────────────

# What Fray can do per asset type
_ASSET_CAPABILITY = {
    # FULL: Fray can WAF-detect + payload-test
    "URL": {
        "level": "full",
        "label": "Web URL",
        "help": "WAF detection + payload testing (XSS, SQLi, SSTI, etc.)",
    },
    "DOMAIN": {
        "level": "full",
        "label": "Domain",
        "help": "WAF detection + payload testing",
    },
    "WILDCARD": {
        "level": "partial",
        "label": "Wildcard Domain",
        "help": "WAF detection + payload testing on root domain. Subdomain enum not included — use tools like subfinder/amass first",
    },
    # PARTIAL: Fray can help with some aspects
    "CIDR": {
        "level": "partial",
        "label": "IP Range (CIDR)",
        "help": "Fray can test individual IPs if they serve HTTP. Use nmap/masscan to find web services first",
    },
    "OTHER": {
        "level": "partial",
        "label": "Other Asset",
        "help": "May contain web URLs — check instructions. Fray can test any HTTP endpoint",
    },
    "SMART_CONTRACT": {
        "level": "partial",
        "label": "Smart Contract",
        "help": "If the contract has a web frontend, Fray can test WAF on it. Contract audit requires Slither/Mythril",
    },
    # NONE: Fray cannot help
    "APPLE_STORE_APP_ID": {
        "level": "none",
        "label": "iOS App",
        "help": "Mobile app testing — use Burp Suite/Frida for API interception, then feed endpoints to Fray",
    },
    "GOOGLE_PLAY_APP_ID": {
        "level": "none",
        "label": "Android App",
        "help": "Mobile app testing — use Burp Suite/Frida for API interception, then feed endpoints to Fray",
    },
    "DOWNLOADABLE_EXECUTABLES": {
        "level": "none",
        "label": "Desktop App",
        "help": "Binary analysis — use Ghidra/IDA for reverse engineering, intercept HTTP traffic with mitmproxy",
    },
    "SOURCE_CODE": {
        "level": "none",
        "label": "Source Code",
        "help": "Code review — use Semgrep/CodeQL for SAST. If repo has a web app, deploy locally and test with Fray",
    },
    "HARDWARE": {
        "level": "none",
        "label": "Hardware/Appliance",
        "help": "Requires physical/network access. If it has a web admin panel, Fray can test that endpoint",
    },
    "WINDOWS_APP_STORE_APP_ID": {
        "level": "none",
        "label": "Windows Store App",
        "help": "Desktop app testing — intercept HTTP traffic with Burp/mitmproxy, then feed endpoints to Fray",
    },
}


def analyze_scope(scopes: List[Dict], program_handle: str = "") -> Dict:
    """Analyze scope entries and classify by Fray capability.

    Returns a dict with 'full', 'partial', 'none' lists and summary stats.
    """
    analysis = {
        "full": [],      # Fray can fully test
        "partial": [],   # Fray can partially help
        "none": [],      # Outside Fray's capabilities
        "total": len(scopes),
        "testable_count": 0,
    }

    for scope in scopes:
        asset_type = scope.get("type", "OTHER")
        identifier = scope.get("identifier", "")
        bounty = scope.get("bounty", False)
        instruction = scope.get("instruction", "")

        cap = _ASSET_CAPABILITY.get(asset_type, _ASSET_CAPABILITY["OTHER"])
        level = cap["level"]

        # For web-testable types, check domain safety
        safe = True
        safety_note = ""
        if level in ("full", "partial") and asset_type in ("URL", "DOMAIN", "WILDCARD"):
            # Normalize to URL for safety check
            test_id = identifier
            if test_id.startswith("*."):
                test_id = test_id[2:]
            if not test_id.startswith(("http://", "https://")):
                test_id = f"https://{test_id}"
            safe, reason = is_safe_target(test_id, program_handle)
            if not safe:
                safety_note = f" [SHARED: {reason}]"

        # Check for special instructions
        notes = []
        if instruction:
            inst_lower = instruction.lower()
            if "vpn" in inst_lower:
                notes.append("VPN required")
            if "user-agent" in inst_lower:
                notes.append("Custom User-Agent required")
            if any(w in inst_lower for w in ("test account", "credentials", "password")):
                notes.append("Test credentials provided")
            if any(w in inst_lower for w in ("fake id", "cnp", "rijksregister")):
                notes.append("Fake ID/registration needed")

        entry = {
            "type": asset_type,
            "identifier": identifier,
            "bounty": bounty,
            "level": level,
            "label": cap["label"],
            "help": cap["help"],
            "safe": safe,
            "safety_note": safety_note,
            "notes": notes,
            "instruction": instruction,
        }

        analysis[level].append(entry)

    analysis["testable_count"] = len(analysis["full"]) + len(analysis["partial"])
    return analysis


def print_scope_analysis(analysis: Dict, program: str):
    """Print formatted scope analysis report."""
    total = analysis["total"]
    full = analysis["full"]
    partial = analysis["partial"]
    none_list = analysis["none"]

    print(f"\n  {Colors.BOLD}Scope Analysis for {program}{Colors.END}")
    print(f"  {Colors.DIM}{'─' * 60}{Colors.END}")
    print(f"  Total scope entries: {total}")
    print(f"  {Colors.GREEN}Full support:    {len(full):>3}{Colors.END}  (WAF detect + payload test)")
    print(f"  {Colors.YELLOW}Partial support: {len(partial):>3}{Colors.END}  (Fray can help with parts)")
    print(f"  {Colors.DIM}Not supported:   {len(none_list):>3}{Colors.END}  (outside Fray's scope)")

    # Full support
    if full:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}✓ Full Fray Support{Colors.END}")
        for e in full:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            safe_tag = "" if e["safe"] else f" {Colors.RED}⚠ SHARED{Colors.END}"
            notes_str = f" {Colors.DIM}({', '.join(e['notes'])}){Colors.END}" if e["notes"] else ""
            print(f"    {bounty_tag}{Colors.END} {e['type']:<10} {e['identifier']}{safe_tag}{notes_str}")

    # Partial support
    if partial:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}◐ Partial Fray Support{Colors.END}")
        for e in partial:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            safe_tag = "" if e["safe"] else f" {Colors.RED}⚠ SHARED{Colors.END}"
            notes_str = f" {Colors.DIM}({', '.join(e['notes'])}){Colors.END}" if e["notes"] else ""
            print(f"    {bounty_tag}{Colors.END} {e['label']:<20} {e['identifier']}")
            print(f"       {Colors.DIM}→ {e['help']}{Colors.END}{safe_tag}{notes_str}")

    # Not supported
    if none_list:
        print(f"\n  {Colors.DIM}{Colors.BOLD}✗ Outside Fray's Scope{Colors.END}")
        for e in none_list:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            print(f"    {bounty_tag}{Colors.END} {e['label']:<20} {e['identifier']}")
            print(f"       {Colors.DIM}→ {e['help']}{Colors.END}")

    # Actionable summary
    safe_full = [e for e in full if e["safe"]]
    safe_partial = [e for e in partial if e["safe"] and e["type"] in ("WILDCARD", "OTHER")]
    testable = len(safe_full) + len(safe_partial)

    print(f"\n  {Colors.DIM}{'─' * 60}{Colors.END}")
    print(f"  {Colors.BOLD}Ready to test: {testable} target(s){Colors.END}")
    if none_list:
        print(f"  {Colors.DIM}Tip: For mobile apps, intercept API traffic with Burp Suite,")
        print(f"  then feed the API endpoints to: fray bounty --urls api_endpoints.txt{Colors.END}")
    print()


# ── Domain Safety & Ownership Validation ─────────────────────────────────────

# Shared platforms: domains owned by major providers, NOT the bounty program.
# Attacking these means attacking the provider, not the target company.
SHARED_PLATFORMS = {
    # Code hosting
    "github.com", "github.io", "githubusercontent.com", "gitlab.com",
    "bitbucket.org", "bitbucket.io",
    # Cloud providers
    "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "s3.amazonaws.com", "execute-api.amazonaws.com",
    "azurewebsites.net", "azure.com", "blob.core.windows.net",
    "cloudapp.azure.com", "trafficmanager.net",
    "googleapis.com", "appspot.com", "firebaseapp.com",
    "cloudfunctions.net", "run.app", "web.app",
    # CDN / Hosting
    "cloudflare.com", "workers.dev", "pages.dev",
    "herokuapp.com", "herokucdn.com",
    "vercel.app", "netlify.app", "netlify.com",
    "surge.sh", "now.sh", "render.com",
    # SaaS / Third-party
    "zendesk.com", "freshdesk.com", "intercom.io",
    "salesforce.com", "force.com",
    "hubspot.com", "marketo.com", "mailchimp.com",
    "google.com", "youtube.com", "goo.gl",
    "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "t.co",
    "linkedin.com", "apple.com",
    # Documentation / Wiki
    "readthedocs.io", "gitbook.io", "notion.so",
    "confluence.atlassian.net", "atlassian.net",
    "jira.com", "trello.com",
    # Container / Registry
    "docker.io", "docker.com", "gcr.io", "quay.io",
    # Package registries
    "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org",
    "crates.io", "nuget.org", "packagist.org",
    # Other shared infra
    "slack.com", "zoom.us", "teams.microsoft.com",
    "wordpress.com", "wpengine.com", "shopify.com",
}

# Programs that OWN these domains (handle → set of domains they actually own)
# github program owns github.com, shopify owns shopify.com, etc.
_PROGRAM_OWNED_OVERRIDES: Dict[str, set] = {
    "github": {"github.com", "github.io", "githubusercontent.com", "github.net",
               "githubapp.com", "npmjs.com", "npmjs.org"},
    "shopify": {"shopify.com", "shopifycs.com", "shopify.io", "shopifykloud.com"},
    "gitlab": {"gitlab.com", "gitlab.net", "gitlab.org"},
    "slack": {"slack.com", "slackb.com", "slack-edge.com", "slack-imgs.com",
              "slack-files.com", "slack-core.com", "slack-redir.net"},
    "automattic": {"wordpress.com", "tumblr.com", "gravatar.com"},
    "cloudflare": {"cloudflare.com", "workers.dev", "pages.dev"},
    "google": {"google.com", "googleapis.com", "youtube.com"},
}


def is_safe_target(url: str, program_handle: str = "") -> Tuple[bool, str]:
    """Check if a URL is safe to test (not shared infrastructure).

    Returns (is_safe, reason).
    """
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "invalid URL"

    # Check program-owned overrides first
    program_owned = _PROGRAM_OWNED_OVERRIDES.get(program_handle.lower(), set())
    for owned_domain in program_owned:
        if hostname == owned_domain or hostname.endswith("." + owned_domain):
            return True, "program-owned domain"

    # Check against shared platforms
    for shared in SHARED_PLATFORMS:
        if hostname == shared or hostname.endswith("." + shared):
            return False, f"shared platform ({shared})"

    return True, "ok"


def filter_safe_targets(urls: List[str], program_handle: str = "") -> Tuple[List[str], List[Dict]]:
    """Filter URLs to only safe-to-test targets.

    Returns (safe_urls, skipped_entries).
    """
    safe = []
    skipped = []
    for url in urls:
        ok, reason = is_safe_target(url, program_handle)
        if ok:
            safe.append(url)
        else:
            skipped.append({"url": url, "reason": reason})
    return safe, skipped


def normalize_scope_to_urls(scopes: List[Dict]) -> List[str]:
    """Convert scope entries to testable URLs."""
    _WEB_TYPES = {"URL", "DOMAIN", "WILDCARD"}
    urls = []
    for scope in scopes:
        # Skip non-web asset types
        if scope.get("type", "") not in _WEB_TYPES:
            continue

        identifier = scope.get("identifier", "").strip()
        if not identifier:
            continue

        # Skip wildcard-only entries
        if identifier in ("*", "*."):
            continue

        # Handle wildcard domains: *.example.com → https://example.com
        if identifier.startswith("*."):
            identifier = identifier[2:]

        # Add scheme if missing
        if not identifier.startswith(("http://", "https://")):
            identifier = f"https://{identifier}"

        # Clean up trailing paths
        parsed = urllib.parse.urlparse(identifier)
        if parsed.hostname:
            url = f"{parsed.scheme}://{parsed.hostname}"
            if parsed.port and parsed.port not in (80, 443):
                url += f":{parsed.port}"
            urls.append(url)

    return sorted(set(urls))


def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from a text file (one per line)."""
    urls = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith(("http://", "https://")):
                        line = f"https://{line}"
                    urls.append(line)
    except (FileNotFoundError, OSError) as e:
        print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.END}")
    return urls


# ── Bounty Testing ───────────────────────────────────────────────────────────

def scan_target(url: str, categories: List[str], max_payloads: int = 10,
                timeout: int = 8, delay: float = 0.5) -> Dict:
    """Run WAF detection and payload tests on a single target."""
    result = {
        "url": url,
        "waf": None,
        "waf_confidence": 0,
        "categories": {},
        "total_tested": 0,
        "total_blocked": 0,
        "total_passed": 0,
        "block_rate": 0.0,
    }

    # WAF detection
    try:
        from fray.detector import WAFDetector
        detector = WAFDetector()
        detection = detector.detect_waf(url)
        result["waf"] = detection.get("waf", "None")
        result["waf_confidence"] = detection.get("confidence", 0)
    except Exception as e:
        result["waf"] = f"Error: {e}"

    # Payload tests per category
    from fray.tester import WAFTester
    for cat in categories:
        cat_dir = PAYLOADS_DIR / cat
        if not cat_dir.exists():
            continue

        tester = WAFTester(target=url, timeout=timeout, delay=delay)
        all_payloads = []
        for pf in sorted(cat_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))

        if not all_payloads:
            continue

        results = tester.test_payloads(all_payloads, max_payloads=max_payloads)
        blocked = sum(1 for r in results if r.get("blocked"))
        passed = len(results) - blocked
        rate = (blocked / len(results) * 100) if results else 0.0

        bypassed = [
            {"payload": r.get("payload", "")[:80], "status": r.get("status_code", 0)}
            for r in results if not r.get("blocked")
        ]

        result["categories"][cat] = {
            "total": len(results),
            "blocked": blocked,
            "passed": passed,
            "block_rate": round(rate, 1),
            "bypassed": bypassed,
        }
        result["total_tested"] += len(results)
        result["total_blocked"] += blocked
        result["total_passed"] += passed

    if result["total_tested"] > 0:
        result["block_rate"] = round(result["total_blocked"] / result["total_tested"] * 100, 1)

    return result


# ── Report ───────────────────────────────────────────────────────────────────

def print_bounty_report(targets: List[Dict], program: str, platform: str):
    """Print formatted bounty test report."""
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}")
    print(f"\n  {Colors.BOLD}Fray Bug Bounty Report{Colors.END}")
    print(f"  {Colors.DIM}Program: {program} ({platform}){Colors.END}")
    print(f"  {Colors.DIM}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{Colors.END}")
    print(f"  {Colors.DIM}Fray v{__version__}{Colors.END}")

    # Per-target summary
    print(f"\n  {Colors.BOLD}Target Results{Colors.END}")
    print(f"  {'Target':<35} {'WAF':<16} {'Block Rate':>10} {'Bypassed':>10}")
    print(f"  {'─' * 71}")

    total_bypassed = 0
    interesting_targets = []

    for t in targets:
        waf = t.get("waf", "None") or "None"
        rate = t.get("block_rate", 0.0)
        passed = t.get("total_passed", 0)
        total_bypassed += passed

        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        url_short = t["url"][:33] + ".." if len(t["url"]) > 35 else t["url"]
        waf_short = waf[:14] + ".." if len(waf) > 16 else waf

        print(f"  {url_short:<35} {waf_short:<16} {rc}{rate:>9.1f}%{Colors.END} {passed:>10}")

        if passed > 0:
            interesting_targets.append(t)

    # Bypass details
    if interesting_targets:
        print(f"\n  {Colors.RED}{Colors.BOLD}Potential Findings{Colors.END}")
        for t in interesting_targets:
            print(f"\n  {Colors.CYAN}{t['url']}{Colors.END} — {t.get('waf', 'Unknown')} WAF")
            for cat, cr in t.get("categories", {}).items():
                if cr.get("passed", 0) > 0:
                    print(f"    {Colors.RED}{cat}:{Colors.END} {cr['passed']} bypass(es)")
                    for bp in cr.get("bypassed", [])[:3]:
                        print(f"      Status {bp.get('status', '?')}: {bp.get('payload', '')[:60]}")

    # Summary
    total_tested = sum(t.get("total_tested", 0) for t in targets)
    total_blocked = sum(t.get("total_blocked", 0) for t in targets)
    overall_rate = (total_blocked / total_tested * 100) if total_tested > 0 else 0

    print(f"\n  {Colors.DIM}{'─' * 65}{Colors.END}")
    print(f"  {Colors.BOLD}Summary{Colors.END}")
    print(f"  Targets scanned:  {len(targets)}")
    print(f"  Payloads tested:  {total_tested}")
    print(f"  Overall block:    {overall_rate:.1f}%")
    print(f"  Total bypasses:   {Colors.RED if total_bypassed > 0 else Colors.GREEN}"
          f"{total_bypassed}{Colors.END}")
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}\n")


# ── Entry Point ──────────────────────────────────────────────────────────────

def run_bounty(
    platform: Optional[str] = None,
    program: Optional[str] = None,
    urls_file: Optional[str] = None,
    categories: Optional[List[str]] = None,
    max_payloads: int = 10,
    timeout: int = 8,
    delay: float = 0.5,
    output: Optional[str] = None,
    scope_only: bool = False,
    force: bool = False,
):
    """Main entry point for fray bounty."""
    print(f"\n{Colors.BOLD}Fray Bounty v{__version__}{Colors.END}")
    print(f"{Colors.DIM}{'━' * 60}{Colors.END}")

    test_categories = categories or ["xss", "sqli"]
    # Filter to existing categories
    available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    test_categories = [c for c in test_categories if c in available]

    urls: List[str] = []

    # ── Fetch scope from platform ────────────────────────────────────────
    if urls_file:
        print(f"  Loading URLs from: {urls_file}")
        urls = load_urls_from_file(urls_file)
        platform = platform or "file"
        program = program or urls_file

    elif platform and program:
        platform = platform.lower()
        # Normalize platform aliases
        if platform in ("h1", "hackerone", "hacker-one"):
            platform = "hackerone"
        elif platform in ("bc", "bugcrowd", "bug-crowd"):
            platform = "bugcrowd"

        print(f"  Platform: {platform}")
        print(f"  Program:  {program}")

        if platform == "hackerone":
            print(f"{Colors.DIM}  Fetching public scope from HackerOne...{Colors.END}")
            api = HackerOnePublic()
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                print(f"  {Colors.DIM}Make sure '{program}' is a valid public program handle.{Colors.END}")
                print(f"  {Colors.DIM}Find programs at: https://hackerone.com/directory{Colors.END}\n")
                return

            # Analyze full scope first
            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")

        elif platform == "bugcrowd":
            print(f"{Colors.DIM}  Fetching public scope from Bugcrowd...{Colors.END}")
            api = BugcrowdPublic()
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                print(f"  {Colors.DIM}Make sure '{program}' is a valid public program handle.{Colors.END}")
                print(f"  {Colors.DIM}Find programs at: https://bugcrowd.com/programs{Colors.END}\n")
                return

            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")

        else:
            print(f"  {Colors.RED}Unknown platform: {platform}{Colors.END}")
            print(f"  {Colors.DIM}Supported: hackerone (h1), bugcrowd (bc){Colors.END}")
            return

    elif program:
        # Auto-detect: try HackerOne first, then Bugcrowd
        print(f"  Program: {program}")
        print(f"{Colors.DIM}  Auto-detecting platform...{Colors.END}")

        api = HackerOnePublic()
        ok, scopes = api.get_program_scope(program)
        if ok and scopes:
            platform = "hackerone"
            print(f"  {Colors.GREEN}Found on HackerOne!{Colors.END}")

            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")
        else:
            api_bc = BugcrowdPublic()
            ok, scopes = api_bc.get_program_scope(program)
            if ok and scopes:
                platform = "bugcrowd"
                print(f"  {Colors.GREEN}Found on Bugcrowd!{Colors.END}")

                analysis = analyze_scope(scopes, program)
                print_scope_analysis(analysis, program)

                urls = normalize_scope_to_urls(scopes)
                print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")
            else:
                print(f"  {Colors.RED}Program '{program}' not found on HackerOne or Bugcrowd.{Colors.END}")
                print(f"  {Colors.DIM}Try: fray bounty --platform hackerone --program <handle>{Colors.END}\n")
                return
    else:
        print(f"  {Colors.RED}Provide --program <handle>, or --urls file{Colors.END}")
        print(f"  {Colors.DIM}Examples:{Colors.END}")
        print(f"    fray bounty --program github")
        print(f"    fray bounty --platform hackerone --program github")
        print(f"    fray bounty --urls targets.txt")
        return

    if not urls:
        print(f"\n  {Colors.YELLOW}No testable URLs found in scope.{Colors.END}\n")
        return

    # ── Domain safety check ──────────────────────────────────────────────
    prog_handle = program or ""
    safe_urls, skipped = filter_safe_targets(urls, prog_handle)

    if skipped:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}Skipped (shared platforms — not owned by {prog_handle}):{Colors.END}")
        for s in skipped:
            print(f"    {Colors.DIM}SKIP{Colors.END}  {s['url']:<40} {Colors.DIM}{s['reason']}{Colors.END}")

    if not force:
        urls = safe_urls
    else:
        print(f"  {Colors.YELLOW}--force: testing ALL URLs including shared platforms{Colors.END}")

    if not urls:
        print(f"\n  {Colors.YELLOW}No safe targets to test after filtering shared platforms.{Colors.END}")
        print(f"  {Colors.DIM}Use --force to override safety checks.{Colors.END}\n")
        return

    # ── Scope-only mode ──────────────────────────────────────────────────
    if scope_only:
        print(f"\n  {Colors.BOLD}Safe Testable URLs ({len(urls)}):{Colors.END}")
        for u in urls:
            print(f"    {Colors.CYAN}{u}{Colors.END}")
        print(f"\n  {Colors.DIM}Remove --scope-only to run payload tests on these targets.{Colors.END}\n")
        return

    print(f"\n  {Colors.BOLD}Testing {len(urls)} target(s) × {len(test_categories)} categories × {max_payloads} payloads{Colors.END}")
    print(f"  {Colors.DIM}Categories: {', '.join(test_categories)}{Colors.END}\n")

    # ── Run tests ────────────────────────────────────────────────────────
    all_results = []
    for i, url in enumerate(urls, 1):
        print(f"  {Colors.DIM}[{i}/{len(urls)}]{Colors.END} {Colors.CYAN}{url}{Colors.END}")
        result = scan_target(url, test_categories, max_payloads=max_payloads,
                             timeout=timeout, delay=delay)
        all_results.append(result)

        waf = result.get("waf", "None") or "None"
        rate = result.get("block_rate", 0.0)
        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        print(f"    WAF: {waf} | Block rate: {rc}{rate:.1f}%{Colors.END}")

    # ── Report ───────────────────────────────────────────────────────────
    print_bounty_report(all_results, program, platform)

    # Save output
    if output:
        report = {
            "platform": platform,
            "program": program,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fray_version": __version__,
            "categories": test_categories,
            "targets": all_results,
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  {Colors.GREEN}Report saved: {output}{Colors.END}\n")
