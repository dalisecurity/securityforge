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
            # Only include web-testable assets
            if asset_type in ("URL", "DOMAIN", "WILDCARD"):
                scopes.append({
                    "type": asset_type,
                    "identifier": identifier,
                    "bounty": bounty,
                    "instruction": (instruction or "")[:100],
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


# ── URL Extraction & Normalization ───────────────────────────────────────────

def normalize_scope_to_urls(scopes: List[Dict]) -> List[str]:
    """Convert scope entries to testable URLs."""
    urls = []
    for scope in scopes:
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

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")

            if scopes:
                bounty_icon = lambda s: f"{Colors.GREEN}$${Colors.END}" if s.get('bounty') else f"{Colors.DIM}--{Colors.END}"
                print(f"\n  {Colors.BOLD}In-Scope Assets:{Colors.END}")
                for s in scopes[:20]:
                    print(f"    {bounty_icon(s)} {s['type']:<10} {s['identifier']}")
                if len(scopes) > 20:
                    print(f"    ... and {len(scopes) - 20} more")

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

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")

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
            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")
            if scopes:
                print(f"\n  {Colors.BOLD}In-Scope Assets:{Colors.END}")
                for s in scopes[:15]:
                    bounty_tag = f"{Colors.GREEN}$$" if s.get('bounty') else f"{Colors.DIM}--"
                    print(f"    {bounty_tag}{Colors.END} {s['type']:<10} {s['identifier']}")
        else:
            api_bc = BugcrowdPublic()
            ok, scopes = api_bc.get_program_scope(program)
            if ok and scopes:
                platform = "bugcrowd"
                print(f"  {Colors.GREEN}Found on Bugcrowd!{Colors.END}")
                urls = normalize_scope_to_urls(scopes)
                print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")
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
