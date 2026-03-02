#!/usr/bin/env python3
"""
SecurityForge MCP Server — Model Context Protocol integration.

Exposes SecurityForge capabilities as MCP tools that AI assistants
(Claude, Windsurf, etc.) can call directly. No copy-paste prompts needed.

Usage:
    # stdio mode (for Claude Desktop, Windsurf, etc.)
    python -m securityforge.mcp_server

    # Or via the securityforge CLI
    securityforge mcp

Configure in Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "securityforge": {
          "command": "python",
          "args": ["-m", "securityforge.mcp_server"]
        }
      }
    }
"""
import json
import sys
import logging
from pathlib import Path
from typing import Optional

# MCP SDK import — optional dependency
try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# Configure logging to stderr (NEVER stdout for stdio MCP servers)
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s [securityforge-mcp] %(message)s")
logger = logging.getLogger(__name__)

# Package paths
PKG_DIR = Path(__file__).resolve().parent
PAYLOADS_DIR = PKG_DIR / "payloads"


def _list_categories() -> list[dict]:
    """List payload categories with file counts."""
    cats = []
    for d in sorted(PAYLOADS_DIR.iterdir()):
        if d.is_dir():
            json_count = len(list(d.glob("*.json")))
            txt_count = len(list(d.glob("*.txt")))
            cats.append({
                "name": d.name,
                "json_files": json_count,
                "txt_files": txt_count,
                "total_files": json_count + txt_count,
            })
    return cats


def _load_payloads(category: str, max_payloads: int = 50) -> list[dict]:
    """Load payloads from a category directory."""
    cat_dir = PAYLOADS_DIR / category
    if not cat_dir.exists():
        return []
    payloads = []
    for jf in sorted(cat_dir.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            plist = data.get("payloads", data) if isinstance(data, dict) else data
            if isinstance(plist, list):
                for p in plist:
                    payloads.append(p)
                    if len(payloads) >= max_payloads:
                        return payloads
        except Exception:
            continue
    return payloads


def _get_waf_signatures() -> dict:
    """Get all WAF signatures from the detector."""
    from securityforge.detector import WAFDetector
    d = WAFDetector()
    result = {}
    for name, sig in d.waf_signatures.items():
        result[name] = {
            "headers": sig.get("headers", []),
            "cookies": sig.get("cookies", []),
            "server": sig.get("server", []),
            "response_codes": sig.get("response_codes", []),
        }
    return result


def create_server() -> "FastMCP":
    """Create and configure the MCP server with SecurityForge tools."""

    mcp = FastMCP(
        "securityforge",
        instructions="SecurityForge v3.1.0 — open-source WAF security testing toolkit. "
                     "4,025+ payloads, 25 WAF fingerprints, structured for AI workflows.",
    )

    # ── Tool: list_categories ──────────────────────────────────────────

    @mcp.tool()
    async def list_payload_categories() -> str:
        """List all available payload categories in SecurityForge.

        Returns a summary of each category with file counts.
        Use this to discover what attack types are available before
        retrieving specific payloads.
        """
        cats = _list_categories()
        lines = ["SecurityForge Payload Categories", "=" * 40, ""]
        total_files = 0
        for c in cats:
            lines.append(f"  {c['name']:30s}  {c['total_files']} files")
            total_files += c["total_files"]
        lines.append("")
        lines.append(f"Total: {len(cats)} categories, {total_files} files")
        return "\n".join(lines)

    # ── Tool: get_payloads ─────────────────────────────────────────────

    @mcp.tool()
    async def get_payloads(category: str, max_results: int = 20) -> str:
        """Retrieve payloads from a specific category.

        Args:
            category: Category name (e.g. xss, sqli, ssrf, ssti, iot_rce,
                      command_injection, ai_prompt_injection, etc.)
            max_results: Maximum number of payloads to return (default 20, max 100)
        """
        max_results = min(max_results, 100)
        available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir()]
        if category not in available:
            return (f"Category '{category}' not found.\n"
                    f"Available: {', '.join(sorted(available))}")

        payloads = _load_payloads(category, max_payloads=max_results)
        if not payloads:
            return f"No payloads found in category '{category}'."

        lines = [f"SecurityForge — {category} payloads ({len(payloads)} shown)", ""]
        for i, p in enumerate(payloads, 1):
            if isinstance(p, dict):
                payload = p.get("payload", str(p))
                desc = p.get("description", "")
                pid = p.get("id", f"#{i}")
                lines.append(f"[{pid}] {payload}")
                if desc:
                    lines.append(f"       → {desc}")
            else:
                lines.append(f"[{i}] {p}")
        return "\n".join(lines)

    # ── Tool: search_payloads ──────────────────────────────────────────

    @mcp.tool()
    async def search_payloads(query: str, max_results: int = 20) -> str:
        """Search across all payload categories for a specific pattern or keyword.

        Args:
            query: Search term (e.g. 'log4j', 'reverse shell', 'base64', 'xmlrpc')
            max_results: Maximum results to return (default 20, max 50)
        """
        max_results = min(max_results, 50)
        query_lower = query.lower()
        matches = []

        for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
            if not cat_dir.is_dir():
                continue
            for jf in cat_dir.glob("*.json"):
                try:
                    data = json.loads(jf.read_text(encoding="utf-8"))
                    plist = data.get("payloads", data) if isinstance(data, dict) else data
                    if not isinstance(plist, list):
                        continue
                    for p in plist:
                        if not isinstance(p, dict):
                            continue
                        searchable = json.dumps(p).lower()
                        if query_lower in searchable:
                            matches.append({
                                "category": cat_dir.name,
                                "file": jf.name,
                                **p
                            })
                            if len(matches) >= max_results:
                                break
                except Exception:
                    continue
                if len(matches) >= max_results:
                    break
            if len(matches) >= max_results:
                break

        if not matches:
            return f"No payloads matching '{query}' found."

        lines = [f"Search results for '{query}' ({len(matches)} matches)", ""]
        for m in matches:
            lines.append(f"[{m.get('category')}/{m.get('id', '?')}] {m.get('payload', '')[:120]}")
            if m.get("description"):
                lines.append(f"       → {m['description']}")
        return "\n".join(lines)

    # ── Tool: get_waf_signatures ───────────────────────────────────────

    @mcp.tool()
    async def get_waf_signatures(vendor: Optional[str] = None) -> str:
        """Get WAF detection signatures for fingerprinting.

        Args:
            vendor: Optional vendor name filter (e.g. 'Cloudflare', 'AWS').
                    If omitted, returns all 25 vendors.
        """
        sigs = _get_waf_signatures()
        if vendor:
            vendor_lower = vendor.lower()
            filtered = {k: v for k, v in sigs.items() if vendor_lower in k.lower()}
            if not filtered:
                return (f"No WAF vendor matching '{vendor}'.\n"
                        f"Available: {', '.join(sorted(sigs.keys()))}")
            sigs = filtered

        lines = [f"WAF Detection Signatures ({len(sigs)} vendors)", ""]
        for name, sig in sorted(sigs.items()):
            lines.append(f"■ {name}")
            lines.append(f"  Headers: {', '.join(sig['headers'][:5])}")
            lines.append(f"  Cookies: {', '.join(sig['cookies'][:5])}")
            lines.append(f"  Server:  {', '.join(sig['server'])}")
            lines.append(f"  Status:  {sig['response_codes']}")
            lines.append("")
        return "\n".join(lines)

    # ── Tool: get_cve_details ──────────────────────────────────────────

    @mcp.tool()
    async def get_cve_details(cve_id: str) -> str:
        """Look up a specific CVE across all SecurityForge payload files.

        Args:
            cve_id: CVE identifier (e.g. 'CVE-2026-27509')
        """
        cve_upper = cve_id.upper()
        results = []

        for jf in sorted(PAYLOADS_DIR.rglob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue
                file_cve = data.get("cve", "")
                if cve_upper in str(file_cve).upper():
                    results.append({
                        "file": str(jf.relative_to(PAYLOADS_DIR)),
                        "title": data.get("title", ""),
                        "severity": data.get("severity", ""),
                        "cwe": data.get("cwe", ""),
                        "affected": data.get("affected", {}),
                        "description": data.get("description", ""),
                        "payload_count": len(data.get("payloads", [])),
                        "references": data.get("references", []),
                    })
            except Exception:
                continue

        if not results:
            return f"No payloads found for {cve_id}."

        lines = []
        for r in results:
            lines.append(f"CVE: {cve_id}")
            lines.append(f"Title: {r['title']}")
            lines.append(f"Severity: {r['severity']}")
            lines.append(f"CWE: {r['cwe']}")
            lines.append(f"File: {r['file']}")
            lines.append(f"Payloads: {r['payload_count']}")
            if r["description"]:
                lines.append(f"Description: {r['description'][:300]}")
            if r["affected"]:
                lines.append(f"Affected: {json.dumps(r['affected'], indent=2)}")
            if r["references"]:
                lines.append(f"References:")
                for ref in r["references"]:
                    lines.append(f"  - {ref}")
        return "\n".join(lines)

    # ── Tool: suggest_payloads_for_waf ─────────────────────────────────

    @mcp.tool()
    async def suggest_payloads_for_waf(waf_vendor: str, attack_type: str = "xss",
                                        max_results: int = 10) -> str:
        """Suggest the best payloads to test against a specific WAF vendor.

        Combines WAF knowledge with payload selection to recommend
        payloads most likely to bypass the specified WAF.

        Args:
            waf_vendor: WAF vendor name (e.g. 'Cloudflare', 'AWS WAF', 'Akamai')
            attack_type: Attack category (e.g. 'xss', 'sqli', 'ssrf', 'command_injection')
            max_results: Number of payloads to suggest (default 10)
        """
        sigs = _get_waf_signatures()
        vendor_lower = waf_vendor.lower()
        matched = [k for k in sigs if vendor_lower in k.lower()]
        if not matched:
            return (f"Unknown WAF vendor '{waf_vendor}'.\n"
                    f"Known vendors: {', '.join(sorted(sigs.keys()))}")

        vendor_name = matched[0]
        payloads = _load_payloads(attack_type, max_payloads=200)
        if not payloads:
            available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir()]
            return (f"No payloads in category '{attack_type}'.\n"
                    f"Available: {', '.join(sorted(available))}")

        # Prefer payloads with evasion techniques, encoding, or bypass in description
        evasion_keywords = ["bypass", "evasion", "encod", "obfuscat", "polyglot",
                           "mutation", "double", "nested", "unicode", "hex", "base64"]
        scored = []
        for p in payloads:
            if not isinstance(p, dict):
                continue
            text = json.dumps(p).lower()
            score = sum(2 for kw in evasion_keywords if kw in text)
            # Bonus if tested against this WAF
            tested = p.get("tested_against", [])
            if any(vendor_lower in t.lower() for t in tested):
                score += 5
            if not p.get("blocked", True):
                score += 3  # Previously bypassed
            scored.append((score, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:max_results]

        lines = [
            f"Suggested {attack_type.upper()} payloads for {vendor_name}",
            f"({len(top)} payloads, ranked by likely bypass potential)", ""
        ]
        for score, p in top:
            lines.append(f"[{p.get('id', '?')}] {p.get('payload', '')[:120]}")
            if p.get("description"):
                lines.append(f"       → {p['description']}")
            lines.append(f"       Score: {score}  Blocked: {p.get('blocked', '?')}")
            lines.append("")
        return "\n".join(lines)

    return mcp


def main():
    if not MCP_AVAILABLE:
        print("Error: MCP SDK not installed. Install with:", file=sys.stderr)
        print("  pip install 'mcp[cli]'", file=sys.stderr)
        sys.exit(1)

    logger.info("Starting SecurityForge MCP server (stdio)")
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
