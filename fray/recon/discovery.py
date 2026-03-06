"""Discovery modules — historical URLs, parameter mining/brute-force,
JS endpoint extraction (LinkFinder-style), and lightweight param crawl."""

import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


# ── Historical URL Discovery ─────────────────────────────────────────────

# Path patterns interesting for WAF testing — old/dev/debug endpoints
_INTERESTING_PATH_RE = re.compile(
    r"(?:/api/|/v[1-9]\d*/|/admin|/debug|/internal|/graphql|/auth|/oauth|"
    r"/dev/|/staging/|/test/|/old/|/backup|/console|/swagger|/docs/api|"
    r"/wp-json|/xmlrpc|/cgi-bin|/\.env|/\.git|/phpinfo|/actuator|"
    r"/config|/secret|/token|/upload|/download|/export|/import|"
    r"/dashboard|/panel|/manage|/setup|/install)",
    re.IGNORECASE,
)

# Extensions to skip (static assets)
_STATIC_EXT_RE = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|tar|gz|"
    r"mp[34]|webp|avif|bmp|tiff?|wav|flac|ogg|avi|mov|wmv|swf|flv)$",
    re.IGNORECASE,
)


def discover_historical_urls(url: str, timeout: int = 12,
                              verify_ssl: bool = True,
                              extra_headers: Optional[Dict[str, str]] = None,
                              wayback_limit: int = 200,
                              ) -> Dict[str, Any]:
    """Discover historical URLs from Wayback Machine, sitemap.xml, and robots.txt.

    Old endpoints often have weaker WAF rules or none at all.
    """
    from fray.recon.http import _fetch_url

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{host}"

    all_paths = {}   # path -> {sources, timestamps, ...}
    errors = []

    # ── 1. Wayback Machine CDX API ──
    wayback_urls = []
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={host}/*&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&filter=statuscode:200&collapse=urlkey&limit={wayback_limit}"
        )
        # Single attempt with tight timeout — CDX is often slow/flaky
        status, body = 0, ""
        wb_timeout = min(timeout, 8)
        for _attempt in range(2):
            status, body, _ = _fetch_url(cdx_url, timeout=wb_timeout, verify_ssl=False)
            if status == 200 and body:
                break
            if _attempt == 0:
                import time as _time
                _time.sleep(1)
        if status == 200 and body:
            import json as _json
            try:
                rows = _json.loads(body)
                # First row is header: ["timestamp","original","statuscode","mimetype"]
                for row in rows[1:]:
                    if len(row) < 4:
                        continue
                    ts, orig_url, sc, mime = row[0], row[1], row[2], row[3]
                    # Skip static assets
                    orig_parsed = urllib.parse.urlparse(orig_url)
                    path = orig_parsed.path.rstrip("/") or "/"
                    if _STATIC_EXT_RE.search(path):
                        continue
                    if path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if "wayback" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("wayback")
                    # Track oldest timestamp
                    if ts and (not all_paths[path]["first_seen"] or ts < all_paths[path]["first_seen"]):
                        all_paths[path]["first_seen"] = ts
                    wayback_urls.append(path)
            except (_json.JSONDecodeError, IndexError):
                pass
    except Exception as e:
        errors.append(f"Wayback: {e}")

    # ── 2. sitemap.xml (current + archived) ──
    sitemap_paths = []
    sitemap_urls_to_check = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap_index.xml",
        f"{base}/sitemap.xml.gz",
    ]
    for smap_url in sitemap_urls_to_check:
        try:
            status, body, _ = _fetch_url(smap_url, timeout=timeout,
                                         verify_ssl=verify_ssl,
                                         headers=extra_headers)
            if status == 200 and body:
                # Extract <loc> tags
                for m in re.finditer(r'<loc>\s*(.*?)\s*</loc>', body, re.IGNORECASE):
                    loc = m.group(1).strip()
                    loc_parsed = urllib.parse.urlparse(loc)
                    path = loc_parsed.path.rstrip("/") or "/"
                    if _STATIC_EXT_RE.search(path):
                        continue
                    if path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if "sitemap" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("sitemap")
                    sitemap_paths.append(path)
        except Exception:
            pass

    # ── 3. robots.txt (Disallow paths are gold) ──
    robots_paths = []
    try:
        robots_url = f"{base}/robots.txt"
        status, body, _ = _fetch_url(robots_url, timeout=timeout,
                                     verify_ssl=verify_ssl,
                                     headers=extra_headers)
        if status == 200 and body:
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if not path or path == "/":
                        continue
                    # Remove trailing wildcards
                    path = path.rstrip("*").rstrip("/") or path
                    if path and path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if path and "robots.txt" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("robots.txt")
                    if path:
                        robots_paths.append(path)
                # Also grab Sitemap directives
                elif line.lower().startswith("sitemap:"):
                    smap = line.split(":", 1)[1].strip()
                    if smap and smap not in sitemap_urls_to_check:
                        sitemap_urls_to_check.append(smap)
    except Exception:
        pass

    # ── Mark interesting paths ──
    for path, info in all_paths.items():
        if _INTERESTING_PATH_RE.search(path):
            info["interesting"] = True

    # ── Sort: interesting first, then by path ──
    sorted_paths = sorted(
        all_paths.values(),
        key=lambda x: (0 if x["interesting"] else 1, x["path"]),
    )

    interesting_count = sum(1 for p in sorted_paths if p["interesting"])

    return {
        "urls": sorted_paths,
        "total": len(sorted_paths),
        "interesting": interesting_count,
        "sources": {
            "wayback": len(set(wayback_urls)),
            "sitemap": len(set(sitemap_paths)),
            "robots": len(set(robots_paths)),
        },
        "errors": errors,
    }


def print_historical_urls(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print historical URL discovery results."""
    from fray.output import console, print_header

    print_header("Fray Recon — Historical URL Discovery", target=target)

    total = result.get("total", 0)
    interesting = result.get("interesting", 0)
    src = result.get("sources", {})

    console.print(f"  URLs discovered: [cyan]{total}[/cyan]")
    console.print(f"  Interesting paths: [yellow]{interesting}[/yellow] (admin, API, debug, config, etc.)")
    console.print(f"  Sources: [green]{src.get('wayback', 0)}[/green] Wayback · "
                  f"[green]{src.get('sitemap', 0)}[/green] sitemap · "
                  f"[green]{src.get('robots', 0)}[/green] robots.txt")
    console.print()

    urls = result.get("urls", [])
    if urls:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Path", min_width=40)
        table.add_column("Sources", width=18, style="dim")
        table.add_column("First Seen", width=10, style="dim")

        for i, u in enumerate(urls[:40], 1):
            path = u["path"]
            if u["interesting"]:
                path_display = f"[yellow]{path}[/yellow]"
            else:
                path_display = path
            sources = ", ".join(u["sources"])
            ts = u.get("first_seen", "")
            if ts and len(ts) >= 8:
                ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
            else:
                ts = ""
            table.add_row(str(i), path_display, sources, ts)

        console.print(table)
        if len(urls) > 40:
            console.print(f"    [dim]... and {len(urls) - 40} more[/dim]")
        console.print()

        if interesting:
            console.print("  [bold yellow]\u26a0 Interesting paths \u2014 likely weaker WAF protection:[/bold yellow]")
            for u in urls:
                if u["interesting"]:
                    console.print(f"    [yellow]{u['path']}[/yellow]  ({', '.join(u['sources'])})")
            console.print()

        console.print(f"  [dim]Test old endpoints: fray scan {target} -c xss -m 3[/dim]")
    else:
        console.print("  [dim]No historical URLs found[/dim]")

    errors = result.get("errors", [])
    if errors:
        for err in errors:
            console.print(f"  [dim]\u26a0 {err}[/dim]")
    console.print()


# ── Parameter Mining (brute-force) ───────────────────────────────────────

# Curated wordlist — common hidden/undocumented parameters across web apps
_PARAM_WORDLIST = [
    # Auth & session
    "id", "user", "username", "login", "password", "pass", "email", "token",
    "session", "auth", "key", "api_key", "apikey", "secret", "access_token",
    # Routing & redirects
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "goto", "dest", "destination", "continue", "callback", "ref",
    # File & path
    "file", "filename", "path", "dir", "folder", "doc", "document", "template",
    "page", "include", "src", "source", "load", "read", "fetch", "download",
    # Data / CRUD
    "name", "value", "data", "content", "text", "body", "message", "comment",
    "title", "description", "type", "category", "status", "action", "cmd",
    "command", "exec", "query", "q", "search", "filter", "sort", "order",
    "limit", "offset", "count", "size", "from", "to", "start", "end",
    # ID variants
    "uid", "pid", "cid", "oid", "item", "item_id", "product", "product_id",
    "order_id", "account", "account_id", "customer_id", "invoice",
    # Debug & internal
    "debug", "test", "admin", "mode", "env", "verbose", "trace", "log",
    "config", "setting", "format", "output", "render", "view", "preview",
    "version", "v", "lang", "locale", "language",
    # SSRF / injection targets
    "host", "ip", "port", "domain", "proxy", "target", "site",
    # Upload & media
    "upload", "image", "img", "avatar", "photo", "attachment", "media",
    # Misc
    "callback", "jsonp", "method", "_method", "csrf", "nonce", "timestamp",
    "sign", "signature", "hash", "checksum", "role", "group", "permission",
]


def mine_params(url: str, timeout: int = 4, verify_ssl: bool = True,
                extra_headers: Optional[Dict[str, str]] = None,
                wordlist: Optional[List[str]] = None,
                quiet: bool = False,
                ) -> Dict[str, Any]:
    """Parameter brute-force mining.

    Probes each param name against the target URL and detects hidden parameters
    by comparing response differences (status, content-length, reflection).

    This is NOT directory fuzzing — it's parameter fuzzing.
    """
    from fray.recon.http import _fetch_url
    from fray.scanner import _fetch, extract_links, _same_origin

    params_to_try = wordlist or _PARAM_WORDLIST

    parsed = urllib.parse.urlparse(url)

    # Quick crawl to find testable endpoints (pages that accept input)
    endpoints = set()
    endpoints.add(url)

    status, body, resp_headers = _fetch(url, timeout=timeout,
                                        verify_ssl=verify_ssl,
                                        headers=extra_headers)
    if status and body:
        content_type = resp_headers.get("content-type", "")
        if "text/html" in content_type:
            for link in extract_links(url, body):
                if _same_origin(url, link):
                    endpoints.add(link.split("?")[0].split("#")[0])

    # Limit endpoints — 3 max keeps total requests under ~320
    test_endpoints = sorted(endpoints)[:3]

    found_params = []
    seen = set()
    total_probed = 0
    total_work = len(test_endpoints) * len(params_to_try)

    for ep_idx, ep_url in enumerate(test_endpoints):
        ep_path = urllib.parse.urlparse(ep_url).path or "/"
        if not quiet:
            sys.stderr.write(f"\r  Mining {ep_path} ... ({ep_idx+1}/{len(test_endpoints)})")
            sys.stderr.flush()

        # Baseline: request without any extra params
        base_status, base_body, _ = _fetch_url(ep_url, timeout=timeout,
                                                verify_ssl=verify_ssl,
                                                headers=extra_headers)
        if base_status == 0:
            continue
        base_len = len(base_body)

        for param in params_to_try:
            key = (ep_url.split("?")[0], param)
            if key in seen:
                continue

            test_value = "fray_test_1337"
            sep = "&" if "?" in ep_url else "?"
            probe_url = f"{ep_url}{sep}{param}={test_value}"
            total_probed += 1

            probe_status, probe_body, _ = _fetch_url(probe_url, timeout=timeout,
                                                      verify_ssl=verify_ssl,
                                                      headers=extra_headers)
            if probe_status == 0:
                continue

            # Detection: compare against baseline
            probe_len = len(probe_body)
            reflected = test_value in probe_body
            status_diff = probe_status != base_status
            # Significant size difference (>50 bytes and >5% change)
            size_diff = abs(probe_len - base_len) > 50 and abs(probe_len - base_len) / max(base_len, 1) > 0.05

            if reflected or status_diff or size_diff:
                seen.add(key)
                evidence = []
                if reflected:
                    evidence.append("reflected")
                if status_diff:
                    evidence.append(f"status {base_status}\u2192{probe_status}")
                if size_diff:
                    diff = probe_len - base_len
                    evidence.append(f"size {'+' if diff > 0 else ''}{diff}b")

                # Classify risk
                risk = "info"
                if param in ("redirect", "redirect_url", "redirect_uri", "url",
                             "return", "return_url", "next", "goto", "dest",
                             "destination", "callback", "continue"):
                    risk = "high"  # Open redirect / SSRF
                elif param in ("file", "path", "dir", "include", "template",
                               "load", "read", "fetch", "doc", "source", "src"):
                    risk = "high"  # LFI / path traversal
                elif param in ("cmd", "command", "exec", "query", "action"):
                    risk = "high"  # Command injection / SQLi
                elif param in ("id", "uid", "user", "account", "account_id",
                               "customer_id", "order_id", "item_id"):
                    risk = "medium"  # IDOR
                elif param in ("debug", "test", "admin", "verbose", "trace",
                               "config", "env", "mode"):
                    risk = "medium"  # Debug/info disclosure
                elif reflected:
                    risk = "medium"  # XSS candidate

                ep_path = urllib.parse.urlparse(ep_url).path or "/"
                found_params.append({
                    "endpoint": ep_path,
                    "param": param,
                    "method": "GET",
                    "evidence": evidence,
                    "risk": risk,
                })

    if not quiet:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    # Sort by risk (high first)
    risk_order = {"high": 0, "medium": 1, "info": 2}
    found_params.sort(key=lambda x: (risk_order.get(x["risk"], 3), x["endpoint"], x["param"]))

    return {
        "params": found_params,
        "total_found": len(found_params),
        "total_probed": total_probed,
        "endpoints_tested": len(test_endpoints),
        "wordlist_size": len(params_to_try),
    }


def print_mined_params(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print parameter mining results."""
    from fray.output import console, print_header

    print_header("Fray Recon \u2014 Parameter Mining", target=target)

    total = result.get("total_found", 0)
    probed = result.get("total_probed", 0)
    eps = result.get("endpoints_tested", 0)

    console.print(f"  Parameters found: [cyan]{total}[/cyan]")
    console.print(f"  Probed: {probed} combinations ({eps} endpoints \u00d7 {result.get('wordlist_size', 0)} params)")
    console.print()

    params = result.get("params", [])
    if params:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Endpoint", min_width=25)
        table.add_column("Param", min_width=15, style="cyan")
        table.add_column("Risk", width=8)
        table.add_column("Evidence", min_width=20, style="dim")

        risk_styles = {
            "high": "[red]HIGH[/red]",
            "medium": "[yellow]MED[/yellow]",
            "info": "[dim]info[/dim]",
        }

        for i, p in enumerate(params[:30], 1):
            risk_display = risk_styles.get(p["risk"], p["risk"])
            evidence = ", ".join(p["evidence"])
            table.add_row(str(i), p["endpoint"], p["param"], risk_display, evidence)

        console.print(table)
        if len(params) > 30:
            console.print(f"    [dim]... and {len(params) - 30} more[/dim]")
        console.print()

        # Summary by risk
        high = sum(1 for p in params if p["risk"] == "high")
        med = sum(1 for p in params if p["risk"] == "medium")
        if high:
            console.print(f"  [red]\u26a0 {high} HIGH risk params[/red] \u2014 test for SSRF, LFI, injection")
        if med:
            console.print(f"  [yellow]\u26a0 {med} MEDIUM risk params[/yellow] \u2014 test for XSS, IDOR, debug disclosure")
        console.print()
        console.print(f"  [dim]Test: fray scan {target} -c xss -m 3[/dim]")
    else:
        console.print("  [dim]No hidden parameters found[/dim]")
    console.print()


# ── JS Endpoint Extraction ───────────────────────────────────────────────

# Comprehensive regex patterns for JS endpoint discovery
_JS_ENDPOINT_PATTERNS = [
    # fetch / axios / xhr
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""axios\.[a-z]+\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # String literals that look like API paths
    re.compile(r"""['"`](/api/[^'"`\s]{2,})['"`]"""),
    re.compile(r"""['"`](/v[1-9]\d*/[^'"`\s]{2,})['"`]"""),
    re.compile(r"""['"`](/graphql[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/rest/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/internal/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/admin/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/auth/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/oauth/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/webhook[s]?/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/upload[s]?[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/download[s]?[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/socket[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/ws/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    # Template literal URLs: `${baseUrl}/endpoint`
    re.compile(r"""\$\{[^}]+\}(/[a-zA-Z0-9_/\-]+)"""),
    # URL concatenation: baseUrl + "/endpoint"
    re.compile(r"""\+\s*['"`](/[a-zA-Z0-9_/\-]{3,})['"`]"""),
]

# ── LinkFinder-style patterns for full URLs, hostnames, cloud buckets ──

# Full absolute URLs in JS string literals
_JS_FULL_URL_RE = re.compile(
    r"""['"`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,})['"`]""",
)

# Internal hostnames / subdomains referenced in JS
_JS_HOSTNAME_RE = re.compile(
    r"""['"`]((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"""
    r"""(?:com|org|net|io|dev|app|co|ai|cloud|internal|local|corp|intranet"""
    r"""|staging|test|qa|uat|prod|infra))['"`]""",
    re.IGNORECASE,
)

# Cloud storage buckets
_JS_CLOUD_BUCKET_PATTERNS = [
    # AWS S3: s3.amazonaws.com/bucket or bucket.s3.amazonaws.com or s3://bucket
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-]+\.s3[.\-]amazonaws\.com)[/'"` ]""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?s3[.\-]amazonaws\.com/([a-zA-Z0-9.\-]+)""", re.IGNORECASE),
    re.compile(r"""['"`]s3://([a-zA-Z0-9.\-]+)['"`]""", re.IGNORECASE),
    # Google Cloud Storage
    re.compile(r"""['"`](?:https?://)?storage\.googleapis\.com/([a-zA-Z0-9.\-_]+)""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-_]+\.storage\.googleapis\.com)""", re.IGNORECASE),
    re.compile(r"""['"`]gs://([a-zA-Z0-9.\-_]+)['"`]""", re.IGNORECASE),
    # Azure Blob Storage
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9]+\.blob\.core\.windows\.net)""", re.IGNORECASE),
    # Firebase
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9\-]+\.firebaseio\.com)""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9\-]+\.firebasestorage\.googleapis\.com)""", re.IGNORECASE),
    # DigitalOcean Spaces
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-]+\.digitaloceanspaces\.com)""", re.IGNORECASE),
]

# API keys and secrets (high-entropy strings with known prefixes)
_JS_SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key", re.compile(r"""(?:^|['"` ,=:])((AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?:['"` ,]|$)""")),
    # Google
    ("Google API Key", re.compile(r"""['"`](AIza[0-9A-Za-z\-_]{35})['"`]""")),
    ("Google OAuth", re.compile(r"""['"`](\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)['"`]""")),
    # GitHub
    ("GitHub Token", re.compile(r"""['"`](gh[pousr]_[A-Za-z0-9_]{36,})['"`]""")),
    # Stripe
    ("Stripe Key", re.compile(r"""['"`](sk_live_[A-Za-z0-9]{20,})['"`]""")),
    ("Stripe Publishable", re.compile(r"""['"`](pk_live_[A-Za-z0-9]{20,})['"`]""")),
    # Slack
    ("Slack Token", re.compile(r"""['"`](xox[bpoas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})['"`]""")),
    ("Slack Webhook", re.compile(r"""['"`](https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)['"`]""")),
    # Twilio
    ("Twilio Key", re.compile(r"""['"`](SK[a-f0-9]{32})['"`]""")),
    # SendGrid
    ("SendGrid Key", re.compile(r"""['"`](SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})['"`]""")),
    # Mailgun
    ("Mailgun Key", re.compile(r"""['"`](key-[a-f0-9]{32})['"`]""")),
    # Generic API key patterns (variable assignment context)
    ("API Key (generic)", re.compile(
        r"""(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"""
        r"""\s*[:=]\s*['"`]([a-zA-Z0-9\-_./+]{20,})['"`]""",
        re.IGNORECASE,
    )),
    # JWT tokens
    ("JWT Token", re.compile(r"""['"`](eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+/=]+)['"`]""")),
    # Private keys
    ("Private Key", re.compile(r"""(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)""")),
    # Bearer tokens in headers
    ("Bearer Token", re.compile(
        r"""['"](Bearer\s+[a-zA-Z0-9\-_./+]{20,})['"]""",
        re.IGNORECASE,
    )),
]

# Patterns to extract <script src="..."> tags
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def discover_js_endpoints(url: str, max_depth: int = 2, max_pages: int = 10,
                          timeout: int = 8, verify_ssl: bool = True,
                          extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Deep JS endpoint extraction (LinkFinder-style).

    Crawls HTML pages, finds all <script src="..."> tags, fetches external
    JS files, and extracts:
      - API endpoints (paths + full URLs)
      - Internal hostnames / subdomains
      - Cloud storage buckets (S3, GCS, Azure, Firebase, DO Spaces)
      - API keys and secrets (AWS, Google, GitHub, Stripe, Slack, JWT, etc.)
    """
    from fray.scanner import _fetch, extract_links, _same_origin, _normalize_url

    parsed_target = urllib.parse.urlparse(url)
    target_domain = parsed_target.netloc.split(":")[0].lower()

    visited_pages = set()
    visited_js = set()
    queue = [(url, 0)]
    endpoints = []   # list of dicts
    seen_paths = set()

    # LinkFinder-style collections
    full_urls = []       # absolute URLs found in JS
    seen_urls = set()
    hostnames = []       # internal hostnames / subdomains
    seen_hosts = set()
    cloud_buckets = []   # S3, GCS, Azure, Firebase, DO Spaces
    seen_buckets = set()
    secrets = []         # API keys, tokens, credentials
    seen_secrets = set()

    def _process_js(js_content: str, source_url: str) -> None:
        """Extract all intelligence from a JS source."""
        _extract_endpoints_from_js(js_content, source_url, endpoints, seen_paths)
        _extract_full_urls(js_content, source_url, target_domain,
                           full_urls, seen_urls)
        _extract_hostnames(js_content, source_url, target_domain,
                           hostnames, seen_hosts)
        _extract_cloud_buckets(js_content, source_url,
                               cloud_buckets, seen_buckets)
        _extract_secrets(js_content, source_url, secrets, seen_secrets)

    while queue and len(visited_pages) < max_pages:
        current_url, depth = queue.pop(0)
        canonical = current_url.split("?")[0].split("#")[0]
        if canonical in visited_pages:
            continue
        visited_pages.add(canonical)

        # Skip non-HTML resources
        lower = canonical.lower()
        if any(lower.endswith(ext) for ext in (
            ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
        )):
            continue

        status, body, resp_headers = _fetch(current_url, timeout=timeout,
                                            verify_ssl=verify_ssl,
                                            headers=extra_headers)
        if status == 0 or not body:
            continue

        # Follow redirects
        if status in (301, 302, 307, 308):
            loc = resp_headers.get("location", "")
            if loc:
                redir_url = urllib.parse.urljoin(current_url, loc)
                if _same_origin(url, redir_url) and redir_url.split("?")[0] not in visited_pages:
                    queue.append((redir_url, depth))
            continue

        content_type = resp_headers.get("content-type", "")

        # Extract endpoints from inline JS in HTML pages
        if "text/html" in content_type or "application/xhtml" in content_type:
            _process_js(body, current_url)

            # Find and fetch external JS files
            for m in _SCRIPT_SRC_RE.finditer(body):
                js_src = m.group(1).strip()
                js_url = _normalize_url(current_url, js_src)
                if not js_url or js_url in visited_js:
                    continue
                visited_js.add(js_url)

                js_status, js_body, _ = _fetch(js_url, timeout=timeout,
                                               verify_ssl=verify_ssl,
                                               headers=extra_headers)
                if js_status == 200 and js_body:
                    _process_js(js_body, js_url)

            # Follow links
            if depth < max_depth:
                for link in extract_links(current_url, body):
                    link_canon = link.split("?")[0].split("#")[0]
                    if link_canon not in visited_pages and _same_origin(url, link):
                        queue.append((link, depth + 1))

    # Sort: /api first, then /admin, then rest
    def _sort_key(ep):
        p = ep["path"]
        if "/api/" in p or "/graphql" in p: return (0, p)
        if "/admin/" in p or "/internal/" in p: return (1, p)
        if "/auth/" in p or "/oauth/" in p: return (2, p)
        return (3, p)
    endpoints.sort(key=_sort_key)

    return {
        "endpoints": endpoints,
        "total": len(endpoints),
        "pages_crawled": len(visited_pages),
        "js_files_parsed": len(visited_js),
        "categories": {
            "api": sum(1 for e in endpoints if "/api/" in e["path"] or "/v" in e["path"]),
            "graphql": sum(1 for e in endpoints if "graphql" in e["path"].lower()),
            "admin": sum(1 for e in endpoints if "/admin/" in e["path"] or "/internal/" in e["path"]),
            "auth": sum(1 for e in endpoints if "/auth/" in e["path"] or "/oauth/" in e["path"]),
            "other": sum(1 for e in endpoints if not any(
                x in e["path"].lower() for x in ("/api/", "/v1/", "/v2/", "/graphql", "/admin/", "/internal/", "/auth/", "/oauth/")
            )),
        },
        # LinkFinder-style intelligence
        "full_urls": full_urls,
        "hostnames": hostnames,
        "cloud_buckets": cloud_buckets,
        "secrets": secrets,
    }


def _extract_endpoints_from_js(js_content: str, source_url: str,
                                endpoints: List[Dict], seen_paths: set) -> None:
    """Extract API endpoints from JS content and append to endpoints list."""
    for pattern in _JS_ENDPOINT_PATTERNS:
        for m in pattern.finditer(js_content):
            path = m.group(1).strip()
            # Filter noise
            if len(path) < 3 or len(path) > 200:
                continue
            if not path.startswith("/"):
                continue
            # Skip obvious non-endpoints
            if any(path.endswith(ext) for ext in (
                ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".map", ".html", ".htm",
            )):
                continue
            # Normalize: strip trailing slashes, query strings for dedup
            clean = path.split("?")[0].split("#")[0].rstrip("/")
            if not clean or clean in seen_paths:
                continue
            seen_paths.add(clean)

            # Classify
            lower = clean.lower()
            if "/admin" in lower or "/internal" in lower:
                category = "admin"
            elif "/graphql" in lower:
                category = "graphql"
            elif "/api/" in lower or re.match(r"/v\d+/", lower):
                category = "api"
            elif "/auth" in lower or "/oauth" in lower:
                category = "auth"
            elif "/upload" in lower or "/download" in lower:
                category = "upload"
            elif "/ws/" in lower or "/socket" in lower:
                category = "websocket"
            else:
                category = "other"

            endpoints.append({
                "path": clean,
                "source": urllib.parse.urlparse(source_url).path or source_url,
                "category": category,
            })


def _extract_full_urls(js_content: str, source_url: str, target_domain: str,
                       full_urls: List[Dict], seen_urls: set) -> None:
    """Extract absolute URLs from JS content."""
    # Common noise domains to skip
    _NOISE_DOMAINS = {
        "w3.org", "schema.org", "xmlns.com", "purl.org", "google.com/recaptcha",
        "fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com", "unpkg.com", "maps.googleapis.com",
        "www.googletagmanager.com", "www.google-analytics.com",
        "connect.facebook.net", "platform.twitter.com",
    }
    for m in _JS_FULL_URL_RE.finditer(js_content):
        raw_url = m.group(1).strip().rstrip("'\"`;,)")
        if raw_url in seen_urls:
            continue
        # Filter noise
        if len(raw_url) > 500:
            continue
        try:
            parsed = urllib.parse.urlparse(raw_url)
            host = parsed.netloc.split(":")[0].lower()
        except Exception:
            continue
        if not host or any(n in raw_url for n in _NOISE_DOMAINS):
            continue
        # Skip same-origin static assets
        if host == target_domain and any(raw_url.lower().endswith(ext) for ext in (
            ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff2",
        )):
            continue
        seen_urls.add(raw_url)
        # Classify
        is_same_org = target_domain in host or host in target_domain
        category = "same-origin" if is_same_org else "third-party"
        if any(kw in raw_url.lower() for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
            category = "api"
        elif any(kw in raw_url.lower() for kw in ("/admin", "/internal", "/debug")):
            category = "admin"
        full_urls.append({
            "url": raw_url,
            "host": host,
            "category": category,
            "source": urllib.parse.urlparse(source_url).path or source_url,
        })


def _extract_hostnames(js_content: str, source_url: str, target_domain: str,
                       hostnames: List[Dict], seen_hosts: set) -> None:
    """Extract internal hostnames and subdomains from JS content."""
    # Extract the base domain (last two parts) for matching related subdomains
    parts = target_domain.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else target_domain

    for m in _JS_HOSTNAME_RE.finditer(js_content):
        hostname = m.group(1).strip().lower()
        if hostname in seen_hosts:
            continue
        if len(hostname) < 5 or len(hostname) > 253:
            continue
        # Skip the target itself
        if hostname == target_domain:
            continue
        seen_hosts.add(hostname)
        # Classify: related subdomain vs third-party
        is_related = base_domain in hostname
        risk = "info"
        if is_related:
            if any(kw in hostname for kw in ("staging", "dev", "test", "internal", "admin", "debug")):
                risk = "medium"
            elif any(kw in hostname for kw in ("prod", "api", "db", "redis", "mongo", "mysql")):
                risk = "high"
        hostnames.append({
            "hostname": hostname,
            "related": is_related,
            "risk": risk,
            "source": urllib.parse.urlparse(source_url).path or source_url,
        })


def _extract_cloud_buckets(js_content: str, source_url: str,
                            cloud_buckets: List[Dict], seen_buckets: set) -> None:
    """Extract cloud storage bucket references from JS content."""
    _PROVIDER_MAP = {
        "s3": "AWS S3",
        "amazonaws": "AWS S3",
        "storage.googleapis": "Google Cloud Storage",
        "gs://": "Google Cloud Storage",
        "blob.core.windows": "Azure Blob",
        "firebaseio": "Firebase",
        "firebasestorage": "Firebase Storage",
        "digitaloceanspaces": "DigitalOcean Spaces",
    }
    for pattern in _JS_CLOUD_BUCKET_PATTERNS:
        for m in pattern.finditer(js_content):
            bucket = m.group(1).strip()
            if bucket in seen_buckets or len(bucket) < 3:
                continue
            seen_buckets.add(bucket)
            # Determine provider
            provider = "Unknown"
            for key, name in _PROVIDER_MAP.items():
                if key in bucket.lower() or key in pattern.pattern.lower():
                    provider = name
                    break
            cloud_buckets.append({
                "bucket": bucket,
                "provider": provider,
                "risk": "high",
                "source": urllib.parse.urlparse(source_url).path or source_url,
            })


def _extract_secrets(js_content: str, source_url: str,
                     secrets: List[Dict], seen_secrets: set) -> None:
    """Extract API keys, tokens, and credentials from JS content."""
    for label, pattern in _JS_SECRET_PATTERNS:
        for m in pattern.finditer(js_content):
            secret = m.group(1).strip()
            if secret in seen_secrets or len(secret) < 8:
                continue
            seen_secrets.add(secret)
            # Mask the secret for display (show first 8 chars + ...)
            masked = secret[:8] + "..." + secret[-4:] if len(secret) > 16 else secret[:8] + "..."
            secrets.append({
                "type": label,
                "value_masked": masked,
                "length": len(secret),
                "risk": "critical",
                "source": urllib.parse.urlparse(source_url).path or source_url,
            })


def print_js_endpoints(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print JS endpoint extraction results."""
    from fray.output import console, print_header

    print_header("Fray Recon \u2014 JS Endpoint Extraction", target=target)

    eps = result.get("endpoints", [])
    cats = result.get("categories", {})
    console.print(f"  Pages crawled: {result.get('pages_crawled', 0)}")
    console.print(f"  JS files parsed: {result.get('js_files_parsed', 0)}")
    console.print(f"  Endpoints found: [cyan]{len(eps)}[/cyan]")
    console.print()

    if cats:
        parts = []
        for label, key in [("API", "api"), ("GraphQL", "graphql"), ("Admin", "admin"),
                           ("Auth", "auth"), ("Other", "other")]:
            count = cats.get(key, 0)
            if count:
                parts.append(f"{label}: {count}")
        if parts:
            cat_str = " \u00b7 ".join(parts)
            console.print(f"  Categories: {cat_str}")
            console.print()

    if eps:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Endpoint", min_width=35, style="cyan")
        table.add_column("Category", width=10)
        table.add_column("Found in", min_width=20, style="dim")

        cat_styles = {
            "api": "[green]api[/green]", "graphql": "[magenta]graphql[/magenta]",
            "admin": "[red]admin[/red]", "auth": "[yellow]auth[/yellow]",
            "upload": "[yellow]upload[/yellow]", "websocket": "[blue]ws[/blue]",
            "other": "[dim]other[/dim]",
        }

        for i, ep in enumerate(eps[:30], 1):
            cat_display = cat_styles.get(ep["category"], ep["category"])
            table.add_row(str(i), ep["path"], cat_display, ep["source"])

        console.print(table)
        if len(eps) > 30:
            console.print(f"    [dim]... and {len(eps) - 30} more[/dim]")
        console.print()
    else:
        console.print("  [dim]No JS endpoints found[/dim]")
        console.print()

    # ── Full URLs ──
    urls = result.get("full_urls", [])
    if urls:
        console.print(f"  [bold]Full URLs[/bold] ({len(urls)})")
        url_cat_styles = {
            "api": "[green]api[/green]", "admin": "[red]admin[/red]",
            "same-origin": "[cyan]same-origin[/cyan]", "third-party": "[dim]3rd-party[/dim]",
        }
        for u in urls[:15]:
            style = url_cat_styles.get(u["category"], "[dim]other[/dim]")
            console.print(f"    {style} {u['url']}")
        if len(urls) > 15:
            console.print(f"    [dim]... +{len(urls) - 15} more[/dim]")
        console.print()

    # ── Hostnames ──
    hosts = result.get("hostnames", [])
    if hosts:
        related = [h for h in hosts if h["related"]]
        third = [h for h in hosts if not h["related"]]
        console.print(f"  [bold]Hostnames[/bold] ({len(hosts)}: {len(related)} related, {len(third)} third-party)")
        risk_styles = {
            "high": "[bold red]HIGH[/bold red]", "medium": "[yellow]MED[/yellow]",
            "info": "[dim]info[/dim]",
        }
        for h in sorted(hosts, key=lambda x: (0 if x["risk"] == "high" else 1 if x["risk"] == "medium" else 2))[:15]:
            risk = risk_styles.get(h["risk"], "[dim]info[/dim]")
            rel = " [cyan](related)[/cyan]" if h["related"] else ""
            console.print(f"    {risk} {h['hostname']}{rel}")
        if len(hosts) > 15:
            console.print(f"    [dim]... +{len(hosts) - 15} more[/dim]")
        console.print()

    # ── Cloud Buckets ──
    buckets = result.get("cloud_buckets", [])
    if buckets:
        console.print(f"  [bold red]Cloud Buckets[/bold red] ({len(buckets)})")
        for b in buckets[:10]:
            console.print(f"    [bold red]\u26a0[/bold red] {b['provider']}: [bold]{b['bucket']}[/bold]  [dim]({b['source']})[/dim]")
        console.print()

    # ── Secrets ──
    secs = result.get("secrets", [])
    if secs:
        console.print(f"  [bold red]\u26a0 Exposed Secrets[/bold red] ({len(secs)})")
        for s in secs[:10]:
            console.print(f"    [bold red]CRITICAL[/bold red] {s['type']}: [bold]{s['value_masked']}[/bold] ({s['length']} chars)  [dim]({s['source']})[/dim]")
        console.print()

    # Summary
    total_findings = len(eps) + len(urls) + len(hosts) + len(buckets) + len(secs)
    console.print(f"  [bold]{total_findings}[/bold] total findings across JS files")
    if secs or buckets:
        console.print(f"  [bold red]\u26a0 {len(secs)} secret(s) + {len(buckets)} bucket(s) require immediate attention[/bold red]")
    console.print(f"  [dim]Test these: fray scan {target} -c xss -m 3[/dim]")
    console.print()


# ── Parameter Discovery (lightweight crawl) ──────────────────────────────

def discover_params(url: str, max_depth: int = 2, max_pages: int = 10,
                    timeout: int = 8, verify_ssl: bool = True,
                    extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Lightweight crawl + parameter extraction.

    Discovers injectable parameters from:
      - URL query strings
      - HTML form inputs (<input>, <textarea>, <select>)
      - JavaScript API endpoints (fetch, axios, XMLHttpRequest)

    Returns dict with params list and summary stats.
    """
    from fray.scanner import (
        _fetch, extract_links, extract_query_params,
        extract_forms, extract_js_endpoints, _same_origin,
    )

    parsed = urllib.parse.urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    visited = set()
    queue = [(url, 0)]
    all_params = []  # list of dicts
    seen = set()     # (url, param, method) dedup
    total_forms = 0
    total_js = 0

    while queue and len(visited) < max_pages:
        current_url, depth = queue.pop(0)
        canonical = current_url.split("?")[0].split("#")[0]
        if canonical in visited:
            continue
        visited.add(canonical)

        # Skip static resources
        lower = canonical.lower()
        if any(lower.endswith(ext) for ext in (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
            ".mp3", ".mp4", ".webp", ".avif",
        )):
            continue

        status, body, resp_headers = _fetch(current_url, timeout=timeout,
                                            verify_ssl=verify_ssl,
                                            headers=extra_headers)
        if status == 0 or not body:
            continue

        # Follow redirects
        if status in (301, 302, 307, 308):
            loc = resp_headers.get("location", "")
            if loc:
                redir_url = urllib.parse.urljoin(current_url, loc)
                if _same_origin(url, redir_url) and redir_url.split("?")[0] not in visited:
                    queue.append((redir_url, depth))
            continue

        content_type = resp_headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            continue

        # 1. Query parameters
        for pt in extract_query_params(current_url):
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "query",
                })

        # 2. HTML forms
        form_pts, fc = extract_forms(current_url, body)
        total_forms += fc
        for pt in form_pts:
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "form",
                })

        # 3. JavaScript endpoints
        js_pts, jc = extract_js_endpoints(current_url, body)
        total_js += jc
        for pt in js_pts:
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "js",
                })

        # Follow links if not at max depth
        if depth < max_depth:
            for link in extract_links(current_url, body):
                link_canon = link.split("?")[0].split("#")[0]
                if link_canon not in visited and _same_origin(url, link):
                    queue.append((link, depth + 1))

    return {
        "params": all_params,
        "pages_crawled": len(visited),
        "total_params": len(all_params),
        "forms_found": total_forms,
        "js_endpoints": total_js,
        "sources": {
            "query": sum(1 for p in all_params if p["source"] == "query"),
            "form": sum(1 for p in all_params if p["source"] == "form"),
            "js": sum(1 for p in all_params if p["source"] == "js"),
        },
    }
