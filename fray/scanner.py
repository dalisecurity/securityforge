#!/usr/bin/env python3
"""
Fray Scanner — Auto Recon → Crawl → Param Discovery → Payload Injection

Automated attack surface mapping:
  1. Crawl — spider target, follow same-origin links
  2. Parameter discovery — extract query params, form inputs, JS endpoints
  3. Endpoint map — deduplicate and classify injection points
  4. Payload injection — test each discovered parameter with WAFTester

Usage:
    fray scan https://example.com
    fray scan https://example.com --depth 3 --max-pages 50
    fray scan https://example.com --category xss --json
"""

import http.client
import json
import re
import socket
import ssl
import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class InjectionPoint:
    """A single parameter that can be tested for injection."""
    url: str
    param: str
    method: str = "GET"            # GET or POST
    source: str = "query"          # query | form | js | path
    context: str = ""              # e.g. "login form", "search box"

    def __hash__(self):
        return hash((self.url, self.param, self.method))

    def __eq__(self, other):
        return (self.url, self.param, self.method) == (other.url, other.param, other.method)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "source": self.source,
            "context": self.context,
        }


@dataclass
class CrawlResult:
    """Result of crawling + parameter discovery."""
    target: str
    pages_crawled: int = 0
    endpoints: List[str] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    forms_found: int = 0
    js_endpoints: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_crawled": self.pages_crawled,
            "total_endpoints": len(self.endpoints),
            "total_injection_points": len(self.injection_points),
            "forms_found": self.forms_found,
            "js_endpoints": self.js_endpoints,
            "endpoints": self.endpoints,
            "injection_points": [ip.to_dict() for ip in self.injection_points],
            "errors": self.errors,
        }


@dataclass
class ScanResult:
    """Full scan result: crawl + test results."""
    target: str
    crawl: Optional[CrawlResult] = None
    test_results: List[dict] = field(default_factory=list)
    total_tested: int = 0
    total_blocked: int = 0
    total_passed: int = 0
    total_reflected: int = 0
    duration: str = "N/A"

    def to_dict(self) -> dict:
        block_rate = f"{(self.total_blocked / self.total_tested * 100):.1f}%" if self.total_tested else "0%"
        return {
            "target": self.target,
            "crawl": self.crawl.to_dict() if self.crawl else {},
            "summary": {
                "total_tested": self.total_tested,
                "blocked": self.total_blocked,
                "passed": self.total_passed,
                "reflected": self.total_reflected,
                "block_rate": block_rate,
            },
            "test_results": self.test_results,
            "duration": self.duration,
        }


# ── HTTP fetcher (stdlib only) ───────────────────────────────────────────

# ── Rate limit backoff state ──────────────────────────────────────────

_backoff_delay: float = 0.0       # extra delay added on 429
_BACKOFF_MAX: float = 30.0        # cap


def _fetch(url: str, timeout: int = 8, verify_ssl: bool = True,
           headers: Optional[Dict[str, str]] = None,
           _retry: int = 0) -> Tuple[int, str, Dict[str, str]]:
    """Fetch a URL and return (status, body, response_headers).

    Uses http.client for zero external dependencies.
    Automatically backs off on 429 (rate limit) responses.
    """
    global _backoff_delay

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        port = port or 443
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        req_headers.update(headers)

    # Apply backoff delay if we've been rate-limited previously
    if _backoff_delay > 0:
        time.sleep(_backoff_delay)

    try:
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read(500_000).decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}

        # Auto-backoff on 429
        if resp.status == 429 and _retry < 3:
            retry_after = resp_headers.get("retry-after", "")
            try:
                wait = min(int(retry_after), 30) if retry_after.isdigit() else 0
            except (ValueError, AttributeError):
                wait = 0
            _backoff_delay = max(wait, _backoff_delay * 2 if _backoff_delay > 0 else 2.0)
            _backoff_delay = min(_backoff_delay, _BACKOFF_MAX)
            time.sleep(_backoff_delay)
            conn.close()
            return _fetch(url, timeout=timeout, verify_ssl=verify_ssl,
                          headers=headers, _retry=_retry + 1)

        # Decay backoff on success
        if resp.status < 400 and _backoff_delay > 0:
            _backoff_delay = max(0.0, _backoff_delay * 0.5)
            if _backoff_delay < 0.1:
                _backoff_delay = 0.0

        return resp.status, body, resp_headers
    except Exception:
        return 0, "", {}
    finally:
        conn.close()


# ── Link extraction ──────────────────────────────────────────────────────

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)', re.IGNORECASE)
_JS_URL_RE = re.compile(
    r"""(?:"""
    r"""fetch\s*\(\s*['"]([^'"]+)['"]"""        # fetch("url")
    r"""|\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""  # xhr.open("GET","url")
    r"""|axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]"""  # axios.get("url")
    r"""|['"](/api/[^'"]+)['"]"""               # "/api/..."
    r"""|['"](/v\d+/[^'"]+)['"]"""              # "/v1/..."
    r""")""",
    re.IGNORECASE,
)

_FORM_RE = re.compile(
    r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL
)
_FORM_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)', re.IGNORECASE)
_INPUT_RE = re.compile(
    r'<(?:input|textarea|select)[^>]*\bname\s*=\s*["\']([^"\']+)',
    re.IGNORECASE,
)


def _same_origin(base: str, url: str) -> bool:
    """Check if url is same origin as base."""
    bp = urlparse(base)
    up = urlparse(url)
    return up.scheme in ("", bp.scheme) and (up.netloc == "" or up.netloc == bp.netloc)


def _normalize_url(base: str, href: str) -> Optional[str]:
    """Resolve relative URL and normalize. Returns None if off-origin."""
    if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    full = urljoin(base, href)
    parsed = urlparse(full)
    # Strip fragment
    normalized = parsed._replace(fragment="").geturl()
    return normalized


def extract_links(base_url: str, html: str) -> Set[str]:
    """Extract same-origin links from HTML."""
    from html import unescape
    links = set()
    for match in _HREF_RE.finditer(html):
        href = unescape(match.group(1).strip())
        url = _normalize_url(base_url, href)
        if url and _same_origin(base_url, url):
            links.add(url)
    return links


def extract_query_params(url: str) -> List[InjectionPoint]:
    """Extract injection points from URL query parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    points = []
    # Base URL without query
    base = parsed._replace(query="", fragment="").geturl()
    for param_name in params:
        points.append(InjectionPoint(
            url=base,
            param=param_name,
            method="GET",
            source="query",
            context=f"query param in {parsed.path}",
        ))
    return points


def extract_forms(base_url: str, html: str) -> Tuple[List[InjectionPoint], int]:
    """Extract injection points from HTML forms. Returns (points, form_count)."""
    points = []
    form_count = 0
    for form_match in _FORM_RE.finditer(html):
        form_count += 1
        form_html = form_match.group(0)
        # Action
        action_match = _FORM_ACTION_RE.search(form_html)
        action = action_match.group(1) if action_match else ""
        form_url = _normalize_url(base_url, action) or base_url
        # Method
        method_match = _FORM_METHOD_RE.search(form_html)
        method = (method_match.group(1).upper() if method_match else "GET")
        if method not in ("GET", "POST"):
            method = "POST"
        # Input names
        for input_match in _INPUT_RE.finditer(form_html):
            param_name = input_match.group(1)
            # Skip common non-injectable fields
            if param_name.lower() in ("csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
                                       "submit", "button", "captcha", "g-recaptcha-response"):
                continue
            points.append(InjectionPoint(
                url=form_url,
                param=param_name,
                method=method,
                source="form",
                context=f"form → {urlparse(form_url).path}",
            ))
    return points, form_count


def extract_js_endpoints(base_url: str, html: str) -> Tuple[List[InjectionPoint], int]:
    """Extract API endpoints from inline/embedded JavaScript."""
    points = []
    js_count = 0
    seen = set()
    for match in _JS_URL_RE.finditer(html):
        # Pick first non-None group
        endpoint = next((g for g in match.groups() if g), None)
        if not endpoint:
            continue
        url = _normalize_url(base_url, endpoint)
        if not url or not _same_origin(base_url, url):
            continue
        if url in seen:
            continue
        seen.add(url)
        js_count += 1
        # Extract params if present
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base = parsed._replace(query="", fragment="").geturl()
        if params:
            for param_name in params:
                points.append(InjectionPoint(
                    url=base,
                    param=param_name,
                    method="GET",
                    source="js",
                    context=f"JS endpoint {parsed.path}",
                ))
        else:
            # API endpoint without params — try common param names
            for common_param in ("id", "q", "query", "search", "input", "name"):
                points.append(InjectionPoint(
                    url=base,
                    param=common_param,
                    method="GET",
                    source="js",
                    context=f"JS endpoint {parsed.path} (inferred param)",
                ))
    return points, js_count


# ── robots.txt / sitemap.xml seeding ─────────────────────────────────

def parse_robots_txt(base_url: str, body: str) -> List[str]:
    """Extract paths from robots.txt Disallow / Allow lines."""
    paths: List[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        for directive in ("Disallow:", "Allow:", "Sitemap:"):
            if line.startswith(directive):
                value = line[len(directive):].strip()
                if value and not value.startswith("#"):
                    if directive == "Sitemap:":
                        # Sitemap is a full URL
                        if _same_origin(base_url, value):
                            paths.append(value)
                    else:
                        # Disallow / Allow are paths
                        if value != "/" and "*" not in value:
                            url = _normalize_url(base_url, value)
                            if url:
                                paths.append(url)
                break
    return paths


def parse_sitemap_xml(base_url: str, body: str) -> List[str]:
    """Extract URLs from a sitemap.xml body."""
    urls: List[str] = []
    for match in re.finditer(r'<loc>\s*([^<]+?)\s*</loc>', body, re.IGNORECASE):
        url = match.group(1).strip()
        if _same_origin(base_url, url):
            urls.append(url)
    return urls


def _seed_from_robots_and_sitemap(
    base_url: str, timeout: int = 8, verify_ssl: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Fetch robots.txt and sitemap.xml to discover additional seed URLs."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    seeds: List[str] = []

    # robots.txt
    status, body, _ = _fetch(f"{origin}/robots.txt", timeout=timeout,
                              verify_ssl=verify_ssl, headers=headers)
    if status == 200 and body:
        seeds.extend(parse_robots_txt(origin, body))

    # sitemap.xml
    status, body, _ = _fetch(f"{origin}/sitemap.xml", timeout=timeout,
                              verify_ssl=verify_ssl, headers=headers)
    if status == 200 and body:
        seeds.extend(parse_sitemap_xml(origin, body))

    return seeds


# ── Crawler ──────────────────────────────────────────────────────────────

def crawl(target: str, max_depth: int = 3, max_pages: int = 30,
          delay: float = 0.3, timeout: int = 8,
          verify_ssl: bool = True,
          headers: Optional[Dict[str, str]] = None,
          quiet: bool = False) -> CrawlResult:
    """Crawl target, discover endpoints and injection points.

    Automatically seeds crawl queue from robots.txt and sitemap.xml.

    Args:
        target: Base URL to crawl.
        max_depth: Maximum link depth to follow.
        max_pages: Maximum pages to fetch.
        delay: Delay between requests.
        timeout: Request timeout.
        verify_ssl: Verify SSL certificates.
        headers: Optional custom headers.
        quiet: Suppress progress output.

    Returns:
        CrawlResult with discovered endpoints and injection points.
    """
    global _backoff_delay
    _backoff_delay = 0.0  # reset backoff state per scan

    result = CrawlResult(target=target)
    visited: Set[str] = set()
    injection_points: Set[InjectionPoint] = set()
    # (url, depth) queue
    queue: List[Tuple[str, int]] = [(target, 0)]

    # Seed from robots.txt and sitemap.xml
    seed_urls = _seed_from_robots_and_sitemap(target, timeout=timeout,
                                               verify_ssl=verify_ssl, headers=headers)
    for seed in seed_urls:
        queue.append((seed, 1))

    if not quiet:
        from fray.output import console
        console.print()
        console.rule(f"[bold]Crawling [cyan]{target}[/cyan][/bold]")

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)

        # Normalize to avoid re-visiting same page with different fragment
        parsed = urlparse(url)
        canonical = parsed._replace(fragment="").geturl()
        if canonical in visited:
            continue
        visited.add(canonical)

        # Skip non-HTML resources
        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
        if ext in ("css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
                    "woff", "woff2", "ttf", "eot", "pdf", "zip", "mp4", "webp"):
            continue

        if not quiet:
            from fray.output import console
            console.print(f"  [dim][{len(visited):>3}][/dim] {canonical[:80]}")

        status, body, resp_headers = _fetch(url, timeout=timeout,
                                             verify_ssl=verify_ssl, headers=headers)
        if status == 0:
            result.errors.append(f"Failed to fetch {url}")
            continue

        # Follow redirects (301/302/307/308)
        if status in (301, 302, 307, 308):
            location = resp_headers.get("location", "")
            if location:
                redir_url = _normalize_url(url, location)
                if redir_url and _same_origin(target, redir_url) and redir_url not in visited:
                    queue.append((redir_url, depth))
            continue

        if status >= 400:
            continue

        result.endpoints.append(canonical)

        # Extract query params from current URL
        qp = extract_query_params(canonical)
        for p in qp:
            injection_points.add(p)

        # Extract forms
        form_points, form_count = extract_forms(canonical, body)
        result.forms_found += form_count
        for p in form_points:
            injection_points.add(p)

        # Extract JS endpoints
        js_points, js_count = extract_js_endpoints(canonical, body)
        result.js_endpoints += js_count
        for p in js_points:
            injection_points.add(p)

        # Discover links for next depth
        if depth < max_depth:
            for link in extract_links(canonical, body):
                if link not in visited:
                    queue.append((link, depth + 1))

        if delay > 0:
            time.sleep(delay)

    result.pages_crawled = len(visited)
    result.injection_points = sorted(injection_points,
                                      key=lambda p: (p.url, p.param))

    if not quiet:
        from fray.output import console
        console.print(
            f"\n  [bold green]✓[/bold green] Crawled {result.pages_crawled} pages, "
            f"found {len(result.injection_points)} injection points "
            f"({result.forms_found} forms, {result.js_endpoints} JS endpoints)"
        )

    return result


# ── Full scan: crawl → inject ────────────────────────────────────────────

def run_scan(target: str, category: str = "xss", max_payloads: int = 5,
             max_depth: int = 3, max_pages: int = 30,
             delay: float = 0.5, timeout: int = 8,
             verify_ssl: bool = True,
             custom_headers: Optional[Dict[str, str]] = None,
             quiet: bool = False,
             jitter: float = 0.0,
             stealth: bool = False,
             rate_limit: float = 0.0) -> ScanResult:
    """Full automated scan: crawl → discover params → inject payloads.

    Args:
        target: Target URL.
        category: Payload category for injection testing.
        max_payloads: Max payloads to test per injection point.
        max_depth: Crawl depth.
        max_pages: Max pages to crawl.
        delay: Delay between requests.
        timeout: Request timeout.
        verify_ssl: Verify SSL certs.
        custom_headers: Optional custom headers.
        quiet: Suppress rich output.
        jitter: Random delay variance.
        stealth: Stealth mode.
        rate_limit: Max req/s.

    Returns:
        ScanResult with crawl data and test results.
    """
    from datetime import datetime
    from fray import PAYLOADS_DIR
    from fray.tester import WAFTester

    start = datetime.now()
    scan = ScanResult(target=target)

    # Phase 1: Crawl
    crawl_result = crawl(
        target, max_depth=max_depth, max_pages=max_pages,
        delay=delay, timeout=timeout, verify_ssl=verify_ssl,
        headers=custom_headers, quiet=quiet,
    )
    scan.crawl = crawl_result

    if not crawl_result.injection_points:
        if not quiet:
            from fray.output import console
            console.print("\n  [yellow]⚠ No injection points discovered.[/yellow]")
        elapsed = datetime.now() - start
        scan.duration = f"{int(elapsed.total_seconds())}s"
        return scan

    # Phase 2: Load payloads
    category_dir = PAYLOADS_DIR / category
    payloads = []
    if category_dir.is_dir():
        for pf in sorted(category_dir.glob("*.json")):
            try:
                data = json.loads(pf.read_text(encoding="utf-8"))
                plist = data.get("payloads", data) if isinstance(data, dict) else data
                if isinstance(plist, list):
                    payloads.extend(plist)
            except Exception:
                pass

    if not payloads:
        if not quiet:
            from fray.output import console
            console.print(f"\n  [yellow]⚠ No payloads found for category '{category}'[/yellow]")
        elapsed = datetime.now() - start
        scan.duration = f"{int(elapsed.total_seconds())}s"
        return scan

    # Limit payloads per injection point
    test_payloads = payloads[:max_payloads]

    if not quiet:
        from fray.output import console
        console.print()
        console.rule("[bold]Payload Injection[/bold]")
        console.print(
            f"  Testing {len(crawl_result.injection_points)} injection points "
            f"× {len(test_payloads)} {category} payloads"
        )
        console.print()

    # Phase 3: Test each injection point
    all_results = []
    for idx, ip in enumerate(crawl_result.injection_points, 1):
        tester = WAFTester(
            target=ip.url,
            timeout=timeout,
            delay=delay,
            verify_ssl=verify_ssl,
            custom_headers=custom_headers or None,
            jitter=jitter,
            stealth=stealth,
            rate_limit=rate_limit,
        )
        if not quiet:
            from fray.output import console, blocked_text, passed_text
            console.print(
                f"  [dim][{idx}/{len(crawl_result.injection_points)}][/dim] "
                f"[bold]{ip.method}[/bold] {ip.url} "
                f"[cyan]?{ip.param}=[/cyan] "
                f"[dim]({ip.source})[/dim]"
            )

        for payload_data in test_payloads:
            payload = payload_data.get("payload", payload_data) if isinstance(payload_data, dict) else str(payload_data)
            result = tester.test_payload(payload, method=ip.method, param=ip.param)
            result["injection_point"] = ip.to_dict()
            result["category"] = category
            all_results.append(result)

            if not quiet:
                from fray.output import blocked_text, passed_text
                badge = blocked_text() if result["blocked"] else passed_text()
                label = payload[:50] if isinstance(payload, str) else str(payload)[:50]
                reflected_tag = " [bold magenta]↩ REFLECTED[/bold magenta]" if result.get("reflected") else ""
                console.print(f"    ", badge, f" {result['status']} │ {label}{reflected_tag}", highlight=False)

            tester._stealth_delay()

    scan.test_results = all_results
    scan.total_tested = len(all_results)
    scan.total_blocked = sum(1 for r in all_results if r.get("blocked"))
    scan.total_passed = scan.total_tested - scan.total_blocked
    scan.total_reflected = sum(1 for r in all_results if r.get("reflected"))

    elapsed = datetime.now() - start
    minutes = int(elapsed.total_seconds() // 60)
    seconds = int(elapsed.total_seconds() % 60)
    scan.duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    return scan


# ── Rich output ──────────────────────────────────────────────────────────

def print_scan_result(scan: ScanResult) -> None:
    """Print scan results using rich."""
    from fray.output import console, make_summary_table
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    # Crawl summary
    if scan.crawl:
        cr = scan.crawl
        tbl = make_summary_table()
        tbl.add_row("Target", scan.target)
        tbl.add_row("Pages Crawled", str(cr.pages_crawled))
        tbl.add_row("Endpoints", str(len(cr.endpoints)))
        tbl.add_row("Injection Points", Text(str(len(cr.injection_points)), style="bold cyan"))
        tbl.add_row("Forms", str(cr.forms_found))
        tbl.add_row("JS Endpoints", str(cr.js_endpoints))
        console.print()
        console.print(Panel(tbl, title="[bold]Crawl Results[/bold]",
                            border_style="bright_cyan", expand=False))

    # Injection point map
    if scan.crawl and scan.crawl.injection_points:
        ip_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        ip_table.add_column("#", style="dim", width=4)
        ip_table.add_column("Method", style="bold", width=6)
        ip_table.add_column("URL", style="cyan", max_width=50)
        ip_table.add_column("Param", style="bold yellow")
        ip_table.add_column("Source", style="dim")

        for i, ip in enumerate(scan.crawl.injection_points, 1):
            ip_table.add_row(
                str(i), ip.method,
                ip.url[:50] + ("…" if len(ip.url) > 50 else ""),
                ip.param, ip.source,
            )

        console.print()
        console.print(Panel(ip_table, title="[bold]Endpoint Map[/bold]",
                            border_style="yellow", expand=False))

    # Test summary
    if scan.total_tested > 0:
        block_rate = scan.total_blocked / scan.total_tested * 100
        tbl2 = make_summary_table()
        tbl2.add_row("Duration", scan.duration)
        tbl2.add_row("Total Tested", str(scan.total_tested))
        tbl2.add_row("Blocked", Text(str(scan.total_blocked), style="bold red"))
        tbl2.add_row("Passed", Text(str(scan.total_passed), style="bold green"))
        tbl2.add_row("Reflected", Text(str(scan.total_reflected), style="bold magenta"))
        tbl2.add_row("Block Rate", Text(f"{block_rate:.1f}%", style="bold"))
        console.print()
        console.print(Panel(tbl2, title="[bold]Scan Summary[/bold]",
                            border_style="bright_green", expand=False))

        # Show passed (bypassed) payloads if any
        # Show reflected payloads (confirmed XSS) first
        reflected = [r for r in scan.test_results if r.get("reflected") and not r.get("blocked")]
        if reflected:
            ref_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            ref_table.add_column("URL", style="cyan", max_width=40)
            ref_table.add_column("Param", style="yellow")
            ref_table.add_column("Status", style="bold")
            ref_table.add_column("Payload", style="red", max_width=40)
            ref_table.add_column("Context", style="dim", max_width=30)

            for r in reflected[:20]:
                ip_info = r.get("injection_point", {})
                ref_table.add_row(
                    ip_info.get("url", "")[:40],
                    ip_info.get("param", ""),
                    str(r.get("status", "")),
                    r.get("payload", "")[:40],
                    r.get("reflection_context", "")[:30],
                )

            console.print()
            console.print(Panel(ref_table,
                                title="[bold magenta]↩ Reflected (Confirmed Injection)[/bold magenta]",
                                border_style="magenta", expand=False))

        # Show passed (bypassed) payloads
        passed = [r for r in scan.test_results if not r.get("blocked")]
        if passed:
            bypass_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            bypass_table.add_column("URL", style="cyan", max_width=40)
            bypass_table.add_column("Param", style="yellow")
            bypass_table.add_column("Status", style="bold")
            bypass_table.add_column("Payload", style="red", max_width=50)

            for r in passed[:20]:
                ip_info = r.get("injection_point", {})
                bypass_table.add_row(
                    ip_info.get("url", "")[:40],
                    ip_info.get("param", ""),
                    str(r.get("status", "")),
                    r.get("payload", "")[:50],
                )

            console.print()
            console.print(Panel(bypass_table, title="[bold red]⚠ Bypassed (Not Blocked)[/bold red]",
                                border_style="red", expand=False))
    else:
        console.print("\n  [dim]No payloads tested (no injection points found).[/dim]")
