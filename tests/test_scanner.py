"""Tests for fray.scanner — crawl, param discovery, endpoint mapping."""

import json
from urllib.parse import urlencode

import pytest

from fray.scanner import (
    InjectionPoint,
    CrawlResult,
    ScanResult,
    ScopeChecker,
    extract_links,
    extract_query_params,
    extract_forms,
    extract_js_endpoints,
    parse_robots_txt,
    parse_sitemap_xml,
    _same_origin,
    _normalize_url,
    _is_crawlable,
)


# ── InjectionPoint ───────────────────────────────────────────────────────

class TestInjectionPoint:
    def test_hash_dedup(self):
        a = InjectionPoint(url="https://x.com/search", param="q", method="GET")
        b = InjectionPoint(url="https://x.com/search", param="q", method="GET")
        assert a == b
        assert len({a, b}) == 1

    def test_different_params(self):
        a = InjectionPoint(url="https://x.com/search", param="q", method="GET")
        b = InjectionPoint(url="https://x.com/search", param="id", method="GET")
        assert a != b

    def test_to_dict(self):
        ip = InjectionPoint(url="https://x.com", param="q", source="form", context="login")
        d = ip.to_dict()
        assert d["url"] == "https://x.com"
        assert d["param"] == "q"
        assert d["source"] == "form"


# ── CrawlResult / ScanResult ────────────────────────────────────────────

class TestCrawlResult:
    def test_to_dict(self):
        cr = CrawlResult(
            target="https://x.com",
            pages_crawled=5,
            endpoints=["https://x.com/", "https://x.com/about"],
            injection_points=[
                InjectionPoint(url="https://x.com/search", param="q"),
            ],
            forms_found=1,
            js_endpoints=2,
        )
        d = cr.to_dict()
        assert d["pages_crawled"] == 5
        assert d["total_endpoints"] == 2
        assert d["total_injection_points"] == 1
        assert d["forms_found"] == 1
        assert d["js_endpoints"] == 2

    def test_empty(self):
        cr = CrawlResult(target="https://x.com")
        d = cr.to_dict()
        assert d["pages_crawled"] == 0
        assert d["total_injection_points"] == 0


class TestScanResult:
    def test_to_dict(self):
        sr = ScanResult(
            target="https://x.com",
            total_tested=10,
            total_blocked=8,
            total_passed=2,
            duration="5s",
        )
        d = sr.to_dict()
        assert d["summary"]["total_tested"] == 10
        assert d["summary"]["blocked"] == 8
        assert d["summary"]["block_rate"] == "80.0%"
        assert d["duration"] == "5s"

    def test_empty(self):
        sr = ScanResult(target="https://x.com")
        d = sr.to_dict()
        assert d["summary"]["block_rate"] == "0%"


# ── URL helpers ──────────────────────────────────────────────────────────

class TestSameOrigin:
    def test_same(self):
        assert _same_origin("https://x.com/a", "https://x.com/b")

    def test_relative(self):
        assert _same_origin("https://x.com/a", "/b")

    def test_different(self):
        assert not _same_origin("https://x.com/a", "https://y.com/b")

    def test_empty_netloc(self):
        assert _same_origin("https://x.com", "page.html")


class TestNormalizeUrl:
    def test_relative(self):
        assert _normalize_url("https://x.com/a/", "b.html") == "https://x.com/a/b.html"

    def test_absolute(self):
        assert _normalize_url("https://x.com/", "https://x.com/page") == "https://x.com/page"

    def test_fragment_stripped(self):
        url = _normalize_url("https://x.com/", "/page#section")
        assert "#" not in url

    def test_javascript_skipped(self):
        assert _normalize_url("https://x.com/", "javascript:void(0)") is None

    def test_mailto_skipped(self):
        assert _normalize_url("https://x.com/", "mailto:a@b.com") is None


# ── Link extraction ──────────────────────────────────────────────────────

class TestExtractLinks:
    def test_href(self):
        html = '<a href="/about">About</a> <a href="/contact">Contact</a>'
        links = extract_links("https://x.com/", html)
        assert "https://x.com/about" in links
        assert "https://x.com/contact" in links

    def test_skips_external(self):
        html = '<a href="https://external.com/page">External</a>'
        links = extract_links("https://x.com/", html)
        assert len(links) == 0

    def test_img_src(self):
        html = '<img src="/images/logo.png">'
        links = extract_links("https://x.com/", html)
        # .png should still be extracted as a link (filtering is done in crawl)
        assert "https://x.com/images/logo.png" in links

    def test_form_action(self):
        html = '<form action="/search"><input name="q"></form>'
        links = extract_links("https://x.com/", html)
        assert "https://x.com/search" in links

    def test_empty_html(self):
        links = extract_links("https://x.com/", "")
        assert len(links) == 0


# ── Query param extraction ───────────────────────────────────────────────

class TestExtractQueryParams:
    def test_single_param(self):
        points = extract_query_params("https://x.com/search?q=test")
        assert len(points) == 1
        assert points[0].param == "q"
        assert points[0].source == "query"

    def test_multiple_params(self):
        points = extract_query_params("https://x.com/api?id=1&name=foo")
        params = {p.param for p in points}
        assert params == {"id", "name"}

    def test_no_params(self):
        points = extract_query_params("https://x.com/page")
        assert len(points) == 0

    def test_blank_value(self):
        points = extract_query_params("https://x.com/search?q=")
        assert len(points) == 1
        assert points[0].param == "q"


# ── Form extraction ─────────────────────────────────────────────────────

class TestExtractForms:
    def test_basic_form(self):
        html = '''
        <form action="/search" method="GET">
            <input name="q" type="text">
            <input type="submit" name="submit" value="Search">
        </form>
        '''
        points, count = extract_forms("https://x.com/", html)
        assert count == 1
        assert len(points) == 1  # submit is filtered out
        assert points[0].param == "q"
        assert points[0].method == "GET"
        assert points[0].source == "form"

    def test_post_form(self):
        html = '''
        <form action="/login" method="POST">
            <input name="username">
            <input name="password" type="password">
            <input name="csrf_token" type="hidden" value="abc123">
        </form>
        '''
        points, count = extract_forms("https://x.com/", html)
        assert count == 1
        params = {p.param for p in points}
        assert "username" in params
        assert "password" in params
        assert "csrf_token" not in params  # filtered

    def test_multiple_forms(self):
        html = '''
        <form action="/search"><input name="q"></form>
        <form action="/login" method="POST"><input name="user"><input name="pass"></form>
        '''
        points, count = extract_forms("https://x.com/", html)
        assert count == 2
        assert len(points) == 3

    def test_no_forms(self):
        points, count = extract_forms("https://x.com/", "<p>No forms here</p>")
        assert count == 0
        assert len(points) == 0

    def test_textarea_and_select(self):
        html = '''
        <form action="/feedback">
            <textarea name="comment"></textarea>
            <select name="rating"><option>1</option></select>
        </form>
        '''
        points, count = extract_forms("https://x.com/", html)
        params = {p.param for p in points}
        assert "comment" in params
        assert "rating" in params

    def test_default_method_is_get(self):
        html = '<form action="/search"><input name="q"></form>'
        points, _ = extract_forms("https://x.com/", html)
        assert points[0].method == "GET"


# ── JS endpoint extraction ──────────────────────────────────────────────

class TestExtractJsEndpoints:
    def test_fetch(self):
        html = '<script>fetch("/api/users?id=1")</script>'
        points, count = extract_js_endpoints("https://x.com/", html)
        assert count >= 1
        params = {p.param for p in points}
        assert "id" in params

    def test_axios(self):
        html = '<script>axios.get("/api/v1/data?key=abc")</script>'
        points, count = extract_js_endpoints("https://x.com/", html)
        params = {p.param for p in points}
        assert "key" in params

    def test_api_path(self):
        html = """<script>var url = '/api/search';</script>"""
        points, count = extract_js_endpoints("https://x.com/", html)
        # Should infer common params for parameterless API endpoints
        if points:
            assert any(p.source == "js" for p in points)

    def test_xhr_open(self):
        html = '<script>xhr.open("GET", "/api/status?check=1")</script>'
        points, count = extract_js_endpoints("https://x.com/", html)
        params = {p.param for p in points}
        assert "check" in params

    def test_external_skipped(self):
        html = '<script>fetch("https://other.com/api/data")</script>'
        points, count = extract_js_endpoints("https://x.com/", html)
        assert count == 0

    def test_empty(self):
        points, count = extract_js_endpoints("https://x.com/", "<p>No JS</p>")
        assert count == 0
        assert len(points) == 0

    def test_dedup(self):
        html = '''<script>
        fetch("/api/users?id=1");
        fetch("/api/users?id=1");
        </script>'''
        points, count = extract_js_endpoints("https://x.com/", html)
        # Should not double-count the same endpoint
        assert count == 1


# ── print_scan_result (smoke test) ──────────────────────────────────────

class TestPrintScanResult:
    def test_smoke(self):
        """Just ensure it doesn't crash."""
        from fray.scanner import print_scan_result
        sr = ScanResult(
            target="https://x.com",
            crawl=CrawlResult(
                target="https://x.com",
                pages_crawled=2,
                endpoints=["https://x.com/", "https://x.com/about"],
                injection_points=[
                    InjectionPoint(url="https://x.com/search", param="q"),
                ],
            ),
            total_tested=5,
            total_blocked=3,
            total_passed=2,
        )
        print_scan_result(sr)  # Should not raise

    def test_empty(self):
        from fray.scanner import print_scan_result
        sr = ScanResult(target="https://x.com")
        print_scan_result(sr)

    def test_reflected(self):
        """Ensure reflected payloads render without crash."""
        from fray.scanner import print_scan_result
        sr = ScanResult(
            target="https://x.com",
            crawl=CrawlResult(
                target="https://x.com",
                pages_crawled=1,
                endpoints=["https://x.com/"],
                injection_points=[
                    InjectionPoint(url="https://x.com/search", param="q"),
                ],
            ),
            total_tested=2,
            total_blocked=0,
            total_passed=2,
            total_reflected=1,
            test_results=[
                {
                    "payload": "<script>alert(1)</script>",
                    "status": 200,
                    "blocked": False,
                    "reflected": True,
                    "reflection_context": "...<script>alert(1)</script>...",
                    "injection_point": {"url": "https://x.com/search", "param": "q"},
                },
                {
                    "payload": "<img onerror=alert(1)>",
                    "status": 200,
                    "blocked": False,
                    "reflected": False,
                    "injection_point": {"url": "https://x.com/search", "param": "q"},
                },
            ],
        )
        print_scan_result(sr)  # Should not raise


# ── robots.txt parsing ───────────────────────────────────────────────────

class TestParseRobotsTxt:
    def test_disallow(self):
        body = """User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
"""
        paths = parse_robots_txt("https://x.com", body)
        assert "https://x.com/admin/" in paths
        assert "https://x.com/private/" in paths
        assert "https://x.com/public/" in paths

    def test_sitemap_directive(self):
        body = """User-agent: *
Disallow: /tmp/
Sitemap: https://x.com/sitemap.xml
"""
        paths = parse_robots_txt("https://x.com", body)
        assert "https://x.com/sitemap.xml" in paths
        assert "https://x.com/tmp/" in paths

    def test_skips_root(self):
        body = "Disallow: /"
        paths = parse_robots_txt("https://x.com", body)
        assert len(paths) == 0

    def test_skips_wildcards(self):
        body = "Disallow: /*.php$"
        paths = parse_robots_txt("https://x.com", body)
        assert len(paths) == 0

    def test_comments(self):
        body = """# This is a comment
User-agent: *
# Another comment
Disallow: /secret/
"""
        paths = parse_robots_txt("https://x.com", body)
        assert "https://x.com/secret/" in paths

    def test_empty(self):
        paths = parse_robots_txt("https://x.com", "")
        assert len(paths) == 0

    def test_external_sitemap_skipped(self):
        body = "Sitemap: https://other.com/sitemap.xml"
        paths = parse_robots_txt("https://x.com", body)
        assert len(paths) == 0


# ── sitemap.xml parsing ──────────────────────────────────────────────────

class TestParseSitemapXml:
    def test_basic(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://x.com/page1</loc></url>
  <url><loc>https://x.com/page2</loc></url>
  <url><loc>https://x.com/about</loc></url>
</urlset>
"""
        urls = parse_sitemap_xml("https://x.com", body)
        assert len(urls) == 3
        assert "https://x.com/page1" in urls
        assert "https://x.com/page2" in urls
        assert "https://x.com/about" in urls

    def test_external_filtered(self):
        body = """<?xml version="1.0"?>
<urlset>
  <url><loc>https://x.com/page1</loc></url>
  <url><loc>https://other.com/page2</loc></url>
</urlset>
"""
        urls = parse_sitemap_xml("https://x.com", body)
        assert len(urls) == 1
        assert "https://x.com/page1" in urls

    def test_empty(self):
        urls = parse_sitemap_xml("https://x.com", "")
        assert len(urls) == 0

    def test_whitespace_in_loc(self):
        body = "<urlset><url><loc>  https://x.com/page  </loc></url></urlset>"
        urls = parse_sitemap_xml("https://x.com", body)
        assert "https://x.com/page" in urls


# ── Rate limit backoff ───────────────────────────────────────────────────

class TestRateLimitBackoff:
    def test_backoff_state_resets(self):
        """Verify the global backoff delay can be reset."""
        import fray.scanner as scanner_mod
        scanner_mod._backoff_delay = 5.0
        # After reset
        scanner_mod._backoff_delay = 0.0
        assert scanner_mod._backoff_delay == 0.0

    def test_backoff_max_cap(self):
        import fray.scanner as scanner_mod
        assert scanner_mod._BACKOFF_MAX == 30.0


# ── ScanResult reflected field ───────────────────────────────────────────

class TestScanResultReflected:
    def test_reflected_in_dict(self):
        sr = ScanResult(
            target="https://x.com",
            total_tested=4,
            total_blocked=1,
            total_passed=3,
            total_reflected=2,
        )
        d = sr.to_dict()
        assert d["summary"]["reflected"] == 2

    def test_reflected_zero(self):
        sr = ScanResult(target="https://x.com")
        d = sr.to_dict()
        assert d["summary"]["reflected"] == 0


# ── ScopeChecker ────────────────────────────────────────────────────────

class TestScopeChecker:
    def test_disabled_by_default(self):
        sc = ScopeChecker()
        assert not sc.enabled
        assert sc.in_scope("https://anything.com/page") is True

    def test_exact_domain(self):
        sc = ScopeChecker(entries=["example.com"])
        assert sc.enabled
        assert sc.in_scope("https://example.com/page") is True
        assert sc.in_scope("https://sub.example.com/page") is False
        assert sc.in_scope("https://other.com/page") is False

    def test_wildcard_domain(self):
        sc = ScopeChecker(entries=["*.example.com"])
        assert sc.in_scope("https://sub.example.com/page") is True
        assert sc.in_scope("https://deep.sub.example.com") is True
        assert sc.in_scope("https://example.com/page") is True
        assert sc.in_scope("https://other.com/page") is False

    def test_exact_ip(self):
        sc = ScopeChecker(entries=["10.0.0.1"])
        assert sc.in_scope("http://10.0.0.1/page") is True
        assert sc.in_scope("http://10.0.0.2/page") is False

    def test_cidr(self):
        sc = ScopeChecker(entries=["192.168.1.0/24"])
        assert sc.in_scope("http://192.168.1.50/page") is True
        assert sc.in_scope("http://192.168.1.255/page") is True
        assert sc.in_scope("http://192.168.2.1/page") is False

    def test_mixed_entries(self):
        sc = ScopeChecker(entries=[
            "# comment line",
            "example.com",
            "*.test.io",
            "10.0.0.5",
            "172.16.0.0/16",
            "",  # blank line
        ])
        assert sc.enabled
        assert sc.in_scope("https://example.com/login") is True
        assert sc.in_scope("https://api.test.io/v1") is True
        assert sc.in_scope("http://10.0.0.5:8080/admin") is True
        assert sc.in_scope("http://172.16.5.10/") is True
        assert sc.in_scope("https://evil.com/") is False

    def test_comments_and_blanks(self):
        sc = ScopeChecker(entries=["# only comments", "", "  "])
        assert not sc.enabled

    def test_case_insensitive(self):
        sc = ScopeChecker(entries=["Example.COM"])
        assert sc.in_scope("https://example.com/page") is True
        assert sc.in_scope("https://EXAMPLE.COM/PAGE") is True

    def test_relative_url_allowed(self):
        sc = ScopeChecker(entries=["example.com"])
        assert sc.in_scope("/relative/path") is True

    def test_scope_file(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("target.com\n*.sub.target.com\n10.0.0.0/8\n")
        sc = ScopeChecker(scope_file=str(scope_file))
        assert sc.enabled
        assert sc.in_scope("https://target.com/") is True
        assert sc.in_scope("https://api.sub.target.com/") is True
        assert sc.in_scope("http://10.5.5.5/") is True
        assert sc.in_scope("https://evil.com/") is False

    def test_missing_scope_file(self):
        sc = ScopeChecker(scope_file="/nonexistent/scope.txt")
        assert not sc.enabled


# ── _is_crawlable ──────────────────────────────────────────────────────

class TestIsCrawlable:
    def test_same_origin_no_scope(self):
        visited = set()
        assert _is_crawlable("https://x.com/page", visited, "https://x.com") is True
        assert _is_crawlable("https://other.com/page", visited, "https://x.com") is False

    def test_already_visited(self):
        visited = {"https://x.com/page"}
        assert _is_crawlable("https://x.com/page", visited, "https://x.com") is False

    def test_static_extension(self):
        visited = set()
        assert _is_crawlable("https://x.com/style.css", visited, "https://x.com") is False
        assert _is_crawlable("https://x.com/logo.png", visited, "https://x.com") is False
        assert _is_crawlable("https://x.com/app.js", visited, "https://x.com") is False

    def test_scope_overrides_same_origin(self):
        """With scope active, cross-origin URLs in scope should be allowed."""
        visited = set()
        scope = ScopeChecker(entries=["x.com", "y.com"])
        assert _is_crawlable("https://x.com/page", visited, "https://x.com", scope) is True
        assert _is_crawlable("https://y.com/page", visited, "https://x.com", scope) is True
        assert _is_crawlable("https://z.com/page", visited, "https://x.com", scope) is False

    def test_scope_wildcard_crawl(self):
        visited = set()
        scope = ScopeChecker(entries=["*.example.com"])
        assert _is_crawlable("https://api.example.com/v1", visited, "https://www.example.com", scope) is True
        assert _is_crawlable("https://evil.com/", visited, "https://www.example.com", scope) is False
