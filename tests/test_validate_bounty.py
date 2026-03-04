#!/usr/bin/env python3
"""
Tests for fray validate and fray bounty modules.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from fray.validate import (
    SECURITY_HEADERS,
    WAF_RECOMMENDATIONS,
    DEFAULT_RECOMMENDATIONS,
    _fetch_headers,
    calculate_grade,
    grade_color,
    run_validate,
)
from fray.bounty import (
    HackerOnePublic,
    BugcrowdPublic,
    SHARED_PLATFORMS,
    _ASSET_CAPABILITY,
    normalize_scope_to_urls,
    load_urls_from_file,
    is_safe_target,
    filter_safe_targets,
    analyze_scope,
    scan_target,
    run_bounty,
)
from fray import __version__


# ══════════════════════════════════════════════════════════════════════════════
# Validate Module Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders(unittest.TestCase):

    def test_all_headers_have_required_keys(self):
        for key, hdr in SECURITY_HEADERS.items():
            self.assertIn("name", hdr)
            self.assertIn("description", hdr)
            self.assertIn("weight", hdr)
            self.assertIn("recommended", hdr)
            self.assertIn("check", hdr)
            self.assertTrue(callable(hdr["check"]))

    def test_hsts_check_valid(self):
        check = SECURITY_HEADERS["strict-transport-security"]["check"]
        self.assertTrue(check("max-age=31536000; includeSubDomains; preload"))
        self.assertTrue(check("max-age=63072000"))

    def test_hsts_check_weak(self):
        check = SECURITY_HEADERS["strict-transport-security"]["check"]
        self.assertFalse(check("max-age=3600"))

    def test_csp_check_valid(self):
        check = SECURITY_HEADERS["content-security-policy"]["check"]
        self.assertTrue(check("default-src 'self'"))
        self.assertTrue(check("script-src 'self' 'nonce-abc'"))

    def test_csp_check_empty(self):
        check = SECURITY_HEADERS["content-security-policy"]["check"]
        self.assertFalse(check(""))

    def test_xcto_check(self):
        check = SECURITY_HEADERS["x-content-type-options"]["check"]
        self.assertTrue(check("nosniff"))
        self.assertFalse(check("sniff"))

    def test_xfo_check(self):
        check = SECURITY_HEADERS["x-frame-options"]["check"]
        self.assertTrue(check("DENY"))
        self.assertTrue(check("SAMEORIGIN"))
        self.assertFalse(check("ALLOW-FROM https://example.com"))

    def test_referrer_policy_check(self):
        check = SECURITY_HEADERS["referrer-policy"]["check"]
        self.assertTrue(check("no-referrer"))
        self.assertTrue(check("strict-origin-when-cross-origin"))
        self.assertFalse(check("unsafe-url"))


class TestWAFRecommendations(unittest.TestCase):

    def test_cloudflare_recommendations_exist(self):
        self.assertIn("cloudflare", WAF_RECOMMENDATIONS)
        self.assertGreater(len(WAF_RECOMMENDATIONS["cloudflare"]["checks"]), 0)

    def test_aws_recommendations_exist(self):
        self.assertIn("aws_waf", WAF_RECOMMENDATIONS)

    def test_imperva_recommendations_exist(self):
        self.assertIn("imperva", WAF_RECOMMENDATIONS)

    def test_akamai_recommendations_exist(self):
        self.assertIn("akamai", WAF_RECOMMENDATIONS)

    def test_default_recommendations(self):
        self.assertGreater(len(DEFAULT_RECOMMENDATIONS), 0)
        for rec in DEFAULT_RECOMMENDATIONS:
            self.assertIn("name", rec)
            self.assertIn("description", rec)
            self.assertIn("category", rec)

    def test_each_recommendation_has_fields(self):
        for waf_key, waf_data in WAF_RECOMMENDATIONS.items():
            for rec in waf_data["checks"]:
                self.assertIn("name", rec, f"{waf_key} missing name")
                self.assertIn("description", rec, f"{waf_key} missing description")
                self.assertIn("category", rec, f"{waf_key} missing category")


class TestCalculateGrade(unittest.TestCase):

    def test_perfect_score(self):
        grade, score = calculate_grade(48, 100.0, True)
        self.assertEqual(grade, "A")
        self.assertEqual(score, 100)

    def test_no_waf_no_headers(self):
        grade, score = calculate_grade(0, 0, False)
        self.assertEqual(grade, "F")
        self.assertEqual(score, 0)

    def test_good_headers_good_waf(self):
        grade, score = calculate_grade(40, 90.0, True)
        self.assertIn(grade[0], ("A", "B"))

    def test_waf_detected_bonus(self):
        _, score_with = calculate_grade(20, 50.0, True)
        _, score_without = calculate_grade(20, 50.0, False)
        self.assertGreater(score_with, score_without)

    def test_grade_boundaries(self):
        grade_a, _ = calculate_grade(48, 100.0, True)
        self.assertEqual(grade_a, "A")
        grade_f, _ = calculate_grade(0, 0.0, False)
        self.assertEqual(grade_f, "F")


class TestGradeColor(unittest.TestCase):

    def test_grade_a(self):
        self.assertIn("92", grade_color("A"))   # GREEN

    def test_grade_b(self):
        self.assertIn("94", grade_color("B+"))  # BLUE

    def test_grade_c(self):
        self.assertIn("93", grade_color("C"))   # YELLOW

    def test_grade_f(self):
        self.assertIn("91", grade_color("F"))   # RED


class TestFetchHeaders(unittest.TestCase):

    @patch("fray.validate.http.client.HTTPSConnection")
    def test_fetch_headers_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheaders.return_value = [
            ("Content-Type", "text/html"),
            ("X-Frame-Options", "DENY"),
        ]
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        status, headers = _fetch_headers("https://example.com")
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-frame-options"], "DENY")


class TestCLIValidate(unittest.TestCase):

    def test_validate_help(self):
        from fray.cli import main
        with patch("sys.argv", ["fray", "validate", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)


# ══════════════════════════════════════════════════════════════════════════════
# Bounty Module Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalizeScopeToUrls(unittest.TestCase):

    def test_domain(self):
        scopes = [{"identifier": "example.com", "type": "DOMAIN"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["https://example.com"])

    def test_wildcard(self):
        scopes = [{"identifier": "*.example.com", "type": "WILDCARD"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["https://example.com"])

    def test_full_url(self):
        scopes = [{"identifier": "https://api.example.com", "type": "URL"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["https://api.example.com"])

    def test_http_url(self):
        scopes = [{"identifier": "http://legacy.example.com", "type": "URL"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["http://legacy.example.com"])

    def test_dedup(self):
        scopes = [
            {"identifier": "example.com", "type": "DOMAIN"},
            {"identifier": "https://example.com", "type": "URL"},
        ]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(len(urls), 1)

    def test_skip_wildcard_only(self):
        scopes = [{"identifier": "*", "type": "WILDCARD"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, [])

    def test_empty(self):
        urls = normalize_scope_to_urls([])
        self.assertEqual(urls, [])

    def test_port_preserved(self):
        scopes = [{"identifier": "https://api.example.com:8443", "type": "URL"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["https://api.example.com:8443"])

    def test_standard_port_stripped(self):
        scopes = [{"identifier": "https://example.com:443", "type": "URL"}]
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(urls, ["https://example.com"])


class TestLoadUrlsFromFile(unittest.TestCase):

    def test_load_valid_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("https://example.com\nhttps://test.com\n# comment\n\n")
            f.flush()
            urls = load_urls_from_file(f.name)
        os.unlink(f.name)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://example.com", urls)

    def test_adds_scheme(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            f.flush()
            urls = load_urls_from_file(f.name)
        os.unlink(f.name)
        self.assertEqual(urls, ["https://example.com"])

    def test_skips_comments(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# this is a comment\nhttps://real.com\n")
            f.flush()
            urls = load_urls_from_file(f.name)
        os.unlink(f.name)
        self.assertEqual(len(urls), 1)

    def test_nonexistent_file(self):
        urls = load_urls_from_file("/tmp/nonexistent_fray_urls_file.txt")
        self.assertEqual(urls, [])


class TestHackerOnePublic(unittest.TestCase):

    @patch("fray.bounty.http.client.HTTPSConnection")
    def test_get_scope_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "team": {
                    "id": "abc123",
                    "name": "Example",
                    "structured_scopes": {
                        "edges": [
                            {
                                "node": {
                                    "asset_type": "URL",
                                    "asset_identifier": "api.example.com",
                                    "eligible_for_submission": True,
                                    "eligible_for_bounty": True,
                                    "instruction": "Main API",
                                }
                            },
                            {
                                "node": {
                                    "asset_type": "URL",
                                    "asset_identifier": "*.example.com",
                                    "eligible_for_submission": True,
                                    "eligible_for_bounty": False,
                                    "instruction": "",
                                }
                            },
                        ]
                    }
                }
            }
        }).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = HackerOnePublic()
        ok, scopes = api.get_program_scope("example")
        self.assertTrue(ok)
        self.assertEqual(len(scopes), 2)
        self.assertEqual(scopes[0]["identifier"], "api.example.com")
        self.assertTrue(scopes[0]["bounty"])
        self.assertFalse(scopes[1]["bounty"])

    @patch("fray.bounty.http.client.HTTPSConnection")
    def test_get_scope_not_found(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {"team": None},
            "errors": [{"message": "Team not found"}]
        }).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = HackerOnePublic()
        ok, scopes = api.get_program_scope("nonexistent")
        self.assertFalse(ok)

    @patch("fray.bounty.http.client.HTTPSConnection")
    def test_filters_non_web_assets(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "team": {
                    "id": "abc",
                    "name": "Test",
                    "structured_scopes": {
                        "edges": [
                            {"node": {"asset_type": "URL", "asset_identifier": "web.com",
                                      "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": ""}},
                            {"node": {"asset_type": "OTHER", "asset_identifier": "Mobile App",
                                      "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": ""}},
                            {"node": {"asset_type": "HARDWARE", "asset_identifier": "Device",
                                      "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": ""}},
                        ]
                    }
                }
            }
        }).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = HackerOnePublic()
        ok, scopes = api.get_program_scope("test")
        self.assertTrue(ok)
        # Now returns ALL asset types (URL, OTHER, HARDWARE)
        self.assertEqual(len(scopes), 3)
        # But normalize_scope_to_urls filters to web-only
        urls = normalize_scope_to_urls(scopes)
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0], "https://web.com")


class TestBugcrowdPublic(unittest.TestCase):

    @patch("fray.bounty.http.client.HTTPSConnection")
    def test_get_scope_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "target_groups": [
                {
                    "targets": [
                        {"name": "Main App", "uri": "https://app.example.com", "category": "website"}
                    ]
                }
            ]
        }).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = BugcrowdPublic()
        ok, scopes = api.get_program_scope("example")
        self.assertTrue(ok)
        self.assertEqual(len(scopes), 1)

    @patch("fray.bounty.http.client.HTTPSConnection")
    def test_get_scope_not_found(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b'{"error": "not found"}'
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = BugcrowdPublic()
        ok, scopes = api.get_program_scope("nonexistent")
        self.assertFalse(ok)


class TestIsSafeTarget(unittest.TestCase):

    def test_normal_domain_safe(self):
        ok, reason = is_safe_target("https://superbet.ro")
        self.assertTrue(ok)

    def test_shared_github_blocked(self):
        ok, reason = is_safe_target("https://github.com")
        self.assertFalse(ok)
        self.assertIn("shared", reason)

    def test_shared_subdomain_blocked(self):
        ok, reason = is_safe_target("https://myapp.herokuapp.com")
        self.assertFalse(ok)

    def test_shared_s3_blocked(self):
        ok, reason = is_safe_target("https://mybucket.s3.amazonaws.com")
        self.assertFalse(ok)

    def test_shared_cloudfront_blocked(self):
        ok, reason = is_safe_target("https://d123.cloudfront.net")
        self.assertFalse(ok)

    def test_shared_vercel_blocked(self):
        ok, reason = is_safe_target("https://myapp.vercel.app")
        self.assertFalse(ok)

    def test_shared_salesforce_blocked(self):
        ok, reason = is_safe_target("https://company.salesforce.com")
        self.assertFalse(ok)

    def test_program_owned_override_github(self):
        ok, reason = is_safe_target("https://github.com", program_handle="github")
        self.assertTrue(ok)
        self.assertIn("program-owned", reason)

    def test_program_owned_subdomain(self):
        ok, reason = is_safe_target("https://api.github.com", program_handle="github")
        self.assertTrue(ok)

    def test_program_owned_npmjs(self):
        ok, reason = is_safe_target("https://npmjs.com", program_handle="github")
        self.assertTrue(ok)

    def test_program_owned_shopify(self):
        ok, reason = is_safe_target("https://shopify.com", program_handle="shopify")
        self.assertTrue(ok)

    def test_program_owned_slack(self):
        ok, reason = is_safe_target("https://slack.com", program_handle="slack")
        self.assertTrue(ok)

    def test_github_blocked_for_other_program(self):
        ok, reason = is_safe_target("https://github.com", program_handle="superbet")
        self.assertFalse(ok)

    def test_invalid_url(self):
        ok, reason = is_safe_target("")
        self.assertFalse(ok)


class TestFilterSafeTargets(unittest.TestCase):

    def test_filters_shared(self):
        urls = [
            "https://superbet.ro",
            "https://github.com",
            "https://superbet.com",
            "https://myapp.herokuapp.com",
        ]
        safe, skipped = filter_safe_targets(urls, "superbet")
        self.assertEqual(len(safe), 2)
        self.assertEqual(len(skipped), 2)
        self.assertIn("https://superbet.ro", safe)
        self.assertIn("https://superbet.com", safe)

    def test_github_program_keeps_github(self):
        urls = ["https://github.com", "https://api.github.com", "https://npmjs.com"]
        safe, skipped = filter_safe_targets(urls, "github")
        self.assertEqual(len(safe), 3)
        self.assertEqual(len(skipped), 0)

    def test_all_shared_returns_empty(self):
        urls = ["https://github.com", "https://herokuapp.com"]
        safe, skipped = filter_safe_targets(urls, "random_company")
        self.assertEqual(len(safe), 0)
        self.assertEqual(len(skipped), 2)


class TestSharedPlatformsList(unittest.TestCase):

    def test_has_major_providers(self):
        for domain in ["github.com", "amazonaws.com", "herokuapp.com",
                       "vercel.app", "netlify.app", "salesforce.com"]:
            self.assertIn(domain, SHARED_PLATFORMS)

    def test_is_set(self):
        self.assertIsInstance(SHARED_PLATFORMS, set)


class TestAnalyzeScope(unittest.TestCase):

    def test_classifies_full(self):
        scopes = [
            {"type": "URL", "identifier": "https://example.com", "bounty": True, "instruction": ""},
            {"type": "DOMAIN", "identifier": "api.example.com", "bounty": True, "instruction": ""},
        ]
        analysis = analyze_scope(scopes)
        self.assertEqual(len(analysis["full"]), 2)
        self.assertEqual(len(analysis["partial"]), 0)
        self.assertEqual(len(analysis["none"]), 0)

    def test_classifies_partial(self):
        scopes = [
            {"type": "WILDCARD", "identifier": "*.example.com", "bounty": True, "instruction": ""},
            {"type": "CIDR", "identifier": "10.0.0.0/24", "bounty": True, "instruction": ""},
        ]
        analysis = analyze_scope(scopes)
        self.assertEqual(len(analysis["partial"]), 2)

    def test_classifies_none(self):
        scopes = [
            {"type": "GOOGLE_PLAY_APP_ID", "identifier": "com.test.app", "bounty": True, "instruction": ""},
            {"type": "APPLE_STORE_APP_ID", "identifier": "12345", "bounty": True, "instruction": ""},
            {"type": "SOURCE_CODE", "identifier": "https://github.com/org/repo", "bounty": True, "instruction": ""},
        ]
        analysis = analyze_scope(scopes)
        self.assertEqual(len(analysis["none"]), 3)

    def test_mixed_scope(self):
        scopes = [
            {"type": "URL", "identifier": "https://app.com", "bounty": True, "instruction": ""},
            {"type": "WILDCARD", "identifier": "*.app.com", "bounty": True, "instruction": ""},
            {"type": "GOOGLE_PLAY_APP_ID", "identifier": "com.app", "bounty": True, "instruction": ""},
            {"type": "HARDWARE", "identifier": "Server", "bounty": False, "instruction": ""},
        ]
        analysis = analyze_scope(scopes)
        self.assertEqual(len(analysis["full"]), 1)
        self.assertEqual(len(analysis["partial"]), 1)
        self.assertEqual(len(analysis["none"]), 2)
        self.assertEqual(analysis["total"], 4)
        self.assertEqual(analysis["testable_count"], 2)

    def test_detects_vpn_note(self):
        scopes = [
            {"type": "URL", "identifier": "https://app.ro", "bounty": True, "instruction": "Use Romanian VPN"},
        ]
        analysis = analyze_scope(scopes)
        self.assertIn("VPN required", analysis["full"][0]["notes"])

    def test_detects_user_agent_note(self):
        scopes = [
            {"type": "URL", "identifier": "https://app.com", "bounty": True,
             "instruction": "Add User-Agent: hackerone header"},
        ]
        analysis = analyze_scope(scopes)
        self.assertIn("Custom User-Agent required", analysis["full"][0]["notes"])

    def test_detects_credentials_note(self):
        scopes = [
            {"type": "URL", "identifier": "https://app.com", "bounty": True,
             "instruction": "Use test account: user1 password123"},
        ]
        analysis = analyze_scope(scopes)
        self.assertIn("Test credentials provided", analysis["full"][0]["notes"])

    def test_shared_platform_flagged(self):
        scopes = [
            {"type": "URL", "identifier": "https://github.com", "bounty": True, "instruction": ""},
        ]
        analysis = analyze_scope(scopes, program_handle="random_company")
        self.assertFalse(analysis["full"][0]["safe"])

    def test_program_owned_not_flagged(self):
        scopes = [
            {"type": "URL", "identifier": "https://github.com", "bounty": True, "instruction": ""},
        ]
        analysis = analyze_scope(scopes, program_handle="github")
        self.assertTrue(analysis["full"][0]["safe"])

    def test_asset_capability_map_complete(self):
        expected_types = {"URL", "DOMAIN", "WILDCARD", "CIDR", "OTHER",
                          "SMART_CONTRACT", "APPLE_STORE_APP_ID",
                          "GOOGLE_PLAY_APP_ID", "DOWNLOADABLE_EXECUTABLES",
                          "SOURCE_CODE", "HARDWARE", "WINDOWS_APP_STORE_APP_ID"}
        for t in expected_types:
            self.assertIn(t, _ASSET_CAPABILITY)


class TestBountyNoArgs(unittest.TestCase):

    def test_no_args_shows_help(self):
        import io
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            run_bounty()
        self.assertIn("--program", captured.getvalue())

    def test_unknown_platform(self):
        import io
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            run_bounty(platform="unknown", program="test")
        self.assertIn("Unknown", captured.getvalue())

    def test_platform_aliases(self):
        """Verify h1/bc aliases are accepted (mocked to avoid network)."""
        with patch.object(HackerOnePublic, 'get_program_scope', return_value=(True, [])):
            import io
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                run_bounty(platform="h1", program="test")
            self.assertIn("hackerone", captured.getvalue().lower())


class TestCLIBounty(unittest.TestCase):

    def test_bounty_help(self):
        from fray.cli import main
        with patch("sys.argv", ["fray", "bounty", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
