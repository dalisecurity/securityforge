"""Tests for fray.recon — reconnaissance and fingerprinting functions."""

import pytest
from unittest.mock import patch, MagicMock
from fray.recon import (
    _parse_version,
    check_frontend_libs,
    fingerprint_app,
    check_security_headers,
    check_cookies,
    diff_recon,
)


# ── _parse_version ──────────────────────────────────────────────────────

class TestParseVersion:
    def test_standard_version(self):
        assert _parse_version("3.5.0") == (3, 5, 0)

    def test_prerelease(self):
        assert _parse_version("4.0.0-rc1") == (4, 0, 0)

    def test_two_digit(self):
        assert _parse_version("12.34.56") == (12, 34, 56)

    def test_invalid_empty(self):
        assert _parse_version("") == (0, 0, 0)

    def test_invalid_garbage(self):
        assert _parse_version("abc") == (0, 0, 0)

    def test_partial_version(self):
        assert _parse_version("1.2") == (0, 0, 0)

    def test_comparison_ordering(self):
        assert _parse_version("2.2.4") < _parse_version("3.0.0")
        assert _parse_version("3.5.0") < _parse_version("3.5.1")
        assert _parse_version("4.17.4") < _parse_version("4.17.21")
        assert _parse_version("3.5.0") == _parse_version("3.5.0")


# ── check_frontend_libs ────────────────────────────────────────────────

class TestCheckFrontendLibs:
    def test_empty_body(self):
        result = check_frontend_libs("")
        assert result["total_libs"] == 0
        assert result["vulnerable_libs"] == 0
        assert result["libraries"] == []
        assert result["vulnerabilities"] == []

    def test_none_body(self):
        result = check_frontend_libs(None)
        assert result["total_libs"] == 0

    def test_no_scripts(self):
        result = check_frontend_libs("<html><body>Hello</body></html>")
        assert result["total_libs"] == 0

    def test_cdnjs_jquery_vulnerable(self):
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["vulnerable_libs"] == 1
        libs = result["libraries"]
        assert libs[0]["name"] == "jquery"
        assert libs[0]["version"] == "2.2.4"
        assert len(libs[0]["cves"]) > 0
        # Should have CVE-2020-11022 (affects < 3.5.0)
        cve_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2020-11022" in cve_ids
        assert "CVE-2020-11023" in cve_ids

    def test_cdnjs_jquery_clean(self):
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["vulnerable_libs"] == 0
        assert result["libraries"][0]["cves"] == []

    def test_jsdelivr_lodash_vulnerable(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.4/lodash.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["vulnerable_libs"] == 1
        cve_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2019-10744" in cve_ids  # critical: prototype pollution

    def test_unpkg_pattern(self):
        body = '<script src="https://unpkg.com/react@16.3.0/umd/react.production.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["libraries"][0]["name"] == "react"
        assert result["libraries"][0]["version"] == "16.3.0"

    def test_googleapis_pattern(self):
        body = '<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["libraries"][0]["version"] == "1.11.3"
        # 1.11.3 < 1.12.0 — should have CVE-2012-6708
        cve_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2012-6708" in cve_ids

    def test_bootstrapcdn_pattern(self):
        body = '<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["libraries"][0]["name"] == "bootstrap"
        assert result["libraries"][0]["version"] == "3.3.7"
        cve_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2019-8331" in cve_ids

    def test_jquery_com_pattern(self):
        body = '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["total_libs"] == 1
        assert result["libraries"][0]["name"] == "jquery"
        assert result["libraries"][0]["version"] == "3.6.0"

    def test_multiple_libs(self):
        body = '''
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.4/lodash.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.0/moment.min.js"></script>
        '''
        result = check_frontend_libs(body)
        assert result["total_libs"] == 3
        assert result["vulnerable_libs"] == 3
        lib_names = [l["name"] for l in result["libraries"]]
        assert "jquery" in lib_names
        assert "lodash" in lib_names
        assert "moment" in lib_names

    def test_cve_deduplication(self):
        # Same lib should not produce duplicate CVEs
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        cve_ids = [v["id"] for v in result["vulnerabilities"]]
        assert len(cve_ids) == len(set(cve_ids))

    def test_severity_fields(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.4/lodash.min.js"></script>'
        result = check_frontend_libs(body)
        for v in result["vulnerabilities"]:
            assert "severity" in v
            assert "id" in v
            assert "summary" in v
            assert "library" in v
            assert "version" in v
            assert "fix_below" in v
            assert v["severity"] in ("critical", "high", "medium", "low")

    def test_clean_modern_libs(self):
        body = '''
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/4.0.0/jquery.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.30.1/moment.min.js"></script>
        '''
        result = check_frontend_libs(body)
        assert result["total_libs"] == 3
        assert result["vulnerable_libs"] == 0
        assert result["vulnerabilities"] == []

    def test_scoped_npm_package(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"></script>'
        result = check_frontend_libs(body)
        # Should detect the lib (core) even if no CVE match
        assert result["total_libs"] >= 1

    def test_source_field_cdn_url(self):
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["libraries"][0]["source"] == "cdn_url"

    def test_sri_missing(self):
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'
        result = check_frontend_libs(body)
        assert result["sri_missing"] == 1
        assert result["sri_present"] == 0
        assert len(result["sri_issues"]) == 1
        assert result["libraries"][0]["has_sri"] is False

    def test_sri_present(self):
        body = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" integrity="sha384-abc123" crossorigin="anonymous"></script>'
        result = check_frontend_libs(body)
        assert result["sri_present"] == 1
        assert result["sri_missing"] == 0
        assert result["sri_issues"] == []
        assert result["libraries"][0]["has_sri"] is True
        assert result["libraries"][0]["sri_hash"] == "sha384-abc123"

    def test_sri_mixed(self):
        body = '''
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" integrity="sha384-xyz"></script>
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
        '''
        result = check_frontend_libs(body)
        assert result["sri_present"] == 1
        assert result["sri_missing"] == 1
        assert len(result["sri_issues"]) == 1
        assert result["sri_issues"][0]["library"] == "lodash"

    def test_sri_empty_body(self):
        result = check_frontend_libs("")
        assert result["sri_missing"] == 0
        assert result["sri_present"] == 0
        assert result["sri_issues"] == []


# ── fingerprint_app ─────────────────────────────────────────────────────

class TestFingerprintApp:
    def test_empty_inputs(self):
        result = fingerprint_app({}, "")
        assert result["primary"] is None
        assert result["technologies"] == {}
        assert result["all"] == []

    def test_php_header(self):
        result = fingerprint_app({"x-powered-by": "PHP/8.2"}, "")
        assert "php" in result["technologies"]
        assert result["primary"] == "php"

    def test_express_header(self):
        result = fingerprint_app({"x-powered-by": "Express"}, "")
        assert "express" in result["technologies"]

    def test_nginx_server(self):
        result = fingerprint_app({"server": "nginx/1.24.0"}, "")
        assert "nginx" in result["technologies"]

    def test_apache_server(self):
        result = fingerprint_app({"server": "Apache/2.4.57"}, "")
        assert "apache" in result["technologies"]

    def test_wordpress_body(self):
        result = fingerprint_app({}, '<link href="/wp-content/themes/test/style.css">')
        assert "wordpress" in result["technologies"]

    def test_react_body(self):
        result = fingerprint_app({}, '<div id="root"></div><script>__NEXT_DATA__</script>')
        assert "react" in result["technologies"]

    def test_angular_body(self):
        result = fingerprint_app({}, '<div ng-app="myApp"></div>')
        assert "angular" in result["technologies"]

    def test_django_body(self):
        result = fingerprint_app({}, '<input name="csrfmiddlewaretoken" value="abc123">')
        assert "python" in result["technologies"]

    def test_cookie_php(self):
        result = fingerprint_app({"set-cookie": "PHPSESSID=abc123; path=/"}, "")
        assert "php" in result["technologies"]

    def test_cookie_python(self):
        result = fingerprint_app({"set-cookie": "csrftoken=abc123; path=/"}, "")
        assert "python" in result["technologies"]

    def test_multiple_signals(self):
        result = fingerprint_app(
            {"server": "nginx", "x-powered-by": "PHP/8.2"},
            '<link href="/wp-content/themes/default/style.css">'
        )
        assert "nginx" in result["technologies"]
        assert "php" in result["technologies"]
        assert "wordpress" in result["technologies"]

    def test_confidence_ordering(self):
        result = fingerprint_app(
            {"x-powered-by": "PHP/8.2", "set-cookie": "PHPSESSID=abc"},
            '<link href="/wp-content/">'
        )
        techs = result["technologies"]
        # PHP should have higher confidence (header 0.7 + cookie 0.6)
        assert techs["php"] >= techs.get("wordpress", 0)

    def test_api_json_content_type(self):
        result = fingerprint_app({"content-type": "application/json"}, "")
        assert "api_json" in result["technologies"]

    def test_drupal_header(self):
        result = fingerprint_app({"x-drupal-cache": "HIT"}, "")
        assert "drupal" in result["technologies"]

    def test_iis_server(self):
        result = fingerprint_app({"server": "Microsoft-IIS/10.0"}, "")
        assert "iis" in result["technologies"]


# ── check_security_headers ──────────────────────────────────────────────

class TestCheckSecurityHeaders:
    def test_no_headers(self):
        result = check_security_headers({})
        assert result["score"] == 0
        assert len(result["missing"]) > 0
        assert len(result["present"]) == 0

    def test_all_present(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1; mode=block",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        }
        result = check_security_headers(headers)
        assert result["score"] == 100
        assert len(result["present"]) == 9
        assert len(result["missing"]) == 0

    def test_partial(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }
        result = check_security_headers(headers)
        assert 0 < result["score"] < 100
        assert len(result["present"]) == 2
        assert len(result["missing"]) > 0


# ── check_cookies ───────────────────────────────────────────────────────

class TestCheckCookies:
    def test_no_cookies(self):
        result = check_cookies({})
        assert result["cookies"] == []
        assert result["score"] == 100

    def test_secure_cookie(self):
        result = check_cookies({
            "set-cookie": "session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/"
        })
        assert len(result["cookies"]) == 1
        c = result["cookies"][0]
        assert c["name"] == "session"
        assert c["httponly"] is True
        assert c["secure"] is True
        assert result["score"] == 100

    def test_insecure_cookie(self):
        result = check_cookies({
            "set-cookie": "session=abc123; Path=/"
        })
        assert len(result["cookies"]) == 1
        # Missing HttpOnly, Secure, SameSite → issues
        assert len(result["issues"]) >= 2
        assert result["score"] < 100

    def test_multiple_cookies(self):
        result = check_cookies({
            "set-cookie": "a=1; HttpOnly; Secure, b=2; Path=/"
        })
        assert len(result["cookies"]) == 2

    def test_missing_httponly_flagged(self):
        result = check_cookies({
            "set-cookie": "token=xyz; Secure; SameSite=Strict"
        })
        issues = [i for i in result["issues"] if "HttpOnly" in i["issue"]]
        assert len(issues) == 1

    def test_samesite_none_without_secure(self):
        result = check_cookies({
            "set-cookie": "sid=abc; SameSite=None"
        })
        issues = [i for i in result["issues"] if "SameSite=None" in i["issue"]]
        assert len(issues) == 1


# ── check_dns (mocked subprocess) ───────────────────────────────────────

class TestCheckDns:
    @patch("subprocess.run")
    def test_basic_dns(self, mock_run):
        from fray.recon import check_dns

        def fake_dig(cmd, **kwargs):
            rtype = cmd[2]  # ["dig", "+short", RTYPE, host]
            outputs = {
                "A": "1.2.3.4\n",
                "AAAA": "",
                "CNAME": "cdn.example.com.\n",
                "MX": "10 mail.example.com.\n",
                "TXT": "v=spf1 include:_spf.google.com ~all\n",
                "NS": "ns1.example.com.\nns2.example.com.\n",
            }
            result = MagicMock()
            result.stdout = outputs.get(rtype, "")
            return result

        mock_run.side_effect = fake_dig

        result = check_dns("example.com")
        assert "a" in result
        assert "1.2.3.4" in result["a"]
        assert "ns" in result
        assert len(result["ns"]) == 2

    @patch("subprocess.run")
    def test_cdn_detection(self, mock_run):
        from fray.recon import check_dns

        def fake_dig(cmd, **kwargs):
            rtype = cmd[2]
            outputs = {
                "A": "104.16.132.229\n",
                "CNAME": "example.com.cdn.cloudflare.net.\n",
                "NS": "ns1.cloudflare.com.\nns2.cloudflare.com.\n",
            }
            result = MagicMock()
            result.stdout = outputs.get(rtype, "")
            return result

        mock_run.side_effect = fake_dig

        result = check_dns("example.com")
        assert result["cdn_detected"] == "cloudflare"

    @patch("subprocess.run")
    def test_dns_failure(self, mock_run):
        from fray.recon import check_dns

        mock_run.side_effect = Exception("DNS timeout")
        result = check_dns("nonexistent.invalid")
        assert isinstance(result, dict)
        assert result["a"] == []

    @patch("subprocess.run")
    def test_deep_mode_extra_records(self, mock_run):
        from fray.recon import check_dns

        called_types = []

        def fake_dig(cmd, **kwargs):
            rtype = cmd[2]
            called_types.append(rtype)
            result = MagicMock()
            result.stdout = ""
            return result

        mock_run.side_effect = fake_dig

        check_dns("example.com", deep=True)
        assert "SOA" in called_types
        assert "CAA" in called_types

    @patch("subprocess.run")
    def test_default_mode_no_soa_caa(self, mock_run):
        from fray.recon import check_dns

        called_types = []

        def fake_dig(cmd, **kwargs):
            rtype = cmd[2]
            called_types.append(rtype)
            result = MagicMock()
            result.stdout = ""
            return result

        mock_run.side_effect = fake_dig

        check_dns("example.com", deep=False)
        assert "SOA" not in called_types
        assert "CAA" not in called_types


# ── diff_recon ──────────────────────────────────────────────────────────

class TestDiffRecon:
    def _base_result(self, **overrides):
        base = {
            "host": "example.com",
            "timestamp": "2026-03-06T00:00:00+00:00",
            "attack_surface": {"risk_score": 30, "risk_level": "MEDIUM", "waf_vendor": "cloudflare",
                               "origin_ip_exposed": False},
            "fingerprint": {"technologies": {"php": 0.8, "nginx": 0.7}},
            "subdomains": {"subdomains": ["api.example.com", "www.example.com"]},
            "frontend_libs": {"vulnerable_libs": 0, "sri_missing": 1, "vulnerabilities": []},
            "headers": {"score": 67},
            "tls": {"tls_version": "TLSv1.3", "cert_days_remaining": 90},
            "dns": {"a": ["1.2.3.4"]},
        }
        base.update(overrides)
        return base

    def test_no_changes(self):
        a = self._base_result()
        b = self._base_result()
        diff = diff_recon(a, b)
        assert diff["total_changes"] == 0
        assert diff["changes"] == []

    def test_risk_score_change(self):
        old = self._base_result()
        new = self._base_result(
            attack_surface={"risk_score": 60, "risk_level": "HIGH", "waf_vendor": "cloudflare",
                            "origin_ip_exposed": False},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "risk_score" in fields
        assert "risk_level" in fields

    def test_new_subdomains(self):
        old = self._base_result()
        new = self._base_result(
            subdomains={"subdomains": ["api.example.com", "www.example.com", "staging.example.com"]},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "subdomains_added" in fields
        added = next(c for c in diff["changes"] if c["field"] == "subdomains_added")
        assert "staging.example.com" in added["new"]

    def test_waf_vendor_change(self):
        old = self._base_result()
        new = self._base_result(
            attack_surface={"risk_score": 30, "risk_level": "MEDIUM", "waf_vendor": "akamai",
                            "origin_ip_exposed": False},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "waf_vendor" in fields

    def test_new_cves(self):
        old = self._base_result()
        new = self._base_result(
            frontend_libs={"vulnerable_libs": 1, "sri_missing": 1,
                           "vulnerabilities": [{"id": "CVE-2020-11022"}]},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "cves_new" in fields
        assert "vulnerable_frontend_libs" in fields

    def test_dns_change(self):
        old = self._base_result()
        new = self._base_result(
            dns={"a": ["5.6.7.8"]},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "dns_a_changed" in fields

    def test_origin_ip_exposed(self):
        old = self._base_result()
        new = self._base_result(
            attack_surface={"risk_score": 80, "risk_level": "CRITICAL", "waf_vendor": "cloudflare",
                            "origin_ip_exposed": True},
            timestamp="2026-03-07T00:00:00+00:00",
        )
        diff = diff_recon(new, old)
        fields = [c["field"] for c in diff["changes"]]
        assert "origin_ip_exposed" in fields
        assert diff["high_severity_changes"] >= 1
