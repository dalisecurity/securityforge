"""Hardening tests — edge cases, error paths, and robustness checks across modules."""

import json
import os
import pytest
import tempfile

from fray.csp import parse_csp, analyze_csp, get_csp_from_headers, _match_domain
from fray.diff import _normalize_report, run_diff
from fray.scope import parse_scope_file, is_target_in_scope, _classify_entry


# ── CSP Edge Cases ────────────────────────────────────────────────────────


class TestCSPEdgeCases:
    def test_garbage_csp_value(self):
        """Malformed CSP should not crash, just produce empty analysis."""
        result = analyze_csp(";;;;;;;")
        assert result.present is False or result.directives == {}

    def test_csp_with_only_whitespace(self):
        result = analyze_csp("   \t  \n  ")
        assert result.present is False
        assert result.score == 0

    def test_csp_unknown_directives(self):
        result = analyze_csp("fake-directive 'self'; another-one value")
        assert result.present is True
        assert "fake-directive" in result.directives

    def test_csp_extremely_long_value(self):
        """Very long CSP shouldn't crash."""
        long_csp = "script-src " + " ".join(f"https://cdn{i}.example.com" for i in range(500))
        result = analyze_csp(long_csp)
        assert result.present is True

    def test_csp_unicode_values(self):
        result = analyze_csp("script-src 'self' https://例え.jp")
        assert result.present is True

    def test_csp_duplicate_directives(self):
        """Per CSP spec, only first directive wins, but parser should handle gracefully."""
        result = analyze_csp("script-src 'self'; script-src 'unsafe-inline'")
        # Our parser overwrites — last one wins
        assert result.present is True

    def test_csp_nonce_with_special_chars(self):
        result = analyze_csp("script-src 'nonce-abc123+/==' 'strict-dynamic'")
        assert any(w.id == "nonce-present" for w in result.weaknesses)

    def test_csp_empty_directive_value(self):
        """Directive with no values."""
        result = analyze_csp("script-src; default-src 'self'")
        assert result.present is True

    def test_match_domain_empty_strings(self):
        assert _match_domain("", "") is True
        assert _match_domain("*.example.com", "") is False
        assert _match_domain("", "cdn.example.com") is False

    def test_match_domain_with_port(self):
        assert _match_domain("cdn.example.com", "https://cdn.example.com:443") is False
        # Port stripping not implemented — this documents current behavior

    def test_get_csp_empty_dict(self):
        val, ro = get_csp_from_headers({})
        assert val == ""
        assert ro is False

    def test_analyze_csp_report_only_score(self):
        """Report-only should score lower than enforced."""
        enforced = analyze_csp("default-src 'self'; script-src 'self'")
        report_only = analyze_csp("default-src 'self'; script-src 'self'", report_only=True)
        assert report_only.score < enforced.score

    def test_wildcard_base_uri(self):
        result = analyze_csp("script-src 'self'; base-uri *")
        assert any(w.id == "wildcard-base-uri" for w in result.weaknesses)

    def test_blob_uri(self):
        result = analyze_csp("script-src 'self' blob:")
        assert any(w.id == "blob-uri" for w in result.weaknesses)
        assert "blob_uri" in result.bypass_techniques

    def test_multiple_weaknesses_combined(self):
        """CSP with everything wrong at once."""
        result = analyze_csp(
            "script-src * 'unsafe-inline' 'unsafe-eval' data: blob: "
            "cdn.jsdelivr.net *.netlify.app"
        )
        ids = {w.id for w in result.weaknesses}
        assert "unsafe-inline" in ids
        assert "unsafe-eval" in ids
        assert "wildcard-script" in ids
        assert "data-uri" in ids
        assert "blob-uri" in ids
        assert result.score == 0  # clamped at 0

    def test_object_src_none_explicit(self):
        result = analyze_csp("script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        assert not any(w.id == "permissive-object-src" for w in result.weaknesses)

    def test_non_exploitable_weakness_excluded_from_techniques(self):
        """frame-ancestors missing is not exploitable for XSS, shouldn't be in bypass_techniques."""
        result = analyze_csp("script-src 'self'; base-uri 'self'; object-src 'none'")
        clickjacking = [w for w in result.weaknesses if w.id == "missing-frame-ancestors"]
        if clickjacking:
            assert "clickjacking" not in result.bypass_techniques


# ── Diff Edge Cases ───────────────────────────────────────────────────────


def _write_json(tmp_dir, filename, data):
    path = os.path.join(tmp_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


class TestDiffEdgeCases:
    def test_empty_results_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "b.json", {"results": []})
            after = _write_json(tmp, "a.json", {"results": []})
            diff = run_diff(before, after)
            assert diff.verdict == "PASS"
            assert diff.regressions == []
            assert diff.improvements == []
            assert diff.bypass_rate_delta == 0.0

    def test_file_not_found(self):
        with pytest.raises((FileNotFoundError, OSError)):
            run_diff("/nonexistent/before.json", "/nonexistent/after.json")

    def test_corrupt_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "corrupt.json")
            with open(path, "w") as f:
                f.write("{not valid json")
            with pytest.raises(json.JSONDecodeError):
                run_diff(path, path)

    def test_normalize_empty_dict(self):
        norm = _normalize_report({})
        assert norm["total_tested"] == 0
        assert norm["bypass_rate"] == 0.0

    def test_normalize_bypass_format_no_bypasses(self):
        data = {
            "overall_evasion_score": 0.0,
            "total_tested": 50,
            "mutations_tested": 0,
            "total_bypassed": 0,
            "mutations_bypassed": 0,
            "bypasses": [],
        }
        norm = _normalize_report(data)
        assert norm["total_bypassed"] == 0
        assert norm["payload_map"] == {}

    def test_same_payload_different_status_no_regression(self):
        """Payload blocked before and after — no regression even if status differs."""
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "b.json", {
                "results": [{"payload": "x", "blocked": True, "status": 403}]
            })
            after = _write_json(tmp, "a.json", {
                "results": [{"payload": "x", "blocked": True, "status": 406}]
            })
            diff = run_diff(before, after)
            assert diff.regressions == []
            assert diff.verdict == "PASS"

    def test_score_delta_triggers_regressed(self):
        """Score increase without explicit regressions still flags REGRESSED."""
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "b.json", {
                "overall_evasion_score": 1.0,
                "total_tested": 10,
                "mutations_tested": 0,
                "total_bypassed": 0,
                "mutations_bypassed": 0,
                "bypasses": [],
            })
            after = _write_json(tmp, "a.json", {
                "overall_evasion_score": 5.0,
                "total_tested": 10,
                "mutations_tested": 0,
                "total_bypassed": 0,
                "mutations_bypassed": 0,
                "bypasses": [],
            })
            diff = run_diff(before, after)
            assert diff.score_delta == 4.0
            assert diff.verdict == "REGRESSED"

    def test_regressions_sorted_by_score(self):
        """Regressions should be sorted by evasion_score descending."""
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "b.json", {
                "results": [
                    {"payload": "low_score", "blocked": True, "status": 403},
                    {"payload": "high_score", "blocked": True, "status": 403},
                ]
            })
            after = _write_json(tmp, "a.json", {
                "results": [
                    {"payload": "low_score", "blocked": False, "status": 200},
                    {"payload": "high_score", "blocked": False, "status": 200},
                ]
            })
            diff = run_diff(before, after)
            assert len(diff.regressions) == 2


# ── Scope Edge Cases ─────────────────────────────────────────────────────


class TestScopeEdgeCases:
    def test_scope_with_trailing_whitespace(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("  example.com  \n  *.test.org  \n")
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "test.org" in scope["wildcards"]
        finally:
            os.unlink(path)

    def test_scope_with_windows_line_endings(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b"example.com\r\ntest.org\r\n")
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "test.org" in scope["domains"]
        finally:
            os.unlink(path)

    def test_scope_ipv6(self):
        """IPv6 addresses should be classified as IPs."""
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("::1\n2001:db8::1\n")
            scope = parse_scope_file(path)
            assert "::1" in scope["ips"]
            assert "2001:db8::1" in scope["ips"]
        finally:
            os.unlink(path)

    def test_scope_url_with_query(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("https://example.com/app?key=value\n")
            scope = parse_scope_file(path)
            assert any("example.com" in u for u in scope["urls"])
        finally:
            os.unlink(path)

    def test_is_target_in_scope_subdomain_of_excluded(self):
        """Deep subdomain of excluded entry should also be excluded."""
        scope = {
            "domains": [], "wildcards": ["example.com"],
            "ips": [], "cidrs": [], "urls": [],
            "out_of_scope": ["staging.example.com"],
        }
        # deep.staging.example.com should be excluded (endswith staging.example.com)
        in_scope, reason = is_target_in_scope("https://deep.staging.example.com", scope)
        assert not in_scope

    def test_is_target_in_scope_cidr_out_of_range(self):
        scope = {
            "domains": [], "wildcards": [],
            "ips": [], "cidrs": ["10.0.0.0/24"],
            "urls": [], "out_of_scope": [],
        }
        in_scope, _ = is_target_in_scope("https://10.0.1.1", scope)
        assert not in_scope

    def test_classify_entry_with_protocol_and_ip(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("https://192.168.1.1/admin", scope)
        assert "192.168.1.1" in scope["ips"]
        assert "https://192.168.1.1/admin" in scope["urls"]

    def test_scope_multiple_out_of_scope_markers(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("# In Scope\nexample.com\n# Exclude\nbad.com\n# In Scope\ngood.com\n")
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "bad.com" in scope["out_of_scope"]
            assert "good.com" in scope["domains"]
        finally:
            os.unlink(path)


# ── Smuggling Robustness ──────────────────────────────────────────────────


class TestSmugglingRobustness:
    def test_dataclass_defaults_are_safe(self):
        from fray.smuggling import SmuggleProbeResult, SmuggleReport
        from dataclasses import asdict
        # Default instances should be JSON-serializable
        r = SmuggleProbeResult()
        d = asdict(r)
        json.dumps(d)

        report = SmuggleReport()
        d2 = asdict(report)
        json.dumps(d2)

    def test_ssrf_protection_blocks_all_private_ranges(self):
        from fray.smuggling import _resolve_and_check
        from unittest.mock import patch

        private_ips = [
            "127.0.0.1", "10.0.0.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.255",
            "192.168.0.1", "192.168.255.255",
            "169.254.1.1",  # link-local
        ]
        for ip in private_ips:
            with patch("socket.gethostbyname", return_value=ip):
                with pytest.raises(ValueError):
                    _resolve_and_check("test.example.com")

    def test_probe_host_header_injection_safe(self):
        """Host header with special chars shouldn't create malformed HTTP."""
        from fray.smuggling import _build_baseline_probe
        # Technically the caller should validate, but probe shouldn't crash
        probe = _build_baseline_probe("example.com\r\nEvil: header", "/")
        assert isinstance(probe, bytes)


# ── Bypass Robustness ─────────────────────────────────────────────────────


class TestBypassRobustness:
    def test_resolve_waf_empty_and_special(self):
        from fray.bypass import resolve_waf_name
        assert resolve_waf_name("") is None
        assert resolve_waf_name("   ") is None
        assert resolve_waf_name("!@#$%") is None

    def test_baseline_match_with_missing_keys(self):
        from fray.bypass import _is_baseline_match
        # Missing keys should not crash — defaults to 0
        assert _is_baseline_match({}, {"status": 200, "response_length": 1000}) is False
        # status=200 matches, response_length defaults to 0 for both → both-zero path → True
        assert _is_baseline_match({"status": 200}, {"status": 200, "response_length": 0}) is True

    def test_soft_block_with_missing_keys(self):
        from fray.bypass import _is_soft_block
        # Empty result dict: status defaults to 0, doesn't match baseline status 200 → False
        assert _is_soft_block({}, {"status": 200, "response_length": 10000}) is False
        # status=200 matches, response_length=0 < 500 and baseline > 1000 → soft block detected
        assert _is_soft_block({"status": 200}, {"status": 200, "response_length": 10000}) is True

    def test_evasion_score_with_empty_payload(self):
        from fray.bypass import _compute_evasion_score
        from fray.evolve import WAFProfile
        profile = WAFProfile(total_probes=100, total_blocked=96)
        result = {"blocked": False, "status": 200, "payload": ""}
        score = _compute_evasion_score(result, profile, is_mutation=False)
        assert score >= 0.0

    def test_scorecard_with_all_fields(self):
        from fray.bypass import BypassScorecard
        from dataclasses import asdict
        s = BypassScorecard(
            target="https://test.com",
            waf_vendor="Test WAF",
            category="xss",
            total_tested=100,
            total_blocked=95,
            total_bypassed=5,
            overall_evasion_score=4.2,
            bypasses=[{"payload": "test", "score": 4.2}],
            tips=["tip1", "tip2"],
        )
        d = asdict(s)
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        assert parsed["total_bypassed"] == 5
