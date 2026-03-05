"""Tests for fray.csp — CSP analysis and weakness detection."""

import pytest
from fray.csp import parse_csp, analyze_csp, get_csp_from_headers, _match_domain


class TestParseCsp:
    def test_basic_directives(self):
        d = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        assert d["default-src"] == ["self"]
        assert d["script-src"] == ["self", "https://cdn.example.com"]

    def test_empty(self):
        d = parse_csp("")
        assert d == {}

    def test_single_directive(self):
        d = parse_csp("script-src 'none'")
        assert d["script-src"] == ["none"]

    def test_multiple_values(self):
        d = parse_csp("script-src 'self' 'unsafe-inline' 'unsafe-eval' https://a.com https://b.com")
        assert "self" in d["script-src"]
        assert "unsafe-inline" in d["script-src"]
        assert "unsafe-eval" in d["script-src"]
        assert "https://a.com" in d["script-src"]

    def test_trailing_semicolons(self):
        d = parse_csp("default-src 'self';;; script-src 'none';;")
        assert d["default-src"] == ["self"]
        assert d["script-src"] == ["none"]


class TestMatchDomain:
    def test_exact_match(self):
        assert _match_domain("cdn.jsdelivr.net", "cdn.jsdelivr.net")
        assert _match_domain("cdn.jsdelivr.net", "https://cdn.jsdelivr.net")

    def test_wildcard_match(self):
        assert _match_domain("*.googleapis.com", "ajax.googleapis.com")
        assert _match_domain("*.googleapis.com", "https://maps.googleapis.com")
        assert not _match_domain("*.googleapis.com", "example.com")

    def test_wildcard_base_domain(self):
        assert _match_domain("*.example.com", "example.com")

    def test_no_match(self):
        assert not _match_domain("cdn.jsdelivr.net", "evil.com")


class TestAnalyzeCsp:
    def test_no_csp(self):
        result = analyze_csp("")
        assert not result.present
        assert result.score == 0
        assert any(w.id == "no-csp" for w in result.weaknesses)
        assert "inline_script" in result.bypass_techniques

    def test_report_only(self):
        result = analyze_csp("default-src 'self'", report_only=True)
        assert result.report_only
        assert any(w.id == "report-only" for w in result.weaknesses)

    def test_unsafe_inline(self):
        result = analyze_csp("script-src 'self' 'unsafe-inline'")
        assert any(w.id == "unsafe-inline" for w in result.weaknesses)
        assert "unsafe_inline" in result.bypass_techniques

    def test_unsafe_eval(self):
        result = analyze_csp("script-src 'self' 'unsafe-eval'")
        assert any(w.id == "unsafe-eval" for w in result.weaknesses)
        assert "unsafe_eval" in result.bypass_techniques

    def test_data_uri(self):
        result = analyze_csp("script-src 'self' data:")
        assert any(w.id == "data-uri" for w in result.weaknesses)
        assert "data_uri" in result.bypass_techniques

    def test_wildcard_script(self):
        result = analyze_csp("script-src *")
        assert any(w.id == "wildcard-script" for w in result.weaknesses)

    def test_missing_base_uri(self):
        result = analyze_csp("script-src 'self'")
        assert any(w.id == "missing-base-uri" for w in result.weaknesses)
        assert "base_injection" in result.bypass_techniques

    def test_base_uri_self(self):
        result = analyze_csp("script-src 'self'; base-uri 'self'")
        assert not any(w.id == "missing-base-uri" for w in result.weaknesses)

    def test_permissive_object_src(self):
        result = analyze_csp("script-src 'self'; base-uri 'none'")
        assert any(w.id == "permissive-object-src" for w in result.weaknesses)

    def test_object_src_none(self):
        result = analyze_csp("script-src 'self'; object-src 'none'; base-uri 'self'")
        assert not any(w.id == "permissive-object-src" for w in result.weaknesses)

    def test_missing_frame_ancestors(self):
        result = analyze_csp("script-src 'self'")
        assert any(w.id == "missing-frame-ancestors" for w in result.weaknesses)

    def test_frame_ancestors_present(self):
        result = analyze_csp("script-src 'self'; frame-ancestors 'self'")
        assert not any(w.id == "missing-frame-ancestors" for w in result.weaknesses)

    def test_jsonp_googleapis(self):
        result = analyze_csp("script-src 'self' ajax.googleapis.com")
        jsonp = [w for w in result.weaknesses if "googleapis" in w.id]
        assert len(jsonp) > 0
        assert "jsonp_callback" in result.bypass_techniques

    def test_user_controlled_origin(self):
        result = analyze_csp("script-src 'self' *.netlify.app")
        user_ctrl = [w for w in result.weaknesses if "user-controlled" in w.id]
        assert len(user_ctrl) > 0
        assert "user_controlled_origin" in result.bypass_techniques

    def test_cdn_jsdelivr(self):
        result = analyze_csp("script-src 'self' cdn.jsdelivr.net")
        cdn = [w for w in result.weaknesses if "cdn" in w.id]
        assert len(cdn) > 0

    def test_nonce_without_strict_dynamic(self):
        result = analyze_csp("script-src 'nonce-abc123' https://cdn.example.com")
        assert any(w.id == "nonce-without-strict-dynamic" for w in result.weaknesses)

    def test_nonce_with_strict_dynamic(self):
        result = analyze_csp("script-src 'nonce-abc123' 'strict-dynamic'")
        assert not any(w.id == "nonce-without-strict-dynamic" for w in result.weaknesses)

    def test_nonce_leakage_technique(self):
        result = analyze_csp("script-src 'nonce-abc123' 'strict-dynamic'")
        assert any(w.id == "nonce-present" for w in result.weaknesses)
        assert "nonce_leakage" in result.bypass_techniques

    def test_strong_csp(self):
        result = analyze_csp(
            "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; "
            "style-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'self'"
        )
        # Should have very high score, only nonce-present as low severity
        critical = [w for w in result.weaknesses if w.severity in ("critical", "high")]
        assert len(critical) == 0
        assert result.score >= 80

    def test_score_clamp(self):
        # Extremely weak CSP should clamp at 0
        result = analyze_csp("script-src * 'unsafe-inline' 'unsafe-eval' data:")
        assert result.score >= 0

    def test_inline_style_dangling_markup(self):
        result = analyze_csp("script-src 'self'; style-src 'unsafe-inline'")
        assert any(w.id == "unsafe-inline-style" for w in result.weaknesses)
        assert "dangling_markup" in result.bypass_techniques

    def test_recommendations(self):
        result = analyze_csp("script-src 'self' 'unsafe-inline' 'unsafe-eval' ajax.googleapis.com")
        recs = result.recommendations
        assert any("unsafe-inline" in r for r in recs)
        assert any("unsafe-eval" in r for r in recs)
        assert any("strict-dynamic" in r.lower() or "domain" in r.lower() for r in recs)


class TestGetCspFromHeaders:
    def test_enforced_csp(self):
        val, ro = get_csp_from_headers({"content-security-policy": "default-src 'self'"})
        assert val == "default-src 'self'"
        assert ro is False

    def test_report_only(self):
        val, ro = get_csp_from_headers({
            "content-security-policy-report-only": "default-src 'self'"
        })
        assert val == "default-src 'self'"
        assert ro is True

    def test_enforced_takes_priority(self):
        val, ro = get_csp_from_headers({
            "content-security-policy": "script-src 'none'",
            "content-security-policy-report-only": "default-src *",
        })
        assert val == "script-src 'none'"
        assert ro is False

    def test_no_csp_headers(self):
        val, ro = get_csp_from_headers({"x-frame-options": "DENY"})
        assert val == ""
        assert ro is False
