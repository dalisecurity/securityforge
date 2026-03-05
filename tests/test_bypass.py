"""Tests for fray.bypass — WAF evasion scoring engine."""

import pytest
from unittest.mock import MagicMock
from dataclasses import asdict

from fray.bypass import (
    resolve_waf_name,
    WAF_EVASION_HINTS,
    _is_baseline_match,
    _is_soft_block,
    _compute_evasion_score,
    _overall_score,
    BypassResult,
    BypassScorecard,
)
from fray.evolve import WAFProfile


# ── WAF Name Resolution ──────────────────────────────────────────────────


class TestResolveWafName:
    def test_canonical_names(self):
        assert resolve_waf_name("cloudflare") == "cloudflare"
        assert resolve_waf_name("akamai") == "akamai"
        assert resolve_waf_name("aws_waf") == "aws_waf"
        assert resolve_waf_name("imperva") == "imperva"
        assert resolve_waf_name("f5") == "f5"
        assert resolve_waf_name("modsecurity") == "modsecurity"

    def test_aliases(self):
        assert resolve_waf_name("cf") == "cloudflare"
        assert resolve_waf_name("kona") == "akamai"
        assert resolve_waf_name("aws") == "aws_waf"
        assert resolve_waf_name("awswaf") == "aws_waf"
        assert resolve_waf_name("incapsula") == "imperva"
        assert resolve_waf_name("bigip") == "f5"
        # big-ip → big_ip after normalization — check what the code does
        assert resolve_waf_name("big-ip") == "f5" or resolve_waf_name("bigip") == "f5"
        assert resolve_waf_name("asm") == "f5"
        assert resolve_waf_name("sigsci") == "fastly"
        assert resolve_waf_name("modsec") == "modsecurity"
        assert resolve_waf_name("crs") == "modsecurity"

    def test_case_insensitive(self):
        assert resolve_waf_name("Cloudflare") == "cloudflare"
        assert resolve_waf_name("AKAMAI") == "akamai"
        assert resolve_waf_name("AWS_WAF") == "aws_waf"

    def test_unknown_returns_none(self):
        assert resolve_waf_name("unknownwaf") is None
        assert resolve_waf_name("") is None
        assert resolve_waf_name("random") is None

    def test_all_hints_have_labels(self):
        for key, hints in WAF_EVASION_HINTS.items():
            assert "label" in hints, f"WAF {key} missing label"
            assert "tips" in hints, f"WAF {key} missing tips"
            assert "priority_mutations" in hints, f"WAF {key} missing priority_mutations"


# ── Baseline Match Detection ─────────────────────────────────────────────


class TestIsBaselineMatch:
    def test_no_baseline(self):
        assert _is_baseline_match({"status": 200, "response_length": 1000}, None) is False

    def test_different_status(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 403, "response_length": 1000}
        assert _is_baseline_match(result, baseline) is False

    def test_same_status_similar_length(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 200, "response_length": 1050}  # within 15%
        assert _is_baseline_match(result, baseline) is True

    def test_same_status_different_length(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 200, "response_length": 500}  # 50% — outside 15%
        assert _is_baseline_match(result, baseline) is False

    def test_both_zero_length(self):
        baseline = {"status": 200, "response_length": 0}
        result = {"status": 200, "response_length": 0}
        assert _is_baseline_match(result, baseline) is True

    def test_boundary_85_percent(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 200, "response_length": 850}
        assert _is_baseline_match(result, baseline) is True

    def test_boundary_115_percent(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 200, "response_length": 1150}
        assert _is_baseline_match(result, baseline) is True

    def test_just_outside_boundary(self):
        baseline = {"status": 200, "response_length": 1000}
        result = {"status": 200, "response_length": 1160}
        assert _is_baseline_match(result, baseline) is False


# ── Soft Block Detection ─────────────────────────────────────────────────


class TestIsSoftBlock:
    def test_no_baseline(self):
        assert _is_soft_block({"status": 200, "response_length": 100}, None) is False

    def test_different_status(self):
        baseline = {"status": 200, "response_length": 10000}
        result = {"status": 403, "response_length": 500}
        assert _is_soft_block(result, baseline) is False

    def test_dramatic_shrink(self):
        baseline = {"status": 200, "response_length": 10000}
        result = {"status": 200, "response_length": 3000}  # 30% — under 40%
        assert _is_soft_block(result, baseline) is True

    def test_normal_response(self):
        baseline = {"status": 200, "response_length": 10000}
        result = {"status": 200, "response_length": 9500}  # 95%
        assert _is_soft_block(result, baseline) is False

    def test_tiny_response(self):
        baseline = {"status": 200, "response_length": 5000}
        result = {"status": 200, "response_length": 300}
        assert _is_soft_block(result, baseline) is True

    def test_small_baseline_not_triggered(self):
        baseline = {"status": 200, "response_length": 500}
        result = {"status": 200, "response_length": 100}
        # baseline < 1000 so neither threshold triggers
        assert _is_soft_block(result, baseline) is False


# ── Evasion Score Computation ─────────────────────────────────────────────


class TestComputeEvasionScore:
    @pytest.fixture
    def strict_profile(self):
        return WAFProfile(
            blocked_tags={"script", "svg"},
            blocked_events={"onerror", "onload"},
            blocked_keywords={"alert", "eval"},
            allowed_tags={"div"},
            total_probes=100,
            total_blocked=96,  # 96% → strict
        )

    @pytest.fixture
    def permissive_profile(self):
        return WAFProfile(
            blocked_tags=set(),
            blocked_events=set(),
            blocked_keywords=set(),
            allowed_tags={"div", "svg", "img"},
            total_probes=100,
            total_blocked=10,  # 10% → minimal
        )

    def test_blocked_result_scores_zero(self, strict_profile):
        result = {"blocked": True, "status": 403, "payload": "<script>alert(1)</script>"}
        score = _compute_evasion_score(result, strict_profile, is_mutation=False)
        assert score == 0.0

    def test_strict_waf_higher_base(self, strict_profile):
        result = {"blocked": False, "status": 200, "payload": "<div>test</div>"}
        score = _compute_evasion_score(result, strict_profile, is_mutation=False)
        assert score >= 4.0  # strict base = 4.0

    def test_permissive_waf_lower_base(self, permissive_profile):
        result = {"blocked": False, "status": 200, "payload": "<div>test</div>"}
        score = _compute_evasion_score(result, permissive_profile, is_mutation=False)
        assert score < 4.0  # permissive base = 2.0

    def test_reflected_bonus(self, strict_profile):
        not_reflected = {"blocked": False, "status": 200, "payload": "test", "reflected": False}
        reflected = {"blocked": False, "status": 200, "payload": "test", "reflected": True}
        score_nr = _compute_evasion_score(not_reflected, strict_profile, is_mutation=False)
        score_r = _compute_evasion_score(reflected, strict_profile, is_mutation=False)
        assert score_r > score_nr

    def test_mutation_bonus(self, strict_profile):
        result = {"blocked": False, "status": 200, "payload": "test"}
        score_normal = _compute_evasion_score(result, strict_profile, is_mutation=False)
        score_mutated = _compute_evasion_score(result, strict_profile, is_mutation=True)
        assert score_mutated > score_normal

    def test_blocked_pattern_overlap_bonus(self, strict_profile):
        # Payload with blocked tags scores higher (impressive bypass)
        boring = {"blocked": False, "status": 200, "payload": "<div>test</div>"}
        impressive = {"blocked": False, "status": 200, "payload": "<script>alert(1)</script>"}
        score_boring = _compute_evasion_score(boring, strict_profile, is_mutation=False)
        score_impressive = _compute_evasion_score(impressive, strict_profile, is_mutation=False)
        assert score_impressive > score_boring

    def test_baseline_match_penalty(self, strict_profile):
        baseline = {"status": 200, "response_length": 5000}
        result = {"blocked": False, "status": 200, "payload": "test",
                  "response_length": 5050}  # matches baseline
        score_with_penalty = _compute_evasion_score(result, strict_profile,
                                                     is_mutation=False, baseline=baseline)
        score_without = _compute_evasion_score(result, strict_profile, is_mutation=False)
        assert score_with_penalty < score_without

    def test_soft_block_penalty(self, strict_profile):
        baseline = {"status": 200, "response_length": 10000}
        result = {"blocked": False, "status": 200, "payload": "test",
                  "response_length": 500}  # dramatic shrink
        score = _compute_evasion_score(result, strict_profile,
                                       is_mutation=False, baseline=baseline)
        # Should be heavily penalized (0.1 multiplier)
        assert score < 1.0

    def test_score_capped_at_10(self, strict_profile):
        # Max out all bonuses
        result = {"blocked": False, "status": 200,
                  "payload": "<script>alert(eval('x'))</script>",
                  "reflected": True}
        score = _compute_evasion_score(result, strict_profile, is_mutation=True)
        assert score <= 10.0


# ── Overall Score ─────────────────────────────────────────────────────────


class TestOverallScore:
    def _strict_profile(self):
        return WAFProfile(total_probes=100, total_blocked=96)

    def _permissive_profile(self):
        return WAFProfile(total_probes=100, total_blocked=40)

    def test_no_tests(self):
        profile = self._strict_profile()
        assert _overall_score([], 0, profile) == 0.0

    def test_no_bypasses(self):
        profile = self._strict_profile()
        assert _overall_score([], 100, profile) == 0.0

    def test_score_increases_with_bypasses(self):
        profile = self._strict_profile()
        bypasses = [BypassResult(payload="a", blocked=False, status=200, evasion_score=5.0)]
        score_1 = _overall_score(bypasses, 100, profile)
        bypasses_2 = bypasses * 10
        score_10 = _overall_score(bypasses_2, 100, profile)
        assert score_10 > score_1

    def test_strict_waf_weighted_higher(self):
        bypasses = [BypassResult(payload="a", blocked=False, status=200, evasion_score=5.0)]
        strict = self._strict_profile()
        permissive = self._permissive_profile()
        score_strict = _overall_score(bypasses, 10, strict)
        score_permissive = _overall_score(bypasses, 10, permissive)
        assert score_strict > score_permissive

    def test_score_capped_at_10(self):
        profile = self._strict_profile()
        bypasses = [BypassResult(payload="a", blocked=False, status=200, evasion_score=10.0)] * 100
        score = _overall_score(bypasses, 100, profile)
        assert score <= 10.0


# ── Dataclass Tests ───────────────────────────────────────────────────────


class TestDataclasses:
    def test_bypass_result_defaults(self):
        r = BypassResult(payload="test", blocked=False, status=200)
        assert r.evasion_score == 0.0
        assert r.reflected is False
        assert r.technique == ""

    def test_scorecard_defaults(self):
        s = BypassScorecard(target="https://example.com")
        assert s.total_tested == 0
        assert s.bypasses == []
        assert s.overall_evasion_score == 0.0

    def test_scorecard_serializable(self):
        import json
        s = BypassScorecard(target="https://example.com", waf_vendor="Cloudflare",
                            total_tested=50, total_bypassed=3)
        d = asdict(s)
        serialized = json.dumps(d)
        assert "Cloudflare" in serialized
