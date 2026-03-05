"""Tests for fray.diff — scan comparison and regression detection."""

import json
import os
import pytest
import tempfile
from dataclasses import asdict

from fray.diff import _normalize_report, run_diff, DiffResult


# ── Normalize Tests ───────────────────────────────────────────────────────


class TestNormalizeReport:
    def test_bypass_format(self):
        data = {
            "overall_evasion_score": 5.2,
            "total_tested": 50,
            "mutations_tested": 10,
            "total_bypassed": 8,
            "mutations_bypassed": 2,
            "waf_strictness": "strict",
            "target": "https://example.com",
            "timestamp": "2025-01-01T00:00:00",
            "blocked_tags": ["script", "svg"],
            "blocked_events": ["onerror"],
            "blocked_keywords": ["alert"],
            "bypasses": [
                {"payload": "<img src=x>", "status": 200, "evasion_score": 4.5,
                 "technique": "tag_sub", "reflected": True},
            ],
        }
        norm = _normalize_report(data)
        assert norm["format"] == "bypass"
        assert norm["total_tested"] == 60  # 50 + 10
        assert norm["total_bypassed"] == 10  # 8 + 2
        assert norm["total_blocked"] == 50
        assert norm["score"] == 5.2
        assert norm["strictness"] == "strict"
        assert "script" in norm["blocked_tags"]
        assert "<img src=x>" in norm["payload_map"]
        assert norm["payload_map"]["<img src=x>"]["blocked"] is False

    def test_test_format_with_results(self):
        data = {
            "target": "https://example.com",
            "timestamp": "2025-01-01",
            "results": [
                {"payload": "<script>alert(1)</script>", "blocked": True, "status": 403},
                {"payload": "<img src=x>", "blocked": False, "status": 200, "reflected": True},
            ],
        }
        norm = _normalize_report(data)
        assert norm["format"] == "test"
        assert norm["total_tested"] == 2
        assert norm["total_blocked"] == 1
        assert norm["total_bypassed"] == 1
        assert norm["bypass_rate"] == 50.0

    def test_test_format_list(self):
        """Raw list format is wrapped in a dict for _normalize_report."""
        data = {
            "results": [
                {"payload": "a", "blocked": True, "status": 403},
                {"payload": "b", "blocked": True, "status": 403},
            ]
        }
        norm = _normalize_report(data)
        assert norm["total_tested"] == 2
        assert norm["total_bypassed"] == 0

    def test_empty_results(self):
        norm = _normalize_report({"results": []})
        assert norm["total_tested"] == 0
        assert norm["bypass_rate"] == 0.0

    def test_bypass_rate_calculation(self):
        data = {
            "results": [
                {"payload": "a", "blocked": False, "status": 200},
                {"payload": "b", "blocked": False, "status": 200},
                {"payload": "c", "blocked": True, "status": 403},
                {"payload": "d", "blocked": True, "status": 403},
            ]
        }
        norm = _normalize_report(data)
        assert norm["bypass_rate"] == 50.0


# ── Diff Logic Tests ─────────────────────────────────────────────────────


def _write_json(tmp_dir, filename, data):
    path = os.path.join(tmp_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


class TestRunDiff:
    def test_no_changes_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "a", "blocked": True, "status": 403},
                    {"payload": "b", "blocked": True, "status": 403},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "a", "blocked": True, "status": 403},
                    {"payload": "b", "blocked": True, "status": 403},
                ]
            })
            diff = run_diff(before, after)
            assert diff.verdict == "PASS"
            assert diff.regressions == []
            assert diff.improvements == []

    def test_regression_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "dangerous", "blocked": True, "status": 403},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "dangerous", "blocked": False, "status": 200},
                ]
            })
            diff = run_diff(before, after)
            assert diff.verdict == "REGRESSED"
            assert len(diff.regressions) == 1
            assert diff.regressions[0]["payload"] == "dangerous"

    def test_improvement_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "was_bypassing", "blocked": False, "status": 200},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "was_bypassing", "blocked": True, "status": 403},
                ]
            })
            diff = run_diff(before, after)
            assert diff.verdict == "IMPROVED"
            assert len(diff.improvements) == 1

    def test_mixed_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "regressed", "blocked": True, "status": 403},
                    {"payload": "improved", "blocked": False, "status": 200},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "regressed", "blocked": False, "status": 200},
                    {"payload": "improved", "blocked": True, "status": 403},
                ]
            })
            diff = run_diff(before, after)
            assert diff.verdict == "MIXED"
            assert len(diff.regressions) == 1
            assert len(diff.improvements) == 1

    def test_new_bypass_in_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "existing", "blocked": True, "status": 403},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "existing", "blocked": True, "status": 403},
                    {"payload": "new_payload", "blocked": False, "status": 200},
                ]
            })
            diff = run_diff(before, after)
            assert len(diff.new_bypasses) == 1
            assert diff.new_bypasses[0]["payload"] == "new_payload"

    def test_bypass_format_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "overall_evasion_score": 3.0,
                "total_tested": 10,
                "mutations_tested": 0,
                "total_bypassed": 2,
                "mutations_bypassed": 0,
                "waf_strictness": "strict",
                "blocked_tags": ["script"],
                "blocked_events": ["onerror"],
                "blocked_keywords": ["alert"],
                "bypasses": [
                    {"payload": "p1", "status": 200, "evasion_score": 3.0},
                ],
            })
            after = _write_json(tmp, "after.json", {
                "overall_evasion_score": 5.0,
                "total_tested": 10,
                "mutations_tested": 0,
                "total_bypassed": 4,
                "mutations_bypassed": 0,
                "waf_strictness": "moderate",
                "blocked_tags": ["script", "svg"],
                "blocked_events": ["onerror"],
                "blocked_keywords": [],
                "bypasses": [
                    {"payload": "p1", "status": 200, "evasion_score": 3.0},
                    {"payload": "p2", "status": 200, "evasion_score": 5.0},
                ],
            })
            diff = run_diff(before, after)
            assert diff.score_delta == 2.0
            assert diff.before_strictness == "strict"
            assert diff.after_strictness == "moderate"
            assert "svg" in diff.new_blocked_tags
            assert "alert" in diff.removed_blocked_keywords

    def test_diff_result_serializable(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {"results": []})
            after = _write_json(tmp, "after.json", {"results": []})
            diff = run_diff(before, after)
            d = asdict(diff)
            serialized = json.dumps(d)
            assert isinstance(serialized, str)

    def test_payload_truncation(self):
        """Long payloads should be truncated to 80 chars in diff."""
        with tempfile.TemporaryDirectory() as tmp:
            long_payload = "A" * 200
            before = _write_json(tmp, "before.json", {
                "results": [{"payload": long_payload, "blocked": True, "status": 403}]
            })
            after = _write_json(tmp, "after.json", {
                "results": [{"payload": long_payload, "blocked": False, "status": 200}]
            })
            diff = run_diff(before, after)
            assert len(diff.regressions[0]["payload"]) == 80

    def test_bypass_rate_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = _write_json(tmp, "before.json", {
                "results": [
                    {"payload": "a", "blocked": True, "status": 403},
                    {"payload": "b", "blocked": True, "status": 403},
                ]
            })
            after = _write_json(tmp, "after.json", {
                "results": [
                    {"payload": "a", "blocked": False, "status": 200},
                    {"payload": "b", "blocked": True, "status": 403},
                ]
            })
            diff = run_diff(before, after)
            assert diff.before_bypass_rate == 0.0
            assert diff.after_bypass_rate == 50.0
            assert diff.bypass_rate_delta == 50.0
