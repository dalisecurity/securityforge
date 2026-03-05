"""Tests for fray.smuggling — HTTP request smuggling probe construction and detection logic."""

import pytest
import socket
from unittest.mock import patch, MagicMock
from dataclasses import asdict

from fray.smuggling import (
    _build_baseline_probe,
    _build_clte_probe,
    _build_clte_delay_probe,
    _build_tecl_probe,
    _build_tecl_delay_probe,
    _build_te_te_probe,
    _build_te_newline_probe,
    _resolve_and_check,
    SmuggleProbeResult,
    SmuggleReport,
    _TIMING_MULTIPLIER,
    _MIN_DELAY_SECONDS,
)


# ── Probe Construction Tests ──────────────────────────────────────────────


class TestBaselineProbe:
    def test_is_get_request(self):
        probe = _build_baseline_probe("example.com", "/")
        assert probe.startswith(b"GET / HTTP/1.1\r\n")

    def test_contains_host_header(self):
        probe = _build_baseline_probe("target.com", "/path")
        assert b"Host: target.com\r\n" in probe

    def test_contains_connection_close(self):
        probe = _build_baseline_probe("example.com", "/")
        assert b"Connection: close\r\n" in probe

    def test_ends_with_double_crlf(self):
        probe = _build_baseline_probe("example.com", "/")
        assert probe.endswith(b"\r\n\r\n")

    def test_custom_path(self):
        probe = _build_baseline_probe("example.com", "/api/v1/test")
        assert b"GET /api/v1/test HTTP/1.1\r\n" in probe


class TestCLTEProbes:
    def test_clte_basic_is_post(self):
        probe = _build_clte_probe("example.com", "/")
        assert probe.startswith(b"POST / HTTP/1.1\r\n")

    def test_clte_basic_has_both_headers(self):
        probe = _build_clte_probe("example.com", "/")
        assert b"Content-Length: 4\r\n" in probe
        assert b"Transfer-Encoding: chunked\r\n" in probe

    def test_clte_basic_body_contains_terminator(self):
        probe = _build_clte_probe("example.com", "/")
        # Body should be "0\r\n\r\n" (chunked terminator)
        assert probe.endswith(b"0\r\n\r\n")

    def test_clte_basic_cl_shorter_than_body(self):
        """CL=4 but body is 5 bytes (0\r\n\r\n) — intentional mismatch."""
        probe = _build_clte_probe("example.com", "/")
        assert b"Content-Length: 4\r\n" in probe
        # Body after headers
        header_end = probe.index(b"\r\n\r\n") + 4
        body = probe[header_end:]
        assert len(body) == 5  # "0\r\n\r\n"

    def test_clte_delay_has_partial_chunk(self):
        probe = _build_clte_delay_probe("example.com", "/")
        assert b"Content-Length: 6\r\n" in probe
        assert b"Transfer-Encoding: chunked\r\n" in probe
        # Body: "1\r\nZ\r\n" — valid chunk start but no terminating chunk
        header_end = probe.index(b"\r\n\r\n") + 4
        body = probe[header_end:]
        assert body == b"1\r\nZ\r\n"
        assert b"0\r\n\r\n" not in body  # No terminator — designed to hang

    def test_clte_delay_no_smuggled_request(self):
        """Safety: no second HTTP request in the body."""
        probe = _build_clte_delay_probe("example.com", "/")
        header_end = probe.index(b"\r\n\r\n") + 4
        body = probe[header_end:]
        assert b"GET " not in body
        assert b"POST " not in body
        assert b"HTTP/" not in body


class TestTECLProbes:
    def test_tecl_basic_has_cl_zero(self):
        probe = _build_tecl_probe("example.com", "/")
        assert b"Content-Length: 0\r\n" in probe

    def test_tecl_basic_has_chunked_body(self):
        probe = _build_tecl_probe("example.com", "/")
        assert probe.endswith(b"0\r\n\r\n")

    def test_tecl_delay_has_full_chunk(self):
        probe = _build_tecl_delay_probe("example.com", "/")
        header_end = probe.index(b"\r\n\r\n") + 4
        body = probe[header_end:]
        # "5\r\nHello\r\n0\r\n\r\n"
        assert b"Hello" in body
        assert body.endswith(b"0\r\n\r\n")

    def test_tecl_probes_safe(self):
        """No smuggled requests in body."""
        for builder in [_build_tecl_probe, _build_tecl_delay_probe]:
            probe = builder("example.com", "/")
            header_end = probe.index(b"\r\n\r\n") + 4
            body = probe[header_end:]
            assert b"GET " not in body
            assert b"POST " not in body


class TestTETEProbes:
    def test_te_te_dual_has_two_te_headers(self):
        probe = _build_te_te_probe("example.com", "/")
        # Should have two Transfer-Encoding lines (different cases)
        # One is "Transfer-Encoding: chunked", other is "Transfer-encoding: x"
        te_count = probe.lower().count(b"transfer-encoding")
        assert te_count >= 2

    def test_te_newline_has_tab(self):
        probe = _build_te_newline_probe("example.com", "/")
        assert b"Transfer-Encoding:\tchunked\r\n" in probe

    def test_te_probes_safe(self):
        for builder in [_build_te_te_probe, _build_te_newline_probe]:
            probe = builder("example.com", "/")
            header_end = probe.index(b"\r\n\r\n") + 4
            body = probe[header_end:]
            assert b"GET " not in body
            assert b"POST " not in body


# ── SSRF Protection Tests ─────────────────────────────────────────────────


class TestSSRFProtection:
    def test_blocks_loopback(self):
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with pytest.raises(ValueError, match="private"):
                _resolve_and_check("localhost")

    def test_blocks_private_10(self):
        with patch("socket.gethostbyname", return_value="10.0.0.1"):
            with pytest.raises(ValueError, match="private"):
                _resolve_and_check("internal.example.com")

    def test_blocks_private_172(self):
        with patch("socket.gethostbyname", return_value="172.16.0.1"):
            with pytest.raises(ValueError, match="private"):
                _resolve_and_check("internal.example.com")

    def test_blocks_private_192(self):
        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            with pytest.raises(ValueError, match="private"):
                _resolve_and_check("home.example.com")

    def test_blocks_link_local(self):
        with patch("socket.gethostbyname", return_value="169.254.1.1"):
            with pytest.raises(ValueError, match="private"):
                _resolve_and_check("metadata.example.com")

    def test_allows_public_ip(self):
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            result = _resolve_and_check("example.com")
            assert result == "93.184.216.34"


# ── Dataclass Tests ───────────────────────────────────────────────────────


class TestDataclasses:
    def test_probe_result_defaults(self):
        r = SmuggleProbeResult()
        assert r.probe_type == ""
        assert r.status == 0
        assert r.timed_out is False
        assert r.desync_detected is False

    def test_probe_result_asdict(self):
        r = SmuggleProbeResult(probe_type="CL.TE", variant="clte_basic", status=200)
        d = asdict(r)
        assert d["probe_type"] == "CL.TE"
        assert d["status"] == 200

    def test_report_defaults(self):
        r = SmuggleReport()
        assert r.vulnerable is False
        assert r.desync_types == []
        assert r.probes == []
        assert r.tips == []

    def test_report_asdict_serializable(self):
        r = SmuggleReport(target="https://example.com", vulnerable=True,
                          desync_types=["CL.TE"], confidence="high")
        d = asdict(r)
        import json
        # Should be JSON-serializable
        serialized = json.dumps(d)
        assert "CL.TE" in serialized


# ── Detection Logic Tests (mocked network) ────────────────────────────────


class TestDetectionLogic:
    """Test the detection engine with mocked network calls."""

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_clean_server_not_vulnerable(self, mock_resolve, mock_request):
        """Server responds normally to all probes → NOT VULNERABLE."""
        from fray.smuggling import run_smuggling_detection

        # Baseline: 3 fast responses
        # Probes: 6 fast responses with 200 status
        mock_request.side_effect = [
            (200, "OK", 0.1, False),  # baseline 1
            (200, "OK", 0.12, False),  # baseline 2
            (200, "OK", 0.11, False),  # baseline 3
            (200, "OK", 0.1, False),  # clte_basic
            (200, "OK", 0.1, False),  # clte_delay
            (200, "OK", 0.1, False),  # tecl_basic
            (200, "OK", 0.1, False),  # tecl_delay
            (400, "Bad Request", 0.05, False),  # te_te_dual (rejected)
            (400, "Bad Request", 0.05, False),  # te_newline (rejected)
        ]

        report = run_smuggling_detection("https://example.com", timeout=5, delay=0)
        assert not report.vulnerable
        assert report.desync_types == []

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_clte_timeout_with_basic_ok_is_false_positive(self, mock_resolve, mock_request):
        """CL.TE delay times out but basic is OK → Phase 3 downgrade → NOT VULNERABLE."""
        from fray.smuggling import run_smuggling_detection

        mock_request.side_effect = [
            (200, "OK", 0.1, False),   # baseline 1
            (200, "OK", 0.1, False),   # baseline 2
            (200, "OK", 0.1, False),   # baseline 3
            (200, "OK", 0.1, False),   # clte_basic — fast response
            (0, "", 10.0, True),       # clte_delay — TIMEOUT
            (200, "OK", 0.1, False),   # tecl_basic
            (200, "OK", 0.1, False),   # tecl_delay
            (400, "", 0.05, False),    # te_te_dual
            (400, "", 0.05, False),    # te_newline
        ]

        report = run_smuggling_detection("https://example.com", timeout=10, delay=0)
        # Phase 3 should downgrade the CL.TE false positive
        assert not report.vulnerable
        assert "CL.TE" not in report.desync_types

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_both_clte_probes_timeout_is_vulnerable(self, mock_resolve, mock_request):
        """Both CL.TE basic and delay timeout → real desync → VULNERABLE."""
        from fray.smuggling import run_smuggling_detection

        mock_request.side_effect = [
            (200, "OK", 0.1, False),  # baseline 1
            (200, "OK", 0.1, False),  # baseline 2
            (200, "OK", 0.1, False),  # baseline 3
            (0, "", 10.0, True),      # clte_basic — TIMEOUT
            (0, "", 10.0, True),      # clte_delay — TIMEOUT
            (200, "OK", 0.1, False),  # tecl_basic
            (200, "OK", 0.1, False),  # tecl_delay
            (200, "OK", 0.1, False),  # te_te_dual
            (200, "OK", 0.1, False),  # te_newline
        ]

        report = run_smuggling_detection("https://example.com", timeout=10, delay=0)
        assert report.vulnerable
        assert "CL.TE" in report.desync_types

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_te_te_400_is_safe(self, mock_resolve, mock_request):
        """Server rejects duplicate TE with 400 → TE.TE is SAFE."""
        from fray.smuggling import run_smuggling_detection

        mock_request.side_effect = [
            (200, "OK", 0.1, False),   # baseline 1
            (200, "OK", 0.1, False),   # baseline 2
            (200, "OK", 0.1, False),   # baseline 3
            (200, "OK", 0.1, False),   # clte_basic
            (200, "OK", 0.1, False),   # clte_delay
            (200, "OK", 0.1, False),   # tecl_basic
            (200, "OK", 0.1, False),   # tecl_delay
            (400, "", 0.05, False),    # te_te_dual — rejected
            (0, "", 10.0, True),       # te_newline — timeout
        ]

        report = run_smuggling_detection("https://example.com", timeout=10, delay=0)
        # TE.TE dual was rejected with 400 → discarded
        assert "TE.TE" not in report.desync_types

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_unreachable_target(self, mock_resolve, mock_request):
        """All baseline requests fail → report with tips but not vulnerable."""
        from fray.smuggling import run_smuggling_detection

        mock_request.side_effect = [
            (0, "", 10.0, True),  # baseline 1 fail
            (0, "", 10.0, True),  # baseline 2 fail
            (0, "", 10.0, True),  # baseline 3 fail
        ]

        report = run_smuggling_detection("https://unreachable.test", timeout=10, delay=0)
        assert not report.vulnerable
        assert any("unreachable" in t.lower() for t in report.tips)

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_tecl_confirmation_downgrade(self, mock_resolve, mock_request):
        """TE.CL delay timeout but basic OK → Phase 3 downgrade."""
        from fray.smuggling import run_smuggling_detection

        mock_request.side_effect = [
            (200, "OK", 0.1, False),   # baseline 1
            (200, "OK", 0.1, False),   # baseline 2
            (200, "OK", 0.1, False),   # baseline 3
            (200, "OK", 0.1, False),   # clte_basic
            (200, "OK", 0.1, False),   # clte_delay
            (200, "OK", 0.1, False),   # tecl_basic — OK
            (0, "", 10.0, True),       # tecl_delay — TIMEOUT
            (200, "OK", 0.1, False),   # te_te_dual
            (200, "OK", 0.1, False),   # te_newline
        ]

        report = run_smuggling_detection("https://example.com", timeout=10, delay=0)
        assert not report.vulnerable
        assert "TE.CL" not in report.desync_types

    @patch("fray.smuggling._raw_request_timed")
    @patch("fray.smuggling._resolve_and_check", return_value="93.184.216.34")
    def test_timing_multiplier_detection(self, mock_resolve, mock_request):
        """Both CL.TE probes significantly slower than baseline → desync detected.

        Phase 3 only downgrades when basic is OK and delay is slow.
        If BOTH basic and delay are slow, it's a real desync.
        """
        from fray.smuggling import run_smuggling_detection

        baseline_time = 0.1
        # Response that's >3x baseline AND >2s slower
        slow_time = baseline_time * (_TIMING_MULTIPLIER + 1) + _MIN_DELAY_SECONDS + 1

        mock_request.side_effect = [
            (200, "OK", baseline_time, False),  # baseline 1
            (200, "OK", baseline_time, False),  # baseline 2
            (200, "OK", baseline_time, False),  # baseline 3
            (0, "", 10.0, True),                # clte_basic — TIMEOUT (desync)
            (0, "", 10.0, True),                # clte_delay — TIMEOUT (desync)
            (200, "OK", 0.1, False),            # tecl_basic
            (200, "OK", 0.1, False),            # tecl_delay
            (200, "OK", 0.1, False),            # te_te_dual
            (200, "OK", 0.1, False),            # te_newline
        ]

        report = run_smuggling_detection("https://example.com", timeout=10, delay=0)
        # Both CL.TE probes timed out → basic also bad → not downgraded by Phase 3
        assert report.vulnerable
        assert "CL.TE" in report.desync_types


# ── Confidence Scoring Tests ──────────────────────────────────────────────


class TestConfidenceScoring:
    def test_report_confidence_none_when_clean(self):
        r = SmuggleReport(vulnerable=False)
        # confidence is set by run_smuggling_detection, but default is ""
        assert r.confidence == ""

    def test_probe_result_fields(self):
        r = SmuggleProbeResult(
            probe_type="CL.TE",
            variant="clte_basic",
            status=200,
            response_time=0.15,
            response_length=1024,
            timed_out=False,
            desync_detected=False,
            confidence="none",
            description="test probe",
        )
        assert r.probe_type == "CL.TE"
        assert r.response_time == 0.15
        assert not r.desync_detected


# ── All Probes Safety Verification ────────────────────────────────────────


class TestAllProbesSafety:
    """Verify ALL probes are safe: no smuggled second requests."""

    @pytest.fixture
    def all_probes(self):
        host = "test.example.com"
        path = "/test"
        return [
            ("baseline", _build_baseline_probe(host, path)),
            ("clte_basic", _build_clte_probe(host, path)),
            ("clte_delay", _build_clte_delay_probe(host, path)),
            ("tecl_basic", _build_tecl_probe(host, path)),
            ("tecl_delay", _build_tecl_delay_probe(host, path)),
            ("te_te_dual", _build_te_te_probe(host, path)),
            ("te_newline", _build_te_newline_probe(host, path)),
        ]

    def test_no_smuggled_get(self, all_probes):
        for name, probe in all_probes:
            # Count HTTP methods — should be exactly 1 (the probe itself)
            method_count = probe.count(b"GET ") + probe.count(b"POST ")
            assert method_count == 1, f"{name} has {method_count} HTTP methods"

    def test_all_have_host_header(self, all_probes):
        for name, probe in all_probes:
            assert b"Host: test.example.com\r\n" in probe, f"{name} missing Host header"

    def test_all_have_connection_close(self, all_probes):
        for name, probe in all_probes:
            assert b"Connection: close\r\n" in probe, f"{name} missing Connection: close"

    def test_all_are_bytes(self, all_probes):
        for name, probe in all_probes:
            assert isinstance(probe, bytes), f"{name} is not bytes"

    def test_all_have_valid_http_line(self, all_probes):
        for name, probe in all_probes:
            first_line = probe.split(b"\r\n")[0]
            assert first_line.endswith(b"HTTP/1.1"), f"{name} bad first line: {first_line}"
