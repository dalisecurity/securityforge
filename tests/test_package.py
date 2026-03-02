#!/usr/bin/env python3
"""
SecurityForge test suite — validates package structure, payload integrity, and CLI.

Run:
    pytest tests/test_package.py -v
"""
import json
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "securityforge"
PAYLOADS = PKG / "payloads"


# ── Package structure ──────────────────────────────────────────────────

class TestPackageStructure:
    def test_package_importable(self):
        import securityforge
        assert hasattr(securityforge, "__version__")

    def test_version_format(self):
        import securityforge
        parts = securityforge.__version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_core_modules_importable(self):
        from securityforge.detector import WAFDetector
        from securityforge.tester import WAFTester
        from securityforge.cli import main
        assert callable(WAFDetector)
        assert callable(WAFTester)
        assert callable(main)

    def test_payloads_dir_exists(self):
        assert PAYLOADS.is_dir()

    def test_init_exports(self):
        import securityforge
        assert securityforge.__author__ == "DALI Security"
        assert securityforge.__license__ == "MIT"


# ── Payload integrity ──────────────────────────────────────────────────

class TestPayloads:
    def test_payload_categories_exist(self):
        categories = [d.name for d in sorted(PAYLOADS.iterdir()) if d.is_dir()]
        assert len(categories) >= 15, f"Expected 15+ categories, got {len(categories)}"
        for required in ["xss", "sqli", "ssrf", "ssti", "xxe", "ai_prompt_injection"]:
            assert required in categories, f"Missing required category: {required}"

    def test_all_json_payloads_valid(self):
        errors = []
        for json_file in sorted(PAYLOADS.rglob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                assert isinstance(data, (dict, list)), f"{json_file.name}: root must be dict or list"
            except (json.JSONDecodeError, AssertionError) as e:
                errors.append(f"{json_file.relative_to(PAYLOADS)}: {e}")
        assert not errors, "Invalid JSON files:\n" + "\n".join(errors)

    def test_json_payloads_have_content(self):
        empty = []
        for json_file in sorted(PAYLOADS.rglob("*.json")):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "payloads" in data:
                if len(data["payloads"]) == 0:
                    empty.append(str(json_file.relative_to(PAYLOADS)))
            elif isinstance(data, list) and len(data) == 0:
                empty.append(str(json_file.relative_to(PAYLOADS)))
        assert not empty, f"Empty payload files: {empty}"

    def test_txt_payloads_not_empty(self):
        empty = []
        for txt_file in sorted(PAYLOADS.rglob("*.txt")):
            content = txt_file.read_text(encoding="utf-8").strip()
            # Filter out comment-only lines
            lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            if len(lines) == 0:
                empty.append(str(txt_file.relative_to(PAYLOADS)))
        assert not empty, f"Empty txt payload files: {empty}"

    def test_payload_count_minimum(self):
        """Verify total payload count is at least 4000."""
        total = 0
        for json_file in PAYLOADS.rglob("*.json"):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "payloads" in data:
                total += len(data["payloads"])
            elif isinstance(data, list):
                total += len(data)
        for txt_file in PAYLOADS.rglob("*.txt"):
            lines = [l for l in txt_file.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            total += len(lines)
        assert total >= 4000, f"Expected 4000+ payloads, got {total}"

    def test_no_false_cve_claims(self):
        """Ensure no payload files falsely claim CVE-2026-28515/16/17 as WordPress."""
        for f in PAYLOADS.rglob("*"):
            if not f.is_file():
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            for cve in ["CVE-2026-28515", "CVE-2026-28516", "CVE-2026-28517"]:
                if cve in content:
                    assert "WordPress" not in content.split(cve)[0][-200:], \
                        f"{f.name} falsely attributes {cve} to WordPress (it's an openDCIM CVE)"


# ── WAF Detector ───────────────────────────────────────────────────────

class TestWAFDetector:
    def test_detector_instantiation(self):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        assert hasattr(d, "detect_waf")
        assert hasattr(d, "print_results")
        assert hasattr(d, "waf_signatures")

    def test_detector_has_25_vendors(self):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        assert len(d.waf_signatures) >= 25, \
            f"Expected 25+ WAF vendors, got {len(d.waf_signatures)}"

    def test_all_signatures_have_required_keys(self):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        required = {"headers", "cookies", "response_codes", "response_text", "server"}
        for name, sig in d.waf_signatures.items():
            missing = required - set(sig.keys())
            assert not missing, f"{name} missing keys: {missing}"


# ── WAF Detection Logic (unit tests for _analyze_signatures) ──────────

class TestWAFDetectionLogic:
    """Test _analyze_signatures with synthetic response data — no network."""

    @staticmethod
    def _make_results(headers=None, cookies=None, server=None,
                      status_code=200, response_snippet=None):
        return {
            "target": "https://test.local",
            "headers": headers or {},
            "cookies": cookies or [],
            "server": server,
            "status_code": status_code,
            "response_snippet": response_snippet,
        }

    def _detect(self, **kwargs):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        return d._analyze_signatures(self._make_results(**kwargs))

    # -- Cloudflare --
    def test_detect_cloudflare_by_headers(self):
        r = self._detect(headers={"cf-ray": "abc123", "cf-cache-status": "HIT"},
                         server="cloudflare", status_code=403)
        assert r["waf_detected"]
        assert r["waf_vendor"] == "Cloudflare"
        assert r["confidence"] >= 60

    def test_detect_cloudflare_by_cookie(self):
        r = self._detect(cookies=["__cfduid"], server="cloudflare")
        assert r["waf_detected"]
        assert r["waf_vendor"] == "Cloudflare"

    def test_detect_cloudflare_by_error_page(self):
        r = self._detect(
            headers={"cf-ray": "abc"},
            response_snippet="<span>Cloudflare Ray ID: abc123</span>",
            status_code=403,
        )
        assert r["waf_detected"]
        assert r["waf_vendor"] == "Cloudflare"

    # -- AWS WAF --
    def test_detect_aws_waf_by_headers(self):
        r = self._detect(headers={"x-amzn-waf-action": "block",
                                  "x-amzn-requestid": "123"},
                         status_code=403)
        assert r["waf_detected"]
        assert r["waf_vendor"] == "AWS WAF"
        assert r["confidence"] >= 50

    def test_detect_aws_waf_by_cookies(self):
        r = self._detect(cookies=["awsalb", "awsalbcors"],
                         response_snippet="request blocked by aws")
        assert r["waf_detected"]
        assert r["waf_vendor"] == "AWS WAF"

    # -- Akamai --
    def test_detect_akamai_by_headers(self):
        r = self._detect(headers={"akamai-grn": "x"}, cookies=["ak_bmsc"],
                         server="AkamaiGHost", status_code=403)
        assert r["waf_detected"]
        assert r["waf_vendor"] == "Akamai"

    # -- Imperva --
    def test_detect_imperva_by_cookies(self):
        r = self._detect(cookies=["incap_ses", "visid_incap"],
                         response_snippet="Incapsula incident ID: abc")
        assert r["waf_detected"]
        assert "Imperva" in r["waf_vendor"]

    # -- No WAF --
    def test_no_waf_detected(self):
        r = self._detect(headers={"content-type": "text/html"},
                         server="nginx", status_code=200)
        assert not r["waf_detected"]
        assert r["confidence"] == 0

    # -- Confidence capping --
    def test_confidence_capped_at_100(self):
        """Even with many signals, confidence should not exceed 100."""
        r = self._detect(
            headers={"cf-ray": "x", "cf-cache-status": "HIT",
                     "cf-request-id": "y"},
            cookies=["__cfduid", "__cflb", "cf_clearance"],
            server="cloudflare",
            status_code=403,
            response_snippet="Cloudflare Ray ID: abc attention required",
        )
        assert r["waf_detected"]
        assert r["confidence"] <= 100

    # -- Multiple WAFs: top match wins --
    def test_multiple_signals_picks_highest(self):
        r = self._detect(
            headers={"cf-ray": "x", "x-amzn-requestid": "y"},
            server="cloudflare",
            status_code=403,
        )
        assert r["waf_detected"]
        assert r["waf_vendor"] == "Cloudflare"  # stronger signal
        assert len(r["all_detections"]) >= 2


# ── Payload Loading ────────────────────────────────────────────────────

class TestPayloadLoading:
    def test_load_json_payloads(self):
        from securityforge.tester import WAFTester
        t = WAFTester(target="https://test.local")
        xss_files = list((PAYLOADS / "xss").glob("*.json"))
        assert len(xss_files) > 0, "No XSS JSON files found"
        payloads = t.load_payloads(str(xss_files[0]))
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        assert isinstance(payloads[0], dict)
        assert "payload" in payloads[0]

    def test_load_all_categories(self):
        from securityforge.tester import WAFTester
        t = WAFTester(target="https://test.local")
        for cat_dir in PAYLOADS.iterdir():
            if not cat_dir.is_dir():
                continue
            for jf in cat_dir.glob("*.json"):
                payloads = t.load_payloads(str(jf))
                assert isinstance(payloads, list), f"Failed: {jf}"

    def test_load_nonexistent_file_raises(self):
        from securityforge.tester import WAFTester
        t = WAFTester(target="https://test.local")
        with pytest.raises(FileNotFoundError):
            t.load_payloads("/nonexistent/path.json")


# ── Report Generation ─────────────────────────────────────────────────

class TestReportGeneration:
    def test_generate_json_report(self, tmp_path):
        from securityforge.tester import WAFTester
        t = WAFTester(target="https://test.local")
        t.start_time = __import__("datetime").datetime.now()
        fake_results = [
            {"payload": "<script>alert(1)</script>", "status": 403,
             "blocked": True, "category": "xss", "description": "basic xss",
             "timestamp": "2026-01-01T00:00:00"},
            {"payload": "' OR 1=1 --", "status": 200,
             "blocked": False, "category": "sqli", "description": "basic sqli",
             "timestamp": "2026-01-01T00:00:01"},
        ]
        out = str(tmp_path / "test_report.json")
        t.generate_report(fake_results, output=out)
        assert Path(out).exists()
        report = json.loads(Path(out).read_text())
        assert report["summary"]["total"] == 2
        assert report["summary"]["blocked"] == 1
        assert report["summary"]["passed"] == 1
        assert "50.00%" in report["summary"]["block_rate"]

    def test_report_empty_results(self, tmp_path):
        from securityforge.tester import WAFTester
        t = WAFTester(target="https://test.local")
        t.start_time = __import__("datetime").datetime.now()
        out = str(tmp_path / "empty_report.json")
        t.generate_report([], output=out)
        report = json.loads(Path(out).read_text())
        assert report["summary"]["total"] == 0
        assert report["summary"]["block_rate"] == "0%"


# ── IoT RCE CVE Payloads ──────────────────────────────────────────────

class TestIoTRCEPayloads:
    def test_iot_rce_category_exists(self):
        assert (PAYLOADS / "iot_rce").is_dir()

    def test_cve_2026_27509_file_valid(self):
        f = PAYLOADS / "iot_rce" / "CVE-2026-27509-dds-rce.json"
        assert f.exists()
        data = json.loads(f.read_text())
        assert data["cve"] == "CVE-2026-27509"
        assert data["severity"] == "HIGH"
        assert len(data["payloads"]) >= 20
        assert data["affected"]["product"] == "Unitree Go2 Robot"
        # Verify NVD-sourced CWE
        assert data["cwe"] == "CWE-306"

    def test_cve_2026_27510_file_valid(self):
        f = PAYLOADS / "iot_rce" / "CVE-2026-27510-mobile-db-rce.json"
        assert f.exists()
        data = json.loads(f.read_text())
        assert data["cve"] == "CVE-2026-27510"
        assert data["severity"] == "HIGH"
        assert len(data["payloads"]) >= 15
        assert "unitree_go2.db" in data["affected"]["database"]

    def test_dds_payloads_have_api_id(self):
        f = PAYLOADS / "iot_rce" / "CVE-2026-27509-dds-rce.json"
        data = json.loads(f.read_text())
        for p in data["payloads"]:
            assert "api_id" in p["payload"] or "boundary" in p["technique"], \
                f"DDS payload {p['id']} missing api_id field"

    def test_mobile_db_payloads_are_sql(self):
        f = PAYLOADS / "iot_rce" / "CVE-2026-27510-mobile-db-rce.json"
        data = json.loads(f.read_text())
        for p in data["payloads"]:
            assert "UPDATE " in p["payload"] or "INSERT " in p["payload"], \
                f"Mobile DB payload {p['id']} should be SQL statement"

    def test_no_placeholder_ips_in_production(self):
        """ATTACKER_IP placeholders should exist (they're templates, not real IPs)."""
        for f in (PAYLOADS / "iot_rce").glob("*.json"):
            content = f.read_text()
            # Should NOT contain real public IPs
            import re
            real_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
            for ip in real_ips:
                parts = ip.split(".")
                assert parts[0] in ("192", "10", "127", "0") or ip == "ATTACKER_IP", \
                    f"{f.name} contains real-looking IP: {ip}"


# ── CLI ────────────────────────────────────────────────────────────────

class TestCLI:
    def _run(self, *args):
        result = subprocess.run(
            [sys.executable, "-m", "securityforge.cli", *args],
            capture_output=True, text=True, timeout=10
        )
        return result

    def test_help(self):
        r = self._run("--help")
        assert r.returncode == 0
        assert "SecurityForge" in r.stdout

    def test_version(self):
        r = self._run("version")
        assert r.returncode == 0
        assert "SecurityForge v" in r.stdout

    def test_payloads(self):
        r = self._run("payloads")
        assert r.returncode == 0
        assert "xss" in r.stdout
        assert "sqli" in r.stdout

    def test_payloads_includes_iot_rce(self):
        r = self._run("payloads")
        assert r.returncode == 0
        assert "iot_rce" in r.stdout

    def test_detect_help(self):
        r = self._run("detect", "--help")
        assert r.returncode == 0
        assert "target" in r.stdout.lower()

    def test_test_help(self):
        r = self._run("test", "--help")
        assert r.returncode == 0
        assert "category" in r.stdout.lower() or "payload" in r.stdout.lower()

    def test_bad_category_exits_nonzero(self):
        r = self._run("test", "https://example.com", "-c", "nonexistent_xyz")
        assert r.returncode != 0

    def test_payloads_lists_categories(self):
        from securityforge.cli import list_categories
        cats = list_categories()
        assert isinstance(cats, list)
        assert "xss" in cats
        assert "sqli" in cats
        assert "iot_rce" in cats
