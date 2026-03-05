"""Tests for fray.scope — scope file parsing and target validation."""

import os
import pytest
import tempfile

from fray.scope import parse_scope_file, is_target_in_scope, _classify_entry


# ── Helpers ───────────────────────────────────────────────────────────────


def _write_scope(content):
    """Write scope content to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# ── parse_scope_file Tests ────────────────────────────────────────────────


class TestParseScopeFile:
    def test_plain_domains(self):
        path = _write_scope("example.com\ntest.org\n")
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "test.org" in scope["domains"]
        finally:
            os.unlink(path)

    def test_wildcard_domains(self):
        path = _write_scope("*.example.com\n*.test.org\n")
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["wildcards"]
            assert "test.org" in scope["wildcards"]
        finally:
            os.unlink(path)

    def test_ip_addresses(self):
        path = _write_scope("192.168.1.1\n10.0.0.5\n")
        try:
            scope = parse_scope_file(path)
            assert "192.168.1.1" in scope["ips"]
            assert "10.0.0.5" in scope["ips"]
        finally:
            os.unlink(path)

    def test_cidr_ranges(self):
        path = _write_scope("10.0.0.0/24\n172.16.0.0/16\n")
        try:
            scope = parse_scope_file(path)
            assert len(scope["cidrs"]) == 2
            assert "10.0.0.0/24" in scope["cidrs"]
        finally:
            os.unlink(path)

    def test_urls(self):
        path = _write_scope("https://example.com/app\nhttp://test.org/api\n")
        try:
            scope = parse_scope_file(path)
            assert "https://example.com/app" in scope["urls"]
            assert "http://test.org/api" in scope["urls"]
            # Host should also be added to domains
            assert "example.com" in scope["domains"]
        finally:
            os.unlink(path)

    def test_comments_and_blank_lines(self):
        path = _write_scope("# This is a comment\n\nexample.com\n\n# Another comment\ntest.org\n")
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "test.org" in scope["domains"]
            assert len(scope["domains"]) == 2
        finally:
            os.unlink(path)

    def test_out_of_scope_section(self):
        path = _write_scope("example.com\n# Out of Scope\nstaging.example.com\n")
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "staging.example.com" in scope["out_of_scope"]
        finally:
            os.unlink(path)

    def test_negation_prefix_dash(self):
        path = _write_scope("example.com\n-staging.example.com\n")
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["domains"]
            assert "staging.example.com" in scope["out_of_scope"]
        finally:
            os.unlink(path)

    def test_negation_prefix_bang(self):
        path = _write_scope("example.com\n!dev.example.com\n")
        try:
            scope = parse_scope_file(path)
            assert "dev.example.com" in scope["out_of_scope"]
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_scope_file("/nonexistent/path/scope.txt")

    def test_mixed_entries(self):
        content = """# Bug Bounty Scope
*.example.com
10.0.0.0/24
192.168.1.1
https://api.example.com/v1

# Out of Scope
-staging.example.com
"""
        path = _write_scope(content)
        try:
            scope = parse_scope_file(path)
            assert "example.com" in scope["wildcards"]
            assert "10.0.0.0/24" in scope["cidrs"]
            assert "192.168.1.1" in scope["ips"]
            assert "https://api.example.com/v1" in scope["urls"]
            assert "staging.example.com" in scope["out_of_scope"]
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = _write_scope("")
        try:
            scope = parse_scope_file(path)
            assert scope["domains"] == []
            assert scope["wildcards"] == []
        finally:
            os.unlink(path)

    def test_in_scope_section_marker(self):
        content = """# Out of Scope
staging.example.com
# In Scope
production.example.com
"""
        path = _write_scope(content)
        try:
            scope = parse_scope_file(path)
            assert "staging.example.com" in scope["out_of_scope"]
            assert "production.example.com" in scope["domains"]
        finally:
            os.unlink(path)


# ── _classify_entry Tests ─────────────────────────────────────────────────


class TestClassifyEntry:
    def test_classify_domain(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("example.com", scope)
        assert "example.com" in scope["domains"]

    def test_classify_wildcard(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("*.example.com", scope)
        assert "example.com" in scope["wildcards"]

    def test_classify_ip(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("93.184.216.34", scope)
        assert "93.184.216.34" in scope["ips"]

    def test_classify_cidr(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("10.0.0.0/24", scope)
        assert len(scope["cidrs"]) == 1

    def test_classify_url(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("https://example.com/path", scope)
        assert "https://example.com/path" in scope["urls"]

    def test_classify_subdomain(self):
        scope = {"domains": set(), "wildcards": set(), "ips": set(), "cidrs": [], "urls": set(), "out_of_scope": set()}
        _classify_entry("sub.example.com", scope)
        assert "sub.example.com" in scope["domains"]


# ── is_target_in_scope Tests ──────────────────────────────────────────────


class TestIsTargetInScope:
    def test_exact_domain_match(self):
        scope = {"domains": ["example.com"], "wildcards": [], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://example.com", scope)
        assert in_scope
        assert "example.com" in reason

    def test_wildcard_match(self):
        scope = {"domains": [], "wildcards": ["example.com"], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://sub.example.com", scope)
        assert in_scope
        assert "wildcard" in reason.lower()

    def test_wildcard_matches_base_domain(self):
        scope = {"domains": [], "wildcards": ["example.com"], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://example.com", scope)
        assert in_scope

    def test_url_prefix_match(self):
        scope = {"domains": [], "wildcards": [], "ips": [], "cidrs": [], "urls": ["https://example.com/app"], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://example.com/app/login", scope)
        assert in_scope

    def test_ip_match(self):
        scope = {"domains": [], "wildcards": [], "ips": ["93.184.216.34"], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://93.184.216.34", scope)
        assert in_scope

    def test_cidr_match(self):
        scope = {"domains": [], "wildcards": [], "ips": [], "cidrs": ["10.0.0.0/24"], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://10.0.0.5", scope)
        assert in_scope
        assert "CIDR" in reason

    def test_out_of_scope_blocks(self):
        scope = {"domains": ["example.com"], "wildcards": ["example.com"],
                 "ips": [], "cidrs": [], "urls": [], "out_of_scope": ["staging.example.com"]}
        in_scope, reason = is_target_in_scope("https://staging.example.com", scope)
        assert not in_scope
        assert "out-of-scope" in reason.lower() or "excluded" in reason.lower()

    def test_not_in_scope(self):
        scope = {"domains": ["example.com"], "wildcards": [], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("https://evil.com", scope)
        assert not in_scope

    def test_empty_url(self):
        scope = {"domains": ["example.com"], "wildcards": [], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, reason = is_target_in_scope("", scope)
        assert not in_scope

    def test_case_insensitive(self):
        scope = {"domains": ["example.com"], "wildcards": [], "ips": [], "cidrs": [], "urls": [], "out_of_scope": []}
        in_scope, _ = is_target_in_scope("https://EXAMPLE.COM/path", scope)
        assert in_scope
