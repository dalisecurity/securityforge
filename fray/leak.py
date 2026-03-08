"""
Fray Leak Search — GitHub code search + Have I Been Pwned breach lookup

Usage:
    fray leak example.com                    # Search GitHub + HIBP for leaks
    fray leak example.com --github-only      # GitHub code search only
    fray leak example.com --hibp-only        # HIBP breach lookup only
    fray leak example.com --json             # JSON output
    fray leak user@example.com               # Check specific email in HIBP

Environment variables:
    GITHUB_TOKEN      — Required for GitHub code search (personal access token)
    HIBP_API_KEY      — Optional: enables domain-wide HIBP search (haveibeenpwned.com/API/Key)

Zero dependencies — stdlib only (urllib.request, json, ssl).
"""

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


# ── Regex-based secret detection ────────────────────────────────────────
# Detect ACTUAL secrets (not just keyword mentions).
# Each tuple: (name, compiled_regex, severity)

_SECRET_REGEXES = [
    ("AWS Access Key",        re.compile(r'AKIA[0-9A-Z]{16}'),                          "critical"),
    ("AWS Secret Key",        re.compile(r'[\'"][0-9a-zA-Z/+]{40}[\'"]'),             "critical"),
    ("GitHub PAT",            re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),                "critical"),
    ("GitHub OAuth",          re.compile(r'gho_[A-Za-z0-9_]{36,}'),                      "critical"),
    ("Stripe Live Key",       re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                   "critical"),
    ("Stripe Publishable",    re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),                   "high"),
    ("Slack Token",           re.compile(r'xox[baprs]-[0-9]{10,}-[0-9a-zA-Z-]+'),       "critical"),
    ("Slack Webhook",         re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'), "high"),
    ("Google API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                     "high"),
    ("Google OAuth",          re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "high"),
    ("Private Key",           re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),"critical"),
    ("JWT Token",             re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+'),      "high"),
    ("Sendgrid API Key",      re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),  "critical"),
    ("Twilio API Key",        re.compile(r'SK[0-9a-f]{32}'),                              "high"),
    ("Mailgun API Key",       re.compile(r'key-[0-9a-zA-Z]{32}'),                         "high"),
    ("Square Access Token",   re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),                  "critical"),
    ("Telegram Bot Token",    re.compile(r'[0-9]{8,10}:[A-Za-z0-9_-]{35}'),              "high"),
    ("Discord Webhook",       re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'), "high"),
    ("Firebase URL",          re.compile(r'[a-z0-9-]+\.firebaseio\.com'),                "medium"),
    ("Generic Secret",        re.compile(r'(?:password|passwd|pwd|secret|token|api_?key|access_?key)\s*[=:]\s*[\'\"][^\'\"\{\s]{8,}[\'\"]', re.IGNORECASE), "high"),
]


def scan_text_for_secrets(text: str) -> List[Dict[str, str]]:
    """Scan text for real secrets using regex patterns.

    Returns list of {type, match, severity} for each detected secret.
    """
    found = []
    seen = set()
    for name, pattern, severity in _SECRET_REGEXES:
        for m in pattern.finditer(text):
            match_str = m.group(0)[:80]  # Truncate for safety
            key = f"{name}:{match_str[:20]}"
            if key not in seen:
                seen.add(key)
                found.append({
                    "type": name,
                    "match": match_str,
                    "severity": severity,
                })
    return found


# ── GitHub Code Search ──────────────────────────────────────────────────

# Sensitive patterns to search for alongside the target domain
_GITHUB_PATTERNS = [
    "password",
    "api_key",
    "apikey",
    "api-key",
    "secret_key",
    "secret",
    "token",
    "access_token",
    "private_key",
    "client_secret",
    "aws_access_key_id",
    "aws_secret_access_key",
    "database_url",
    "db_password",
    "smtp_password",
    "authorization",
    "bearer",
]


def _github_api_request(url: str, token: str, timeout: int = 10,
                        max_retries: int = 6) -> Optional[dict]:
    """Make an authenticated GitHub API request with auto-retry on rate limit.

    GitHub code search: 10 requests/minute for authenticated users.
    On 403/429, reads X-RateLimit-Reset and waits the exact time needed,
    retrying up to max_retries times (enough for all 17 patterns across
    multiple rate-limit windows).
    """
    req_headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Fray-Leak-Scanner",
    }
    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers=req_headers)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset", "")
                retry_after = e.headers.get("Retry-After", "")
                remaining = e.headers.get("X-RateLimit-Remaining", "")
                if attempt < max_retries - 1:
                    if reset:
                        wait = max(int(reset) - int(time.time()), 1)
                    elif retry_after:
                        wait = int(retry_after)
                    else:
                        # Exponential backoff: 30, 45, 60, 60, 60
                        wait = min(30 * (1.5 ** attempt), 60)
                    # Cap at 120s per wait (2 rate-limit windows max)
                    wait = min(int(wait), 120)
                    sys.stderr.write(
                        f"  \u23f3 GitHub rate limit \u2014 waiting {wait}s "
                        f"(attempt {attempt + 1}/{max_retries})\r")
                    sys.stderr.flush()
                    time.sleep(wait)
                    continue
                if reset:
                    wait = max(int(reset) - int(time.time()), 1)
                    return {"error": f"GitHub rate limit exceeded. Resets in {wait}s.", "rate_limited": True}
                return {"error": "GitHub API rate limit exceeded.", "rate_limited": True}
            elif e.code == 401:
                return {"error": "Invalid GITHUB_TOKEN. Check your token permissions.", "auth_error": True}
            elif e.code == 422:
                return {"error": "GitHub search validation error (HTTP 422).", "total_count": 0}
            return {"error": f"GitHub API error: HTTP {e.code}", "total_count": 0}
        except Exception as e:
            return {"error": f"GitHub API request failed: {e}", "total_count": 0}
    return {"error": "GitHub API: max retries exceeded.", "rate_limited": True}


def _fetch_file_content(url: str, token: str, timeout: int = 10) -> str:
    """Fetch raw file content from GitHub API for secret scanning."""
    req_headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.raw",
        "User-Agent": "Fray-Leak-Scanner",
    }
    req = urllib.request.Request(url, headers=req_headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(10240).decode("utf-8", errors="replace")
    except Exception:
        return ""


def search_github(domain: str, token: str, max_patterns: int = 17,
                  timeout: int = 10, auto_retry: bool = True) -> Dict[str, Any]:
    """Search GitHub code for leaked credentials mentioning the target domain.

    With auto_retry=True, waits and retries on rate limit to cover all patterns.
    Fetches file content and runs regex secret detection on matches.
    """
    results = []
    total_matches = 0
    errors = []
    rate_limited = False
    confirmed_secrets = []
    max_retries = 3 if auto_retry else 1

    patterns_to_search = _GITHUB_PATTERNS[:max_patterns]
    # With auto_retry, use enough retries to span multiple rate-limit windows
    api_retries = 6 if auto_retry else 1

    for i, pattern in enumerate(patterns_to_search):
        query = f'"{domain}" "{pattern}"'
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded}&per_page=5&sort=indexed&order=desc"

        sys.stderr.write(
            f"\r  \U0001f50d GitHub [{i + 1}/{len(patterns_to_search)}] {pattern:<25}"
        )
        sys.stderr.flush()

        data = _github_api_request(url, token, timeout, max_retries=api_retries)
        if not data:
            continue

        if data.get("rate_limited"):
            errors.append(data["error"])
            rate_limited = True
            break

        if data.get("auth_error"):
            errors.append(data["error"])
            break

        if data.get("error"):
            errors.append(data["error"])
            continue

        count = data.get("total_count", 0)
        items = data.get("items", [])

        if count > 0:
            total_matches += count
            for item in items[:3]:
                repo = item.get("repository", {})
                api_url = item.get("url", "")
                html_url = item.get("html_url", "")

                entry = {
                    "pattern": pattern,
                    "total_matches": count,
                    "file": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file_url": html_url,
                    "score": item.get("score", 0),
                    "secrets_detected": [],
                }

                # Fetch file content and scan for real secrets
                if api_url:
                    content = _fetch_file_content(api_url, token, timeout)
                    if content:
                        secrets = scan_text_for_secrets(content)
                        entry["secrets_detected"] = secrets
                        for s in secrets:
                            confirmed_secrets.append({
                                **s,
                                "file": entry["file"],
                                "repo": entry["repo"],
                            })

                results.append(entry)

        # Pace requests to stay under 10/min limit
        # GitHub code search: 10 req/min. ~6s between requests avoids hitting it.
        if i < len(patterns_to_search) - 1:
            time.sleep(6)

    sys.stderr.write("\r" + " " * 60 + "\r")  # Clear progress line
    sys.stderr.flush()

    # Deduplicate by repo
    seen_repos = {}
    for r in results:
        repo = r["repo"]
        if repo not in seen_repos:
            seen_repos[repo] = {
                "repo": repo,
                "repo_url": r["repo_url"],
                "patterns_found": [],
                "files": [],
                "confirmed_secrets": [],
            }
        if r["pattern"] not in seen_repos[repo]["patterns_found"]:
            seen_repos[repo]["patterns_found"].append(r["pattern"])
        seen_repos[repo]["files"].append({
            "path": r["file"],
            "pattern": r["pattern"],
            "url": r["file_url"],
        })
        if r.get("secrets_detected"):
            seen_repos[repo]["confirmed_secrets"].extend(r["secrets_detected"])

    return {
        "source": "github",
        "domain": domain,
        "total_matches": total_matches,
        "repos_with_leaks": len(seen_repos),
        "patterns_searched": len(patterns_to_search),
        "rate_limited": rate_limited,
        "confirmed_secrets": confirmed_secrets,
        "errors": errors,
        "repos": list(seen_repos.values()),
    }


# ── GitHub Gist Search ──────────────────────────────────────────────────

def search_github_gists(domain: str, token: str, timeout: int = 10,
                        max_retries: int = 3) -> Dict[str, Any]:
    """Search GitHub for config/secret files mentioning the target domain.

    Targets .env, .yml, .json, .conf, .sh, .py files \u2014 common leak vectors.
    """
    gist_patterns = ["password", "api_key", "secret", "token", "private_key"]
    results = []
    errors = []
    rate_limited = False

    for i, pattern in enumerate(gist_patterns):
        query = f'"{domain}" "{pattern}"'
        encoded = urllib.parse.quote(query)
        url = (f"https://api.github.com/search/code?q={encoded}"
               f"+in:file+language:shell+language:python+language:yaml"
               f"+language:json&per_page=5&sort=indexed&order=desc")

        data = _github_api_request(url, token, timeout, max_retries=max_retries)
        if not data:
            continue

        if data.get("rate_limited"):
            errors.append(data["error"])
            rate_limited = True
            break

        if data.get("auth_error") or data.get("error"):
            if data.get("error"):
                errors.append(data["error"])
            break

        items = data.get("items", [])
        for item in items[:3]:
            path = item.get("path", "")
            if any(ext in path.lower() for ext in (".env", ".yml", ".yaml", ".json",
                    ".conf", ".cfg", ".ini", ".toml", ".sh", ".py", ".rb", ".js")):
                repo = item.get("repository", {})
                results.append({
                    "pattern": pattern,
                    "file": path,
                    "repo": repo.get("full_name", ""),
                    "file_url": item.get("html_url", ""),
                })

        if i < len(gist_patterns) - 1:
            time.sleep(2)

    return {
        "source": "github_gists",
        "domain": domain,
        "matches": len(results),
        "rate_limited": rate_limited,
        "errors": errors,
        "results": results,
    }


# ── Have I Been Pwned ───────────────────────────────────────────────────

def _hibp_request(url: str, api_key: Optional[str] = None,
                  timeout: int = 10) -> Optional[Any]:
    """Make HIBP API request."""
    headers = {
        "User-Agent": "Fray-Leak-Scanner",
    }
    if api_key:
        headers["hibp-api-key"] = api_key

    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # Not found = clean
        elif e.code == 401:
            return {"error": "HIBP API key required for this endpoint. Set HIBP_API_KEY env var."}
        elif e.code == 429:
            retry = e.headers.get("Retry-After", "2")
            return {"error": f"HIBP rate limited. Retry after {retry}s."}
        return {"error": f"HIBP API error: HTTP {e.code}"}
    except Exception as e:
        return {"error": f"HIBP request failed: {e}"}


def search_hibp_email(email: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if a specific email appears in HIBP breaches.

    This endpoint is free and does not require an API key.
    """
    encoded = urllib.parse.quote(email)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"

    data = _hibp_request(url, timeout=timeout)

    if data is None:
        return {
            "source": "hibp",
            "email": email,
            "breached": False,
            "breach_count": 0,
            "breaches": [],
        }

    if isinstance(data, dict) and data.get("error"):
        return {
            "source": "hibp",
            "email": email,
            "breached": False,
            "error": data["error"],
            "breaches": [],
        }

    breaches = []
    for b in data if isinstance(data, list) else []:
        breaches.append({
            "name": b.get("Name", ""),
            "domain": b.get("Domain", ""),
            "date": b.get("BreachDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "is_verified": b.get("IsVerified", False),
            "is_sensitive": b.get("IsSensitive", False),
        })

    return {
        "source": "hibp",
        "email": email,
        "breached": len(breaches) > 0,
        "breach_count": len(breaches),
        "breaches": breaches,
    }


def search_hibp_breaches(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Search the public HIBP breach catalog for breaches involving the target domain.

    This endpoint is free and requires no API key. It checks the full breach
    list and filters for breaches whose Domain field matches the target.
    """
    url = "https://haveibeenpwned.com/api/v3/breaches"
    data = _hibp_request(url, timeout=timeout)

    if data is None or (isinstance(data, dict) and data.get("error")):
        error = data.get("error", "Failed to fetch breach list") if data else "No response"
        return {
            "source": "hibp",
            "domain": domain,
            "method": "public_breach_catalog",
            "breached": False,
            "error": error,
            "breaches": [],
        }

    # Filter breaches where the breached service's domain matches our target
    # Also check if the domain appears in the breach Name field
    matching = []
    domain_lower = domain.lower()
    if isinstance(data, list):
        for b in data:
            breach_domain = (b.get("Domain") or "").lower()
            breach_name = (b.get("Name") or "").lower()
            if domain_lower == breach_domain or domain_lower in breach_domain:
                matching.append({
                    "name": b.get("Name", ""),
                    "domain": b.get("Domain", ""),
                    "date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified", False),
                    "description": b.get("Description", "")[:200],
                })

    return {
        "source": "hibp",
        "domain": domain,
        "method": "public_breach_catalog",
        "breached": len(matching) > 0,
        "breach_count": len(matching),
        "total_pwned": sum(b["pwn_count"] for b in matching),
        "breaches": matching,
    }


def search_hibp_domain(domain: str, api_key: Optional[str] = None,
                       timeout: int = 10) -> Dict[str, Any]:
    """Search HIBP for all breached emails on a domain.

    Requires a paid HIBP API key or domain verification at haveibeenpwned.com/DomainSearch.
    """
    encoded = urllib.parse.quote(domain)
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{encoded}"

    data = _hibp_request(url, api_key=api_key, timeout=timeout)

    if data is None:
        return {
            "source": "hibp",
            "domain": domain,
            "breached": False,
            "total_emails": 0,
            "emails": [],
        }

    if isinstance(data, dict) and data.get("error"):
        return {
            "source": "hibp",
            "domain": domain,
            "breached": False,
            "error": data["error"],
            "emails": [],
        }

    # Domain search returns {alias: [breach_names]}
    emails = []
    if isinstance(data, dict):
        for alias, breach_names in data.items():
            emails.append({
                "email": f"{alias}@{domain}",
                "breaches": breach_names,
                "breach_count": len(breach_names),
            })

    # Sort by breach count descending
    emails.sort(key=lambda x: x["breach_count"], reverse=True)

    return {
        "source": "hibp",
        "domain": domain,
        "breached": len(emails) > 0,
        "total_emails": len(emails),
        "total_breaches": sum(e["breach_count"] for e in emails),
        "emails": emails,
    }


# ── Combined search ─────────────────────────────────────────────────────

def search_leaks(target: str, github: bool = True, hibp: bool = True,
                 timeout: int = 10) -> Dict[str, Any]:
    """Run combined leak search across GitHub and HIBP.

    Args:
        target: Domain (example.com) or email (user@example.com)
        github: Enable GitHub code search
        hibp: Enable HIBP breach lookup
        timeout: Request timeout

    Returns:
        Combined results dict with 'github' and 'hibp' keys.
    """
    is_email = "@" in target
    domain = target.split("@")[1] if is_email else target

    # Strip scheme if present
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain

    result = {
        "target": target,
        "domain": domain,
        "is_email": is_email,
        "github": None,
        "hibp": None,
        "summary": {},
    }

    # GitHub code search
    if github and not is_email:
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        if gh_token:
            result["github"] = search_github(domain, gh_token, timeout=timeout)
            # Also search config-file patterns (Gist-like)
            result["github_gists"] = search_github_gists(domain, gh_token, timeout=timeout)
        else:
            result["github"] = {
                "source": "github",
                "error": "GITHUB_TOKEN not set. Export your GitHub personal access token to enable code search.",
                "skipped": True,
            }

    # HIBP
    if hibp:
        hibp_key = os.environ.get("HIBP_API_KEY", "") or None

        if is_email:
            # Single email lookup (requires API key since v3)
            result["hibp"] = search_hibp_email(target, timeout=timeout)
        elif hibp_key:
            # Domain search with API key — returns per-email breakdown
            result["hibp"] = search_hibp_domain(domain, api_key=hibp_key, timeout=timeout)
        else:
            # Free: search public breach catalog for this domain
            result["hibp"] = search_hibp_breaches(domain, timeout=timeout)

    # Summary
    gh = result.get("github") or {}
    gists = result.get("github_gists") or {}
    hb = result.get("hibp") or {}

    risk_factors = []
    actions = []
    gh_leaks = gh.get("repos_with_leaks", 0)
    hb_breached = hb.get("breached", False)
    n_confirmed = len(gh.get("confirmed_secrets", []))
    n_gist_matches = gists.get("matches", 0)

    # ── Collect risk factors ──
    if n_confirmed > 0:
        risk_factors.append(f"{n_confirmed} confirmed secret(s) (regex-verified)")
    if gh_leaks > 0:
        risk_factors.append(f"{gh_leaks} GitHub repos with keyword matches")
    if n_gist_matches > 0:
        risk_factors.append(f"{n_gist_matches} config file(s) with domain + secrets")
    if hb_breached:
        if hb.get("total_emails"):
            risk_factors.append(f"{hb['total_emails']} emails in {hb.get('total_breaches', 0)} breaches")
        elif hb.get("breach_count"):
            risk_factors.append(f"{hb['breach_count']} breaches found")

    # ── Determine risk level ──
    if n_confirmed > 0:
        risk_level = "critical"
    elif gh_leaks > 5 or (gh_leaks > 0 and hb_breached):
        risk_level = "high"
    elif gh_leaks > 0 or hb_breached:
        risk_level = "medium"
    else:
        risk_level = "low"

    # ── Build recommended actions ──
    if gh_leaks > 0:
        # Check which patterns were found across all repos
        all_patterns = set()
        for repo in gh.get("repos", []):
            all_patterns.update(repo.get("patterns_found", []))

        actions.append({
            "priority": "critical",
            "action": "Review and revoke exposed credentials",
            "detail": f"Audit {gh_leaks} repo(s) for live secrets. "
                       f"Patterns found: {', '.join(sorted(all_patterns)[:6])}",
        })
        actions.append({
            "priority": "high",
            "action": "Enable GitHub secret scanning",
            "detail": "Settings → Code security → Secret scanning. "
                       "Also consider GitHub push protection to block future leaks.",
        })
        if any(p in all_patterns for p in ("aws_access_key_id", "aws_secret_access_key")):
            actions.append({
                "priority": "critical",
                "action": "Rotate AWS credentials immediately",
                "detail": "AWS keys found in public repos. Rotate in IAM console "
                           "and check CloudTrail for unauthorized usage.",
            })
        if any(p in all_patterns for p in ("password", "db_password", "database_url", "smtp_password")):
            actions.append({
                "priority": "high",
                "action": "Rotate exposed passwords and database credentials",
                "detail": "Change all passwords that match leaked values. "
                           "Enable MFA on all accounts.",
            })
        if any(p in all_patterns for p in ("api_key", "apikey", "api-key", "token", "access_token",
                                            "client_secret", "secret_key", "secret", "bearer")):
            actions.append({
                "priority": "high",
                "action": "Rotate API keys and tokens",
                "detail": "Regenerate all API keys/tokens that may match leaked values. "
                           "Review API access logs for suspicious activity.",
            })

    if hb_breached:
        # Get leaked data classes
        data_classes = set()
        for b in hb.get("breaches", []):
            data_classes.update(b.get("data_classes", []))

        if "Passwords" in data_classes or "Password" in data_classes:
            actions.append({
                "priority": "critical",
                "action": "Force password reset for breached accounts",
                "detail": "Passwords were exposed. Enforce password reset for all "
                           "affected users and enable MFA.",
            })
        if data_classes:
            actions.append({
                "priority": "high",
                "action": "Notify affected users per breach disclosure policy",
                "detail": f"Exposed data types: {', '.join(sorted(data_classes)[:8])}",
            })
        actions.append({
            "priority": "medium",
            "action": "Monitor for credential stuffing attacks",
            "detail": "Breached credentials are commonly used in automated "
                       "login attacks. Monitor auth logs for unusual patterns.",
        })
        actions.append({
            "priority": "medium",
            "action": "Verify domain at haveibeenpwned.com/DomainSearch",
            "detail": "Get per-email breach breakdown after DNS verification.",
        })

    if risk_level == "low":
        actions.append({
            "priority": "low",
            "action": "No immediate action required",
            "detail": "Continue monitoring. Set up HIBP domain notifications "
                       "and enable GitHub secret scanning as preventive measures.",
        })

    result["summary"] = {
        "github_repos_with_leaks": gh_leaks,
        "confirmed_secrets": n_confirmed,
        "gist_matches": n_gist_matches,
        "hibp_breached": hb_breached,
        "risk_factors": risk_factors,
        "risk_level": risk_level,
        "recommended_actions": actions,
    }

    return result


# ── Recon integration ───────────────────────────────────────────────────

def run_leak_check(domain: str, timeout: int = 8) -> Dict[str, Any]:
    """Lightweight leak check for recon pipeline integration.

    Runs a faster subset of leak searches suitable for embedding
    in fray recon --leak. Uses fewer patterns and shorter timeouts.

    Returns a compact dict for inclusion in recon results.
    """
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    hibp_key = os.environ.get("HIBP_API_KEY", "") or None

    result = {
        "github_repos": 0,
        "confirmed_secrets": 0,
        "hibp_breaches": 0,
        "hibp_pwn_count": 0,
        "risk_level": "low",
        "risk_factors": [],
        "details": {},
    }

    # GitHub: search top 5 patterns only (fast mode)
    if gh_token:
        gh = search_github(domain, gh_token, max_patterns=5,
                           timeout=timeout, auto_retry=False)
        result["github_repos"] = gh.get("repos_with_leaks", 0)
        result["confirmed_secrets"] = len(gh.get("confirmed_secrets", []))
        result["details"]["github"] = {
            "repos_with_leaks": gh.get("repos_with_leaks", 0),
            "total_matches": gh.get("total_matches", 0),
            "confirmed_secrets": gh.get("confirmed_secrets", [])[:5],
            "top_repos": [r["repo"] for r in gh.get("repos", [])[:5]],
        }

    # HIBP: breach catalog (free, fast)
    hb = search_hibp_breaches(domain, timeout=timeout)
    if hb.get("breached"):
        result["hibp_breaches"] = hb.get("breach_count", 0)
        result["hibp_pwn_count"] = hb.get("total_pwned", 0)
        result["details"]["hibp"] = {
            "breach_count": hb.get("breach_count", 0),
            "total_pwned": hb.get("total_pwned", 0),
            "breaches": [{"name": b["name"], "date": b["date"],
                          "pwn_count": b["pwn_count"]}
                         for b in hb.get("breaches", [])[:5]],
        }

    # Risk assessment
    factors = []
    if result["confirmed_secrets"] > 0:
        factors.append(f"{result['confirmed_secrets']} confirmed secret(s) on GitHub")
    if result["github_repos"] > 0:
        factors.append(f"{result['github_repos']} GitHub repo(s) with credentials")
    if result["hibp_breaches"] > 0:
        factors.append(f"{result['hibp_breaches']} breach(es) ({result['hibp_pwn_count']:,} accounts)")

    result["risk_factors"] = factors

    if result["confirmed_secrets"] > 0:
        result["risk_level"] = "critical"
    elif result["github_repos"] > 0 and result["hibp_breaches"] > 0:
        result["risk_level"] = "high"
    elif result["github_repos"] > 0 or result["hibp_breaches"] > 0:
        result["risk_level"] = "medium"

    return result


# ── Pretty-print ────────────────────────────────────────────────────────

def print_leak_results(result: Dict[str, Any]) -> None:
    """Pretty-print leak search results."""
    target = result.get("target", "?")
    domain = result.get("domain", "?")

    print(f"\n{'═' * 60}")
    print(f"  🔍 Leak Search — {target}")
    print(f"{'═' * 60}")

    # ── GitHub results ──
    gh = result.get("github")
    if gh:
        print(f"\n  📁 GitHub Code Search")
        print(f"  {'─' * 40}")

        if gh.get("skipped"):
            print(f"  ⚠️  {gh.get('error', 'Skipped')}")
        elif gh.get("error") and not gh.get("repos"):
            print(f"  ❌ {gh['error']}")
        else:
            repos = gh.get("repos", [])
            total = gh.get("total_matches", 0)
            print(f"  Patterns searched: {gh.get('patterns_searched', 0)}")
            print(f"  Total matches:     {total}")
            print(f"  Repos with leaks:  {len(repos)}")

            # Show confirmed secrets first (regex-detected real secrets)
            confirmed = gh.get("confirmed_secrets", [])
            if confirmed:
                print(f"\n  🚨 Confirmed Secrets (regex-verified):")
                severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡"}
                seen = set()
                for s in confirmed[:15]:
                    key = f"{s['type']}:{s.get('repo', '')}"
                    if key in seen:
                        continue
                    seen.add(key)
                    icon = severity_icons.get(s.get("severity", ""), "⚪")
                    # Redact middle of match for safety
                    match = s.get("match", "")
                    if len(match) > 16:
                        redacted = match[:8] + "…" + match[-4:]
                    else:
                        redacted = match
                    print(f"  {icon} {s['type']}: {redacted}")
                    if s.get("repo"):
                        print(f"     in {s['repo']} → {s.get('file', '')}")
                print()

            if repos:
                print(f"  📂 Repos with keyword matches:")
                print()
                for repo in repos[:10]:  # Show top 10 repos
                    has_secrets = bool(repo.get("confirmed_secrets"))
                    icon = "🚨" if has_secrets else "🔴"
                    patterns = ", ".join(repo["patterns_found"][:5])
                    print(f"  {icon} {repo['repo']}")
                    print(f"     Patterns: {patterns}")
                    for f in repo["files"][:3]:
                        print(f"     → {f['path']}")
                    print(f"     {repo['repo_url']}")
                    print()
            else:
                print(f"  ✅ No leaked credentials found on GitHub")

            if gh.get("rate_limited"):
                print(f"  ⚠️  Search was rate-limited. Re-run later for full results.")

            if gh.get("errors"):
                for err in gh["errors"]:
                    print(f"  ⚠️  {err}")

    # ── Gist/config file results ──
    gists = result.get("github_gists")
    if gists and gists.get("matches", 0) > 0:
        print(f"\n  📄 Config Files (shell/python/yaml/json/env)")
        print(f"  {'─' * 40}")
        print(f"  Matches: {gists['matches']}")
        for g in gists.get("results", [])[:10]:
            print(f"  • {g['repo']} → {g['file']} (pattern: {g['pattern']})")
            if g.get("file_url"):
                print(f"    {g['file_url']}")
        if gists.get("rate_limited"):
            print(f"  ⚠️  Rate-limited. Re-run later for full results.")

    # ── HIBP results ──
    hb = result.get("hibp")
    if hb:
        print(f"\n  🔓 Have I Been Pwned")
        print(f"  {'─' * 40}")

        if hb.get("skipped"):
            print(f"  ⚠️  {hb.get('note', hb.get('error', 'Skipped'))}")
        elif hb.get("error"):
            print(f"  ❌ {hb['error']}")
        elif result.get("is_email"):
            # Single email result
            if hb.get("breached"):
                print(f"  ❌ {hb['email']} found in {hb['breach_count']} breach(es):")
                print()
                for b in hb.get("breaches", [])[:10]:
                    verified = "✓" if b.get("is_verified") else "?"
                    data = ", ".join(b.get("data_classes", [])[:5])
                    print(f"  [{verified}] {b['name']} ({b['date']}) — {b['pwn_count']:,} accounts")
                    if data:
                        print(f"      Data: {data}")
            else:
                print(f"  ✅ {hb.get('email', target)} — not found in any breaches")
        elif hb.get("method") == "public_breach_catalog":
            # Free breach catalog search
            if hb.get("breached"):
                total_pwned = hb.get("total_pwned", 0)
                print(f"  ❌ {domain} appears in {hb['breach_count']} known breach(es) ({total_pwned:,} accounts)")
                print()
                for b in hb.get("breaches", [])[:10]:
                    verified = "✓" if b.get("is_verified") else "?"
                    data = ", ".join(b.get("data_classes", [])[:5])
                    print(f"  [{verified}] {b['name']} ({b['date']}) — {b['pwn_count']:,} accounts")
                    if data:
                        print(f"      Data: {data}")
                print(f"\n  ℹ️  For per-email breakdown, verify domain at haveibeenpwned.com/DomainSearch")
            else:
                print(f"  ✅ {domain} not found in HIBP breach catalog")
                print(f"     (checked {len(hb.get('breaches', []))} known breaches)")
        else:
            # Domain result with API key (per-email breakdown)
            if hb.get("breached"):
                print(f"  ❌ {hb['total_emails']} email(s) from {domain} found in breaches")
                print(f"     Total breach entries: {hb.get('total_breaches', 0)}")
                print()
                for e in hb.get("emails", [])[:15]:
                    print(f"  • {e['email']} — {e['breach_count']} breach(es): {', '.join(e['breaches'][:3])}")
            else:
                print(f"  ✅ No breached emails found for {domain}")

    # ── Summary ──
    summary = result.get("summary", {})
    risk = summary.get("risk_level", "low")
    factors = summary.get("risk_factors", [])
    actions = summary.get("recommended_actions", [])

    print(f"\n  {'─' * 40}")
    risk_icons = {"critical": "🔴", "high": "�", "medium": "🟡", "low": "🟢"}
    print(f"  {risk_icons.get(risk, '⚪')} Risk Level: {risk.upper()}")
    if factors:
        for f in factors:
            print(f"     • {f}")

    if actions:
        print(f"\n  📋 Recommended Actions")
        print(f"  {'─' * 40}")
        priority_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for a in actions:
            icon = priority_icons.get(a.get("priority", "medium"), "⚪")
            print(f"  {icon} [{a['priority'].upper()}] {a['action']}")
            print(f"     {a['detail']}")

    print(f"{'═' * 60}\n")
