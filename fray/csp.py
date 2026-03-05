#!/usr/bin/env python3
"""
Fray CSP — Content Security Policy Analysis & Bypass Mapping

Parses a CSP header, identifies weaknesses, and maps each weakness to
specific bypass techniques that can be tested. Integrates with recon
(auto-detect weak CSP) and bypass/test (load CSP-specific payloads).

Weakness categories:
  - unsafe-inline / unsafe-eval in script-src
  - Missing default-src or overly permissive wildcards
  - Whitelisted JSONP endpoints (*.googleapis.com, etc.)
  - Missing base-uri (base tag injection)
  - Missing object-src (plugin-based XSS)
  - Missing frame-ancestors (clickjacking)
  - Nonce/hash without strict-dynamic
  - data: or blob: URI schemes in script-src
  - Dangling markup opportunities (missing style-src restrictions)

References:
  - https://csp-evaluator.withgoogle.com/
  - https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CSPWeakness:
    """A single weakness found in the CSP."""
    id: str                     # e.g. "unsafe-inline", "jsonp-endpoint"
    severity: str               # "critical", "high", "medium", "low"
    directive: str              # e.g. "script-src", "default-src"
    description: str            # Human-readable explanation
    bypass_technique: str       # Technique tag for payload selection
    exploitable: bool = True    # Can this be actively tested?


@dataclass
class CSPAnalysis:
    """Full CSP analysis result."""
    raw: str = ""
    present: bool = False
    report_only: bool = False
    directives: Dict[str, List[str]] = field(default_factory=dict)
    weaknesses: List[CSPWeakness] = field(default_factory=list)
    score: int = 100            # 0-100 (100 = strong, 0 = no CSP)
    bypass_techniques: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ── Known JSONP / callback endpoints that bypass CSP whitelists ──────────

_JSONP_DOMAINS = {
    "accounts.google.com": "Google accounts JSONP",
    "ajax.googleapis.com": "Google CDN — hosts Angular, jQuery (CSP bypass via callback)",
    "cdn.jsdelivr.net": "jsDelivr CDN — arbitrary JS hosting",
    "cdnjs.cloudflare.com": "Cloudflare CDN — hosts libraries with JSONP",
    "*.cloudflare.com": "Cloudflare CDN wildcard",
    "*.facebook.com": "Facebook SDK JSONP endpoints",
    "*.fbcdn.net": "Facebook CDN",
    "*.google.com": "Google wildcard — includes JSONP endpoints",
    "*.googleapis.com": "Google APIs — known JSONP/callback endpoints",
    "*.googlesyndication.com": "Google Ads — JSONP callbacks",
    "*.googletagmanager.com": "GTM — script injection via container",
    "*.gstatic.com": "Google static — hosts Angular/libraries",
    "maps.google.com": "Google Maps JSONP",
    "maps.googleapis.com": "Google Maps API JSONP",
    "translate.googleapis.com": "Google Translate JSONP",
    "*.twimg.com": "Twitter CDN",
    "*.twitter.com": "Twitter JSONP",
    "*.youtube.com": "YouTube JSONP/embed",
    "*.ytimg.com": "YouTube image CDN",
    "cdn.rawgit.com": "RawGit CDN — arbitrary JS",
    "raw.githubusercontent.com": "GitHub raw — arbitrary file hosting",
    "unpkg.com": "unpkg CDN — npm packages (arbitrary JS)",
    "*.azurewebsites.net": "Azure — user-controlled origins",
    "*.herokuapp.com": "Heroku — user-controlled origins",
    "*.netlify.app": "Netlify — user-controlled origins",
    "*.vercel.app": "Vercel — user-controlled origins",
    "*.pages.dev": "Cloudflare Pages — user-controlled origins",
    "*.workers.dev": "Cloudflare Workers — user-controlled origins",
}

# Domains where whitelisting allows arbitrary JS execution
_UNSAFE_CDN_DOMAINS = {
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "cdn.rawgit.com", "raw.githubusercontent.com",
    "ajax.googleapis.com", "*.googleapis.com",
}

# User-controlled hosting platforms (attacker can host arbitrary JS)
_USER_CONTROLLED_DOMAINS = {
    "*.azurewebsites.net", "*.herokuapp.com", "*.netlify.app",
    "*.vercel.app", "*.pages.dev", "*.workers.dev",
    "*.github.io", "*.gitlab.io", "*.bitbucket.io",
    "*.surge.sh", "*.glitch.me", "*.repl.co",
}


def parse_csp(csp_value: str) -> Dict[str, List[str]]:
    """Parse a CSP header value into {directive: [values]}."""
    directives: Dict[str, List[str]] = {}
    # CSP directives are separated by semicolons
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        values = [t.strip("'\"") for t in tokens[1:]]
        directives[directive] = values
    return directives


def _match_domain(pattern: str, value: str) -> bool:
    """Check if a CSP source value matches a known domain pattern."""
    value = value.lower().replace("https://", "").replace("http://", "").rstrip("/")
    pattern = pattern.lower()
    if pattern.startswith("*."):
        # Wildcard match: *.example.com matches sub.example.com
        suffix = pattern[1:]  # .example.com
        return value.endswith(suffix) or value == pattern[2:]
    return value == pattern


def analyze_csp(csp_value: str, report_only: bool = False) -> CSPAnalysis:
    """Analyze a CSP header and identify weaknesses.

    Args:
        csp_value: Raw CSP header value
        report_only: True if this is Content-Security-Policy-Report-Only

    Returns:
        CSPAnalysis with weaknesses, score, and bypass techniques
    """
    result = CSPAnalysis(
        raw=csp_value,
        present=bool(csp_value.strip()),
        report_only=report_only,
    )

    if not csp_value.strip():
        result.score = 0
        result.weaknesses.append(CSPWeakness(
            id="no-csp",
            severity="critical",
            directive="(none)",
            description="No Content-Security-Policy header — all inline scripts execute freely",
            bypass_technique="inline_script",
            exploitable=True,
        ))
        result.bypass_techniques = ["inline_script", "dangling_markup",
                                     "jsonp_callback", "base_injection"]
        result.recommendations.append("Add a Content-Security-Policy header")
        return result

    directives = parse_csp(csp_value)
    result.directives = directives

    if report_only:
        result.weaknesses.append(CSPWeakness(
            id="report-only",
            severity="high",
            directive="(header)",
            description="CSP is in report-only mode — violations are logged but NOT enforced",
            bypass_technique="inline_script",
            exploitable=True,
        ))
        result.score -= 30

    # ── Effective script-src ──────────────────────────────────────────
    script_src = directives.get("script-src", directives.get("default-src", []))
    default_src = directives.get("default-src", [])

    # No default-src and no script-src → scripts unrestricted
    if "script-src" not in directives and "default-src" not in directives:
        result.weaknesses.append(CSPWeakness(
            id="no-script-restriction",
            severity="critical",
            directive="(none)",
            description="Neither script-src nor default-src defined — scripts unrestricted",
            bypass_technique="inline_script",
        ))
        result.score -= 40

    # unsafe-inline
    if "unsafe-inline" in script_src:
        result.weaknesses.append(CSPWeakness(
            id="unsafe-inline",
            severity="critical",
            directive="script-src",
            description="'unsafe-inline' allows inline <script> tags and event handlers",
            bypass_technique="unsafe_inline",
        ))
        result.score -= 30

    # unsafe-eval
    if "unsafe-eval" in script_src:
        result.weaknesses.append(CSPWeakness(
            id="unsafe-eval",
            severity="high",
            directive="script-src",
            description="'unsafe-eval' allows eval(), Function(), setTimeout('string')",
            bypass_technique="unsafe_eval",
        ))
        result.score -= 20

    # data: URI in script-src
    if "data:" in script_src:
        result.weaknesses.append(CSPWeakness(
            id="data-uri",
            severity="high",
            directive="script-src",
            description="data: URIs in script-src allow <script src='data:text/javascript,...'>",
            bypass_technique="data_uri",
        ))
        result.score -= 20

    # blob: URI in script-src
    if "blob:" in script_src:
        result.weaknesses.append(CSPWeakness(
            id="blob-uri",
            severity="medium",
            directive="script-src",
            description="blob: URIs may allow script execution via Blob URLs",
            bypass_technique="blob_uri",
        ))
        result.score -= 10

    # Wildcard * in script-src
    if "*" in script_src:
        result.weaknesses.append(CSPWeakness(
            id="wildcard-script",
            severity="critical",
            directive="script-src",
            description="Wildcard (*) in script-src allows scripts from any origin",
            bypass_technique="inline_script",
        ))
        result.score -= 40

    # JSONP / unsafe CDN endpoints
    for src_value in script_src:
        for domain_pattern, info in _JSONP_DOMAINS.items():
            if _match_domain(domain_pattern, src_value):
                is_cdn = domain_pattern in _UNSAFE_CDN_DOMAINS
                is_user = domain_pattern in _USER_CONTROLLED_DOMAINS
                if is_user:
                    result.weaknesses.append(CSPWeakness(
                        id=f"user-controlled-{domain_pattern}",
                        severity="critical",
                        directive="script-src",
                        description=f"User-controlled hosting: {src_value} ({info}) — "
                                    f"attacker can host arbitrary JS",
                        bypass_technique="user_controlled_origin",
                    ))
                    result.score -= 25
                elif is_cdn:
                    result.weaknesses.append(CSPWeakness(
                        id=f"unsafe-cdn-{domain_pattern}",
                        severity="high",
                        directive="script-src",
                        description=f"CDN whitelist: {src_value} ({info}) — "
                                    f"hosts libraries with known CSP bypasses",
                        bypass_technique="jsonp_callback",
                    ))
                    result.score -= 15
                else:
                    result.weaknesses.append(CSPWeakness(
                        id=f"jsonp-{domain_pattern}",
                        severity="medium",
                        directive="script-src",
                        description=f"JSONP endpoint: {src_value} ({info})",
                        bypass_technique="jsonp_callback",
                    ))
                    result.score -= 10

    # ── base-uri ──────────────────────────────────────────────────────
    if "base-uri" not in directives:
        result.weaknesses.append(CSPWeakness(
            id="missing-base-uri",
            severity="high",
            directive="base-uri",
            description="Missing base-uri — <base> tag injection can redirect relative script URLs",
            bypass_technique="base_injection",
        ))
        result.score -= 15
    elif "self" not in directives.get("base-uri", []) and \
         "none" not in directives.get("base-uri", []):
        if "*" in directives.get("base-uri", []):
            result.weaknesses.append(CSPWeakness(
                id="wildcard-base-uri",
                severity="high",
                directive="base-uri",
                description="Wildcard base-uri allows <base> tag to any origin",
                bypass_technique="base_injection",
            ))
            result.score -= 15

    # ── object-src ────────────────────────────────────────────────────
    object_src = directives.get("object-src", default_src)
    if not object_src or "*" in object_src or "none" not in object_src:
        has_none = "none" in object_src if object_src else False
        if not has_none:
            result.weaknesses.append(CSPWeakness(
                id="permissive-object-src",
                severity="medium",
                directive="object-src",
                description="object-src not restricted to 'none' — "
                            "plugin-based XSS via <object>/<embed> possible",
                bypass_technique="object_injection",
            ))
            result.score -= 10

    # ── frame-ancestors ───────────────────────────────────────────────
    if "frame-ancestors" not in directives:
        result.weaknesses.append(CSPWeakness(
            id="missing-frame-ancestors",
            severity="medium",
            directive="frame-ancestors",
            description="Missing frame-ancestors — page can be framed (clickjacking)",
            bypass_technique="clickjacking",
            exploitable=False,  # Not an XSS bypass, but still a weakness
        ))
        result.score -= 5

    # ── style-src ─────────────────────────────────────────────────────
    style_src = directives.get("style-src", default_src)
    if not style_src or "unsafe-inline" in style_src:
        result.weaknesses.append(CSPWeakness(
            id="unsafe-inline-style",
            severity="medium",
            directive="style-src",
            description="Inline styles allowed — dangling markup injection for data exfiltration",
            bypass_technique="dangling_markup",
        ))
        result.score -= 10

    # ── Nonce without strict-dynamic ──────────────────────────────────
    has_nonce = any(v.startswith("nonce-") for v in script_src)
    has_hash = any(v.startswith("sha256-") or v.startswith("sha384-")
                   or v.startswith("sha512-") for v in script_src)
    has_strict_dynamic = "strict-dynamic" in script_src

    if (has_nonce or has_hash) and not has_strict_dynamic:
        # Nonce/hash without strict-dynamic: whitelisted domains still apply
        if len([v for v in script_src if not v.startswith("nonce-")
                and not v.startswith("sha") and v not in ("self", "strict-dynamic",
                "unsafe-inline", "unsafe-eval")]) > 0:
            result.weaknesses.append(CSPWeakness(
                id="nonce-without-strict-dynamic",
                severity="medium",
                directive="script-src",
                description="Nonce/hash used but without 'strict-dynamic' — "
                            "whitelisted domains still honored alongside nonce",
                bypass_technique="jsonp_callback",
            ))
            result.score -= 10

    if has_nonce:
        result.weaknesses.append(CSPWeakness(
            id="nonce-present",
            severity="low",
            directive="script-src",
            description="Nonce-based CSP — test for nonce leakage via CSS injection or "
                        "DOM clobbering",
            bypass_technique="nonce_leakage",
        ))

    # ── Clamp score ───────────────────────────────────────────────────
    result.score = max(0, min(100, result.score))

    # ── Collect unique bypass techniques ──────────────────────────────
    techniques = []
    seen = set()
    for w in result.weaknesses:
        if w.exploitable and w.bypass_technique not in seen:
            techniques.append(w.bypass_technique)
            seen.add(w.bypass_technique)
    result.bypass_techniques = techniques

    # ── Recommendations ───────────────────────────────────────────────
    if any(w.id == "unsafe-inline" for w in result.weaknesses):
        result.recommendations.append(
            "Remove 'unsafe-inline' from script-src — use nonce or hash instead")
    if any(w.id == "unsafe-eval" for w in result.weaknesses):
        result.recommendations.append(
            "Remove 'unsafe-eval' from script-src — refactor eval() usage")
    if any(w.id == "missing-base-uri" for w in result.weaknesses):
        result.recommendations.append(
            "Add base-uri 'self' or 'none' to prevent <base> tag injection")
    if any(w.id.startswith("jsonp-") or w.id.startswith("unsafe-cdn-")
           for w in result.weaknesses):
        result.recommendations.append(
            "Use 'strict-dynamic' with nonces instead of domain whitelists")
    if any(w.id.startswith("user-controlled-") for w in result.weaknesses):
        result.recommendations.append(
            "Remove user-controlled hosting platforms from script-src whitelist")
    if any(w.id == "data-uri" for w in result.weaknesses):
        result.recommendations.append(
            "Remove data: from script-src — use nonce-based loading instead")
    if any(w.id == "permissive-object-src" for w in result.weaknesses):
        result.recommendations.append(
            "Set object-src 'none' to block plugin-based script execution")

    return result


def get_csp_from_headers(headers: Dict[str, str]) -> Tuple[str, bool]:
    """Extract CSP value from response headers.

    Returns (csp_value, is_report_only).
    Checks both enforced and report-only headers.
    """
    csp = headers.get("content-security-policy", "")
    if csp:
        return csp, False
    csp_ro = headers.get("content-security-policy-report-only", "")
    if csp_ro:
        return csp_ro, True
    return "", False
