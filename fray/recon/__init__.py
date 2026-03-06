"""
Fray Recon — Target Reconnaissance & Fingerprinting

Package structure (incrementally refactored from _monolith.py):
  http.py        — URL parsing, SSL context, HTTP GET, TLS audit
  _monolith.py   — remaining implementation (being extracted)

All public symbols are re-exported here so existing imports
like `from fray.recon import run_recon` continue to work.
"""

# ── Extracted submodules ──
from fray.recon.http import (  # noqa: F401
    _parse_url,
    _make_ssl_context,
    _http_get,
    check_http,
    check_tls,
)
from fray.recon.fingerprint import (  # noqa: F401
    check_security_headers,
    check_cookies,
    fingerprint_app,
    recommend_categories,
)

# ── Remaining (from monolith, being incrementally extracted) ──
from fray.recon._monolith import (  # noqa: F401
    Colors,
    _follow_redirect,
    _post_json,
    _fetch_url,
    # Supply chain
    _parse_version,
    check_frontend_libs,
    fetch_retirejs_db,
    # DNS
    check_dns,
    check_subdomains_crt,
    check_subdomains_bruteforce,
    discover_origin_ip,
    # Extended checks
    check_robots_sitemap,
    check_cors,
    check_exposed_files,
    check_http_methods,
    check_error_page,
    check_graphql_introspection,
    check_api_discovery,
    check_host_header_injection,
    check_admin_panels,
    check_rate_limits,
    # WAF analysis
    check_differential_responses,
    waf_gap_analysis,
    # Historical URLs
    discover_historical_urls,
    print_historical_urls,
    # Parameter mining
    discover_params,
    mine_params,
    print_mined_params,
    # JS endpoint extraction
    discover_js_endpoints,
    print_js_endpoints,
    # Comparison / history
    _load_previous_recon,
    diff_recon,
    print_recon_diff,
    # Pipeline
    run_recon,
    print_recon,
)
