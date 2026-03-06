"""Fray Recon — legacy monolith shim.

All implementation has been extracted to submodules:
  http.py, fingerprint.py, supply_chain.py, history.py,
  dns.py, checks.py, discovery.py, pipeline.py

This file retains only Colors (used across fray.*) and
re-exports _follow_redirect / _post_json / _fetch_url
for any remaining `from fray.recon._monolith import` callsites.
"""

from fray.recon.http import (  # noqa: F401
    _follow_redirect,
    _post_json,
    _fetch_url,
)


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'
