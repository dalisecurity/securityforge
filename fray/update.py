#!/usr/bin/env python3
"""
Fray Update — Pull latest payloads from GitHub without reinstalling.

Downloads the latest payload archive from the Fray repository,
extracts it, and replaces the local payloads directory.

Usage:
    fray update
    fray update --check   # Check for updates without applying
"""

import http.client
import io
import json
import os
import shutil
import ssl
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple

from fray import __version__, PAYLOADS_DIR, PACKAGE_DIR


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


_REPO_OWNER = "dalisecurity"
_REPO_NAME = "Fray"
_BRANCH = "main"
_API_HOST = "api.github.com"
_RAW_HOST = "raw.githubusercontent.com"


def _https_get(host: str, path: str, headers: Optional[dict] = None) -> Tuple[int, bytes, dict]:
    """Make an HTTPS GET request using stdlib only."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, context=ctx, timeout=15)
    hdrs = {"User-Agent": f"Fray/{__version__}"}
    if headers:
        hdrs.update(headers)
    conn.request("GET", path, headers=hdrs)
    resp = conn.getresponse()
    status = resp.status
    body = resp.read()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return status, body, resp_headers


def _follow_redirect(host: str, path: str, headers: Optional[dict] = None, max_hops: int = 5) -> Tuple[int, bytes]:
    """Follow redirects for HTTPS GET."""
    for _ in range(max_hops):
        status, body, resp_headers = _https_get(host, path, headers)
        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("location", "")
            if location.startswith("https://"):
                from urllib.parse import urlparse
                parsed = urlparse(location)
                host = parsed.hostname
                path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                continue
            elif location.startswith("/"):
                path = location
                continue
        return status, body
    return status, body


def check_latest_version() -> Optional[str]:
    """Check the latest version tag from GitHub releases."""
    path = f"/repos/{_REPO_OWNER}/{_REPO_NAME}/releases/latest"
    try:
        status, body, _ = _https_get(_API_HOST, path, {"Accept": "application/vnd.github+json"})
        if status == 200:
            data = json.loads(body)
            return data.get("tag_name", "").lstrip("v")
        # If no releases, check the __init__.py on main
        path = f"/{_REPO_OWNER}/{_REPO_NAME}/{_BRANCH}/fray/__init__.py"
        status, body = _follow_redirect(_RAW_HOST, path)
        if status == 200:
            for line in body.decode("utf-8").splitlines():
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return None


def count_payloads(payloads_dir: Path) -> int:
    """Count total payload files."""
    return sum(1 for _ in payloads_dir.rglob("*.json"))


def download_and_update(dry_run: bool = False) -> bool:
    """Download latest payloads from GitHub and replace local copy."""
    url_path = f"/repos/{_REPO_OWNER}/{_REPO_NAME}/zipball/{_BRANCH}"
    print(f"  {Colors.DIM}Downloading from github.com/{_REPO_OWNER}/{_REPO_NAME}@{_BRANCH}...{Colors.END}")

    try:
        status, body = _follow_redirect(
            _API_HOST, url_path,
            {"Accept": "application/vnd.github+json", "User-Agent": f"Fray/{__version__}"}
        )
    except Exception as e:
        print(f"  {Colors.RED}Download failed: {e}{Colors.END}")
        return False

    if status != 200:
        print(f"  {Colors.RED}Download failed: HTTP {status}{Colors.END}")
        return False

    print(f"  {Colors.DIM}Downloaded {len(body) / 1024:.0f} KB{Colors.END}")

    if dry_run:
        print(f"  {Colors.YELLOW}Dry run — no changes applied.{Colors.END}")
        return True

    # Extract payloads from zip
    try:
        zf = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile:
        print(f"  {Colors.RED}Invalid zip file received.{Colors.END}")
        return False

    # Find the payloads directory inside the zip
    # GitHub zip has a top-level dir like "dalisecurity-Fray-abc1234/"
    payload_prefix = None
    for name in zf.namelist():
        # Look for fray/payloads/ inside the archive
        if "/fray/payloads/" in name and name.endswith(".json"):
            parts = name.split("/fray/payloads/", 1)
            payload_prefix = parts[0] + "/fray/payloads/"
            break

    if not payload_prefix:
        print(f"  {Colors.RED}Could not find payloads directory in downloaded archive.{Colors.END}")
        return False

    # Extract to temp dir first, then swap
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_payloads = Path(tmpdir) / "payloads"
        tmp_payloads.mkdir()

        extracted = 0
        for name in zf.namelist():
            if name.startswith(payload_prefix) and not name.endswith("/"):
                relative = name[len(payload_prefix):]
                dest = tmp_payloads / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
                extracted += 1

        if extracted == 0:
            print(f"  {Colors.RED}No payload files found in archive.{Colors.END}")
            return False

        # Backup existing payloads
        backup_dir = PACKAGE_DIR / "payloads.bak"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)

        if PAYLOADS_DIR.exists():
            shutil.move(str(PAYLOADS_DIR), str(backup_dir))

        # Move new payloads into place
        shutil.move(str(tmp_payloads), str(PAYLOADS_DIR))

        # Clean up backup
        if backup_dir.exists():
            shutil.rmtree(backup_dir)

        print(f"  {Colors.GREEN}Updated {extracted} payload files.{Colors.END}")

    return True


def run_update(check_only: bool = False):
    """Main entry point for fray update."""
    print(f"\n{Colors.BOLD}Fray Update{Colors.END}")
    print(f"{Colors.DIM}{'━' * 50}{Colors.END}")
    print(f"  Current version: {Colors.CYAN}{__version__}{Colors.END}")

    current_count = count_payloads(PAYLOADS_DIR)
    print(f"  Local payloads:  {current_count} files")

    # Check remote version
    print(f"  {Colors.DIM}Checking github.com/{_REPO_OWNER}/{_REPO_NAME}...{Colors.END}")
    remote_version = check_latest_version()
    if remote_version:
        print(f"  Remote version:  {Colors.CYAN}{remote_version}{Colors.END}")
        if remote_version == __version__:
            print(f"  {Colors.GREEN}Already up to date!{Colors.END}")
            if check_only:
                return
        else:
            print(f"  {Colors.YELLOW}New version available: {remote_version}{Colors.END}")
    else:
        print(f"  {Colors.DIM}Could not check remote version (continuing anyway).{Colors.END}")

    if check_only:
        print(f"\n  {Colors.DIM}Run 'fray update' to apply updates.{Colors.END}\n")
        return

    # Download and update
    print()
    success = download_and_update()
    if success:
        new_count = count_payloads(PAYLOADS_DIR)
        diff = new_count - current_count
        diff_str = f" ({Colors.GREEN}+{diff}{Colors.END})" if diff > 0 else (f" ({diff})" if diff < 0 else "")
        print(f"  Payloads now:    {new_count} files{diff_str}")
        print(f"\n  {Colors.GREEN}Update complete!{Colors.END}\n")
    else:
        print(f"\n  {Colors.RED}Update failed. Your existing payloads are unchanged.{Colors.END}\n")
