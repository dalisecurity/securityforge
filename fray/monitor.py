"""
Fray Monitor — continuous monitoring with diff + alerting

Usage:
    fray monitor example.com                          # Default: 24h interval
    fray monitor example.com --interval 12h           # Custom interval
    fray monitor example.com --interval 6h --webhook https://hooks.slack.com/...
    fray monitor example.com --once                   # Single run, compare to last
    fray monitor example.com --list                   # List previous snapshots
    fray monitor example.com --email alerts@team.com  # Email alerts (needs RESEND_API_KEY)

Runs recon + leak periodically, diffs against previous results,
sends alerts via webhook (Slack/Discord/Teams) or email when new findings appear.

State stored in ~/.fray/monitor/{domain}/ as timestamped JSON snapshots.

Zero dependencies — stdlib only.
"""

import hashlib
import json
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ── State Management ──────────────────────────────────────────────────

def _monitor_dir(domain: str) -> Path:
    """Return ~/.fray/monitor/{domain}/"""
    return Path.home() / ".fray" / "monitor" / domain


def _list_snapshots(domain: str) -> List[Path]:
    """List all snapshot files for a domain, sorted by timestamp."""
    d = _monitor_dir(domain)
    if not d.exists():
        return []
    snapshots = sorted(d.glob("snapshot_*.json"))
    return snapshots


def _save_snapshot(domain: str, data: Dict[str, Any]) -> Path:
    """Save a monitoring snapshot with timestamp."""
    d = _monitor_dir(domain)
    d.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = d / f"snapshot_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return path


def _load_latest_snapshot(domain: str) -> Optional[Dict[str, Any]]:
    """Load the most recent snapshot for comparison."""
    snapshots = _list_snapshots(domain)
    if not snapshots:
        return None
    with open(snapshots[-1], "r", encoding="utf-8") as f:
        return json.loads(f.read())


# ── Diff Engine ───────────────────────────────────────────────────────

def diff_snapshots(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two monitoring snapshots and return a structured diff.

    Detects:
      - New subdomains
      - New endpoints / parameters
      - WAF changes
      - New technologies
      - New leaked credentials
      - Risk score changes
      - New vulnerabilities
    """
    diff: Dict[str, Any] = {
        "has_changes": False,
        "severity": "info",  # info, low, medium, high, critical
        "new_subdomains": [],
        "removed_subdomains": [],
        "new_endpoints": [],
        "new_params": [],
        "new_technologies": [],
        "waf_changes": {},
        "risk_score_change": None,
        "new_leak_findings": [],
        "alerts": [],
    }

    # Subdomains
    prev_recon = previous.get("recon", {})
    curr_recon = current.get("recon", {})

    prev_subs = set()
    for s in prev_recon.get("subdomains", {}).get("subdomains", []):
        if isinstance(s, dict):
            prev_subs.add(s.get("fqdn", ""))
        elif isinstance(s, str):
            prev_subs.add(s)

    curr_subs = set()
    for s in curr_recon.get("subdomains", {}).get("subdomains", []):
        if isinstance(s, dict):
            curr_subs.add(s.get("fqdn", ""))
        elif isinstance(s, str):
            curr_subs.add(s)

    new_subs = curr_subs - prev_subs
    removed_subs = prev_subs - curr_subs

    if new_subs:
        diff["new_subdomains"] = sorted(new_subs)
        diff["has_changes"] = True
        diff["alerts"].append({
            "severity": "medium",
            "type": "new_subdomains",
            "message": f"{len(new_subs)} new subdomain(s) discovered",
            "details": sorted(new_subs)[:10],
        })

    if removed_subs:
        diff["removed_subdomains"] = sorted(removed_subs)
        diff["has_changes"] = True

    # Endpoints
    prev_eps = set(prev_recon.get("endpoints", []))
    curr_eps = set(curr_recon.get("endpoints", []))
    new_eps = curr_eps - prev_eps
    if new_eps:
        diff["new_endpoints"] = sorted(new_eps)[:50]
        diff["has_changes"] = True
        diff["alerts"].append({
            "severity": "low",
            "type": "new_endpoints",
            "message": f"{len(new_eps)} new endpoint(s) found",
            "details": sorted(new_eps)[:5],
        })

    # Technologies
    prev_tech = set()
    curr_tech = set()
    for t in prev_recon.get("fingerprint", {}).get("technologies", []):
        if isinstance(t, dict):
            prev_tech.add(t.get("name", ""))
        elif isinstance(t, str):
            prev_tech.add(t)
    for t in curr_recon.get("fingerprint", {}).get("technologies", []):
        if isinstance(t, dict):
            curr_tech.add(t.get("name", ""))
        elif isinstance(t, str):
            curr_tech.add(t)
    new_tech = curr_tech - prev_tech
    if new_tech:
        diff["new_technologies"] = sorted(new_tech)
        diff["has_changes"] = True

    # WAF changes
    prev_waf = prev_recon.get("attack_surface", {}).get("waf_vendor", "none")
    curr_waf = curr_recon.get("attack_surface", {}).get("waf_vendor", "none")
    if prev_waf != curr_waf:
        diff["waf_changes"] = {"previous": prev_waf, "current": curr_waf}
        diff["has_changes"] = True
        diff["alerts"].append({
            "severity": "high",
            "type": "waf_change",
            "message": f"WAF changed: {prev_waf} → {curr_waf}",
        })

    # Risk score
    prev_score = prev_recon.get("attack_surface", {}).get("risk_score", 0)
    curr_score = curr_recon.get("attack_surface", {}).get("risk_score", 0)
    if prev_score != curr_score:
        diff["risk_score_change"] = {
            "previous": prev_score,
            "current": curr_score,
            "delta": curr_score - prev_score,
        }
        diff["has_changes"] = True
        if curr_score - prev_score >= 20:
            diff["alerts"].append({
                "severity": "high",
                "type": "risk_increase",
                "message": f"Risk score increased: {prev_score} → {curr_score} (+{curr_score - prev_score})",
            })

    # Leak findings
    prev_leaks = previous.get("leak", {})
    curr_leaks = current.get("leak", {})
    prev_gh_repos = set()
    curr_gh_repos = set()
    for r in (prev_leaks.get("github", {}) or {}).get("repos", []):
        prev_gh_repos.add(r.get("repo", ""))
    for r in (curr_leaks.get("github", {}) or {}).get("repos", []):
        curr_gh_repos.add(r.get("repo", ""))
    new_repos = curr_gh_repos - prev_gh_repos
    if new_repos:
        diff["new_leak_findings"] = sorted(new_repos)
        diff["has_changes"] = True
        diff["alerts"].append({
            "severity": "critical",
            "type": "new_leaks",
            "message": f"{len(new_repos)} new GitHub repo(s) with potential leaks",
            "details": sorted(new_repos)[:5],
        })

    # Determine overall severity
    severities = [a["severity"] for a in diff["alerts"]]
    severity_order = ["critical", "high", "medium", "low", "info"]
    for s in severity_order:
        if s in severities:
            diff["severity"] = s
            break

    return diff


# ── Alerting ──────────────────────────────────────────────────────────

def _send_webhook(webhook_url: str, diff: Dict[str, Any], domain: str) -> bool:
    """Send alert to Slack/Discord/Teams webhook."""
    alerts = diff.get("alerts", [])
    if not alerts:
        return True

    severity_icons = {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🟢", "info": "ℹ️",
    }

    lines = [f"**Fray Monitor Alert — {domain}**"]
    lines.append(f"Severity: {severity_icons.get(diff['severity'], '⚪')} {diff['severity'].upper()}")
    lines.append("")

    for alert in alerts:
        icon = severity_icons.get(alert["severity"], "⚪")
        lines.append(f"{icon} {alert['message']}")
        if alert.get("details"):
            for d in alert["details"][:3]:
                lines.append(f"  • {d}")

    text = "\n".join(lines)

    # Detect webhook type and format accordingly
    if "slack.com" in webhook_url:
        payload = {"text": text}
    elif "discord.com" in webhook_url:
        payload = {"content": text}
    elif "office.com" in webhook_url or "webhook.office" in webhook_url:
        payload = {"text": text}
    else:
        payload = {"text": text}

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Fray-Monitor",
            },
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return resp.status < 400
    except Exception as e:
        sys.stderr.write(f"  ⚠️  Webhook failed: {e}\n")
        return False


def _send_email_alert(email: str, diff: Dict[str, Any], domain: str) -> bool:
    """Send email alert via Resend API."""
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        sys.stderr.write("  ⚠️  RESEND_API_KEY not set — skipping email alert\n")
        return False

    alerts = diff.get("alerts", [])
    if not alerts:
        return True

    severity = diff.get("severity", "info").upper()
    subject = f"[Fray Monitor] {severity} — {domain}"

    body_lines = [f"Fray Monitor Alert for {domain}", ""]
    for alert in alerts:
        body_lines.append(f"[{alert['severity'].upper()}] {alert['message']}")
        if alert.get("details"):
            for d in alert["details"][:5]:
                body_lines.append(f"  • {d}")
        body_lines.append("")

    payload = {
        "from": "fray@dalisec.io",
        "to": [email],
        "subject": subject,
        "text": "\n".join(body_lines),
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return resp.status < 400
    except Exception as e:
        sys.stderr.write(f"  ⚠️  Email alert failed: {e}\n")
        return False


# ── Single Monitor Cycle ──────────────────────────────────────────────

def _run_single_cycle(domain: str, timeout: int = 10,
                      include_leak: bool = False,
                      quiet: bool = False) -> Dict[str, Any]:
    """Run a single recon (+ optional leak) cycle and return snapshot data."""
    from fray.recon.pipeline import run_recon

    snapshot: Dict[str, Any] = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recon": {},
        "leak": {},
    }

    # Run recon
    target = f"https://{domain}" if not domain.startswith("http") else domain
    recon_result = run_recon(target, timeout=timeout, quiet=quiet)
    snapshot["recon"] = recon_result

    # Run leak search if requested
    if include_leak:
        try:
            from fray.leak import search_leaks
            leak_result = search_leaks(domain, timeout=timeout)
            snapshot["leak"] = leak_result
        except Exception as e:
            snapshot["leak"] = {"error": str(e)}

    return snapshot


# ── Parse Interval ────────────────────────────────────────────────────

def _parse_interval(interval_str: str) -> int:
    """Parse interval string (e.g., '24h', '30m', '7d') to seconds."""
    interval_str = interval_str.strip().lower()
    if interval_str.endswith("d"):
        return int(interval_str[:-1]) * 86400
    elif interval_str.endswith("h"):
        return int(interval_str[:-1]) * 3600
    elif interval_str.endswith("m"):
        return int(interval_str[:-1]) * 60
    elif interval_str.endswith("s"):
        return int(interval_str[:-1])
    else:
        return int(interval_str)


# ── Main Monitor Loop ────────────────────────────────────────────────

def run_monitor(domain: str, interval: str = "24h",
                webhook: Optional[str] = None,
                email: Optional[str] = None,
                include_leak: bool = False,
                once: bool = False,
                timeout: int = 10,
                quiet: bool = False) -> None:
    """Run continuous monitoring loop.

    Args:
        domain: Target domain
        interval: Time between scans (e.g., '24h', '12h', '30m')
        webhook: Slack/Discord/Teams webhook URL for alerts
        email: Email address for alerts (needs RESEND_API_KEY)
        include_leak: Also run leak search each cycle
        once: Run single cycle and exit
        timeout: Per-request timeout
        quiet: Suppress recon progress output
    """
    # Strip scheme
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain

    interval_secs = _parse_interval(interval)
    monitor_path = _monitor_dir(domain)

    print(f"\n  🔄 Fray Monitor — {domain}")
    print(f"  {'━' * 50}")
    print(f"  Interval:   {interval} ({interval_secs}s)")
    print(f"  State dir:  {monitor_path}/")
    if webhook:
        print(f"  Webhook:    {webhook[:50]}...")
    if email:
        print(f"  Email:      {email}")
    if include_leak:
        print(f"  Leak scan:  enabled")
    print(f"  {'━' * 50}")

    # Graceful shutdown
    running = [True]
    def _signal_handler(sig, frame):
        running[0] = False
        print(f"\n  ⏹  Monitor stopped (received signal {sig})")
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    cycle = 0
    while running[0]:
        cycle += 1
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n  ── Cycle {cycle} ({now}) {'─' * 20}")

        # Load previous snapshot for diff
        previous = _load_latest_snapshot(domain)

        # Run scan
        snapshot = _run_single_cycle(domain, timeout=timeout,
                                     include_leak=include_leak, quiet=quiet)

        # Save snapshot
        path = _save_snapshot(domain, snapshot)
        print(f"  💾 Snapshot saved: {path.name}")

        # Diff against previous
        if previous:
            diff = diff_snapshots(previous, snapshot)
            if diff["has_changes"]:
                severity_icons = {
                    "critical": "🔴", "high": "🟠", "medium": "🟡",
                    "low": "🟢", "info": "ℹ️",
                }
                print(f"\n  {severity_icons.get(diff['severity'], '⚪')} "
                      f"Changes detected ({diff['severity'].upper()}):")
                for alert in diff["alerts"]:
                    icon = severity_icons.get(alert["severity"], "⚪")
                    print(f"    {icon} {alert['message']}")

                # Send alerts
                if webhook:
                    ok = _send_webhook(webhook, diff, domain)
                    print(f"    📤 Webhook: {'sent ✓' if ok else 'failed ✗'}")
                if email:
                    ok = _send_email_alert(email, diff, domain)
                    print(f"    📧 Email: {'sent ✓' if ok else 'failed ✗'}")
            else:
                print(f"  ✅ No changes since last scan")
        else:
            print(f"  📊 First scan — baseline established")

        if once:
            break

        # Wait for next cycle
        next_time = datetime.now(timezone.utc).timestamp() + interval_secs
        next_str = datetime.fromtimestamp(next_time, tz=timezone.utc).strftime("%H:%M:%S UTC")
        print(f"\n  ⏳ Next scan at {next_str} (in {interval})")

        # Sleep in small increments so SIGINT works
        elapsed = 0
        while elapsed < interval_secs and running[0]:
            time.sleep(min(10, interval_secs - elapsed))
            elapsed += 10

    snapshots = _list_snapshots(domain)
    print(f"\n  📁 {len(snapshots)} snapshot(s) stored in {monitor_path}/")


def list_snapshots(domain: str) -> None:
    """List all stored monitoring snapshots for a domain."""
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain

    snapshots = _list_snapshots(domain)
    if not snapshots:
        print(f"\n  No snapshots for {domain}")
        print(f"  Run: fray monitor {domain}")
        return

    print(f"\n  📁 Monitoring History — {domain}")
    print(f"  {'━' * 50}")
    for s in snapshots:
        size = s.stat().st_size
        # Extract timestamp from filename
        ts = s.stem.replace("snapshot_", "")
        try:
            dt = datetime.strptime(ts, "%Y%m%d_%H%M%S")
            ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            ts_str = ts
        print(f"    {ts_str}  ({size:,} bytes)  {s.name}")
    print(f"\n  Total: {len(snapshots)} snapshot(s)")
    print(f"  Path:  {_monitor_dir(domain)}/")
