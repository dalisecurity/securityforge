#!/usr/bin/env python3
"""
Fray Smuggling — HTTP Request Smuggling Detection

Detects CL.TE and TE.CL desync vulnerabilities using safe, non-destructive
timing-based probes. Does NOT smuggle real requests or alter application state.

Detection technique (per James Kettle / PortSwigger research):
  - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding.
    Probe sends short CL + chunked body. If back-end parses TE, it waits
    for the terminating chunk → measurable timeout delay = desync.
  - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length.
    Probe sends chunked body with CL shorter than actual. If back-end
    parses CL, it reads less data → different response or timeout.

Safety:
  - Probes contain no smuggled second request
  - Body content is benign (zeros, terminators)
  - Each probe is a single self-contained HTTP request
  - No persistent state changes on server

References:
  - https://portswigger.net/research/http-request-smuggling
  - https://portswigger.net/web-security/request-smuggling
"""

import re
import socket
import ssl
import time
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class SmuggleProbeResult:
    """Result of a single smuggling probe."""
    probe_type: str = ""          # "CL.TE", "TE.CL", "TE.TE"
    variant: str = ""             # probe variant name
    status: int = 0               # HTTP status code
    response_time: float = 0.0    # seconds
    response_length: int = 0
    timed_out: bool = False
    error: str = ""
    desync_detected: bool = False
    confidence: str = ""          # "high", "medium", "low"
    description: str = ""


@dataclass
class SmuggleReport:
    """Full smuggling detection report."""
    target: str = ""
    timestamp: str = ""
    duration: str = ""
    vulnerable: bool = False
    desync_types: List[str] = field(default_factory=list)
    confidence: str = ""          # overall confidence
    probes: List[Dict] = field(default_factory=list)
    baseline_time: float = 0.0
    tips: List[str] = field(default_factory=list)


class _Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'


def _resolve_and_check(host: str) -> str:
    """Resolve hostname and block private IPs."""
    ip_str = socket.gethostbyname(host)
    ip = ipaddress.ip_address(ip_str)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"Resolved to private/internal IP: {ip_str}")
    return ip_str


def _raw_request_timed(host: str, port: int, use_ssl: bool, request: bytes,
                       timeout: float = 10.0, verify_ssl: bool = True,
                       verbose: bool = False) -> Tuple[int, str, float, bool]:
    """Send raw bytes and return (status, response, elapsed, timed_out).

    Uses bytes directly (not str) to preserve exact smuggling probe format.
    """
    C = _Colors
    try:
        resolved_ip = _resolve_and_check(host)
    except (socket.gaierror, ValueError) as e:
        if isinstance(e, ValueError):
            raise
        resolved_ip = host

    try:
        sock = socket.create_connection((resolved_ip, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            if not verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = sock

        if verbose:
            print(f"\n{C.DIM}>>> SMUGGLE PROBE ({len(request)} bytes) >>>{C.END}")
            # Show first 300 bytes, replacing \r\n with visible markers
            preview = request[:300].decode('utf-8', errors='replace')
            print(f"{C.DIM}{repr(preview)}{C.END}")

        start = time.time()
        conn.sendall(request)

        resp = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                resp += data
                if len(resp) > 50000:
                    break
            except socket.timeout:
                elapsed = time.time() - start
                conn.close()
                return 0, "", elapsed, True
            except (socket.error, OSError):
                break

        elapsed = time.time() - start
        conn.close()

        resp_str = resp.decode('utf-8', errors='replace')
        status_match = re.search(r'HTTP/[\d.]+ (\d+)', resp_str)
        status = int(status_match.group(1)) if status_match else 0

        if verbose:
            print(f"{C.DIM}<<< RESPONSE: status={status}, {len(resp_str)} bytes, "
                  f"{elapsed:.2f}s <<<{C.END}")

        return status, resp_str, elapsed, False

    except socket.timeout:
        return 0, "", timeout, True
    except Exception as e:
        return 0, str(e), 0.0, False


# ── Probe Builders ──────────────────────────────────────────────────────────

def _build_baseline_probe(host: str, path: str) -> bytes:
    """Normal GET request to establish baseline response time."""
    return (f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n").encode()


def _build_clte_probe(host: str, path: str) -> bytes:
    """CL.TE detection probe.

    Content-Length says body is 4 bytes, but body contains a chunked
    terminator that's longer. If back-end uses Transfer-Encoding: chunked,
    it will try to parse chunks and wait for more data → timeout = desync.

    Safe: no smuggled second request, just a terminator mismatch.
    """
    body = b"0\r\n\r\n"
    # CL is intentionally shorter than the actual body
    # If front-end uses CL (reads 4 bytes: "0\r\n\r"), back-end uses TE
    # (tries to parse chunks, reads "0\r\n" as terminator) → normal response.
    # But if we set CL even shorter, back-end waits for chunk data → timeout.
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 4\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


def _build_clte_delay_probe(host: str, path: str) -> bytes:
    """CL.TE timing probe — designed to cause a measurable delay.

    CL says 6 bytes. Body starts with chunk size "1" but we only send
    partial chunk data. If back-end uses TE, it waits for chunk completion.
    """
    # The body: "1\r\nZ\r\n" = valid chunk of 1 byte ("Z"), then we DON'T
    # send the terminating "0\r\n\r\n". If back-end parses TE, it hangs
    # waiting for the next chunk.
    body = b"1\r\nZ\r\n"
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 6\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


def _build_tecl_probe(host: str, path: str) -> bytes:
    """TE.CL detection probe.

    Transfer-Encoding says chunked, but Content-Length is shorter than
    the full chunked body. If back-end uses CL, it reads fewer bytes
    and may return a normal response while the front-end parsed more.

    Safe: body is just "0" with a terminator — no smuggled request.
    """
    body = b"0\r\n\r\n"
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 0\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


def _build_tecl_delay_probe(host: str, path: str) -> bytes:
    """TE.CL timing probe — designed to cause measurable delay.

    Sends valid chunked encoding but CL=0. If front-end uses TE and
    back-end uses CL, back-end ignores the body (CL=0) and responds
    immediately while front-end is still reading chunks.

    If the response is much faster than baseline, that's a signal too.
    """
    body = b"5\r\nHello\r\n0\r\n\r\n"
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 0\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


def _build_te_te_probe(host: str, path: str) -> bytes:
    """TE.TE detection probe — obfuscated Transfer-Encoding.

    Some servers normalize TE headers differently. Using non-standard
    variants like "Transfer-Encoding: xchunked" or extra whitespace
    can cause front-end/back-end to disagree on which TE to use.

    Safe: benign body, no smuggled request.
    """
    body = b"0\r\n\r\n"
    # Obfuscated TE — some servers strip the "x", others don't
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 5\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Transfer-encoding: x\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


def _build_te_newline_probe(host: str, path: str) -> bytes:
    """TE header with embedded newline/tab — parser confusion.

    Some front-ends parse "Transfer-Encoding:\\tchunked" as TE,
    while back-ends may ignore the malformed header.
    """
    body = b"0\r\n\r\n"
    request = (f"POST {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: 5\r\n"
               f"Transfer-Encoding:\tchunked\r\n"
               f"Connection: close\r\n\r\n").encode()
    return request + body


# ── Detection Engine ────────────────────────────────────────────────────────

# Timing threshold multiplier: if response takes >Nx baseline, suspicious
_TIMING_MULTIPLIER = 3.0
_MIN_DELAY_SECONDS = 2.0


def run_smuggling_detection(target: str, timeout: int = 10, delay: float = 1.0,
                            verify_ssl: bool = True, verbose: bool = False) -> SmuggleReport:
    """Run HTTP request smuggling detection probes.

    Args:
        target: URL to test (e.g., https://example.com)
        timeout: Request timeout in seconds
        delay: Delay between probes in seconds
        verify_ssl: Verify SSL certificates
        verbose: Print raw request/response details

    Returns:
        SmuggleReport with detection results
    """
    from datetime import datetime

    start_time = time.time()
    C = _Colors

    # Parse target
    if not target.startswith('http'):
        target = f'https://{target}'
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    use_ssl = parsed.scheme == 'https'
    path = parsed.path or '/'

    report = SmuggleReport(
        target=target,
        timestamp=datetime.now().isoformat(),
    )

    if verbose:
        print(f"\n{C.BOLD}{'━' * 60}{C.END}")
        print(f"{C.BOLD}  Fray Smuggling — HTTP Desync Detection{C.END}")
        print(f"{C.BOLD}{'━' * 60}{C.END}")
        print(f"  Target: {target}")
        print(f"  Method: Timing-based CL.TE / TE.CL / TE.TE probes")
        print(f"  Safety: Detection only — no smuggled requests\n")

    # ── Phase 1: Baseline ────────────────────────────────────────────────
    if verbose:
        print(f"  {C.CYAN}Phase 1: Establishing baseline response time...{C.END}")

    baseline_times = []
    for i in range(3):
        probe = _build_baseline_probe(host, path)
        status, resp, elapsed, timed_out = _raw_request_timed(
            host, port, use_ssl, probe, timeout=timeout,
            verify_ssl=verify_ssl, verbose=verbose
        )
        if not timed_out and status > 0:
            baseline_times.append(elapsed)
        if i < 2:
            time.sleep(delay)

    if not baseline_times:
        if verbose:
            print(f"    {C.RED}Could not establish baseline — target unreachable{C.END}")
        report.tips.append("Target unreachable — cannot perform smuggling detection")
        return report

    baseline_avg = sum(baseline_times) / len(baseline_times)
    report.baseline_time = round(baseline_avg, 3)

    if verbose:
        print(f"    Baseline: {baseline_avg:.3f}s avg ({len(baseline_times)} samples)")

    # ── Phase 2: Smuggling Probes ────────────────────────────────────────
    probes = [
        ("CL.TE", "clte_basic", "CL.TE basic: CL=4 + chunked terminator",
         _build_clte_probe(host, path)),
        ("CL.TE", "clte_delay", "CL.TE timing: partial chunk to trigger wait",
         _build_clte_delay_probe(host, path)),
        ("TE.CL", "tecl_basic", "TE.CL basic: CL=0 + chunked body",
         _build_tecl_probe(host, path)),
        ("TE.CL", "tecl_delay", "TE.CL timing: CL=0 + full chunked body",
         _build_tecl_delay_probe(host, path)),
        ("TE.TE", "te_te_dual", "TE.TE: duplicate Transfer-Encoding headers",
         _build_te_te_probe(host, path)),
        ("TE.TE", "te_newline", "TE.TE: tab-prefixed Transfer-Encoding value",
         _build_te_newline_probe(host, path)),
    ]

    if verbose:
        print(f"\n  {C.CYAN}Phase 2: Running {len(probes)} smuggling probes...{C.END}")

    desync_types = set()
    results = []

    for probe_type, variant, description, probe_bytes in probes:
        time.sleep(delay)

        status, resp, elapsed, timed_out = _raw_request_timed(
            host, port, use_ssl, probe_bytes, timeout=timeout,
            verify_ssl=verify_ssl, verbose=verbose
        )

        # Detect desync: timeout or significant delay vs baseline
        desync = False
        confidence = "low"

        if timed_out:
            # Request timed out — strong indicator of desync
            desync = True
            confidence = "high"
        elif elapsed > max(baseline_avg * _TIMING_MULTIPLIER, baseline_avg + _MIN_DELAY_SECONDS):
            # Response significantly slower than baseline
            desync = True
            confidence = "medium"
        elif status == 0:
            # Connection error — could indicate server confusion
            confidence = "low"
        elif status in (400, 501):
            # Server rejected the ambiguous headers — NOT vulnerable
            # (this is actually good — the server validates properly)
            confidence = "none"

        if desync:
            desync_types.add(probe_type)

        result = SmuggleProbeResult(
            probe_type=probe_type,
            variant=variant,
            status=status,
            response_time=round(elapsed, 3),
            response_length=len(resp),
            timed_out=timed_out,
            desync_detected=desync,
            confidence=confidence,
            description=description,
        )
        results.append(result)

        if verbose:
            if desync:
                timeout_tag = " TIMEOUT" if timed_out else ""
                print(f"    {C.RED}⚠ DESYNC{C.END} [{probe_type}] {variant} | "
                      f"{elapsed:.2f}s (baseline: {baseline_avg:.2f}s){timeout_tag}")
            elif status in (400, 501):
                print(f"    {C.GREEN}SAFE{C.END}    [{probe_type}] {variant} | "
                      f"status {status} — server rejects ambiguous headers")
            else:
                print(f"    {C.DIM}OK{C.END}      [{probe_type}] {variant} | "
                      f"status {status}, {elapsed:.2f}s")

    # ── Phase 3: Confirmation — eliminate false positives ──────────────
    # The delay probes send incomplete chunks, so ANY server that parses TE
    # will hang — that's normal, not a desync. A true CL.TE desync requires
    # the front-end to use CL (forwarding the short body) while the back-end
    # uses TE (hanging on the incomplete chunk). Cross-reference:
    #   - If basic probe (complete body) got a fast response AND delay probe
    #     timed out → server just parses TE normally → NOT a desync.
    #   - If basic probe ALSO timed out or errored → possible real desync.
    result_by_variant = {r.variant: r for r in results}

    # CL.TE confirmation
    clte_basic = result_by_variant.get("clte_basic")
    clte_delay = result_by_variant.get("clte_delay")
    if clte_delay and clte_delay.desync_detected and clte_basic:
        if not clte_basic.timed_out and clte_basic.status > 0:
            # Basic probe completed fine → server parses TE normally
            # Delay probe timeout is just incomplete-chunk behavior, not desync
            clte_delay.desync_detected = False
            clte_delay.confidence = "none"
            clte_delay.description += " (false positive: server parses TE normally)"
            desync_types.discard("CL.TE")
            if verbose:
                print(f"\n    {C.DIM}↳ CL.TE downgraded: basic probe OK → "
                      f"delay timeout is normal TE parsing, not desync{C.END}")

    # TE.CL confirmation
    tecl_basic = result_by_variant.get("tecl_basic")
    tecl_delay = result_by_variant.get("tecl_delay")
    if tecl_delay and tecl_delay.desync_detected and tecl_basic:
        if not tecl_basic.timed_out and tecl_basic.status > 0:
            tecl_delay.desync_detected = False
            tecl_delay.confidence = "none"
            tecl_delay.description += " (false positive: server handles CL/TE consistently)"
            desync_types.discard("TE.CL")
            if verbose:
                print(f"    {C.DIM}↳ TE.CL downgraded: basic probe OK → "
                      f"no desync detected{C.END}")

    # TE.TE confirmation: only flag if at least one TE.TE probe shows desync
    # and the duplicate-header probe wasn't rejected (400)
    te_dual = result_by_variant.get("te_te_dual")
    if te_dual and te_dual.status in (400, 501):
        # Server rejects duplicate TE — that's secure behavior
        desync_types.discard("TE.TE")

    # ── Build Report ─────────────────────────────────────────────────────
    report.probes = [asdict(r) for r in results]
    report.desync_types = sorted(desync_types)
    report.vulnerable = len(desync_types) > 0

    # Overall confidence
    high_count = sum(1 for r in results if r.desync_detected and r.confidence == "high")
    med_count = sum(1 for r in results if r.desync_detected and r.confidence == "medium")
    if high_count >= 2:
        report.confidence = "high"
    elif high_count >= 1:
        report.confidence = "medium"
    elif med_count >= 2:
        report.confidence = "medium"
    elif med_count >= 1 or high_count >= 1:
        report.confidence = "low"
    else:
        report.confidence = "none"

    # Tips
    if report.vulnerable:
        report.tips.append("HTTP request smuggling detected — this is a critical vulnerability")
        if "CL.TE" in desync_types:
            report.tips.append("CL.TE desync: front-end uses Content-Length, back-end uses Transfer-Encoding")
            report.tips.append("Mitigation: normalize TE handling, reject ambiguous requests at front-end")
        if "TE.CL" in desync_types:
            report.tips.append("TE.CL desync: front-end uses Transfer-Encoding, back-end uses Content-Length")
            report.tips.append("Mitigation: ensure back-end supports chunked encoding or strip TE header")
        if "TE.TE" in desync_types:
            report.tips.append("TE.TE desync: front-end and back-end disagree on Transfer-Encoding parsing")
            report.tips.append("Mitigation: normalize Transfer-Encoding headers, reject malformed variants")
        report.tips.append("Use HTTP/2 end-to-end to eliminate CL/TE ambiguity")
    else:
        report.tips.append("No smuggling detected — server properly handles CL/TE ambiguity")
        rejected = sum(1 for r in results if r.status in (400, 501))
        if rejected > 0:
            report.tips.append(f"Server rejected {rejected}/{len(results)} ambiguous probes (good)")

    elapsed = time.time() - start_time
    report.duration = f"{int(elapsed)}s"

    return report


def print_smuggle_report(report: SmuggleReport) -> None:
    """Print formatted smuggling detection report."""
    C = _Colors

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
    print(f"{C.BOLD}  Fray Smuggling — Detection Report{C.END}")
    print(f"{C.BOLD}{'━' * 60}{C.END}")
    print(f"  Target:   {report.target}")
    print(f"  Duration: {report.duration}")
    print(f"  Baseline: {report.baseline_time}s avg response time")

    # Verdict
    if report.vulnerable:
        conf_color = C.RED if report.confidence == "high" else C.YELLOW
        print(f"\n  {C.RED}{C.BOLD}⚠ VULNERABLE — HTTP Request Smuggling Detected{C.END}")
        print(f"  Confidence: {conf_color}{C.BOLD}{report.confidence.upper()}{C.END}")
        print(f"  Desync types: {', '.join(report.desync_types)}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}✓ NOT VULNERABLE{C.END}")
        print(f"  Server properly handles CL/TE header ambiguity")

    # Probe results
    print(f"\n  {'─' * 45}")
    print(f"  {C.CYAN}Probe Results:{C.END}")
    for p in report.probes:
        if p["desync_detected"]:
            timeout_tag = " TIMEOUT" if p["timed_out"] else ""
            print(f"    {C.RED}⚠ DESYNC{C.END}  [{p['probe_type']}] {p['variant']} | "
                  f"{p['response_time']}s | confidence: {p['confidence']}{timeout_tag}")
        elif p["status"] in (400, 501):
            print(f"    {C.GREEN}SAFE{C.END}     [{p['probe_type']}] {p['variant']} | "
                  f"status {p['status']} — rejects ambiguous request")
        else:
            print(f"    {C.DIM}OK{C.END}       [{p['probe_type']}] {p['variant']} | "
                  f"status {p['status']}, {p['response_time']}s")

    # Tips
    if report.tips:
        print(f"\n  {C.CYAN}Analysis:{C.END}")
        for tip in report.tips:
            print(f"    💡 {tip}")

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
