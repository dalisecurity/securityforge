# Why I Built SecurityForge — And Why I'm Giving It Away

*A deep dive into building an open-source offensive security toolkit with 4,025+ payloads, 25 WAF fingerprints, and AI-native workflows*

---

## The Problem Nobody Talks About

Here's a dirty secret in web application security: **most companies have no idea if their WAF actually works.**

They pay $5,000–$50,000/year for a Web Application Firewall — Cloudflare, AWS WAF, Akamai, Imperva — slap it in front of their app, and assume they're protected. They run a quick scan with a commercial tool, see a green checkmark, and move on.

But what happens when a real attacker shows up?

I've spent years in security consulting, and the pattern is always the same:

1. Company deploys WAF with default rules
2. Company assumes they're safe
3. Attacker bypasses WAF in 15 minutes using a $0 payload from a GitHub repo
4. Company gets breached
5. Repeat

The problem isn't the WAF vendors — they build solid products. The problem is **nobody stress-tests their WAF configuration with real-world attack payloads.** And the few tools that exist are either:

- **Outdated** — last updated in 2019, missing modern bypass techniques
- **Fragmented** — scattered across 50 different repos with no organization
- **Expensive** — commercial tools that cost more than the WAF itself
- **Unusable** — raw text files with no tooling, no reports, no workflow

I built SecurityForge to fix all four.

---

## What SecurityForge Actually Is

SecurityForge is an open-source offensive security toolkit. At its core, it's a **curated database of 4,025+ attack payloads** organized across 15 categories, paired with:

- **A WAF detector** that fingerprints 25 vendors automatically
- **An interactive CLI** that guides you through testing
- **AI integration** that lets Claude Code and ChatGPT drive your testing
- **A report generator** that produces professional HTML output

But the real value isn't the tool — it's the **payloads themselves** and how they're organized.

### The Payload Philosophy

Every payload in SecurityForge has a purpose. I didn't just scrape random XSS strings from the internet. Each payload is:

- **Categorized** by attack vector (XSS, SQLi, SSRF, SSTI, XXE, etc.)
- **Mapped to OWASP** frameworks (Top 10, Mobile, LLM, API)
- **Tagged with CVEs** where applicable
- **Tested against real WAFs** to verify they actually work
- **Documented** with descriptions explaining what each payload does

This matters because when you're testing a WAF, you need to know *why* a payload should be blocked, not just *that* it should be blocked.

---

## The Nitty Gritty: What's Inside

### 4,025+ Payloads Across 15 Categories

Let me break down what's actually in the database, because this is where SecurityForge earns its keep:

**Cross-Site Scripting (XSS) — 779 payloads**
This is the largest category, and for good reason. XSS is the most common web vulnerability (OWASP A03:2021), and WAF bypass techniques evolve constantly. The collection includes:

- Classic `<script>alert(1)</script>` variants (yes, some WAFs still miss these)
- Event handler abuse: `<img src=x onerror=alert(1)>` and 200+ variations
- Encoding bypasses: double URL encoding, Unicode, HTML entities, mixed case
- DOM-based XSS payloads targeting client-side frameworks
- Mutation XSS (mXSS) payloads that exploit browser parsing differences
- **2025-2026 bypass techniques** using template literals, CSS injection, and SVG abuse

**SQL Injection — 148 payloads**
- Classic UNION-based, blind boolean, and time-based injection
- NoSQL injection for MongoDB, CouchDB
- Second-order injection payloads
- WAF bypass variants: comment injection, whitespace alternatives, encoding tricks

**Server-Side Request Forgery (SSRF) — 72 payloads**
- Cloud metadata endpoint targeting (AWS `169.254.169.254`, GCP, Azure)
- DNS rebinding payloads
- Protocol smuggling (gopher://, dict://, file://)
- Internal network scanning payloads

**Server-Side Template Injection (SSTI) — 62 payloads**
- Jinja2, Twig, Freemarker, Velocity, Mako
- RCE chains for each template engine
- Sandbox escape techniques

**LLM/AI Security — 300+ payloads**
This is the category I'm most excited about. As organizations deploy LLMs in production, prompt injection and jailbreaks are the new XSS. The collection includes:
- Direct prompt injection (DPI)
- Indirect prompt injection via RAG poisoning
- Jailbreak techniques (DAN, role-playing, encoding tricks)
- Data exfiltration through LLM responses
- Tool/function calling abuse

**Command Injection — 125 payloads**
**Path Traversal — 59 payloads**
**LDAP Injection — 55 payloads**
**XPath Injection — 54 payloads**
**CRLF Injection — 54 payloads**
**Open Redirect — 51 payloads**
**XXE — 34 payloads**

Plus **120 CVE-specific exploit payloads** from 2020-2026, including CISA KEV entries like Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), and Palo Alto GlobalProtect (CVE-2024-3400).

### 138 Modern Bypass Techniques (2025-2026)

This section alone is worth the clone. These are bypass techniques discovered in the last 18 months that most WAFs haven't caught up to yet:

- Chunked transfer encoding abuse
- HTTP/2 header smuggling
- Unicode normalization bypasses
- Polyglot payloads (valid in multiple contexts)
- Browser-specific parsing quirks
- Content-Type confusion attacks

---

## WAF Detection: The 25 Vendors

Before you test payloads, you need to know what you're up against. SecurityForge's WAF detector identifies 25 vendors by analyzing:

- **HTTP response headers** — most WAFs inject custom headers
- **Cookies** — WAF session cookies have distinctive naming patterns
- **Error pages** — block pages contain vendor-specific HTML
- **Server signatures** — some WAFs modify the `Server` header
- **Response timing** — WAF processing adds measurable latency

Here are the 25 vendors we detect:

| Vendor | What to look for |
|--------|-----------------|
| Cloudflare | `cf-ray` header, `__cfduid` cookie |
| Akamai | `akamai-grn` header, `ak_bmsc` cookie |
| AWS WAF | `x-amzn-waf-action`, CloudFront headers |
| Imperva | `x-iinfo` header, `incap_ses` cookie |
| F5 BIG-IP | `x-wa-info`, `bigipserver` cookie |
| Fastly | `x-sigsci-requestid`, `x-served-by` |
| Azure WAF | `x-azure-fdid`, `arr_affinity` cookie |
| Google Cloud Armor | `x-cloud-trace-context`, `gfe` server |
| Barracuda | `x-barracuda-url` header |
| Citrix NetScaler | `citrix-transactionid`, `nsc_` cookie |
| Radware | `x-protected-by` header |
| Palo Alto | `x-pan-` headers |
| Check Point | `x-checkpoint` header |
| ModSecurity | `x-mod-security`, Server header |
| Qualys WAF | `x-qualys` header |
| Penta Security | `x-wapples` header |
| StackPath | `x-stackpath-shield` header |
| Sophos | `x-sophos` header |
| Scutum | `x-scutum` header |
| Rohde & Schwarz | `x-rs-` headers |
| Sucuri | `x-sucuri-id`, `sucuri_cloudproxy_uuid` |
| Fortinet FortiWeb | `x-fortiweb`, `fortiwafsid` cookie |
| Wallarm | `x-wallarm-waf-check` header |
| Reblaze | `x-reblaze-protection`, `rbzid` cookie |
| Vercel | `x-vercel-id`, `x-vercel-cache` |

Each detection comes with a **confidence score** (0-100%) so you know how certain the identification is.

---

## Why Open Source?

I could have kept this proprietary. A curated payload database with WAF detection and AI integration has real commercial value — security consulting firms would pay for it.

But here's why I'm open-sourcing it:

### 1. Security Through Transparency

The attackers already have these payloads. They share them in private Telegram channels, dark web forums, and closed bug bounty communities. The defenders are the ones who don't have access.

By making this public, I'm leveling the playing field. Every security team, every startup, every indie developer can now test their defenses against the same payloads that real attackers use.

### 2. WAF Vendors Need Pressure

When WAF vendors know their customers can easily test bypass techniques, they're incentivized to improve their rule sets. SecurityForge creates a **public benchmark** — if your WAF can't block these payloads, the community will know.

This raises the bar for the entire industry.

### 3. Community Improvement

No single person can keep up with every new bypass technique across every WAF vendor. Open source means:

- Bug bounty hunters contribute new bypasses they discover
- Security researchers add payloads from their publications
- WAF vendors can test against a standardized set
- Students learn from real-world examples, not textbook theory

### 4. AI Needs Good Data

Claude Code, ChatGPT, and other AI assistants are increasingly used for security testing. But they're only as good as the data they work with. SecurityForge provides **structured, categorized, AI-friendly data** that makes AI-assisted security testing actually useful.

---

## The AI-Native Approach

This is what makes SecurityForge different from SecLists, PayloadsAllTheThings, and other payload collections.

SecurityForge was designed from day one to work with AI assistants. Here's what that means in practice:

### With Claude Code (in your IDE):

```
You: "Detect the WAF on staging.example.com and test it for XSS bypasses"

Claude Code:
→ Runs waf_detector.py → Identifies Cloudflare (92% confidence)
→ Selects Cloudflare-specific XSS bypass payloads
→ Runs waf_tester.py against target
→ Generates HTML report with findings
→ Suggests remediation steps
```

### With ChatGPT:

```
You: "I'm testing a WordPress site behind AWS WAF. 
      What payloads should I try for authentication bypass?"

ChatGPT:
→ References CVE-2026-28515 (REST API bypass)
→ Pulls 150+ relevant payloads
→ Explains each attack vector
→ Suggests testing methodology
→ Provides remediation guidance
```

The key insight is that **AI assistants can understand the structure of SecurityForge's payload database** because everything is categorized, tagged, and documented. It's not just a dump of raw strings — it's a knowledge base.

---

## How to Actually Use This

### Scenario 1: "Is my WAF actually protecting me?"

```bash
# Step 1: Detect your WAF
python3 waf_detector.py -t https://yoursite.com

# Step 2: Run category-specific tests
python3 waf_tester.py -t https://yoursite.com -p payloads/xss/basic.json
python3 waf_tester.py -t https://yoursite.com -p payloads/sqli/basic.json

# Step 3: Generate a report
python3 report_generator.py --html-report security_report.html
```

### Scenario 2: "We just deployed a WAF — what should we test first?"

Start with the OWASP Top 10 payloads. If your WAF can't block these, nothing else matters:

1. **A03: Injection** — Run all XSS and SQLi payloads
2. **A01: Broken Access Control** — Test path traversal and SSRF
3. **A10: SSRF** — Critical for cloud deployments

### Scenario 3: "I'm doing a bug bounty and found a WAF"

1. Run `waf_detector.py` to identify the vendor
2. Check the vendor-specific bypass payloads
3. Use the 2025-2026 modern bypass techniques
4. Test with encoding variations and polyglots

### Scenario 4: "I want to test our LLM deployment"

```bash
python3 waf_tester.py -i
# Select "AI/LLM Security" category
# Run prompt injection and jailbreak payloads against your LLM endpoint
```

---

## What's Next

SecurityForge is just getting started. Here's the roadmap:

- **Auto-update pipeline** — New CVEs and bypass techniques added within 48 hours of disclosure
- **WAF benchmark reports** — Monthly public reports comparing WAF vendor effectiveness
- **Community payload submissions** — Structured process for contributing new payloads
- **API mode** — REST API for integrating SecurityForge into CI/CD pipelines
- **More AI integrations** — Codex CLI, Gemini, local LLMs via Ollama

---

## Try It Now

```bash
git clone https://github.com/dalisecurity/securityforge.git
cd securityforge
python3 waf_tester.py -i
```

Zero dependencies. Zero configuration. Just clone and run.

**Star the repo** if you think every security team should have access to this: [github.com/dalisecurity/securityforge](https://github.com/dalisecurity/securityforge)

---

*SecurityForge is maintained by [DALI Security](https://github.com/dalisecurity). Licensed under MIT — use it, fork it, improve it.*

*Only test systems you own or have explicit written permission to test. Use responsibly.*
