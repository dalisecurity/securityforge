# SecurityForge

### ⚔️ *Forge your attack payloads with AI — 4,000+ exploits, 25 WAF detections, works with Claude & ChatGPT*

**The open-source offensive security toolkit built for the AI era** • 4,025+ Payloads • 25 WAF Fingerprints • Zero-Config • AI-Native

[![Total Payloads](https://img.shields.io/badge/Total_Payloads-4025+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/securityforge)
[![OWASP Coverage](https://img.shields.io/badge/OWASP_Coverage-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/securityforge)
[![WAF Detection](https://img.shields.io/badge/WAF_Vendors-25+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/securityforge)
[![AI Powered](https://img.shields.io/badge/AI_Powered-Claude_+_ChatGPT-purple.svg?style=for-the-badge&logo=openai)](https://github.com/dalisecurity/securityforge)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## ⚡ Why SecurityForge?

Most payload collections are just static text files. **SecurityForge is different** — it's an AI-native toolkit that lets you **generate, test, and report** in seconds:

- 🤖 **Ask AI to build payloads** — works with Claude Code & ChatGPT out of the box
- 🔍 **Auto-detect which WAF** you're facing — 25 vendors fingerprinted instantly
- 📊 **One-command reports** — professional HTML output with vuln analysis
- 🎯 **4,025+ battle-tested payloads** — XSS, SQLi, SSRF, SSTI, LLM jailbreaks, and more
- ⚡ **Zero config** — `python3 waf_tester.py -i` and you're testing

### 🔥 Built For

- **Bug bounty hunters** — ready-made payloads from real-world disclosures + 120 CVEs
- **Red teamers & pentesters** — WAF detection → payload selection → report, all in one tool
- **Security researchers** — AI-assisted payload generation and bypass research
- **Blue teams** — validate your WAF config against 4,000+ real attack patterns
- **Students** — learn offensive security with guided AI workflows

### �️ WAF Vendor Detection — 25 Vendors Supported

SecurityForge detects and fingerprints **25 major WAF vendors** using header analysis, cookie inspection, response patterns, and error signatures.

| # | WAF Vendor | Detection Method | Key Signatures |
|---|-----------|-----------------|----------------|
| 1 | **Cloudflare** | Headers, Cookies, Error Page | `cf-ray`, `__cfduid`, Ray ID pattern |
| 2 | **Akamai** | Headers, Cookies, Bot Manager | `akamai-grn`, `ak_bmsc`, Reference # |
| 3 | **AWS WAF** | Headers, Cookies, Response Body | `x-amzn-waf-action`, `awsalb`, CloudFront |
| 4 | **Imperva (Incapsula)** | Headers, Cookies, Challenge | `x-iinfo`, `incap_ses`, Incident ID |
| 5 | **F5 BIG-IP** | Headers, Cookies, Error Page | `x-wa-info`, `bigipserver`, Support ID |
| 6 | **Fastly (Signal Sciences)** | Headers, Cookies, Server | `x-sigsci-requestid`, `x-served-by` |
| 7 | **Microsoft Azure WAF** | Headers, Cookies, Front Door | `x-azure-fdid`, `x-azure-ref`, `arr_affinity` |
| 8 | **Google Cloud Armor** | Headers, Server, reCAPTCHA | `x-cloud-trace-context`, `gfe`, Cloud Armor |
| 9 | **Barracuda** | Headers, Cookies, Server | `x-barracuda-url`, `barra_counter_session` |
| 10 | **Citrix NetScaler** | Headers, Cookies, Server | `citrix-transactionid`, `nsc_`, NetScaler |
| 11 | **Radware** | Headers, Response Text | `x-protected-by`, AppWall |
| 12 | **Palo Alto (Prisma Cloud)** | Headers, Response Text | `x-pan-`, `x-prisma` |
| 13 | **Check Point** | Headers, Response Text | `x-checkpoint`, Check Point |
| 14 | **Trustwave (ModSecurity)** | Headers, Server, Response | `x-mod-security`, ModSecurity |
| 15 | **Qualys WAF** | Headers, Response Text | `x-qualys` |
| 16 | **Penta Security (WAPPLES)** | Headers, Cookies | `x-wapples`, `wapples` |
| 17 | **StackPath** | Headers, Server | `x-stackpath-shield`, StackPath |
| 18 | **Sophos** | Headers, Response Text | `x-sophos`, UTM |
| 19 | **Scutum** | Headers, Response Text | `x-scutum` |
| 20 | **Rohde & Schwarz** | Headers, Response Text | `x-rs-` |
| 21 | **Sucuri** | Headers, Cookies, Server | `x-sucuri-id`, `sucuri_cloudproxy_uuid` |
| 22 | **Fortinet FortiWeb** | Headers, Cookies, Server | `x-fortiweb`, `fortiwafsid` |
| 23 | **Wallarm** | Headers, Server | `x-wallarm-waf-check`, `nginx-wallarm` |
| 24 | **Reblaze** | Headers, Cookies, Server | `x-reblaze-protection`, `rbzid` |
| 25 | **Vercel** | Headers, Server | `x-vercel-id`, `x-vercel-cache` |

## ⚡ Quick Start

```bash
# Clone and run
git clone https://github.com/dalisecurity/securityforge.git
cd securityforge
python3 waf_tester.py -i
```

## 📚 Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Full Documentation](README.md)
- [Docker Usage](DOCKER.md)
- [Team Sharing](SHARE_WITH_TEAM.md)

## 🤖 Use with AI Assistants

### Claude Code
```
Use the WAF Payload Database to test our staging environment
```

### ChatGPT
```
Run WAF tests using the payload database against https://example.com
```

### Codex CLI
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json
```

## 📊 Complete OWASP Coverage

**4,025+ total payloads across 40+ categories:**

### OWASP Top 10:2021 (Web) - 1,690+ Payloads
- A01: Broken Access Control (150+)
- A02: Cryptographic Failures (50+)
- A03: Injection (500+ - XSS, SQLi, XXE, SSTI, Command Injection)
- A04: Insecure Design (80+)
- A05: Security Misconfiguration (100+)
- A06: Vulnerable Components (450+ - WordPress CVEs)
- A07: Authentication Failures (200+)
- A08: Software/Data Integrity (70+)
- A09: Logging/Monitoring (30+)
- A10: SSRF (60+)

### OWASP Mobile Top 10:2024 - 575+ Payloads
- M1-M10: Complete mobile security coverage (Android & iOS)

### OWASP LLM Top 10 - 300+ Payloads
- LLM01: Prompt Injection (100+)
- LLM02-LLM10: AI/ML security testing

### OWASP API Security Top 10 - 520+ Payloads
- API1-API10: Complete API security coverage (REST, GraphQL, SOAP)

### WordPress CVEs - 450+ Payloads
- CVE-2026-28515: REST API Bypass (150+)
- CVE-2026-28516: File Upload (200+)
- CVE-2026-28517: XML-RPC Attack (100+)

### Additional Attack Vectors - 490+ Payloads
- XSS, SQLi, SSRF, Path Traversal, LDAP, XPath, CRLF, and more

See [OWASP_COMPLETE_COVERAGE.md](OWASP_COMPLETE_COVERAGE.md) for detailed breakdown.

## 🔒 Legal & Ethical Use

**IMPORTANT**: Only test systems you own or have explicit permission to test. See [LICENSE](LICENSE) for full legal disclaimer.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

**⭐ Star this repo if you find it useful!**

📚 **Documentation**: [OWASP_COMPLETE_COVERAGE.md](OWASP_COMPLETE_COVERAGE.md) | [SKILLS.md](SKILLS.md) | [CLAUDE_CODE_GUIDE.md](CLAUDE_CODE_GUIDE.md)
