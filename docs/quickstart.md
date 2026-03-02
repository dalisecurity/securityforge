# Quick Start Guide

Get started with SecurityForge in 5 minutes!

## 🚀 Installation

### Option 1: Install from PyPI (Recommended)

```bash
pip install securityforge
```

### Option 2: Clone from GitHub

```bash
git clone https://github.com/dalisecurity/securityforge.git
cd securityforge
```

## 📋 Prerequisites

- Python 3.8+
- No additional dependencies required (uses standard library only!)

## 🎯 Usage

### Detect WAF Vendor

```bash
securityforge detect https://example.com
```

### Test with Specific Category

```bash
# Test XSS payloads
securityforge test https://example.com -c xss --max 10

# Test SQL injection
securityforge test https://example.com -c sqli --max 10

# Test SSRF
securityforge test https://example.com -c ssrf --max 10
```

### List Available Payload Categories

```bash
securityforge payloads
```

### Legacy CLI (also works)

```bash
python3 waf_tester.py -i
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json --max 10
```

## 📊 Understanding Results

### Output Example
```
[1/10] BLOCKED  | Status: 403 | basic script tag
[2/10] BLOCKED  | Status: 403 | img onerror
[3/10] PASSED   | Status: 200 | benign input
```

- **BLOCKED** (Red): WAF detected and blocked the payload
- **PASSED** (Green): Payload was not blocked
- **Status**: HTTP response code (403 = blocked, 200 = passed)

### Report File

After testing, a JSON report is generated:

```json
{
  "target": "https://example.com",
  "timestamp": "2026-02-28T15:30:00",
  "summary": {
    "total": 100,
    "blocked": 98,
    "passed": 2,
    "block_rate": "98.00%"
  },
  "results": [...]
}
```

## 🎓 Common Use Cases

### 1. Quick WAF Check
```bash
securityforge detect https://your-site.com
```

### 2. Quick XSS Test
```bash
securityforge test https://your-site.com -c xss --max 10
```

### 3. Multi-Vector Test
```bash
# Test XSS
securityforge test https://your-site.com -c xss -o xss_results.json

# Test SQLi
securityforge test https://your-site.com -c sqli -o sqli_results.json

# Test SSRF
securityforge test https://your-site.com -c ssrf -o ssrf_results.json
```

### 4. Comprehensive Test (all categories)
```bash
securityforge test https://your-site.com --max 20
```

## ⚙️ Advanced Options

```bash
securityforge test --help
```

Options:
- `-c, --category`: Payload category (e.g. xss, sqli, ssrf)
- `-p, --payload-file`: Specific payload file to use
- `-m, --max`: Maximum number of payloads to test
- `-d, --delay`: Delay between requests (default: 0.5s)
- `-t, --timeout`: Request timeout (default: 8s)
- `-o, --output`: Output results JSON file

## 🔒 Important Notes

### Authorization Required
**ONLY test systems you own or have explicit permission to test!**

Unauthorized testing is:
- ✗ Illegal
- ✗ Unethical
- ✗ May result in criminal charges

### Responsible Use
- Get written permission before testing
- Follow bug bounty program rules
- Respect rate limits
- Don't cause harm or disruption

## 🐛 Troubleshooting

### Connection Errors
```bash
# Increase timeout
securityforge test https://example.com -c xss --timeout 15
```

### Rate Limiting
```bash
# Increase delay between requests
securityforge test https://example.com -c xss --delay 2
```

### SSL Certificate Errors
The tool automatically ignores SSL certificate validation for testing purposes.

## 📚 Payload Categories

Available payload files:

### XSS
- `payloads/xss/basic.json` - 412 basic XSS payloads
- `payloads/xss/svg_based.json` - 175 SVG-based XSS
- `payloads/xss/encoded.json` - 12 encoded XSS
- `payloads/xss/obfuscated.json` - 3 obfuscated XSS
- `payloads/xss/mutation.json` - 4 mutation XSS
- `payloads/xss/dom_based.json` - 24 DOM-based XSS
- `payloads/xss/polyglot.json` - 1 polyglot XSS

### Other
- `payloads/sqli/general.json` - 13 SQL injection
- `payloads/ssrf/general.json` - 7 SSRF payloads
- `payloads/xxe/general.json` - 3 XXE payloads
- `payloads/ssti/general.json` - 8 SSTI payloads

## 🎬 Video Tutorial

Coming soon! Check the repository for updates.

## 💬 Getting Help

- **Issues**: [GitHub Issues](https://github.com/dalisecurity/securityforge/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dalisecurity/securityforge/discussions)
- **PyPI**: [pypi.org/project/securityforge](https://pypi.org/project/securityforge/)
- **Documentation**: See `/docs` folder

## 🚀 Next Steps

1. ✅ Run your first test in interactive mode
2. 📖 Read the [full documentation](README.md)
3. 🔬 Explore the [methodology](docs/methodology.md)
4. 🤝 [Contribute](CONTRIBUTING.md) your own payloads

---

**Happy (ethical) testing! 🎯**
