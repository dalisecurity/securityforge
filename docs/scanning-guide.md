# Fray Scan — Automated Attack Surface Mapping

`fray scan` automates the full recon-to-injection pipeline:

```
Crawl → Parameter Discovery → Endpoint Map → Payload Injection → Report
```

## Basic Usage

```bash
fray scan https://example.com
fray scan https://example.com -c xss --depth 3 --max-pages 50
fray scan https://example.com --json -o results.json
```

## How It Works

### Phase 1: Crawl
- BFS spider follows same-origin links (configurable depth)
- Seeds from `robots.txt` and `sitemap.xml` automatically
- Filters static assets (css, js, images, fonts)
- Follows redirects (301/302/307/308)

### Phase 2: Parameter Discovery
- **Query parameters** — extracted from crawled URLs
- **HTML forms** — parses `<form>` tags, extracts named `<input>`, `<textarea>`, `<select>` fields
- **JavaScript endpoints** — finds `fetch()`, `XMLHttpRequest.open()`, `axios` calls, `/api/` and `/v1/` paths
- Skips non-injectable fields (CSRF tokens, captchas, submit buttons)
- Deduplicates injection points by (URL, param, method)

### Phase 3: Payload Injection
- Tests each discovered parameter with payloads from the chosen category
- Uses WAFTester engine with full WAF signature detection
- **Reflected payload detection** — checks if payload appears in response body (confirmed injection)
- Reports blocked (403), passed, and reflected for each test

## All Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --category` | xss | Payload category (xss, sqli, ssti, ssrf, etc.) |
| `-m, --max` | 5 | Max payloads per injection point |
| `--depth` | 3 | Max crawl depth |
| `--max-pages` | 30 | Max pages to crawl |
| `-d, --delay` | 0.3 | Delay between requests (seconds) |
| `-t, --timeout` | 8 | Request timeout (seconds) |
| `-w, --workers` | 1 | Concurrent workers for crawl + injection |
| `--scope` | — | Scope file: one domain/IP/CIDR per line |
| `--insecure` | off | Skip SSL certificate verification |
| `--stealth` | off | Stealth mode: randomize UA, add jitter, throttle |
| `--jitter` | 0 | Random delay variance (seconds) |
| `--rate-limit` | 0 | Max requests per second (0 = unlimited) |
| `--cookie` | — | Cookie header for authenticated scanning |
| `--bearer` | — | Bearer token for Authorization header |
| `-H, --header` | — | Custom header (repeatable) |
| `-o, --output` | — | Save results JSON to file |
| `--json` | off | Output results as JSON to stdout |

## Scope File

Restricts crawling and injection to permitted domains. Essential for bug bounty:

```
# scope.txt — one entry per line
example.com              # exact domain
*.example.com            # wildcard subdomain
10.0.0.5                 # exact IP
192.168.1.0/24           # CIDR range
# comments are ignored
```

```bash
fray scan https://target.com --scope scope.txt
```

With scope active, the crawler will follow cross-origin links **only** if the destination is in scope. Without scope, only same-origin links are followed.

## Concurrent Workers

Speed up large scans with parallel crawling and injection:

```bash
fray scan https://target.com -w 4              # 4 parallel workers
fray scan https://target.com -w 4 --scope scope.txt  # combined
```

| Workers | testphp.vulnweb.com (10 pages) | Speedup |
|---------|-------------------------------|---------|
| 1 | 49s | — |
| 4 | 15s | **3.3x** |

Both crawl and injection phases run concurrently. Delay is spread across workers.

## Rate Limit Auto-Backoff

The scanner automatically handles rate limiting:

- Detects **429 Too Many Requests** responses
- Retries up to 3 times with exponential backoff (2s → 4s → 8s, capped at 30s)
- Respects `Retry-After` header
- Decays backoff on successful responses
- Resets at the start of each scan

## Reflected Payload Detection

When a payload passes the WAF, the scanner checks if it appears **in the response body**:

- **Reflected** = payload string found verbatim in HTML → confirmed injection
- Checks both raw and URL-decoded forms
- Shows surrounding HTML context (40 chars each side)
- Distinct panel in output: `↩ Reflected (Confirmed Injection)`

## Output Formats

### Rich terminal (default)

Shows crawl progress, endpoint map, scan summary, reflected panel, and bypass table.

### JSON (`--json`)

```bash
fray scan https://target.com --json | jq '.summary'
```

```json
{
  "total_tested": 14,
  "blocked": 4,
  "passed": 10,
  "reflected": 6,
  "block_rate": "28.6%"
}
```

### Save to file (`-o`)

```bash
fray scan https://target.com -o scan-results.json
```

## Examples

```bash
# Quick XSS scan
fray scan https://target.com -c xss -m 3

# Deep SQLi scan with stealth
fray scan https://target.com -c sqli --depth 5 --max-pages 100 --stealth

# Authenticated scan with scope
fray scan https://app.target.com --cookie "session=abc123" --scope scope.txt -w 4

# HTTPS target with cert issues
fray scan https://internal.target.com --insecure -w 4

# CI/pipeline integration
fray scan https://staging.target.com --json -o results.json -c xss -m 10
```
