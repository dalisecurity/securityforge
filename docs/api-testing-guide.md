# API Testing Guide

## 🚀 Quick Start

### Start the API Server

```bash
# Install Flask (if not already installed)
pip install flask

# Start the API server
python3 api_example.py
```

The API will be available at `http://localhost:5000`

---

## 📖 API Endpoints

### 1. Get All Payloads

```bash
curl http://localhost:5000/api/v1/payloads
```

**Response:**
```json
{
  "status": "success",
  "total_categories": 13,
  "categories": ["xss", "sqli", "command_injection", "modern_bypasses", ...],
  "data": { ... }
}
```

### 2. Get Payloads by Category

```bash
# Get all XSS payloads
curl http://localhost:5000/api/v1/payloads/xss

# Get all SQL injection payloads
curl http://localhost:5000/api/v1/payloads/sqli
```

**Response:**
```json
{
  "status": "success",
  "category": "xss",
  "subcategories": ["basic", "advanced", "cve_2025_real_world"],
  "data": { ... }
}
```

### 3. Get CVE Payloads with Filters

```bash
# Get all critical CVEs
curl "http://localhost:5000/api/v1/cves?severity=critical"

# Get CVEs with CVSS >= 9.0
curl "http://localhost:5000/api/v1/cves?min_cvss=9.0"

# Get 2025 CVEs
curl "http://localhost:5000/api/v1/cves?year=2025"

# Combine filters
curl "http://localhost:5000/api/v1/cves?severity=critical&min_cvss=9.5&year=2025"
```

**Response:**
```json
{
  "status": "success",
  "total": 15,
  "filters": {
    "severity": "critical",
    "min_cvss": 9.0,
    "year": "2025"
  },
  "data": [
    {
      "id": "cve-2025-0001",
      "cve": "CVE-2025-55182",
      "description": "React2Shell - React Server Components RCE",
      "severity": "critical",
      "cvss": "10.0",
      "payload": "...",
      "tested_against": ["cloudflare_waf"],
      "success_rate": 0.0,
      "blocked": true
    }
  ]
}
```

### 4. Get Modern Bypass Techniques

```bash
# Get all modern bypasses
curl http://localhost:5000/api/v1/modern-bypasses

# Filter by technique
curl "http://localhost:5000/api/v1/modern-bypasses?technique=http2"
curl "http://localhost:5000/api/v1/modern-bypasses?technique=websocket"
curl "http://localhost:5000/api/v1/modern-bypasses?technique=graphql"
```

**Response:**
```json
{
  "status": "success",
  "total": 7,
  "filter": {
    "technique": "http2"
  },
  "data": [
    {
      "id": "http2-smuggling-001",
      "category": "http2_smuggling",
      "technique": "HTTP/2 to HTTP/1.1 downgrade smuggling",
      "payload": "...",
      "description": "HTTP/2 request smuggling via downgrade to HTTP/1.1"
    }
  ]
}
```

### 5. Search Payloads

```bash
# Search for Log4Shell
curl "http://localhost:5000/api/v1/search?q=log4shell"

# Search for SQL injection
curl "http://localhost:5000/api/v1/search?q=union+select"

# Search for XSS
curl "http://localhost:5000/api/v1/search?q=alert"
```

**Response:**
```json
{
  "status": "success",
  "query": "log4shell",
  "total": 5,
  "data": [
    {
      "category": "xss",
      "subcategory": "cve_2025_real_world",
      "payload": {
        "cve": "CVE-2021-44228",
        "description": "Log4Shell - Log4j RCE",
        "payload": "..."
      }
    }
  ]
}
```

### 6. Get Statistics

```bash
curl http://localhost:5000/api/v1/stats
```

**Response:**
```json
{
  "status": "success",
  "total_payloads": 2325,
  "categories": {
    "xss": 779,
    "sqli": 456,
    "command_injection": 234,
    "modern_bypasses": 50
  },
  "cve_count": 120,
  "modern_bypass_count": 50
}
```

### 7. Health Check

```bash
curl http://localhost:5000/api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "payloads_loaded": true
}
```

---

## 🧪 Testing with Python

### Example 1: Get Critical CVEs

```python
import requests

response = requests.get('http://localhost:5000/api/v1/cves', params={
    'severity': 'critical',
    'min_cvss': 9.0
})

data = response.json()
print(f"Found {data['total']} critical CVEs")

for payload in data['data']:
    print(f"- {payload['cve']}: {payload['description']} (CVSS {payload['cvss']})")
```

### Example 2: Test Payloads Against Your WAF

```python
import requests

# Get XSS payloads
response = requests.get('http://localhost:5000/api/v1/payloads/xss/basic')
payloads = response.json()['data']['payloads']

# Test against your WAF endpoint
waf_endpoint = 'https://your-waf-protected-site.com/test'

for payload in payloads[:10]:  # Test first 10
    try:
        test_response = requests.get(waf_endpoint, params={
            'input': payload['payload']
        })
        
        if test_response.status_code == 200:
            print(f"✅ Bypassed: {payload['id']}")
        else:
            print(f"❌ Blocked: {payload['id']}")
    except Exception as e:
        print(f"⚠️ Error: {e}")
```

### Example 3: Search and Filter

```python
import requests

# Search for specific CVE
response = requests.get('http://localhost:5000/api/v1/search', params={
    'q': 'CVE-2025-55182'
})

results = response.json()
if results['total'] > 0:
    cve_data = results['data'][0]['payload']
    print(f"CVE: {cve_data['cve']}")
    print(f"Description: {cve_data['description']}")
    print(f"CVSS: {cve_data['cvss']}")
    print(f"Payload: {cve_data['payload']}")
```

---

## 🧪 Testing with cURL

### Get All 2025 Critical CVEs

```bash
curl -s "http://localhost:5000/api/v1/cves?year=2025&severity=critical" | jq '.data[] | {cve: .cve, cvss: .cvss, description: .description}'
```

### Get HTTP/2 Smuggling Techniques

```bash
curl -s "http://localhost:5000/api/v1/modern-bypasses?technique=http2" | jq '.data[] | {id: .id, technique: .technique}'
```

### Search for ProxyShell

```bash
curl -s "http://localhost:5000/api/v1/search?q=proxyshell" | jq '.data[0].payload'
```

---

## 🔧 Integration Examples

### Burp Suite Extension

```python
from burp import IBurpExtender, IHttpListener
import requests

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("WAF Payload Arsenal")
        callbacks.registerHttpListener(self)
        
        # Load payloads from API
        self.payloads = self.load_payloads()
    
    def load_payloads(self):
        response = requests.get('http://localhost:5000/api/v1/payloads/xss')
        return response.json()['data']
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Test payloads against requests
        pass
```

### Automated WAF Testing Script

```python
#!/usr/bin/env python3
import requests
import time

API_BASE = 'http://localhost:5000/api/v1'
TARGET_WAF = 'https://your-target.com'

def test_waf_with_category(category):
    """Test WAF with all payloads from a category"""
    response = requests.get(f'{API_BASE}/payloads/{category}')
    
    if response.status_code != 200:
        print(f"Error loading {category}")
        return
    
    data = response.json()['data']
    
    for subcategory, payloads_data in data.items():
        print(f"\nTesting {category}/{subcategory}...")
        
        for payload in payloads_data.get('payloads', [])[:5]:
            # Test payload
            try:
                test_response = requests.get(TARGET_WAF, params={
                    'test': payload['payload']
                }, timeout=5)
                
                status = "BYPASSED" if test_response.status_code == 200 else "BLOCKED"
                print(f"  [{status}] {payload.get('id', 'unknown')}")
                
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                print(f"  [ERROR] {e}")

# Test all categories
categories = ['xss', 'sqli', 'command_injection']
for cat in categories:
    test_waf_with_category(cat)
```

---

## 📊 Response Format

All API responses follow this structure:

### Success Response

```json
{
  "status": "success",
  "data": { ... },
  "total": 100,
  "filters": { ... }
}
```

### Error Response

```json
{
  "status": "error",
  "message": "Category not found",
  "available_categories": ["xss", "sqli", ...]
}
```

---

## 🔒 Security Notes

1. **Local Use Only**: This API is designed for local testing
2. **No Authentication**: Do not expose to the internet without adding auth
3. **Rate Limiting**: Consider adding rate limiting for production use
4. **CORS**: Enable CORS if testing from browser

---

## 🚀 Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install flask

EXPOSE 5000

CMD ["python3", "api_example.py"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  waf-payload-api:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./payloads:/app/payloads:ro
    environment:
      - FLASK_ENV=production
```

---

## 📝 Notes

- All payloads are returned in JSON format
- Payloads include metadata (CVE, CVSS, severity, etc.)
- API supports filtering and searching
- Perfect for automated WAF testing
- Easy integration with security tools

---

## 🆘 Troubleshooting

**API not starting?**
```bash
pip install flask
python3 api_example.py
```

**Empty responses?**
- Ensure `payloads/` directory exists
- Check JSON files are valid

**CORS errors?**
```python
from flask_cors import CORS
CORS(app)
```
