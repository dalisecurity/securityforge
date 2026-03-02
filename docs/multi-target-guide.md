# 🎯 Multi-Target Testing Guide

## Overview

SecurityForge now supports testing **multiple targets, endpoints, and domains** in a single test run. You can test specific URLs, API endpoints, or entire lists of targets from a file.

---

## 🚀 Features

### **1. Single Target Testing**
Test any specific URL, endpoint, or path:
```bash
# Test root domain
python3 waf_tester.py -t https://example.com -p payloads/xss/

# Test specific endpoint
python3 waf_tester.py -t https://example.com/api/search -p payloads/sqli/

# Test API endpoint with path
python3 waf_tester.py -t https://api.example.com/v1/users -p payloads/
```

### **2. Multiple Targets from File**
Test multiple URLs from a targets file:
```bash
# Test all targets in file
python3 waf_tester.py --targets-file targets.txt -p payloads/xss/ --html-report

# Test with custom settings
python3 waf_tester.py --targets-file targets.txt -p payloads/ --max 50 --delay 1
```

### **3. Custom Endpoints**
The tool automatically uses the full URL path:
```bash
# Login endpoint
python3 waf_tester.py -t https://example.com/login -p payloads/sqli/ -m POST

# Admin panel
python3 waf_tester.py -t https://example.com/admin/dashboard -p payloads/

# API with version
python3 waf_tester.py -t https://api.example.com/v2/search -p payloads/xss/
```

### **4. Query Parameters**
Existing query parameters are preserved:
```bash
# Test with existing query params
python3 waf_tester.py -t "https://example.com/search?category=products" -p payloads/xss/

# API with filters
python3 waf_tester.py -t "https://api.example.com/items?filter=active" -p payloads/
```

---

## 📝 Creating a Targets File

### **Format**
Create a text file with one URL per line:

```text
# targets.txt
https://example.com
https://example.com/api/search
https://example.com/login
https://api.example.com/v1/users
https://admin.example.com/panel
```

### **Features**
- ✅ One URL per line
- ✅ Comments start with `#`
- ✅ Blank lines are ignored
- ✅ Supports full URLs with paths
- ✅ Supports query parameters
- ✅ Supports different ports
- ✅ Supports subdomains

### **Example Targets File**

```text
# Production Domains
https://example.com
https://www.example.com
https://api.example.com

# API Endpoints
https://api.example.com/v1/search
https://api.example.com/v1/users
https://api.example.com/v2/products

# Admin Panels
https://admin.example.com/login
https://admin.example.com/dashboard

# Staging Environment
https://staging.example.com
https://staging-api.example.com

# Specific Endpoints
https://example.com/search?q=test
https://example.com/api/auth/login
https://example.com/api/data/export

# Different Ports
https://example.com:8443/api
http://example.com:8080/test
```

---

## 💡 Usage Examples

### **Test Single Domain**
```bash
python3 waf_tester.py \
  -t https://example.com \
  -p payloads/xss/basic.json \
  --html-report
```

### **Test Specific API Endpoint**
```bash
python3 waf_tester.py \
  -t https://api.example.com/v1/search \
  -p payloads/sqli/ \
  --param query \
  -m POST
```

### **Test Multiple Domains**
```bash
python3 waf_tester.py \
  --targets-file targets.txt \
  -p payloads/xss/ \
  --html-report \
  --delay 1
```

### **Test Login Endpoints**
```bash
# Create targets file with login endpoints
cat > login_targets.txt << EOF
https://example.com/login
https://example.com/admin/login
https://api.example.com/auth/login
EOF

# Test all login endpoints
python3 waf_tester.py \
  --targets-file login_targets.txt \
  -p payloads/sqli/ \
  -m POST \
  --param username
```

### **Test API Endpoints with Custom Parameters**
```bash
python3 waf_tester.py \
  -t https://api.example.com/v1/users \
  -p payloads/ \
  --param search \
  --max 100 \
  --timeout 10
```

---

## 📊 Output for Multiple Targets

When testing multiple targets, SecurityForge generates:

### **Individual Reports**
Each target gets its own report:
```
report_1.json  → First target results
report_1.html  → First target HTML report
report_2.json  → Second target results
report_2.html  → Second target HTML report
...
```

### **Combined Report**
A combined JSON report with all results:
```
report_combined.json
```

Contains:
```json
{
  "targets": [
    "https://example.com",
    "https://api.example.com"
  ],
  "timestamp": "2026-03-01T14:13:00",
  "total_targets": 2,
  "results_by_target": [
    {
      "target": "https://example.com",
      "results": [...]
    },
    {
      "target": "https://api.example.com",
      "results": [...]
    }
  ]
}
```

---

## 🎯 Use Cases

### **1. Multi-Domain Testing**
Test all your domains in one run:
```bash
# domains.txt
https://example.com
https://www.example.com
https://m.example.com
https://api.example.com

# Run test
python3 waf_tester.py --targets-file domains.txt -p payloads/xss/
```

### **2. API Endpoint Testing**
Test all API endpoints:
```bash
# api_endpoints.txt
https://api.example.com/v1/users
https://api.example.com/v1/products
https://api.example.com/v1/orders
https://api.example.com/v1/search

# Run test
python3 waf_tester.py --targets-file api_endpoints.txt -p payloads/sqli/
```

### **3. Environment Testing**
Test across environments:
```bash
# environments.txt
https://dev.example.com
https://staging.example.com
https://uat.example.com
https://prod.example.com

# Run test
python3 waf_tester.py --targets-file environments.txt -p payloads/
```

### **4. Subdomain Testing**
Test all subdomains:
```bash
# subdomains.txt
https://www.example.com
https://api.example.com
https://admin.example.com
https://blog.example.com
https://shop.example.com

# Run test
python3 waf_tester.py --targets-file subdomains.txt -p payloads/xss/
```

### **5. Critical Endpoint Testing**
Test high-risk endpoints:
```bash
# critical_endpoints.txt
https://example.com/login
https://example.com/admin
https://example.com/api/auth
https://example.com/payment/process
https://example.com/user/profile

# Run test
python3 waf_tester.py --targets-file critical_endpoints.txt -p payloads/
```

---

## 🔧 Advanced Options

### **Custom Parameter Names**
```bash
# Test with custom parameter name
python3 waf_tester.py \
  -t https://example.com/search \
  -p payloads/xss/ \
  --param q
```

### **Rate Limiting**
```bash
# Add delay between requests
python3 waf_tester.py \
  --targets-file targets.txt \
  -p payloads/ \
  --delay 2
```

### **Timeout Configuration**
```bash
# Set custom timeout
python3 waf_tester.py \
  -t https://slow-api.example.com \
  -p payloads/ \
  --timeout 15
```

### **Limit Payloads**
```bash
# Test only first 50 payloads per target
python3 waf_tester.py \
  --targets-file targets.txt \
  -p payloads/ \
  --max 50
```

### **POST Method**
```bash
# Use POST instead of GET
python3 waf_tester.py \
  -t https://example.com/api/submit \
  -p payloads/sqli/ \
  -m POST
```

---

## 📈 Best Practices

### **1. Organize Targets by Purpose**
```
targets/
├── production.txt      # Production domains
├── staging.txt         # Staging environments
├── api_endpoints.txt   # API endpoints
├── admin_panels.txt    # Admin interfaces
└── login_pages.txt     # Authentication endpoints
```

### **2. Use Descriptive Comments**
```text
# Production API Endpoints - Critical
https://api.example.com/v1/users
https://api.example.com/v1/payments  # High priority

# Staging - Safe to test aggressively
https://staging.example.com/api/test
```

### **3. Test Incrementally**
```bash
# Start with small payload set
python3 waf_tester.py --targets-file targets.txt -p payloads/xss/basic.json

# Then expand to full suite
python3 waf_tester.py --targets-file targets.txt -p payloads/
```

### **4. Monitor Rate Limits**
```bash
# Use appropriate delays for production
python3 waf_tester.py \
  --targets-file production.txt \
  -p payloads/ \
  --delay 2 \
  --max 100
```

### **5. Generate HTML Reports**
```bash
# Always generate HTML reports for stakeholders
python3 waf_tester.py \
  --targets-file targets.txt \
  -p payloads/ \
  --html-report
```

---

## 🎯 Real-World Examples

### **E-commerce Platform**
```bash
# ecommerce_targets.txt
https://shop.example.com
https://shop.example.com/search
https://shop.example.com/cart
https://shop.example.com/checkout
https://api.shop.example.com/v1/products
https://api.shop.example.com/v1/orders

python3 waf_tester.py --targets-file ecommerce_targets.txt -p payloads/ --html-report
```

### **SaaS Application**
```bash
# saas_targets.txt
https://app.example.com
https://app.example.com/dashboard
https://app.example.com/settings
https://api.example.com/v1/users
https://api.example.com/v1/workspaces
https://api.example.com/v1/integrations

python3 waf_tester.py --targets-file saas_targets.txt -p payloads/xss/ --delay 1
```

### **Banking Application**
```bash
# banking_targets.txt
https://online.bank.com/login
https://online.bank.com/transfer
https://online.bank.com/statements
https://api.bank.com/v1/accounts
https://api.bank.com/v1/transactions

python3 waf_tester.py --targets-file banking_targets.txt -p payloads/sqli/ -m POST
```

---

## 📊 Report Analysis

### **Single Target Report**
Shows results for one specific URL/endpoint

### **Multiple Target Reports**
- Individual JSON/HTML reports per target
- Combined JSON report with all results
- Easy comparison across targets

### **HTML Report Features**
- Target URL displayed prominently
- Endpoint-specific results
- Vulnerability analysis per target
- Security recommendations

---

## ✅ Summary

**SecurityForge now supports:**
- ✅ Single domain testing
- ✅ Specific endpoint testing
- ✅ Multiple domain testing
- ✅ Targets file support
- ✅ Full URL paths and query parameters
- ✅ Custom ports and protocols
- ✅ Individual and combined reports
- ✅ HTML reports with Dali Security branding

**Perfect for:**
- Multi-domain security assessments
- API endpoint testing
- Environment comparison (dev/staging/prod)
- Subdomain enumeration testing
- Critical endpoint validation
- Comprehensive security audits

---

## 🚀 Quick Start

1. **Create targets file:**
   ```bash
   cp targets.txt.example targets.txt
   # Edit targets.txt with your URLs
   ```

2. **Run test:**
   ```bash
   python3 waf_tester.py --targets-file targets.txt -p payloads/xss/ --html-report
   ```

3. **Review reports:**
   - Individual reports: `report_1.html`, `report_2.html`, etc.
   - Combined data: `report_combined.json`

**Start testing multiple targets today!** 🎯
