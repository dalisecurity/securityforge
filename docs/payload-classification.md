# Payload Classification

Comprehensive classification of all 1,548 payloads by attack type, technique, and severity.

## 📊 Overview Statistics

| Category | Payloads | Percentage | Severity |
|----------|----------|------------|----------|
| **XSS (Cross-Site Scripting)** | 681 | 44.0% | High |
| **Other/Mixed** | 760 | 49.1% | Varies |
| **SQL Injection** | 28 | 1.8% | Critical |
| **SSRF** | 22 | 1.4% | High |
| **SSTI** | 17 | 1.1% | Critical |
| **Command Injection** | 10 | 0.6% | Critical |
| **Path Traversal** | 9 | 0.6% | High |
| **XXE** | 7 | 0.5% | High |
| **LDAP Injection** | 5 | 0.3% | Medium |
| **XPath Injection** | 4 | 0.3% | Medium |
| **CRLF Injection** | 4 | 0.3% | Medium |
| **Open Redirect** | 1 | 0.1% | Low |
| **TOTAL** | **1,548** | **100%** | - |

## 🎯 Attack Type Breakdown

### 1. Cross-Site Scripting (XSS) - 681 payloads

#### Subcategories:
- **Basic XSS** (412 payloads)
  - Script tags: `<script>alert(1)</script>`
  - Standard event handlers
  - Common vectors
  
- **SVG-based XSS** (175 payloads)
  - SVG onload events
  - SVG animation attacks
  - SVG namespace abuse
  
- **Advanced XSS** (15 payloads)
  - ES6+ features (async/await, promises, classes)
  - WebAssembly exploitation
  - Service Worker attacks
  - Modern JavaScript APIs
  
- **Event Handlers** (35 payloads)
  - Rare event handlers (onbounce, onfinish, etc.)
  - Media events (video/audio)
  - Page lifecycle events
  
- **DOM-based XSS** (24 payloads)
  - Hash fragment attacks
  - Client-side manipulation
  - DOM clobbering
  
- **Encoded XSS** (12 payloads)
  - URL encoding
  - HTML entities
  - Unicode variations
  
- **Obfuscated XSS** (3 payloads)
  - Case variation
  - Whitespace manipulation
  - Comment injection
  
- **Mutation XSS** (4 payloads)
  - Browser parsing mutations
  - Context-breaking
  
- **Polyglot XSS** (1 payload)
  - Multi-context payloads

**Techniques:**
- Direct injection
- Event handler abuse
- Protocol manipulation (javascript:, data:)
- DOM manipulation
- Template injection
- Encoding bypass
- Browser quirks exploitation

**Severity:** High (can lead to account takeover, data theft, malware distribution)

---

### 2. SQL Injection - 28 payloads

#### Subcategories:
- **General SQLi** (13 payloads)
  - Union-based
  - Boolean-based
  - Stacked queries
  
- **Advanced SQLi** (15 payloads)
  - PostgreSQL specific (pg_sleep, COPY to PROGRAM)
  - MySQL specific (SLEEP, BENCHMARK, extractvalue)
  - MSSQL specific (WAITFOR, xp_cmdshell)
  - Oracle specific (UTL_INADDR, DBMS_PIPE)
  - SQLite specific (LOAD_EXTENSION)
  - NoSQL injection

**Techniques:**
- Time-based blind SQLi
- Error-based SQLi
- Union-based data extraction
- Out-of-band data exfiltration
- Second-order SQLi
- Database-specific functions

**Severity:** Critical (can lead to full database compromise, RCE)

---

### 3. Server-Side Request Forgery (SSRF) - 22 payloads

#### Subcategories:
- **General SSRF** (7 payloads)
  - AWS metadata
  - GCP metadata
  - Internal network access
  
- **Advanced SSRF** (15 payloads)
  - Cloud metadata variations (AWS IMDSv2, GCP tokens, Azure)
  - Protocol smuggling (gopher, dict, ftp, tftp)
  - DNS rebinding
  - IPv6 exploitation
  - IP encoding (decimal, hex, octal)

**Techniques:**
- Cloud metadata exploitation
- Internal service enumeration
- Protocol smuggling
- DNS rebinding
- IP address obfuscation

**Severity:** High (can access internal services, cloud credentials, sensitive data)

---

### 4. Server-Side Template Injection (SSTI) - 17 payloads

#### Subcategories:
- **General SSTI** (8 payloads)
  - Jinja2/Flask
  - Twig
  - Freemarker
  - Velocity
  
- **Advanced SSTI** (9 payloads)
  - Jinja2 RCE (OS command execution)
  - Twig filter callback exploitation
  - Freemarker Execute utility
  - Velocity Runtime exploitation
  - Pug/Jade RCE

**Techniques:**
- Template syntax injection
- Filter/function abuse
- Object introspection
- Sandbox escape
- Remote code execution

**Severity:** Critical (direct RCE in most cases)

---

### 5. Command Injection - 10 payloads

#### Subcategories:
- **Advanced Command Injection** (10 payloads)
  - Reverse shells (bash, nc, python, perl, ruby)
  - Base64 encoding bypass
  - Time-based detection

**Techniques:**
- Shell metacharacter injection
- Command chaining (; && ||)
- Command substitution ($() ``)
- Encoding bypass
- Reverse shell establishment

**Severity:** Critical (direct OS command execution)

---

### 6. Path Traversal - 9 payloads

#### Subcategories:
- **Advanced Path Traversal** (9 payloads)
  - Unicode encoding
  - Double URL encoding
  - UTF-8 slash encoding
  - Windows-specific paths
  - Null byte bypass
  - Absolute paths
  - Zip slip

**Techniques:**
- Directory traversal (../)
- Encoding bypass
- Null byte injection
- Absolute path access
- Archive extraction exploitation

**Severity:** High (can access sensitive files, configuration)

---

### 7. XML External Entity (XXE) - 7 payloads

#### Subcategories:
- **General XXE** (3 payloads)
  - File disclosure
  - SSRF via XXE
  - Blind XXE
  
- **Advanced XXE** (4 payloads)
  - Parameter entity exfiltration
  - PHP wrapper exploitation
  - Expect wrapper RCE
  - Blind XXE OOB

**Techniques:**
- External entity declaration
- Parameter entity abuse
- Protocol wrapper exploitation
- Out-of-band data exfiltration
- Blind XXE with DTD

**Severity:** High (file disclosure, SSRF, potential RCE)

---

### 8. LDAP Injection - 5 payloads

#### Subcategories:
- **Basic LDAP Injection** (5 payloads)
  - Wildcard injection
  - AND/OR bypass
  - NOT bypass
  - Complex filter manipulation

**Techniques:**
- Filter injection
- Boolean logic manipulation
- Wildcard abuse
- Authentication bypass

**Severity:** Medium (authentication bypass, information disclosure)

---

### 9. XPath Injection - 4 payloads

#### Subcategories:
- **Basic XPath Injection** (4 payloads)
  - OR bypass
  - Numeric bypass
  - Function exploitation
  - Substring extraction

**Techniques:**
- Boolean logic injection
- Function abuse (name(), substring())
- Authentication bypass
- Data extraction

**Severity:** Medium (authentication bypass, data extraction)

---

### 10. CRLF Injection - 4 payloads

#### Subcategories:
- **Basic CRLF Injection** (4 payloads)
  - Cookie injection
  - HTTP redirect
  - Response splitting XSS
  - LF-only injection

**Techniques:**
- HTTP header injection
- Response splitting
- Cookie manipulation
- Cache poisoning

**Severity:** Medium (session fixation, XSS, cache poisoning)

---

### 11. Open Redirect - 1 payload

**Techniques:**
- URL parameter manipulation
- Protocol-relative URLs
- JavaScript protocol

**Severity:** Low (phishing, OAuth token theft)

---

### 12. Other/Mixed - 760 payloads

This category includes:
- Experimental payloads
- Multi-vector attacks
- Fuzzing patterns
- Edge cases
- Unclassified variations

---

## 🔍 Classification by Technique

### Encoding Techniques
- URL encoding (single, double, triple)
- HTML entity encoding
- Unicode encoding (UTF-7, UTF-8, UTF-16)
- Base64 encoding
- Hex encoding
- Octal encoding
- Mixed encoding

### Obfuscation Techniques
- Case variation
- Whitespace manipulation
- Comment injection
- Null byte injection
- String concatenation
- Character substitution

### Bypass Techniques
- WAF signature evasion
- Input validation bypass
- Blacklist circumvention
- Context breaking
- Protocol smuggling
- Charset confusion

### Exploitation Techniques
- Remote code execution
- Data exfiltration
- Authentication bypass
- Privilege escalation
- Denial of service
- Information disclosure

---

## 📈 Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| **Critical** (RCE, SQLi, SSTI) | 55 | 3.6% |
| **High** (XSS, SSRF, XXE, Path Traversal) | 719 | 46.4% |
| **Medium** (LDAP, XPath, CRLF) | 13 | 0.8% |
| **Low** (Open Redirect) | 1 | 0.1% |
| **Varies** (Other/Mixed) | 760 | 49.1% |

---

## 🎯 Use Cases by Category

### Penetration Testing
- XSS: Client-side security assessment
- SQLi: Database security testing
- Command Injection: OS-level security
- SSRF: Internal network mapping

### Security Research
- Advanced techniques for WAF bypass research
- Novel exploitation methods
- Zero-day discovery

### Security Training
- Educational examples for each attack type
- Real-world payload variations
- Defense mechanism understanding

### WAF Testing
- Signature coverage validation
- False positive/negative testing
- Performance benchmarking

---

## 📚 References

- OWASP Top 10
- CWE (Common Weakness Enumeration)
- CAPEC (Common Attack Pattern Enumeration)
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports

---

**Last Updated:** February 2026  
**Total Payloads:** 1,548  
**Classification Version:** 1.0
