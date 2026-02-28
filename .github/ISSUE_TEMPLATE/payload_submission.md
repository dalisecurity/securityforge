---
name: Payload Submission
about: Submit new payloads or CVEs to the database
title: '[PAYLOAD] '
labels: payload, enhancement
assignees: ''
---

## 🎯 Payload Submission

Thank you for contributing to WAF Payload Arsenal!

## 📋 Payload Information

**Category**: [e.g., XSS, SQLi, Command Injection, CVE]

**Subcategory**: [e.g., DOM-based, Time-based, etc.]

**Payload(s)**:
```
[Paste your payload(s) here]
```

## 🔍 Payload Details

**Description**: What does this payload do?

**Technique**: What bypass technique does it use?

**Target**: What WAF/filter does it bypass? (if known)

**Source**: Where did you find/create this payload?
- [ ] Original research
- [ ] CVE reference: ___________
- [ ] Security researcher: ___________
- [ ] Bug bounty disclosure: ___________
- [ ] Other: ___________

## ✅ Testing Results

Have you tested this payload?

- [ ] Yes, successfully bypassed WAF
- [ ] Yes, but was blocked
- [ ] No, theoretical payload

**Testing Details**:
- **Target WAF**: [e.g., Cloudflare, AWS WAF, ModSecurity]
- **Test Date**: [YYYY-MM-DD]
- **Success Rate**: [e.g., 100%, 50%, 0%]

## 📊 CVE Information (if applicable)

- **CVE ID**: [e.g., CVE-2024-12345]
- **CVSS Score**: [e.g., 9.8]
- **Affected Versions**: [e.g., WordPress 6.4.0 - 6.4.3]
- **Disclosure Date**: [YYYY-MM-DD]
- **Reference**: [Link to CVE details]

## 📝 JSON Format

Please provide the payload in our JSON format:

```json
{
  "id": "category-XXXX",
  "category": "xss",
  "subcategory": "dom_based",
  "payload": "your payload here",
  "description": "Brief description",
  "technique": "bypass_technique",
  "source": "your_name or CVE-XXXX",
  "tested_against": ["cloudflare_waf"],
  "success_rate": 0.0,
  "blocked": true
}
```

## ⚖️ Legal Compliance

- [ ] I have authorization to share this payload
- [ ] This payload is for educational/research purposes only
- [ ] I understand this will be published under MIT License
- [ ] I have followed responsible disclosure (if CVE)

## 🤝 Attribution

How would you like to be credited?

- **Name/Handle**: ___________
- **Twitter/X**: ___________
- **GitHub**: ___________
- **Website**: ___________
- [ ] I prefer to remain anonymous

## ✅ Checklist

- [ ] Payload is properly formatted
- [ ] Description is clear and accurate
- [ ] Testing information provided (if available)
- [ ] Legal compliance confirmed
- [ ] JSON format provided
