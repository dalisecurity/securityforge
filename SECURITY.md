# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of WAF Payload Arsenal seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report security issues privately:

1. **Email**: security@dalisecurity.com
2. **Subject**: `[SECURITY] WAF Payload Arsenal - [Brief Description]`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Updates**: Every 7-14 days
- **Resolution Timeline**: 90 days for responsible disclosure

### Disclosure Policy

- **90-day disclosure timeline** from initial report
- **Credit**: We will credit researchers in release notes (unless you prefer to remain anonymous)
- **CVE Assignment**: We will work with you to assign CVEs when applicable
- **Public Disclosure**: After fix is released or 90 days, whichever comes first

## 🛡️ Security Scope

### In Scope

This repository contains security testing payloads for **educational and authorized testing only**.

**Vulnerabilities we're interested in:**
- Issues in the CLI tool (`waf_tester.py`)
- JSON parsing vulnerabilities
- Path traversal in payload loading
- Code injection in testing scripts
- Docker container security issues
- Documentation that could lead to misuse

### Out of Scope

**Not security issues:**
- Payloads that successfully bypass WAFs (that's the point!)
- False positives in payload detection
- WAF vendors blocking our payloads
- Theoretical attacks without proof of concept

## ⚖️ Legal and Ethical Use

### Important Reminders

**This repository is for AUTHORIZED TESTING ONLY:**

1. ✅ **Do**: Test systems you own or have written permission to test
2. ✅ **Do**: Follow bug bounty program rules and scope
3. ✅ **Do**: Practice responsible disclosure
4. ✅ **Do**: Use for educational and research purposes

5. ❌ **Don't**: Test systems without authorization
6. ❌ **Don't**: Use for malicious purposes
7. ❌ **Don't**: Violate laws or regulations
8. ❌ **Don't**: Ignore bug bounty program rules

### Responsible Use Agreement

By using this repository, you agree to:
- Only test authorized systems
- Follow all applicable laws
- Practice responsible disclosure
- Not use for malicious purposes
- Respect intellectual property rights

## 🔐 Security Best Practices

### For Users

1. **Verify Payloads**: Always review payloads before testing
2. **Isolated Environment**: Test in isolated/sandboxed environments
3. **Authorization**: Get written permission before testing
4. **Data Protection**: Don't include sensitive data in reports
5. **Update Regularly**: Pull latest security fixes

### For Contributors

1. **Code Review**: All contributions are reviewed
2. **No Malicious Code**: Contributions must not contain malware
3. **Safe Payloads**: Payloads should be safe for testing (no destructive actions)
4. **Documentation**: Document any security implications
5. **Dependencies**: Minimize external dependencies

## 📋 Security Checklist

Before using this tool:

- [ ] I have authorization to test the target system
- [ ] I understand the legal implications
- [ ] I have reviewed the payloads I'm using
- [ ] I'm testing in an appropriate environment
- [ ] I will follow responsible disclosure practices
- [ ] I will not use this for malicious purposes

## 🏆 Security Researchers Hall of Fame

We recognize and thank security researchers who help improve this project:

<!-- Researchers will be listed here after responsible disclosure -->

*No vulnerabilities reported yet. Be the first!*

## 📞 Contact

- **Security Issues**: security@dalisecurity.com
- **General Questions**: GitHub Issues
- **Commercial Inquiries**: contact@dalisecurity.com

## 📚 Additional Resources

- [OWASP Responsible Disclosure](https://owasp.org/www-community/vulnerabilities/Responsible_Disclosure_Cheat_Sheet)
- [Bug Bounty Best Practices](https://www.bugcrowd.com/resources/reports/the-state-of-bug-bounty-2023/)
- [CVE Program](https://www.cve.org/)

---

**Last Updated**: February 28, 2026  
**Version**: 1.0.0
