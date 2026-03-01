# Screenshot Creation Guide

This guide helps you create professional screenshots for SecurityForge documentation.

## Required Screenshots

### 1. WAF Detection - No WAF Scenario
**Command to run:**
```bash
python3 waf_recommendation_engine.py
```
**What to capture:**
- Terminal output showing "CRITICAL - No WAF Protection Detected"
- Recommended WAF vendors with pricing
- Immediate action items

**Expected output:**
```
================================================================================
WAF DETECTION AND SECURITY RECOMMENDATIONS
================================================================================

Target: https://example.com
Security Posture: CRITICAL - No WAF Protection Detected

IMMEDIATE ACTIONS:
🚨 Deploy a Web Application Firewall immediately
🔍 Conduct comprehensive security assessment
🛡️ Implement input validation and output encoding

RECOMMENDED WAF VENDORS:

Cloudflare:
  Pricing: $20/month
  Deployment: 5 minutes
  URL: https://www.cloudflare.com/waf/
```

### 2. WAF Detection - Cloudflare Detected
**Command to run:**
```bash
python3 waf_recommendation_engine.py
```
**What to capture:**
- Terminal output showing "Cloudflare WAF Detected (95% confidence)"
- WAF vendor information
- Optimization recommendations

### 3. HTML Report - No WAF
**Command to run:**
```bash
open sample_report_no_waf.html
```
**What to capture:**
- Full browser window showing the HTML report
- Critical alert section
- WAF vendor recommendations
- Statistics dashboard

### 4. HTML Report - With WAF
**Command to run:**
```bash
open sample_report_with_waf.html
```
**What to capture:**
- Full browser window showing the HTML report
- Success alert with Cloudflare detection
- WAF vendor information card
- Test results summary

### 5. Integration Test Output
**Command to run:**
```bash
python3 test_integration_complete.py
```
**What to capture:**
- All three test scenarios output
- Success indicators
- Generated report filenames

### 6. WordPress Payload Testing
**Command to run:**
```bash
cat payloads/wordpress/CVE-2026-28515.txt | head -30
```
**What to capture:**
- WordPress vulnerability payloads
- CVE header information
- Attack vector examples

## Screenshot Settings

### Terminal Screenshots
- **Font**: Monaco or Menlo, 14pt
- **Theme**: Dark theme preferred
- **Window Size**: 1200x800px minimum
- **Format**: PNG with transparency

### Browser Screenshots
- **Browser**: Chrome or Firefox
- **Window Size**: 1400x900px
- **Zoom**: 100%
- **Format**: PNG

## Tools for Screenshots

### macOS
```bash
# Full screen
Cmd + Shift + 3

# Selected area
Cmd + Shift + 4

# Window capture
Cmd + Shift + 4, then Space
```

### Terminal Recording
```bash
# Install asciinema for terminal recording
brew install asciinema

# Record session
asciinema rec demo.cast

# Convert to GIF
npm install -g asciicast2gif
asciicast2gif demo.cast demo.gif
```

## Image Optimization

```bash
# Install optimization tools
brew install optipng jpegoptim

# Optimize PNG
optipng -o7 screenshot.png

# Resize if needed
sips -Z 1400 screenshot.png
```

## Naming Convention

```
waf-detection-no-waf.png
waf-detection-cloudflare.png
report-no-waf-critical.png
report-cloudflare-detected.png
integration-test-results.png
wordpress-payloads-preview.png
recommendation-engine-output.png
```

## Adding to Documentation

Once screenshots are created, update `GITHUB_FEATURE_ANNOUNCEMENT.md`:

```markdown
## Screenshots

### WAF Detection
![No WAF Detected](assets/screenshots/waf-detection-no-waf.png)
*Critical alert when no WAF protection is found*

![Cloudflare Detected](assets/screenshots/waf-detection-cloudflare.png)
*Successful WAF detection with vendor identification*

### HTML Reports
![Report - No WAF](assets/screenshots/report-no-waf-critical.png)
*Professional security report with deployment recommendations*

![Report - WAF Detected](assets/screenshots/report-cloudflare-detected.png)
*Security report showing WAF vendor information*
```
