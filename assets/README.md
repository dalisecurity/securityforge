# SecurityForge Visual Assets

This directory contains visual assets for SecurityForge documentation and GitHub presentation.

## Directory Structure

```
assets/
├── icons/
│   ├── securityforge-logo.svg
│   ├── securityforge-icon.svg
│   └── feature-icons/
├── screenshots/
│   ├── waf-detection-no-waf.png
│   ├── waf-detection-cloudflare.png
│   ├── report-sample-no-waf.png
│   ├── report-sample-with-waf.png
│   ├── recommendation-engine.png
│   └── dashboard-overview.png
└── README.md
```

## Icon Specifications

### SecurityForge Logo
- **File**: `icons/securityforge-logo.svg`
- **Dimensions**: 512x512px
- **Format**: SVG (vector)
- **Colors**: 
  - Primary: #1e3a8a (Deep Blue)
  - Secondary: #5b21b6 (Purple)
  - Accent: #10b981 (Green)

### Feature Icons
- Shield icon for WAF detection
- Chart icon for analytics
- Alert icon for recommendations
- Lock icon for security

## Screenshot Specifications

### 1. WAF Detection - No WAF Scenario
**File**: `screenshots/waf-detection-no-waf.png`
**Description**: Terminal output showing critical alert when no WAF is detected
**Size**: 1200x800px

### 2. WAF Detection - Cloudflare Detected
**File**: `screenshots/waf-detection-cloudflare.png`
**Description**: Terminal output showing successful WAF detection with vendor info
**Size**: 1200x800px

### 3. HTML Report - No WAF
**File**: `screenshots/report-sample-no-waf.png`
**Description**: Professional HTML report showing critical WAF deployment recommendations
**Size**: 1400x900px

### 4. HTML Report - With WAF
**File**: `screenshots/report-sample-with-waf.png`
**Description**: HTML report showing Cloudflare WAF detected with optimization tips
**Size**: 1400x900px

### 5. Recommendation Engine
**File**: `screenshots/recommendation-engine.png`
**Description**: Formatted recommendation output with vendor suggestions
**Size**: 1200x800px

### 6. Dashboard Overview
**File**: `screenshots/dashboard-overview.png`
**Description**: Overview of SecurityForge features and capabilities
**Size**: 1600x1000px

## Usage in Documentation

### Markdown
```markdown
![SecurityForge Logo](assets/icons/securityforge-logo.svg)
![WAF Detection](assets/screenshots/waf-detection-no-waf.png)
```

### HTML
```html
<img src="assets/icons/securityforge-logo.svg" alt="SecurityForge" width="200">
<img src="assets/screenshots/waf-detection-no-waf.png" alt="WAF Detection">
```

## Creating Screenshots

To create actual screenshots:

1. **Terminal Screenshots**: Use `waf_tester.py` and capture output
2. **HTML Reports**: Open generated reports in browser and screenshot
3. **Recommendation Output**: Run `waf_recommendation_engine.py` and capture

## Image Optimization

- Use PNG for screenshots (better quality)
- Use SVG for icons (scalable)
- Optimize file sizes for web
- Maximum width: 1600px for GitHub display
