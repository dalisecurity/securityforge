#!/usr/bin/env python3
"""
Generate sample security reports demonstrating WAF detection and recommendations
"""

import json
from datetime import datetime

# Sample HTML template with WAF recommendations
def generate_sample_report_no_waf():
    """Generate sample report when NO WAF is detected"""
    
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report - No WAF Detected</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: linear-gradient(135deg, #f5f7fa 0%, #e8edf2 100%);
            padding: 40px 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 50%, #5b21b6 100%);
            color: white;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(30, 58, 138, 0.25);
        }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.1em; opacity: 0.9; }
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        .critical-alert {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            border-left: 6px solid #7f1d1d;
        }
        .critical-alert h2 { font-size: 1.8em; margin-bottom: 15px; }
        .critical-alert .icon { font-size: 3em; margin-bottom: 10px; }
        .waf-vendor {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 2px solid #0ea5e9;
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
        }
        .waf-vendor h3 { color: #0369a1; margin-bottom: 10px; }
        .waf-vendor .detail { margin: 8px 0; color: #0c4a6e; }
        .waf-vendor .detail strong { color: #075985; }
        .recommendation {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid #0ea5e9;
        }
        .stat-value { font-size: 2.5em; font-weight: bold; color: #0369a1; }
        .stat-label { color: #0c4a6e; margin-top: 5px; }
        .vulnerability {
            background: #fee2e2;
            border-left: 4px solid #dc2626;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
        }
        .vulnerability h3 { color: #991b1b; margin-bottom: 10px; }
        .action-item {
            background: white;
            border-left: 4px solid #10b981;
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .action-item h4 { color: #047857; margin-bottom: 8px; }
        ul { margin-left: 20px; margin-top: 10px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Testing Report</h1>
            <div class="subtitle">Target: https://vulnerable-example.com</div>
            <div class="subtitle">Date: ''' + datetime.now().strftime('%B %d, %Y %H:%M:%S') + '''</div>
        </div>

        <div class="critical-alert">
            <div class="icon">🚨</div>
            <h2>CRITICAL: No WAF Protection Detected</h2>
            <p style="font-size: 1.1em; margin-top: 10px;">
                Your application has <strong>NO Web Application Firewall</strong> protection, 
                leaving it vulnerable to automated attacks and OWASP Top 10 vulnerabilities.
            </p>
        </div>

        <div class="card">
            <h2 style="color: #1e3a8a; margin-bottom: 20px;">📊 Test Results Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">5</div>
                    <div class="stat-label">Total Payloads Tested</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">4</div>
                    <div class="stat-label">Payloads Blocked</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-color: #dc2626;">
                    <div class="stat-value" style="color: #991b1b;">1</div>
                    <div class="stat-label" style="color: #7f1d1d;">Payloads Bypassed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">80%</div>
                    <div class="stat-label">Block Rate</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #dc2626; margin-bottom: 20px;">⚠️ Vulnerabilities Found</h2>
            <div class="vulnerability">
                <h3>XSS (Cross-Site Scripting)</h3>
                <p><strong>Bypassed Payloads:</strong> 1</p>
                <p><strong>Payload:</strong> <code>&lt;svg/onload=alert`XSS`&gt;</code></p>
                <p><strong>Status Code:</strong> 200 (Not Blocked)</p>
                <p style="margin-top: 10px;">
                    <strong>Risk:</strong> This XSS vulnerability allows attackers to inject malicious JavaScript 
                    into your web pages, potentially stealing user sessions, credentials, or performing actions 
                    on behalf of users.
                </p>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #dc2626; margin-bottom: 20px;">🚨 Immediate Actions Required</h2>
            
            <div class="action-item">
                <h4>1. Deploy a Web Application Firewall IMMEDIATELY</h4>
                <p>Your application is currently exposed to:</p>
                <ul>
                    <li>OWASP Top 10 attacks (XSS, SQL Injection, etc.)</li>
                    <li>Automated bot attacks and credential stuffing</li>
                    <li>DDoS and resource exhaustion attacks</li>
                    <li>Zero-day vulnerabilities</li>
                    <li>No virtual patching capability</li>
                </ul>
            </div>

            <div class="action-item">
                <h4>2. Fix XSS Vulnerability in Code</h4>
                <p>Implement proper output encoding and Content Security Policy (CSP)</p>
            </div>

            <div class="action-item">
                <h4>3. Enable Security Headers</h4>
                <p>Add X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security</p>
            </div>

            <div class="action-item">
                <h4>4. Implement Input Validation</h4>
                <p>Validate and sanitize all user inputs on both client and server side</p>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #0369a1; margin-bottom: 20px;">🛡️ Recommended WAF Vendors</h2>
            <p style="margin-bottom: 20px; font-size: 1.1em;">
                Deploy a WAF to protect your application while you fix the underlying vulnerabilities. 
                Here are the top recommended options:
            </p>

            <div class="waf-vendor">
                <h3>☁️ Cloudflare WAF (Recommended for Quick Deployment)</h3>
                <div class="detail"><strong>Deployment Time:</strong> 5 minutes (DNS change only)</div>
                <div class="detail"><strong>Pricing:</strong> $20/month (includes CDN + DDoS protection)</div>
                <div class="detail"><strong>Best For:</strong> Any size website, quick deployment needed</div>
                <div class="detail"><strong>Features:</strong> DDoS protection, Bot management, Rate limiting, Global CDN, SSL/TLS</div>
                <div class="detail"><strong>Setup:</strong> Sign up → Add domain → Update DNS → Enable WAF (5 minutes)</div>
                <div class="detail"><strong>URL:</strong> <a href="https://www.cloudflare.com/waf/" target="_blank">https://www.cloudflare.com/waf/</a></div>
            </div>

            <div class="waf-vendor">
                <h3>☁️ AWS WAF (Best for AWS-Hosted Applications)</h3>
                <div class="detail"><strong>Deployment Time:</strong> 30 minutes (CloudFormation/Terraform)</div>
                <div class="detail"><strong>Pricing:</strong> $5/month + $1/rule + $0.60/million requests</div>
                <div class="detail"><strong>Best For:</strong> AWS-hosted applications, API protection</div>
                <div class="detail"><strong>Features:</strong> AWS integration, Custom rules, Managed rule groups, API protection</div>
                <div class="detail"><strong>URL:</strong> <a href="https://aws.amazon.com/waf/" target="_blank">https://aws.amazon.com/waf/</a></div>
            </div>

            <div class="waf-vendor">
                <h3>☁️ Azure WAF (Best for Azure-Hosted Applications)</h3>
                <div class="detail"><strong>Deployment Time:</strong> 30 minutes (Azure Portal)</div>
                <div class="detail"><strong>Pricing:</strong> Included with Application Gateway</div>
                <div class="detail"><strong>Best For:</strong> Azure-hosted applications</div>
                <div class="detail"><strong>Features:</strong> Azure integration, OWASP rule sets, Custom rules, Bot protection</div>
                <div class="detail"><strong>URL:</strong> <a href="https://azure.microsoft.com/products/web-application-firewall" target="_blank">Azure WAF</a></div>
            </div>

            <div class="waf-vendor" style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-color: #10b981;">
                <h3>🆓 ModSecurity (Free & Open Source)</h3>
                <div class="detail"><strong>Deployment Time:</strong> 1-2 hours (server installation)</div>
                <div class="detail"><strong>Pricing:</strong> Free (open source)</div>
                <div class="detail"><strong>Best For:</strong> Budget-conscious, self-managed infrastructure</div>
                <div class="detail"><strong>Features:</strong> OWASP Core Rule Set, Custom rules, Self-hosted</div>
                <div class="detail"><strong>URL:</strong> <a href="https://github.com/SpiderLabs/ModSecurity" target="_blank">ModSecurity on GitHub</a></div>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #7c3aed; margin-bottom: 20px;">📋 Security Best Practices</h2>
            <div class="recommendation">
                <h4 style="margin-bottom: 10px;">Defense in Depth</h4>
                <p>A WAF is one layer of security. Implement multiple layers:</p>
                <ul>
                    <li><strong>Application Layer:</strong> Input validation, output encoding, parameterized queries</li>
                    <li><strong>Network Layer:</strong> Firewall rules, network segmentation, VPN for admin access</li>
                    <li><strong>Infrastructure Layer:</strong> Regular patching, secure configurations, access controls</li>
                    <li><strong>WAF Layer:</strong> OWASP Top 10 protection, bot management, rate limiting</li>
                </ul>
            </div>

            <div class="recommendation">
                <h4 style="margin-bottom: 10px;">Regular Security Testing</h4>
                <p>Test your security posture regularly:</p>
                <ul>
                    <li>Quarterly penetration testing</li>
                    <li>Automated vulnerability scanning</li>
                    <li>Code security reviews</li>
                    <li>WAF effectiveness testing</li>
                </ul>
            </div>
        </div>

        <div class="card" style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border: 2px solid #f59e0b;">
            <h2 style="color: #92400e; margin-bottom: 15px;">⚡ Quick Start: Deploy Cloudflare WAF in 5 Minutes</h2>
            <ol style="margin-left: 20px; color: #78350f;">
                <li style="margin: 10px 0;"><strong>Sign up</strong> at <a href="https://dash.cloudflare.com/sign-up" target="_blank">cloudflare.com</a></li>
                <li style="margin: 10px 0;"><strong>Add your domain</strong> to Cloudflare</li>
                <li style="margin: 10px 0;"><strong>Update DNS nameservers</strong> at your domain registrar</li>
                <li style="margin: 10px 0;"><strong>Enable WAF</strong> in Cloudflare dashboard (included in all plans)</li>
                <li style="margin: 10px 0;"><strong>Done!</strong> Your site is now protected</li>
            </ol>
        </div>

        <div class="card" style="text-align: center; background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%); color: white;">
            <h3 style="margin-bottom: 15px;">Generated by SecurityForge</h3>
            <p>Comprehensive Security Testing Platform</p>
            <p style="margin-top: 10px; opacity: 0.9;">For authorized security testing only</p>
        </div>
    </div>
</body>
</html>'''
    
    with open('sample_report_no_waf.html', 'w', encoding='utf-8') as f:
        f.write(html)
    
    print('✅ Generated: sample_report_no_waf.html')


def generate_sample_report_with_waf():
    """Generate sample report when Cloudflare WAF is detected"""
    
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report - Cloudflare WAF Detected</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: linear-gradient(135deg, #f5f7fa 0%, #e8edf2 100%);
            padding: 40px 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 50%, #5b21b6 100%);
            color: white;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(30, 58, 138, 0.25);
        }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.1em; opacity: 0.9; }
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        .success-alert {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            border-left: 6px solid #047857;
        }
        .success-alert h2 { font-size: 1.8em; margin-bottom: 15px; }
        .success-alert .icon { font-size: 3em; margin-bottom: 10px; }
        .waf-info {
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            border: 2px solid #3b82f6;
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
        }
        .waf-info h3 { color: #1e40af; margin-bottom: 15px; font-size: 1.5em; }
        .waf-info .detail { margin: 10px 0; color: #1e3a8a; font-size: 1.05em; }
        .waf-info .detail strong { color: #1e40af; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid #10b981;
        }
        .stat-value { font-size: 2.5em; font-weight: bold; color: #047857; }
        .stat-label { color: #065f46; margin-top: 5px; }
        .recommendation {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
        }
        .action-item {
            background: white;
            border-left: 4px solid #3b82f6;
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .action-item h4 { color: #1e40af; margin-bottom: 8px; }
        ul { margin-left: 20px; margin-top: 10px; }
        li { margin: 5px 0; }
        .vulnerability {
            background: #fee2e2;
            border-left: 4px solid #dc2626;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Testing Report</h1>
            <div class="subtitle">Target: https://secure-example.com</div>
            <div class="subtitle">Date: ''' + datetime.now().strftime('%B %d, %Y %H:%M:%S') + '''</div>
        </div>

        <div class="success-alert">
            <div class="icon">✅</div>
            <h2>Cloudflare WAF Detected (95% Confidence)</h2>
            <p style="font-size: 1.1em; margin-top: 10px;">
                Your application is protected by <strong>Cloudflare Web Application Firewall</strong>. 
                Continue monitoring and tuning for optimal protection.
            </p>
        </div>

        <div class="card">
            <h2 style="color: #1e3a8a; margin-bottom: 20px;">📊 Test Results Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">5</div>
                    <div class="stat-label">Total Payloads Tested</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">4</div>
                    <div class="stat-label">Payloads Blocked</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-color: #dc2626;">
                    <div class="stat-value" style="color: #991b1b;">1</div>
                    <div class="stat-label" style="color: #7f1d1d;">Payloads Bypassed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">80%</div>
                    <div class="stat-label">Block Rate</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #1e40af; margin-bottom: 20px;">🛡️ WAF Vendor Information</h2>
            <div class="waf-info">
                <h3>Cloudflare Web Application Firewall</h3>
                <div class="detail"><strong>Type:</strong> Cloud WAF</div>
                <div class="detail"><strong>Pricing:</strong> Starts at $20/month</div>
                <div class="detail"><strong>Deployment:</strong> DNS change (5 minutes)</div>
                <div class="detail"><strong>Best For:</strong> Small to large websites, e-commerce, SaaS</div>
                <div class="detail"><strong>Features:</strong> DDoS protection, Bot management, Rate limiting, Global CDN, SSL/TLS</div>
                <div class="detail"><strong>Detection Confidence:</strong> 95% (High)</div>
                <div class="detail"><strong>URL:</strong> <a href="https://www.cloudflare.com/waf/" target="_blank">https://www.cloudflare.com/waf/</a></div>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #dc2626; margin-bottom: 20px;">⚠️ Vulnerability Found Despite WAF</h2>
            <div class="vulnerability">
                <h3>XSS (Cross-Site Scripting) - WAF Bypass</h3>
                <p><strong>Bypassed Payload:</strong> <code>&lt;svg/onload=alert`XSS`&gt;</code></p>
                <p><strong>Status Code:</strong> 200 (Not Blocked by WAF)</p>
                <p style="margin-top: 10px;">
                    <strong>Action Required:</strong> This payload bypassed the Cloudflare WAF, indicating a configuration gap. 
                    Update WAF rules to block this specific pattern and fix the vulnerability in your application code.
                </p>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #1e40af; margin-bottom: 20px;">🔧 Recommended Improvements</h2>
            
            <div class="action-item">
                <h4>1. Update Cloudflare WAF Rules</h4>
                <p>The bypassed XSS payload indicates a rule gap. Actions:</p>
                <ul>
                    <li>Review Cloudflare WAF dashboard for blocked attacks</li>
                    <li>Enable "OWASP ModSecurity Core Rule Set" if not already active</li>
                    <li>Create custom rule to block SVG-based XSS patterns</li>
                    <li>Set WAF to "High" security level for sensitive endpoints</li>
                </ul>
            </div>

            <div class="action-item">
                <h4>2. Fix XSS Vulnerability in Application Code</h4>
                <p>WAF is a defense layer, but vulnerabilities must be fixed in code:</p>
                <ul>
                    <li>Implement Content Security Policy (CSP)</li>
                    <li>Use output encoding for all user-generated content</li>
                    <li>Sanitize inputs on both client and server side</li>
                    <li>Enable XSS protection headers</li>
                </ul>
            </div>

            <div class="action-item">
                <h4>3. Enable Advanced Cloudflare Features</h4>
                <ul>
                    <li><strong>Bot Management:</strong> Block automated attacks and credential stuffing</li>
                    <li><strong>Rate Limiting:</strong> Prevent brute force and DDoS attacks</li>
                    <li><strong>Page Rules:</strong> Apply stricter security to admin/login pages</li>
                    <li><strong>Firewall Rules:</strong> Block suspicious IP addresses and patterns</li>
                </ul>
            </div>

            <div class="action-item">
                <h4>4. Monitoring and Logging</h4>
                <ul>
                    <li>Enable detailed WAF logs in Cloudflare dashboard</li>
                    <li>Set up alerts for blocked requests and bypass attempts</li>
                    <li>Review false positives regularly and adjust rules</li>
                    <li>Integrate with SIEM if available</li>
                </ul>
            </div>

            <div class="action-item">
                <h4>5. Regular Testing</h4>
                <ul>
                    <li>Test WAF effectiveness quarterly with SecurityForge</li>
                    <li>Update rules based on new threats and bypass attempts</li>
                    <li>Conduct penetration testing annually</li>
                    <li>Review Cloudflare's threat intelligence updates</li>
                </ul>
            </div>
        </div>

        <div class="card">
            <h2 style="color: #7c3aed; margin-bottom: 20px;">📋 Security Best Practices</h2>
            <div class="recommendation">
                <h4 style="margin-bottom: 10px;">Defense in Depth</h4>
                <p>WAF is one layer. Implement multiple security layers:</p>
                <ul>
                    <li><strong>Application Layer:</strong> Input validation, output encoding, secure coding</li>
                    <li><strong>WAF Layer:</strong> Cloudflare WAF with OWASP rules + custom rules</li>
                    <li><strong>Network Layer:</strong> Firewall, network segmentation, VPN</li>
                    <li><strong>Infrastructure Layer:</strong> Regular patching, secure configs, monitoring</li>
                </ul>
            </div>

            <div class="recommendation">
                <h4 style="margin-bottom: 10px;">Continuous Improvement</h4>
                <ul>
                    <li>Review WAF logs daily for attack patterns</li>
                    <li>Update rules based on new vulnerabilities</li>
                    <li>Test after application changes</li>
                    <li>Stay informed about new attack techniques</li>
                </ul>
            </div>
        </div>

        <div class="card" style="text-align: center; background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%); color: white;">
            <h3 style="margin-bottom: 15px;">Generated by SecurityForge</h3>
            <p>Comprehensive Security Testing Platform</p>
            <p style="margin-top: 10px; opacity: 0.9;">For authorized security testing only</p>
        </div>
    </div>
</body>
</html>'''
    
    with open('sample_report_with_waf.html', 'w', encoding='utf-8') as f:
        f.write(html)
    
    print('✅ Generated: sample_report_with_waf.html')


if __name__ == '__main__':
    print('Generating sample security reports...\n')
    generate_sample_report_no_waf()
    generate_sample_report_with_waf()
    print('\n📊 Sample reports generated successfully!')
    print('\nOpen these files in your browser to view:')
    print('   1. sample_report_no_waf.html - Critical WAF deployment recommendations')
    print('   2. sample_report_with_waf.html - Cloudflare WAF detected with vendor info')
