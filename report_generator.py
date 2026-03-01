#!/usr/bin/env python3
"""
SecurityForge - Professional Security Testing Report Generator
Generates comprehensive HTML/PDF reports with Dali Security branding
"""

import json
import datetime
from pathlib import Path
from collections import defaultdict

class SecurityReportGenerator:
    """Generate professional security testing reports"""
    
    def __init__(self):
        self.dali_logo_html = '''
        <div class="dali-logo-container" style="display: flex; align-items: center; gap: 15px;">
            <a href="http://localhost:8090/" target="_blank" style="display: flex; align-items: center; gap: 12px; text-decoration: none;">
                <img src="http://localhost:8090/logo-icon.svg" alt="DALI Security Icon" style="height: 50px; width: 50px;">
                <div style="display: flex; flex-direction: column; line-height: 1.2;">
                    <span style="font-size: 28px; font-weight: bold; color: white; letter-spacing: 2px;">DALI</span>
                    <span style="font-size: 14px; color: rgba(255,255,255,0.9); letter-spacing: 3px;">SECURITY</span>
                </div>
            </a>
        </div>
        '''
    
    def generate_html_report(self, test_results, output_file='security_report.html'):
        """Generate comprehensive HTML security report"""
        
        # Calculate statistics
        stats = self._calculate_statistics(test_results)
        vulnerabilities = self._identify_vulnerabilities(test_results)
        recommendations = self._generate_recommendations(vulnerabilities, stats)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report - Dali Security</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #2d3748;
            background: #f7fafc;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .logo {{
            margin-bottom: 20px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .meta-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        
        .meta-card .label {{
            font-size: 0.9em;
            color: #718096;
            margin-bottom: 5px;
        }}
        
        .meta-card .value {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2d3748;
        }}
        
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2d3748;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .severity-critical {{
            color: #e53e3e;
            font-weight: bold;
        }}
        
        .severity-high {{
            color: #dd6b20;
            font-weight: bold;
        }}
        
        .severity-medium {{
            color: #d69e2e;
            font-weight: bold;
        }}
        
        .severity-low {{
            color: #38a169;
            font-weight: bold;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        
        .stat-card.blocked {{
            background: #f0fff4;
            border-color: #38a169;
        }}
        
        .stat-card.bypassed {{
            background: #fff5f5;
            border-color: #e53e3e;
        }}
        
        .stat-card.total {{
            background: #ebf8ff;
            border-color: #3182ce;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card .label {{
            font-size: 1.1em;
            color: #718096;
        }}
        
        .vulnerability-list {{
            margin: 20px 0;
        }}
        
        .vulnerability-item {{
            background: #f7fafc;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        
        .vulnerability-item.critical {{
            border-color: #e53e3e;
        }}
        
        .vulnerability-item.high {{
            border-color: #dd6b20;
        }}
        
        .vulnerability-item.medium {{
            border-color: #d69e2e;
        }}
        
        .vulnerability-item.low {{
            border-color: #38a169;
        }}
        
        .vulnerability-item h3 {{
            font-size: 1.3em;
            margin-bottom: 10px;
        }}
        
        .vulnerability-item .details {{
            margin: 10px 0;
            color: #4a5568;
        }}
        
        .vulnerability-item .payload {{
            background: #2d3748;
            color: #68d391;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .recommendation-list {{
            margin: 20px 0;
        }}
        
        .recommendation-item {{
            background: #edf2f7;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #4299e1;
        }}
        
        .recommendation-item h3 {{
            font-size: 1.2em;
            margin-bottom: 10px;
            color: #2d3748;
        }}
        
        .recommendation-item .priority {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .priority.high {{
            background: #fed7d7;
            color: #c53030;
        }}
        
        .priority.medium {{
            background: #feebc8;
            color: #c05621;
        }}
        
        .priority.low {{
            background: #c6f6d5;
            color: #276749;
        }}
        
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f7fafc;
            border-radius: 8px;
        }}
        
        .progress-bar {{
            height: 30px;
            background: #e2e8f0;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.3s ease;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #718096;
            border-top: 2px solid #e2e8f0;
            margin-top: 50px;
        }}
        
        .footer .powered-by {{
            margin-top: 10px;
            font-size: 0.9em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        th {{
            background: #f7fafc;
            font-weight: bold;
            color: #2d3748;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge.success {{
            background: #c6f6d5;
            color: #276749;
        }}
        
        .badge.danger {{
            background: #fed7d7;
            color: #c53030;
        }}
        
        .badge.warning {{
            background: #feebc8;
            color: #c05621;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .section {{
                box-shadow: none;
                border: 1px solid #e2e8f0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                {self.dali_logo_html}
            </div>
            <h1>Security Testing Report</h1>
            <div class="subtitle">Comprehensive Web Application Security Assessment</div>
        </div>
        
        <!-- Meta Information -->
        <div class="meta-info">
            <div class="meta-card">
                <div class="label">Report Date</div>
                <div class="value">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
            </div>
            <div class="meta-card">
                <div class="label">Target URL</div>
                <div class="value">{test_results.get('target', 'N/A')}</div>
            </div>
            <div class="meta-card">
                <div class="label">Test Duration</div>
                <div class="value">{test_results.get('duration', 'N/A')}</div>
            </div>
            <div class="meta-card">
                <div class="label">Security Score</div>
                <div class="value">{stats['security_score']}/100</div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="number">{stats['total_payloads']}</div>
                    <div class="label">Total Payloads Tested</div>
                </div>
                <div class="stat-card blocked">
                    <div class="number">{stats['blocked_payloads']}</div>
                    <div class="label">Payloads Blocked ✓</div>
                </div>
                <div class="stat-card bypassed">
                    <div class="number">{stats['bypassed_payloads']}</div>
                    <div class="label">Payloads Bypassed ⚠️</div>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>Security Effectiveness</h3>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {stats['block_rate']}%">
                        {stats['block_rate']}% Blocked
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Found -->
        <div class="section">
            <h2>🔍 Vulnerabilities Discovered</h2>
            {self._render_vulnerabilities(vulnerabilities)}
        </div>
        
        <!-- Payload Analysis -->
        <div class="section">
            <h2>📈 Payload Analysis by Category</h2>
            {self._render_payload_analysis(stats)}
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <h2>💡 Security Recommendations</h2>
            {self._render_recommendations(recommendations)}
        </div>
        
        <!-- Detailed Test Results -->
        <div class="section">
            <h2>📋 Detailed Test Results</h2>
            {self._render_detailed_results(test_results)}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>Generated by SecurityForge</strong></p>
            <p class="powered-by">Powered by Dali Security | Professional Security Testing Platform</p>
            <p style="margin-top: 10px; font-size: 0.85em;">
                This report is confidential and intended for authorized personnel only.
            </p>
        </div>
    </div>
</body>
</html>'''
        
        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file
    
    def _calculate_statistics(self, test_results):
        """Calculate testing statistics"""
        results = test_results.get('results', [])
        
        total = len(results)
        blocked = sum(1 for r in results if r.get('blocked', False))
        bypassed = total - blocked
        block_rate = round((blocked / total * 100) if total > 0 else 0, 1)
        
        # Calculate security score (higher is better)
        security_score = min(100, round(block_rate))
        
        # Category breakdown
        categories = defaultdict(lambda: {'total': 0, 'blocked': 0, 'bypassed': 0})
        for result in results:
            cat = result.get('category', 'unknown')
            categories[cat]['total'] += 1
            if result.get('blocked', False):
                categories[cat]['blocked'] += 1
            else:
                categories[cat]['bypassed'] += 1
        
        return {
            'total_payloads': total,
            'blocked_payloads': blocked,
            'bypassed_payloads': bypassed,
            'block_rate': block_rate,
            'security_score': security_score,
            'categories': dict(categories)
        }
    
    def _identify_vulnerabilities(self, test_results):
        """Identify vulnerabilities from test results"""
        vulnerabilities = []
        results = test_results.get('results', [])
        
        # Group bypassed payloads by category
        bypassed_by_category = defaultdict(list)
        for result in results:
            if not result.get('blocked', False):
                cat = result.get('category', 'unknown')
                bypassed_by_category[cat].append(result)
        
        # Create vulnerability entries
        severity_map = {
            'xss': 'high',
            'sqli': 'critical',
            'command_injection': 'critical',
            'xxe': 'high',
            'ssrf': 'high',
            'ssti': 'high',
            'path_traversal': 'medium',
            'open-redirect': 'medium',
            'crlf_injection': 'medium',
        }
        
        for category, payloads in bypassed_by_category.items():
            if payloads:
                vulnerabilities.append({
                    'category': category,
                    'severity': severity_map.get(category, 'medium'),
                    'count': len(payloads),
                    'payloads': payloads[:5],  # Show first 5 examples
                    'description': self._get_vulnerability_description(category)
                })
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return vulnerabilities
    
    def _get_vulnerability_description(self, category):
        """Get description for vulnerability category"""
        descriptions = {
            'xss': 'Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages.',
            'sqli': 'SQL Injection vulnerabilities allow attackers to manipulate database queries and access sensitive data.',
            'command_injection': 'Command Injection allows attackers to execute arbitrary system commands on the server.',
            'xxe': 'XML External Entity (XXE) vulnerabilities can lead to data disclosure and server-side request forgery.',
            'ssrf': 'Server-Side Request Forgery (SSRF) allows attackers to make requests from the server to internal resources.',
            'ssti': 'Server-Side Template Injection can lead to remote code execution.',
            'path_traversal': 'Path Traversal vulnerabilities allow access to files outside the intended directory.',
            'open-redirect': 'Open Redirect vulnerabilities can be used in phishing attacks.',
            'crlf_injection': 'CRLF Injection can lead to HTTP response splitting and cache poisoning.',
        }
        return descriptions.get(category, 'Security vulnerability detected in this category.')
    
    def _generate_recommendations(self, vulnerabilities, stats):
        """Generate security recommendations"""
        recommendations = []
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v['severity'] == 'critical']
        if critical_vulns:
            for vuln in critical_vulns:
                recommendations.append({
                    'priority': 'high',
                    'title': f'Fix {vuln["category"].upper()} Vulnerability',
                    'description': f'Immediately address {vuln["count"]} bypassed {vuln["category"]} payloads.',
                    'action': self._get_fix_recommendation(vuln['category'])
                })
        
        # High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v['severity'] == 'high']
        if high_vulns:
            for vuln in high_vulns:
                recommendations.append({
                    'priority': 'high',
                    'title': f'Strengthen {vuln["category"].upper()} Protection',
                    'description': f'{vuln["count"]} {vuln["category"]} payloads bypassed security controls.',
                    'action': self._get_fix_recommendation(vuln['category'])
                })
        
        # General recommendations based on block rate
        if stats['block_rate'] < 80:
            recommendations.append({
                'priority': 'high',
                'title': 'Improve Overall WAF Configuration',
                'description': f'Current block rate is {stats["block_rate"]}%. Target should be >95%.',
                'action': 'Review and update WAF rules, enable stricter security policies, and implement defense-in-depth strategies.'
            })
        
        # Category-specific recommendations
        for category, data in stats['categories'].items():
            if data['bypassed'] > 0:
                bypass_rate = round((data['bypassed'] / data['total'] * 100), 1)
                if bypass_rate > 20:
                    recommendations.append({
                        'priority': 'medium',
                        'title': f'Enhance {category.upper()} Detection',
                        'description': f'{bypass_rate}% of {category} payloads bypassed detection.',
                        'action': self._get_fix_recommendation(category)
                    })
        
        return recommendations
    
    def _get_fix_recommendation(self, category):
        """Get specific fix recommendations for each category"""
        fixes = {
            'xss': 'Implement Content Security Policy (CSP), use output encoding, sanitize user input, and enable XSS protection headers.',
            'sqli': 'Use parameterized queries/prepared statements, implement input validation, apply principle of least privilege to database accounts.',
            'command_injection': 'Avoid system calls with user input, use safe APIs, implement strict input validation and whitelisting.',
            'xxe': 'Disable external entity processing in XML parsers, use less complex data formats like JSON when possible.',
            'ssrf': 'Implement URL whitelisting, validate and sanitize URLs, use network segmentation to restrict outbound requests.',
            'ssti': 'Use logic-less template engines, implement sandboxing, validate and sanitize template inputs.',
            'path_traversal': 'Implement strict path validation, use chroot jails, avoid user input in file operations.',
            'open-redirect': 'Validate redirect URLs against whitelist, avoid using user input directly in redirects.',
            'crlf_injection': 'Sanitize user input in HTTP headers, use framework-provided header setting methods.',
        }
        return fixes.get(category, 'Review security best practices for this vulnerability type and implement appropriate controls.')
    
    def _render_vulnerabilities(self, vulnerabilities):
        """Render vulnerabilities section"""
        if not vulnerabilities:
            return '<p style="color: #38a169; font-size: 1.2em;">✅ No vulnerabilities detected! All payloads were successfully blocked.</p>'
        
        html = f'<p style="margin-bottom: 20px;">Found <strong>{len(vulnerabilities)}</strong> vulnerability categories:</p>'
        html += '<div class="vulnerability-list">'
        
        for vuln in vulnerabilities:
            severity_class = vuln['severity']
            html += f'''
            <div class="vulnerability-item {severity_class}">
                <h3>
                    <span class="severity-{severity_class}">[{vuln["severity"].upper()}]</span>
                    {vuln["category"].upper()} Vulnerability
                </h3>
                <div class="details">
                    <p><strong>Bypassed Payloads:</strong> {vuln["count"]}</p>
                    <p><strong>Description:</strong> {vuln["description"]}</p>
                </div>
                <p><strong>Example Bypassed Payloads:</strong></p>
            '''
            
            for payload in vuln['payloads'][:3]:
                html += f'<div class="payload">{self._escape_html(payload.get("payload", "N/A"))}</div>'
            
            html += '</div>'
        
        html += '</div>'
        return html
    
    def _render_payload_analysis(self, stats):
        """Render payload analysis table"""
        html = '<table>'
        html += '<thead><tr><th>Category</th><th>Total Tested</th><th>Blocked</th><th>Bypassed</th><th>Block Rate</th><th>Status</th></tr></thead>'
        html += '<tbody>'
        
        for category, data in sorted(stats['categories'].items()):
            block_rate = round((data['blocked'] / data['total'] * 100) if data['total'] > 0 else 0, 1)
            
            if block_rate >= 95:
                status = '<span class="badge success">Excellent</span>'
            elif block_rate >= 80:
                status = '<span class="badge warning">Good</span>'
            else:
                status = '<span class="badge danger">Needs Attention</span>'
            
            html += f'''
            <tr>
                <td><strong>{category.upper()}</strong></td>
                <td>{data["total"]}</td>
                <td style="color: #38a169;">{data["blocked"]}</td>
                <td style="color: #e53e3e;">{data["bypassed"]}</td>
                <td><strong>{block_rate}%</strong></td>
                <td>{status}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html
    
    def _render_recommendations(self, recommendations):
        """Render recommendations section"""
        if not recommendations:
            return '<p style="color: #38a169;">✅ No immediate recommendations. Security posture is strong!</p>'
        
        html = '<div class="recommendation-list">'
        
        for rec in recommendations:
            html += f'''
            <div class="recommendation-item">
                <span class="priority {rec["priority"]}">{rec["priority"].upper()} PRIORITY</span>
                <h3>{rec["title"]}</h3>
                <p><strong>Issue:</strong> {rec["description"]}</p>
                <p><strong>Recommended Action:</strong> {rec["action"]}</p>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _render_detailed_results(self, test_results):
        """Render detailed test results table"""
        results = test_results.get('results', [])[:50]  # Show first 50
        
        html = '<table>'
        html += '<thead><tr><th>#</th><th>Category</th><th>Payload</th><th>Status</th><th>Response Code</th></tr></thead>'
        html += '<tbody>'
        
        for i, result in enumerate(results, 1):
            status = '✅ Blocked' if result.get('blocked', False) else '⚠️ Bypassed'
            status_class = 'success' if result.get('blocked', False) else 'danger'
            
            html += f'''
            <tr>
                <td>{i}</td>
                <td>{result.get("category", "N/A")}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{self._escape_html(result.get("payload", "N/A")[:100])}</td>
                <td><span class="badge {status_class}">{status}</span></td>
                <td>{result.get("status_code", "N/A")}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        
        if len(test_results.get('results', [])) > 50:
            html += f'<p style="margin-top: 10px; color: #718096;">Showing first 50 of {len(test_results.get("results", []))} results.</p>'
        
        return html
    
    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ''
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))


def generate_sample_report():
    """Generate a sample report for demonstration"""
    sample_data = {
        'target': 'https://example.com',
        'duration': '5 minutes 32 seconds',
        'results': [
            {'category': 'xss', 'payload': '<script>alert(1)</script>', 'blocked': True, 'status_code': 403},
            {'category': 'xss', 'payload': '<img src=x onerror=alert(1)>', 'blocked': False, 'status_code': 200},
            {'category': 'sqli', 'payload': "' OR '1'='1", 'blocked': True, 'status_code': 403},
            {'category': 'sqli', 'payload': "' UNION SELECT NULL--", 'blocked': False, 'status_code': 200},
            {'category': 'command_injection', 'payload': '; ls -la', 'blocked': True, 'status_code': 403},
            {'category': 'ssrf', 'payload': 'http://169.254.169.254', 'blocked': False, 'status_code': 200},
        ] * 10  # Multiply for more data
    }
    
    generator = SecurityReportGenerator()
    output_file = generator.generate_html_report(sample_data, 'sample_security_report.html')
    print(f"✅ Sample report generated: {output_file}")
    return output_file


if __name__ == '__main__':
    print("=" * 60)
    print("SecurityForge - Report Generator")
    print("=" * 60)
    print("\nGenerating sample security report...")
    generate_sample_report()
    print("\n✅ Done! Open 'sample_security_report.html' in your browser.")
