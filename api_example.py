#!/usr/bin/env python3
"""
WAF Payload Arsenal - API Example
Simple Flask API for serving payloads in JSON format
"""

from flask import Flask, jsonify, request
import json
import os
from pathlib import Path

app = Flask(__name__)

# Load all payload files
def load_payloads():
    """Load all payload JSON files"""
    payloads_dir = Path('payloads')
    all_payloads = {}
    
    for category_dir in payloads_dir.iterdir():
        if category_dir.is_dir():
            category = category_dir.name
            all_payloads[category] = {}
            
            for payload_file in category_dir.glob('*.json'):
                with open(payload_file, 'r') as f:
                    data = json.load(f)
                    subcategory = payload_file.stem
                    all_payloads[category][subcategory] = data
    
    return all_payloads

PAYLOADS = load_payloads()

@app.route('/api/v1/payloads', methods=['GET'])
def get_all_payloads():
    """Get all payloads"""
    return jsonify({
        'status': 'success',
        'total_categories': len(PAYLOADS),
        'categories': list(PAYLOADS.keys()),
        'data': PAYLOADS
    })

@app.route('/api/v1/payloads/<category>', methods=['GET'])
def get_category_payloads(category):
    """Get payloads by category (e.g., xss, sqli, etc.)"""
    if category not in PAYLOADS:
        return jsonify({
            'status': 'error',
            'message': f'Category "{category}" not found',
            'available_categories': list(PAYLOADS.keys())
        }), 404
    
    return jsonify({
        'status': 'success',
        'category': category,
        'subcategories': list(PAYLOADS[category].keys()),
        'data': PAYLOADS[category]
    })

@app.route('/api/v1/payloads/<category>/<subcategory>', methods=['GET'])
def get_subcategory_payloads(category, subcategory):
    """Get payloads by category and subcategory"""
    if category not in PAYLOADS:
        return jsonify({
            'status': 'error',
            'message': f'Category "{category}" not found'
        }), 404
    
    if subcategory not in PAYLOADS[category]:
        return jsonify({
            'status': 'error',
            'message': f'Subcategory "{subcategory}" not found in category "{category}"',
            'available_subcategories': list(PAYLOADS[category].keys())
        }), 404
    
    return jsonify({
        'status': 'success',
        'category': category,
        'subcategory': subcategory,
        'data': PAYLOADS[category][subcategory]
    })

@app.route('/api/v1/cves', methods=['GET'])
def get_cves():
    """Get all CVE payloads"""
    cve_data = PAYLOADS.get('xss', {}).get('cve_2025_real_world', {})
    
    # Filter parameters
    severity = request.args.get('severity')
    min_cvss = request.args.get('min_cvss', type=float)
    year = request.args.get('year')
    
    payloads = cve_data.get('payloads', [])
    
    # Apply filters
    if severity:
        payloads = [p for p in payloads if p.get('severity') == severity]
    
    if min_cvss:
        payloads = [p for p in payloads if float(p.get('cvss', 0)) >= min_cvss]
    
    if year:
        payloads = [p for p in payloads if year in p.get('cve', '')]
    
    return jsonify({
        'status': 'success',
        'total': len(payloads),
        'filters': {
            'severity': severity,
            'min_cvss': min_cvss,
            'year': year
        },
        'data': payloads
    })

@app.route('/api/v1/modern-bypasses', methods=['GET'])
def get_modern_bypasses():
    """Get modern bypass techniques (2025-2026)"""
    modern_data = PAYLOADS.get('modern_bypasses', {}).get('2025_2026_techniques', {})
    
    # Filter by technique
    technique = request.args.get('technique')
    
    payloads = modern_data.get('payloads', [])
    
    if technique:
        payloads = [p for p in payloads if technique.lower() in p.get('category', '').lower()]
    
    return jsonify({
        'status': 'success',
        'total': len(payloads),
        'filter': {'technique': technique},
        'data': payloads
    })

@app.route('/api/v1/search', methods=['GET'])
def search_payloads():
    """Search payloads by keyword"""
    query = request.args.get('q', '').lower()
    
    if not query:
        return jsonify({
            'status': 'error',
            'message': 'Query parameter "q" is required'
        }), 400
    
    results = []
    
    for category, subcategories in PAYLOADS.items():
        for subcategory, data in subcategories.items():
            for payload in data.get('payloads', []):
                # Search in description, payload, and CVE
                searchable = f"{payload.get('description', '')} {payload.get('payload', '')} {payload.get('cve', '')}".lower()
                
                if query in searchable:
                    results.append({
                        'category': category,
                        'subcategory': subcategory,
                        'payload': payload
                    })
    
    return jsonify({
        'status': 'success',
        'query': query,
        'total': len(results),
        'data': results
    })

@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get repository statistics"""
    total_payloads = 0
    categories_count = {}
    
    for category, subcategories in PAYLOADS.items():
        category_total = 0
        for subcategory, data in subcategories.items():
            count = data.get('count', len(data.get('payloads', [])))
            category_total += count
        
        categories_count[category] = category_total
        total_payloads += category_total
    
    return jsonify({
        'status': 'success',
        'total_payloads': total_payloads,
        'categories': categories_count,
        'cve_count': PAYLOADS.get('xss', {}).get('cve_2025_real_world', {}).get('count', 0),
        'modern_bypass_count': PAYLOADS.get('modern_bypasses', {}).get('2025_2026_techniques', {}).get('count', 0)
    })

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'payloads_loaded': len(PAYLOADS) > 0
    })

@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        'name': 'WAF Payload Arsenal API',
        'version': '1.0.0',
        'endpoints': {
            'GET /api/v1/payloads': 'Get all payloads',
            'GET /api/v1/payloads/<category>': 'Get payloads by category',
            'GET /api/v1/payloads/<category>/<subcategory>': 'Get specific subcategory',
            'GET /api/v1/cves': 'Get CVE payloads (filters: severity, min_cvss, year)',
            'GET /api/v1/modern-bypasses': 'Get modern bypass techniques (filter: technique)',
            'GET /api/v1/search?q=<query>': 'Search payloads',
            'GET /api/v1/stats': 'Get repository statistics',
            'GET /api/v1/health': 'Health check'
        },
        'examples': {
            'Get all XSS payloads': '/api/v1/payloads/xss',
            'Get CVEs with CVSS >= 9.0': '/api/v1/cves?min_cvss=9.0',
            'Get critical CVEs': '/api/v1/cves?severity=critical',
            'Get 2025 CVEs': '/api/v1/cves?year=2025',
            'Get HTTP/2 bypasses': '/api/v1/modern-bypasses?technique=http2',
            'Search for Log4Shell': '/api/v1/search?q=log4shell',
            'Get statistics': '/api/v1/stats'
        }
    })

if __name__ == '__main__':
    print("🚀 WAF Payload Arsenal API")
    print("📊 Loaded payloads from database")
    print("🌐 Starting server on http://localhost:5000")
    print("\n📖 API Documentation: http://localhost:5000")
    print("🔍 Example: http://localhost:5000/api/v1/cves?severity=critical\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
