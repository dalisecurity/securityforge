# API Documentation

## 📚 Programmatic Usage Guide

SecurityForge can be used programmatically in your Python scripts and automation workflows.

---

## 🚀 Quick Start

### Basic Usage

```python
import json
from pathlib import Path

# Load payloads from a category
def load_payloads(category, subcategory=None):
    """Load payloads from JSON files"""
    if subcategory:
        file_path = Path(f'payloads/{category}/{subcategory}.json')
    else:
        file_path = Path(f'payloads/{category}/basic.json')
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    return data['payloads']

# Example: Load XSS payloads
xss_payloads = load_payloads('xss', 'basic')
print(f"Loaded {len(xss_payloads)} XSS payloads")
```

---

## 📖 Core Functions

### 1. Load All Payloads

```python
def load_all_payloads():
    """Load all payloads from all categories"""
    from pathlib import Path
    import json
    
    all_payloads = {}
    payload_dir = Path('payloads')
    
    for json_file in payload_dir.rglob('*.json'):
        category = json_file.parent.name
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        if category not in all_payloads:
            all_payloads[category] = []
        
        all_payloads[category].extend(data['payloads'])
    
    return all_payloads

# Usage
payloads = load_all_payloads()
print(f"Total categories: {len(payloads)}")
for category, items in payloads.items():
    print(f"{category}: {len(items)} payloads")
```

### 2. Filter Payloads by CVE

```python
def get_cve_payloads(cve_id):
    """Get all payloads for a specific CVE"""
    import json
    
    with open('payloads/xss/cve_2025_real_world.json', 'r') as f:
        data = json.load(f)
    
    return [p for p in data['payloads'] if p.get('cve') == cve_id]

# Usage
log4shell = get_cve_payloads('CVE-2021-44228')
print(f"Found {len(log4shell)} Log4Shell payloads")
```

### 3. Search Payloads

```python
def search_payloads(query, category=None):
    """Search payloads by description or technique"""
    results = []
    all_payloads = load_all_payloads()
    
    for cat, payloads in all_payloads.items():
        if category and cat != category:
            continue
            
        for payload in payloads:
            if query.lower() in payload.get('description', '').lower():
                results.append(payload)
            elif query.lower() in payload.get('technique', '').lower():
                results.append(payload)
    
    return results

# Usage
results = search_payloads('prototype pollution')
print(f"Found {len(results)} payloads related to prototype pollution")
```

---

## 🧪 Testing Functions

### 1. Basic WAF Testing

```python
import requests

def test_payload(target_url, payload, method='GET'):
    """Test a single payload against a target"""
    try:
        if method == 'GET':
            response = requests.get(
                target_url,
                params={'test': payload},
                timeout=10
            )
        else:
            response = requests.post(
                target_url,
                data={'test': payload},
                timeout=10
            )
        
        return {
            'status_code': response.status_code,
            'blocked': response.status_code == 403,
            'response_time': response.elapsed.total_seconds(),
            'waf_header': response.headers.get('X-WAF-Status', 'unknown')
        }
    except Exception as e:
        return {'error': str(e)}

# Usage
result = test_payload('https://example.com', '<script>alert(1)</script>')
print(f"Status: {result['status_code']}, Blocked: {result['blocked']}")
```

### 2. Batch Testing

```python
def batch_test(target_url, payloads, max_workers=10):
    """Test multiple payloads concurrently"""
    from concurrent.futures import ThreadPoolExecutor
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(test_payload, target_url, p['payload'])
            for p in payloads
        ]
        
        for future, payload in zip(futures, payloads):
            result = future.result()
            results.append({
                'payload_id': payload['id'],
                'payload': payload['payload'],
                'result': result
            })
    
    return results

# Usage
xss_payloads = load_payloads('xss', 'basic')[:10]  # Test first 10
results = batch_test('https://example.com', xss_payloads)
blocked = sum(1 for r in results if r['result'].get('blocked'))
print(f"Blocked: {blocked}/{len(results)}")
```

### 3. CVE Testing

```python
def test_cve(target_url, cve_id):
    """Test all payloads for a specific CVE"""
    payloads = get_cve_payloads(cve_id)
    results = batch_test(target_url, payloads)
    
    return {
        'cve': cve_id,
        'total_payloads': len(payloads),
        'blocked': sum(1 for r in results if r['result'].get('blocked')),
        'bypassed': sum(1 for r in results if not r['result'].get('blocked')),
        'errors': sum(1 for r in results if 'error' in r['result']),
        'results': results
    }

# Usage
log4shell_results = test_cve('https://example.com', 'CVE-2021-44228')
print(f"CVE-2021-44228: {log4shell_results['bypassed']} bypasses found")
```

---

## 📊 Analysis Functions

### 1. Generate Report

```python
def generate_report(results, output_file='report.json'):
    """Generate JSON report from test results"""
    import json
    from datetime import datetime
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_tests': len(results),
            'blocked': sum(1 for r in results if r['result'].get('blocked')),
            'bypassed': sum(1 for r in results if not r['result'].get('blocked')),
            'errors': sum(1 for r in results if 'error' in r['result'])
        },
        'results': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

# Usage
report = generate_report(results)
print(f"Report saved: {report['summary']}")
```

### 2. Statistics

```python
def get_statistics():
    """Get payload database statistics"""
    all_payloads = load_all_payloads()
    
    stats = {
        'total_payloads': sum(len(p) for p in all_payloads.values()),
        'categories': len(all_payloads),
        'by_category': {
            cat: len(payloads) 
            for cat, payloads in all_payloads.items()
        }
    }
    
    # CVE statistics
    with open('payloads/xss/cve_2025_real_world.json', 'r') as f:
        cve_data = json.load(f)
    
    stats['cve_count'] = len(cve_data['payloads'])
    stats['cve_by_severity'] = {}
    
    for payload in cve_data['payloads']:
        severity = payload.get('severity', 'unknown')
        stats['cve_by_severity'][severity] = \
            stats['cve_by_severity'].get(severity, 0) + 1
    
    return stats

# Usage
stats = get_statistics()
print(f"Total: {stats['total_payloads']} payloads")
print(f"CVEs: {stats['cve_count']}")
```

---

## 🔧 Advanced Usage

### Custom Payload Class

```python
class PayloadTester:
    """Advanced payload testing class"""
    
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.results = []
    
    def load_category(self, category):
        """Load all payloads from a category"""
        self.payloads = load_all_payloads()[category]
        return self
    
    def test_all(self, method='GET'):
        """Test all loaded payloads"""
        for payload in self.payloads:
            result = test_payload(
                self.target_url,
                payload['payload'],
                method
            )
            self.results.append({
                'payload': payload,
                'result': result
            })
        return self
    
    def get_bypasses(self):
        """Get all successful bypasses"""
        return [
            r for r in self.results 
            if not r['result'].get('blocked')
        ]
    
    def save_report(self, filename):
        """Save results to file"""
        generate_report(self.results, filename)
        return self

# Usage
tester = PayloadTester('https://example.com')
tester.load_category('xss').test_all().save_report('xss_report.json')
bypasses = tester.get_bypasses()
print(f"Found {len(bypasses)} bypasses")
```

---

## 🎯 Integration Examples

### 1. CI/CD Integration

```python
#!/usr/bin/env python3
"""CI/CD WAF validation script"""

def validate_waf_protection(target_url, min_block_rate=0.95):
    """Validate WAF is blocking payloads"""
    all_payloads = load_all_payloads()
    total_tested = 0
    total_blocked = 0
    
    for category, payloads in all_payloads.items():
        results = batch_test(target_url, payloads[:100])  # Sample
        total_tested += len(results)
        total_blocked += sum(1 for r in results if r['result'].get('blocked'))
    
    block_rate = total_blocked / total_tested
    
    if block_rate >= min_block_rate:
        print(f"✅ WAF Protection: {block_rate:.1%} (PASS)")
        return 0
    else:
        print(f"❌ WAF Protection: {block_rate:.1%} (FAIL)")
        return 1

# Usage in CI/CD
import sys
sys.exit(validate_waf_protection('https://staging.example.com'))
```

### 2. Bug Bounty Automation

```python
def bug_bounty_scan(targets, output_dir='reports'):
    """Automated bug bounty WAF testing"""
    from pathlib import Path
    
    Path(output_dir).mkdir(exist_ok=True)
    
    for target in targets:
        print(f"Testing {target}...")
        
        # Test critical CVEs first
        critical_cves = [
            'CVE-2021-44228',  # Log4Shell
            'CVE-2022-22965',  # Spring4Shell
            'CVE-2024-3400',   # Palo Alto
        ]
        
        for cve in critical_cves:
            results = test_cve(target, cve)
            if results['bypassed'] > 0:
                print(f"🚨 Potential bypass found: {cve}")
                generate_report(
                    results['results'],
                    f"{output_dir}/{target.replace('://', '_')}_{cve}.json"
                )

# Usage
targets = ['https://target1.com', 'https://target2.com']
bug_bounty_scan(targets)
```

---

## 📞 Support

For API questions or integration help:
- GitHub Issues: https://github.com/dalisecurity/waf-payload-arsenal/issues
- Documentation: https://github.com/dalisecurity/waf-payload-arsenal

---

**Last Updated**: February 28, 2026  
**Version**: 1.0.0
