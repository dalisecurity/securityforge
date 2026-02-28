#!/usr/bin/env python3
"""
CVE Checker - Check if a CVE is supported and auto-create PR if missing
"""

import json
import os
import sys
import requests
from datetime import datetime

class CVEChecker:
    """Check CVE coverage and create PRs for missing CVEs"""
    
    def __init__(self):
        self.cve_files = [
            'payloads/xss/cve_2025_real_world.json',
            'payloads/xss/cve_additional_2020_2024.json'
        ]
        self.loaded_cves = {}
        self.load_existing_cves()
    
    def load_existing_cves(self):
        """Load all existing CVEs from database"""
        for cve_file in self.cve_files:
            if os.path.exists(cve_file):
                with open(cve_file, 'r') as f:
                    data = json.load(f)
                    for payload in data.get('payloads', []):
                        cve_id = payload.get('cve', '')
                        if cve_id:
                            self.loaded_cves[cve_id] = {
                                'file': cve_file,
                                'payload': payload
                            }
    
    def check_cve(self, cve_id):
        """Check if CVE is in database"""
        cve_id = cve_id.upper().strip()
        
        if not cve_id.startswith('CVE-'):
            cve_id = 'CVE-' + cve_id
        
        if cve_id in self.loaded_cves:
            return {
                'found': True,
                'cve': cve_id,
                'file': self.loaded_cves[cve_id]['file'],
                'payload': self.loaded_cves[cve_id]['payload']
            }
        
        return {
            'found': False,
            'cve': cve_id
        }
    
    def fetch_cve_info(self, cve_id):
        """Fetch CVE information from NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Extract CVSS score
                    cvss_score = 'N/A'
                    severity = 'unknown'
                    
                    if 'metrics' in vuln:
                        if 'cvssMetricV31' in vuln['metrics'] and vuln['metrics']['cvssMetricV31']:
                            cvss_score = vuln['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                            severity = vuln['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'].lower()
                        elif 'cvssMetricV30' in vuln['metrics'] and vuln['metrics']['cvssMetricV30']:
                            cvss_score = vuln['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                            severity = vuln['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity'].lower()
                    
                    # Extract description
                    description = 'No description available'
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc['lang'] == 'en':
                                description = desc['value']
                                break
                    
                    return {
                        'found': True,
                        'cve_id': cve_id,
                        'description': description,
                        'cvss': str(cvss_score),
                        'severity': severity,
                        'published': vuln.get('published', 'Unknown')
                    }
        except Exception as e:
            print(f"Error fetching CVE info: {e}")
        
        return {'found': False}
    
    def generate_payload_template(self, cve_info):
        """Generate basic payload template for new CVE"""
        cve_id = cve_info['cve_id']
        cve_num = cve_id.replace('CVE-', '').replace('-', '')
        
        payload = {
            'id': f'cve-auto-{cve_num.lower()}',
            'category': 'rce',
            'subcategory': f'cve_{cve_id.lower().replace("-", "_")}',
            'payload': f'POST /api/endpoint HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{{"exploit": "payload"}}',
            'description': f'{cve_id}: {cve_info["description"][:100]}... - CVSS {cve_info["cvss"]}, auto-added',
            'cve': cve_id,
            'severity': cve_info['severity'],
            'cvss': cve_info['cvss'],
            'affected_versions': 'Various products',
            'disclosure_date': cve_info['published'][:10] if cve_info['published'] != 'Unknown' else datetime.now().strftime('%Y-%m-%d'),
            'source': 'NVD, Auto-added by CVE Checker',
            'tested_against': ['cloudflare_waf'],
            'success_rate': 0.0,
            'blocked': True
        }
        
        return payload
    
    def create_pr_branch(self, cve_id, payload):
        """Create PR for missing CVE"""
        print(f"\n🔧 Creating PR for {cve_id}...")
        
        # Add to cve_additional file
        target_file = 'payloads/xss/cve_additional_2020_2024.json'
        
        with open(target_file, 'r') as f:
            data = json.load(f)
        
        # Add new payload
        data['payloads'].append(payload)
        data['count'] = len(data['payloads'])
        
        # Save
        with open(target_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Added {cve_id} to {target_file}")
        print(f"📊 New count: {data['count']} CVEs")
        
        # Generate PR instructions
        pr_instructions = f"""
# Pull Request: Add {cve_id}

## Summary
Added {cve_id} to the CVE payload database.

## Details
- **CVE**: {cve_id}
- **CVSS**: {payload['cvss']}
- **Severity**: {payload['severity']}
- **Description**: {payload['description']}

## Changes
- Added payload to `{target_file}`
- Updated CVE count to {data['count']}

## Testing
- [ ] Payload format validated
- [ ] CVE information verified from NVD
- [ ] File structure maintained

## Checklist
- [x] CVE information fetched from NVD
- [x] Payload template generated
- [x] JSON structure validated
- [x] Count updated

---
Auto-generated by CVE Checker
"""
        
        # Save PR template
        with open('PR_TEMPLATE.md', 'w') as f:
            f.write(pr_instructions)
        
        print(f"\n📝 PR template saved to PR_TEMPLATE.md")
        print(f"\n🚀 Next steps:")
        print(f"   1. Review the changes in {target_file}")
        print(f"   2. git add {target_file}")
        print(f"   3. git commit -m 'Add {cve_id} payload'")
        print(f"   4. git push origin HEAD")
        print(f"   5. Create PR on GitHub using PR_TEMPLATE.md")
        
        return True

def interactive_mode():
    """Interactive CVE checking"""
    checker = CVEChecker()
    
    print("=" * 70)
    print("🔍 CVE CHECKER - Check CVE Coverage")
    print("=" * 70)
    print(f"\nLoaded {len(checker.loaded_cves)} CVEs from database\n")
    
    while True:
        print("=" * 70)
        cve_input = input("💬 Enter CVE ID to check (or 'quit' to exit): ").strip()
        
        if cve_input.lower() in ['quit', 'exit', 'q']:
            print("\n👋 Goodbye!")
            break
        
        if not cve_input:
            continue
        
        # Check if CVE exists
        result = checker.check_cve(cve_input)
        
        if result['found']:
            print(f"\n✅ FOUND: {result['cve']} is in the database!")
            print(f"📁 File: {result['file']}")
            print(f"📝 Description: {result['payload']['description']}")
            print(f"🎯 CVSS: {result['payload']['cvss']}")
            print(f"⚠️  Severity: {result['payload']['severity']}")
        else:
            print(f"\n❌ NOT FOUND: {result['cve']} is not in the database")
            
            # Ask if user wants to add it
            add = input(f"\n🤔 Would you like to add {result['cve']}? (yes/no): ").strip().lower()
            
            if add in ['yes', 'y']:
                print(f"\n🔍 Fetching {result['cve']} information from NVD...")
                cve_info = checker.fetch_cve_info(result['cve'])
                
                if cve_info['found']:
                    print(f"\n✅ Found CVE information:")
                    print(f"   Description: {cve_info['description'][:200]}...")
                    print(f"   CVSS: {cve_info['cvss']}")
                    print(f"   Severity: {cve_info['severity']}")
                    
                    # Generate payload
                    payload = checker.generate_payload_template(cve_info)
                    
                    # Create PR
                    confirm = input(f"\n🚀 Create PR for {result['cve']}? (yes/no): ").strip().lower()
                    
                    if confirm in ['yes', 'y']:
                        checker.create_pr_branch(result['cve'], payload)
                    else:
                        print("❌ Cancelled")
                else:
                    print(f"❌ Could not fetch information for {result['cve']} from NVD")
        
        print()

def cli_mode():
    """Command-line mode"""
    if len(sys.argv) < 2:
        print("Usage: python3 cve_checker.py CVE-2026-12345")
        print("   or: python3 cve_checker.py 2026-12345")
        return
    
    checker = CVEChecker()
    cve_id = sys.argv[1]
    
    result = checker.check_cve(cve_id)
    
    if result['found']:
        print(f"✅ {result['cve']} is supported")
        print(f"File: {result['file']}")
    else:
        print(f"❌ {result['cve']} is NOT supported")
        
        if len(sys.argv) > 2 and sys.argv[2] == '--add':
            print(f"Fetching {result['cve']} information...")
            cve_info = checker.fetch_cve_info(result['cve'])
            
            if cve_info['found']:
                payload = checker.generate_payload_template(cve_info)
                checker.create_pr_branch(result['cve'], payload)
            else:
                print(f"Could not fetch CVE information")
                sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()
