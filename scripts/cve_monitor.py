#!/usr/bin/env python3
"""
CVE Monitor Script
Monitors CISA KEV catalog for new critical CVEs and creates JSON file for auto-PR
"""

import json
import requests
from datetime import datetime, timedelta
import sys

# CISA KEV API endpoint
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Minimum CVSS score to consider (critical/high)
MIN_CVSS_SCORE = 8.0

# Days to look back for new CVEs
LOOKBACK_DAYS = 7

def load_existing_cves():
    """Load existing CVEs from our database"""
    try:
        with open('payloads/xss/cve_2025_real_world.json', 'r') as f:
            data = json.load(f)
            existing = set()
            for payload in data.get('payloads', []):
                if 'cve' in payload:
                    existing.add(payload['cve'])
            return existing
    except Exception as e:
        print(f"Error loading existing CVEs: {e}")
        return set()

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
        return None

def parse_cvss_score(cve_data):
    """Extract CVSS score from CVE data"""
    # Try to get CVSS from various fields
    if 'cvssScore' in cve_data:
        try:
            return float(cve_data['cvssScore'])
        except:
            pass
    
    # Default to high severity if we can't determine
    return 9.0

def filter_new_critical_cves(kev_data, existing_cves):
    """Filter for new critical CVEs not in our database"""
    if not kev_data or 'vulnerabilities' not in kev_data:
        return []
    
    new_cves = []
    cutoff_date = datetime.now() - timedelta(days=LOOKBACK_DAYS)
    
    for vuln in kev_data['vulnerabilities']:
        cve_id = vuln.get('cveID', '')
        
        # Skip if we already have this CVE
        if cve_id in existing_cves:
            continue
        
        # Check if it's recent
        date_added = vuln.get('dateAdded', '')
        try:
            vuln_date = datetime.strptime(date_added, '%Y-%m-%d')
            if vuln_date < cutoff_date:
                continue
        except:
            pass
        
        # Get CVSS score
        cvss_score = parse_cvss_score(vuln)
        
        # Only include critical/high severity
        if cvss_score < MIN_CVSS_SCORE:
            continue
        
        # Determine severity
        if cvss_score >= 9.0:
            severity = 'critical'
        elif cvss_score >= 7.0:
            severity = 'high'
        else:
            severity = 'medium'
        
        new_cves.append({
            'cve': cve_id,
            'description': vuln.get('vulnerabilityName', 'Unknown vulnerability'),
            'cvss': str(cvss_score),
            'severity': severity,
            'date': date_added,
            'vendor': vuln.get('vendorProject', 'Unknown'),
            'product': vuln.get('product', 'Unknown'),
            'required_action': vuln.get('requiredAction', ''),
            'due_date': vuln.get('dueDate', ''),
            'notes': vuln.get('notes', '')
        })
    
    return new_cves

def main():
    print("🔍 CVE Monitor: Checking for new critical CVEs...")
    
    # Load existing CVEs
    existing_cves = load_existing_cves()
    print(f"📊 Found {len(existing_cves)} existing CVEs in database")
    
    # Fetch CISA KEV
    print("🌐 Fetching CISA KEV catalog...")
    kev_data = fetch_cisa_kev()
    
    if not kev_data:
        print("❌ Failed to fetch CISA KEV data")
        sys.exit(1)
    
    # Filter for new critical CVEs
    new_cves = filter_new_critical_cves(kev_data, existing_cves)
    
    if not new_cves:
        print("✅ No new critical CVEs found")
        sys.exit(0)
    
    print(f"🚨 Found {len(new_cves)} new critical CVE(s)!")
    for cve in new_cves:
        print(f"  - {cve['cve']}: {cve['description']} (CVSS {cve['cvss']})")
    
    # Save new CVEs to file for the workflow
    with open('new_cves.json', 'w') as f:
        json.dump(new_cves, f, indent=2)
    
    print("💾 Saved new CVEs to new_cves.json")
    print("✅ CVE monitor complete")

if __name__ == '__main__':
    main()
