#!/usr/bin/env python3
"""
Add CVE Payloads Script
Automatically adds new CVE payloads to the database
"""

import json
import re
from datetime import datetime

def load_new_cves():
    """Load new CVEs from the monitor output"""
    try:
        with open('new_cves.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading new CVEs: {e}")
        return []

def generate_payload_template(cve_data):
    """Generate a payload template for the CVE"""
    cve_id = cve_data['cve']
    description = cve_data['description']
    cvss = cve_data['cvss']
    severity = cve_data['severity']
    vendor = cve_data.get('vendor', 'Unknown')
    product = cve_data.get('product', 'Unknown')
    
    # Generate a basic payload template
    # In production, this could be enhanced with AI or pattern matching
    payload = f"# {cve_id} exploitation attempt\n# Target: {vendor} {product}\n# CVSS: {cvss}"
    
    # Determine category based on description
    category = "rce"
    if "xss" in description.lower() or "cross-site" in description.lower():
        category = "xss"
    elif "sql" in description.lower() or "injection" in description.lower():
        category = "sqli"
    elif "command" in description.lower():
        category = "command_injection"
    elif "authentication" in description.lower() or "auth" in description.lower():
        category = "auth_bypass"
    
    # Create payload entry
    payload_entry = {
        "id": f"cve-auto-{cve_id.lower().replace('cve-', '')}",
        "category": category,
        "subcategory": f"cve_{vendor.lower().replace(' ', '_')}",
        "payload": payload,
        "description": f"{cve_id}: {description} - CVSS {cvss}, CISA KEV, auto-added",
        "cve": cve_id,
        "severity": severity,
        "cvss": cvss,
        "affected_versions": f"{vendor} {product}",
        "disclosure_date": cve_data.get('date', datetime.now().strftime('%Y-%m-%d')),
        "source": "CISA KEV, Auto-added by CVE Monitor Bot",
        "tested_against": ["cloudflare_waf"],
        "success_rate": 0.0,
        "blocked": True
    }
    
    return payload_entry

def add_cves_to_database(new_cves):
    """Add new CVEs to the payload database"""
    try:
        # Load existing database
        with open('payloads/xss/cve_2025_real_world.json', 'r') as f:
            data = json.load(f)
        
        # Add new payloads
        for cve in new_cves:
            payload_entry = generate_payload_template(cve)
            data['payloads'].append(payload_entry)
            print(f"✅ Added {cve['cve']}")
        
        # Update count
        data['count'] = len(data['payloads'])
        
        # Save updated database
        with open('payloads/xss/cve_2025_real_world.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"💾 Updated database with {len(new_cves)} new CVE(s)")
        print(f"📊 Total CVE count: {data['count']}")
        
        return data['count']
        
    except Exception as e:
        print(f"❌ Error adding CVEs to database: {e}")
        return None

def update_readme(new_count):
    """Update README with new CVE count"""
    try:
        with open('README.md', 'r') as f:
            content = f.read()
        
        # Update CVE badge
        content = re.sub(
            r'CVEs-\d+-red',
            f'CVEs-{new_count}-red',
            content
        )
        
        # Update CVE count in text
        content = re.sub(
            r'\*\*120 Critical CVE Payloads',
            f'**{new_count} Critical CVE Payloads',
            content
        )
        
        content = re.sub(
            r'120 critical CVEs',
            f'{new_count} critical CVEs',
            content
        )
        
        with open('README.md', 'w') as f:
            f.write(content)
        
        print(f"✅ Updated README.md with new count: {new_count}")
        
    except Exception as e:
        print(f"⚠️ Warning: Could not update README: {e}")

def main():
    print("🤖 CVE Payload Adder: Adding new CVEs to database...")
    
    # Load new CVEs
    new_cves = load_new_cves()
    
    if not new_cves:
        print("❌ No new CVEs to add")
        return
    
    print(f"📋 Processing {len(new_cves)} new CVE(s)...")
    
    # Add to database
    new_count = add_cves_to_database(new_cves)
    
    if new_count:
        # Update README
        update_readme(new_count)
        print("✅ CVE addition complete!")
    else:
        print("❌ Failed to add CVEs")

if __name__ == '__main__':
    main()
