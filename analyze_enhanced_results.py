#!/usr/bin/env python3
"""Analyze enhanced WAF detection results"""

import json
from collections import defaultdict

def analyze_results(filename):
    with open(filename, 'r') as f:
        results = json.load(f)
    
    total = len(results)
    detected = sum(1 for r in results if r['waf_detected'])
    
    vendor_counts = defaultdict(int)
    vendor_confidences = defaultdict(list)
    
    for result in results:
        if result['waf_detected']:
            vendor = result['waf_vendor']
            vendor_counts[vendor] += 1
            vendor_confidences[vendor].append(result['confidence'])
    
    print(f"\n{'='*70}")
    print(f"ENHANCED WAF DETECTION RESULTS - 100 DOMAINS")
    print(f"{'='*70}\n")
    
    print(f"Total Domains Tested: {total}")
    print(f"WAF Detected: {detected} ({detected/total*100:.1f}%)")
    print(f"No WAF: {total - detected} ({(total-detected)/total*100:.1f}%)\n")
    
    print(f"{'='*70}")
    print(f"VENDOR BREAKDOWN")
    print(f"{'='*70}\n")
    
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    
    for vendor, count in sorted_vendors:
        avg_conf = sum(vendor_confidences[vendor]) / len(vendor_confidences[vendor])
        market_share = count / detected * 100
        print(f"{vendor}:")
        print(f"  Detections: {count} ({market_share:.1f}% of detected)")
        print(f"  Avg Confidence: {avg_conf:.1f}%")
        print(f"  Confidences: {sorted(vendor_confidences[vendor], reverse=True)[:5]}")
        print()
    
    print(f"{'='*70}")
    print(f"CONFIDENCE DISTRIBUTION")
    print(f"{'='*70}\n")
    
    all_confidences = []
    for vendor in vendor_confidences:
        all_confidences.extend(vendor_confidences[vendor])
    
    if all_confidences:
        avg_conf = sum(all_confidences) / len(all_confidences)
        high_conf = sum(1 for c in all_confidences if c >= 70)
        med_conf = sum(1 for c in all_confidences if 40 <= c < 70)
        low_conf = sum(1 for c in all_confidences if c < 40)
        
        print(f"Average Confidence: {avg_conf:.1f}%")
        print(f"High Confidence (70%+): {high_conf} ({high_conf/len(all_confidences)*100:.1f}%)")
        print(f"Medium Confidence (40-69%): {med_conf} ({med_conf/len(all_confidences)*100:.1f}%)")
        print(f"Low Confidence (<40%): {low_conf} ({low_conf/len(all_confidences)*100:.1f}%)")
    
    print(f"\n{'='*70}\n")
    
    # Focus on AWS WAF and Azure WAF
    print(f"{'='*70}")
    print(f"AWS WAF & AZURE WAF ANALYSIS")
    print(f"{'='*70}\n")
    
    aws_results = [r for r in results if r['waf_detected'] and r['waf_vendor'] == 'AWS WAF']
    azure_results = [r for r in results if r['waf_detected'] and r['waf_vendor'] == 'Microsoft Azure WAF']
    
    print(f"AWS WAF:")
    print(f"  Detections: {len(aws_results)}")
    if aws_results:
        aws_avg = sum(r['confidence'] for r in aws_results) / len(aws_results)
        print(f"  Avg Confidence: {aws_avg:.1f}%")
        print(f"  Confidences: {sorted([r['confidence'] for r in aws_results], reverse=True)}")
    print()
    
    print(f"Microsoft Azure WAF:")
    print(f"  Detections: {len(azure_results)}")
    if azure_results:
        azure_avg = sum(r['confidence'] for r in azure_results) / len(azure_results)
        print(f"  Avg Confidence: {azure_avg:.1f}%")
        print(f"  Confidences: {sorted([r['confidence'] for r in azure_results], reverse=True)}")
    
    print(f"\n{'='*70}\n")

if __name__ == '__main__':
    analyze_results('test_results_enhanced_100.json')
