#!/usr/bin/env python3
"""
Quick Security Scan for chime.com
Runs a fast subset of tests with timeout handling
"""
import sys
import json
import time
from datetime import datetime

sys.path.insert(0, 'D:/zeroHack  v2.0')

from modules.sql_injection import SQLInjectionTester
from modules.xss_tester import XSSTester

def run_quick_scan(target):
    print("=" * 60)
    print(f"zeroHack v2.0 - Quick Security Scan")
    print(f"Target: {target}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    results = {
        'target': target,
        'scan_time': {'start': datetime.now().isoformat()},
        'vulnerabilities': [],
        'waf_detected': None
    }
    
    all_vulns = []
    
    # Prepare target
    if not target.startswith('http'):
        url = f"https://{target}"
    else:
        url = target
    
    targets = [{'url': url}]
    
    # 1. SQL Injection Testing
    print("\n[1/2] SQL Injection Testing...")
    print("-" * 40)
    
    try:
        sqli_tester = SQLInjectionTester(timeout=5, level='normal')
        
        # Check for WAF first
        waf = sqli_tester.detect_waf(url)
        if waf:
            print(f"[!] WAF Detected: {waf}")
            results['waf_detected'] = waf
        
        sqli_results = sqli_tester.test_sql_injection(targets)
        all_vulns.extend(sqli_results)
        
        print(f"[*] SQLi scan complete: {len(sqli_results)} findings")
        for v in sqli_results:
            conf = v.get('confidence', 'N/A')
            print(f"    - {v.get('type')}: {v.get('parameter')} [Confidence: {conf}]")
            
    except KeyboardInterrupt:
        print("[!] SQLi scan interrupted")
    except Exception as e:
        print(f"[!] SQLi error: {e}")
    
    # 2. XSS Testing
    print("\n[2/2] XSS Testing...")
    print("-" * 40)
    
    try:
        xss_tester = XSSTester(timeout=5, level='normal')
        xss_results = xss_tester.test_xss(targets)
        all_vulns.extend(xss_results)
        
        print(f"[*] XSS scan complete: {len(xss_results)} findings")
        for v in xss_results:
            conf = v.get('confidence', 'N/A')
            print(f"    - {v.get('type')}: {v.get('parameter')} [Confidence: {conf}]")
            
    except KeyboardInterrupt:
        print("[!] XSS scan interrupted")
    except Exception as e:
        print(f"[!] XSS error: {e}")
    
    # Summary
    results['vulnerabilities'] = all_vulns
    results['scan_time']['end'] = datetime.now().isoformat()
    
    # Count by severity
    summary = {'total': len(all_vulns), 'high': 0, 'medium': 0, 'low': 0}
    for v in all_vulns:
        sev = v.get('severity', 'medium').lower()
        if sev in summary:
            summary[sev] += 1
    
    results['summary'] = summary
    
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"WAF: {results['waf_detected'] or 'None detected'}")
    print(f"Total Vulnerabilities: {summary['total']}")
    print(f"  - High: {summary['high']}")
    print(f"  - Medium: {summary['medium']}")
    print(f"  - Low: {summary['low']}")
    
    if summary['total'] == 0:
        print("\n✅ No vulnerabilities detected!")
        if results['waf_detected']:
            print(f"   (Site is protected by {results['waf_detected']} WAF)")
    else:
        print("\n⚠️ Vulnerabilities found - review details above")
    
    print("=" * 60)
    
    # Save results
    with open('chime_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: chime_results.json")
    
    return results

if __name__ == '__main__':
    run_quick_scan('chime.com')
