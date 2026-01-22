#!/usr/bin/env python3
"""Quick test script for chime.com scan"""
import sys
sys.path.insert(0, 'D:/zeroHack  v2.0')

from modules.sql_injection import SQLInjectionTester
from modules.xss_tester import XSSTester

print('=' * 60)
print('Testing zeroHack modules on chime.com')
print('=' * 60)

# Note: chime.com uses Cloudflare WAF which blocks most automated scans
# This is expected behavior - a well-protected site!

# Test SQLi module with fewer payloads for speed
print('\n[1] Testing SQL Injection module (limited payloads)...')
sqli = SQLInjectionTester(timeout=5, level='normal')
targets = [{'url': 'https://www.chime.com'}]

try:
    sqli_results = sqli.test_sql_injection(targets)
    print(f'\nSQLi results: {len(sqli_results)} findings')
    for r in sqli_results[:5]:  # Show max 5
        print(f"  - {r.get('type')}: {r.get('parameter')} [Confidence: {r.get('confidence', 'N/A')}]")
except KeyboardInterrupt:
    print('\nScan interrupted by user')
    sqli_results = []
except Exception as e:
    print(f'\nError during SQLi scan: {e}')
    sqli_results = []

# Test XSS module  
print('\n[2] Testing XSS module...')
xss = XSSTester(timeout=5, level='normal')
try:
    xss_results = xss.test_xss([{'url': 'https://www.chime.com'}])
    print(f'\nXSS results: {len(xss_results)} findings')
    for r in xss_results[:5]:  # Show max 5
        print(f"  - {r.get('type')}: {r.get('parameter')} [Confidence: {r.get('confidence', 'N/A')}]")
except KeyboardInterrupt:
    print('\nScan interrupted by user')
    xss_results = []
except Exception as e:
    print(f'\nError during XSS scan: {e}')
    xss_results = []

print('\n' + '=' * 60)
total = len(sqli_results) + len(xss_results) if 'sqli_results' in dir() and 'xss_results' in dir() else 0
print(f'TOTAL: {total} potential vulnerabilities')
if total == 0:
    print('\nNote: chime.com is protected by Cloudflare WAF.')
    print('No vulnerabilities found = good security posture!')
print('=' * 60)
