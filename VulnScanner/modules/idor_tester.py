#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Testing Module
Tests for unauthorized access to objects and resources
"""

import requests
import re
import itertools
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import time
import json

class IDORTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Common ID patterns and formats
        self.id_patterns = {
            'numeric': [1, 2, 3, 10, 100, 999, 1000, 9999, 12345],
            'sequential': ['001', '002', '003', '010', '100'],
            'guid': ['00000000-0000-0000-0000-000000000000', 
                    '11111111-1111-1111-1111-111111111111',
                    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],
            'hash_like': ['admin', 'test', 'user', 'guest', '1234567890abcdef'],
            'encoded': ['YWRtaW4=', 'dGVzdA==', 'dXNlcg=='],  # base64: admin, test, user
        }
        
        # Extended patterns for moderate/extreme levels
        if level in ['moderate', 'extreme']:
            self.id_patterns.update({
                'numeric_extended': list(range(-10, 0)) + list(range(10000, 10100)),
                'common_usernames': ['admin', 'administrator', 'root', 'test', 'guest', 
                                   'user', 'demo', 'support', 'help', 'info'],
                'special_chars': ['../1', '../admin', '..\\1', '..\\admin', '%2e%2e%2f1'],
                'injection_attempts': ["1'", '1"', "1 OR 1=1", "1' OR '1'='1", "1; DROP TABLE users--"],
                'null_bytes': ['1%00', 'admin%00', '1\x00'],
            })
        
        # Common IDOR-prone parameters
        self.idor_params = [
            # User/Profile related
            'user_id', 'userid', 'uid', 'id', 'user', 'username', 'account_id',
            'profile_id', 'member_id', 'customer_id', 'client_id',
            
            # Document/File related  
            'file_id', 'fileid', 'document_id', 'doc_id', 'attachment_id',
            'media_id', 'image_id', 'video_id', 'photo_id',
            
            # Order/Transaction related
            'order_id', 'orderid', 'transaction_id', 'payment_id', 'invoice_id',
            'receipt_id', 'ticket_id', 'booking_id', 'reservation_id',
            
            # Content related
            'post_id', 'postid', 'article_id', 'news_id', 'page_id',
            'comment_id', 'message_id', 'thread_id', 'topic_id',
            
            # System related
            'session_id', 'token', 'key', 'ref', 'reference', 'guid',
            'hash', 'code', 'identifier', 'index', 'number',
        ]
        
        # Response indicators that suggest IDOR
        self.idor_indicators = {
            'unauthorized_access': [
                'unauthorized', 'forbidden', 'access denied', 'permission denied',
                'not authorized', 'login required', 'authentication required'
            ],
            'sensitive_data': [
                'password', 'ssn', 'social security', 'credit card', 'bank account',
                'phone number', 'address', 'email', 'private', 'confidential',
                'personal', 'internal', 'admin', 'root'
            ],
            'user_data': [
                'firstname', 'lastname', 'fullname', 'birthdate', 'age',
                'gender', 'salary', 'income', 'balance', 'account'
            ]
        }
    
    def extract_ids_from_response(self, text):
        """Extract potential IDs from response content"""
        ids = set()
        
        # Extract numeric IDs
        numeric_ids = re.findall(r'\b\d{1,10}\b', text)
        ids.update(numeric_ids[:20])  # Limit to first 20 found
        
        # Extract GUID-like patterns
        guids = re.findall(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', text, re.IGNORECASE)
        ids.update(guids[:10])
        
        # Extract hash-like patterns
        hashes = re.findall(r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b', text, re.IGNORECASE)
        ids.update(hashes[:10])
        
        return list(ids)
    
    def test_parameter_idor(self, url, param, original_value, method='GET'):
        """Test a specific parameter for IDOR"""
        results = []
        
        # Get baseline response with original value
        try:
            if method.upper() == 'GET':
                baseline_response = requests.get(url, params={param: original_value}, 
                                               timeout=self.timeout, verify=False)
            else:
                baseline_response = requests.post(url, data={param: original_value}, 
                                                timeout=self.timeout, verify=False)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
        except:
            return results
        
        # Generate test values
        test_values = []
        
        # Add pattern-based values
        for pattern_type, values in self.id_patterns.items():
            test_values.extend([str(v) for v in values])
        
        # Try to increment/decrement if original value is numeric
        try:
            if original_value.isdigit():
                num_val = int(original_value)
                test_values.extend([
                    str(num_val - 1), str(num_val + 1), 
                    str(num_val - 10), str(num_val + 10),
                    str(num_val * 2), str(num_val // 2) if num_val > 1 else '0'
                ])
        except:
            pass
        
        # Remove duplicates and original value
        test_values = list(set(test_values))
        if original_value in test_values:
            test_values.remove(original_value)
        
        for test_value in test_values[:50]:  # Limit tests for performance
            try:
                if method.upper() == 'GET':
                    test_response = requests.get(url, params={param: test_value}, 
                                               timeout=self.timeout, verify=False)
                else:
                    test_response = requests.post(url, data={param: test_value}, 
                                                timeout=self.timeout, verify=False)
                
                # Analyze response differences
                status_diff = test_response.status_code != baseline_status
                length_diff = abs(len(test_response.text) - baseline_length) > 100
                
                # Check for IDOR indicators
                idor_found = False
                evidence = []
                
                # Check if we got different content that might indicate access to other user's data
                if status_diff and test_response.status_code == 200 and baseline_status != 200:
                    idor_found = True
                    evidence.append(f"Status changed from {baseline_status} to 200 (unauthorized access)")
                
                if length_diff and test_response.status_code == 200:
                    # Check for sensitive data patterns
                    for category, indicators in self.idor_indicators.items():
                        for indicator in indicators:
                            if indicator.lower() in test_response.text.lower():
                                idor_found = True
                                evidence.append(f"Sensitive data found: {indicator} (category: {category})")
                                break
                        if idor_found:
                            break
                
                # Check for different user data
                if not idor_found and length_diff:
                    # Look for patterns that suggest different user data
                    user_patterns = [
                        r'"username":\s*"([^"]+)"', r'"email":\s*"([^"@]+@[^"]+)"',
                        r'"name":\s*"([^"]+)"', r'"id":\s*"?(\d+)"?',
                        r'<title>([^<]+)</title>', r'Welcome,?\s+([A-Za-z\s]+)'
                    ]
                    
                    for pattern in user_patterns:
                        baseline_matches = set(re.findall(pattern, baseline_response.text, re.IGNORECASE))
                        test_matches = set(re.findall(pattern, test_response.text, re.IGNORECASE))
                        
                        if test_matches and test_matches != baseline_matches:
                            idor_found = True
                            evidence.append(f"Different user data detected: {list(test_matches)[:3]}")
                            break
                
                if idor_found:
                    severity = 'High'
                    if any('admin' in e.lower() or 'root' in e.lower() for e in evidence):
                        severity = 'Critical'
                    elif any('unauthorized access' in e.lower() for e in evidence):
                        severity = 'Critical'
                    
                    vuln = {
                        'type': 'Insecure Direct Object Reference (IDOR)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'original_value': original_value,
                        'test_value': test_value,
                        'method': method,
                        'evidence': '; '.join(evidence),
                        'baseline_status': baseline_status,
                        'test_status': test_response.status_code,
                        'baseline_length': baseline_length,
                        'test_length': len(test_response.text)
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] IDOR found: {url} (param: {param}) - {original_value} -> {test_value}{Style.RESET_ALL}")
                
                time.sleep(0.1)  # Small delay
                
            except Exception:
                continue
        
        return results
    
    def discover_idor_endpoints(self, base_url):
        """Discover potential IDOR endpoints"""
        endpoints = []
        
        # Common IDOR-prone paths
        idor_paths = [
            '/profile', '/user', '/account', '/settings', '/dashboard',
            '/admin', '/panel', '/control', '/manage', '/edit',
            '/view', '/show', '/details', '/info', '/data',
            '/file', '/download', '/document', '/media', '/image',
            '/order', '/invoice', '/receipt', '/transaction', '/payment',
            '/message', '/mail', '/inbox', '/outbox', '/sent',
            '/report', '/log', '/history', '/activity', '/audit'
        ]
        
        for path in idor_paths:
            # Try different ID parameter formats
            test_endpoints = [
                f"{base_url}{path}?id=1",
                f"{base_url}{path}?user_id=1",
                f"{base_url}{path}/1",
                f"{base_url}{path}/user/1",
                f"{base_url}/api{path}/1",
                f"{base_url}/v1{path}/1"
            ]
            
            for endpoint in test_endpoints:
                try:
                    response = requests.get(endpoint, timeout=self.timeout, verify=False)
                    if response.status_code in [200, 301, 302, 403]:  # Interesting responses
                        endpoints.append(endpoint)
                except:
                    continue
        
        return endpoints
    
    def test_idor(self, targets):
        """Main IDOR testing function"""
        print(f"{Fore.YELLOW}[*] Starting IDOR testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing IDOR: {url}{Style.RESET_ALL}")
            
            # First, try to discover IDOR-prone endpoints
            if self.level in ['moderate', 'extreme']:
                endpoints = self.discover_idor_endpoints(url)
                print(f"{Fore.CYAN}[*] Discovered {len(endpoints)} potential IDOR endpoints{Style.RESET_ALL}")
            else:
                endpoints = [url]
            
            for endpoint in endpoints[:10]:  # Limit for performance
                # Extract any existing IDs from the URL
                url_ids = re.findall(r'[?&]([^=]+)=([^&]+)', endpoint)
                
                for param, value in url_ids:
                    if any(idor_param in param.lower() for idor_param in self.idor_params):
                        vulns = self.test_parameter_idor(endpoint, param, value, 'GET')
                        all_vulnerabilities.extend(vulns)
                
                # Test common IDOR parameters even if not in URL
                for param in self.idor_params[:15]:  # Test first 15 parameters
                    vulns = self.test_parameter_idor(endpoint, param, '1', 'GET')
                    all_vulnerabilities.extend(vulns)
                    
                    # Also test POST for some parameters
                    if param in ['user_id', 'id', 'file_id', 'order_id']:
                        vulns = self.test_parameter_idor(endpoint, param, '1', 'POST')
                        all_vulnerabilities.extend(vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities