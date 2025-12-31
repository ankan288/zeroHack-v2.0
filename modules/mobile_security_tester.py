#!/usr/bin/env python3
"""
Mobile Security Testing Module
Tests for mobile application vulnerabilities including:
- Android APK security issues
- iOS mobile app vulnerabilities
- Mobile API security flaws
- Deep linking vulnerabilities
- Certificate pinning bypass
- Mobile authentication flaws
- WebView security issues
"""

import requests
import re
import json
import base64
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib.parse

class MobileSecurityTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Mobile vulnerability patterns
        self.mobile_vulnerabilities = {
            # Android security issues
            'android': {
                'endpoints': [
                    '/android', '/apk', '/mobile', '/app', '/api/mobile',
                    '/api/android', '/download/apk', '/apps'
                ],
                'payloads': [
                    # Intent injection
                    'intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end',
                    'content://com.example.provider/data',
                    
                    # WebView exploitation
                    'javascript:alert(document.cookie)',
                    'file:///android_asset/www/index.html',
                    
                    # Deep link manipulation
                    'myapp://profile?user_id=../../../admin',
                    'custom-scheme://action?param=<script>alert(1)</script>',
                ]
            },
            
            # iOS security issues
            'ios': {
                'endpoints': [
                    '/ios', '/ipa', '/mobile', '/app', '/api/mobile',
                    '/api/ios', '/download/ipa', '/apps'
                ],
                'payloads': [
                    # URL scheme exploitation
                    'myapp://profile?user_id=admin',
                    'tel:+1234567890',
                    'sms:+1234567890',
                    
                    # Pasteboard exploitation
                    'UIPasteboard.general.string',
                    
                    # Keychain bypass
                    'kSecAttrAccessibleWhenUnlocked',
                ]
            },
            
            # Mobile API vulnerabilities
            'mobile_api': {
                'endpoints': [
                    '/api/mobile', '/mobile/api', '/app/api', '/api/app',
                    '/m/api', '/api/v1/mobile', '/api/v2/mobile'
                ],
                'payloads': [
                    # Device fingerprinting bypass
                    '{"device_id": "rooted_device", "jailbroken": true}',
                    '{"platform": "android", "root": true, "debug": true}',
                    
                    # Certificate pinning bypass
                    '{"ssl_pinning": false, "certificate_validation": false}',
                    
                    # Mobile-specific injection
                    '{"user_agent": "Mozilla/5.0 (Android)", "payload": "<script>"}',
                ]
            },
            
            # WebView vulnerabilities
            'webview': {
                'endpoints': [
                    '/webview', '/hybrid', '/cordova', '/phonegap',
                    '/ionic', '/react-native', '/flutter'
                ],
                'payloads': [
                    # JavaScript bridge exploitation
                    'window.Android.method("malicious_payload")',
                    'webkit.messageHandlers.handler.postMessage("exploit")',
                    
                    # File access
                    'file:///android_asset/',
                    'file:///system/etc/hosts',
                    
                    # XSS in WebView
                    '<iframe src="javascript:alert(document.domain)"></iframe>',
                ]
            }
        }
        
        # Mobile vulnerability indicators
        self.vulnerability_indicators = {
            'android_vulnerable': [
                'debug enabled', 'rooted device', 'backup allowed', 'exported component',
                'intent filter', 'android manifest', 'webview debugging', 'ssl pinning disabled'
            ],
            'ios_vulnerable': [
                'jailbreak detected', 'debug mode', 'keychain accessible', 'url scheme',
                'info plist', 'app transport security', 'certificate pinning disabled'
            ],
            'mobile_api_vulnerable': [
                'device bypass', 'root detection bypass', 'api key exposed', 'mobile token',
                'device fingerprint', 'certificate validation disabled', 'ssl verification off'
            ],
            'webview_vulnerable': [
                'javascript enabled', 'file access allowed', 'bridge exposed',
                'webview debugging', 'javascript bridge', 'cordova exposed', 'phonegap vulnerable'
            ]
        }
        
        # Mobile-specific headers for testing
        self.mobile_headers = {
            'android': {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
                'X-Requested-With': 'com.example.app',
                'X-Android-Package': 'com.example.app',
                'X-Device-ID': 'android_test_device'
            },
            'ios': {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'X-iOS-Bundle-Identifier': 'com.example.app',
                'X-Device-ID': 'ios_test_device'
            }
        }
    
    def test_android_vulnerabilities(self, url):
        """Test for Android security vulnerabilities"""
        results = []
        
        android_config = self.mobile_vulnerabilities['android']
        
        for endpoint in android_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in android_config['payloads']:
                try:
                    headers = self.mobile_headers['android'].copy()
                    
                    # Test different HTTP methods
                    methods = [requests.get, requests.post]
                    for method in methods:
                        if method == requests.post:
                            response = method(test_url, data={'payload': payload}, 
                                            headers=headers, timeout=self.timeout, verify=False)
                        else:
                            response = method(f"{test_url}?payload={urllib.parse.quote(payload)}", 
                                            headers=headers, timeout=self.timeout, verify=False)
                        
                        # Check for Android vulnerability indicators
                        for indicator in self.vulnerability_indicators['android_vulnerable']:
                            if indicator.lower() in response.text.lower():
                                vuln = {
                                    'type': 'Android Security Vulnerability',
                                    'severity': 'High' if 'debug' in indicator or 'root' in indicator else 'Medium',
                                    'url': test_url,
                                    'method': method.__name__.upper().replace('REQUESTS.', ''),
                                    'payload': payload,
                                    'evidence': f"Android vulnerability indicator: {indicator}",
                                    'attack_vector': 'Android app security misconfiguration',
                                    'impact': 'App compromise, data extraction, privilege escalation',
                                    'remediation': 'Secure Android app configuration, disable debugging in production',
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[!] Android vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                        
                        # Special check for intent scheme handling
                        if payload.startswith('intent://') and response.status_code == 200:
                            vuln = {
                                'type': 'Android Intent Injection',
                                'severity': 'High',
                                'url': test_url,
                                'method': method.__name__.upper().replace('REQUESTS.', ''),
                                'payload': payload,
                                'evidence': 'Application processes malicious intent URLs',
                                'attack_vector': 'Intent injection via URL schemes',
                                'impact': 'Arbitrary app launching, data theft',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] Android Intent injection: {test_url}{Style.RESET_ALL}")
                            
                except Exception:
                    continue
        
        return results
    
    def test_ios_vulnerabilities(self, url):
        """Test for iOS security vulnerabilities"""
        results = []
        
        ios_config = self.mobile_vulnerabilities['ios']
        
        for endpoint in ios_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in ios_config['payloads']:
                try:
                    headers = self.mobile_headers['ios'].copy()
                    
                    response = requests.get(f"{test_url}?payload={urllib.parse.quote(payload)}", 
                                          headers=headers, timeout=self.timeout, verify=False)
                    
                    # Check for iOS vulnerability indicators
                    for indicator in self.vulnerability_indicators['ios_vulnerable']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'iOS Security Vulnerability',
                                'severity': 'High' if 'jailbreak' in indicator or 'debug' in indicator else 'Medium',
                                'url': test_url,
                                'method': 'GET',
                                'payload': payload,
                                'evidence': f"iOS vulnerability indicator: {indicator}",
                                'attack_vector': 'iOS app security misconfiguration',
                                'impact': 'App compromise, keychain access, privacy bypass',
                                'remediation': 'Implement proper iOS security measures, jailbreak detection',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] iOS vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                    
                    # Check for URL scheme vulnerabilities
                    if payload.endswith('://') and 'scheme' in response.text.lower():
                        vuln = {
                            'type': 'iOS URL Scheme Vulnerability',
                            'severity': 'Medium',
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'evidence': 'Application exposes custom URL schemes',
                            'attack_vector': 'URL scheme manipulation',
                            'impact': 'Deep link manipulation, unauthorized actions',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.CYAN}[!] iOS URL scheme vulnerability: {test_url}{Style.RESET_ALL}")
                        
                except Exception:
                    continue
        
        return results
    
    def test_mobile_api_vulnerabilities(self, url):
        """Test for mobile API security vulnerabilities"""
        results = []
        
        mobile_api_config = self.mobile_vulnerabilities['mobile_api']
        
        for endpoint in mobile_api_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in mobile_api_config['payloads']:
                try:
                    # Test with both Android and iOS headers
                    for platform in ['android', 'ios']:
                        headers = self.mobile_headers[platform].copy()
                        headers['Content-Type'] = 'application/json'
                        
                        response = requests.post(test_url, data=payload, headers=headers,
                                               timeout=self.timeout, verify=False)
                        
                        # Check for mobile API vulnerability indicators
                        for indicator in self.vulnerability_indicators['mobile_api_vulnerable']:
                            if indicator.lower() in response.text.lower():
                                vuln = {
                                    'type': 'Mobile API Security Vulnerability',
                                    'severity': 'High',
                                    'url': test_url,
                                    'method': 'POST',
                                    'payload': payload,
                                    'evidence': f"Mobile API vulnerability: {indicator}",
                                    'attack_vector': 'Mobile API security bypass',
                                    'impact': 'Authentication bypass, device spoofing, API abuse',
                                    'remediation': 'Implement proper mobile API security, device attestation',
                                    'platform': platform,
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[!] Mobile API vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                        
                        # Check for certificate pinning bypass
                        if 'ssl_pinning' in payload and response.status_code == 200:
                            vuln = {
                                'type': 'Certificate Pinning Bypass',
                                'severity': 'High',
                                'url': test_url,
                                'method': 'POST',
                                'payload': payload,
                                'evidence': 'API accepts requests with disabled SSL pinning',
                                'attack_vector': 'SSL pinning bypass',
                                'impact': 'Man-in-the-middle attacks, traffic interception',
                                'platform': platform,
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] Certificate pinning bypass: {test_url}{Style.RESET_ALL}")
                            
                except Exception:
                    continue
        
        return results
    
    def test_webview_vulnerabilities(self, url):
        """Test for WebView security vulnerabilities"""
        results = []
        
        webview_config = self.mobile_vulnerabilities['webview']
        
        for endpoint in webview_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in webview_config['payloads']:
                try:
                    # Test with mobile user agents
                    for platform in ['android', 'ios']:
                        headers = self.mobile_headers[platform].copy()
                        
                        response = requests.get(f"{test_url}?content={urllib.parse.quote(payload)}", 
                                              headers=headers, timeout=self.timeout, verify=False)
                        
                        # Check for WebView vulnerability indicators
                        for indicator in self.vulnerability_indicators['webview_vulnerable']:
                            if indicator.lower() in response.text.lower():
                                vuln = {
                                    'type': 'WebView Security Vulnerability',
                                    'severity': 'High' if 'bridge' in indicator or 'javascript' in indicator else 'Medium',
                                    'url': test_url,
                                    'method': 'GET',
                                    'payload': payload,
                                    'evidence': f"WebView vulnerability: {indicator}",
                                    'attack_vector': 'WebView security misconfiguration',
                                    'impact': 'XSS in mobile app, file access, bridge exploitation',
                                    'remediation': 'Secure WebView configuration, disable unnecessary features',
                                    'platform': platform,
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[!] WebView vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                        
                        # Check for JavaScript bridge exposure
                        if 'window.' in payload and 'javascript' in response.text.lower():
                            vuln = {
                                'type': 'JavaScript Bridge Exposure',
                                'severity': 'Critical',
                                'url': test_url,
                                'method': 'GET',
                                'payload': payload,
                                'evidence': 'JavaScript bridge accessible in WebView',
                                'attack_vector': 'JavaScript bridge exploitation',
                                'impact': 'Native function calls, app compromise',
                                'platform': platform,
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] CRITICAL: JavaScript bridge exposed: {test_url}{Style.RESET_ALL}")
                            
                except Exception:
                    continue
        
        return results
    
    def test_deep_linking_vulnerabilities(self, url):
        """Test for deep linking security vulnerabilities"""
        results = []
        
        # Deep link test patterns
        deep_link_patterns = [
            'myapp://profile?user_id=../admin',
            'app://action?param=<script>alert(1)</script>',
            'scheme://host/path?redirect=javascript:alert(1)',
            'custom://open?url=file:///etc/passwd'
        ]
        
        deep_link_endpoints = ['/deeplink', '/link', '/open', '/redirect', '/navigate']
        
        for endpoint in deep_link_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for pattern in deep_link_patterns:
                try:
                    response = requests.get(f"{test_url}?link={urllib.parse.quote(pattern)}", 
                                          timeout=self.timeout, verify=False)
                    
                    # Check for successful deep link processing
                    if response.status_code == 200 and ('redirect' in response.text.lower() or 'open' in response.text.lower()):
                        vuln = {
                            'type': 'Deep Link Vulnerability',
                            'severity': 'Medium',
                            'url': test_url,
                            'method': 'GET',
                            'payload': pattern,
                            'evidence': 'Application processes untrusted deep links',
                            'attack_vector': 'Malicious deep link injection',
                            'impact': 'Unauthorized navigation, XSS, file access',
                            'remediation': 'Validate and sanitize deep link parameters',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.CYAN}[!] Deep link vulnerability: {test_url}{Style.RESET_ALL}")
                        
                except Exception:
                    continue
        
        return results
    
    def test_mobile_security_vulnerabilities(self, targets):
        """Main function to test mobile security vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Starting mobile security testing...{Style.RESET_ALL}")
        
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
            
            print(f"{Fore.CYAN}[*] Testing mobile security: {url}{Style.RESET_ALL}")
            
            # Test Android vulnerabilities
            android_vulns = self.test_android_vulnerabilities(url)
            all_vulnerabilities.extend(android_vulns)
            
            # Test iOS vulnerabilities
            ios_vulns = self.test_ios_vulnerabilities(url)
            all_vulnerabilities.extend(ios_vulns)
            
            # Test mobile API vulnerabilities
            mobile_api_vulns = self.test_mobile_api_vulnerabilities(url)
            all_vulnerabilities.extend(mobile_api_vulns)
            
            # Advanced tests for moderate/extreme levels
            if self.level in ['moderate', 'extreme']:
                # Test WebView vulnerabilities
                webview_vulns = self.test_webview_vulnerabilities(url)
                all_vulnerabilities.extend(webview_vulns)
                
                # Test deep linking vulnerabilities
                deep_link_vulns = self.test_deep_linking_vulnerabilities(url)
                all_vulnerabilities.extend(deep_link_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities