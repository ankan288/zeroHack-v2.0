#!/usr/bin/env python3
"""
Enhanced Security Scanner Module
Finds real security issues that other scanners miss
"""

import requests
import ssl
import socket
import re
import json
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EnhancedSecurityScanner:
    """Comprehensive security scanner that finds real vulnerabilities"""
    
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.findings = []
        
        # User agents for testing
        self.user_agents = {
            'normal': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'bot': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        }
        
        # Required security headers
        self.security_headers = {
            'Strict-Transport-Security': {
                'severity': 'Medium',
                'description': 'Missing HSTS header - site vulnerable to SSL stripping attacks',
                'remediation': 'Add Strict-Transport-Security header with max-age of at least 31536000'
            },
            'X-Content-Type-Options': {
                'severity': 'Low',
                'description': 'Missing X-Content-Type-Options header - browser may MIME-sniff responses',
                'remediation': 'Add X-Content-Type-Options: nosniff header'
            },
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': 'Missing X-Frame-Options header - site may be vulnerable to clickjacking',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header'
            },
            'Content-Security-Policy': {
                'severity': 'Medium',
                'description': 'Missing Content-Security-Policy header - no protection against XSS and data injection',
                'remediation': 'Implement a strict Content-Security-Policy'
            },
            'X-XSS-Protection': {
                'severity': 'Low',
                'description': 'Missing X-XSS-Protection header (legacy browsers)',
                'remediation': 'Add X-XSS-Protection: 1; mode=block header'
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': 'Missing Referrer-Policy header - may leak sensitive URL data',
                'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'description': 'Missing Permissions-Policy header - browser features not restricted',
                'remediation': 'Add Permissions-Policy header to restrict browser features'
            }
        }
        
        # Sensitive paths to check
        self.sensitive_paths = [
            # Configuration files
            '/.env', '/config.php', '/wp-config.php', '/configuration.php',
            '/config.yml', '/config.json', '/settings.py', '/local_settings.py',
            
            # Backup files
            '/backup.sql', '/backup.zip', '/backup.tar.gz', '/db.sql',
            '/.git/config', '/.git/HEAD', '/.svn/entries', '/.hg/hgrc',
            
            # Admin panels
            '/admin', '/administrator', '/admin.php', '/wp-admin',
            '/phpmyadmin', '/adminer.php', '/manager/html',
            
            # API documentation
            '/swagger.json', '/swagger.yaml', '/api-docs', '/openapi.json',
            '/graphql', '/graphiql', '/__graphql',
            
            # Debug/Info files
            '/phpinfo.php', '/info.php', '/test.php', '/debug',
            '/.well-known/security.txt', '/robots.txt', '/sitemap.xml',
            
            # Source code exposure
            '/index.php~', '/index.php.bak', '/index.php.old',
            '/.DS_Store', '/Thumbs.db', '/web.config',
            
            # Cloud metadata (SSRF check)
            # These shouldn't be accessible from public internet
        ]
        
        # Information disclosure patterns
        self.info_disclosure_patterns = [
            (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?[\w@#$%^&*]+', 'Password in response'),
            (r'(?i)api[_-]?key\s*[:=]\s*["\']?[\w-]{20,}', 'API key exposed'),
            (r'(?i)secret[_-]?key\s*[:=]\s*["\']?[\w-]{20,}', 'Secret key exposed'),
            (r'(?i)access[_-]?token\s*[:=]\s*["\']?[\w-]{20,}', 'Access token exposed'),
            (r'(?i)aws[_-]?(?:access|secret)', 'AWS credentials reference'),
            (r'(?i)mongodb(?:\+srv)?://[^"\s]+', 'MongoDB connection string'),
            (r'(?i)mysql://[^"\s]+', 'MySQL connection string'),
            (r'(?i)postgres(?:ql)?://[^"\s]+', 'PostgreSQL connection string'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'(?i)private[_-]?key', 'Private key reference'),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', 'Private key exposed'),
            (r'(?i)bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT token exposed'),
        ]
        
        # Server version patterns (information disclosure)
        self.version_patterns = [
            (r'Apache/[\d.]+', 'Apache version disclosed'),
            (r'nginx/[\d.]+', 'Nginx version disclosed'),
            (r'PHP/[\d.]+', 'PHP version disclosed'),
            (r'Microsoft-IIS/[\d.]+', 'IIS version disclosed'),
            (r'X-Powered-By:\s*[\w\s/.]+', 'Technology stack disclosed'),
            (r'Server:\s*[\w\s/.]+', 'Server software disclosed'),
        ]
    
    def scan(self, target):
        """Run comprehensive security scan"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"ENHANCED SECURITY SCAN")
        print(f"Target: {target}")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if not target.startswith('http'):
            target = f"https://{target}"
        
        self.findings = []
        
        # 1. Security Headers Analysis
        print(f"{Fore.YELLOW}[1/7] Checking Security Headers...{Style.RESET_ALL}")
        self.check_security_headers(target)
        
        # 2. SSL/TLS Analysis
        print(f"{Fore.YELLOW}[2/7] Analyzing SSL/TLS Configuration...{Style.RESET_ALL}")
        self.check_ssl_tls(target)
        
        # 3. Sensitive File Exposure
        print(f"{Fore.YELLOW}[3/7] Checking for Sensitive Files...{Style.RESET_ALL}")
        self.check_sensitive_files(target)
        
        # 4. Information Disclosure
        print(f"{Fore.YELLOW}[4/7] Checking for Information Disclosure...{Style.RESET_ALL}")
        self.check_information_disclosure(target)
        
        # 5. CORS Misconfiguration
        print(f"{Fore.YELLOW}[5/7] Testing CORS Configuration...{Style.RESET_ALL}")
        self.check_cors(target)
        
        # 6. Cookie Security
        print(f"{Fore.YELLOW}[6/7] Analyzing Cookie Security...{Style.RESET_ALL}")
        self.check_cookie_security(target)
        
        # 7. HTTP Methods
        print(f"{Fore.YELLOW}[7/7] Testing HTTP Methods...{Style.RESET_ALL}")
        self.check_http_methods(target)
        
        return self.findings
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            response = requests.get(
                url, 
                timeout=self.timeout, 
                verify=False,
                headers={'User-Agent': self.user_agents['normal']}
            )
            
            headers = response.headers
            
            for header, info in self.security_headers.items():
                if header not in headers:
                    finding = {
                        'type': 'Missing Security Header',
                        'severity': info['severity'],
                        'confidence': 'High',
                        'header': header,
                        'url': url,
                        'description': info['description'],
                        'remediation': info['remediation']
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.RED}[!] Missing: {header}{Style.RESET_ALL}")
                else:
                    # Check for weak configurations
                    value = headers[header]
                    if header == 'Strict-Transport-Security':
                        if 'max-age=' in value.lower():
                            max_age = re.search(r'max-age=(\d+)', value.lower())
                            if max_age and int(max_age.group(1)) < 31536000:
                                finding = {
                                    'type': 'Weak Security Header',
                                    'severity': 'Low',
                                    'confidence': 'High',
                                    'header': header,
                                    'value': value,
                                    'url': url,
                                    'description': 'HSTS max-age is less than 1 year',
                                    'remediation': 'Set max-age to at least 31536000 (1 year)'
                                }
                                self.findings.append(finding)
                                print(f"  {Fore.YELLOW}[!] Weak HSTS: {value}{Style.RESET_ALL}")
                    
                    elif header == 'Content-Security-Policy':
                        if 'unsafe-inline' in value.lower() or 'unsafe-eval' in value.lower():
                            finding = {
                                'type': 'Weak Security Header',
                                'severity': 'Medium',
                                'confidence': 'High',
                                'header': header,
                                'value': value[:100] + '...' if len(value) > 100 else value,
                                'url': url,
                                'description': 'CSP contains unsafe-inline or unsafe-eval',
                                'remediation': 'Remove unsafe-inline and unsafe-eval from CSP'
                            }
                            self.findings.append(finding)
                            print(f"  {Fore.YELLOW}[!] Weak CSP detected{Style.RESET_ALL}")
            
            # Check for information disclosure in headers
            if 'Server' in headers:
                server = headers['Server']
                if re.search(r'[\d.]+', server):
                    finding = {
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'confidence': 'High',
                        'header': 'Server',
                        'value': server,
                        'url': url,
                        'description': f'Server version disclosed: {server}',
                        'remediation': 'Remove or obfuscate server version information'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.YELLOW}[!] Server version: {server}{Style.RESET_ALL}")
            
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                finding = {
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'confidence': 'High',
                    'header': 'X-Powered-By',
                    'value': powered_by,
                    'url': url,
                    'description': f'Technology disclosed: {powered_by}',
                    'remediation': 'Remove X-Powered-By header'
                }
                self.findings.append(finding)
                print(f"  {Fore.YELLOW}[!] X-Powered-By: {powered_by}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"  {Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    
    def check_ssl_tls(self, url):
        """Check SSL/TLS configuration"""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        finding = {
                            'type': 'Weak TLS Version',
                            'severity': 'High',
                            'confidence': 'High',
                            'url': url,
                            'tls_version': version,
                            'description': f'Outdated TLS version in use: {version}',
                            'remediation': 'Upgrade to TLS 1.2 or 1.3'
                        }
                        self.findings.append(finding)
                        print(f"  {Fore.RED}[!] Weak TLS: {version}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}[+] TLS Version: {version}{Style.RESET_ALL}")
                    
                    # Check cipher strength
                    cipher_name, cipher_version, cipher_bits = cipher
                    if cipher_bits < 128:
                        finding = {
                            'type': 'Weak Cipher',
                            'severity': 'High',
                            'confidence': 'High',
                            'url': url,
                            'cipher': cipher_name,
                            'bits': cipher_bits,
                            'description': f'Weak cipher in use: {cipher_name} ({cipher_bits} bits)',
                            'remediation': 'Use ciphers with at least 128-bit encryption'
                        }
                        self.findings.append(finding)
                        print(f"  {Fore.RED}[!] Weak cipher: {cipher_name}{Style.RESET_ALL}")
                    
                    # Check certificate expiry
                    import datetime
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.datetime.now()).days
                        
                        if days_left < 0:
                            finding = {
                                'type': 'Expired Certificate',
                                'severity': 'Critical',
                                'confidence': 'High',
                                'url': url,
                                'expiry_date': not_after,
                                'description': 'SSL certificate has expired',
                                'remediation': 'Renew the SSL certificate immediately'
                            }
                            self.findings.append(finding)
                            print(f"  {Fore.RED}[!] EXPIRED CERTIFICATE{Style.RESET_ALL}")
                        elif days_left < 30:
                            finding = {
                                'type': 'Certificate Expiring Soon',
                                'severity': 'Medium',
                                'confidence': 'High',
                                'url': url,
                                'expiry_date': not_after,
                                'days_left': days_left,
                                'description': f'SSL certificate expires in {days_left} days',
                                'remediation': 'Renew the SSL certificate before expiry'
                            }
                            self.findings.append(finding)
                            print(f"  {Fore.YELLOW}[!] Cert expires in {days_left} days{Style.RESET_ALL}")
                        else:
                            print(f"  {Fore.GREEN}[+] Certificate valid for {days_left} days{Style.RESET_ALL}")
                            
        except ssl.SSLError as e:
            finding = {
                'type': 'SSL Error',
                'severity': 'High',
                'confidence': 'High',
                'url': url,
                'error': str(e),
                'description': f'SSL/TLS error: {e}',
                'remediation': 'Fix SSL/TLS configuration'
            }
            self.findings.append(finding)
            print(f"  {Fore.RED}[!] SSL Error: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Could not check SSL: {e}{Style.RESET_ALL}")
    
    def check_sensitive_files(self, url):
        """Check for exposed sensitive files"""
        found_count = 0
        
        def check_path(path):
            nonlocal found_count
            try:
                full_url = urljoin(url, path)
                response = requests.get(
                    full_url,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': self.user_agents['normal']},
                    allow_redirects=False
                )
                
                # Check for successful response
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    content_length = len(response.content)
                    
                    # Filter out generic error pages
                    if content_length > 0 and content_length < 1000000:
                        # Check if it's not a redirect or error page
                        if 'text/html' not in content_type or path.endswith(('.json', '.yml', '.yaml', '.xml', '.sql', '.env')):
                            finding = {
                                'type': 'Sensitive File Exposed',
                                'severity': 'High' if any(x in path for x in ['.env', '.git', 'config', 'backup', '.sql']) else 'Medium',
                                'confidence': 'High',
                                'url': full_url,
                                'path': path,
                                'status_code': response.status_code,
                                'content_length': content_length,
                                'description': f'Sensitive file accessible: {path}',
                                'remediation': 'Remove or restrict access to this file'
                            }
                            self.findings.append(finding)
                            found_count += 1
                            print(f"  {Fore.RED}[!] Found: {path} ({content_length} bytes){Style.RESET_ALL}")
                            return True
                        
                        # Check for specific file signatures
                        content = response.text[:500].lower()
                        if any(sig in content for sig in ['<?php', 'password', 'secret', 'apikey', 'database']):
                            finding = {
                                'type': 'Sensitive File Exposed',
                                'severity': 'High',
                                'confidence': 'Medium',
                                'url': full_url,
                                'path': path,
                                'description': f'Potentially sensitive content in: {path}',
                                'remediation': 'Review and remove sensitive files from public access'
                            }
                            self.findings.append(finding)
                            found_count += 1
                            print(f"  {Fore.RED}[!] Sensitive content: {path}{Style.RESET_ALL}")
                            return True
                            
            except:
                pass
            return False
        
        # Check paths in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_path, self.sensitive_paths[:30])  # Limit for speed
        
        if found_count == 0:
            print(f"  {Fore.GREEN}[+] No sensitive files found{Style.RESET_ALL}")
    
    def check_information_disclosure(self, url):
        """Check for information disclosure in responses"""
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': self.user_agents['normal']}
            )
            
            content = response.text
            
            # Check for sensitive patterns
            for pattern, description in self.info_disclosure_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    finding = {
                        'type': 'Information Disclosure',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'url': url,
                        'pattern': description,
                        'matches': len(matches),
                        'description': f'{description} found in response',
                        'remediation': 'Remove sensitive information from public responses'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.RED}[!] {description} ({len(matches)} matches){Style.RESET_ALL}")
            
            # Check for debug mode / stack traces
            debug_indicators = [
                'Traceback (most recent call last)',
                'Exception in thread',
                'Stack trace:',
                'at java.',
                'at org.',
                'DEBUG = True',
                'DJANGO_SETTINGS_MODULE',
                'laravel_session',
            ]
            
            for indicator in debug_indicators:
                if indicator.lower() in content.lower():
                    finding = {
                        'type': 'Debug Mode Enabled',
                        'severity': 'Medium',
                        'confidence': 'Medium',
                        'url': url,
                        'indicator': indicator,
                        'description': f'Debug mode indicator found: {indicator}',
                        'remediation': 'Disable debug mode in production'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.YELLOW}[!] Debug indicator: {indicator}{Style.RESET_ALL}")
                    break
                    
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Error: {e}{Style.RESET_ALL}")
    
    def check_cors(self, url):
        """Check for CORS misconfigurations"""
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            url.replace('https://', 'https://evil.'),
        ]
        
        for origin in test_origins:
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    headers={
                        'User-Agent': self.user_agents['normal'],
                        'Origin': origin
                    }
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*':
                    finding = {
                        'type': 'CORS Misconfiguration',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'url': url,
                        'acao': acao,
                        'description': 'CORS allows any origin (*)',
                        'remediation': 'Restrict CORS to specific trusted origins'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.YELLOW}[!] CORS: Allows any origin (*){Style.RESET_ALL}")
                    break
                    
                elif acao == origin and origin != url:
                    severity = 'High' if acac.lower() == 'true' else 'Medium'
                    finding = {
                        'type': 'CORS Misconfiguration',
                        'severity': severity,
                        'confidence': 'High',
                        'url': url,
                        'acao': acao,
                        'acac': acac,
                        'test_origin': origin,
                        'description': f'CORS reflects arbitrary origin: {origin}',
                        'remediation': 'Validate Origin header against whitelist'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.RED}[!] CORS: Reflects origin {origin}{Style.RESET_ALL}")
                    break
                    
            except:
                pass
        else:
            print(f"  {Fore.GREEN}[+] CORS configuration appears secure{Style.RESET_ALL}")
    
    def check_cookie_security(self, url):
        """Check cookie security flags"""
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': self.user_agents['normal']}
            )
            
            cookies = response.cookies
            
            for cookie in cookies:
                issues = []
                
                if not cookie.secure and url.startswith('https'):
                    issues.append('Missing Secure flag')
                    
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    # Check the raw Set-Cookie header
                    set_cookie = response.headers.get('Set-Cookie', '')
                    if cookie.name in set_cookie and 'httponly' not in set_cookie.lower():
                        issues.append('Missing HttpOnly flag')
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    set_cookie = response.headers.get('Set-Cookie', '')
                    if cookie.name in set_cookie and 'samesite' not in set_cookie.lower():
                        issues.append('Missing SameSite flag')
                
                if issues:
                    finding = {
                        'type': 'Insecure Cookie',
                        'severity': 'Medium' if 'Secure' in str(issues) else 'Low',
                        'confidence': 'High',
                        'url': url,
                        'cookie_name': cookie.name,
                        'issues': issues,
                        'description': f"Cookie '{cookie.name}' missing: {', '.join(issues)}",
                        'remediation': 'Add Secure, HttpOnly, and SameSite flags to cookies'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.YELLOW}[!] Cookie '{cookie.name}': {', '.join(issues)}{Style.RESET_ALL}")
            
            if not cookies:
                print(f"  {Fore.GREEN}[+] No cookies to analyze{Style.RESET_ALL}")
            elif not any('Insecure Cookie' in f.get('type', '') for f in self.findings):
                print(f"  {Fore.GREEN}[+] Cookie security appears adequate{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Error: {e}{Style.RESET_ALL}")
    
    def check_http_methods(self, url):
        """Check for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        for method in dangerous_methods:
            try:
                response = requests.request(
                    method,
                    url,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': self.user_agents['normal']}
                )
                
                # Check if method is allowed (not 405 Method Not Allowed)
                if response.status_code not in [405, 501]:
                    finding = {
                        'type': 'Dangerous HTTP Method',
                        'severity': 'Medium' if method in ['PUT', 'DELETE'] else 'Low',
                        'confidence': 'Medium',
                        'url': url,
                        'method': method,
                        'status_code': response.status_code,
                        'description': f'HTTP {method} method may be enabled',
                        'remediation': f'Disable {method} method if not required'
                    }
                    self.findings.append(finding)
                    print(f"  {Fore.YELLOW}[!] {method} returned {response.status_code}{Style.RESET_ALL}")
                    
            except:
                pass
        
        # Check OPTIONS for allowed methods
        try:
            response = requests.options(url, timeout=5, verify=False)
            allow = response.headers.get('Allow', '')
            if allow:
                print(f"  {Fore.CYAN}[i] Allowed methods: {allow}{Style.RESET_ALL}")
        except:
            pass


def run_enhanced_scan(target):
    """Run enhanced security scan and save results"""
    import json
    from datetime import datetime
    
    scanner = EnhancedSecurityScanner(timeout=10, level='normal')
    findings = scanner.scan(target)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Count by severity
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for f in findings:
        sev = f.get('severity', 'Low')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    print(f"\nTotal Findings: {len(findings)}")
    print(f"  {Fore.RED}Critical: {severity_counts['Critical']}{Style.RESET_ALL}")
    print(f"  {Fore.RED}High: {severity_counts['High']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium: {severity_counts['Medium']}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Low: {severity_counts['Low']}{Style.RESET_ALL}")
    
    # Save results
    results = {
        'target': target,
        'scan_time': datetime.now().isoformat(),
        'total_findings': len(findings),
        'severity_summary': severity_counts,
        'findings': findings
    }
    
    filename = f"enhanced_scan_{target.replace('https://', '').replace('http://', '').replace('/', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to: {filename}")
    
    return results


if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'chime.com'
    run_enhanced_scan(target)
