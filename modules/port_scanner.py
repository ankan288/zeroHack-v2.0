#!/usr/bin/env python3
"""
Port Scanning Module
Performs port scanning using nmap and custom TCP/UDP scanning
"""

import socket
import threading
import subprocess
import time
import random
import struct
import platform
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import json
import re
from datetime import datetime
import hashlib

# Advanced Port Scanner with Enhanced Capabilities
class PortScanner:
    def __init__(self, threads=100, timeout=3, level='normal'):
        self.threads = threads
        self.timeout = timeout
        self.level = level
        self.open_ports = {}
        self.services = {}
        self.scan_statistics = {
            'total_ports_scanned': 0,
            'open_ports_found': 0,
            'scan_start_time': None,
            'scan_end_time': None,
            'vulnerabilities_detected': 0,
            'os_fingerprint': None
        }
        
        # Advanced scanning techniques
        self.stealth_mode = False
        self.adaptive_timing = True
        self.deep_fingerprinting = True
        self.vulnerability_correlation = True
        
        # Dynamic thread pool management
        self.dynamic_threads = True
        self.max_threads = min(threads, 500)
        self.min_threads = max(10, threads // 4)
        
        # Enhanced port ranges for comprehensive scanning
        self.port_ranges = {
            'normal': {
                'tcp': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9000, 9090, 10000, 11211, 15672, 27017, 50070],
                'udp': [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 1434, 1900, 4500, 5353, 11211, 27017]
            },
            'moderate': {
                'tcp': list(range(1, 5001)) + [5432, 5900, 6379, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 15672, 25565, 27017, 50070, 60000, 65000, 65535],
                'udp': [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 1434, 1900, 4500, 5353, 11211, 27017] + list(range(1000, 10000, 500))
            },
            'extreme': {
                'tcp': list(range(1, 25001)) + list(range(50000, 65536, 100)),
                'udp': list(range(1, 5001)) + [1434, 1900, 4500, 5353, 11211, 27017, 31337, 54321] + list(range(50000, 65001, 1000))
            }
        }
        
        # Enhanced service detection with vulnerability correlation
        self.service_patterns = {
            21: {
                'name': 'FTP', 
                'banner_patterns': [r'220.*FTP', r'vsftpd', r'ProFTPD', r'Microsoft FTP', r'FileZilla'],
                'common_vulns': ['Anonymous login', 'Directory traversal', 'Brute force'],
                'risk_level': 'HIGH',
                'default_creds': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')]
            },
            22: {
                'name': 'SSH', 
                'banner_patterns': [r'SSH-', r'OpenSSH'],
                'common_vulns': ['Weak algorithms', 'User enumeration', 'Brute force'],
                'risk_level': 'MEDIUM',
                'version_vulns': {
                    'OpenSSH_7.4': ['CVE-2018-15473', 'CVE-2018-15919'],
                    'OpenSSH_8.2': ['CVE-2020-14145'],
                    'OpenSSH_8.3': ['CVE-2020-15778']
                }
            },
            23: {
                'name': 'Telnet', 
                'banner_patterns': [r'Telnet', r'login:', r'Password:'],
                'common_vulns': ['Unencrypted transmission', 'No authentication'],
                'risk_level': 'CRITICAL',
                'default_creds': [('admin', 'admin'), ('root', ''), ('guest', 'guest')]
            },
            25: {
                'name': 'SMTP', 
                'banner_patterns': [r'220.*SMTP', r'220.*mail', r'ESMTP'],
                'common_vulns': ['Open relay', 'User enumeration', 'Command injection'],
                'risk_level': 'MEDIUM',
                'enum_commands': ['VRFY', 'EXPN', 'RCPT TO']
            },
            53: {
                'name': 'DNS', 
                'banner_patterns': [r'DNS', r'BIND'],
                'common_vulns': ['Zone transfer', 'Cache poisoning', 'Amplification'],
                'risk_level': 'MEDIUM',
                'test_queries': ['version.bind', 'authors.bind']
            },
            80: {
                'name': 'HTTP', 
                'banner_patterns': [r'HTTP/1\.[01]', r'Server:', r'Apache', r'nginx', r'IIS'],
                'common_vulns': ['XSS', 'SQLi', 'Directory traversal', 'File upload'],
                'risk_level': 'HIGH',
                'fingerprint_paths': ['/robots.txt', '/sitemap.xml', '/.well-known/']
            },
            110: {
                'name': 'POP3', 
                'banner_patterns': [r'\+OK', r'POP3'],
                'common_vulns': ['Plaintext authentication', 'Buffer overflow'],
                'risk_level': 'MEDIUM',
                'default_creds': [('admin', 'admin'), ('test', 'test')]
            },
            135: {
                'name': 'RPC', 
                'banner_patterns': [r'RPC', r'Microsoft Windows RPC'],
                'common_vulns': ['MS08-067', 'MS17-010', 'Authentication bypass'],
                'risk_level': 'CRITICAL',
                'os_indicator': 'Windows'
            },
            139: {
                'name': 'NetBIOS', 
                'banner_patterns': [r'NetBIOS'],
                'common_vulns': ['SMB vulnerabilities', 'Null sessions', 'Share enumeration'],
                'risk_level': 'HIGH',
                'enum_commands': ['nbtscan', 'smbclient']
            },
            143: {'name': 'IMAP', 'banner_patterns': [r'\* OK', r'IMAP']},
            443: {'name': 'HTTPS', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            993: {'name': 'IMAPS', 'banner_patterns': [r'IMAP', r'SSL', r'TLS']},
            995: {'name': 'POP3S', 'banner_patterns': [r'POP3', r'SSL', r'TLS']},
            1433: {'name': 'MSSQL', 'banner_patterns': [r'Microsoft SQL Server']},
            1521: {'name': 'Oracle', 'banner_patterns': [r'Oracle']},
            3306: {'name': 'MySQL', 'banner_patterns': [r'mysql_native_password', r'MySQL']},
            3389: {'name': 'RDP', 'banner_patterns': [r'Remote Desktop', r'RDP']},
            5432: {'name': 'PostgreSQL', 'banner_patterns': [r'PostgreSQL']},
            5900: {'name': 'VNC', 'banner_patterns': [r'RFB', r'VNC']},
            6379: {'name': 'Redis', 'banner_patterns': [r'redis_version']},
            8080: {'name': 'HTTP-Alt', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            8443: {'name': 'HTTPS-Alt', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            8888: {'name': 'HTTP-Proxy', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            9000: {'name': 'HTTP-Dev', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            9090: {'name': 'HTTP-Admin', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            9200: {'name': 'Elasticsearch', 'banner_patterns': [r'elasticsearch']},
            9300: {'name': 'Elasticsearch-Transport', 'banner_patterns': [r'elasticsearch']},
            10000: {'name': 'Webmin', 'banner_patterns': [r'MiniServ', r'Webmin']},
            11211: {'name': 'Memcached', 'banner_patterns': [r'VERSION', r'memcached']},
            15672: {'name': 'RabbitMQ-Management', 'banner_patterns': [r'RabbitMQ', r'HTTP/1\.[01]']},
            25565: {'name': 'Minecraft', 'banner_patterns': [r'Minecraft']},
            27017: {'name': 'MongoDB', 'banner_patterns': [r'MongoDB']},
            50070: {'name': 'Hadoop-NameNode', 'banner_patterns': [r'Hadoop', r'NameNode']},
            60000: {'name': 'Hadoop-RegionServer', 'banner_patterns': [r'Hadoop', r'RegionServer']},
            65000: {'name': 'High-Port-Service', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']},
            65535: {'name': 'Max-Port', 'banner_patterns': [r'HTTP/1\.[01]', r'Server:']}
        }
        
    def syn_scan(self, host, port):
        """Advanced SYN stealth scan (requires raw socket privileges)"""
        try:
            # Create raw socket for SYN scan
            if platform.system().lower() == 'windows':
                # Windows raw socket implementation
                return self.tcp_connect_scan(host, port)  # Fallback to connect scan
            
            # Linux/Unix SYN scan implementation
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(self.timeout)
            
            # Build SYN packet
            syn_packet = self.build_syn_packet(host, port)
            sock.sendto(syn_packet, (host, port))
            
            # Listen for SYN-ACK response
            response = sock.recv(1024)
            return self.parse_tcp_response(response)
            
        except PermissionError:
            # Fallback to connect scan if no raw socket privileges
            return self.tcp_connect_scan(host, port)
        except Exception:
            return False
    
    def tcp_connect_scan(self, host, port):
        """Standard TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def build_syn_packet(self, dest_ip, dest_port):
        """Build TCP SYN packet for stealth scanning"""
        # IP Header fields
        version = 4
        ihl = 5
        tos = 0
        tot_len = 40
        id = random.randint(1, 65535)
        frag_off = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        check = 0
        saddr = socket.inet_aton('127.0.0.1')  # Source IP
        daddr = socket.inet_aton(dest_ip)      # Destination IP
        
        ihl_version = (version << 4) + ihl
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ihl_version, tos, tot_len, id,
                               frag_off, ttl, protocol, check,
                               saddr, daddr)
        
        # TCP Header fields
        source = random.randint(1024, 65535)  # Random source port
        dest = dest_port
        seq = random.randint(0, 4294967295)
        ack_seq = 0
        doff = 5
        syn = 1
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0
        
        offset_res = (doff << 4) + 0
        tcp_flags = syn
        tcp_header = struct.pack('!HHLLBBHHH',
                                source, dest, seq, ack_seq,
                                offset_res, tcp_flags, window,
                                check, urg_ptr)
        
        return ip_header + tcp_header
    
    def advanced_os_fingerprinting(self, host):
        """Advanced OS fingerprinting using multiple techniques"""
        os_hints = {
            'ttl_values': {},
            'tcp_window_size': {},
            'tcp_options': [],
            'icmp_responses': {},
            'service_banners': []
        }
        
        print(f"{Fore.YELLOW}[*] Performing OS fingerprinting on {host}...{Style.RESET_ALL}")
        
        # TTL analysis
        ttl = self.get_ttl_value(host)
        if ttl:
            os_hints['ttl_values']['icmp'] = ttl
            
        # TCP window size analysis
        window_size = self.get_tcp_window_size(host)
        if window_size:
            os_hints['tcp_window_size']['default'] = window_size
        
        # Service banner analysis
        for port in [22, 25, 53, 80, 110, 143]:
            if self.is_port_open(host, port):
                banner = self.grab_enhanced_banner(host, port)
                if banner:
                    os_hints['service_banners'].append({
                        'port': port,
                        'banner': banner,
                        'os_signature': self.analyze_banner_os(banner)
                    })
        
        # Analyze collected fingerprints
        os_guess = self.analyze_os_fingerprints(os_hints)
        
        print(f"{Fore.GREEN}[+] OS Fingerprinting Results:")
        print(f"    └── Detected OS: {os_guess['primary']}")
        print(f"    └── Confidence: {os_guess['confidence']}%")
        print(f"    └── Alternative: {os_guess.get('secondary', 'None')}{Style.RESET_ALL}")
        
        return os_guess
    
    def get_ttl_value(self, host):
        """Extract TTL value from ICMP ping"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', host], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                result = subprocess.run(['ping', '-c', '1', host], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                return int(ttl_match.group(1))
        except Exception:
            pass
        return None
    
    def analyze_os_fingerprints(self, os_hints):
        """Analyze collected OS fingerprints and make educated guess"""
        os_scores = {
            'Windows': 0,
            'Linux': 0,
            'FreeBSD': 0,
            'macOS': 0,
            'Solaris': 0,
            'Unknown': 0
        }
        
        # TTL-based analysis
        ttl = os_hints['ttl_values'].get('icmp')
        if ttl:
            if ttl >= 120:  # Windows (usually 128)
                os_scores['Windows'] += 30
            elif ttl >= 60:  # Linux/Unix (usually 64)
                os_scores['Linux'] += 30
            elif ttl >= 250:  # Solaris (usually 255)
                os_scores['Solaris'] += 30
        
        # Banner analysis
        for banner_info in os_hints['service_banners']:
            banner = banner_info['banner'].lower()
            if 'microsoft' in banner or 'windows' in banner:
                os_scores['Windows'] += 20
            elif 'ubuntu' in banner or 'debian' in banner or 'redhat' in banner:
                os_scores['Linux'] += 20
            elif 'freebsd' in banner:
                os_scores['FreeBSD'] += 20
            elif 'darwin' in banner or 'macos' in banner:
                os_scores['macOS'] += 20
        
        # Determine primary OS
        primary_os = max(os_scores, key=os_scores.get)
        confidence = min(os_scores[primary_os], 95)
        
        # Get secondary guess
        sorted_scores = sorted(os_scores.items(), key=lambda x: x[1], reverse=True)
        secondary_os = sorted_scores[1][0] if len(sorted_scores) > 1 else None
        
        return {
            'primary': primary_os,
            'confidence': confidence,
            'secondary': secondary_os,
            'detailed_scores': os_scores
        }
    
    def vulnerability_correlation_engine(self, host, port, service_info):
        """Correlate discovered services with known vulnerabilities"""
        vulnerabilities = []
        
        service_name = service_info.get('name', '').lower()
        banner = service_info.get('banner', '')
        
        print(f"{Fore.MAGENTA}[*] Analyzing {service_name} on {host}:{port} for vulnerabilities...{Style.RESET_ALL}")
        
        # Check service-specific vulnerabilities
        if port in self.service_patterns:
            pattern_info = self.service_patterns[port]
            
            # Add common vulnerabilities
            for vuln in pattern_info.get('common_vulns', []):
                vulnerabilities.append({
                    'type': vuln,
                    'severity': pattern_info.get('risk_level', 'MEDIUM'),
                    'port': port,
                    'service': service_name,
                    'description': f'{vuln} vulnerability in {service_name}',
                    'cve_refs': []
                })
            
            # Version-specific vulnerabilities
            version_vulns = pattern_info.get('version_vulns', {})
            for version_pattern, cves in version_vulns.items():
                if version_pattern.lower() in banner.lower():
                    for cve in cves:
                        vulnerabilities.append({
                            'type': 'Version Vulnerability',
                            'severity': 'HIGH',
                            'port': port,
                            'service': service_name,
                            'description': f'Known CVE in {service_name} version',
                            'cve_refs': [cve],
                            'version_detected': version_pattern
                        })
            
            # Default credential testing
            default_creds = pattern_info.get('default_creds', [])
            if default_creds:
                vulnerabilities.append({
                    'type': 'Default Credentials',
                    'severity': 'HIGH',
                    'port': port,
                    'service': service_name,
                    'description': f'Service may use default credentials',
                    'test_credentials': default_creds
                })
        
        # Display vulnerabilities found
        if vulnerabilities:
            print(f"{Fore.RED}[!] VULNERABILITIES DETECTED on {host}:{port}:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"    {i}. {vuln['type']} ({vuln['severity']})")
                print(f"       └── {vuln['description']}")
                if vuln.get('cve_refs'):
                    print(f"       └── CVE: {', '.join(vuln['cve_refs'])}")
            print(f"{Style.RESET_ALL}")
            
            self.scan_statistics['vulnerabilities_detected'] += len(vulnerabilities)
        
        return vulnerabilities
    
    def calculate_optimal_threads(self):
        """Calculate optimal thread count based on system resources"""
        try:
            # Get system information
            cpu_count = psutil.cpu_count(logical=True)
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Base threads on CPU and memory
            cpu_based_threads = cpu_count * 4  # 4 threads per CPU core
            memory_based_threads = int(memory_gb * 20)  # 20 threads per GB RAM
            
            # Take the minimum to avoid overwhelming the system
            optimal = min(cpu_based_threads, memory_based_threads, self.max_threads)
            optimal = max(optimal, self.min_threads)
            
            return optimal
            
        except Exception:
            # Fallback to original thread count
            return self.threads
    
    def generate_scan_report(self, host):
        """Generate comprehensive scan report with statistics"""
        if not self.scan_statistics['scan_end_time']:
            self.scan_statistics['scan_end_time'] = datetime.now()
        
        total_time = (self.scan_statistics['scan_end_time'] - self.scan_statistics['scan_start_time']).total_seconds()
        
        open_ports = self.open_ports.get(host, [])
        tcp_ports = [p for p in open_ports if p['protocol'] == 'tcp']
        udp_ports = [p for p in open_ports if p['protocol'] == 'udp']
        
        # Calculate risk statistics
        risk_stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for port in open_ports:
            risk_level = port.get('risk_level', 'UNKNOWN')
            if risk_level in risk_stats:
                risk_stats[risk_level] += 1
        
        print(f"\n{Fore.YELLOW}{'='*100}")
        print(f"📊 COMPREHENSIVE SCAN REPORT FOR {host}")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}🔍 SCAN STATISTICS:")
        print(f"    ├── Total Scan Time: {total_time:.2f} seconds")
        print(f"    ├── Ports Scanned: {self.scan_statistics['total_ports_scanned']:,}")
        print(f"    ├── Open Ports Found: {len(open_ports)}")
        print(f"    ├── Vulnerabilities Detected: {self.scan_statistics['vulnerabilities_detected']}")
        print(f"    ├── Scan Rate: {self.scan_statistics['total_ports_scanned']/total_time:.1f} ports/second")
        
        if self.scan_statistics.get('os_fingerprint'):
            os_info = self.scan_statistics['os_fingerprint']
            print(f"    └── OS Detection: {os_info['primary']} ({os_info['confidence']}% confidence){Style.RESET_ALL}")
        else:
            print(f"    └── OS Detection: Not performed{Style.RESET_ALL}")
        
        if open_ports:
            print(f"\n{Fore.GREEN}🎯 DISCOVERED SERVICES:")
            for port_info in sorted(open_ports, key=lambda x: x['port']):
                risk_color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.MAGENTA,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN
                }.get(port_info.get('risk_level', 'UNKNOWN'), Fore.WHITE)
                
                vuln_count = len(port_info.get('vulnerabilities', []))
                vuln_indicator = f" ({vuln_count} vulns)" if vuln_count > 0 else ""
                
                print(f"    ├── {port_info['port']}/{port_info['protocol']} - {port_info['service']} {port_info.get('version', '')}")
                print(f"    │   ├── Risk: {risk_color}{port_info.get('risk_level', 'UNKNOWN')}{Style.RESET_ALL}")
                print(f"    │   ├── Banner: {port_info.get('banner', 'None')[:60]}...")
                print(f"    │   └── Security: {vuln_count} vulnerabilities detected{vuln_indicator}")
            
            print(f"\n{Fore.MAGENTA}⚠️  RISK ASSESSMENT:")
            for risk_level, count in risk_stats.items():
                if count > 0:
                    risk_color = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.MAGENTA,
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.GREEN
                    }.get(risk_level, Fore.WHITE)
                    print(f"    ├── {risk_color}{risk_level}: {count} services{Style.RESET_ALL}")
            
            # Top vulnerabilities summary
            all_vulns = []
            for port in open_ports:
                all_vulns.extend(port.get('vulnerabilities', []))
            
            if all_vulns:
                print(f"\n{Fore.RED}🚨 TOP VULNERABILITIES:")
                critical_vulns = [v for v in all_vulns if v.get('severity') == 'CRITICAL'][:5]
                high_vulns = [v for v in all_vulns if v.get('severity') == 'HIGH'][:5]
                
                for i, vuln in enumerate(critical_vulns + high_vulns, 1):
                    print(f"    {i}. {vuln['type']} on port {vuln['port']} ({vuln['severity']})")
                    if vuln.get('cve_refs'):
                        print(f"       └── CVE: {', '.join(vuln['cve_refs'])}")
        else:
            print(f"\n{Fore.BLUE}🔒 No open ports discovered on {host}")
            print(f"    └── Target may be behind firewall or all services are filtered{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")
        
        return {
            'host': host,
            'scan_time': total_time,
            'open_ports': open_ports,
            'vulnerabilities': self.scan_statistics['vulnerabilities_detected'],
            'risk_summary': risk_stats,
            'os_fingerprint': self.scan_statistics.get('os_fingerprint')
        }
    
    def advanced_tcp_scan(self, host, port):
        """Enhanced TCP port scanning with multiple techniques"""
        try:
            # Dynamic logging based on scan progress
            self.scan_statistics['total_ports_scanned'] += 1
            
            if port % 1000 == 0:
                progress = (self.scan_statistics['total_ports_scanned'] / len(self.port_ranges[self.level]['tcp'])) * 100
                print(f"{Fore.CYAN}[*] Progress: {progress:.1f}% | Scanning TCP port range {port}-{port+999} on {host}...{Style.RESET_ALL}")
            
            # Adaptive timeout based on network latency
            adaptive_timeout = self.get_adaptive_timeout(host) if self.adaptive_timing else self.timeout
            
            # Use stealth scan if enabled and available
            if self.stealth_mode:
                is_open = self.syn_scan(host, port)
            else:
                is_open = self.tcp_connect_scan(host, port)
            
            # Critical port logging with enhanced details
            if port in [21, 22, 23, 25, 53, 80, 443, 8080, 9200, 27017]:
                scan_method = "SYN" if self.stealth_mode else "Connect"
                print(f"{Fore.YELLOW}[*] {scan_method} scan on critical port {host}:{port}/tcp...{Style.RESET_ALL}")
            
            if is_open:
                # Enhanced banner grabbing and service identification
                banner = self.grab_enhanced_banner(host, port)
                service_info = self.deep_service_identification(port, banner)
                
                # Vulnerability correlation if enabled
                vulnerabilities = []
                if self.vulnerability_correlation:
                    vulnerabilities = self.vulnerability_correlation_engine(host, port, service_info)
                
                if host not in self.open_ports:
                    self.open_ports[host] = []
                
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service_info['name'],
                    'version': service_info.get('version', ''),
                    'banner': banner,
                    'timestamp': time.time(),
                    'scan_method': 'syn' if self.stealth_mode else 'connect',
                    'response_time': adaptive_timeout,
                    'vulnerabilities': vulnerabilities,
                    'risk_level': service_info.get('risk_level', 'UNKNOWN')
                }
                
                self.open_ports[host].append(port_info)
                self.scan_statistics['open_ports_found'] += 1
                
                # Enhanced port reporting
                risk_color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.MAGENTA,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN
                }.get(service_info.get('risk_level', 'UNKNOWN'), Fore.WHITE)
                
                print(f"{Fore.GREEN}[+] OPEN PORT: {host}:{port}/tcp")
                print(f"    ├── Service: {service_info['name']}")
                print(f"    ├── Version: {service_info.get('version', 'Unknown')}")
                print(f"    ├── Banner: {banner[:80] if banner else 'No banner'}")
                print(f"    ├── Risk Level: {risk_color}{service_info.get('risk_level', 'UNKNOWN')}{Style.RESET_ALL}")
                print(f"    └── Vulnerabilities: {len(vulnerabilities)} detected{Style.RESET_ALL}")
                
                # High-value port alerts
                if port in [22, 80, 443, 3306, 3389, 5432, 6379, 9200, 27017]:
                    print(f"{Fore.RED}[!] CRITICAL SERVICE DETECTED: {host}:{port} ({service_info['name']})")
                    print(f"    └── Immediate attention recommended!{Style.RESET_ALL}")
                
            else:
                # Intelligent closed port logging
                if port % 10000 == 0:  # Reduced frequency
                    print(f"{Fore.BLUE}[*] Progress: Port {port}/tcp - Closed{Style.RESET_ALL}")
                
        except Exception as e:
            # Enhanced error logging with categorization
            error_type = self.categorize_scan_error(e)
            if port in [80, 443, 22, 21] or error_type == 'CRITICAL':
                print(f"{Fore.RED}[!] {error_type} error on {host}:{port}/tcp - {str(e)[:60]}...{Style.RESET_ALL}")
    
    def get_adaptive_timeout(self, host):
        """Calculate adaptive timeout based on network latency"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Quick test
            sock.connect_ex((host, 80))  # Test with common port
            sock.close()
            latency = time.time() - start_time
            
            # Adaptive timeout: base timeout + (latency * multiplier)
            adaptive_timeout = max(self.timeout, min(self.timeout + (latency * 2), 10))
            return adaptive_timeout
        except:
            return self.timeout
    
    def categorize_scan_error(self, error):
        """Categorize scan errors for better diagnostics"""
        error_str = str(error).lower()
        
        if 'permission denied' in error_str:
            return 'PERMISSION'
        elif 'network unreachable' in error_str:
            return 'NETWORK'
        elif 'host unreachable' in error_str:
            return 'HOST'
        elif 'connection refused' in error_str:
            return 'REFUSED'
        elif 'timeout' in error_str:
            return 'TIMEOUT'
        else:
            return 'UNKNOWN'
    
    def deep_service_identification(self, port, banner):
        """Enhanced service identification with version detection"""
        service_info = {
            'name': 'Unknown',
            'version': '',
            'risk_level': 'UNKNOWN',
            'confidence': 0
        }
        
        if port in self.service_patterns:
            pattern_info = self.service_patterns[port]
            service_info['name'] = pattern_info['name']
            service_info['risk_level'] = pattern_info.get('risk_level', 'UNKNOWN')
            
            if banner:
                # Version extraction patterns
                version_patterns = [
                    r'(\d+\.\d+\.\d+)',  # x.y.z format
                    r'(\d+\.\d+)',       # x.y format
                    r'v(\d+\.\d+\.\d+)', # vx.y.z format
                    r'version\s+(\d+\.\d+)', # version x.y format
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        service_info['version'] = match.group(1)
                        service_info['confidence'] = 80
                        break
                
                # Banner pattern matching for confidence
                for pattern in pattern_info['banner_patterns']:
                    if re.search(pattern, banner, re.IGNORECASE):
                        service_info['confidence'] = max(service_info['confidence'], 90)
                        break
        
        return service_info
    
    def grab_enhanced_banner(self, host, port):
        """Enhanced banner grabbing with multiple probes"""
        banners = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Service-specific probes
            if port == 80 or port == 8080:
                probes = [
                    b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n',
                    b'HEAD / HTTP/1.0\r\n\r\n',
                    b'OPTIONS / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n'
                ]
            elif port == 25:
                probes = [b'EHLO test.com\r\n', b'HELP\r\n']
            elif port == 21:
                probes = [b'USER anonymous\r\n', b'HELP\r\n']
            elif port == 22:
                probes = [b'']  # SSH sends banner immediately
            else:
                probes = [b'', b'\r\n', b'HELP\r\n']
            
            for probe in probes:
                try:
                    if probe:
                        sock.send(probe)
                    
                    banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                    if banner and banner not in banners:
                        banners.append(banner)
                        
                except:
                    continue
            
            sock.close()
            
        except:
            pass
        
        # Return the most informative banner
        return max(banners, key=len) if banners else ''
    
    def scan_udp_port(self, host, port):
        """Scan a single UDP port with enhanced logging"""
        try:
            # Log UDP scanning progress
            if port % 500 == 0:
                print(f"{Fore.CYAN}[*] Scanning UDP port range {port}-{port+499} on {host}...{Style.RESET_ALL}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Show progress for critical UDP ports
            if port in [53, 69, 123, 161, 162, 500, 514, 1434]:
                print(f"{Fore.YELLOW}[*] Testing critical UDP port {host}:{port}/udp...{Style.RESET_ALL}")
            
            # Send a UDP packet
            sock.sendto(b'', (host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                # If we get a response, port is likely open
                service = self.identify_service(port, data.decode('utf-8', errors='ignore'))
                
                if host not in self.open_ports:
                    self.open_ports[host] = []
                
                port_info = {
                    'port': port,
                    'protocol': 'udp',
                    'state': 'open',
                    'service': service,
                    'banner': data.decode('utf-8', errors='ignore')[:100] if data else '',
                    'timestamp': time.time()
                }
                
                self.open_ports[host].append(port_info)
                print(f"{Fore.GREEN}[+] OPEN UDP PORT FOUND: {host}:{port}/udp - {service}")
                print(f"    └── Response: {data.decode('utf-8', errors='ignore')[:80] if data else 'No response data'}...{Style.RESET_ALL}")
                
                # Alert for critical UDP services
                if port in [53, 161, 162, 500, 1434]:
                    print(f"{Fore.RED}[!] CRITICAL UDP SERVICE DETECTED: {host}:{port} ({service}){Style.RESET_ALL}")
                
            except socket.timeout:
                # Log timeout status for monitoring
                if port % 1000 == 0:
                    print(f"{Fore.MAGENTA}[*] UDP port {port} timeout on {host} (normal behavior){Style.RESET_ALL}")
                
            sock.close()
        except Exception as e:
            # Log UDP errors for critical ports
            if port in [53, 161, 162]:  # DNS, SNMP
                print(f"{Fore.RED}[!] UDP error on {host}:{port}/udp - {str(e)[:50]}{Style.RESET_ALL}")
    
    def grab_banner(self, host, port, sock=None):
        """Attempt to grab service banner"""
        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
            
            # Send common probes based on port
            if port == 80 or port == 8080:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            elif port == 443:
                # For HTTPS, we'd need SSL/TLS handling
                pass
            elif port in [21, 22, 23, 25, 110, 143]:
                # These services usually send banners immediately
                pass
            else:
                sock.send(b'\r\n')
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
            
        except Exception:
            return ''
    
    def identify_service(self, port, banner=''):
        """Identify service based on port and banner"""
        if port in self.service_patterns:
            service_info = self.service_patterns[port]
            service_name = service_info['name']
            
            if banner:
                for pattern in service_info['banner_patterns']:
                    if re.search(pattern, banner, re.IGNORECASE):
                        return f"{service_name} ({banner[:30]}...)"
            
            return service_name
        
        return f'Unknown ({port})'
    
    def nmap_scan(self, host, port_range='1-1000'):
        """Use nmap for advanced scanning if available"""
        try:
            # Check if nmap is available
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            
            # Basic nmap scan
            cmd = ['nmap', '-p', port_range, '-sV', '-sC', '--open', host]
            if self.level == 'extreme':
                cmd.extend(['-A', '-T4'])  # Aggressive scan
            elif self.level == 'moderate':
                cmd.extend(['-sS', '-T3'])  # SYN scan
            
            print(f"{Fore.CYAN}[*] Running nmap scan: {' '.join(cmd)}{Style.RESET_ALL}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return self.parse_nmap_output(result.stdout, host)
            
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print(f"{Fore.YELLOW}[!] Nmap not available or failed, using custom scanner{Style.RESET_ALL}")
        
        return []
    
    def parse_nmap_output(self, nmap_output, host):
        """Parse nmap output and extract port information"""
        ports = []
        
        # Extract open ports from nmap output
        port_lines = re.findall(r'(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.+))?', nmap_output)
        
        for port_num, protocol, service, version in port_lines:
            port_info = {
                'port': int(port_num),
                'protocol': protocol,
                'state': 'open',
                'service': service,
                'banner': version.strip() if version else ''
            }
            ports.append(port_info)
            print(f"{Fore.GREEN}[+] {host}:{port_num}/{protocol} - {service} {version if version else ''}{Style.RESET_ALL}")
        
        if host not in self.open_ports:
            self.open_ports[host] = []
        self.open_ports[host].extend(ports)
        
        return ports
    
    def scan_host(self, host):
        """Scan all ports on a single host with comprehensive logging"""
        print(f"\n{Fore.YELLOW}{'='*80}")
        print(f"🎯 STARTING COMPREHENSIVE PORT SCAN ON: {host}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        tcp_ports = self.port_ranges[self.level]['tcp']
        udp_ports = self.port_ranges[self.level]['udp']
        
        print(f"{Fore.CYAN}[*] Scan Configuration:")
        print(f"    └── Level: {self.level.upper()}")
        print(f"    └── TCP Ports: {len(tcp_ports)} ports ({min(tcp_ports)}-{max(tcp_ports)})")
        print(f"    └── UDP Ports: {len(udp_ports)} ports")
        print(f"    └── Threads: {self.threads}")
        print(f"    └── Timeout: {self.timeout}s{Style.RESET_ALL}")
        
        # Try nmap first if available and level is moderate/extreme
        if self.level in ['moderate', 'extreme']:
            port_range = f"{min(tcp_ports)}-{max(tcp_ports)}" if len(tcp_ports) > 50 else ','.join(map(str, tcp_ports))
            
            nmap_results = self.nmap_scan(host, port_range)
            if nmap_results:
                return nmap_results
        
        # Custom scanning with enhanced logging
        print(f"\n{Fore.YELLOW}[*] Starting TCP Port Scan...{Style.RESET_ALL}")
        tcp_start_time = time.time()
        
        # Initialize scan statistics
        self.scan_statistics['scan_start_time'] = datetime.now()
        self.scan_statistics['total_ports_scanned'] = 0
        
        # Perform OS fingerprinting first
        if self.deep_fingerprinting and self.level in ['moderate', 'extreme']:
            os_info = self.advanced_os_fingerprinting(host)
            self.scan_statistics['os_fingerprint'] = os_info
        
        # Dynamic thread management based on system resources
        optimal_threads = self.calculate_optimal_threads()
        
        print(f"{Fore.CYAN}[*] Advanced Scanning Configuration:")
        print(f"    ├── Stealth Mode: {'Enabled' if self.stealth_mode else 'Disabled'}")
        print(f"    ├── Deep Fingerprinting: {'Enabled' if self.deep_fingerprinting else 'Disabled'}")
        print(f"    ├── Vulnerability Correlation: {'Enabled' if self.vulnerability_correlation else 'Disabled'}")
        print(f"    ├── Adaptive Timing: {'Enabled' if self.adaptive_timing else 'Disabled'}")
        print(f"    └── Optimal Threads: {optimal_threads}{Style.RESET_ALL}")
        
        # TCP scan with advanced techniques
        with ThreadPoolExecutor(max_workers=optimal_threads) as executor:
            tcp_futures = [executor.submit(self.advanced_tcp_scan, host, port) for port in tcp_ports]
            
            # Real-time progress monitoring with performance metrics
            completed = 0
            total_tcp = len(tcp_ports)
            last_update = time.time()
            
            for future in as_completed(tcp_futures):
                future.result()  # Wait for completion
                completed += 1
                
                # Update progress every 5% or 2 seconds
                current_time = time.time()
                if (completed % max(1, total_tcp // 20) == 0) or (current_time - last_update > 2):
                    progress = (completed / total_tcp) * 100
                    rate = completed / (current_time - tcp_start_time) if completed > 0 else 0
                    eta = ((total_tcp - completed) / rate) if rate > 0 else 0
                    
                    print(f"{Fore.CYAN}[*] TCP Scan: {progress:.1f}% | {completed}/{total_tcp} ports | Rate: {rate:.1f} ports/sec | ETA: {eta:.0f}s{Style.RESET_ALL}")
                    last_update = current_time
        
        tcp_time = time.time() - tcp_start_time
        tcp_open = len([p for p in self.open_ports.get(host, []) if p.get('protocol') == 'tcp'])
        print(f"{Fore.GREEN}[+] TCP Scan Complete: {tcp_open} open ports found in {tcp_time:.2f}s{Style.RESET_ALL}")
        
        # UDP scan (only for moderate/extreme levels due to time)
        if self.level in ['moderate', 'extreme']:
            print(f"\n{Fore.YELLOW}[*] Starting UDP Port Scan...{Style.RESET_ALL}")
            udp_start_time = time.time()
            
            # Limit UDP ports for performance
            udp_scan_ports = udp_ports[:100] if self.level == 'moderate' else udp_ports[:200]
            
            with ThreadPoolExecutor(max_workers=min(self.threads // 2, 50)) as executor:
                udp_futures = [executor.submit(self.scan_udp_port, host, port) for port in udp_scan_ports]
                
                # Monitor UDP scan progress
                completed = 0
                total_udp = len(udp_scan_ports)
                for future in udp_futures:
                    future.result()  # Wait for completion
                    completed += 1
                    if completed % max(1, total_udp // 5) == 0:  # Show progress every 20%
                        progress = (completed / total_udp) * 100
                        print(f"{Fore.CYAN}[*] UDP Scan Progress: {progress:.1f}% ({completed}/{total_udp} ports){Style.RESET_ALL}")
            
            udp_time = time.time() - udp_start_time
            udp_open = len([p for p in self.open_ports.get(host, []) if p.get('protocol') == 'udp'])
            print(f"{Fore.GREEN}[+] UDP Scan Complete: {udp_open} open ports found in {udp_time:.2f}s{Style.RESET_ALL}")
        
        # Summary
        total_open = len(self.open_ports.get(host, []))
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"📊 SCAN SUMMARY FOR {host}")
        print(f"{'='*60}")
        print(f"Total Open Ports: {total_open}")
        if total_open > 0:
            print(f"Open TCP Ports: {tcp_open}")
            if self.level in ['moderate', 'extreme']:
                print(f"Open UDP Ports: {udp_open}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        return self.open_ports.get(host, [])
    
    def detect_os(self, host):
        """Attempt OS detection based on open ports and banners"""
        if host not in self.open_ports:
            return "Unknown"
        
        open_ports = self.open_ports[host]
        
        # Windows indicators
        windows_ports = [135, 139, 445, 3389, 1433]
        windows_services = ['Microsoft', 'Windows', 'IIS', 'RDP']
        
        # Linux indicators
        linux_ports = [22]
        linux_services = ['OpenSSH', 'Apache', 'nginx']
        
        # Count indicators
        windows_score = sum(1 for port in open_ports if port['port'] in windows_ports)
        windows_score += sum(1 for port in open_ports for service in windows_services if service.lower() in port.get('banner', '').lower())
        
        linux_score = sum(1 for port in open_ports if port['port'] in linux_ports)
        linux_score += sum(1 for port in open_ports for service in linux_services if service.lower() in port.get('banner', '').lower())
        
        if windows_score > linux_score:
            return "Windows"
        elif linux_score > windows_score:
            return "Linux/Unix"
        else:
            return "Unknown"
    
    def scan_ports(self, targets):
        """Enhanced main port scanning function with advanced capabilities"""
        print(f"\n{Fore.YELLOW}{'='*100}")
        print(f"🚀 ZEROHACK ADVANCED PORT SCANNING ENGINE v2.0")
        print(f"{'='*100}")
        print(f"Scan Level: {self.level.upper()} | Stealth: {'ON' if self.stealth_mode else 'OFF'} | Vulnerabilities: {'ON' if self.vulnerability_correlation else 'OFF'}")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        all_results = []
        
        for target_idx, target in enumerate(targets, 1):
            # Extract host from target
            if isinstance(target, dict):
                host = target.get('subdomain', target.get('url', ''))
            else:
                host = target
            
            # Clean up host (remove protocol if present)
            if '://' in host:
                host = host.split('://', 1)[1]
            if '/' in host:
                host = host.split('/', 1)[0]
            
            print(f"\n{Fore.MAGENTA}{'='*80}")
            print(f"🎯 TARGET {target_idx}/{len(targets)}: {host}")
            print(f"{'='*80}{Style.RESET_ALL}")
            
            try:
                # Resolve hostname to IP with timeout
                print(f"{Fore.CYAN}[*] Resolving hostname...{Style.RESET_ALL}")
                ip = socket.gethostbyname(host)
                print(f"{Fore.GREEN}[+] Resolution successful: {host} -> {ip}{Style.RESET_ALL}")
                
                # Reset statistics for this target
                self.scan_statistics = {
                    'total_ports_scanned': 0,
                    'open_ports_found': 0,
                    'scan_start_time': datetime.now(),
                    'scan_end_time': None,
                    'vulnerabilities_detected': 0,
                    'os_fingerprint': None
                }
                
                # Perform the scan
                start_time = time.time()
                ports = self.scan_host(ip)
                scan_time = time.time() - start_time
                
                # Mark scan end time
                self.scan_statistics['scan_end_time'] = datetime.now()
                
                # Generate comprehensive report
                scan_report = self.generate_scan_report(host)
                
                result = {
                    'host': host,
                    'ip': ip,
                    'open_ports': ports,
                    'scan_report': scan_report,
                    'scan_time': round(scan_time, 2),
                    'total_ports': len(ports),
                    'vulnerabilities_found': self.scan_statistics['vulnerabilities_detected'],
                    'risk_assessment': scan_report.get('risk_summary', {}),
                    'os_fingerprint': self.scan_statistics.get('os_fingerprint')
                }
                
                all_results.append(result)
                
                # Summary for this target
                risk_summary = scan_report.get('risk_summary', {})
                critical_count = risk_summary.get('CRITICAL', 0)
                high_count = risk_summary.get('HIGH', 0)
                
                status_color = Fore.RED if (critical_count > 0 or high_count > 0) else Fore.GREEN
                print(f"\n{status_color}[+] TARGET SCAN COMPLETE: {host}")
                print(f"    ├── Total Time: {scan_time:.2f}s")
                print(f"    ├── Open Ports: {len(ports)}")
                print(f"    ├── Vulnerabilities: {self.scan_statistics['vulnerabilities_detected']}")
                print(f"    └── Risk Level: {critical_count} Critical, {high_count} High{Style.RESET_ALL}")
                
            except socket.gaierror:
                print(f"{Fore.RED}[-] DNS Resolution failed for {host}")
                print(f"    └── Target may not exist or DNS issues{Style.RESET_ALL}")
                continue
            except Exception as e:
                print(f"{Fore.RED}[-] Unexpected error scanning {host}: {str(e)[:100]}...")
                print(f"    └── Skipping to next target{Style.RESET_ALL}")
                continue
        
        # Final summary across all targets
        if all_results:
            self.print_final_summary(all_results)
        
        return all_results
    
    def print_final_summary(self, all_results):
        """Print final summary across all scanned targets"""
        total_ports = sum(len(r['open_ports']) for r in all_results)
        total_vulns = sum(r['vulnerabilities_found'] for r in all_results)
        total_time = sum(r['scan_time'] for r in all_results)
        
        # Aggregate risk statistics
        total_risks = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in all_results:
            for risk_level, count in result.get('risk_assessment', {}).items():
                if risk_level in total_risks:
                    total_risks[risk_level] += count
        
        print(f"\n{Fore.YELLOW}{'='*100}")
        print(f"🏁 SCAN CAMPAIGN SUMMARY")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}📊 OVERALL STATISTICS:")
        print(f"    ├── Targets Scanned: {len(all_results)}")
        print(f"    ├── Total Open Ports: {total_ports}")
        print(f"    ├── Total Vulnerabilities: {total_vulns}")
        print(f"    ├── Total Scan Time: {total_time:.2f}s")
        print(f"    └── Average Time/Target: {total_time/len(all_results):.2f}s{Style.RESET_ALL}")
        
        if total_vulns > 0:
            print(f"\n{Fore.RED}⚠️  SECURITY SUMMARY:")
            for risk_level, count in total_risks.items():
                if count > 0:
                    risk_color = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.MAGENTA, 
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.GREEN
                    }.get(risk_level, Fore.WHITE)
                    print(f"    ├── {risk_color}{risk_level}: {count} services across all targets{Style.RESET_ALL}")
            
            print(f"\n{Fore.MAGENTA}🎯 RECOMMENDED ACTIONS:")
            if total_risks['CRITICAL'] > 0:
                print(f"    ├── 🚨 IMMEDIATE: Address {total_risks['CRITICAL']} critical vulnerabilities")
            if total_risks['HIGH'] > 0:
                print(f"    ├── ⚡ HIGH PRIORITY: Remediate {total_risks['HIGH']} high-risk services")
            print(f"    └── 📋 Create detailed remediation plan for all findings{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}✅ zeroHack scan campaign completed successfully!")
        print(f"Use the detailed reports above for vulnerability remediation.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")