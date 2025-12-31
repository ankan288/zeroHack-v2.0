#!/usr/bin/env python3
"""
Subdomain Enumeration Module
Discovers subdomains using multiple techniques
"""

import requests
import dns.resolver
import dns.exception
import threading
import time
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainEnum:
    def __init__(self, domain, threads=10, timeout=5, level='normal'):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.level = level
        self.subdomains = set()
        self.live_subdomains = set()
        
        # Common subdomain wordlist
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'mx1', 'mx2',
            'www1', 'www2', 'ns', 'test', 'm', 'blog', 'dev', 'www3', 'tmp', 'ns3',
            'cloud', 'secure', 'admin', 'demo', 'api', 'mobile', 'shop', 'cms', 'beta',
            'staging', 'support', 'help', 'cdn', 'img', 'images', 'static', 'assets',
            'files', 'upload', 'downloads', 'login', 'portal', 'app', 'apps', 'service',
            'git', 'vpn', 'ssh', 'remote', 'backup', 'old', 'new', 'dev2', 'test2',
            'preview', 'temp', 'mysql', 'db', 'database', 'phpmyadmin', 'pma',
            'webserver', 'server', 'ns4', 'ns5', 'mail2', 'email', 'direct', 'direct-connect',
            'cpanel', 'forum', 'forums', 'community', 'social', 'store', 'payment',
            'pay', 'checkout', 'cart', 'order', 'orders', 'client', 'clients', 'customer',
            'customers', 'account', 'accounts', 'user', 'users', 'member', 'members',
            'dashboard', 'panel', 'control', 'manage', 'management', 'config', 'configuration',
            'setup', 'install', 'installer', 'update', 'updates', 'patch', 'patches',
            'maintenance', 'status', 'monitor', 'monitoring', 'metrics', 'stats',
            'statistics', 'analytics', 'log', 'logs', 'error', 'errors', 'debug',
            'trace', 'tracking', 'search', 'find', 'lookup', 'directory', 'dir',
            'list', 'listing', 'catalog', 'catalogue', 'inventory', 'stock', 'product',
            'products', 'item', 'items', 'category', 'categories', 'tag', 'tags'
        ]
        
        # Extended wordlist for moderate/extreme levels
        if level in ['moderate', 'extreme']:
            self.wordlist.extend([
                'internal', 'intranet', 'extranet', 'citrix', 'owa', 'exchange', 'sharepoint',
                'lync', 'lyncdiscover', 'sip', 'teams', 'office', 'o365', 'office365',
                'azure', 'aws', 'cloud', 's3', 'ec2', 'rds', 'elb', 'cloudfront',
                'jenkins', 'bamboo', 'gitlab', 'github', 'bitbucket', 'svn', 'cvs',
                'jira', 'confluence', 'wiki', 'redmine', 'trac', 'bugzilla', 'mantis',
                'grafana', 'kibana', 'elasticsearch', 'logstash', 'splunk', 'nagios',
                'zabbix', 'cacti', 'munin', 'icinga', 'prometheus', 'influxdb',
                'docker', 'kubernetes', 'k8s', 'registry', 'harbor', 'nexus', 'artifactory',
                'sonar', 'sonarqube', 'fortify', 'checkmarx', 'veracode', 'snyk',
                'vault', 'consul', 'etcd', 'redis', 'memcached', 'mongo', 'mongodb',
                'cassandra', 'elasticsearch', 'solr', 'lucene', 'sphinx', 'whoosh'
            ])
    
    def dns_lookup(self, subdomain):
        """Perform DNS lookup for a subdomain"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Try A record
            try:
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    ips = [str(answer) for answer in answers]
                    self.subdomains.add(full_domain)
                    return full_domain, ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            
            # Try CNAME record
            try:
                answers = resolver.resolve(full_domain, 'CNAME')
                if answers:
                    cnames = [str(answer) for answer in answers]
                    self.subdomains.add(full_domain)
                    return full_domain, cnames
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
                
        except Exception:
            pass
        return None, None
    
    def check_http_status(self, subdomain):
        """Check if subdomain responds to HTTP/HTTPS"""
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.get(url, timeout=self.timeout, verify=False, 
                                      allow_redirects=True, headers={'User-Agent': 'VulnScanner/1.0'})
                if response.status_code:
                    self.live_subdomains.add(subdomain)
                    return {
                        'subdomain': subdomain,
                        'protocol': protocol,
                        'status_code': response.status_code,
                        'title': self.extract_title(response.text),
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_length': len(response.content)
                    }
            except Exception:
                continue
        return None
    
    def extract_title(self, html):
        """Extract title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()[:100]
        except:
            pass
        return "No Title"
    
    def certificate_transparency(self):
        """Search certificate transparency logs"""
        try:
            ct_subdomains = set()
            
            # crt.sh API
            try:
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for cert in data:
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if name.endswith(f'.{self.domain}') and '*' not in name:
                                    ct_subdomains.add(name)
            except Exception:
                pass
            
            return ct_subdomains
        except Exception:
            return set()
    
    def dns_bruteforce(self):
        """Perform DNS bruteforce attack"""
        print(f"{Fore.CYAN}[*] Starting DNS bruteforce with {len(self.wordlist)} subdomains...{Style.RESET_ALL}")
        
        found_subdomains = []
        
        def worker(subdomain):
            domain, ips = self.dns_lookup(subdomain)
            if domain:
                found_subdomains.append({'domain': domain, 'ips': ips, 'method': 'DNS'})
                print(f"{Fore.GREEN}[+] Found: {domain} -> {ips}{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(worker, self.wordlist)
        
        return found_subdomains
    
    def enumerate_subdomains(self):
        """Main subdomain enumeration function"""
        print(f"{Fore.YELLOW}[*] Starting subdomain enumeration for {self.domain}{Style.RESET_ALL}")
        
        all_results = {
            'target': self.domain,
            'subdomains': [],
            'live_subdomains': [],
            'methods_used': []
        }
        
        # 1. DNS Bruteforce
        print(f"{Fore.CYAN}[*] Method 1: DNS Bruteforce{Style.RESET_ALL}")
        dns_results = self.dns_bruteforce()
        all_results['subdomains'].extend(dns_results)
        all_results['methods_used'].append('DNS Bruteforce')
        
        # 2. Certificate Transparency
        if self.level in ['moderate', 'extreme']:
            print(f"{Fore.CYAN}[*] Method 2: Certificate Transparency Logs{Style.RESET_ALL}")
            ct_subdomains = self.certificate_transparency()
            for subdomain in ct_subdomains:
                if subdomain not in [r['domain'] for r in all_results['subdomains']]:
                    all_results['subdomains'].append({
                        'domain': subdomain, 
                        'ips': ['Unknown'], 
                        'method': 'Certificate Transparency'
                    })
                    print(f"{Fore.GREEN}[+] CT Found: {subdomain}{Style.RESET_ALL}")
            all_results['methods_used'].append('Certificate Transparency')
        
        # 3. Check live status
        print(f"{Fore.CYAN}[*] Checking live status of discovered subdomains...{Style.RESET_ALL}")
        
        def check_live(subdomain_data):
            domain = subdomain_data['domain']
            live_info = self.check_http_status(domain)
            if live_info:
                all_results['live_subdomains'].append(live_info)
                print(f"{Fore.GREEN}[+] Live: {domain} ({live_info['protocol']}) - {live_info['status_code']}{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_live, all_results['subdomains'])
        
        # Summary
        print(f"\n{Fore.YELLOW}Subdomain Enumeration Summary:{Style.RESET_ALL}")
        print(f"  Total subdomains found: {len(all_results['subdomains'])}")
        print(f"  Live subdomains: {len(all_results['live_subdomains'])}")
        print(f"  Methods used: {', '.join(all_results['methods_used'])}")
        
        return all_results