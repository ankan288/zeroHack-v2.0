#!/usr/bin/env python3
"""
zeroHack - Comprehensive Vulnerability Assessment Tool
Author: ZeroHack Team
Version: 2.0 - Ultimate SQL Injection Arsenal (320+ Payloads)

⚠️  ETHICAL USE ONLY ⚠️
This tool is designed for authorized security testing only.
Only use this on systems you own or have explicit permission to test.
Unauthorized scanning may be illegal and unethical.

Features:
- Subdomain enumeration & port scanning
- Web application vulnerabilities (SQL Injection, XSS, SSRF, RCE, IDOR)
- Smart contract security (signature bypass, NFT bridge, ERC777 reentrancy, LayerZero messaging, DeFi lending, perpetual bad debt, proxy vulnerabilities)
- API security testing (GraphQL, JWT, mass assignment, rate limiting)
- Cloud security testing (AWS, Azure, GCP, containers, serverless)
- Mobile security testing (Android, iOS, WebView, deep linking)
- IoT security testing (MQTT, CoAP, default credentials, industrial protocols)
- Multiple attack intensity levels (Normal/Moderate/Extreme)
"""

import sys
import os
import argparse
import json
from datetime import datetime
from colorama import init, Fore, Style
import threading
import time

# Initialize colorama for Windows color support
init()

# Import notification system
try:
    from modules.notification_system import initialize_notifications, notify_vulnerability, get_notification_manager
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False

class zeroHack:
    def __init__(self):
        self.banner = f"""
{Fore.CYAN}
███████╗███████╗██████╗  ██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝
  ███╔╝ █████╗  ██████╔╝██║   ██║███████║███████║██║     █████╔╝ 
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔══██║██╔══██║██║     ██╔═██╗ 
███████╗███████╗██║  ██║╚██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}           Comprehensive Vulnerability Assessment Tool v2.0{Style.RESET_ALL}
{Fore.RED}                         ⚠️  AUTHORIZED USE ONLY ⚠️{Style.RESET_ALL}
        """
        
        self.attack_levels = {
            'normal': {
                'threads': 10,
                'timeout': 5,
                'aggressive': False,
                'delay': 1,
                'description': 'Basic vulnerability testing with minimal impact'
            },
            'moderate': {
                'threads': 25,
                'timeout': 10,
                'aggressive': True,
                'delay': 0.5,
                'description': 'Comprehensive testing with moderate resource usage'
            },
            'extreme': {
                'threads': 50,
                'timeout': 15,
                'aggressive': True,
                'delay': 0.1,
                'description': 'Intensive testing with maximum detection capabilities'
            }
        }
        
        self.vulnerabilities_found = []
        self.start_time = None
        self.end_time = None
        self.notification_manager = None
    
    def run_comprehensive_scan(self, args):
        """Run the comprehensive vulnerability scan"""
        from modules.subdomain_enum import SubdomainEnum
        from modules.port_scanner import PortScanner  
        from modules.sql_injection import SQLInjectionTester
        from modules.xss_tester import XSSTester
        from modules.ssrf_tester import SSRFTester
        from modules.rce_tester import RCETester
        from modules.idor_tester import IDORTester
        from modules.web3_tester import Web3Tester
        from modules.additional_vulns import AdditionalVulnTester
        from modules.smart_contract_tester import SmartContractTester
        from modules.api_security_tester import APISecurityTester
        from modules.cloud_security_tester import CloudSecurityTester
        from modules.mobile_security_tester import MobileSecurityTester
        from modules.web_cache_tester import WebCacheTester
        from modules.iot_security_tester import IoTSecurityTester
        
        level_config = self.attack_levels[args.level]
        results = {
            'target': args.target,
            'level': args.level,
            'scan_time': {'start': self.start_time, 'end': None},
            'subdomains': [],
            'open_ports': [],
            'vulnerabilities': [],
            'summary': {'total_vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        targets = [{'url': f"http://{args.target}", 'subdomain': args.target}]  # Start with main target
        
        # 1. Subdomain Enumeration
        if not args.no_subdomain:
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f"PHASE 1: SUBDOMAIN ENUMERATION")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            subdomain_scanner = SubdomainEnum(
                domain=args.target,
                threads=level_config['threads'],
                timeout=level_config['timeout'],
                level=args.level
            )
            subdomain_results = subdomain_scanner.enumerate_subdomains()
            results['subdomains'] = subdomain_results
            
            # Update targets with discovered subdomains
            if subdomain_results['live_subdomains']:
                targets = [{'url': f"http://{sub['subdomain']}", 'subdomain': sub['subdomain']} 
                          for sub in subdomain_results['live_subdomains']]
            
        # 2. Port Scanning
        if not args.no_port_scan:
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f"PHASE 2: PORT SCANNING")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            port_scanner = PortScanner(
                threads=level_config['threads'],
                timeout=level_config['timeout'],
                level=args.level
            )
            port_results = port_scanner.scan_ports(targets)
            results['open_ports'] = port_results
        
        # 3. Vulnerability Testing
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"PHASE 3: VULNERABILITY ASSESSMENT")  
        print(f"{'='*60}{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # SQL Injection Testing
        print(f"\n{Fore.CYAN}--- SQL Injection Testing ---{Style.RESET_ALL}")
        sql_tester = SQLInjectionTester(timeout=level_config['timeout'], level=args.level)
        sql_vulns = sql_tester.test_sql_injection(targets)
        all_vulnerabilities.extend(sql_vulns)
        
        # XSS Testing
        print(f"\n{Fore.CYAN}--- XSS Testing ---{Style.RESET_ALL}")
        xss_tester = XSSTester(timeout=level_config['timeout'], level=args.level)
        xss_vulns = xss_tester.test_xss(targets)
        all_vulnerabilities.extend(xss_vulns)
        
        # SSRF Testing
        print(f"\n{Fore.CYAN}--- SSRF Testing ---{Style.RESET_ALL}")
        ssrf_tester = SSRFTester(timeout=level_config['timeout'], level=args.level)
        ssrf_vulns = ssrf_tester.test_ssrf(targets)
        all_vulnerabilities.extend(ssrf_vulns)
        
        # RCE Testing
        print(f"\n{Fore.CYAN}--- RCE Testing ---{Style.RESET_ALL}")
        rce_tester = RCETester(timeout=level_config['timeout'], level=args.level)
        rce_vulns = rce_tester.test_rce(targets)
        all_vulnerabilities.extend(rce_vulns)
        
        # IDOR Testing
        print(f"\n{Fore.CYAN}--- IDOR Testing ---{Style.RESET_ALL}")
        idor_tester = IDORTester(timeout=level_config['timeout'], level=args.level)
        idor_vulns = idor_tester.test_idor(targets)
        all_vulnerabilities.extend(idor_vulns)
        
        # Web3/Blockchain Testing
        print(f"\n{Fore.CYAN}--- Web3/Blockchain Testing ---{Style.RESET_ALL}")
        web3_tester = Web3Tester(timeout=level_config['timeout'], level=args.level)
        web3_vulns = web3_tester.test_web3(targets)
        all_vulnerabilities.extend(web3_vulns)
        
        # Advanced Smart Contract Security Testing
        print(f"\n{Fore.CYAN}--- Advanced Smart Contract Security Testing ---{Style.RESET_ALL}")
        sc_tester = SmartContractTester(timeout=level_config['timeout'], level=args.level)
        sc_vulns = sc_tester.test_smart_contract_vulnerabilities(targets)
        all_vulnerabilities.extend(sc_vulns)
        
        # Additional Vulnerability Tests
        print(f"\n{Fore.CYAN}--- Additional Vulnerability Tests ---{Style.RESET_ALL}")
        additional_tester = AdditionalVulnTester(timeout=level_config['timeout'], level=args.level)
        additional_vulns = additional_tester.test_additional_vulnerabilities(targets)
        all_vulnerabilities.extend(additional_vulns)
        
        # API Security Testing
        print(f"\n{Fore.CYAN}--- API Security Testing ---{Style.RESET_ALL}")
        api_tester = APISecurityTester(timeout=level_config['timeout'], level=args.level)
        api_vulns = api_tester.test_api_security_vulnerabilities(targets)
        all_vulnerabilities.extend(api_vulns)
        
        # Cloud Security Testing
        print(f"\n{Fore.CYAN}--- Cloud Security Testing ---{Style.RESET_ALL}")
        cloud_tester = CloudSecurityTester(timeout=level_config['timeout'], level=args.level)
        cloud_vulns = cloud_tester.test_cloud_security_vulnerabilities(targets)
        all_vulnerabilities.extend(cloud_vulns)
        
        # Web Cache Testing (Poisoning + Deception - PortSwigger Research)
        print(f"\n{Fore.CYAN}--- Web Cache Poisoning & Cache Deception Testing ---{Style.RESET_ALL}")
        if hasattr(args, 'cache_deception') and args.cache_deception:
            print(f"{Fore.YELLOW}[*] Cache Deception mode enabled (PortSwigger research patterns){Style.RESET_ALL}")
        cache_tester = WebCacheTester(timeout=level_config['timeout'], level=args.level)
        cache_vulns = cache_tester.test_web_cache_vulnerabilities(targets)
        all_vulnerabilities.extend(cache_vulns)
        
        # Mobile Security Testing
        print(f"\n{Fore.CYAN}--- Mobile Security Testing ---{Style.RESET_ALL}")
        mobile_tester = MobileSecurityTester(timeout=level_config['timeout'], level=args.level)
        mobile_vulns = mobile_tester.test_mobile_security_vulnerabilities(targets)
        all_vulnerabilities.extend(mobile_vulns)
        
        # IoT Security Testing
        print(f"\n{Fore.CYAN}--- IoT Security Testing ---{Style.RESET_ALL}")
        iot_tester = IoTSecurityTester(timeout=level_config['timeout'], level=args.level)
        iot_vulns = iot_tester.test_iot_security_vulnerabilities(targets)
        all_vulnerabilities.extend(iot_vulns)
        
        results['vulnerabilities'] = all_vulnerabilities
        self.vulnerabilities_found = all_vulnerabilities
        
        # Calculate summary statistics
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        results['summary'] = {
            'total_vulnerabilities': len(all_vulnerabilities),
            'critical': severity_counts['Critical'],
            'high': severity_counts['High'], 
            'medium': severity_counts['Medium'],
            'low': severity_counts['Low'],
            'targets_scanned': len(targets),
            'subdomains_found': len(results.get('subdomains', {}).get('subdomains', [])),
            'live_subdomains': len(results.get('subdomains', {}).get('live_subdomains', []))
        }
        
        return results
    
    def generate_report(self, results, output_file=None):
        """Generate comprehensive scan report"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"SCAN RESULTS SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        summary = results['summary']
        scan_duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        
        print(f"\n{Fore.GREEN}Target: {results['target']}")
        print(f"Scan Level: {results['level'].upper()}")
        print(f"Scan Duration: {scan_duration:.2f} seconds")
        print(f"Targets Scanned: {summary['targets_scanned']}")
        
        if results.get('subdomains'):
            print(f"Subdomains Found: {summary['subdomains_found']}")
            print(f"Live Subdomains: {summary['live_subdomains']}")
        
        print(f"\n{Fore.YELLOW}VULNERABILITY SUMMARY:")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"  {Fore.RED}Critical: {summary['critical']}")
        print(f"  {Fore.MAGENTA}High: {summary['high']}")
        print(f"  {Fore.YELLOW}Medium: {summary['medium']}")
        print(f"  {Fore.CYAN}Low: {summary['low']}{Style.RESET_ALL}")
        
        if results['vulnerabilities']:
            print(f"\n{Fore.YELLOW}DETAILED VULNERABILITIES:{Style.RESET_ALL}")
            for i, vuln in enumerate(results['vulnerabilities'][:20], 1):  # Show first 20
                severity_color = {
                    'Critical': Fore.RED,
                    'High': Fore.MAGENTA, 
                    'Medium': Fore.YELLOW,
                    'Low': Fore.CYAN
                }.get(vuln.get('severity'), Fore.WHITE)
                
                print(f"\n{i}. {severity_color}[{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
                print(f"   URL: {vuln.get('url', 'N/A')}")
                print(f"   Evidence: {vuln.get('evidence', 'N/A')[:100]}...")
                
                if vuln.get('parameter'):
                    print(f"   Parameter: {vuln['parameter']}")
                if vuln.get('payload'):
                    print(f"   Payload: {vuln['payload'][:50]}...")
            
            if len(results['vulnerabilities']) > 20:
                print(f"\n... and {len(results['vulnerabilities']) - 20} more vulnerabilities")
        
        # Save to file if requested
        if output_file:
            self.save_report_to_file(results, output_file)
            print(f"\n{Fore.GREEN}Report saved to: {output_file}{Style.RESET_ALL}")
        
        # Security recommendations
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"SECURITY RECOMMENDATIONS")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if summary['critical'] > 0:
            print(f"{Fore.RED}⚠️  CRITICAL: Immediate action required!")
            print(f"   - {summary['critical']} critical vulnerabilities found")
            print(f"   - These pose immediate security risks")
            print(f"   - Prioritize fixing these vulnerabilities{Style.RESET_ALL}")
        
        if summary['high'] > 0:
            print(f"{Fore.MAGENTA}⚠️  HIGH: Address these vulnerabilities soon")
            print(f"   - {summary['high']} high-severity vulnerabilities found{Style.RESET_ALL}")
        
        recommendations = [
            "Keep all software and dependencies updated",
            "Implement proper input validation and sanitization", 
            "Use parameterized queries to prevent SQL injection",
            "Implement proper authentication and session management",
            "Configure security headers (CSP, HSTS, etc.)",
            "Regular security testing and code reviews",
            "Implement proper error handling to prevent information disclosure",
            "Use HTTPS for all sensitive communications"
        ]
        
        print(f"\n{Fore.CYAN}General Security Best Practices:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        print(f"{Style.RESET_ALL}")
    
    def save_report_to_file(self, results, output_file):
        """Save detailed report to JSON file"""
        import json
        
        # Prepare serializable results
        export_results = results.copy()
        if export_results['scan_time']['start']:
            export_results['scan_time']['start'] = export_results['scan_time']['start'].isoformat()
        if self.end_time:
            export_results['scan_time']['end'] = self.end_time.isoformat()
        
        with open(output_file, 'w') as f:
            json.dump(export_results, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] Detailed report saved to {output_file}{Style.RESET_ALL}")
    
    def print_banner(self):
        """Display the tool banner and warnings"""
        print(self.banner)
        print(f"{Fore.RED}{'='*80}")
        print(f"WARNING: This tool is for authorized security testing ONLY!")
        print(f"Ensure you have explicit permission before scanning any target.")
        print(f"Unauthorized use may violate laws and regulations.")
        print(f"{'='*80}{Style.RESET_ALL}\n")
    
    def ethical_warning(self, target):
        """Display ethical use warning and get user confirmation"""
        print(f"\n{Fore.YELLOW}ETHICAL USE CONFIRMATION{Style.RESET_ALL}")
        print(f"Target: {Fore.CYAN}{target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Do you have explicit authorization to test this target? (yes/no): {Style.RESET_ALL}", end="")
        
        confirmation = input().strip().lower()
        if confirmation not in ['yes', 'y']:
            print(f"{Fore.RED}Scanning aborted. Only test systems you own or have permission to test.{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.GREEN}Authorization confirmed. Proceeding with scan...{Style.RESET_ALL}\n")

def main():
    """Main function to handle command line arguments and start scanning"""
    scanner = zeroHack()
    scanner.print_banner()
    
    parser = argparse.ArgumentParser(
        description="""Comprehensive Vulnerability Assessment Tool v2.0
        
Tests for web application, API, cloud, mobile, and IoT security vulnerabilities including:
• Web: SQL Injection, XSS, SSRF, RCE, IDOR
• Smart Contracts: Signature bypass, NFT bridge, ERC777 reentrancy, LayerZero messaging, DeFi lending, perpetual bad debt, proxy vulnerabilities (7 Immunefi studies)
• API: GraphQL injection, JWT flaws, mass assignment, rate limiting
• Cloud: AWS/Azure/GCP misconfigurations, container security
• Mobile: Android/iOS vulnerabilities, WebView exploits, deep linking
• IoT: MQTT/CoAP protocols, default credentials, industrial systems""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-t", "--target", required=True, 
                      help="Target domain to scan (e.g., example.com)")
    
    parser.add_argument("-l", "--level", choices=['normal', 'moderate', 'extreme'], 
                      default='normal', help="Attack intensity level (default: normal)")
    
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    
    parser.add_argument("--no-subdomain", action="store_true", 
                      help="Skip subdomain enumeration")
    
    parser.add_argument("--no-port-scan", action="store_true", 
                      help="Skip port scanning")
    
    parser.add_argument("--ports", default="1-1000", 
                      help="Port range to scan (default: 1-1000)")
    
    parser.add_argument("--threads", type=int, 
                      help="Number of threads (overrides level default)")
    
    # Notification options
    parser.add_argument("--no-notifications", action="store_true",
                      help="Disable all real-time notifications")
    
    parser.add_argument("--no-desktop", action="store_true",
                      help="Disable desktop notifications")
    
    parser.add_argument("--no-audio", action="store_true",
                      help="Disable audio alerts")
    
    parser.add_argument("--email-alerts", type=str, 
                      help="Enable email alerts (provide recipient email)")
    
    parser.add_argument("--cache-poisoning", action="store_true",
                      help="Enable advanced web cache poisoning detection")
    
    parser.add_argument("--cache-deception", action="store_true",
                      help="Enable web cache deception testing (PortSwigger research)")
    
    parser.add_argument("--static-bypass", action="store_true", 
                      help="Test static extension cache bypass (like /profile;a.js)")
    
    args = parser.parse_args()
    
    # Initialize notification system
    if not args.no_notifications and NOTIFICATIONS_AVAILABLE:
        enable_desktop = not args.no_desktop
        enable_audio = not args.no_audio
        enable_email = bool(args.email_alerts)
        
        scanner.notification_manager = initialize_notifications(enable_desktop, enable_audio, enable_email)
        
        if args.email_alerts:
            print(f"{Fore.YELLOW}[*] Email alerts configured for {args.email_alerts}")
            print(f"[*] Note: Configure SMTP settings for email functionality{Style.RESET_ALL}")
    
    # Show ethical warning and get confirmation
    scanner.ethical_warning(args.target)
    
    # Display scan configuration
    level_config = scanner.attack_levels[args.level]
    threads = args.threads if args.threads else level_config['threads']
    
    print(f"{Fore.GREEN}Scan Configuration:{Style.RESET_ALL}")
    print(f"  Target: {Fore.CYAN}{args.target}{Style.RESET_ALL}")
    print(f"  Level: {Fore.YELLOW}{args.level.upper()}{Style.RESET_ALL} - {level_config['description']}")
    print(f"  Threads: {threads}")
    print(f"  Port Range: {args.ports}")
    print(f"  Output: {args.output if args.output else 'Console only'}")
    
    print(f"\n{Fore.YELLOW}Starting vulnerability scan...{Style.RESET_ALL}")
    
    # Initialize scanner and start scan
    scanner.start_time = datetime.now()
    scan_results = scanner.run_comprehensive_scan(args)
    scanner.end_time = datetime.now()
    
    # Generate report
    scanner.generate_report(scan_results, args.output)
    
    # Show final notification summary
    if scanner.notification_manager:
        scanner.notification_manager.show_final_summary()
    
    print(f"\n{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)