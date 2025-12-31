#!/usr/bin/env python3
"""
zeroHack v1.8 - Comprehensive Vulnerability Assessment Tool
Integrates 7 Immunefi Case Studies ($10.66M+ Portfolio)

This package provides a comprehensive vulnerability assessment framework
for web applications, APIs, cloud infrastructure, mobile apps, IoT devices,
and smart contracts.

Features:
- Multi-domain security testing capabilities
- 7 real-world Immunefi case studies integration
- Educational demonstrations and learning modules
- Production-ready vulnerability detection
- Ethical use enforcement and guidelines

⚠️  AUTHORIZED USE ONLY - Only use on systems you own or have explicit permission to test.
"""

__version__ = "1.8.0"
__author__ = "ZeroHack Team"
__email__ = "security@zerohack.dev"
__license__ = "MIT"
__description__ = "Comprehensive Vulnerability Assessment Tool with 7 Immunefi Case Studies"
__url__ = "https://github.com/zerohack-team/zerohack"

# Import main components for easy access
try:
    from .vulnscanner import zeroHack, main
except ImportError:
    # Handle cases where the module is run directly
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from vulnscanner import zeroHack, main

# Immunefi Case Studies Portfolio
IMMUNEFI_PORTFOLIO = {
    "total_value": "$10,660,000+",
    "case_studies": [
        {
            "id": 1,
            "name": "Signature Verification Bypass",
            "type": "Cryptographic Vulnerability",
            "bounty_value": "Undisclosed",
            "status": "Integrated"
        },
        {
            "id": 2,
            "name": "NFT Bridge Vulnerabilities", 
            "type": "Cross-Chain Bridge",
            "bounty_value": "Undisclosed",
            "status": "Integrated"
        },
        {
            "id": 3,
            "name": "ERC777 Reentrancy",
            "type": "Token Hook Vulnerability",
            "bounty_value": "Undisclosed", 
            "status": "Integrated"
        },
        {
            "id": 4,
            "name": "LayerZero Cross-Chain DoS",
            "type": "Messaging Protocol",
            "bounty_value": "Undisclosed",
            "status": "Integrated"
        },
        {
            "id": 5,
            "name": "Port Finance DeFi Logic Error",
            "type": "Lending Protocol",
            "bounty_value": "$630,000",
            "status": "Integrated"
        },
        {
            "id": 6,
            "name": "Perpetual Protocol Bad Debt",
            "type": "Derivative Trading",
            "bounty_value": "$30,000",
            "status": "Integrated"
        },
        {
            "id": 7,
            "name": "Wormhole Proxy Vulnerability",
            "type": "Infrastructure Proxy",
            "bounty_value": "$10,000,000",
            "status": "Integrated",
            "note": "World Record Bug Bounty"
        }
    ]
}

# Feature Matrix
FEATURES = {
    "web_application": [
        "SQL Injection (Error-based, Time-based, Union-based, Boolean-based)",
        "Cross-Site Scripting (Reflected, Stored, DOM-based)",
        "Server-Side Request Forgery (SSRF)",
        "Remote Code Execution (RCE)",
        "Insecure Direct Object Reference (IDOR)",
        "Directory Traversal / Path Traversal"
    ],
    "smart_contract": [
        "Signature Verification Bypass",
        "NFT Bridge Vulnerabilities", 
        "ERC777 Reentrancy Attacks",
        "LayerZero Messaging DoS",
        "DeFi Lending Logic Errors",
        "Perpetual Protocol Bad Debt",
        "Proxy Implementation Bugs"
    ],
    "api_security": [
        "GraphQL Injection & Introspection",
        "JWT Security Flaws",
        "Mass Assignment Vulnerabilities",
        "Rate Limiting Bypass",
        "API Versioning Attacks"
    ],
    "cloud_security": [
        "AWS Misconfigurations",
        "Azure Security Issues", 
        "Google Cloud Platform Vulnerabilities",
        "Container Security (Docker, Kubernetes)",
        "Serverless Security"
    ],
    "mobile_security": [
        "Android Security Vulnerabilities",
        "iOS Security Issues",
        "Mobile API Security",
        "WebView Security",
        "Deep Linking Vulnerabilities"
    ],
    "iot_security": [
        "MQTT Protocol Security",
        "CoAP Protocol Vulnerabilities",
        "Default Credentials Testing", 
        "Industrial Protocol Security",
        "Device Fingerprinting"
    ]
}

# Ethical Use Guidelines
ETHICAL_GUIDELINES = {
    "allowed": [
        "Testing systems you own",
        "Authorized penetration testing with written permission",
        "Educational research and learning",
        "Bug bounty programs with explicit scope",
        "Security audits with proper authorization"
    ],
    "prohibited": [
        "Unauthorized scanning of systems you don't own",
        "Malicious attacks or exploitation",
        "Violation of terms of service",
        "Illegal activities or unauthorized access",
        "Using findings for harmful purposes"
    ],
    "requirements": [
        "Always obtain written authorization before testing",
        "Respect rate limits and avoid service disruption", 
        "Follow responsible disclosure practices",
        "Comply with local laws and regulations",
        "Respect intellectual property and confidentiality"
    ]
}

def get_version():
    """Return the current version of zeroHack"""
    return __version__

def get_immunefi_portfolio():
    """Return information about integrated Immunefi case studies"""
    return IMMUNEFI_PORTFOLIO

def get_features():
    """Return the complete feature matrix"""
    return FEATURES

def get_ethical_guidelines():
    """Return ethical use guidelines"""
    return ETHICAL_GUIDELINES

def print_banner():
    """Print the zeroHack banner"""
    from colorama import init, Fore, Style
    init()
    
    print(f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                      ZEROHACK v{__version__}                     ║
║         Comprehensive Vulnerability Assessment Tool          ║
║              7 Immunefi Case Studies Integrated             ║
║                $10,660,000+ Bounty Portfolio                ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}⚠️  AUTHORIZED USE ONLY - Explicit permission required{Style.RESET_ALL}
""")

def show_portfolio():
    """Display the Immunefi case studies portfolio"""
    from colorama import init, Fore, Style
    init()
    
    portfolio = get_immunefi_portfolio()
    
    print(f"\n{Fore.CYAN}💰 IMMUNEFI CASE STUDIES PORTFOLIO{Style.RESET_ALL}")
    print(f"Total Value: {Fore.GREEN}{portfolio['total_value']}{Style.RESET_ALL}")
    print(f"Cases Integrated: {Fore.YELLOW}{len(portfolio['case_studies'])}/7{Style.RESET_ALL}\n")
    
    for case in portfolio['case_studies']:
        status_color = Fore.GREEN if case['status'] == 'Integrated' else Fore.YELLOW
        bounty_color = Fore.RED if case['bounty_value'] == '$10,000,000' else Fore.CYAN
        
        print(f"Case #{case['id']}: {Fore.WHITE}{case['name']}{Style.RESET_ALL}")
        print(f"  Type: {case['type']}")
        print(f"  Bounty: {bounty_color}{case['bounty_value']}{Style.RESET_ALL}")
        print(f"  Status: {status_color}{case['status']}{Style.RESET_ALL}")
        
        if case.get('note'):
            print(f"  Note: {Fore.YELLOW}{case['note']}{Style.RESET_ALL}")
        print()

# Module-level constants for easy access
VERSION = __version__
AUTHOR = __author__
LICENSE = __license__
DESCRIPTION = __description__

# Export main components
__all__ = [
    'zeroHack',
    'main',
    'get_version', 
    'get_immunefi_portfolio',
    'get_features',
    'get_ethical_guidelines',
    'print_banner',
    'show_portfolio',
    'IMMUNEFI_PORTFOLIO',
    'FEATURES',
    'ETHICAL_GUIDELINES',
    'VERSION',
    'AUTHOR',
    'LICENSE',
    'DESCRIPTION'
]

# Package initialization message
if __name__ != "__main__":
    pass  # Silent import for production use
else:
    # Direct execution - show information
    print_banner()
    show_portfolio()