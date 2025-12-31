# zeroHack Modules Package
# Advanced Security Testing Modules

from .web_cache_tester import WebCacheTester
from .sql_injection import SQLInjectionTester
from .xss_tester import XSSTester
from .ssrf_tester import SSRFTester
from .rce_tester import RCETester
from .idor_tester import IDORTester
from .port_scanner import PortScanner
from .subdomain_enum import SubdomainEnum
from .additional_vulns import AdditionalVulnTester
from .smart_contract_tester import SmartContractTester
from .api_security_tester import APISecurityTester
from .cloud_security_tester import CloudSecurityTester
from .mobile_security_tester import MobileSecurityTester
from .web3_tester import Web3Tester
from .iot_security_tester import IoTSecurityTester
from .notification_system import NotificationManager

__all__ = [
    'WebCacheTester',      # NEW: Web Cache Poisoning & Static Extension Bypass
    'SQLInjectionTester',
    'XSSTester', 
    'SSRFTester',
    'RCETester',
    'IDORTester',
    'PortScanner',
    'SubdomainEnum',
    'AdditionalVulnTester',
    'SmartContractTester',
    'APISecurityTester',
    'CloudSecurityTester',
    'MobileSecurityTester',
    'Web3Tester',
    'IoTSecurityTester',
    'NotificationManager'
]