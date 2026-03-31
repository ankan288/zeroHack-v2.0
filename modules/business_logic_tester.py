#!/usr/bin/env python3
"""
Business Logic Tester Module
Tries to identify semantic logic flaws like parameter tampering, negative values for quantity/price,
and role/privilege escalation indicators.
"""

import requests
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

class BusinessLogicTester:
    def __init__(self, target_url, level='normal'):
        self.target_url = target_url
        self.level = level
        self.findings = []
        self.timeout = 5 if level == 'normal' else 10

        self.user_agents = {
            'normal': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }

    def scan(self):
        """Run business logic security tests"""
        print(f"\n[*] Starting Business Logic Analysis on {self.target_url}")
        
        # Test 1: Parameter Tampering / Negative Values Checks
        self.test_parameter_tampering()
        
        # Test 2: Privilege / Role Name Manipulation
        self.test_privilege_escalation_parameters()

        # Test 3: ID parameter manipulation (Heuristic)
        self.test_mass_assignment()

        return self.findings

    def get_base_params(self, url):
        parsed = urlparse(url)
        return parse_qsl(parsed.query)

    def test_parameter_tampering(self):
        """Test for manipulation of financial or quantity-related parameters"""
        parsed = urlparse(self.target_url)
        params = parse_qsl(parsed.query)
        
        if not params:
            return  # No parameters to test
            
        financial_keywords = ['price', 'total', 'amount', 'cost', 'qty', 'quantity', 'discount']
        tampered_values = ['-1', '0', '-9999', '9999999999999']

        for key, val in params:
            if any(keyword in key.lower() for keyword in financial_keywords):
                print(f"  [!] Detected potentially manipulatable financial/quantity parameter: {key}")
                
                for tampered in tampered_values:
                    # Construct tampered URL
                    tampered_params = [(k, tampered if k == key else v) for k, v in params]
                    tampered_query = urlencode(tampered_params)
                    tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, tampered_query, parsed.fragment))
                    
                    try:
                        response = requests.get(
                            tampered_url, 
                            timeout=self.timeout, 
                            headers={'User-Agent': self.user_agents['normal']}
                        )
                        # Basic heuristic: if the app doesn't reject it (e.g., status 400/500/403) and 
                        # reflects the negative or huge value, it might be vulnerable.
                        if response.status_code == 200 and tampered in response.text:
                            self.findings.append({
                                'type': 'Business Logic / Parameter Tampering',
                                'severity': 'High',
                                'url': tampered_url,
                                'parameter': key,
                                'payload': tampered,
                                'description': f'Parameter "{key}" accepted unnatural value "{tampered}" which was reflected in the response. Check for Business Logic Flaws.'
                            })
                            print(f"  [+] Possible Parameter Tampering Success: {key} = {tampered}")
                    except Exception:
                        pass
        
    def test_privilege_escalation_parameters(self):
        """Test for forced browsing / role manipulation in URL parameters"""
        parsed = urlparse(self.target_url)
        params = parse_qsl(parsed.query)
        
        role_keywords = ['role', 'is_admin', 'isadmin', 'privilege', 'admin', 'user_type', 'group']
        escalation_values = ['admin', '1', 'true', 'superadmin', 'manager']

        for key, val in params:
            if any(keyword in key.lower() for keyword in role_keywords):
                print(f"  [!] Detected potential role-based parameter: {key}")
                
                for payload in escalation_values:
                    tampered_params = [(k, payload if k == key else v) for k, v in params]
                    tampered_query = urlencode(tampered_params)
                    tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, tampered_query, parsed.fragment))
                    
                    try:
                        response = requests.get(
                            tampered_url, 
                            timeout=self.timeout, 
                            headers={'User-Agent': self.user_agents['normal']}
                        )
                        
                        if response.status_code == 200 and ('admin' in response.text.lower() or 'dashboard' in response.text.lower()):
                            self.findings.append({
                                'type': 'Business Logic / Request Parameter Authorization Bypass',
                                'severity': 'Critical',
                                'url': tampered_url,
                                'parameter': key,
                                'payload': payload,
                                'description': f'Manipulating "{key}" to "{payload}" might have granted higher privileges or loaded admin elements.'
                            })
                            print(f"  [+] Possible Privilege Escalation Success: {key} = {payload}")
                    except Exception:
                        pass

    def test_mass_assignment(self):
        """Appends unexpected parameters to test for mass assignment vulnerabilities"""
        parsed = urlparse(self.target_url)
        existing_params = parse_qsl(parsed.query)
        
        # Inject an unexpected admin/role parameter
        injected_params = [('is_admin', 'true'), ('role', 'admin'), ('admin', '1')]
        
        for inject_k, inject_v in injected_params:
            tampered_params = existing_params + [(inject_k, inject_v)]
            tampered_query = urlencode(tampered_params)
            tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, tampered_query, parsed.fragment))
            
            try:
                response = requests.get(
                    tampered_url, 
                    timeout=self.timeout, 
                    headers={'User-Agent': self.user_agents['normal']}
                )
                
                if response.status_code == 200 and 'admin' in response.text.lower() and ('welcome admin' in response.text.lower() or 'admin dashboard' in response.text.lower()):
                    self.findings.append({
                        'type': 'Business Logic / Mass Assignment',
                        'severity': 'High',
                        'url': tampered_url,
                        'parameter': inject_k,
                        'payload': inject_v,
                        'description': f'Appending unexpected parameter "{inject_k}={inject_v}" may have altered user context/mass-assigned an admin role.'
                    })
                    print(f"  [+] Possible Mass Assignment Success: Added {inject_k}={inject_v}")
            except Exception:
                pass
