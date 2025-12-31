#!/usr/bin/env python3
"""
Cloud Security Testing Module
Tests for cloud infrastructure vulnerabilities including:
- AWS S3 bucket misconfigurations
- Azure blob storage exposures
- Google Cloud Platform misconfigurations
- Container security issues
- Serverless security vulnerabilities
- Cloud metadata service exploitation
- IAM misconfigurations
"""

import requests
import re
import json
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import xml.etree.ElementTree as ET

class CloudSecurityTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Cloud vulnerability patterns
        self.cloud_vulnerabilities = {
            # AWS S3 bucket misconfigurations
            'aws_s3': {
                'endpoints': [
                    '/.aws/credentials', '/.aws/config', '/aws-keys', '/s3',
                    '/backup', '/backups', '/data', '/files', '/uploads',
                    '/assets', '/static', '/public', '/private'
                ],
                'payloads': [
                    # S3 bucket enumeration
                    'https://s3.amazonaws.com/{bucket_name}',
                    'https://{bucket_name}.s3.amazonaws.com',
                    
                    # AWS metadata service
                    'http://169.254.169.254/latest/meta-data/',
                    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                    
                    # AWS keys exposure
                    'AKIA[0-9A-Z]{16}',  # AWS Access Key ID pattern
                    'AWS_ACCESS_KEY_ID',
                    'AWS_SECRET_ACCESS_KEY',
                ]
            },
            
            # Azure misconfigurations
            'azure': {
                'endpoints': [
                    '/.azure', '/azure-keys', '/azure', '/blob',
                    '/storage', '/container', '/vault', '/keyvault'
                ],
                'payloads': [
                    # Azure metadata service
                    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                    
                    # Azure storage account patterns
                    'https://{account}.blob.core.windows.net/{container}',
                    'https://{account}.file.core.windows.net/',
                    
                    # Azure key patterns
                    'DefaultEndpointsProtocol=https;AccountName=',
                    'SharedAccessSignature=',
                ]
            },
            
            # Google Cloud Platform
            'gcp': {
                'endpoints': [
                    '/.gcp', '/gcp-keys', '/gcp', '/storage',
                    '/bucket', '/cloud-storage', '/firebase'
                ],
                'payloads': [
                    # GCP metadata service
                    'http://169.254.169.254/computeMetadata/v1/',
                    'http://metadata.google.internal/computeMetadata/v1/',
                    
                    # GCP storage patterns
                    'https://storage.googleapis.com/{bucket_name}',
                    'https://storage.cloud.google.com/{bucket_name}',
                    
                    # Service account keys
                    'type": "service_account',
                    'private_key_id',
                ]
            },
            
            # Container security
            'containers': {
                'endpoints': [
                    '/docker', '/.docker', '/containers', '/k8s',
                    '/.kube', '/kubernetes', '/api/v1', '/metrics'
                ],
                'payloads': [
                    # Docker socket exposure
                    'unix:///var/run/docker.sock',
                    '/var/run/docker.sock',
                    
                    # Kubernetes API exposure
                    '/api/v1/namespaces',
                    '/api/v1/pods',
                    '/api/v1/secrets',
                    
                    # Container escape indicators
                    'privileged: true',
                    'hostNetwork: true',
                    'hostPID: true',
                ]
            },
            
            # Serverless vulnerabilities
            'serverless': {
                'endpoints': [
                    '/lambda', '/.serverless', '/functions', '/api/lambda',
                    '/azure-functions', '/cloud-functions'
                ],
                'payloads': [
                    # Function enumeration
                    '/.aws-sam/',
                    '/.serverless/',
                    
                    # Cold start exploitation
                    '{"cold_start": true, "memory_leak": true}',
                    
                    # Environment variable exposure
                    'process.env',
                    'os.environ',
                ]
            }
        }
        
        # Cloud vulnerability indicators
        self.vulnerability_indicators = {
            'aws_exposure': [
                'aws access key', 'secret access key', 's3 bucket', 'iam role',
                'ec2 instance', 'security credentials', 'temporary credentials'
            ],
            'azure_exposure': [
                'storage account', 'shared access signature', 'azure ad', 'key vault',
                'managed identity', 'azure credentials', 'subscription id'
            ],
            'gcp_exposure': [
                'service account', 'private key', 'project id', 'gcp storage',
                'compute metadata', 'google cloud', 'firebase config'
            ],
            'container_vulnerable': [
                'docker exposed', 'kubernetes api', 'container escape', 'privileged container',
                'host network', 'docker socket', 'pod security', 'cluster admin'
            ],
            'serverless_vulnerable': [
                'function exposed', 'lambda credentials', 'environment variables',
                'cold start attack', 'serverless config', 'function timeout'
            ]
        }
        
        # Common cloud misconfigurations to test
        self.cloud_tests = {
            's3_buckets': [
                'backup', 'backups', 'data', 'files', 'uploads', 'assets',
                'static', 'public', 'private', 'logs', 'config', 'secrets'
            ],
            'azure_containers': [
                'backup', 'data', 'files', 'logs', 'config', 'storage'
            ],
            'gcp_buckets': [
                'backup', 'data', 'files', 'logs', 'config', 'storage'
            ]
        }
    
    def test_aws_misconfigurations(self, url):
        """Test for AWS security misconfigurations"""
        results = []
        
        aws_config = self.cloud_vulnerabilities['aws_s3']
        
        # Test for AWS credentials exposure
        for endpoint in aws_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for AWS exposure indicators
                for indicator in self.vulnerability_indicators['aws_exposure']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'AWS Configuration Exposure',
                            'severity': 'High',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"AWS exposure indicator: {indicator}",
                            'attack_vector': 'AWS credentials or configuration exposure',
                            'impact': 'Cloud infrastructure compromise, data access',
                            'remediation': 'Secure AWS credentials, implement proper IAM policies',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] AWS exposure: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                
                # Check for AWS Access Key patterns
                aws_key_pattern = r'AKIA[0-9A-Z]{16}'
                if re.search(aws_key_pattern, response.text):
                    vuln = {
                        'type': 'AWS Access Key Exposure',
                        'severity': 'Critical',
                        'url': test_url,
                        'method': 'GET',
                        'evidence': 'AWS Access Key ID found in response',
                        'attack_vector': 'Hardcoded AWS credentials exposure',
                        'impact': 'Complete AWS account compromise',
                        'remediation': 'Remove hardcoded credentials, use IAM roles',
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] CRITICAL: AWS Access Key found: {test_url}{Style.RESET_ALL}")
                    
            except Exception:
                continue
        
        # Test S3 bucket enumeration
        for bucket_name in self.cloud_tests['s3_buckets']:
            s3_urls = [
                f"https://s3.amazonaws.com/{bucket_name}",
                f"https://{bucket_name}.s3.amazonaws.com"
            ]
            
            for s3_url in s3_urls:
                try:
                    response = requests.get(s3_url, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200 and 'ListBucketResult' in response.text:
                        vuln = {
                            'type': 'Public S3 Bucket Exposure',
                            'severity': 'High',
                            'url': s3_url,
                            'method': 'GET',
                            'evidence': 'S3 bucket contents accessible without authentication',
                            'attack_vector': 'Public S3 bucket misconfiguration',
                            'impact': 'Data exposure, unauthorized access to files',
                            'remediation': 'Configure proper S3 bucket policies and ACLs',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] Public S3 bucket: {s3_url}{Style.RESET_ALL}")
                        
                except Exception:
                    continue
        
        return results
    
    def test_azure_misconfigurations(self, url):
        """Test for Azure security misconfigurations"""
        results = []
        
        azure_config = self.cloud_vulnerabilities['azure']
        
        for endpoint in azure_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for Azure exposure indicators
                for indicator in self.vulnerability_indicators['azure_exposure']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Azure Configuration Exposure',
                            'severity': 'High',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"Azure exposure indicator: {indicator}",
                            'attack_vector': 'Azure credentials or configuration exposure',
                            'impact': 'Azure resource compromise, unauthorized access',
                            'remediation': 'Secure Azure credentials, implement proper RBAC',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] Azure exposure: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                        
            except Exception:
                continue
        
        return results
    
    def test_gcp_misconfigurations(self, url):
        """Test for Google Cloud Platform misconfigurations"""
        results = []
        
        gcp_config = self.cloud_vulnerabilities['gcp']
        
        for endpoint in gcp_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for GCP exposure indicators
                for indicator in self.vulnerability_indicators['gcp_exposure']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'GCP Configuration Exposure',
                            'severity': 'High',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"GCP exposure indicator: {indicator}",
                            'attack_vector': 'GCP credentials or configuration exposure',
                            'impact': 'GCP resource compromise, data access',
                            'remediation': 'Secure GCP service accounts, implement proper IAM',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] GCP exposure: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                        
            except Exception:
                continue
        
        return results
    
    def test_container_security(self, url):
        """Test for container security vulnerabilities"""
        results = []
        
        container_config = self.cloud_vulnerabilities['containers']
        
        for endpoint in container_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for container vulnerability indicators
                for indicator in self.vulnerability_indicators['container_vulnerable']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Container Security Vulnerability',
                            'severity': 'Critical' if 'escape' in indicator else 'High',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"Container vulnerability: {indicator}",
                            'attack_vector': 'Container misconfiguration or exposure',
                            'impact': 'Container escape, host system compromise',
                            'remediation': 'Secure container configurations, implement security policies',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] Container vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                        
            except Exception:
                continue
        
        return results
    
    def test_serverless_vulnerabilities(self, url):
        """Test for serverless security vulnerabilities"""
        results = []
        
        serverless_config = self.cloud_vulnerabilities['serverless']
        
        for endpoint in serverless_config['endpoints']:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for serverless vulnerability indicators
                for indicator in self.vulnerability_indicators['serverless_vulnerable']:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Serverless Security Vulnerability',
                            'severity': 'Medium',
                            'url': test_url,
                            'method': 'GET',
                            'evidence': f"Serverless vulnerability: {indicator}",
                            'attack_vector': 'Serverless function misconfiguration',
                            'impact': 'Function compromise, environment variable exposure',
                            'remediation': 'Secure serverless configurations, implement proper access controls',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.CYAN}[!] Serverless vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                        break
                        
            except Exception:
                continue
        
        return results
    
    def test_metadata_service_exposure(self, url):
        """Test for cloud metadata service exposure"""
        results = []
        
        # Common metadata service endpoints
        metadata_endpoints = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',  # Azure
            'http://metadata.google.internal/computeMetadata/v1/'  # GCP
        ]
        
        for metadata_url in metadata_endpoints:
            try:
                # Try SSRF to metadata service
                ssrf_payload = {'url': metadata_url, 'target': metadata_url}
                response = requests.post(f"{url}/api", json=ssrf_payload, timeout=self.timeout, verify=False)
                
                if 'ami-id' in response.text or 'instance-id' in response.text:  # AWS
                    vuln = {
                        'type': 'AWS Metadata Service Exposure',
                        'severity': 'Critical',
                        'url': url,
                        'method': 'POST',
                        'evidence': 'AWS metadata service accessible via SSRF',
                        'attack_vector': 'SSRF to AWS metadata service',
                        'impact': 'IAM credentials exposure, instance information disclosure',
                        'remediation': 'Implement SSRF protection, use IMDSv2',
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] CRITICAL: AWS metadata exposure via SSRF: {url}{Style.RESET_ALL}")
                    
            except Exception:
                continue
        
        return results
    
    def test_cloud_security_vulnerabilities(self, targets):
        """Main function to test cloud security vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Starting cloud security testing...{Style.RESET_ALL}")
        
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
            
            print(f"{Fore.CYAN}[*] Testing cloud security: {url}{Style.RESET_ALL}")
            
            # Test AWS misconfigurations
            aws_vulns = self.test_aws_misconfigurations(url)
            all_vulnerabilities.extend(aws_vulns)
            
            # Test Azure misconfigurations
            azure_vulns = self.test_azure_misconfigurations(url)
            all_vulnerabilities.extend(azure_vulns)
            
            # Test GCP misconfigurations
            gcp_vulns = self.test_gcp_misconfigurations(url)
            all_vulnerabilities.extend(gcp_vulns)
            
            # Advanced tests for moderate/extreme levels
            if self.level in ['moderate', 'extreme']:
                # Test container security
                container_vulns = self.test_container_security(url)
                all_vulnerabilities.extend(container_vulns)
                
                # Test serverless vulnerabilities
                serverless_vulns = self.test_serverless_vulnerabilities(url)
                all_vulnerabilities.extend(serverless_vulns)
                
                # Test metadata service exposure
                metadata_vulns = self.test_metadata_service_exposure(url)
                all_vulnerabilities.extend(metadata_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities