#!/usr/bin/env python3
"""
Web3 & Blockchain Security Testing Module
Tests for Web3 and blockchain-related vulnerabilities
"""

import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import time

class Web3Tester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Common Web3/DeFi endpoints and patterns
        self.web3_endpoints = [
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/rpc', '/jsonrpc', '/graphql', '/ws',
            '/eth/', '/btc/', '/bnb/', '/matic/',
            '/defi/', '/swap/', '/pool/', '/stake/',
            '/nft/', '/token/', '/mint/', '/burn/',
            '/wallet/', '/bridge/', '/oracle/',
            '/governance/', '/dao/', '/vote/',
        ]
        
        # Blockchain-specific vulnerabilities to test
        self.web3_tests = {
            'rpc_exposure': [
                # Ethereum JSON-RPC methods
                '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}',
                '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x0000000000000000000000000000000000000000","latest"],"id":1}',
                '{"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":1}',
                '{"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0x0000000000000000000000000000000000000000","password",0],"id":1}',
                '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}',
                '{"jsonrpc":"2.0","method":"debug_dumpBlock","params":["latest"],"id":1}',
                '{"jsonrpc":"2.0","method":"miner_setEtherbase","params":["0x0000000000000000000000000000000000000000"],"id":1}',
                
                # Bitcoin RPC methods
                '{"jsonrpc":"1.0","method":"getwalletinfo","params":[],"id":1}',
                '{"jsonrpc":"1.0","method":"listaccounts","params":[],"id":1}',
                '{"jsonrpc":"1.0","method":"dumpprivkey","params":["address"],"id":1}',
                '{"jsonrpc":"1.0","method":"getnetworkinfo","params":[],"id":1}',
            ],
            
            # Smart contract signature verification bypass
            'signature_bypass': [
                # Zero threshold attacks (based on the article)
                '{"threshold": 0, "validators": ["0x1234567890123456789012345678901234567890"], "signatures": []}',
                '{"metadata": {"threshold": 0}, "message": {"data": "malicious_payload"}}',
                '{"_threshold": 0, "_validators": ["0xValidatorAddress"], "_signatures": []}',
                
                # Signature manipulation attacks
                '{"threshold": 1, "validators": [], "signatures": ["0x00"]}',  # Empty validators
                '{"threshold": 255, "validators": ["0x1234"], "signatures": []}',  # Overflow attempt
                '{"threshold": -1, "validators": ["0x1234"], "signatures": []}',  # Underflow attempt
                
                # Commitment manipulation
                '{"commitment": "0x0000000000000000000000000000000000000000000000000000000000000000"}',
                '{"commitment": "", "validators": ["0x1234"], "threshold": 0}',
                
                # Invalid signature formats
                '{"signatures": [""], "threshold": 1, "validators": ["0x1234"]}',
                '{"signatures": ["0x"], "threshold": 1, "validators": ["0x1234"]}',
                '{"signatures": ["invalid"], "threshold": 1, "validators": ["0x1234"]}',
                
                # Frontrunning simulation payloads
                '{"action": "enrollValidator", "validator": "0x1234567890123456789012345678901234567890"}',
                '{"action": "setThreshold", "threshold": 0, "domain": 1}',
                '{"action": "process", "message": "malicious", "threshold": 0}',
            ],
            
            'private_key_exposure': [
                # Common private key patterns
                r'["\']?private[_-]?key["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{64})["\']?',
                r'["\']?mnemonic["\']?\s*[:=]\s*["\']?([a-z\s]{95,})["\']?',
                r'["\']?seed["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{64})["\']?',
                r'-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----',
                r'0x[a-fA-F0-9]{64}',  # Ethereum private key format
            ],
            
            'wallet_exposure': [
                # Wallet-related patterns
                r'keystore', r'wallet\.dat', r'private\.key',
                r'mnemonic', r'seed\.txt', r'recovery\.txt',
                r'metamask', r'trustwallet', r'coinbase',
            ],
            
            'defi_vulnerabilities': [
                # Price manipulation
                '{"amount": "999999999999999999999999"}',
                '{"price": "-1"}', '{"slippage": "100"}',
                
                # Reentrancy attempts
                '{"callback": "malicious_contract"}',
                '{"to": "0x0000000000000000000000000000000000000000"}',
                
                # Overflow/Underflow
                '{"amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935"}',
                '{"value": "0"}', '{"balance": "-1"}',
            ],
            
            # Cross-chain bridge vulnerabilities (from the article)
            'cross_chain_exploits': [
                # Signature verification bypass in cross-chain messaging
                '{"origin": 1, "threshold": 0, "validators": ["0x1234"], "message": "malicious_cross_chain"}',
                '{"domain": 1, "_threshold": 0, "_metadata": {"validators": ["0xValidator"]}}',
                
                # Commitment hash manipulation  
                '{"commitment": "0x0000000000000000000000000000000000000000000000000000000000000000", "domain": 1}',
                '{"_commitment": "", "_origin": 1, "_threshold": 0}',
                
                # Validator enrollment race conditions
                '{"enrollValidator": {"domain": 1, "validator": "0x1234"}, "setThreshold": {"domain": 1, "threshold": 0}}',
                
                # Message processing with invalid signatures
                '{"process": {"message": "malicious", "metadata": {"threshold": 0, "signatures": []}}}',
                
                # Domain/chain manipulation
                '{"domain": 0, "threshold": 0}',  # Default domain with zero threshold
                '{"domain": 4294967295, "threshold": 0}',  # Max uint32 domain
                '{"_domain": -1, "_threshold": 0}',  # Underflow attempt
            ]
        }
        
        # Web3 vulnerability indicators
        self.web3_indicators = {
            'exposed_rpc': [
                '"jsonrpc":', '"result":', '"error":', '"method":',
                'eth_accounts', 'personal_listAccounts', 'admin_',
                'getwalletinfo', 'listaccounts', 'bitcoin',
            ],
            'private_keys': [
                'private key', 'mnemonic phrase', 'seed phrase',
                'BEGIN PRIVATE KEY', 'keystore', 'wallet password',
            ],
            'sensitive_blockchain_data': [
                'balance', 'transaction hash', 'block hash',
                'contract address', 'gas price', 'nonce',
                'signature', 'recovery id', 'chain id',
            ],
            'defi_errors': [
                'insufficient balance', 'slippage exceeded',
                'price impact too high', 'liquidity error',
                'oracle manipulation', 'flash loan',
            ],
            # NEW: Smart contract signature verification indicators (from article)
            'signature_vulnerabilities': [
                'signature verification', 'threshold', 'validator', 'commitment',
                '_verifyValidatorSignatures', 'enrollValidator', 'setThreshold',
                '_updateCommitment', 'ECDSA.recover', 'signature bypass',
                'zero threshold', 'frontrunning', 'race condition'
            ],
            # NEW: Cross-chain bridge indicators
            'cross_chain_indicators': [
                'cross-chain', 'bridge', 'relay', 'messenger', 'origin',
                'domain', 'validator enrollment', 'threshold set',
                'commitment updated', 'message processed'
            ],
            # NEW: Smart contract access control
            'access_control_bypass': [
                'onlyOwner', 'require(msg.sender', 'unauthorized access',
                'access control', 'permission denied', 'role based',
                'modifier bypass', 'function visibility'
            ],
            # NEW: Reentrancy and state manipulation
            'state_manipulation': [
                'reentrancy', 'state change', 'external call', 'callback',
                'mutex', 'lock', 'nonReentrant', 'check-effects-interactions'
            ]
        }
    
    def test_rpc_exposure(self, url):
        """Test for exposed blockchain RPC endpoints"""
        results = []
        
        rpc_paths = ['/rpc', '/jsonrpc', '/api/rpc', '/eth/rpc', '/btc/rpc', '/v1/rpc', '/', '/api']
        
        for path in rpc_paths:
            test_url = f"{url.rstrip('/')}{path}"
            
            for rpc_payload in self.web3_tests['rpc_exposure']:
                try:
                    headers = {
                        'Content-Type': 'application/json',
                        'User-Agent': 'VulnScanner/1.0'
                    }
                    
                    response = requests.post(test_url, data=rpc_payload, 
                                           headers=headers, timeout=self.timeout, verify=False)
                    
                    # Check for RPC response indicators
                    for indicator in self.web3_indicators['exposed_rpc']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'Exposed Blockchain RPC Endpoint',
                                'severity': 'High',
                                'url': test_url,
                                'method': 'POST',
                                'payload': rpc_payload,
                                'evidence': f"RPC response detected: {indicator}",
                                'status_code': response.status_code,
                                'response_length': len(response.text)
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] Exposed RPC found: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                    
                    # Check for specific dangerous methods
                    if any(dangerous in response.text.lower() for dangerous in 
                          ['personal_unlockaccount', 'dumpprivkey', 'admin_', 'miner_']):
                        vuln = {
                            'type': 'Dangerous RPC Method Exposed',
                            'severity': 'Critical',
                            'url': test_url,
                            'method': 'POST',
                            'payload': rpc_payload,
                            'evidence': "Dangerous RPC methods accessible",
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] Dangerous RPC methods exposed: {test_url}{Style.RESET_ALL}")
                    
                except Exception:
                    continue
        
        return results
    
    def test_private_key_exposure(self, url):
        """Test for exposed private keys or mnemonics"""
        results = []
        
        # Common paths where private keys might be exposed
        key_paths = [
            '/.env', '/config.json', '/wallet.json', '/keystore/',
            '/backup/', '/keys/', '/secrets/', '/private/',
            '/.git/config', '/package.json', '/yarn.lock',
            '/hardhat.config.js', '/truffle-config.js',
        ]
        
        for path in key_paths:
            try:
                test_url = f"{url.rstrip('/')}{path}"
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check for private key patterns
                    for pattern in self.web3_tests['private_key_exposure']:
                        matches = re.findall(pattern, response.text, re.IGNORECASE | re.MULTILINE)
                        if matches:
                            vuln = {
                                'type': 'Private Key Exposure',
                                'severity': 'Critical',
                                'url': test_url,
                                'method': 'GET',
                                'evidence': f"Private key pattern found: {pattern[:50]}...",
                                'matches_count': len(matches),
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] Private key exposure: {test_url}{Style.RESET_ALL}")
                            break
                    
                    # Check for wallet indicators
                    for indicator in self.web3_tests['wallet_exposure']:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'Wallet File Exposure',
                                'severity': 'High',
                                'url': test_url,
                                'method': 'GET',
                                'evidence': f"Wallet indicator found: {indicator}",
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] Wallet file exposure: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                            
            except Exception:
                continue
        
        return results
    
    def test_defi_vulnerabilities(self, url):
        """Test for DeFi-specific vulnerabilities"""
        results = []
        
        # Common DeFi API endpoints
        defi_endpoints = [
            '/api/swap', '/api/pool', '/api/stake', '/api/unstake',
            '/api/borrow', '/api/lend', '/api/liquidate',
            '/api/oracle', '/api/price', '/api/balance',
            '/v1/swap', '/v1/pool', '/v1/defi'
        ]
        
        for endpoint in defi_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in self.web3_tests['defi_vulnerabilities']:
                try:
                    # Test both GET and POST
                    methods = [
                        ('GET', {'params': json.loads(payload) if payload.startswith('{') else {'test': payload}}),
                        ('POST', {'json': json.loads(payload) if payload.startswith('{') else {'data': payload}})
                    ]
                    
                    for method, kwargs in methods:
                        response = requests.request(method, test_url, timeout=self.timeout, 
                                                  verify=False, **kwargs)
                        
                        # Check for DeFi error messages that might indicate vulnerabilities
                        for indicator in self.web3_indicators['defi_errors']:
                            if indicator.lower() in response.text.lower():
                                vuln = {
                                    'type': 'DeFi Vulnerability Indicator',
                                    'severity': 'Medium',
                                    'url': test_url,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': f"DeFi error indicator: {indicator}",
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[!] DeFi vulnerability indicator: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                        
                        # Check for successful responses to malicious payloads
                        if response.status_code == 200 and 'success' in response.text.lower():
                            vuln = {
                                'type': 'Potential DeFi Logic Vulnerability',
                                'severity': 'High',
                                'url': test_url,
                                'method': method,
                                'payload': payload,
                                'evidence': "Malicious payload accepted by DeFi endpoint",
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] Potential DeFi vulnerability: {test_url}{Style.RESET_ALL}")
                
                except Exception:
                    continue
        
        return results
    
    def test_smart_contract_exposure(self, url):
        """Test for smart contract information exposure"""
        results = []
        
        contract_paths = [
            '/contracts/', '/abi/', '/bytecode/', '/deployment/',
            '/.openzeppelin/', '/artifacts/', '/cache/',
            '/contracts.json', '/abi.json', '/deployment.json'
        ]
        
        for path in contract_paths:
            try:
                test_url = f"{url.rstrip('/')}{path}"
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check for contract-related content
                    contract_indicators = [
                        'abi', 'bytecode', 'contract address', 'constructor',
                        'function selector', 'event signature', 'solidity',
                        'pragma', 'contract', 'interface', 'library'
                    ]
                    
                    for indicator in contract_indicators:
                        if indicator.lower() in response.text.lower():
                            vuln = {
                                'type': 'Smart Contract Information Exposure',
                                'severity': 'Low',
                                'url': test_url,
                                'method': 'GET',
                                'evidence': f"Contract information exposed: {indicator}",
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.CYAN}[!] Contract info exposure: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                            
            except Exception:
                continue
        
        return results
    
    def test_signature_verification_bypass(self, url):
        """Test for signature verification bypass vulnerabilities (based on Immunefi article)"""
        results = []
        
        # Smart contract function endpoints that might handle signature verification
        sig_endpoints = [
            '/api/verify', '/api/process', '/api/bridge', '/api/cross-chain',
            '/verify', '/process', '/bridge', '/validate', '/execute',
            '/api/v1/verify', '/api/v1/process', '/api/v1/bridge',
            '/contracts/verify', '/contracts/process', '/contracts/execute',
            '/validator/verify', '/validator/process', '/validator/enroll',
            '/threshold/set', '/commitment/update', '/domain/add'
        ]
        
        for endpoint in sig_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            # Test signature bypass payloads from the article
            for payload in self.web3_tests['signature_bypass']:
                try:
                    # Test both GET and POST
                    methods = [
                        ('POST', {'json': json.loads(payload) if payload.startswith('{') else {'data': payload}}),
                        ('GET', {'params': json.loads(payload) if payload.startswith('{') else {'q': payload}})
                    ]
                    
                    for method, kwargs in methods:
                        response = requests.request(method, test_url, timeout=self.timeout, 
                                                  verify=False, **kwargs)
                        
                        # Check for indicators of successful signature bypass
                        bypass_indicators = [
                            'signature verification bypassed', 'threshold is 0', 'no signatures required',
                            'commitment mismatch', 'validator not found', 'invalid threshold',
                            'processed without verification', 'bypass successful', 'verification skipped',
                            'message processed', 'transaction executed', 'cross-chain success',
                            'enrollValidator', 'setThreshold', '_updateCommitment'
                        ]
                        
                        for indicator in bypass_indicators:
                            if indicator.lower() in response.text.lower():
                                severity = 'Critical' if any(crit in indicator.lower() for crit in 
                                         ['bypassed', 'processed', 'executed', 'success']) else 'High'
                                
                                vuln = {
                                    'type': 'Smart Contract Signature Verification Bypass',
                                    'severity': severity,
                                    'url': test_url,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': f"Signature bypass indicator: {indicator}",
                                    'attack_vector': 'Zero threshold or commitment manipulation',
                                    'impact': 'Unauthorized transaction execution, fund theft, cross-chain attacks',
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.RED}[!] Signature verification bypass: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                        
                        # Check for successful responses to zero threshold attacks
                        if response.status_code == 200 and '0' in payload and 'threshold' in payload.lower():
                            vuln = {
                                'type': 'Potential Zero Threshold Vulnerability', 
                                'severity': 'High',
                                'url': test_url,
                                'method': method,
                                'payload': payload,
                                'evidence': 'Zero threshold payload accepted by endpoint',
                                'attack_vector': 'Threshold manipulation during validator enrollment',
                                'remediation': 'Add validation to ensure threshold > 0 in signature verification',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.YELLOW}[!] Potential zero threshold vuln: {test_url}{Style.RESET_ALL}")
                
                except Exception:
                    continue
        
        return results
    
    def test_cross_chain_vulnerabilities(self, url):
        """Test for cross-chain bridge and messaging vulnerabilities"""
        results = []
        
        # Cross-chain bridge endpoints
        bridge_endpoints = [
            '/bridge', '/cross-chain', '/relay', '/messenger', '/validator',
            '/api/bridge', '/api/cross-chain', '/api/relay', '/api/validator',
            '/v1/bridge', '/v1/cross-chain', '/contracts/bridge'
        ]
        
        for endpoint in bridge_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for payload in self.web3_tests['cross_chain_exploits']:
                try:
                    headers = {'Content-Type': 'application/json', 'User-Agent': 'VulnScanner/1.0'}
                    
                    response = requests.post(test_url, data=payload, headers=headers,
                                           timeout=self.timeout, verify=False)
                    
                    # Cross-chain vulnerability indicators
                    cross_chain_indicators = [
                        'domain added', 'validator enrolled', 'threshold set', 'commitment updated',
                        'message processed', 'cross-chain executed', 'bridge successful',
                        'frontrunning detected', 'race condition', 'invalid commitment',
                        'signature verification failed', 'threshold validation error'
                    ]
                    
                    for indicator in cross_chain_indicators:
                        if indicator.lower() in response.text.lower():
                            severity = 'Critical' if any(crit in indicator.lower() for crit in 
                                     ['executed', 'processed', 'successful', 'enrolled']) else 'High'
                            
                            vuln = {
                                'type': 'Cross-Chain Bridge Vulnerability',
                                'severity': severity,
                                'url': test_url,
                                'method': 'POST',
                                'payload': payload[:100] + '...',
                                'evidence': f"Cross-chain indicator: {indicator}",
                                'attack_vector': 'Frontrunning validator enrollment or threshold manipulation',
                                'impact': 'Unauthorized cross-chain message execution',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            print(f"{Fore.RED}[!] Cross-chain vulnerability: {test_url} - {indicator}{Style.RESET_ALL}")
                            break
                
                except Exception:
                    continue
        
        return results
    
    def test_commitment_manipulation(self, url):
        """Test for commitment hash manipulation vulnerabilities"""
        results = []
        
        commitment_payloads = [
            # Zero commitment hashes
            '0x0000000000000000000000000000000000000000000000000000000000000000',
            '0x',
            '',
            'null',
            
            # Invalid commitment formats
            '0xINVALID',
            '0x123',  # Too short
            '0x' + 'ff' * 33,  # Too long
            
            # Commitment manipulation attempts
            '{"commitment": "0x0000000000000000000000000000000000000000000000000000000000000000", "action": "verify"}',
            '{"_commitment": "", "_domain": 1, "_threshold": 0}',
        ]
        
        commitment_endpoints = [
            '/commitment', '/verify', '/validate', '/check',
            '/api/commitment', '/api/verify', '/contracts/commitment'
        ]
        
        for endpoint in commitment_endpoints:
            for payload in commitment_payloads:
                try:
                    test_url = f"{url.rstrip('/')}{endpoint}"
                    
                    # Test as parameter and in body
                    test_methods = [
                        ('GET', {'params': {'commitment': payload}}),
                        ('POST', {'data': {'commitment': payload}}),
                        ('POST', {'json': {'commitment': payload}}),
                    ]
                    
                    for method, kwargs in test_methods:
                        response = requests.request(method, test_url, timeout=self.timeout,
                                                  verify=False, **kwargs)
                        
                        # Look for commitment validation errors or bypasses
                        commitment_indicators = [
                            'commitment verified', 'commitment invalid', 'commitment mismatch',
                            'hash validation failed', 'commitment bypass', 'verification skipped'
                        ]
                        
                        for indicator in commitment_indicators:
                            if indicator.lower() in response.text.lower():
                                vuln = {
                                    'type': 'Commitment Hash Manipulation',
                                    'severity': 'Medium',
                                    'url': test_url,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': f"Commitment indicator: {indicator}",
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.YELLOW}[!] Commitment manipulation: {test_url} - {indicator}{Style.RESET_ALL}")
                                break
                
                except Exception:
                    continue
        
        return results
    
    def test_web3(self, targets):
        """Main Web3 testing function"""
        print(f"{Fore.YELLOW}[*] Starting Web3/Blockchain security testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing Web3 vulnerabilities: {url}{Style.RESET_ALL}")
            
            # Test RPC exposure
            rpc_vulns = self.test_rpc_exposure(url)
            all_vulnerabilities.extend(rpc_vulns)
            
            # Test private key exposure
            key_vulns = self.test_private_key_exposure(url)
            all_vulnerabilities.extend(key_vulns)
            
            # Test signature verification bypass (NEW - based on Immunefi article)
            sig_bypass_vulns = self.test_signature_verification_bypass(url)
            all_vulnerabilities.extend(sig_bypass_vulns)
            
            # Test cross-chain vulnerabilities (NEW)
            cross_chain_vulns = self.test_cross_chain_vulnerabilities(url)
            all_vulnerabilities.extend(cross_chain_vulns)
            
            # Test commitment manipulation (NEW)
            commitment_vulns = self.test_commitment_manipulation(url)
            all_vulnerabilities.extend(commitment_vulns)
            
            # Test DeFi vulnerabilities (moderate/extreme only)
            if self.level in ['moderate', 'extreme']:
                defi_vulns = self.test_defi_vulnerabilities(url)
                all_vulnerabilities.extend(defi_vulns)
                
                # Test smart contract exposure
                contract_vulns = self.test_smart_contract_exposure(url)
                all_vulnerabilities.extend(contract_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities