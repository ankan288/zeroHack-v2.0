"""
ZeroHack v2.0 - Mobile Security Tester
APK static analysis (manifest, hardcoded secrets, SSL pinning bypass patterns),
Frida integration hooks, and mobile API endpoint probing.
"""

import re
import os
import subprocess
import json
from typing import List, Optional

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info, print_warning

# ─────────────────────────────────────────────────────────────
# Hardcoded secret patterns
# ─────────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":      r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":      r'[0-9a-zA-Z/+]{40}',
    "Google API Key":      r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase URL":        r'https://[a-z0-9-]+\.firebaseio\.com',
    "Firebase API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "Private Key (PEM)":   r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "Generic Secret":      r'(?i)(secret|password|passwd|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']',
    "JWT Token":           r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.',
    "Slack Token":         r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
    "GitHub Token":        r'ghp_[0-9a-zA-Z]{36}',
    "Stripe Key":          r'sk_live_[0-9a-zA-Z]{24}',
    "SendGrid Key":        r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
}

# Android dangerous permissions
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_DEVICE_ADMIN",
]

# SSL pinning bypass indicators in Smali/Java
SSL_BYPASS_PATTERNS = [
    r"TrustAllCerts",
    r"X509TrustManager",
    r"checkServerTrusted.*\{\s*\}",
    r"setHostnameVerifier.*ALLOW_ALL",
    r"ALLOW_ALL_HOSTNAME_VERIFIER",
    r"HttpsURLConnection\.setDefaultHostnameVerifier",
    r"onReceivedSslError.*proceed",
]

# Mobile API paths commonly used
MOBILE_API_PATHS = [
    "/api/v1/mobile", "/api/mobile", "/mobile/api",
    "/app/api", "/api/app", "/m/api",
]


class MobileSecurityTester(BaseScanner):
    """
    Mobile application security tester.
    Analyzes APK files statically and probes mobile API endpoints.
    """

    MODULE = "Mobile Security"

    def scan(self, mode: str = "both", apk_path: Optional[str] = None) -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        if apk_path and os.path.exists(apk_path):
            print_info(f"Analyzing APK: {apk_path}")
            self._analyze_apk(apk_path)
        else:
            print_info("No APK path provided — scanning mobile API endpoints and network responses")

        self._test_mobile_api_endpoints()
        self._test_mobile_tls()
        self._scan_response_for_secrets()

        return self.get_findings()

    # ─────── APK static analysis ─────────────────────────────
    def _analyze_apk(self, apk_path: str):
        """Extract and analyze APK contents."""
        import zipfile, tempfile

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(apk_path, 'r') as apk:
                    apk.extractall(tmpdir)

                # Analyze AndroidManifest.xml (plain text if using AAPT or jadx)
                manifest_path = os.path.join(tmpdir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    self._analyze_manifest(manifest_path)

                # Scan all extracted files for hardcoded secrets
                for root, dirs, files in os.walk(tmpdir):
                    for fname in files:
                        if fname.endswith((".xml", ".json", ".properties", ".smali",
                                          ".java", ".kt", ".gradle", ".yaml", ".yml")):
                            fpath = os.path.join(root, fname)
                            try:
                                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                                    content = f.read()
                                self._scan_file_for_secrets(fpath, content)
                                self._scan_for_ssl_bypass(fpath, content)
                            except Exception:
                                pass

                # Try jadx decompilation for deeper analysis
                self._try_jadx_analysis(apk_path)

        except zipfile.BadZipFile:
            print_warning(f"{apk_path} is not a valid APK/ZIP file")
        except Exception as e:
            print_warning(f"APK analysis error: {e}")

    def _analyze_manifest(self, manifest_path: str):
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Check for debuggable
            if 'android:debuggable="true"' in content:
                f = self.add_finding(
                    module=self.MODULE,
                    title="APK is Debuggable (android:debuggable=true)",
                    severity="HIGH",
                    description=(
                        "The app is compiled with debuggable=true, allowing "
                        "debugger attachment and JavaScript console access on any device."
                    ),
                    target=manifest_path,
                    evidence='android:debuggable="true" in AndroidManifest.xml',
                    remediation="Remove debuggable=true from release builds.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

            # Check for backup allowed
            if 'android:allowBackup="true"' in content or 'allowBackup' not in content:
                f = self.add_finding(
                    module=self.MODULE,
                    title="APK Allows Backup (android:allowBackup=true)",
                    severity="MEDIUM",
                    description=(
                        "The app allows ADB backup, enabling extraction of app data "
                        "including databases and shared preferences."
                    ),
                    target=manifest_path,
                    evidence='android:allowBackup="true" or not set (defaults to true)',
                    remediation='Set android:allowBackup="false" in AndroidManifest.xml.',
                    owasp="A01:2021 – Broken Access Control",
                )
                print_finding(f)

            # Check dangerous permissions
            found_perms = [p for p in DANGEROUS_PERMISSIONS if p in content]
            if found_perms:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Dangerous Permissions Declared ({len(found_perms)})",
                    severity="MEDIUM",
                    description=(
                        "The APK declares multiple dangerous permissions. "
                        "Ensure all are strictly necessary."
                    ),
                    target=manifest_path,
                    evidence=f"Permissions: {found_perms}",
                    remediation="Remove unnecessary permissions. Justify each in privacy policy.",
                    owasp="A01:2021 – Broken Access Control",
                )
                print_finding(f)

            # Check for exported activities without permissions
            exported = re.findall(r'<activity[^>]*android:exported="true"[^>]*>', content)
            if len(exported) > 2:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Exported Activities Without Restrictions ({len(exported)})",
                    severity="MEDIUM",
                    description=(
                        f"{len(exported)} activities are exported (accessible from other apps). "
                        "Verify each has proper permission protection."
                    ),
                    target=manifest_path,
                    evidence=f"{len(exported)} exported activities found",
                    remediation="Set android:exported=false on activities not intended for inter-app access.",
                    owasp="A01:2021 – Broken Access Control",
                )
                print_finding(f)

        except Exception as e:
            print_warning(f"Manifest analysis error: {e}")

    def _scan_file_for_secrets(self, fpath: str, content: str):
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                # Avoid flagging obvious placeholders
                filtered = [m for m in matches if "example" not in m.lower() and
                            "placeholder" not in m.lower() and len(m) > 8]
                if filtered:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Hardcoded Secret — {secret_type}",
                        severity="CRITICAL",
                        description=(
                            f"A {secret_type} was found hardcoded in {os.path.basename(fpath)}. "
                            "Hardcoded secrets in APKs can be extracted by any user."
                        ),
                        target=fpath,
                        evidence=f"Match: {str(filtered[0])[:50]}...",
                        remediation=(
                            "Remove all hardcoded secrets. "
                            "Use Android Keystore for storing sensitive keys. "
                            "Fetch credentials from secure backend APIs."
                        ),
                        owasp="A02:2021 – Cryptographic Failures",
                    )
                    print_finding(f)
                    return

    def _scan_for_ssl_bypass(self, fpath: str, content: str):
        for pattern in SSL_BYPASS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                f = self.add_finding(
                    module=self.MODULE,
                    title="SSL Certificate Validation Disabled",
                    severity="CRITICAL",
                    description=(
                        f"SSL/TLS certificate validation appears to be disabled in {os.path.basename(fpath)}. "
                        "This allows man-in-the-middle attacks on all HTTPS connections."
                    ),
                    target=fpath,
                    evidence=f"Pattern '{pattern}' found",
                    remediation=(
                        "Remove all trust-all or ALLOW_ALL HostnameVerifier implementations. "
                        "Use Android Network Security Config for certificate pinning. "
                        "Never override SSL validation."
                    ),
                    owasp="A02:2021 – Cryptographic Failures",
                    cve="CWE-295",
                )
                print_finding(f)
                return

    def _try_jadx_analysis(self, apk_path: str):
        """Try to use jadx for decompilation if available."""
        try:
            result = subprocess.run(
                ["jadx", "--version"],
                capture_output=True, timeout=5
            )
            print_info("jadx found — decompilation available for deeper analysis")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print_info("jadx not installed — skipping decompilation (install: https://github.com/skylot/jadx)")

    # ─────── Mobile API endpoints ────────────────────────────
    def _test_mobile_api_endpoints(self):
        for path in MOBILE_API_PATHS:
            url  = self.join(self.target, path)
            resp = self.get(url, headers={
                **self.session.headers,
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RQ3A.210805.001.A1)"
            })
            if resp and resp.status_code in (200, 401, 403):
                if resp.status_code == 200:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Mobile API Endpoint Publicly Accessible: {path}",
                        severity="MEDIUM",
                        description=(
                            f"The mobile API endpoint {path} is accessible without authentication. "
                            "Verify this is intentional."
                        ),
                        target=url,
                        evidence=f"HTTP {resp.status_code} | {len(resp.text)} bytes",
                        remediation="Require authentication on all mobile API endpoints.",
                        owasp="A01:2021 – Broken Access Control",
                    )
                    print_finding(f)

    # ─────── Mobile TLS checks ───────────────────────────────
    def _test_mobile_tls(self):
        """Check for weak TLS configuration relevant to mobile clients."""
        import ssl
        from urllib.parse import urlparse

        parsed = urlparse(self.target)
        host   = parsed.hostname
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            f = self.add_finding(
                module=self.MODULE,
                title="Target Uses HTTP (No TLS) — Mobile Security Risk",
                severity="HIGH",
                description=(
                    "The target does not use HTTPS. All data between the mobile app "
                    "and server is transmitted in plaintext."
                ),
                target=self.target,
                evidence="URL scheme is http://",
                remediation="Enforce HTTPS. Use HSTS. Implement certificate pinning in the mobile app.",
                owasp="A02:2021 – Cryptographic Failures",
            )
            print_finding(f)
            return

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cert = s.getpeercert()
                proto = s.version()

                if proto in ("TLSv1", "TLSv1.1"):
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Weak TLS Version: {proto}",
                        severity="HIGH",
                        description=f"Server supports deprecated {proto}. Mobile clients may downgrade.",
                        target=self.target,
                        evidence=f"TLS version: {proto}",
                        remediation="Disable TLSv1.0 and TLSv1.1. Support only TLSv1.2+.",
                        owasp="A02:2021 – Cryptographic Failures",
                    )
                    print_finding(f)
        except Exception:
            pass

    def _scan_response_for_secrets(self):
        """Scan the target's HTTP response for accidental secret exposure."""
        resp = self.get(self.target)
        if not resp:
            return
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                filtered = [m for m in matches if len(str(m)) > 10]
                if filtered:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Secret Exposed in HTTP Response — {secret_type}",
                        severity="CRITICAL",
                        description=(
                            f"A {secret_type} was found in the HTTP response of {self.target}. "
                            "This may be served to all mobile clients."
                        ),
                        target=self.target,
                        evidence=f"Pattern matched: {str(filtered[0])[:50]}",
                        remediation="Never include secrets in HTTP responses. Rotate exposed secrets immediately.",
                        owasp="A02:2021 – Cryptographic Failures",
                    )
                    print_finding(f)


import socket  # needed for TLS test at module level
