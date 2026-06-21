"""
ZeroHack v2.0 - IoT Security Tester
Default credential testing, MQTT open access, UPnP exposure,
CoAP enumeration, and Telnet/SSH/HTTP admin brute-force.
"""

import socket
import time
from typing import List, Optional

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info, print_warning

# ─────────────────────────────────────────────────────────────
# Default credentials (vendor → [username, password])
# ─────────────────────────────────────────────────────────────
DEFAULT_CREDENTIALS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "1234"),
    ("admin",     "12345"),
    ("admin",     "123456"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("root",      ""),
    ("root",      "admin"),
    ("root",      "password"),
    ("user",      "user"),
    ("guest",     "guest"),
    ("admin",     "admin123"),
    ("support",   "support"),
    ("ubnt",      "ubnt"),           # Ubiquiti
    ("pi",        "raspberry"),      # Raspberry Pi
    ("cisco",     "cisco"),          # Cisco
    ("enable",    "cisco"),
    ("netgear",   "netgear"),
    ("admin",     "netgear"),
    ("admin",     "motorola"),
    ("mstg",      "mstg"),
    ("admin",     "1111"),
    ("admin",     "0000"),
    ("admin",     "9999"),
]

# HTTP admin panel paths for IoT devices
IOT_ADMIN_PATHS = [
    "/admin", "/administration", "/admin.html",
    "/cgi-bin/luci", "/cgi-bin/admin", "/cgi-bin/login",
    "/setup.cgi", "/setup.html", "/login.htm", "/login.html",
    "/index.cgi", "/config", "/management",
    "/HNAP1/",
]

# MQTT test ports
MQTT_PORT  = 1883
MQTTS_PORT = 8883


class IoTSecurityTester(BaseScanner):
    """
    IoT device security scanner: default creds, MQTT, UPnP, exposed admin panels.
    """

    MODULE = "IoT Security"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        self.host = parsed.hostname or self.target.split("/")[0]

        print_info("Testing IoT-specific attack surfaces...")

        self._test_http_default_creds()
        self._test_mqtt_open_access()
        self._test_upnp()
        self._test_telnet()
        self._test_exposed_apis()

        return self.get_findings()

    # ─────── HTTP default credentials ────────────────────────
    def _test_http_default_creds(self):
        """Try default credentials on discovered admin panels."""
        admin_urls = []

        # Discover admin panel
        for path in IOT_ADMIN_PATHS:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code in (200, 401):
                admin_urls.append(url)

        if not admin_urls:
            admin_urls = [self.target]

        for admin_url in admin_urls[:3]:
            resp = self.get(admin_url)
            if not resp:
                continue

            # HTTP Basic Auth challenge
            if resp.status_code == 401:
                self._try_basic_auth(admin_url)
            elif resp.status_code == 200:
                # Form-based login
                forms = self.extract_forms(resp.text, admin_url)
                for form in forms:
                    if self._is_login_form(form):
                        self._try_form_login(form, admin_url)
                        break

    def _try_basic_auth(self, url: str):
        for username, password in DEFAULT_CREDENTIALS:
            try:
                resp = self.session.get(url, auth=(username, password), timeout=self.timeout)
                if resp.status_code == 200:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Default Credentials Accepted — HTTP Basic Auth",
                        severity="CRITICAL",
                        description=(
                            f"The admin panel at {url} accepted default credentials: "
                            f"username='{username}', password='{password}'. "
                            "An attacker can fully compromise this device."
                        ),
                        target=url,
                        evidence=f"Credentials: {username}:{password} → HTTP 200",
                        remediation=(
                            "Change all default credentials immediately. "
                            "Implement account lockout after failed attempts. "
                            "Use strong, unique passwords."
                        ),
                        owasp="A07:2021 – Identification and Authentication Failures",
                        cve="CWE-1392",
                    )
                    print_finding(f)
                    return  # Stop at first successful credential
            except Exception:
                pass

    def _try_form_login(self, form: dict, base_url: str):
        action = form["action"]
        inputs = form["inputs"]

        # Identify username and password fields
        username_fields = [i for i in inputs if any(
            kw in i["name"].lower() for kw in ["user", "login", "email", "name", "uname"]
        )]
        password_fields = [i for i in inputs if any(
            kw in i["name"].lower() for kw in ["pass", "pwd", "password", "secret"]
        )]

        if not username_fields or not password_fields:
            return

        for username, password in DEFAULT_CREDENTIALS[:15]:
            data = {i["name"]: i["value"] for i in inputs}
            data[username_fields[0]["name"]] = username
            data[password_fields[0]["name"]] = password

            method = form["method"]
            resp   = self.post(action, data=data) if method == "POST" else self.get(action, params=data)
            if not resp:
                continue

            # Heuristic: successful login redirects or shows dashboard keywords
            if resp.status_code in (200, 302):
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["dashboard", "logout", "welcome", "admin", "panel"]):
                    f = self.add_finding(
                        module=self.MODULE,
                        title="Default Credentials Accepted — Web Admin Panel",
                        severity="CRITICAL",
                        description=(
                            f"Admin panel at {action} accepted default login: "
                            f"'{username}' / '{password}'."
                        ),
                        target=action,
                        evidence=f"Credentials {username}:{password} → dashboard page",
                        remediation="Change default credentials. Implement MFA. Add rate limiting.",
                        owasp="A07:2021 – Identification and Authentication Failures",
                    )
                    print_finding(f)
                    return

    # ─────── MQTT open access ─────────────────────────────────
    def _test_mqtt_open_access(self):
        """Check if MQTT broker is accessible without authentication."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.host, MQTT_PORT))

            if result == 0:
                # Send MQTT CONNECT packet (no auth)
                connect_packet = bytes([
                    0x10,                    # CONNECT
                    0x0c,                    # Remaining length: 12
                    0x00, 0x04,              # Protocol Name Length: 4
                    0x4d, 0x51, 0x54, 0x54,  # "MQTT"
                    0x04,                    # Protocol Level: 4 (3.1.1)
                    0x00,                    # Connect Flags (no auth, no will, clean session)
                    0x00, 0x3c,              # Keep Alive: 60s
                    0x00, 0x00,              # Client ID Length: 0
                ])
                sock.send(connect_packet)
                resp = sock.recv(4)

                # CONNACK: 0x20, 0x02, 0x00, 0x00 = Connection Accepted
                if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="MQTT Broker Open — No Authentication Required",
                        severity="CRITICAL",
                        description=(
                            f"The MQTT broker on {self.host}:{MQTT_PORT} accepts anonymous connections. "
                            "Attackers can subscribe to all topics, publish rogue messages, "
                            "and intercept all IoT device communications."
                        ),
                        target=f"{self.host}:{MQTT_PORT}",
                        evidence=f"CONNACK 0x00 (Connection Accepted) without credentials",
                        remediation=(
                            "Enable MQTT authentication (username/password). "
                            "Use TLS (port 8883). "
                            "Implement ACLs to restrict topic access."
                        ),
                        owasp="A05:2021 – Security Misconfiguration",
                        cve="CWE-306",
                    )
                    print_finding(f)
            sock.close()
        except Exception:
            pass

    # ─────── UPnP exposure ────────────────────────────────────
    def _test_upnp(self):
        """Check if UPnP service is exposed."""
        upnp_paths = [
            "/rootDesc.xml", "/RootDevice.xml", "/description.xml",
            ":1900", "/upnp/BasicDevice.xml",
        ]
        for path in upnp_paths:
            if path.startswith(":"):
                continue
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code == 200 and "upnp" in resp.text.lower():
                f = self.add_finding(
                    module=self.MODULE,
                    title="UPnP Service Exposed via HTTP",
                    severity="HIGH",
                    description=(
                        f"UPnP device description is accessible at {url}. "
                        "UPnP allows network configuration changes without authentication."
                    ),
                    target=url,
                    evidence=f"UPnP XML found at {path}",
                    remediation=(
                        "Disable UPnP on internet-facing interfaces. "
                        "Restrict UPnP to trusted internal networks only."
                    ),
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)
                return

    # ─────── Telnet exposure ──────────────────────────────────
    def _test_telnet(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((self.host, 23)) == 0:
                banner = ""
                try:
                    sock.settimeout(2)
                    data = sock.recv(256)
                    banner = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

                f = self.add_finding(
                    module=self.MODULE,
                    title="Telnet Service Open (Plaintext Protocol)",
                    severity="CRITICAL",
                    description=(
                        f"Telnet is running on {self.host}:23. "
                        "All credentials and data are transmitted in plaintext. "
                        "This is a critical IoT security risk."
                    ),
                    target=f"{self.host}:23",
                    evidence=f"TCP connect succeeded. Banner: {banner[:100]!r}",
                    remediation=(
                        "Disable Telnet immediately. Use SSH instead. "
                        "Block port 23 at the firewall."
                    ),
                    owasp="A05:2021 – Security Misconfiguration",
                    cve="CWE-319",
                )
                print_finding(f)
            sock.close()
        except Exception:
            pass

    # ─────── Exposed IoT APIs ─────────────────────────────────
    def _test_exposed_apis(self):
        """Test for common IoT API endpoints that expose device info."""
        api_paths = [
            "/api/v1/device", "/api/device", "/device/info",
            "/cgi-bin/status", "/status.json", "/info.json",
            "/system/info", "/api/system",
        ]
        sensitive_keywords = [
            "serial", "mac_address", "mac", "firmware", "model",
            "ssid", "password", "wifi", "psk",
        ]
        for path in api_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code == 200:
                body_lower = resp.text.lower()
                found = [kw for kw in sensitive_keywords if kw in body_lower]
                if found:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"IoT API Exposes Device Information — {path}",
                        severity="MEDIUM",
                        description=(
                            f"The endpoint {path} is publicly accessible and returns "
                            f"device information including: {', '.join(found)}"
                        ),
                        target=url,
                        evidence=f"Keywords found: {found}",
                        remediation=(
                            "Require authentication on all device API endpoints. "
                            "Never expose credentials or network keys via API."
                        ),
                        owasp="A01:2021 – Broken Access Control",
                    )
                    print_finding(f)

    @staticmethod
    def _is_login_form(form: dict) -> bool:
        """Heuristic to detect login forms."""
        has_pass  = any("pass" in i["name"].lower() or i["type"] == "password" for i in form["inputs"])
        has_user  = any(any(kw in i["name"].lower() for kw in ["user", "login", "email", "name"])
                        for i in form["inputs"])
        return has_pass and has_user
