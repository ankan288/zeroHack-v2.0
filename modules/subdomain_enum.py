"""
ZeroHack v2.0 - Subdomain Enumeration
DNS brute-force wordlist enumeration, Certificate Transparency (crt.sh) queries,
wildcard DNS detection, A/CNAME record resolution.
"""

import socket
import threading
import time
from typing import List, Set, Optional

from modules.notification_system import Finding, print_module_start, print_finding, print_info, print_warning

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Subdomain wordlist (top ~250 common subdomains)
# ─────────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "blog", "webdisk", "vpn", "m", "shop", "forum", "news",
    "web", "dev", "staging", "stage", "test", "demo", "api", "admin",
    "app", "apps", "beta", "portal", "secure", "server", "static", "cdn",
    "store", "media", "images", "img", "video", "download", "downloads",
    "login", "signin", "auth", "sso", "oauth", "id", "identity",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "git", "gitlab", "github", "jira", "confluence", "wiki",
    "ci", "jenkins", "travis", "build", "deploy", "docker",
    "k8s", "kubernetes", "grafana", "prometheus", "kibana",
    "internal", "corp", "intranet", "extranet", "private",
    "sandbox", "uat", "prod", "production", "alpha", "preview",
    "monitoring", "status", "health", "metrics", "logs",
    "smtp", "imap", "pop3", "mx", "mail2", "email",
    "support", "help", "helpdesk", "desk", "chat", "live",
    "old", "legacy", "backup", "archive", "bak",
    "dev2", "dev3", "test2", "stage2", "staging2",
    "api2", "api3", "apiv2", "apiv3",
    "mobile", "android", "ios", "app2",
    "ws", "wss", "socket", "push", "webhook",
    "remote", "vpn2", "gateway",
    "data", "files", "assets", "upload", "uploads",
]


class SubdomainEnumerator:
    """
    Subdomain enumerator: DNS brute-force + crt.sh CT logs.
    """

    MODULE = "Subdomain Enumeration"

    def __init__(self, target: str, max_workers: int = 50, timeout: float = 3.0):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.domain = parsed.hostname or target.replace("http://", "").replace("https://", "").split("/")[0]
        self.max_workers = max_workers
        self.timeout     = timeout
        self.findings: List[Finding] = []
        self._found: Set[str] = set()
        self._lock = threading.Lock()

        # Detect wildcard DNS
        self._wildcard_ip: Optional[str] = self._detect_wildcard()

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.domain)
        self.findings.clear()
        self._found.clear()

        if self._wildcard_ip:
            print_warning(f"Wildcard DNS detected ({self._wildcard_ip}) — results may include false positives")

        # 1. Certificate Transparency via crt.sh
        ct_subs = self._fetch_crtsh()
        print_info(f"crt.sh returned {len(ct_subs)} unique subdomain(s)")
        for sub in ct_subs:
            self._resolve_and_add(sub)

        # 2. DNS brute-force
        print_info(f"Brute-forcing {len(SUBDOMAIN_WORDLIST)} subdomain(s)...")
        self._brute_force_dns()

        return self.get_findings()

    def get_findings(self) -> List[Finding]:
        return list(self.findings)

    # ─────── Wildcard detection ───────────────────────────────
    def _detect_wildcard(self) -> Optional[str]:
        """Check if *.domain resolves (wildcard DNS)."""
        test_sub = f"zerohack-nonexistent-{int(time.time())}.{self.domain}"
        try:
            ip = socket.gethostbyname(test_sub)
            return ip
        except socket.gaierror:
            return None

    # ─────── crt.sh (Certificate Transparency) ───────────────
    def _fetch_crtsh(self) -> Set[str]:
        if not REQUESTS_AVAILABLE:
            print_warning("requests not installed — skipping crt.sh")
            return set()
        try:
            url  = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                return set()
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{self.domain}") and "*" not in line:
                        subs.add(line)
            return subs
        except Exception as e:
            print_warning(f"crt.sh failed: {e}")
            return set()

    # ─────── DNS brute-force ──────────────────────────────────
    def _brute_force_dns(self):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        subdomains = [f"{w}.{self.domain}" for w in SUBDOMAIN_WORDLIST]

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._resolve_and_add, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def _resolve_and_add(self, subdomain: str):
        """Resolve a subdomain and add a finding if it exists."""
        try:
            if DNS_AVAILABLE:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                answers = resolver.resolve(subdomain, "A")
                ips = [r.address for r in answers]
            else:
                ips = [socket.gethostbyname(subdomain)]

            # Skip wildcard hits
            if self._wildcard_ip and all(ip == self._wildcard_ip for ip in ips):
                return

            with self._lock:
                if subdomain in self._found:
                    return
                self._found.add(subdomain)

            # Try HTTP to get title/status
            status, title = self._probe_http(subdomain)

            severity = "INFO"
            desc = f"Subdomain {subdomain} resolves to: {', '.join(ips)}"
            if title:
                desc += f" | HTTP title: {title}"

            # Flag internal-looking or sensitive subdomains higher
            sensitive_keywords = ["dev", "staging", "test", "admin", "internal",
                                   "corp", "db", "database", "prod", "api", "jenkins",
                                   "gitlab", "jira", "monitor"]
            if any(kw in subdomain.lower() for kw in sensitive_keywords):
                severity = "MEDIUM"

            f = Finding(
                module=self.MODULE,
                title=f"Subdomain Found: {subdomain}",
                severity=severity,
                description=desc,
                target=f"https://{subdomain}" if status else subdomain,
                evidence=f"DNS: {', '.join(ips)} | HTTP {status or 'no response'} | Title: {title or 'N/A'}",
                remediation=(
                    "Review and remove unused subdomains. "
                    "Ensure sensitive subdomains are not publicly accessible. "
                    "Monitor for subdomain takeover (dangling DNS)."
                ),
            )
            with self._lock:
                self.findings.append(f)
            print_finding(f)

        except (socket.gaierror, Exception):
            pass  # Subdomain doesn't resolve

    @staticmethod
    def _probe_http(subdomain: str):
        """Quick HTTP probe to get status and page title."""
        if not REQUESTS_AVAILABLE:
            return None, None
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=4,
                    verify=False,
                    allow_redirects=True,
                )
                import re
                title_m = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
                title   = title_m.group(1).strip()[:80] if title_m else None
                return resp.status_code, title
            except Exception:
                pass
        return None, None
