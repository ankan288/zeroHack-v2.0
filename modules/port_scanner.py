"""
ZeroHack v2.0 - Port Scanner
TCP connect scan with banner grabbing, service identification, OS fingerprinting,
and side-by-side Nmap comparison output.
"""

import socket
import ssl
import subprocess
import threading
import time
import json
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.notification_system import Finding, print_module_start, print_finding, print_info, print_warning

# ─────────────────────────────────────────────────────────────
# Top 1000 common ports (compressed — top 200 for speed)
# ─────────────────────────────────────────────────────────────
TOP_200_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443, 445,
    465, 500, 512, 513, 514, 543, 544, 587, 631, 636, 873, 990, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2483, 2484, 2967, 3000, 3306, 3389, 3690, 4333, 4444, 4567, 4848, 5000,
    5432, 5555, 5672, 5900, 5984, 6379, 6443, 6660, 6661, 6662, 6663, 6664,
    6665, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7070, 7443, 7777, 7778,
    8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8118, 8123, 8443, 8444, 8500, 8888, 8983, 9000, 9001, 9042,
    9090, 9091, 9200, 9300, 9418, 9999, 10000, 10443, 11211, 15672, 16010,
    16000, 17000, 17001, 18080, 18081, 20000, 27017, 27018, 28017, 50000,
    50030, 50060, 50070, 50075, 50090, 60000, 60010, 60030,
]

# Service / port mapping
SERVICE_MAP = {
    21:    "FTP",          22:    "SSH",           23:    "Telnet",
    25:    "SMTP",         53:    "DNS",            80:    "HTTP",
    110:   "POP3",         111:   "RPC",            119:   "NNTP",
    135:   "MSRPC",        139:   "NetBIOS",        143:   "IMAP",
    443:   "HTTPS",        445:   "SMB",            465:   "SMTPS",
    512:   "rexec",        513:   "rlogin",         514:   "rsh/syslog",
    587:   "SMTP (TLS)",   636:   "LDAPS",          873:   "rsync",
    993:   "IMAPS",        995:   "POP3S",          1080:  "SOCKS Proxy",
    1194:  "OpenVPN",      1433:  "MSSQL",          1521:  "Oracle DB",
    1723:  "PPTP VPN",     2049:  "NFS",            2082:  "cPanel",
    3000:  "Node.js/Dev",  3306:  "MySQL",          3389:  "RDP",
    3690:  "SVN",          5000:  "Flask/Dev",      5432:  "PostgreSQL",
    5555:  "ADB (Android)",5672:  "RabbitMQ",       5900:  "VNC",
    5984:  "CouchDB",      6379:  "Redis",          6443:  "Kubernetes API",
    7001:  "WebLogic",     8000:  "HTTP Alt",       8080:  "HTTP Proxy",
    8443:  "HTTPS Alt",    8888:  "Jupyter/HTTP",   8983:  "Solr",
    9000:  "PHP-FPM/SonarQube", 9042: "Cassandra", 9200:  "Elasticsearch",
    9300:  "Elasticsearch Transport", 10000: "Webmin",
    11211: "Memcached",    15672: "RabbitMQ Mgmt",  27017: "MongoDB",
    28017: "MongoDB HTTP",
}

# Risk classification for open ports
HIGH_RISK_PORTS = {23, 512, 513, 514, 2049, 11211, 6379, 27017, 28017, 5984, 9200, 5900}
MEDIUM_RISK_PORTS = {21, 110, 119, 1080, 3306, 1433, 1521, 5432, 3389, 5672, 6443}


class PortScanner:
    """
    TCP connect port scanner with banner grabbing,
    service identification, and Nmap comparison.
    """

    MODULE = "Port Scanner"

    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 timeout: float = 1.5, max_workers: int = 150):
        # Strip http/https scheme if present
        self.target_raw = target
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            self.host = parsed.hostname or target
        else:
            self.host = target

        self.ports      = ports or TOP_200_PORTS
        self.timeout    = timeout
        self.max_workers = max_workers
        self.findings: List[Finding] = []
        self._lock = threading.Lock()

    def scan(self, mode: str = "both") -> List[Finding]:
        """Run the port scan. mode: 'async'|'sync'|'both'"""
        print_module_start(self.MODULE, self.host)
        self.findings.clear()

        print_info(f"Scanning {len(self.ports)} ports on {self.host} (workers: {self.max_workers})")

        open_ports: List[Dict] = []

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        elapsed = time.perf_counter() - start
        open_ports.sort(key=lambda x: x["port"])

        print_info(f"Scan completed in {elapsed:.2f}s — {len(open_ports)} open port(s)")

        # Generate findings
        for port_info in open_ports:
            self._generate_finding(port_info)

        # Nmap comparison (if nmap is installed)
        self._compare_with_nmap(open_ports)

        return self.get_findings()

    def get_findings(self) -> List[Finding]:
        return list(self.findings)

    # ─────── Single port scan ────────────────────────────────
    def _scan_port(self, port: int) -> Optional[Dict]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.host, port))
            if result == 0:
                banner  = self._grab_banner(sock, port)
                service = SERVICE_MAP.get(port, self._detect_service_from_banner(banner))
                return {
                    "port":    port,
                    "state":   "open",
                    "service": service,
                    "banner":  banner,
                }
            return None
        except (socket.timeout, socket.error, OSError):
            return None
        finally:
            sock.close()

    # ─────── Banner grabbing ──────────────────────────────────
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            # Send a probe for common text protocols
            if port in (80, 8080, 8000, 8888):
                sock.send(b"GET / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            else:
                sock.send(b"\r\n")

            sock.settimeout(1.5)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:300]  # Truncate
        except Exception:
            return ""

    @staticmethod
    def _detect_service_from_banner(banner: str) -> str:
        b = banner.lower()
        if "ssh" in b:         return "SSH"
        if "ftp" in b:         return "FTP"
        if "smtp" in b:        return "SMTP"
        if "http" in b:        return "HTTP"
        if "mysql" in b:       return "MySQL"
        if "postgresql" in b:  return "PostgreSQL"
        if "redis" in b:       return "Redis"
        if "mongodb" in b:     return "MongoDB"
        return "Unknown"

    # ─────── Finding generation ───────────────────────────────
    def _generate_finding(self, port_info: Dict):
        port    = port_info["port"]
        service = port_info["service"]
        banner  = port_info["banner"]

        if port in HIGH_RISK_PORTS:
            severity = "HIGH"
            description = (
                f"Port {port}/{service} is open and is considered HIGH RISK. "
                "This service should not be publicly accessible."
            )
        elif port in MEDIUM_RISK_PORTS:
            severity = "MEDIUM"
            description = f"Port {port}/{service} is open. Ensure access is restricted to authorized hosts only."
        else:
            severity = "INFO"
            description = f"Port {port}/{service} is open."

        remediation = self._get_remediation(port, service)

        f = Finding(
            module=self.MODULE,
            title=f"Open Port {port}/{service}",
            severity=severity,
            description=description,
            target=f"{self.host}:{port}",
            evidence=f"Banner: {banner[:100]!r}" if banner else f"TCP connect to {self.host}:{port} succeeded",
            remediation=remediation,
            owasp="A05:2021 – Security Misconfiguration",
        )
        with self._lock:
            self.findings.append(f)
        print_finding(f)

    @staticmethod
    def _get_remediation(port: int, service: str) -> str:
        tips = {
            23:    "Disable Telnet immediately. Use SSH instead.",
            512:   "Disable rexec. Use SSH.",
            513:   "Disable rlogin. Use SSH.",
            514:   "Block rsh. Use SSH. Filter syslog to internal only.",
            6379:  "Bind Redis to 127.0.0.1. Require authentication. Never expose publicly.",
            9200:  "Restrict Elasticsearch with firewall rules. Enable X-Pack security.",
            27017: "Bind MongoDB to localhost. Enable authentication. Use a firewall.",
            11211: "Bind Memcached to localhost. Never expose publicly.",
            5900:  "Use VNC over SSH tunnel. Require strong password.",
            3389:  "Use RDP over VPN only. Enable NLA. Patch regularly.",
            2049:  "Restrict NFS exports. Use NFSv4 with Kerberos.",
            5984:  "Enable CouchDB authentication. Disable admin party mode.",
        }
        return tips.get(port, f"Restrict port {port} to trusted IP ranges. Use a firewall.")

    # ─────── Nmap comparison ─────────────────────────────────
    def _compare_with_nmap(self, zerohack_results: List[Dict]):
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--open", "-p",
                 ",".join(str(p) for p in self.ports[:100]),
                 self.host, "-oX", "-"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print_warning("Nmap not available or failed — skipping comparison")
                return

            # Parse nmap XML output
            nmap_ports = self._parse_nmap_xml(result.stdout)
            zerohack_port_nums = {p["port"] for p in zerohack_results}
            nmap_port_nums     = set(nmap_ports.keys())

            missed_by_zh = nmap_port_nums - zerohack_port_nums
            found_by_zh_only = zerohack_port_nums - nmap_port_nums

            if missed_by_zh:
                print_warning(f"Ports found by Nmap but missed by ZeroHack: {sorted(missed_by_zh)}")
            if found_by_zh_only:
                print_info(f"Ports found by ZeroHack only (not in Nmap): {sorted(found_by_zh_only)}")
            if not missed_by_zh and not found_by_zh_only:
                from modules.notification_system import print_success
                print_success("ZeroHack port results match Nmap perfectly ✓")

            # Add comparison summary as INFO finding
            f = Finding(
                module=self.MODULE,
                title="Nmap Comparison Result",
                severity="INFO",
                description=(
                    f"ZeroHack found {len(zerohack_port_nums)} open port(s). "
                    f"Nmap found {len(nmap_port_nums)}. "
                    f"Missed by ZeroHack: {sorted(missed_by_zh) or 'none'}. "
                    f"ZeroHack-only: {sorted(found_by_zh_only) or 'none'}."
                ),
                target=self.host,
                evidence=f"ZeroHack ports: {sorted(zerohack_port_nums)} | Nmap ports: {sorted(nmap_port_nums)}",
                remediation="N/A — informational comparison",
            )
            with self._lock:
                self.findings.append(f)

        except FileNotFoundError:
            print_warning("Nmap not installed — skipping comparison. Install with: apt install nmap")
        except subprocess.TimeoutExpired:
            print_warning("Nmap timed out — skipping comparison")
        except Exception as e:
            print_warning(f"Nmap comparison error: {e}")

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> Dict[int, str]:
        import xml.etree.ElementTree as ET
        ports = {}
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        portid  = int(port_el.get("portid", 0))
                        service = port_el.find("service")
                        svc_name = service.get("name", "unknown") if service is not None else "unknown"
                        ports[portid] = svc_name
        except ET.ParseError:
            pass
        return ports
