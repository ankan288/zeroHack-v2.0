"""
ZeroHack v2.0 - Enhanced Base Scanner
HTTP session management, async + sync request helpers, WAF detection, rate limiting.
"""

import time
import random
import asyncio
import threading
from typing import Optional, Dict, List, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from modules.notification_system import Finding, print_info, print_error, print_warning

# ─────────────────────────────────────────────
# Default headers mimicking a real browser
# ─────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

# ─────────────────────────────────────────────
# WAF signatures
# ─────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "__cfduid", "cloudflare"],
    "AWS WAF":      ["x-amzn-requestid", "awselb"],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "Akamai":       ["akamai", "ak_bmsc"],
    "Imperva":      ["imperva", "incapsula", "_incap_ses"],
    "F5 BIG-IP":    ["bigip", "f5_st", "ts"],
    "Sucuri":       ["sucuri", "x-sucuri-id"],
    "Barracuda":    ["barra_counter_session"],
}


class BaseScanner:
    """
    Reusable base scanner that manages HTTP sessions, WAF detection,
    and provides both sync/async request utilities.
    """

    def __init__(self, target: str, timeout: int = 10, delay: float = 0.5,
                 verify_ssl: bool = False, cookies: Optional[Dict] = None,
                 headers: Optional[Dict] = None, proxy: Optional[str] = None,
                 rotate_ua: bool = False, max_workers: int = 10):
        self.target      = target.rstrip("/")
        self.timeout     = timeout
        self.delay       = delay
        self.verify_ssl  = verify_ssl
        self.cookies     = cookies or {}
        self.extra_headers = headers or {}
        self.proxy       = {"http": proxy, "https": proxy} if proxy else None
        self.rotate_ua   = rotate_ua
        self.max_workers = max_workers
        self.findings: List[Finding] = []
        self._lock = threading.Lock()

        # Build session
        self.session = requests.Session()
        self.session.verify  = verify_ssl
        self.session.cookies.update(self.cookies)
        merged = {**DEFAULT_HEADERS, **self.extra_headers}
        self.session.headers.update(merged)
        if proxy:
            self.session.proxies = self.proxy

        # Parse base URL
        parsed = urlparse(self.target)
        self.base_scheme = parsed.scheme
        self.base_host   = parsed.netloc
        self.base_path   = parsed.path

    # ── WAF detection ──────────────────────────────────────────────
    def detect_waf(self) -> Optional[str]:
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body_lower    = resp.text.lower()

            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig in headers_lower or sig in body_lower:
                        return waf

            # Check status code after sending a known-bad payload
            probe = self.session.get(
                self.target + "/?q=<script>alert(1)</script>&id=1'--",
                timeout=self.timeout
            )
            if probe.status_code in (403, 406, 501):
                return "Unknown WAF (blocked probe)"
        except Exception:
            pass
        return None

    # ── Request helpers ───────────────────────────────────────────
    def get(self, url: str, params=None, **kwargs) -> Optional[requests.Response]:
        """Sync GET with delay and UA rotation."""
        try:
            if self.rotate_ua:
                self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
            time.sleep(self.delay)
            resp = self.session.get(url, params=params, timeout=self.timeout,
                                    allow_redirects=True, **kwargs)
            return resp
        except requests.exceptions.RequestException as e:
            print_error(f"GET {url} → {e}")
            return None

    def post(self, url: str, data=None, json_data=None, **kwargs) -> Optional[requests.Response]:
        """Sync POST with delay and UA rotation."""
        try:
            if self.rotate_ua:
                self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
            time.sleep(self.delay)
            resp = self.session.post(url, data=data, json=json_data,
                                     timeout=self.timeout, allow_redirects=True, **kwargs)
            return resp
        except requests.exceptions.RequestException as e:
            print_error(f"POST {url} → {e}")
            return None

    def concurrent_requests(self, tasks: List[Tuple[str, dict]]) -> List[Optional[requests.Response]]:
        """
        Run multiple GET requests concurrently.
        tasks: list of (url, params_dict)
        """
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.get, url, params): (url, params) for url, params in tasks}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    results.append(None)
        return results

    # ── Async request engine ──────────────────────────────────────
    async def async_get_many(self, urls: List[str]) -> List[Optional[str]]:
        """Fetch many URLs asynchronously, return list of response bodies."""
        if not AIOHTTP_AVAILABLE:
            print_warning("aiohttp not installed — falling back to sync.")
            return [self._sync_get_body(u) for u in urls]

        results = []
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=self.max_workers)
        timeout   = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            headers={**DEFAULT_HEADERS, **self.extra_headers},
            cookies=self.cookies,
            connector=connector,
            timeout=timeout,
        ) as session:
            tasks = [self._async_fetch(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r if isinstance(r, str) else None for r in results]

    async def _async_fetch(self, session: "aiohttp.ClientSession", url: str) -> str:
        await asyncio.sleep(self.delay)
        async with session.get(url, allow_redirects=True) as resp:
            return await resp.text()

    def _sync_get_body(self, url: str) -> Optional[str]:
        r = self.get(url)
        return r.text if r else None

    def run_async(self, urls: List[str]) -> List[Optional[str]]:
        """Sync wrapper around async_get_many."""
        return asyncio.run(self.async_get_many(urls))

    # ── Finding management ────────────────────────────────────────
    def add_finding(self, **kwargs) -> Finding:
        f = Finding(**kwargs)
        with self._lock:
            self.findings.append(f)
        return f

    def get_findings(self) -> List[Finding]:
        return list(self.findings)

    # ── URL manipulation helpers ──────────────────────────────────
    @staticmethod
    def inject_param(url: str, param: str, payload: str) -> str:
        """Replace or add a parameter value in a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def join(base: str, path: str) -> str:
        return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

    @staticmethod
    def extract_forms(html: str, base_url: str) -> List[Dict]:
        """Parse HTML forms with inputs."""
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self._current = None

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form":
                    self._current = {
                        "action": urljoin(base_url, attrs.get("action", base_url)),
                        "method": attrs.get("method", "get").upper(),
                        "inputs": [],
                    }
                elif tag == "input" and self._current:
                    self._current["inputs"].append({
                        "name":  attrs.get("name", ""),
                        "type":  attrs.get("type", "text"),
                        "value": attrs.get("value", ""),
                    })

            def handle_endtag(self, tag):
                if tag == "form" and self._current:
                    self.forms.append(self._current)
                    self._current = None

        parser = FormParser()
        parser.feed(html)
        return parser.forms

    # ── Timing measurement ────────────────────────────────────────
    def measure_response_time(self, url: str, params=None) -> Tuple[Optional[requests.Response], float]:
        start = time.perf_counter()
        resp  = self.get(url, params=params)
        elapsed = time.perf_counter() - start
        return resp, elapsed
