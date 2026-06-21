"""
ZeroHack v2.0 - Web Cache Poisoning Tester
Tests for unkeyed headers, cache poisoning via Host/X-Forwarded-Host injection,
and cache key confusion attacks.
"""

import re
from typing import List

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Unkeyed headers to test
# ─────────────────────────────────────────────────────────────
UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-Host",
    "X-Custom-IP-Authorization",
    "X-Rewrite-URL",
    "X-Original-URL",
    "X-Override-URL",
]

POISON_HOST = "zerohack-cache-test.com"

# ─────────────────────────────────────────────────────────────
# Cache indicators in response headers
# ─────────────────────────────────────────────────────────────
CACHE_HEADERS = [
    "Cache-Control", "X-Cache", "CF-Cache-Status", "Age",
    "Vary", "ETag", "Surrogate-Control", "X-Varnish",
    "X-Squid-Error", "X-Cache-Lookup",
]

HIT_INDICATORS  = ["HIT", "hit", "CACHED", "cached", "from cache"]
MISS_INDICATORS = ["MISS", "miss", "BYPASS", "bypass", "EXPIRED"]


class WebCacheTester(BaseScanner):
    """
    Web cache poisoning vulnerability scanner.
    """

    MODULE = "Web Cache Poisoning"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        # First, check if caching is active
        is_cached = self._check_if_cached()
        if not is_cached:
            print_info("No caching detected — cache poisoning tests may produce false positives")

        # Test unkeyed header injection
        self._test_unkeyed_headers()

        # Test cache key normalization
        self._test_cache_key_normalization()

        # Test web cache deception
        self._test_cache_deception()

        return self.get_findings()

    # ─────── Check if caching is present ─────────────────────
    def _check_if_cached(self) -> bool:
        resp1 = self.get(self.target)
        resp2 = self.get(self.target)
        if not resp1 or not resp2:
            return False

        for h in CACHE_HEADERS:
            if h.lower() in {k.lower() for k in resp1.headers}:
                return True

        # Check for Age header or X-Cache
        for h in resp1.headers:
            if "cache" in h.lower() or h.lower() == "age":
                return True
        return False

    # ─────── Unkeyed header injection ─────────────────────────
    def _test_unkeyed_headers(self):
        baseline_resp = self.get(self.target)
        if not baseline_resp:
            return
        baseline_body = baseline_resp.text

        for header in UNKEYED_HEADERS:
            # Inject our poison host value
            inject_headers = {header: POISON_HOST}
            resp = self.get(self.target, headers={**self.session.headers, **inject_headers})
            if not resp:
                continue

            # Check if our injected host appears in the response (reflection = poison candidate)
            if POISON_HOST in resp.text:
                # Try to confirm: fetch without the header — does poison value persist?
                confirm = self.get(self.target)
                if confirm and POISON_HOST in confirm.text:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Web Cache Poisoning — {header} Unkeyed",
                        severity="HIGH",
                        description=(
                            f"The header {header!r} is not included in the cache key. "
                            f"Injecting {POISON_HOST!r} was reflected in a cached response "
                            "fetched without the header, confirming poisoning."
                        ),
                        target=self.target,
                        evidence=f"{header}: {POISON_HOST} → reflected in cached response",
                        remediation=(
                            "Include all Host-related headers in the cache key. "
                            "Validate and normalize Host headers before caching responses. "
                            "Use Vary header to differentiate cache entries."
                        ),
                        owasp="A05:2021 – Security Misconfiguration",
                        cve="CWE-444",
                    )
                    print_finding(f)
                else:
                    # Reflected but not cached yet — still informational
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Possible Cache Poisoning Vector — {header} Reflected",
                        severity="MEDIUM",
                        description=(
                            f"The header {header!r} is reflected in the response body but could not be "
                            "confirmed as cached. Manual verification recommended."
                        ),
                        target=self.target,
                        evidence=f"{header}: {POISON_HOST} → reflected in response but not confirmed cached",
                        remediation="Include Host-related headers in cache keys. Sanitize reflected input.",
                        owasp="A05:2021 – Security Misconfiguration",
                    )
                    print_finding(f)

    # ─────── Cache key normalization ─────────────────────────
    def _test_cache_key_normalization(self):
        """
        Test if adding a harmless parameter causes a cache miss
        but eventually gets cached with the same content as the
        original, indicating the parameter is excluded from the cache key.
        """
        probe_url = self.inject_param(self.target, "zh_cachebust", "1")
        resp1 = self.get(probe_url)
        resp2 = self.get(self.target)

        if resp1 and resp2:
            if resp1.text == resp2.text and len(resp1.text) > 50:
                # Content identical — parameter may be stripped from cache key
                f = self.add_finding(
                    module=self.MODULE,
                    title="Cache Key Excludes Query Parameters",
                    severity="LOW",
                    description=(
                        "Adding a novel parameter to the URL returns identical content as the "
                        "original URL. This suggests parameters may be excluded from the cache key, "
                        "which could enable cache poisoning via parameter injection."
                    ),
                    target=probe_url,
                    evidence="?zh_cachebust=1 → identical body to base URL",
                    remediation="Include the full query string in the cache key. Use cache-busting carefully.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

    # ─────── Web cache deception ──────────────────────────────
    def _test_cache_deception(self):
        """
        Web cache deception: appending static file extensions to dynamic endpoints.
        If the response is cached and returns user-specific content,
        attackers can steal it.
        """
        static_suffixes = [
            "/style.css", "/logo.png", "/script.js",
            "/favicon.ico", "/.jpg",
        ]
        dynamic_paths = ["/account", "/profile", "/dashboard", "/user", "/me"]

        for dyn in dynamic_paths:
            base_url = self.join(self.target, dyn)
            resp_base = self.get(base_url)
            if not resp_base or resp_base.status_code not in (200, 302):
                continue

            for suffix in static_suffixes:
                deception_url = base_url.rstrip("/") + suffix
                resp_deception = self.get(deception_url)

                if resp_deception and resp_deception.status_code == 200:
                    # Check if the response is cached
                    x_cache = resp_deception.headers.get("X-Cache", "")
                    age     = resp_deception.headers.get("Age", "0")
                    if any(h in x_cache for h in HIT_INDICATORS) or int(age) > 0:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="Web Cache Deception Attack",
                            severity="HIGH",
                            description=(
                                f"The dynamic endpoint {base_url} with a static suffix {suffix} "
                                "returned a cached 200 response. An attacker can trick a logged-in "
                                "user into visiting this URL to steal their cached personal data."
                            ),
                            target=deception_url,
                            evidence=f"X-Cache: {x_cache} | Age: {age} | HTTP 200",
                            remediation=(
                                "Configure cache to not cache authenticated/personalized responses. "
                                "Use Cache-Control: no-store on sensitive pages. "
                                "Normalize URLs before caching."
                            ),
                            owasp="A05:2021 – Security Misconfiguration",
                        )
                        print_finding(f)
