"""
ZeroHack v2.0 - API Security Tester
JWT attacks, GraphQL introspection, rate limiting bypass,
mass assignment, broken object-level authorization (BOLA).
"""

import base64
import json
import re
import time
from typing import List, Optional, Dict

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Common API paths to discover
# ─────────────────────────────────────────────────────────────
API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/graphql", "/gql", "/api/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json",
    "/.well-known/openid-configuration",
    "/api/users", "/api/user", "/api/me",
    "/api/admin", "/api/health", "/api/status",
]

# Weak JWT secrets to brute-force
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "jwt_secret", "your-256-bit-secret", "secretkey",
    "change_this", "mysecretkey", "supersecret",
    "HS256", "token", "key", "private", "jwttoken",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { types { name } queryType { name } mutationType { name } } }"
})

# Mass assignment test payload
MASS_ASSIGNMENT_FIELDS = [
    "role", "is_admin", "admin", "isAdmin", "is_superuser",
    "privilege", "access_level", "permissions", "user_type",
    "verified", "active", "enabled", "credit", "balance",
]


class APISecurityTester(BaseScanner):
    """
    API security scanner: JWT attacks, GraphQL, rate limiting, BOLA, mass assignment.
    """

    MODULE = "API Security"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        # 1. API endpoint discovery
        endpoints = self._discover_api_endpoints()
        print_info(f"Discovered {len(endpoints)} API endpoint(s)")

        # 2. JWT testing
        self._test_jwt_vulnerabilities()

        # 3. GraphQL
        self._test_graphql(endpoints)

        # 4. Rate limiting
        self._test_rate_limiting(endpoints)

        # 5. Mass assignment
        self._test_mass_assignment(endpoints)

        # 6. BOLA / IDOR on APIs
        self._test_bola(endpoints)

        return self.get_findings()

    # ─────── API endpoint discovery ───────────────────────────
    def _discover_api_endpoints(self) -> List[str]:
        found = []
        for path in API_DISCOVERY_PATHS:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code in (200, 401, 403):
                found.append(url)
                print_info(f"  API: {url} → HTTP {resp.status_code}")
        return found

    # ─────── JWT attacks ──────────────────────────────────────
    def _test_jwt_vulnerabilities(self):
        # Look for JWT in common headers/cookies in the initial response
        resp = self.get(self.target)
        if not resp:
            return

        # Find JWTs in response headers/body
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        all_data = resp.text + " " + str(dict(resp.headers))
        tokens = re.findall(jwt_pattern, all_data)

        if not tokens:
            # Try auth endpoint
            for path in ["/api/auth", "/api/login", "/auth/token"]:
                url  = self.join(self.target, path)
                test = self.post(url, json_data={"username": "test", "password": "test"})
                if test:
                    tokens = re.findall(jwt_pattern, test.text)
                    if tokens:
                        break

        for token in tokens[:2]:  # test max 2 tokens
            self._test_jwt_none_algorithm(token)
            self._test_jwt_weak_secret(token)

    def _test_jwt_none_algorithm(self, token: str):
        """Test JWT 'none' algorithm attack."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header and modify algorithm to 'none'
            header_decoded = base64.urlsafe_b64decode(parts[0] + "==").decode()
            header_data    = json.loads(header_decoded)
            header_data["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header_data).encode()
            ).rstrip(b"=").decode()

            # Forged token: header.payload. (no signature)
            forged_token = f"{new_header}.{parts[1]}."

            # Try to use the forged token
            resp = self.get(self.target, headers={"Authorization": f"Bearer {forged_token}"})
            if resp and resp.status_code == 200:
                f = self.add_finding(
                    module=self.MODULE,
                    title="JWT None Algorithm Attack",
                    severity="CRITICAL",
                    description=(
                        "The server accepts JWTs with alg=none, meaning signature verification is disabled. "
                        "An attacker can forge tokens with arbitrary claims."
                    ),
                    target=self.target,
                    evidence=f"Forged token accepted → HTTP {resp.status_code}",
                    remediation=(
                        "Reject tokens with alg=none. Pin the expected algorithm in the verification logic."
                    ),
                    owasp="A02:2021 – Cryptographic Failures",
                    cve="CVE-2015-9235",
                )
                print_finding(f)
        except Exception:
            pass

    def _test_jwt_weak_secret(self, token: str):
        """Try to crack JWT with common weak secrets (HMAC only)."""
        try:
            import hmac
            import hashlib

            parts = token.split(".")
            if len(parts) != 3:
                return

            header_decoded = base64.urlsafe_b64decode(parts[0] + "==").decode()
            header_data    = json.loads(header_decoded)
            alg = header_data.get("alg", "")
            if not alg.startswith("HS"):
                return

            message = f"{parts[0]}.{parts[1]}".encode()
            sig     = base64.urlsafe_b64decode(parts[2] + "==")

            for secret in WEAK_JWT_SECRETS:
                expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                if hmac.compare_digest(expected, sig):
                    f = self.add_finding(
                        module=self.MODULE,
                        title="JWT Signed with Weak Secret",
                        severity="CRITICAL",
                        description=(
                            f"JWT token is signed with the weak secret: {secret!r}. "
                            "An attacker can forge valid tokens with any claims."
                        ),
                        target=self.target,
                        evidence=f"Secret cracked: {secret!r}",
                        remediation=(
                            "Use a cryptographically random secret of at least 256 bits. "
                            "Rotate all existing tokens. Consider RSA/ECDSA asymmetric signing."
                        ),
                        owasp="A02:2021 – Cryptographic Failures",
                    )
                    print_finding(f)
                    return
        except Exception:
            pass

    # ─────── GraphQL ──────────────────────────────────────────
    def _test_graphql(self, endpoints: List[str]):
        graphql_urls = [e for e in endpoints if "graphql" in e.lower() or "gql" in e.lower()]
        if not graphql_urls:
            graphql_urls = [self.join(self.target, "/graphql")]

        for url in graphql_urls:
            # Test introspection
            resp = self.post(url, json_data={"query": "{ __schema { types { name } } }"},
                             headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200 and "__schema" in resp.text:
                f = self.add_finding(
                    module=self.MODULE,
                    title="GraphQL Introspection Enabled",
                    severity="MEDIUM",
                    description=(
                        "GraphQL introspection is enabled, exposing the full schema including all types, "
                        "queries, mutations, and fields. This aids attackers in mapping the API."
                    ),
                    target=url,
                    evidence=f"__schema found in response | HTTP {resp.status_code}",
                    remediation=(
                        "Disable introspection in production. "
                        "Use depth limiting and query complexity analysis."
                    ),
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

            # GraphQL batch attack (DoS potential)
            batch_query = json.dumps([{"query": "{ __typename }"} for _ in range(100)])
            resp_batch  = self.post(url, data=batch_query,
                                    headers={"Content-Type": "application/json"})
            if resp_batch and resp_batch.status_code == 200:
                try:
                    parsed = json.loads(resp_batch.text)
                    if isinstance(parsed, list) and len(parsed) > 1:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="GraphQL Batching Enabled (DoS Risk)",
                            severity="MEDIUM",
                            description=(
                                "GraphQL accepts batched queries, which can be used to "
                                "amplify requests and bypass rate limiting."
                            ),
                            target=url,
                            evidence=f"Batch of 100 queries → {len(parsed)} responses",
                            remediation="Disable or limit query batching. Implement rate limiting per query.",
                            owasp="A04:2021 – Insecure Design",
                        )
                        print_finding(f)
                except Exception:
                    pass

    # ─────── Rate limiting ────────────────────────────────────
    def _test_rate_limiting(self, endpoints: List[str]):
        test_endpoints = endpoints[:3] or [self.target]
        for url in test_endpoints:
            times   = []
            codes   = []
            for i in range(15):
                t0   = time.perf_counter()
                resp = self.get(url)
                t1   = time.perf_counter()
                if resp:
                    codes.append(resp.status_code)
                    times.append(t1 - t0)

            # If no 429 was returned in 15 requests, rate limiting may be absent
            if codes and 429 not in codes and codes.count(200) > 10:
                f = self.add_finding(
                    module=self.MODULE,
                    title="Missing Rate Limiting",
                    severity="MEDIUM",
                    description=(
                        f"15 rapid requests to {url} returned no 429 (Too Many Requests). "
                        "The API may be vulnerable to brute-force and credential stuffing."
                    ),
                    target=url,
                    evidence=f"15 requests, all returned {set(codes)}. No 429 observed.",
                    remediation=(
                        "Implement rate limiting (e.g., 100 req/min per IP). "
                        "Use exponential backoff. Consider CAPTCHA on sensitive endpoints."
                    ),
                    owasp="API4:2023 – Unrestricted Resource Consumption",
                )
                print_finding(f)
                break

    # ─────── Mass assignment ──────────────────────────────────
    def _test_mass_assignment(self, endpoints: List[str]):
        register_paths = [e for e in endpoints if
                          any(kw in e for kw in ["register", "signup", "user", "profile", "create"])]
        if not register_paths:
            register_paths = [self.join(self.target, "/api/users")]

        for url in register_paths:
            # Try POST with mass assignment fields
            payload = {
                "username": "testuser_zh",
                "password": "Test@12345",
                "email":    "test@zerohack.local",
            }
            for field in MASS_ASSIGNMENT_FIELDS:
                payload[field] = True   # or "admin", 1, etc.

            resp = self.post(url, json_data=payload,
                             headers={"Content-Type": "application/json"})
            if resp and resp.status_code in (200, 201):
                resp_data = resp.text.lower()
                for field in MASS_ASSIGNMENT_FIELDS:
                    if field in resp_data and "true" in resp_data:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="Mass Assignment Vulnerability",
                            severity="HIGH",
                            description=(
                                f"The endpoint {url} accepted and reflected privileged field '{field}' "
                                "in the response, indicating mass assignment is not restricted."
                            ),
                            target=url,
                            evidence=f"Field '{field}' sent and appears in response",
                            remediation=(
                                "Use DTOs (Data Transfer Objects) to allowlist accepted fields. "
                                "Never bind request bodies directly to data models."
                            ),
                            owasp="API6:2023 – Unrestricted Access to Sensitive Business Flows",
                        )
                        print_finding(f)
                        break

    # ─────── BOLA ────────────────────────────────────────────
    def _test_bola(self, endpoints: List[str]):
        resource_endpoints = [e for e in endpoints if re.search(r'/\d+', e) or
                              any(kw in e for kw in ["user", "order", "account", "profile"])]
        for url in resource_endpoints[:3]:
            m = re.search(r'/(\d+)$', url)
            if m:
                current_id = int(m.group(1))
                for test_id in [current_id + 1, current_id + 2]:
                    test_url = url.rsplit(f"/{current_id}", 1)[0] + f"/{test_id}"
                    resp     = self.get(test_url)
                    if resp and resp.status_code == 200:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="Broken Object Level Authorization (BOLA/IDOR) on API",
                            severity="HIGH",
                            description=(
                                f"API endpoint {test_url} returned 200 for a different object ID, "
                                "indicating missing authorization checks."
                            ),
                            target=test_url,
                            evidence=f"ID {test_id} → HTTP {resp.status_code}",
                            remediation="Enforce object-level authorization on all API endpoints.",
                            owasp="API1:2023 – Broken Object Level Authorization",
                        )
                        print_finding(f)
