"""
ZeroHack v2.0 - IDOR Tester
Insecure Direct Object Reference detection via ID enumeration,
horizontal/vertical privilege escalation, and response differential analysis.
"""

import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# Parameters that commonly carry object IDs
ID_PARAMS = [
    "id", "user_id", "userid", "account_id", "account", "uid",
    "order_id", "orderid", "invoice_id", "file_id", "doc_id",
    "document_id", "record_id", "item_id", "product_id", "pid",
    "customer_id", "member_id", "profile_id", "group_id", "post_id",
    "message_id", "ticket_id", "report_id", "resource_id", "object_id",
]

# API path patterns with numeric/UUID IDs
API_PATH_PATTERNS = [
    r"/api/v\d+/users/(\d+)",
    r"/api/v\d+/orders/(\d+)",
    r"/api/v\d+/accounts/(\d+)",
    r"/users/(\d+)",
    r"/orders/(\d+)",
    r"/profile/(\d+)",
    r"/items/(\d+)",
    r"/documents/(\d+)",
]


class IDORTester(BaseScanner):
    """
    IDOR vulnerability scanner.
    Enumerates object IDs around a discovered baseline and compares responses.
    """

    MODULE = "IDOR"
    ENUM_RANGE   = 5      # Test IDs ±5 around the detected baseline
    MIN_DIFF     = 20     # Minimum byte difference to flag

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        parsed   = urlparse(self.target)
        params   = parse_qs(parsed.query, keep_blank_values=True)
        path     = parsed.path

        # Detect ID params in URL query string
        id_params_found = [p for p in params if p.lower() in ID_PARAMS or re.match(r'.*id.*', p, re.I)]

        print_info(f"ID parameters found: {id_params_found or 'none in URL — probing common names'}")

        if not id_params_found:
            id_params_found = ID_PARAMS[:8]

        # Test each ID param via enumeration
        for param in id_params_found:
            baseline_value = params.get(param, ["1"])[0]
            try:
                baseline_int = int(baseline_value)
            except ValueError:
                baseline_int = 1

            self._test_param_idor(param, baseline_int)

        # Test API path IDOR
        self._test_path_idor(path)

        # Test UUID-based IDOR
        self._test_uuid_idor()

        return self.get_findings()

    # ─────── Numeric ID enumeration ──────────────────────────
    def _test_param_idor(self, param: str, baseline_id: int):
        # Get baseline response
        baseline_url  = self.inject_param(self.target, param, str(baseline_id))
        baseline_resp = self.get(baseline_url)
        if not baseline_resp or baseline_resp.status_code in (404, 403, 401):
            return

        baseline_body = baseline_resp.text
        baseline_len  = len(baseline_body)

        # Try adjacent IDs
        for delta in range(1, self.ENUM_RANGE + 1):
            for test_id in [baseline_id + delta, baseline_id - delta]:
                if test_id <= 0:
                    continue
                test_url  = self.inject_param(self.target, param, str(test_id))
                test_resp = self.get(test_url)
                if not test_resp:
                    continue

                # IDOR indicators:
                # 1. 200 response when we'd expect 403/404 for another user's data
                # 2. Significantly different content (different user's data)
                if test_resp.status_code == 200:
                    diff = abs(len(test_resp.text) - baseline_len)
                    is_different = diff > self.MIN_DIFF or self._content_differs(baseline_body, test_resp.text)

                    if is_different:
                        f = self.add_finding(
                            module=self.MODULE,
                            title=f"Potential IDOR — Parameter '{param}'",
                            severity="HIGH",
                            description=(
                                f"Changing '{param}' from {baseline_id} to {test_id} returns a "
                                f"different {test_resp.status_code} response (diff: {diff} bytes). "
                                "This may indicate access to another user's data without authorization."
                            ),
                            target=test_url,
                            evidence=(
                                f"Baseline ID {baseline_id} → {baseline_len} bytes | "
                                f"Test ID {test_id} → {len(test_resp.text)} bytes | "
                                f"Diff: {diff} bytes"
                            ),
                            remediation=(
                                "Implement object-level authorization checks on every request. "
                                "Use indirect references (e.g., session-scoped tokens) instead of direct DB IDs. "
                                "Never rely solely on ID obscurity."
                            ),
                            owasp="API1:2023 – Broken Object Level Authorization",
                            cve="CWE-639",
                        )
                        print_finding(f)
                        return  # one finding per param

    # ─────── API path IDOR ────────────────────────────────────
    def _test_path_idor(self, path: str):
        for pattern in API_PATH_PATTERNS:
            m = re.search(pattern, path)
            if m:
                original_id = m.group(1)
                try:
                    base_int = int(original_id)
                except ValueError:
                    continue

                for test_id in [base_int + 1, base_int - 1, base_int + 100]:
                    if test_id <= 0:
                        continue
                    test_path = path.replace(f"/{original_id}", f"/{test_id}", 1)
                    parsed    = urlparse(self.target)
                    test_url  = f"{parsed.scheme}://{parsed.netloc}{test_path}"

                    resp = self.get(test_url)
                    if resp and resp.status_code == 200:
                        f = self.add_finding(
                            module=self.MODULE,
                            title="IDOR via API Path Traversal",
                            severity="HIGH",
                            description=(
                                f"Modifying the resource ID in the API path from {original_id} to {test_id} "
                                "returns a 200 response, suggesting broken object-level authorization."
                            ),
                            target=test_url,
                            evidence=f"Original path: {path} | Test path: {test_path} → HTTP {resp.status_code}",
                            remediation="Enforce row-level authorization in all API handlers.",
                            owasp="API1:2023 – Broken Object Level Authorization",
                        )
                        print_finding(f)
                        return

    # ─────── UUID IDOR ────────────────────────────────────────
    def _test_uuid_idor(self):
        """
        Check if UUID-based endpoints accept predictable/invalid UUIDs
        and return data (indicates improper auth, not just predictability).
        """
        test_uuids = [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]
        for uuid_val in test_uuids:
            for param in ["id", "user_id", "uuid", "token", "resource_id"]:
                url  = self.inject_param(self.target, param, uuid_val)
                resp = self.get(url)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    f = self.add_finding(
                        module=self.MODULE,
                        title="Potential IDOR — UUID Parameter Accessible",
                        severity="MEDIUM",
                        description=(
                            f"The UUID {uuid_val!r} injected into parameter '{param}' "
                            "returned a 200 response with content. Manual verification needed."
                        ),
                        target=url,
                        evidence=f"UUID {uuid_val} → HTTP 200 | {len(resp.text)} bytes",
                        remediation="Verify that UUID-based resources enforce proper ownership checks.",
                        owasp="API1:2023 – Broken Object Level Authorization",
                    )
                    print_finding(f)
                    break

    @staticmethod
    def _content_differs(body1: str, body2: str) -> bool:
        """Simple heuristic: compare first 200 chars of meaningful content."""
        strip1 = re.sub(r'\s+', ' ', body1).strip()[:200]
        strip2 = re.sub(r'\s+', ' ', body2).strip()[:200]
        return strip1 != strip2
