"""
ZeroHack v2.0 - Business Logic Tester
Negative price manipulation, workflow bypass, race conditions,
quantity manipulation, and coupon/promo abuse.
"""

import threading
import time
from typing import List
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info


class BusinessLogicTester(BaseScanner):
    """
    Business logic vulnerability scanner.
    Tests for flaws in e-commerce, registration, and workflow logic.
    """

    MODULE = "Business Logic"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        self._test_negative_values()
        self._test_price_manipulation()
        self._test_quantity_overflow()
        self._test_workflow_bypass()
        self._test_race_conditions()

        return self.get_findings()

    # ─────── Negative values ──────────────────────────────────
    def _test_negative_values(self):
        """Test if negative quantities/prices are accepted."""
        test_params = [
            ("quantity", ["-1", "-999", "-0.01"]),
            ("price",    ["-1", "-0.01", "-100"]),
            ("amount",   ["-1", "-500"]),
            ("qty",      ["-1", "-999"]),
        ]
        for param, values in test_params:
            for value in values:
                url  = self.inject_param(self.target, param, value)
                resp = self.get(url)
                if not resp:
                    continue
                # If we get a success response, flag it
                if resp.status_code in (200, 201) and self._looks_successful(resp.text):
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Negative Value Accepted — '{param}'",
                        severity="HIGH",
                        description=(
                            f"The application accepted a negative value ({value}) for '{param}' "
                            "without rejecting it. This can lead to credit balance manipulation, "
                            "free goods, or account credit fraud."
                        ),
                        target=url,
                        evidence=f"param={param}, value={value} → HTTP {resp.status_code}",
                        remediation=(
                            "Validate that all numeric business inputs are within allowed ranges. "
                            "Reject negative values for quantities, prices, and amounts at the server level."
                        ),
                        owasp="A04:2021 – Insecure Design",
                        cve="CWE-20",
                    )
                    print_finding(f)

    # ─────── Price manipulation ───────────────────────────────
    def _test_price_manipulation(self):
        """Test if price can be overridden in POST requests."""
        cart_paths = [
            "/cart", "/checkout", "/order", "/buy", "/purchase",
            "/api/cart", "/api/checkout", "/api/order",
        ]
        for path in cart_paths:
            url = self.join(self.target, path)
            resp = self.get(url)
            if not resp or resp.status_code not in (200, 401, 403):
                continue

            forms = self.extract_forms(resp.text, url)
            for form in forms:
                action = form["action"]
                inputs = form["inputs"]
                data   = {i["name"]: i["value"] for i in inputs}

                # If there's a price field, try to set it to 0.01 or 1
                price_fields = [i for i in inputs if any(
                    kw in i["name"].lower() for kw in ["price", "amount", "cost", "total"]
                )]
                for pf in price_fields:
                    data[pf["name"]] = "0.01"
                    tampered_resp = self.post(action, data=data)
                    if tampered_resp and tampered_resp.status_code in (200, 201):
                        if self._looks_successful(tampered_resp.text):
                            f = self.add_finding(
                                module=self.MODULE,
                                title="Price Manipulation via Form Tampering",
                                severity="CRITICAL",
                                description=(
                                    f"Form at {action} accepted a tampered price of $0.01 "
                                    f"for field '{pf['name']}'. Server-side price validation is absent."
                                ),
                                target=action,
                                evidence=f"Field '{pf['name']}' set to 0.01 → success response",
                                remediation=(
                                    "Never trust client-supplied prices. "
                                    "Recalculate prices server-side from the product catalog. "
                                    "Sign cart contents to detect tampering."
                                ),
                                owasp="A04:2021 – Insecure Design",
                            )
                            print_finding(f)

    # ─────── Quantity overflow ────────────────────────────────
    def _test_quantity_overflow(self):
        """Test integer overflow / max boundary for quantity."""
        overflow_values = [
            "2147483647",    # INT_MAX
            "2147483648",    # INT_MAX + 1
            "9999999999",    # Large number
            "1e9",           # Scientific notation
        ]
        for val in overflow_values:
            for param in ["quantity", "qty", "count", "num", "amount"]:
                url  = self.inject_param(self.target, param, val)
                resp = self.get(url)
                if resp and resp.status_code == 200 and self._looks_successful(resp.text):
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Integer Overflow / Large Value Accepted — '{param}'",
                        severity="MEDIUM",
                        description=(
                            f"Parameter '{param}' accepted an extreme value of {val} without rejection. "
                            "This may cause integer overflow in backend calculations."
                        ),
                        target=url,
                        evidence=f"{param}={val} → HTTP {resp.status_code}",
                        remediation=(
                            "Enforce strict maximum bounds on all numeric inputs. "
                            "Use safe integer arithmetic. Validate ranges on the server."
                        ),
                        owasp="A04:2021 – Insecure Design",
                        cve="CWE-190",
                    )
                    print_finding(f)
                    break

    # ─────── Workflow bypass ──────────────────────────────────
    def _test_workflow_bypass(self):
        """Test if multi-step checkout/registration can be bypassed."""
        # Try to access later steps directly without completing earlier ones
        step_patterns = [
            ("/checkout/payment",    "Checkout step 3 (payment) accessible without prior steps"),
            ("/checkout/confirm",    "Order confirm page accessible without payment"),
            ("/checkout/complete",   "Order complete page accessible without checkout"),
            ("/register/verify",     "Registration verification step accessible directly"),
            ("/admin/dashboard",     "Admin dashboard accessible without login check"),
        ]
        for path, description in step_patterns:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Workflow Step Bypass — {path}",
                    severity="HIGH",
                    description=(
                        f"Direct access to {path} returned HTTP 200. {description}. "
                        "Multi-step process state is not properly enforced."
                    ),
                    target=url,
                    evidence=f"GET {url} → HTTP {resp.status_code} ({len(resp.text)} bytes)",
                    remediation=(
                        "Track multi-step state server-side (e.g., session flags). "
                        "Validate that preceding steps were completed before allowing access."
                    ),
                    owasp="A04:2021 – Insecure Design",
                )
                print_finding(f)

    # ─────── Race conditions ──────────────────────────────────
    def _test_race_conditions(self):
        """
        Send simultaneous requests to single-use endpoints
        (coupon redemption, limited-item purchase, etc.)
        to test for TOCTOU / race condition vulnerabilities.
        """
        race_paths = [
            ("/api/coupon/apply",   {"code": "DISCOUNT10"}),
            ("/api/redeem",         {"code": "PROMO50"}),
            ("/api/claim",          {"item_id": "1"}),
            ("/checkout/apply",     {"coupon": "FREE100"}),
        ]

        CONCURRENT = 10  # simultaneous requests

        for path, data in race_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if resp and resp.status_code == 404:
                continue  # endpoint doesn't exist

            results = []
            barrier = threading.Barrier(CONCURRENT)

            def race_request(u=url, d=data):
                barrier.wait()   # All threads fire simultaneously
                try:
                    r = self.session.post(u, json=d, timeout=5)
                    return r.status_code
                except Exception:
                    return 0

            with ThreadPoolExecutor(max_workers=CONCURRENT) as pool:
                futures = [pool.submit(race_request) for _ in range(CONCURRENT)]
                for f in futures:
                    try:
                        results.append(f.result(timeout=10))
                    except Exception:
                        pass

            success_count = results.count(200) + results.count(201)
            if success_count > 1:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Race Condition — {path}",
                    severity="HIGH",
                    description=(
                        f"{success_count} out of {CONCURRENT} simultaneous requests to {path} "
                        "succeeded. This indicates a race condition / TOCTOU vulnerability — "
                        "a single-use operation was executed multiple times concurrently."
                    ),
                    target=url,
                    evidence=f"{CONCURRENT} concurrent requests → {success_count} successes",
                    remediation=(
                        "Use database-level locks (SELECT FOR UPDATE, atomic transactions). "
                        "Implement idempotency keys for financial operations. "
                        "Use Redis/Lua scripts for atomic counter updates."
                    ),
                    owasp="A04:2021 – Insecure Design",
                    cve="CWE-362",
                )
                print_finding(f)

    @staticmethod
    def _looks_successful(body: str) -> bool:
        """Heuristic: does the response look like a success?"""
        body_lower = body.lower()
        success_indicators = ["success", "added", "complete", "confirmed", "thank you",
                              "order placed", "cart", "checkout", "payment"]
        error_indicators   = ["error", "invalid", "failed", "rejected", "not allowed",
                              "out of range", "must be positive"]
        has_success = any(kw in body_lower for kw in success_indicators)
        has_error   = any(kw in body_lower for kw in error_indicators)
        return has_success and not has_error
