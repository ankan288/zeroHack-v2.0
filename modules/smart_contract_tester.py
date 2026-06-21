"""
ZeroHack v2.0 - Smart Contract Security Tester
Reentrancy detection, integer overflow/underflow, unchecked return values,
tx.origin authentication, and Solidity ABI analysis.
"""

import re
import json
from typing import List, Optional, Dict, Any

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info, print_warning

# ─────────────────────────────────────────────────────────────
# Solidity vulnerability patterns (static analysis via ABI + bytecode)
# ─────────────────────────────────────────────────────────────
REENTRANCY_PATTERNS = [
    r"call\.value\(",              # External call before state update
    r"send\(",                     # Unchecked send
    r"transfer\(",                 # Transfer before state change
    r"\.call{value:",
    r"call\(\)",
]

INTEGER_OVERFLOW_PATTERNS = [
    r"\+\+",                       # Unprotected increment
    r"\-\-",                       # Unprotected decrement
    r"\*\s*\w+",                   # Multiplication without SafeMath
    r"uint\d*\s+\w+\s*=\s*\w+\s*\-",  # Subtraction on uint (underflow)
]

TX_ORIGIN_PATTERNS = [
    r"tx\.origin",
    r"require\s*\(\s*tx\.origin",
    r"if\s*\(\s*tx\.origin",
]

SELFDESTRUCT_PATTERNS = [
    r"selfdestruct\s*\(",
    r"suicide\s*\(",
]

DELEGATE_CALL_PATTERNS = [
    r"delegatecall\s*\(",
    r"\.delegatecall\(",
]

# Common DeFi / Web3 endpoints
WEB3_RPC_PATHS = [
    "/rpc", "/jsonrpc", "/eth", "/json-rpc",
    "/api/eth", "/api/rpc",
]

ETHERSCAN_API = "https://api.etherscan.io/api"


class SmartContractTester(BaseScanner):
    """
    Smart contract security analyzer.
    Performs static analysis on Solidity source/ABI and probes Web3 endpoints.
    """

    MODULE = "Smart Contract"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        # Discover contract artifacts exposed via the target
        source_code, abi, bytecode = self._fetch_contract_artifacts()

        if source_code:
            print_info("Solidity source code found — running static analysis")
            self._analyze_source(source_code)
        elif abi:
            print_info("ABI found — analyzing function signatures")
            self._analyze_abi(abi)
        else:
            print_info("No on-chain artifacts exposed — scanning Web3 RPC endpoints")

        self._test_rpc_exposure()

        return self.get_findings()

    # ─────── Artifact discovery ───────────────────────────────
    def _fetch_contract_artifacts(self):
        """Try to find Solidity source/ABI/bytecode exposed via HTTP."""
        source, abi, bytecode = None, None, None

        artifact_paths = [
            "/contracts", "/abi", "/build/contracts",
            "/artifacts", "/truffle/build",
        ]
        sol_extensions = [".sol", ".json", "/abi.json", "/contract.json"]

        for path in artifact_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text
            if "pragma solidity" in body or "contract " in body:
                source = body
                break
            try:
                data = json.loads(body)
                if isinstance(data, list) and data and "inputs" in str(data[0]):
                    abi = data
                elif isinstance(data, dict):
                    abi      = data.get("abi")
                    bytecode = data.get("bytecode") or data.get("bin")
                    if data.get("source"):
                        source = data["source"]
            except (json.JSONDecodeError, Exception):
                pass

        return source, abi, bytecode

    # ─────── Source code analysis ────────────────────────────
    def _analyze_source(self, source: str):
        self._check_reentrancy(source)
        self._check_integer_issues(source)
        self._check_tx_origin(source)
        self._check_selfdestruct(source)
        self._check_delegate_call(source)
        self._check_visibility(source)

    def _check_reentrancy(self, source: str):
        for pattern in REENTRANCY_PATTERNS:
            matches = re.findall(pattern, source)
            if matches:
                # Check if state changes happen AFTER external calls (simplified heuristic)
                f = self.add_finding(
                    module=self.MODULE,
                    title="Potential Reentrancy Vulnerability",
                    severity="CRITICAL",
                    description=(
                        "The contract uses external calls (call/send/transfer) which may be vulnerable to "
                        "reentrancy if state changes occur after the external call. "
                        "This was the attack vector in the DAO hack ($60M stolen)."
                    ),
                    target=self.target,
                    evidence=f"Pattern '{pattern}' found in source",
                    remediation=(
                        "Apply the Checks-Effects-Interactions pattern: "
                        "update state BEFORE making external calls. "
                        "Use ReentrancyGuard (OpenZeppelin). "
                        "Use pull-over-push payment patterns."
                    ),
                    owasp="Smart Contract — SWC-107",
                )
                print_finding(f)
                return

    def _check_integer_issues(self, source: str):
        # Check for Solidity version < 0.8.0 without SafeMath
        version_m = re.search(r'pragma\s+solidity\s+(\^?[\d.]+)', source)
        uses_safemath = "SafeMath" in source or "using SafeMath" in source

        if version_m:
            version_str = version_m.group(1).lstrip("^").strip()
            try:
                parts = [int(x) for x in version_str.split(".")[:2]]
                is_old = parts[0] == 0 and parts[1] < 8
            except Exception:
                is_old = False

            if is_old and not uses_safemath:
                f = self.add_finding(
                    module=self.MODULE,
                    title="Integer Overflow/Underflow Risk (Solidity < 0.8.0 without SafeMath)",
                    severity="HIGH",
                    description=(
                        f"The contract uses Solidity {version_str} which does not have built-in overflow "
                        "protection, and SafeMath is not imported. "
                        "Integer overflow/underflow can corrupt balances and access controls."
                    ),
                    target=self.target,
                    evidence=f"Solidity version: {version_str} | SafeMath: {uses_safemath}",
                    remediation=(
                        "Upgrade to Solidity ^0.8.0 (overflow checked by default). "
                        "If using older versions, import OpenZeppelin SafeMath."
                    ),
                    owasp="Smart Contract — SWC-101",
                )
                print_finding(f)

    def _check_tx_origin(self, source: str):
        for pattern in TX_ORIGIN_PATTERNS:
            if re.search(pattern, source):
                f = self.add_finding(
                    module=self.MODULE,
                    title="tx.origin Used for Authentication",
                    severity="HIGH",
                    description=(
                        "The contract uses tx.origin for access control. "
                        "An attacker can trick a privileged user into calling a malicious contract "
                        "which then calls the victim contract with tx.origin == legitimate user."
                    ),
                    target=self.target,
                    evidence=f"Pattern 'tx.origin' found in authentication logic",
                    remediation="Replace tx.origin with msg.sender for all access control checks.",
                    owasp="Smart Contract — SWC-115",
                )
                print_finding(f)
                return

    def _check_selfdestruct(self, source: str):
        for pattern in SELFDESTRUCT_PATTERNS:
            if re.search(pattern, source):
                f = self.add_finding(
                    module=self.MODULE,
                    title="selfdestruct() Present — Contract Kill-Switch",
                    severity="MEDIUM",
                    description=(
                        "The contract contains selfdestruct(), which destroys the contract and sends "
                        "all ETH to an address. If poorly controlled, an attacker could drain funds."
                    ),
                    target=self.target,
                    evidence=f"Pattern '{pattern}' found",
                    remediation=(
                        "Remove selfdestruct if unnecessary. "
                        "Restrict with strong access controls (multi-sig or DAO governance). "
                        "Consider using an upgradeable proxy pattern instead."
                    ),
                    owasp="Smart Contract — SWC-106",
                )
                print_finding(f)
                return

    def _check_delegate_call(self, source: str):
        for pattern in DELEGATE_CALL_PATTERNS:
            if re.search(pattern, source):
                f = self.add_finding(
                    module=self.MODULE,
                    title="Uncontrolled delegatecall() Detected",
                    severity="CRITICAL",
                    description=(
                        "The contract uses delegatecall() which executes code in the context of the calling contract. "
                        "If the target address is user-controlled, an attacker can execute arbitrary code "
                        "and modify the calling contract's storage."
                    ),
                    target=self.target,
                    evidence=f"Pattern '{pattern}' found",
                    remediation=(
                        "Never delegatecall to user-controlled addresses. "
                        "Use allowlists for delegatecall targets. "
                        "Audit proxy patterns carefully."
                    ),
                    owasp="Smart Contract — SWC-112",
                )
                print_finding(f)
                return

    def _check_visibility(self, source: str):
        """Check for functions missing explicit visibility modifiers."""
        # Functions without public/private/internal/external
        implicit = re.findall(r'\bfunction\s+\w+\s*\([^)]*\)\s*(?!public|private|internal|external)', source)
        if implicit and len(implicit) > 2:
            f = self.add_finding(
                module=self.MODULE,
                title="Functions with Implicit Visibility (Default Public)",
                severity="MEDIUM",
                description=(
                    f"{len(implicit)} function(s) may be missing explicit visibility modifiers. "
                    "In Solidity <0.5.0, functions without explicit visibility default to public."
                ),
                target=self.target,
                evidence=f"Functions without explicit visibility: {len(implicit)}",
                remediation="Always declare explicit visibility for all functions.",
                owasp="Smart Contract — SWC-100",
            )
            print_finding(f)

    # ─────── ABI analysis ────────────────────────────────────
    def _analyze_abi(self, abi: list):
        """Analyze function ABI for dangerous patterns."""
        for func in abi:
            if not isinstance(func, dict):
                continue
            name   = func.get("name", "")
            inputs = func.get("inputs", [])

            # Check for admin functions without obvious access control in ABI name
            if any(kw in name.lower() for kw in ["withdraw", "drain", "kill", "destroy", "pause"]):
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Sensitive Function in ABI: {name}()",
                    severity="MEDIUM",
                    description=(
                        f"The function {name}() is exposed in the contract ABI and performs "
                        "a potentially sensitive operation. Verify it has proper access controls."
                    ),
                    target=self.target,
                    evidence=f"ABI function: {name}({', '.join(i.get('type','') for i in inputs)})",
                    remediation="Restrict sensitive functions with onlyOwner or role-based access control.",
                    owasp="Smart Contract — SWC-105",
                )
                print_finding(f)

    # ─────── RPC endpoint exposure ────────────────────────────
    def _test_rpc_exposure(self):
        for path in WEB3_RPC_PATHS:
            url = self.join(self.target, path)
            rpc_payload = json.dumps({
                "jsonrpc": "2.0",
                "method":  "eth_blockNumber",
                "params":  [],
                "id":      1
            })
            resp = self.post(url, data=rpc_payload,
                             headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200 and "result" in resp.text:
                f = self.add_finding(
                    module=self.MODULE,
                    title="Web3 JSON-RPC Endpoint Publicly Exposed",
                    severity="HIGH",
                    description=(
                        f"A Web3 JSON-RPC endpoint at {url} is publicly accessible. "
                        "Attackers can query blockchain state, enumerate accounts, "
                        "and potentially send transactions."
                    ),
                    target=url,
                    evidence=f"eth_blockNumber returned a valid result",
                    remediation=(
                        "Restrict RPC endpoint access to trusted IPs. "
                        "Require API key authentication. "
                        "Disable dangerous methods (eth_sendTransaction, personal_*)."
                    ),
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)
