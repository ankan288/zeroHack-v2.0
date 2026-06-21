"""
ZeroHack v2.0 - Web3 Tester
Web3 RPC endpoint enumeration, eth_sign phishing detection,
flash loan attack surface mapping, and wallet drainer pattern detection.
"""

import json
from typing import List

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Dangerous RPC methods
# ─────────────────────────────────────────────────────────────
DANGEROUS_RPC_METHODS = [
    "eth_accounts",           # Lists all accounts (huge privacy risk)
    "personal_listAccounts",  # Same
    "personal_unlockAccount", # Can unlock wallet without password if improperly set
    "eth_sendTransaction",    # Send transactions without sig
    "personal_sign",          # Sign arbitrary data
    "eth_sign",               # Legacy dangerous sign method
    "personal_ecRecover",     # Recover signer (used in phishing)
    "debug_traceTransaction", # Debug endpoints
    "miner_start",            # Start mining
    "miner_stop",
]

# Common Web3 frontend patterns that indicate phishing
PHISHING_PATTERNS = [
    r"eth_sign\s*\(",
    r"personal_sign\s*\(",
    r"sign\s*\(\s*web3\.eth",
    r"signMessage\s*\(",
    r"_eth\.sign\s*\(",
    r"\"eth_sign\"",
    r"ethereum\.request.*eth_sign",
    r"ethereum\.request.*personal_sign",
    r"setApprovalForAll",    # NFT drainer signature
    r"permit\s*\(",          # EIP-2612 permit abuse
]

# Flash loan attack surface (DeFi protocols)
DEFI_SELECTORS = {
    "flashLoan":           "0x5cffe9de",  # Aave
    "flashloan":           "0xd9d98ce4",
    "flash":               "0x490e6cbc",  # Uniswap V3
    "executeFlashLoan":    "0xab9c4b5d",
    "callFunction":        "0x9e5d4c49",  # dYdX
}


class Web3Tester(BaseScanner):
    """
    Web3 / DeFi security tester.
    """

    MODULE = "Web3 / DeFi"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        resp = self.get(self.target)

        self._test_rpc_methods()
        self._test_phishing_patterns(resp)
        self._test_wallet_connector_security(resp)
        self._test_defi_attack_surface()

        return self.get_findings()

    # ─────── RPC method enumeration ──────────────────────────
    def _test_rpc_methods(self):
        rpc_paths = ["/rpc", "/jsonrpc", "/eth", "/api/rpc", "/api/eth"]

        for path in rpc_paths:
            url = self.join(self.target, path)

            for method in DANGEROUS_RPC_METHODS:
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "method":  method,
                    "params":  [],
                    "id":      1,
                })
                resp = self.post(url, data=payload,
                                 headers={"Content-Type": "application/json"})
                if not resp:
                    continue
                if resp.status_code == 200 and '"error"' not in resp.text:
                    severity = "CRITICAL" if method in ("personal_unlockAccount", "eth_sendTransaction") \
                               else "HIGH"
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Dangerous RPC Method Exposed: {method}",
                        severity=severity,
                        description=(
                            f"The JSON-RPC endpoint at {url} responded to {method} without error. "
                            "This method should be disabled or restricted on production nodes."
                        ),
                        target=url,
                        evidence=f"Method {method} → HTTP {resp.status_code}, no error in response",
                        remediation=(
                            f"Disable {method} in your node configuration. "
                            "Use --rpc-api flag to allowlist only needed methods. "
                            "Restrict RPC access to localhost or VPN."
                        ),
                        owasp="A05:2021 – Security Misconfiguration",
                    )
                    print_finding(f)

    # ─────── Phishing pattern detection ──────────────────────
    def _test_phishing_patterns(self, resp):
        if not resp:
            return
        import re
        body = resp.text

        found_patterns = []
        for pattern in PHISHING_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found_patterns.extend(matches[:2])

        if found_patterns:
            f = self.add_finding(
                module=self.MODULE,
                title="Web3 Phishing / Wallet Drainer Patterns Detected",
                severity="HIGH",
                description=(
                    "The page's JavaScript contains patterns commonly associated with "
                    "wallet draining attacks (eth_sign, setApprovalForAll, permit abuse). "
                    "Manual code review is required."
                ),
                target=self.target,
                evidence=f"Patterns: {list(set(found_patterns))[:5]}",
                remediation=(
                    "Avoid using eth_sign (use personal_sign with EIP-712 instead). "
                    "Warn users before signing setApprovalForAll. "
                    "Use EIP-712 structured data signing. "
                    "Implement transaction simulation before execution."
                ),
                owasp="A04:2021 – Insecure Design",
            )
            print_finding(f)

    # ─────── Wallet connector security ───────────────────────
    def _test_wallet_connector_security(self, resp):
        if not resp:
            return
        import re
        body = resp.text

        issues = []

        # Check for WalletConnect without version pinning
        if "walletconnect" in body.lower() and "v2" not in body.lower():
            issues.append("WalletConnect v1 (deprecated) may be in use")

        # Check for MetaMask injection sniffing without fallback
        if "window.ethereum" in body and "window.web3" in body:
            issues.append("Legacy window.web3 detected alongside window.ethereum")

        # Check for hardcoded chain IDs (mainnet only)
        chain_ids = re.findall(r'chainId["\s:]+["\']?(0x1|1)["\']?', body)
        if chain_ids:
            issues.append("Hardcoded mainnet chainId — testnet transactions could be replayed")

        if issues:
            f = self.add_finding(
                module=self.MODULE,
                title="Web3 Wallet Connector Security Issues",
                severity="MEDIUM",
                description="Web3 wallet connector implementation has potential security issues.",
                target=self.target,
                evidence=" | ".join(issues),
                remediation=(
                    "Use WalletConnect v2. "
                    "Remove legacy web3 support. "
                    "Validate chainId before transactions."
                ),
                owasp="A04:2021 – Insecure Design",
            )
            print_finding(f)

    # ─────── DeFi attack surface ─────────────────────────────
    def _test_defi_attack_surface(self):
        """Check for flash loan–related function selectors in exposed ABI/contracts."""
        contract_paths = ["/abi", "/contract", "/contracts/abi.json"]

        for path in contract_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text.lower()
            for func_name, selector in DEFI_SELECTORS.items():
                if func_name.lower() in body or selector in body:
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"Flash Loan Function Exposed: {func_name}()",
                        severity="MEDIUM",
                        description=(
                            f"The contract exposes a flash loan function '{func_name}'. "
                            "If callback validation is insufficient, flash loan attacks "
                            "can manipulate prices and drain liquidity pools."
                        ),
                        target=url,
                        evidence=f"Function '{func_name}' (selector: {selector}) found in ABI",
                        remediation=(
                            "Validate flash loan callback origin strictly. "
                            "Use reentrancy guards on all functions called during flash loans. "
                            "Implement price oracle manipulation protection."
                        ),
                        owasp="A04:2021 – Insecure Design",
                    )
                    print_finding(f)
