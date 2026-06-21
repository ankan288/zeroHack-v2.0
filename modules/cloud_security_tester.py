"""
ZeroHack v2.0 - Cloud Security Tester
AWS S3 public bucket checks, IMDS v1/v2 detection,
Azure managed identity, GCP metadata probing, and IAM misconfiguration indicators.
"""

import re
import json
from typing import List
from urllib.parse import urlparse

from modules.enhanced_scanner import BaseScanner
from modules.notification_system import Finding, print_module_start, print_finding, print_info

# ─────────────────────────────────────────────────────────────
# Cloud metadata endpoints
# ─────────────────────────────────────────────────────────────
AWS_METADATA_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]

GCP_METADATA_ENDPOINTS = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
]

AZURE_METADATA_ENDPOINTS = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

# Common S3 bucket name patterns (generated from target domain)
S3_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1",
]


class CloudSecurityTester(BaseScanner):
    """
    Cloud security misconfiguration tester.
    """

    MODULE = "Cloud Security"

    def scan(self, mode: str = "both") -> List[Finding]:
        print_module_start(self.MODULE, self.target)
        self.findings.clear()

        print_info("Testing cloud metadata endpoints, S3 buckets, and environment variable exposure")

        self._test_aws_metadata()
        self._test_gcp_metadata()
        self._test_azure_metadata()
        self._test_s3_buckets()
        self._test_env_variable_exposure()
        self._test_cloud_storage_urls()

        return self.get_findings()

    # ─────── AWS IMDS ─────────────────────────────────────────
    def _test_aws_metadata(self):
        # Test IMDSv1 (no token needed — if accessible, it's a misconfiguration)
        for endpoint in AWS_METADATA_ENDPOINTS:
            resp = self.get(endpoint)
            if resp and resp.status_code == 200 and len(resp.text) > 5:
                severity = "CRITICAL"
                if "security-credentials" in endpoint and resp.text.strip():
                    severity = "CRITICAL"
                    # Try to extract credential key names
                    cred_name = resp.text.strip().split("\n")[0]
                    cred_url  = f"{endpoint}{cred_name}"
                    cred_resp = self.get(cred_url)
                    evidence  = f"Credentials accessible: {cred_name}"
                    if cred_resp:
                        try:
                            creds = json.loads(cred_resp.text)
                            evidence += f" | AccessKeyId: {creds.get('AccessKeyId', 'N/A')[:8]}..."
                        except Exception:
                            pass
                else:
                    evidence = f"Response: {resp.text[:100]}"

                f = self.add_finding(
                    module=self.MODULE,
                    title="AWS IMDSv1 Accessible (SSRF/IMDS Attack)",
                    severity=severity,
                    description=(
                        f"AWS instance metadata endpoint {endpoint} is accessible. "
                        "An attacker with SSRF can steal IAM credentials and take over the AWS account."
                    ),
                    target=endpoint,
                    evidence=evidence,
                    remediation=(
                        "Enforce IMDSv2 by requiring a session token. "
                        "Use instance metadata hop limit of 1. "
                        "Block SSRF to 169.254.169.254 at network level."
                    ),
                    owasp="A10:2021 – Server-Side Request Forgery",
                    cve="CVE-2019-11043",
                )
                print_finding(f)
                return

    # ─────── GCP Metadata ────────────────────────────────────
    def _test_gcp_metadata(self):
        for endpoint in GCP_METADATA_ENDPOINTS:
            resp = self.get(endpoint, headers={
                **self.session.headers,
                "Metadata-Flavor": "Google"
            })
            if resp and resp.status_code == 200 and len(resp.text) > 5:
                f = self.add_finding(
                    module=self.MODULE,
                    title="GCP Metadata Server Accessible",
                    severity="CRITICAL",
                    description=(
                        f"GCP compute metadata endpoint {endpoint} is accessible. "
                        "Attackers with SSRF can extract service account tokens."
                    ),
                    target=endpoint,
                    evidence=f"Response: {resp.text[:150]}",
                    remediation=(
                        "Restrict metadata API access. "
                        "Use workload identity. Block SSRF in application and at VPC level."
                    ),
                    owasp="A10:2021 – Server-Side Request Forgery",
                )
                print_finding(f)
                return

    # ─────── Azure IMDS ───────────────────────────────────────
    def _test_azure_metadata(self):
        for endpoint in AZURE_METADATA_ENDPOINTS:
            resp = self.get(endpoint, headers={
                **self.session.headers,
                "Metadata": "true"
            })
            if resp and resp.status_code == 200 and len(resp.text) > 5:
                f = self.add_finding(
                    module=self.MODULE,
                    title="Azure IMDS (Managed Identity) Accessible",
                    severity="CRITICAL",
                    description=(
                        f"Azure instance metadata endpoint {endpoint} is accessible. "
                        "Attackers with SSRF can steal managed identity OAuth tokens."
                    ),
                    target=endpoint,
                    evidence=f"Response length: {len(resp.text)} bytes",
                    remediation=(
                        "Block SSRF to 169.254.169.254 at application and network level. "
                        "Use Azure Private Endpoints and network policies."
                    ),
                    owasp="A10:2021 – Server-Side Request Forgery",
                )
                print_finding(f)
                return

    # ─────── S3 bucket enumeration ────────────────────────────
    def _test_s3_buckets(self):
        parsed = urlparse(self.target)
        domain = parsed.hostname or ""
        # Generate bucket name candidates from domain parts
        parts = domain.replace(".", "-").replace("_", "-").split("-")
        candidates = set()
        base = domain.split(".")[0]
        candidates.update([
            base,
            f"{base}-static",
            f"{base}-assets",
            f"{base}-media",
            f"{base}-uploads",
            f"{base}-backup",
            f"{base}-data",
            f"{base}-files",
            f"{base}-dev",
            f"{base}-staging",
            f"{base}-prod",
            f"static.{domain}",
            f"assets.{domain}",
        ])

        for bucket_name in list(candidates)[:15]:
            # S3 path-style URL
            s3_url = f"https://s3.amazonaws.com/{bucket_name}"
            resp   = self.get(s3_url)
            if resp:
                if resp.status_code == 200:
                    is_public_listing = "<ListBucketResult" in resp.text
                    severity = "CRITICAL" if is_public_listing else "HIGH"
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"AWS S3 Bucket {'Publicly Listed' if is_public_listing else 'Accessible'}: {bucket_name}",
                        severity=severity,
                        description=(
                            f"S3 bucket '{bucket_name}' is {'publicly listable' if is_public_listing else 'publicly accessible'}. "
                            + ("Full object listing exposes all stored files." if is_public_listing else "")
                        ),
                        target=s3_url,
                        evidence=f"HTTP {resp.status_code} | Listing: {is_public_listing}",
                        remediation=(
                            "Enable S3 Block Public Access settings. "
                            "Remove public bucket policies. "
                            "Use pre-signed URLs for controlled access."
                        ),
                        owasp="A05:2021 – Security Misconfiguration",
                    )
                    print_finding(f)
                elif resp.status_code == 403:
                    # Bucket exists but is private — still informational
                    f = self.add_finding(
                        module=self.MODULE,
                        title=f"AWS S3 Bucket Exists (Private): {bucket_name}",
                        severity="INFO",
                        description=f"Bucket '{bucket_name}' exists but is private (HTTP 403).",
                        target=s3_url,
                        evidence=f"HTTP 403 — bucket exists",
                        remediation="Ensure bucket policies are correctly locked down. Monitor for ACL changes.",
                    )
                    print_finding(f)

    # ─────── Environment variable exposure ────────────────────
    def _test_env_variable_exposure(self):
        """Check for debug endpoints that expose environment variables."""
        debug_paths = [
            "/debug", "/env", "/actuator/env", "/actuator/configprops",
            "/_ah/admin", "/console", "/phpinfo.php", "/info",
            "/actuator", "/actuator/health", "/health",
            "/__debug__", "/flask/info",
        ]
        env_indicators = [
            "AWS_ACCESS_KEY", "AWS_SECRET", "DATABASE_URL", "SECRET_KEY",
            "API_KEY", "PASSWORD", "TOKEN", "PRIVATE_KEY",
        ]
        for path in debug_paths:
            url  = self.join(self.target, path)
            resp = self.get(url)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text.upper()
            found = [kw for kw in env_indicators if kw in body]
            if found:
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Environment/Secrets Exposed at {path}",
                    severity="CRITICAL",
                    description=(
                        f"The endpoint {path} is publicly accessible and contains "
                        f"potentially sensitive environment variables: {', '.join(found)}"
                    ),
                    target=url,
                    evidence=f"Found keywords: {found}",
                    remediation=(
                        "Disable debug endpoints in production. "
                        "Restrict actuator endpoints with Spring Security. "
                        "Never log or expose environment variables via HTTP."
                    ),
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)

    # ─────── Cloud storage direct URL patterns ────────────────
    def _test_cloud_storage_urls(self):
        """Scan page content for exposed cloud storage URLs."""
        resp = self.get(self.target)
        if not resp:
            return
        patterns = {
            "AWS S3":            r's3\.amazonaws\.com/[a-zA-Z0-9._-]+',
            "GCS":               r'storage\.googleapis\.com/[a-zA-Z0-9._-]+',
            "Azure Blob":        r'[a-zA-Z0-9]+\.blob\.core\.windows\.net',
            "DigitalOcean Spaces": r'[a-zA-Z0-9]+\.digitaloceanspaces\.com',
        }
        for service, pattern in patterns.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                unique = list(set(matches))[:5]
                f = self.add_finding(
                    module=self.MODULE,
                    title=f"Cloud Storage URLs Exposed in Page ({service})",
                    severity="INFO",
                    description=(
                        f"The page contains references to {service} storage URLs. "
                        "These should be audited for public accessibility."
                    ),
                    target=self.target,
                    evidence=f"URLs found: {unique}",
                    remediation="Audit all cloud storage references. Ensure buckets/containers are private.",
                    owasp="A05:2021 – Security Misconfiguration",
                )
                print_finding(f)
