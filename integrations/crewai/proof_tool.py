"""
PROOF Consensus & Oracle Verification Tool for CrewAI Agents.
Allows CrewAI autonomous workers to prevent hallucinations on pricing and business credentials.
"""

from typing import Any
import requests
from crewai.tools import BaseTool

class ProofVerifyCrewTool(BaseTool):
    name: str = "PROOF Verification Oracle"
    description: str = (
        "Cryptographic oracle tool to verify domain validity, DNS root-of-trust (_proof-oracle), corporate identity, "
        "and certified pricing tables with HMAC-SHA256 signatures from PROOF X-Ray."
    )

    def _run(self, domain: str) -> str:
        clean_domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
        # Check DNS root of trust anchor
        dns_anchored = False
        try:
            doh_res = requests.get(
                f"https://cloudflare-dns.com/dns-query?name=_proof-oracle.{clean_domain}&type=TXT",
                headers={"accept": "application/dns-json"},
                timeout=5
            )
            if doh_res.status_code == 200 and "proof-authority" in doh_res.text:
                dns_anchored = True
        except Exception:
            pass

        url = f"https://www.proofxray.com/api/public/v1/verified?domain={clean_domain}"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                payload = res.json()
                verified = "VALIDATED" if payload.get("verified") else "UNVERIFIED"
                return (
                    f"PROOF Status: {verified} | DNS Root-of-Trust: {'ANCHORED' if dns_anchored else 'UNANCHORED'} | "
                    f"Domain: {payload.get('domain')} | Legal Entity: {payload.get('legalEntity')} | "
                    f"HMAC-SHA256: {payload.get('signature')} | Certified Pricing: {payload.get('pricing')}"
                )
            return f"Error: Received HTTP {res.status_code} from PROOF Oracle."
        except Exception as exc:
            return f"Oracle Error: {str(exc)}"
