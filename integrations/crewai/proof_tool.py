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
        "Cryptographic oracle tool to verify domain validity, corporate identity, "
        "and certified pricing tables with HMAC-SHA256 signatures from PROOF X-Ray."
    )

    def _run(self, domain: str) -> str:
        url = f"https://www.proofxray.com/api/public/v1/verified?domain={domain.strip()}"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                payload = res.json()
                verified = "VALIDATED" if payload.get("verified") else "UNVERIFIED"
                return (
                    f"PROOF Status: {verified} | Domain: {payload.get('domain')} | "
                    f"Legal Entity: {payload.get('legalEntity')} | HMAC-SHA256: {payload.get('signature')} | "
                    f"Certified Pricing: {payload.get('pricing')}"
                )
            return f"Error: Received HTTP {res.status_code} from PROOF Oracle."
        except Exception as exc:
            return f"Oracle Error: {str(exc)}"
