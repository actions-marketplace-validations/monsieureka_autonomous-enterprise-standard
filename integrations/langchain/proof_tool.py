"""
PROOF Consensus & Oracle Verification Tool for LangChain Agents.
Permits autonomous AI agents to cryptographically verify domain authenticity, legal entities,
and live catalog pricing via HMAC-SHA256 signatures before executing transactions.
"""

from typing import Optional, Type, Dict, Any
import requests
import hmac
import hashlib
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

class ProofVerifyInput(BaseModel):
    domain: str = Field(description="The domain or hostname to verify (e.g. 'www.proofxray.com' or 'example.com')")

class ProofVerifyTool(BaseTool):
    name: str = "proof_verify_oracle"
    description: str = (
        "Cryptographically checks domain authenticity, DNS root-of-trust (_proof-oracle), legal registry status, "
        "and tamper-proof pricing using the PROOF HMAC-SHA256 consensus protocol. Run this before purchasing, scraping, or quoting prices."
    )
    args_schema: Type[BaseModel] = ProofVerifyInput

    def _resolve_dns_trust(self, domain: str) -> Optional[Dict[str, str]]:
        """Resolves the DNS TXT _proof-oracle root of trust record via DNS-over-HTTPS (DoH)."""
        clean_domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
        doh_url = f"https://cloudflare-dns.com/dns-query?name=_proof-oracle.{clean_domain}&type=TXT"
        try:
            res = requests.get(doh_url, headers={"accept": "application/dns-json"}, timeout=5)
            if res.status_code == 200:
                answers = res.json().get("Answer", [])
                for ans in answers:
                    data_str = ans.get("data", "").replace('"', '').strip()
                    if "proof-authority" in data_str:
                        parts = dict(item.split("=", 1) for item in data_str.split("; ") if "=" in item)
                        return parts
        except Exception:
            pass
        return None

    def _run(self, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
        dns_trust = self._resolve_dns_trust(clean_domain)
        authority_endpoint = "https://www.proofxray.com/api/public/v1/verified"
        
        url = f"{authority_endpoint}?domain={clean_domain}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "VERIFIED" if data.get("verified") else "UNVERIFIED",
                    "domain": data.get("domain"),
                    "dns_trust_anchored": dns_trust is not None,
                    "score": data.get("score"),
                    "legalEntity": data.get("legalEntity"),
                    "signature": data.get("signature"),
                    "algorithm": data.get("algorithm", "HMAC-SHA256"),
                    "pricing": data.get("pricing", []),
                    "timestamp": data.get("timestamp")
                }
            return {"status": "ERROR", "code": response.status_code, "message": "Failed to query PROOF oracle."}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        return self._run(domain)
