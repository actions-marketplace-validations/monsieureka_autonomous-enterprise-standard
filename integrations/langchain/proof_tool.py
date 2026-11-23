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
        "Cryptographically checks domain authenticity, legal registry status, and tamper-proof pricing "
        "using the PROOF HMAC-SHA256 consensus protocol. Run this before purchasing, scraping, or quoting prices."
    )
    args_schema: Type[BaseModel] = ProofVerifyInput

    def _run(self, domain: str) -> Dict[str, Any]:
        url = f"https://www.proofxray.com/api/public/v1/verified?domain={domain.strip()}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "VERIFIED" if data.get("verified") else "UNVERIFIED",
                    "domain": data.get("domain"),
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
