"""
PROOF-VC v2 Public Certificate & Verification Tool for LangChain Agents.
Queries the live PROOF X-Ray public certificate API (/api/public/v1/certificate),
checks DNS-01 ownership anchoring (_proof-verify TXT), and validates SHA-256 JCS digests
and verifies the Ed25519 signature against a PINNED public key (fail closed: no valid signature, no trust).
"""

import json
import os
import re
import sys
from typing import Any, Dict, Optional, Type
import requests
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from _proof_core import evaluate  # noqa: E402


def _normalize_domain(domain: str) -> str:
    clean = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0].split(":")[0]
    return clean.removeprefix("www.").rstrip(".")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ProofVerifyInput(BaseModel):
    domain: str = Field(description="The domain or hostname to verify (e.g. 'proofxray.com' or 'example.com')")


class ProofVerifyTool(BaseTool):
    name: str = "proof_verify_certificate"
    description: str = (
        "Queries the live PROOF X-Ray public certificate API (PROOF-VC v2) to inspect deterministic "
        "SEO/GEO audit scores, DOM prompt-injection safety (injectionFree), Merkle claimRoot, "
        "expiration window, and offline-verifiable Ed25519 attestations via /.well-known/jwks.json."
    )
    args_schema: Type[BaseModel] = ProofVerifyInput

    def _resolve_dns_anchor(self, domain: str) -> Optional[Dict[str, str]]:
        """Resolves optional DNS-01 ownership record (_proof-verify.<domain> TXT) via Cloudflare DoH."""
        doh_url = f"https://cloudflare-dns.com/dns-query?name=_proof-verify.{domain}&type=TXT"
        try:
            res = requests.get(doh_url, headers={"Accept": "application/dns-json"}, timeout=5)
            if res.status_code == 200:
                for ans in res.json().get("Answer", []):
                    data_str = str(ans.get("data", "")).replace('"', "").strip()
                    if "proof-v2=" in data_str:
                        return dict(item.split("=", 1) for item in data_str.split(";") if "=" in item)
        except Exception:
            pass
        return None

    def _run(self, domain: str) -> Dict[str, Any]:
        clean_domain = _normalize_domain(domain)
        dns_anchor = self._resolve_dns_anchor(clean_domain)
        url = f"https://www.proofxray.com/api/public/v1/certificate?domain={clean_domain}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # Fail closed: trust comes only from a valid Ed25519 signature by a pinned key (see integrations/_proof_core.py).
                verdict = evaluate(data, clean_domain)
                if verdict["status"] == "UNVERIFIED":
                    return {"status": "UNVERIFIED", "domain": clean_domain, "reason": verdict["reason"], "ed25519Check": verdict["signature"]}
                payload = verdict["payload"]
                return {
                    "status": verdict["status"],
                    "domain": payload.get("domain"),
                    "certified": verdict["ok"],
                    "score": verdict["score"],
                    "tier": data.get("tier"),
                    "injectionFree": data.get("injectionFree"),
                    "dns_anchored": dns_anchor is not None,
                    "auditedAt": data.get("auditedAt"),
                    "expiresAt": payload.get("expiresAt"),
                    "fingerprint": data.get("fingerprint"),
                    "claimRoot": data.get("claimRoot"),
                    "ed25519Check": verdict["signature"],
                    "certificateUrl": data.get("certificateUrl"),
                }
            return {"status": "UNVERIFIED", "code": response.status_code, "domain": clean_domain}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        return self._run(domain)
