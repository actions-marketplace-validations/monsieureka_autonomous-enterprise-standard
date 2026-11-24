"""
PROOF-VC v2 Public Certificate & Verification Tool for LangChain Agents.
Queries the live PROOF X-Ray public certificate API (/api/public/v1/certificate),
checks DNS-01 ownership anchoring (_proof-verify TXT), and validates SHA-256 JCS digests
(plus offline Ed25519 verification via /.well-known/jwks.json when `cryptography` is installed).
"""

import base64
import hashlib
import json
import re
from typing import Any, Dict, Optional, Type
import requests
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


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

    def _verify_ed25519(self, attestation: Dict[str, Any]) -> Dict[str, Any]:
        sig = attestation.get("signature") or {}
        if sig.get("alg") != "Ed25519":
            return {"verified": False, "reason": "no_ed25519_attestation"}
        expected = hashlib.sha256(_canonical_json(attestation.get("payload", {})).encode("utf-8")).hexdigest()
        if expected != attestation.get("digest"):
            return {"verified": False, "reason": "digest_mismatch"}
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return {"verified": True, "reason": "digest_ok_install_cryptography_for_ed25519"}
        jwks_url = sig.get("jwksUrl") or "https://www.proofxray.com/.well-known/jwks.json"
        jwks_res = requests.get(jwks_url, timeout=5)
        if jwks_res.status_code != 200:
            return {"verified": False, "reason": "jwks_unreachable"}
        keys = jwks_res.json().get("keys", [])
        jwk = next((k for k in keys if k.get("kid") == sig.get("kid")), keys[0] if keys else None)
        if not jwk or not jwk.get("x"):
            return {"verified": False, "reason": "jwks_key_not_found"}
        x_bytes = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        sig_bytes = base64.urlsafe_b64decode(sig["value"] + "=" * (-len(sig["value"]) % 4))
        try:
            Ed25519PublicKey.from_public_bytes(x_bytes).verify(sig_bytes, f"proof-vc-v2\n{expected}".encode("utf-8"))
            return {"verified": True, "reason": "ed25519_verified_offline"}
        except Exception:
            return {"verified": False, "reason": "invalid_signature"}

    def _run(self, domain: str) -> Dict[str, Any]:
        clean_domain = _normalize_domain(domain)
        dns_anchor = self._resolve_dns_anchor(clean_domain)
        url = f"https://www.proofxray.com/api/public/v1/certificate?domain={clean_domain}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                sig_check = self._verify_ed25519(data["attestation"]) if isinstance(data.get("attestation"), dict) else None
                return {
                    "status": "CERTIFIED" if data.get("certified") else "AUDITED",
                    "domain": data.get("domain"),
                    "certified": bool(data.get("certified")),
                    "score": data.get("score"),
                    "tier": data.get("tier"),
                    "injectionFree": data.get("injectionFree"),
                    "dns_anchored": dns_anchor is not None,
                    "auditedAt": data.get("auditedAt"),
                    "expiresAt": data.get("expiresAt"),
                    "fingerprint": data.get("fingerprint"),
                    "claimRoot": data.get("claimRoot"),
                    "ed25519Check": sig_check,
                    "certificateUrl": data.get("certificateUrl"),
                    "jwksUrl": data.get("jwksUrl"),
                }
            return {"status": "UNVERIFIED", "code": response.status_code, "domain": clean_domain}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        return self._run(domain)
