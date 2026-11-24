"""
PROOF-VC v2 Public Certificate & Verification Tool for CrewAI Agents.
Queries the live PROOF X-Ray public certificate API (/api/public/v1/certificate)
and checks optional DNS-01 ownership anchoring (_proof-verify TXT).
"""

import os
import re
import sys
import requests
from crewai.tools import BaseTool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from _proof_core import evaluate  # noqa: E402


def _normalize_domain(domain: str) -> str:
    clean = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0].split(":")[0]
    return clean.removeprefix("www.").rstrip(".")


class ProofVerifyCrewTool(BaseTool):
    name: str = "PROOF Certificate Verifier"
    description: str = (
        "Queries the live PROOF X-Ray public certificate API (PROOF-VC v2) to inspect deterministic "
        "audit scores, DOM prompt-injection safety, Merkle claimRoot, expiration, and Ed25519 JWKS URL."
    )

    def _run(self, domain: str) -> str:
        clean_domain = _normalize_domain(domain)
        dns_anchored = False
        try:
            doh_res = requests.get(
                f"https://cloudflare-dns.com/dns-query?name=_proof-verify.{clean_domain}&type=TXT",
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            if doh_res.status_code == 200 and "proof-v2=" in doh_res.text:
                dns_anchored = True
        except Exception:
            pass

        url = f"https://www.proofxray.com/api/public/v1/certificate?domain={clean_domain}"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                # Fail closed: trust comes only from a valid Ed25519 signature by a pinned key (see integrations/_proof_core.py).
                data = res.json()
                verdict = evaluate(data, clean_domain)
                if verdict["status"] == "UNVERIFIED":
                    return f"UNVERIFIED: {verdict['reason']} for {clean_domain} (signature not accepted)"
                payload = verdict["payload"]
                return (
                    f"PROOF Status: {verdict['status']} | Score: {verdict['score']}/100 | "
                    f"Injection-Free: {data.get('injectionFree')} | DNS-01: {'ANCHORED' if dns_anchored else 'OPTIONAL'} | "
                    f"Domain: {payload.get('domain')} | SHA-256: {data.get('fingerprint')} | "
                    f"ClaimRoot: {data.get('claimRoot')} | Expires: {payload.get('expiresAt')} | "
                    f"Certificate: {data.get('certificateUrl')}"
                )
            return f"UNVERIFIED: HTTP {res.status_code} for {clean_domain} (run free audit at https://www.proofxray.com/#audit-gratuit)"
        except Exception as exc:
            return f"PROOF Verifier Error: {exc}"
