# The Agentic Web Manifesto: The PROOF-VC v2 Standard for Verifiable AI Discovery

> **"Unverified agents hallucinate. Verified agents inspect deterministic proofs."**

Autonomous AI agents are shifting from answering questions to comparing businesses, validating compliance, and routing real-world transactions. Yet today's web HTML is noisy, self-asserted, and vulnerable to indirect prompt injection and cloaking.

---

## 1. The Autonomous Enterprise Standard (EAI v1.0) & PROOF-VC v2

Every compliant digital entity exposes:
1. **Security Transparency** (`/.well-known/security.txt`, RFC 9116).
2. **Machine-Readable Routing & Capabilities** (`/llms.txt`, `/.well-known/agent.json`, Schema.org JSON-LD).
3. **Offline-Verifiable Public Attestation (PROOF-VC v2)**: deterministic root-homepage audit (`/api/public/v1/certificate?domain=...`) with a SHA-256 Merkle root over extracted entity facts (`claimRoot`), DOM prompt-injection check (`injectionFree`), bounded expiration (`expiresAt`), and asymmetric **Ed25519** signature verifiable offline against `https://www.proofxray.com/.well-known/jwks.json`.

---

## 2. Deterministic Verification in CLI or Python (Zero Magic)

```bash
git clone https://github.com/monsieureka/autonomous-enterprise-standard.git
cd autonomous-enterprise-standard

# Instant verification via Node.js (verifies Ed25519 offline via JWKS) or Python 3
node bin/cli.js proofxray.com
python3 bin/proof-verify.py proofxray.com
```

Or import the included local LangChain / CrewAI tool directly from this repository:

```python
from integrations.langchain.proof_tool import ProofVerifyTool

result = ProofVerifyTool().run("proofxray.com")
print(result["status"], result["score"], result["claimRoot"])
```

---

## 3. Join & Inspect the Standard

- **Open-Source Specification (MIT):** https://github.com/monsieureka/autonomous-enterprise-standard
- **Live Canonical Page:** https://www.proofxray.com/entreprise-autonome-internationale
- **Live Certificate API:** `GET https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com`
- **Public Ed25519 JWKS:** `GET https://www.proofxray.com/.well-known/jwks.json`
