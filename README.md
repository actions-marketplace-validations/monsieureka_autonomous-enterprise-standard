# The Autonomous International Enterprise (AIE / EAI) Standard — v1.0 & PROOF-VC v2

[![PROOF Verified](https://www.proofxray.com/api/badge?domain=proofxray.com)](https://www.proofxray.com/certifie/proofxray.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-B6FF00.svg)](./LICENSE)
[![Standard: W3C Schema.org](https://img.shields.io/badge/Standard-W3C%20Schema.org-111312.svg)](./schema/eai-v1.jsonld)

> **Canonical open specification of L'Entreprise Autonome Internationale (EAI) / The Autonomous International Enterprise (AIE)** and the **PROOF-VC v2** verifiable web-audit protocol, formalized by **Arthur Mellin** (founder of [PROOF X-Ray](https://www.proofxray.com/)).
>
> **Disambiguation:** PROOF X-Ray (`proofxray.com`) is a deterministic SEO, GEO (Generative Engine Optimization), and AI-visibility software platform. It has no connection with medical X-ray equipment, radiology, or healthcare imaging.

---

## 1. Formal Definition (EAI / AIE v1.0)

In the framework designed by **Arthur Mellin**, an **Autonomous International Enterprise (AIE)** — *Entreprise Autonome Internationale (EAI)* — is an organization operated by **1 to 3 humans** that combines:

1. **Deterministic software rules & verifiable protocols** (public HTML auditing, automated payments, deterministic verification of signed claims).
2. **AI agents & machine-readable distribution** (`llms.txt`, `llms-full.txt`, W3C `Schema.org` `@graph`, and `/.well-known/agent.json` A2A discovery).
3. **End-to-end autonomy across at least two countries** on the same core offer, from organic & AI-engine acquisition to automated delivery.

---

## 2. Pilot Case #001 — PROOF X-Ray (`proofxray.com`)

**PROOF X-Ray** is the live empirical reference implementation (**Cas Pilote EAI #001**) of this standard:

| Pillar | Live Implementation | Endpoint / Proof |
| :--- | :--- | :--- |
| **Platform & Engine** | Deterministic 48-signal / 8-category HTML audit (~10s, zero JS) | [`https://www.proofxray.com/`](https://www.proofxray.com/) |
| **Public Certificate Page** | Live root-homepage verified certificate | [`https://www.proofxray.com/certifie/proofxray.com`](https://www.proofxray.com/certifie/proofxray.com) |
| **PROOF-VC v2 JSON API** | JCS SHA-256 Merkle `claimRoot`, bounded TTL, DOM injection guard & Ed25519 signature | [`/api/public/v1/certificate?domain=proofxray.com`](https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com) |
| **Public Ed25519 JWKS** | Asymmetric verification keys (RFC 7517); the CLIs ship the current key pinned | [`/.well-known/jwks.json`](https://www.proofxray.com/.well-known/jwks.json) |
| **Signed Merkle snapshot** | Ed25519-signed Merkle root over listed domains (a signed snapshot, not an append-only log; it may include expired or alerting domains) | [`/.well-known/transparency-log.json`](https://www.proofxray.com/.well-known/transparency-log.json) |
| **Zero-Token Stapled VC** | Compact ~100-token signed entity & pricing attestation | [`/.well-known/proof-vc.json`](https://www.proofxray.com/.well-known/proof-vc.json) |
| **GEO Benchmark (experimental)** | Experimental: anonymized benchmark endpoint, no measured sample yet (`sampleSize` 0) | [`/api/public/v1/benchmark`](https://www.proofxray.com/api/public/v1/benchmark) |
| **Public Verification Badge** | SVG badge reflecting the last homepage audit; valid 7 days after it (30 days with active monitoring) | [`/api/badge?domain=proofxray.com`](https://www.proofxray.com/api/badge?domain=proofxray.com) |
| **Canonical EAI Page & Press** | Official French canonical page + press kit | [`/entreprise-autonome-internationale`](https://www.proofxray.com/entreprise-autonome-internationale) · [`/presse`](https://www.proofxray.com/presse) |
| **LLM Routing Index** | High-density machine index + full specification | [`llms.txt`](https://www.proofxray.com/llms.txt) · [`llms-full.txt`](https://www.proofxray.com/llms-full.txt) |
| **A2A & Security (RFC 9116)** | Agent-to-Agent discovery card + security policy | [`agent.json`](https://www.proofxray.com/.well-known/agent.json) · [`security.txt`](https://www.proofxray.com/.well-known/security.txt) |

---

## 3. Canonical Machine Schema (W3C JSON-LD)

See [`schema/eai-v1.jsonld`](./schema/eai-v1.jsonld) for the machine-readable `DefinedTermSet`, `DefinedTerm`, and `CreativeWork` definitions implementing this ontology.

---

## 4. PROOF-VC v2 Verification Protocol & CLI Tooling

Autonomous AI agents can verify any audited domain deterministically via the live public API or the included Node.js / Python CLIs:

```bash
# Node.js (zero dependencies, native Ed25519)
node bin/cli.js proofxray.com

# Standalone Python 3 (zero dependencies, pure-Python RFC 8032 Ed25519 fallback)
python3 bin/proof-verify.py proofxray.com

# Or, once published to npm:  npx proof-verify proofxray.com
```

### What the verifiers check, and how they fail

The certificate JSON is **fetched online**. Its Ed25519 attestation is then checked against a public key **pinned in the verifier** (matched by `kid`), so that step needs no network. The tools **fail closed**: exit code `1` (and `FAIL: no valid Ed25519 signature`) when the attestation is missing, malformed, has an unknown `kid`, a digest mismatch or an invalid signature. The score, `certified` flag, domain and expiry are read from the **signed payload**; unsigned top-level fields that disagree with it are rejected. Exit `0` only if the signature is valid, the certificate is not expired, `certified` is true and the score reaches `PROOF_MIN_SCORE` (default 80).

- The key URL written inside the attestation (`jwksUrl`) is **never** used. A missing `kid` is a failure (no fallback to "the first key").
- DNS-01 (`_proof-verify.<domain>`), `llms.txt` and `agent.json` are reported for information and **do not change the exit code**. The DNS check compares the token of the certificate's `dnsChallenge`; it prints `VERIFIED`, `NOT VERIFIED` or `NOT CHECKED` (resolver unreachable, or no usable challenge) and never claims verification it did not perform.
- Trusted keys live in the `PINNED_KEYS` array of `lib/verify.js` and `bin/proof-verify.py`. Currently: `proof-root-2026-11-24` (same key as the published JWKS at the time of writing).

**Key rotation.** To trust a new key, a maintainer adds `{ kid, x }` to both `PINNED_KEYS` arrays (values from `/.well-known/jwks.json`), bumps the version and publishes a new release. Old and new `kid` can be pinned side by side. Until users upgrade, they can opt in explicitly with `--jwks-url <url>` (or `PROOF_JWKS_URL`) to look up an unknown `kid` in that HTTPS JWKS; this prints a visible `UNPINNED KEY (insecure)` warning and the result is labelled as such. Never enable it in CI by default.

### Tests

```bash
npm test                                   # node --test  +  python3 -m unittest (no network needed)
node --test                                # JavaScript only
python3 -m unittest discover -s test -p "test_*.py" -v   # Python only
```

The tests generate a throwaway Ed25519 key and a signed fixture certificate; they cover valid, tampered, missing-attestation, unknown-kid and wrong-key cases. See also [`ci/README.md`](./ci/README.md).

### Zero-Dependency MCP Server (Claude Code, Claude Desktop, Cursor, Antigravity)
Connect PROOF-VC v2 directly to any MCP client with **zero `npm install`**:
```json
{
  "mcpServers": {
    "proof-xray": {
      "command": "node",
      "args": ["/path/to/autonomous-enterprise-standard/mcp/server.js"]
    }
  }
}
```
Exposes `verify_domain_proof`, `get_transparency_log` (the snapshot signature is checked against the pinned key; entries are returned only if it is valid), and `get_causal_geo_benchmark`.

### GitHub Action

```yaml
- uses: monsieureka/autonomous-enterprise-standard@v1.0.0
  with:
    domain: example.com
    min_score: '80'
```
The step fails unless the domain's certificate has a valid pinned-key Ed25519 signature, is not expired, is certified and reaches `min_score`. It needs `python3` on the runner (present on GitHub-hosted Ubuntu runners; not tested here).

### Live API Query
```http
GET https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com HTTP/1.1
Host: www.proofxray.com
Accept: application/json
```

### Draft Specifications (Proposals — Not Active On-Chain Services)
- [`schema/dns-handshake.md`](./schema/dns-handshake.md) — RFC Draft for optional DNS-01 ownership anchor (`_proof-verify`) and offline Ed25519 JWKS verification.
- [`schema/IProofOracle.sol`](./schema/IProofOracle.sol) — RFC Draft Solidity interface (EIP-712 ECDSA bridge proposal).
- [`schema/AGENTIC_HANDOVER_PROTOCOL.md`](./schema/AGENTIC_HANDOVER_PROTOCOL.md) — Deterministic JSON session handover spec (`agent_state.json`).

---

## 5. Published Reference Works by Arthur Mellin

The EAI / GEO methodology is grounded in Arthur Mellin's published books (Amazon KDP, registered ISBNs):

- ***Le SEO ne suffit plus*** (2026) — ISBN `9798167459038` (Broché) / `9798143487390` (Relié) · [Amazon](https://www.amazon.fr/dp/B0HPHNC533)
- ***Travailler avec Claude*** (2026) — ISBN `9798167459458` (Broché) · [Amazon](https://www.amazon.fr/dp/B0HQ8NQ6VG)
- ***L'IA au travail*** (2026) — ISBN `9798166046079` (Broché) / `9798140904432` (Relié) · [Amazon](https://www.amazon.fr/dp/B0HQJSH4K2)
- Full catalog: [`https://www.proofxray.com/livre`](https://www.proofxray.com/livre)

---

## 6. Publisher, Legal Entity & Licensing

- **Author & Founder:** Arthur Mellin ([proofxray.com/a-propos](https://www.proofxray.com/a-propos))
- **Legal Entity:** Arthur Mellin — Entrepreneur Individuel (SIRET `509 969 622 00067`), 16 rue de la République, 95270 Chaumontel, France
- **Contact:** `contact@proofxray.com`
- **License:** [MIT License](./LICENSE) (code & specifications). See [TRADEMARKS.md](./TRADEMARKS.md) for trademark and root-key authority policy.
