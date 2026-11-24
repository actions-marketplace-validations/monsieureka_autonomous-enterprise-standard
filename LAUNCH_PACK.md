# Kit de Lancement Vérifié : PROOF X-Ray & Standard EAI / PROOF-VC v2

> **Règle de vérité stricte :** Tous les liens, endpoints et snippets ci-dessous correspondent à du code réellement déployé et testable en direct (zéro import fictif, zéro 404).

---

## 1. Show HN (Hacker News)

**Title:**
`Show HN: PROOF-VC v2 – Deterministic 48-signal HTML/GEO audit & Ed25519 certificate spec for AI agents`

**Text:**
> Hi HN,
>
> I built **PROOF X-Ray** (`https://www.proofxray.com`) to audit how websites are actually read by search engines and AI crawlers (raw HTML without JS execution, 48 deterministic signals, zero LLM hallucination — unmeasured items are explicitly marked "unmeasured").
>
> Today I'm open-sourcing the **EAI v1.0 / PROOF-VC v2** spec and zero-dependency CLI verifiers (Node.js & Python 3) under MIT:
> https://github.com/monsieureka/autonomous-enterprise-standard
>
> What is actually live right now:
> - Free 10-second raw-HTML audit (international: FR/EN/DE/ES, multi-currency, E.164 phones) + DOM prompt-injection & Unicode steganography guard
> - Public multi-domain certificate JSON API: `GET https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com`
> - Deterministic SHA-256 Merkle root over extracted entity facts (`claimRoot`), bounded expiration (`expiresAt`), and asymmetric **Ed25519** signatures verifiable offline via `https://www.proofxray.com/.well-known/jwks.json`
> - Root-homepage anti-poisoning guard (subpage scans cannot overwrite a domain's certificate)
>
> Try it locally with zero deps:
> `git clone https://github.com/monsieureka/autonomous-enterprise-standard && node autonomous-enterprise-standard/bin/cli.js proofxray.com`
>
> Would love brutal technical feedback on the scoring invariants, prompt-injection DOM guard, and Ed25519 attestation schema!

---

## 2. Thread X / Twitter

### Tweet 1
> AI agents reading raw web HTML face two silent failure modes:
> 1. Blindly trusting self-asserted `llms.txt` / JSON-LD
> 2. Indirect prompt injection hidden in DOM / Unicode tags
>
> Today we're open-sourcing **PROOF-VC v2** (MIT): deterministic HTML/GEO audits with Merkle `claimRoot`, DOM injection guard & offline-verifiable Ed25519 certificates (`/.well-known/jwks.json`).

### Tweet 2
> Every audited root homepage gets:
> - Live public certificate page (`/certifie/<domain>`)
> - JSON attestation API (`/api/public/v1/certificate?domain=...`)
> - Dynamic SVG badge (`/api/badge?domain=...`)
> - Zero-dep Node & Python CLI verifiers
>
> Repo (MIT): https://github.com/monsieureka/autonomous-enterprise-standard

---

## 3. Post LinkedIn (B2B & Presse)

> Les moteurs de réponse IA (ChatGPT Search, Perplexity, Claude, Gemini) lisent le HTML brut de votre site, sans exécuter JavaScript.
>
> Nous publions aujourd'hui en open-source (licence MIT) la spécification **EAI v1.0 / PROOF-VC v2** et ses outils CLI de vérification :
> - Audit déterministe en ~10 secondes sur 48 signaux SEO & GEO (ce qui n'est pas mesuré reste indiqué « non mesuré ») ;
> - Pare-feu déterministe anti-injection de prompt et anti-stéganographie DOM ;
> - Certificat public `/certifie/<domaine>` + racine Merkle des faits d'entité + signature asymétrique Ed25519 vérifiable hors-ligne via `/.well-known/jwks.json`.
>
> Dépôt open-source : https://github.com/monsieureka/autonomous-enterprise-standard
> Diagnostic gratuit (10 s, sans inscription) : https://www.proofxray.com/
