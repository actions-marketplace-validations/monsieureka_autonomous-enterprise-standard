#!/usr/bin/env node

/**
 * proof-verify: Deterministic CLI verifier for the Autonomous International Enterprise (EAI) Standard & PROOF-VC v2.
 * Queries live https://www.proofxray.com/api/public/v1/certificate and verifies Ed25519 attestations offline via /.well-known/jwks.json.
 * Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
 */

const https = require('node:https');
const crypto = require('node:crypto');

const domainArg = process.argv[2];

if (!domainArg || domainArg === '--help' || domainArg === '-h') {
  console.log(`
\x1b[1m\x1b[36mPROOF X-Ray — Autonomous Enterprise Standard CLI Verifier (EAI v1.0 / PROOF-VC v2)\x1b[0m
Author: Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)

\x1b[1mUsage:\x1b[0m
  node bin/cli.js <domain>

\x1b[1mExamples:\x1b[0m
  node bin/cli.js proofxray.com
  node bin/cli.js example.com
`);
  process.exit(0);
}

const cleanDomain = domainArg
  .trim()
  .toLowerCase()
  .replace(/^https?:\/\//i, '')
  .split('/')[0]
  .replace(/:\d+$/, '')
  .replace(/^www\./, '')
  .replace(/\.$/, '');

if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleanDomain)) {
  console.error(`\x1b[31mError: invalid domain "${domainArg}"\x1b[0m`);
  process.exit(2);
}

const minScore = Number(process.env.PROOF_MIN_SCORE || 80);

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

function fetchUrl(url, accept = 'application/json, text/plain', redirects = 3) {
  return new Promise((resolve) => {
    const req = https.get(
      url,
      { headers: { 'User-Agent': 'proof-verify-cli/2.0.0', Accept: accept }, timeout: 8000 },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
          res.resume();
          const next = new URL(res.headers.location, url).toString();
          return resolve(fetchUrl(next, accept, redirects - 1));
        }
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(data) });
          } catch {
            resolve({ status: res.statusCode, data });
          }
        });
      },
    );
    req.on('timeout', () => { req.destroy(); resolve({ status: 408, error: 'timeout' }); });
    req.on('error', (err) => resolve({ status: 500, error: err.message }));
  });
}

async function verifyEd25519Offline(attestation) {
  if (!attestation || !attestation.signature || attestation.signature.alg !== 'Ed25519') {
    return { checked: false, valid: false, reason: 'no_ed25519_attestation' };
  }
  const expectedDigest = crypto.createHash('sha256').update(canonicalJson(attestation.payload)).digest('hex');
  if (expectedDigest !== attestation.digest) {
    return { checked: true, valid: false, reason: 'digest_mismatch' };
  }
  const jwksRes = await fetchUrl(attestation.signature.jwksUrl || 'https://www.proofxray.com/.well-known/jwks.json');
  const keys = Array.isArray(jwksRes.data?.keys) ? jwksRes.data.keys : [];
  const jwk = keys.find((k) => k.kid === attestation.signature.kid) || keys[0];
  if (!jwk) return { checked: true, valid: false, reason: 'jwks_key_not_found' };
  try {
    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const msg = Buffer.from(`proof-vc-v2\n${expectedDigest}`, 'utf8');
    const ok = crypto.verify(null, msg, pub, Buffer.from(attestation.signature.value, 'base64url'));
    return { checked: true, valid: ok, reason: ok ? 'ok' : 'invalid_signature' };
  } catch (e) {
    return { checked: true, valid: false, reason: e.message };
  }
}

async function runAudit() {
  console.log(`\n\x1b[1m\x1b[34m[PROOF-VC v2]\x1b[0m Verifying domain: \x1b[1m${cleanDomain}\x1b[0m`);
  console.log('─────────────────────────────────────────────────────────────────────────────');

  // 1. DNS-01 Ownership Anchor (_proof-verify.<domain> TXT) via Cloudflare DoH
  process.stdout.write(`• DNS-01 Ownership TXT (_proof-verify.${cleanDomain})... `);
  const doh = await fetchUrl(
    `https://cloudflare-dns.com/dns-query?name=_proof-verify.${encodeURIComponent(cleanDomain)}&type=TXT`,
    'application/dns-json',
  );
  const answers = Array.isArray(doh.data?.Answer) ? doh.data.Answer : [];
  const hasDnsAnchor = answers.some((a) => String(a.data || '').includes('proof-v2='));
  console.log(hasDnsAnchor ? '\x1b[32m✔ ANCHORED\x1b[0m' : '\x1b[33m○ OPTIONAL (not anchored)\x1b[0m');

  // 2. llms.txt discovery
  process.stdout.write(`• LLM Routing Index (https://${cleanDomain}/llms.txt)... `);
  const llmsCheck = await fetchUrl(`https://${cleanDomain}/llms.txt`, 'text/markdown, text/plain');
  console.log(llmsCheck.status === 200 ? '\x1b[32m✔ 200 OK\x1b[0m' : `\x1b[33m✖ ${llmsCheck.status}\x1b[0m`);

  // 3. A2A Agent Card discovery
  process.stdout.write(`• A2A Agent Card (https://${cleanDomain}/.well-known/agent.json)... `);
  const agentCheck = await fetchUrl(`https://${cleanDomain}/.well-known/agent.json`, 'application/json');
  console.log(agentCheck.status === 200 ? '\x1b[32m✔ 200 OK\x1b[0m' : `\x1b[33m✖ ${agentCheck.status}\x1b[0m`);

  // 4. Live Public Certificate API
  process.stdout.write('• Querying PROOF Public Certificate API... ');
  const certUrl = `https://www.proofxray.com/api/public/v1/certificate?domain=${encodeURIComponent(cleanDomain)}`;
  const certRes = await fetchUrl(certUrl, 'application/json');
  if (certRes.status !== 200 || !certRes.data || certRes.data.status !== 'verified') {
    console.log(`\x1b[33m✖ HTTP ${certRes.status}\x1b[0m`);
    console.log('─────────────────────────────────────────────────────────────────────────────');
    console.log(`\x1b[1m\x1b[33mSTATUS: UNVERIFIED (No completed root-homepage audit found for ${cleanDomain})\x1b[0m`);
    console.log('Run a free 10-second deterministic X-Ray audit at:');
    console.log('  https://www.proofxray.com/#audit-gratuit\n');
    process.exit(1);
  }
  console.log('\x1b[32m✔ 200 OK\x1b[0m');

  const cert = certRes.data;
  const sigCheck = cert.attestation ? await verifyEd25519Offline(cert.attestation) : null;
  const score = Number(cert.score);
  const certified = Boolean(cert.certified) && score >= minScore && (!sigCheck || !sigCheck.checked || sigCheck.valid);

  console.log('─────────────────────────────────────────────────────────────────────────────');
  console.log(`  • Domain         : ${cert.domain}`);
  console.log(`  • PROOF Score    : ${score}/100 (certified: ${cert.certified ? 'yes' : 'no'})`);
  console.log(`  • Audited At     : ${cert.auditedAt}`);
  if (cert.expiresAt) console.log(`  • Expires At     : ${cert.expiresAt} (${cert.tier || 'snapshot'})`);
  console.log(`  • SHA-256 Digest : ${cert.fingerprint}`);
  if (cert.claimRoot) console.log(`  • Merkle Claims  : ${cert.claimRoot}`);
  if (sigCheck && sigCheck.checked) {
    console.log(`  • Ed25519 JWKS   : ${sigCheck.valid ? '\x1b[32mVALID (verified offline)\x1b[0m' : `\x1b[31mINVALID (${sigCheck.reason})\x1b[0m`}`);
  }
  console.log(`  • Public Cert    : ${cert.certificateUrl}`);
  console.log(`  • Live Badge     : ${cert.badgeUrl}\n`);

  process.exit(certified ? 0 : 1);
}

runAudit();
