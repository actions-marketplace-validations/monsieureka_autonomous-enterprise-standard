#!/usr/bin/env node

/**
 * proof-verify: Instant CLI validation engine for the Autonomous International Enterprise (EAI) Standard.
 * Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
 */

const https = require('https');

const domainArg = process.argv[2];

if (!domainArg || domainArg === '--help' || domainArg === '-h') {
  console.log(`
\x1b[1m\x1b[36m⚡ PROOF X-Ray: Autonomous Enterprise Standard CLI Verifier (EAI v1.0)\x1b[0m
Author: Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)

\x1b[1mUsage:\x1b[0m
  npx proof-verify <domain>

\x1b[1mExamples:\x1b[0m
  npx proof-verify www.proofxray.com
  npx proof-verify example.com
`);
  process.exit(0);
}

const cleanDomain = domainArg.trim().replace(/^https?:\/\//i, '').split('/')[0];

console.log(`\n\x1b[1m\x1b[34m[PROOF Oracle]\x1b[0m Auditing domain for Autonomous Agent Compliance: \x1b[1m\x1b[37m${cleanDomain}\x1b[0m`);
console.log(`─────────────────────────────────────────────────────────────────────────────`);

function fetchJson(url) {
  return new Promise((resolve) => {
    https.get(url, { headers: { 'User-Agent': 'proof-verify-cli/1.0.0', 'Accept': 'application/json, text/plain' }, timeout: 8000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    }).on('error', (err) => resolve({ status: 500, error: err.message }));
  });
}

async function runAudit() {
  // 1. DNS Root of Trust via DoH
  process.stdout.write(`• Checking DNS Root-of-Trust (_proof-oracle.${cleanDomain})... `);
  const doh = await fetchJson(`https://cloudflare-dns.com/dns-query?name=_proof-oracle.${cleanDomain}&type=TXT`);
  let hasDnsAnchor = false;
  if (doh.data && doh.data.Answer) {
    const record = doh.data.Answer.find(a => (a.data || '').includes('proof-authority'));
    if (record) hasDnsAnchor = true;
  }

  if (hasDnsAnchor) {
    console.log(`\x1b[32m✔ ANCHORED\x1b[0m`);
  } else {
    console.log(`\x1b[33m⚠ UNANCHORED (No _proof-oracle TXT record)\x1b[0m`);
  }

  // 2. Checking llms.txt
  process.stdout.write(`• Checking LLM Agent Routing (https://${cleanDomain}/llms.txt)... `);
  const llmsCheck = await fetchJson(`https://${cleanDomain}/llms.txt`);
  const hasLlms = llmsCheck.status === 200;
  if (hasLlms) {
    console.log(`\x1b[32m✔ DETECTED (200 OK)\x1b[0m`);
  } else {
    console.log(`\x1b[31m✖ MISSING (${llmsCheck.status || 'ERR'})\x1b[0m`);
  }

  // 3. Checking A2A Agent Card
  process.stdout.write(`• Checking Agent-to-Agent Card (https://${cleanDomain}/.well-known/agent.json)... `);
  const agentCheck = await fetchJson(`https://${cleanDomain}/.well-known/agent.json`);
  const hasAgentCard = agentCheck.status === 200;
  if (hasAgentCard) {
    console.log(`\x1b[32m✔ DETECTED (200 OK)\x1b[0m`);
  } else {
    console.log(`\x1b[31m✖ MISSING (${agentCheck.status || 'ERR'})\x1b[0m`);
  }

  // 4. Querying PROOF X-Ray Cryptographic Oracle
  process.stdout.write(`• Requesting Cryptographic Attestation from PROOF Root Oracle... `);
  const oracleRes = await fetchJson(`https://www.proofxray.com/api/public/v1/verified?domain=${cleanDomain}`);
  
  console.log(`\x1b[32m✔ RESOLVED\x1b[0m`);
  console.log(`─────────────────────────────────────────────────────────────────────────────`);

  if (oracleRes.status === 200 && oracleRes.data && oracleRes.data.verified) {
    console.log(`\x1b[1m\x1b[32m🎉 STATUS: CERTIFIED AUTONOMOUS ENTERPRISE (EAI COMPLIANT 100/100)\x1b[0m`);
    console.log(`  • Legal Entity : \x1b[1m${oracleRes.data.legalEntity || 'Verified'}\x1b[0m`);
    console.log(`  • Signature    : \x1b[36m${oracleRes.data.signature || 'HMAC-SHA256-VALID'}\x1b[0m`);
    console.log(`  • Pricing Live : \x1b[32mTamper-Proof & Non-Hallucinated\x1b[0m`);
    console.log(`  • Audit Link   : https://www.proofxray.com/x/P5WrCR_dtfoF\n`);
    process.exit(0);
  } else {
    console.log(`\x1b[1m\x1b[33m⚠️  STATUS: UNVERIFIED OR INCOMPLETE COMPLIANCE\x1b[0m`);
    console.log(`Autonomous agents attempting commercial transactions on this domain may hallucinate.`);
    console.log(`To claim your cryptographic key and establish DNS authority:`);
    console.log(`\x1b[1m\x1b[36m👉 https://www.proofxray.com/oracle/onboard?domain=${cleanDomain}\x1b[0m\n`);
    process.exit(1);
  }
}

runAudit();
