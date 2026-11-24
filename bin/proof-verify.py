#!/usr/bin/env python3
"""
proof-verify: Standalone Python 3 CLI verifier for the Autonomous International Enterprise (EAI) Standard & PROOF-VC v2.
Queries live https://www.proofxray.com/api/public/v1/certificate, verifies SHA-256 JCS digest (and Ed25519 offline if
`cryptography` is installed), and emits GitHub Actions outputs when GITHUB_OUTPUT is set.
Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
"""

import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def print_help():
    print(
        "\nPROOF X-Ray — Autonomous Enterprise Standard CLI Verifier (EAI v1.0 / PROOF-VC v2)\n"
        "Usage:\n"
        "  python3 bin/proof-verify.py <domain>\n\n"
        "Examples:\n"
        "  python3 bin/proof-verify.py proofxray.com\n"
        "  python3 bin/proof-verify.py example.com\n"
    )
    sys.exit(0)


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_github_outputs(status: str, score: str, certified: bool):
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(f"status={status}\n")
        fh.write(f"score={score}\n")
        fh.write(f"certified={'true' if certified else 'false'}\n")


def fetch_json(url: str, accept: str = "application/json, text/plain"):
    req = urllib.request.Request(url, headers={"User-Agent": "proof-verify-cli/2.0.0", "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            raw = res.read().decode("utf-8", errors="replace")
            try:
                return res.status, json.loads(raw)
            except Exception:
                return res.status, raw
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 500, None


def verify_attestation_offline(attestation: dict):
    sig = attestation.get("signature") or {}
    if sig.get("alg") != "Ed25519":
        return False, "no_ed25519_attestation"
    expected_digest = hashlib.sha256(canonical_json(attestation.get("payload", {})).encode("utf-8")).hexdigest()
    if expected_digest != attestation.get("digest"):
        return False, "digest_mismatch"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return True, "digest_ok_ed25519_lib_not_installed"

    jwks_url = sig.get("jwksUrl") or "https://www.proofxray.com/.well-known/jwks.json"
    st, jwks = fetch_json(jwks_url, "application/json")
    if st != 200 or not isinstance(jwks, dict):
        return False, "jwks_unreachable"
    keys = jwks.get("keys") or []
    jwk = next((k for k in keys if k.get("kid") == sig.get("kid")), keys[0] if keys else None)
    if not jwk or not jwk.get("x"):
        return False, "jwks_key_not_found"
    x_pad = jwk["x"] + "=" * (-len(jwk["x"]) % 4)
    sig_pad = sig["value"] + "=" * (-len(sig["value"]) % 4)
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x_pad))
        pub.verify(base64.urlsafe_b64decode(sig_pad), f"proof-vc-v2\n{expected_digest}".encode("utf-8"))
        return True, "ed25519_verified_offline"
    except Exception:
        return False, "invalid_signature"


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_help()

    raw = sys.argv[1].strip().lower()
    raw = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0].removeprefix("www.").rstrip(".")
    if not DOMAIN_RE.match(raw):
        print(f"Error: invalid domain '{sys.argv[1]}'", file=sys.stderr)
        write_github_outputs("INVALID", "", False)
        sys.exit(2)

    min_score = int(os.environ.get("PROOF_MIN_SCORE", "80"))
    print(f"\n[PROOF-VC v2] Verifying domain: {raw}")
    print("─" * 77)

    # 1. DNS-01 Ownership TXT (_proof-verify.<domain>)
    sys.stdout.write(f"• DNS-01 Ownership TXT (_proof-verify.{raw})... ")
    sys.stdout.flush()
    doh_status, doh = fetch_json(
        f"https://cloudflare-dns.com/dns-query?name=_proof-verify.{urllib.parse.quote(raw)}&type=TXT",
        "application/dns-json",
    )
    has_dns = False
    if doh_status == 200 and isinstance(doh, dict):
        has_dns = any("proof-v2=" in str(a.get("data", "")) for a in doh.get("Answer", []))
    print("✔ ANCHORED" if has_dns else "○ OPTIONAL (not anchored)")

    # 2. llms.txt
    sys.stdout.write(f"• LLM Routing Index (https://{raw}/llms.txt)... ")
    sys.stdout.flush()
    llms_status, _ = fetch_json(f"https://{raw}/llms.txt", "text/markdown, text/plain")
    print("✔ 200 OK" if llms_status == 200 else f"✖ {llms_status}")

    # 3. A2A Agent Card
    sys.stdout.write(f"• A2A Agent Card (https://{raw}/.well-known/agent.json)... ")
    sys.stdout.flush()
    agent_status, _ = fetch_json(f"https://{raw}/.well-known/agent.json", "application/json")
    print("✔ 200 OK" if agent_status == 200 else f"✖ {agent_status}")

    # 4. Live Certificate API
    sys.stdout.write("• Querying PROOF Public Certificate API... ")
    sys.stdout.flush()
    cert_status, cert = fetch_json(
        f"https://www.proofxray.com/api/public/v1/certificate?domain={urllib.parse.quote(raw)}",
        "application/json",
    )
    if cert_status != 200 or not isinstance(cert, dict) or cert.get("status") != "verified":
        print(f"✖ HTTP {cert_status}")
        print("─" * 77)
        print(f"STATUS: UNVERIFIED (No completed root-homepage audit found for {raw})")
        print("Run a free 10-second deterministic X-Ray audit at:")
        print("  https://www.proofxray.com/#audit-gratuit\n")
        write_github_outputs("UNVERIFIED", "", False)
        sys.exit(1)

    print("✔ 200 OK")
    score = int(cert.get("score", 0))
    sig_ok = True
    sig_note = None
    if isinstance(cert.get("attestation"), dict):
        sig_ok, sig_note = verify_attestation_offline(cert["attestation"])

    is_certified = bool(cert.get("certified")) and score >= min_score and sig_ok
    status_label = "CERTIFIED" if is_certified else "AUDITED"
    write_github_outputs(status_label, str(score), is_certified)

    print("─" * 77)
    print(f"  • Status         : {status_label}")
    print(f"  • Domain         : {cert.get('domain')}")
    print(f"  • PROOF Score    : {score}/100")
    print(f"  • Audited At     : {cert.get('auditedAt')}")
    if cert.get("expiresAt"):
        print(f"  • Expires At     : {cert.get('expiresAt')} ({cert.get('tier', 'snapshot')})")
    print(f"  • SHA-256 Digest : {cert.get('fingerprint')}")
    if cert.get("claimRoot"):
        print(f"  • Merkle Claims  : {cert.get('claimRoot')}")
    if sig_note:
        print(f"  • Ed25519 Check  : {sig_note}")
    print(f"  • Public Cert    : {cert.get('certificateUrl')}")
    print(f"  • Live Badge     : {cert.get('badgeUrl')}\n")
    sys.exit(0 if is_certified else 1)


if __name__ == "__main__":
    main()
