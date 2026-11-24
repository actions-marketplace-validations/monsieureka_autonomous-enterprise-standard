#!/usr/bin/env python3
"""
proof-verify: Standalone Python 3 CLI verifier for the Autonomous International Enterprise (EAI) Standard & PROOF-VC v2.
Queries live https://www.proofxray.com/api/public/v1/certificate, verifies SHA-256 JCS digest and offline Ed25519
signature against /.well-known/jwks.json with zero external dependencies (RFC 8032 pure-Python fallback), and emits
GitHub Actions outputs when GITHUB_OUTPUT is set.
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


def fetch_json(url: str, accept: str = "application/json, text/plain", redirects: int = 3):
    req = urllib.request.Request(url, headers={"User-Agent": "proof-verify-cli/2.0.0", "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            raw = res.read().decode("utf-8", errors="replace")
            try:
                return res.status, json.loads(raw)
            except Exception:
                return res.status, raw
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location") and redirects > 0:
            next_url = urllib.parse.urljoin(url, e.headers.get("Location"))
            return fetch_json(next_url, accept, redirects - 1)
        return e.code, None
    except Exception:
        return 500, None


# ── Pure-Python RFC 8032 Ed25519 verifier (zero external dependencies) ─────────
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * _ED_D * t1 * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_point_mul(s: int, pt):
    acc = (0, 1, 1, 0)
    addend = pt
    while s > 0:
        if s & 1:
            acc = _ed_point_add(acc, addend)
        addend = _ed_point_add(addend, addend)
        s >>= 1
    return acc


def _ed_point_equal(p1, p2) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def _ed_point_decompress(buf: bytes):
    if len(buf) != 32:
        return None
    y = int.from_bytes(buf, "little") & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    sign = buf[31] >> 7
    u = (y * y - 1) % _ED_P
    v = (_ED_D * y * y + 1) % _ED_P
    x2 = (u * pow(v, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        if sign == 1:
            return None
        x = 0
    else:
        x = pow(x2, (_ED_P + 3) // 8, _ED_P)
        if (x * x - x2) % _ED_P != 0:
            x = (x * _ED_I) % _ED_P
        if (x * x - x2) % _ED_P != 0:
            return None
        if (x & 1) != sign:
            x = _ED_P - x
    return (x, y, 1, (x * y) % _ED_P)


def _ed_base_point():
    by = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
    u = (by * by - 1) % _ED_P
    v = (_ED_D * by * by + 1) % _ED_P
    x2 = (u * pow(v, _ED_P - 2, _ED_P)) % _ED_P
    bx = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (bx * bx - x2) % _ED_P != 0:
        bx = (bx * _ED_I) % _ED_P
    if bx & 1:
        bx = _ED_P - bx
    return (bx, by, 1, (bx * by) % _ED_P)


_ED_B = _ed_base_point()


def ed25519_verify_pure(pub_bytes: bytes, sig_bytes: bytes, msg: bytes) -> bool:
    if len(pub_bytes) != 32 or len(sig_bytes) != 64:
        return False
    a_pt = _ed_point_decompress(pub_bytes)
    r_pt = _ed_point_decompress(sig_bytes[:32])
    if a_pt is None or r_pt is None:
        return False
    s_int = int.from_bytes(sig_bytes[32:], "little")
    if s_int >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig_bytes[:32] + pub_bytes + msg).digest(), "little") % _ED_L
    return _ed_point_equal(_ed_point_mul(s_int, _ED_B), _ed_point_add(r_pt, _ed_point_mul(k, a_pt)))


def verify_attestation_offline(attestation: dict):
    sig = attestation.get("signature") or {}
    if sig.get("alg") != "Ed25519":
        return False, "no_ed25519_attestation"
    expected_digest = hashlib.sha256(canonical_json(attestation.get("payload", {})).encode("utf-8")).hexdigest()
    if expected_digest != attestation.get("digest"):
        return False, "digest_mismatch"

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
    pub_bytes = base64.urlsafe_b64decode(x_pad)
    sig_bytes = base64.urlsafe_b64decode(sig_pad)
    message = f"proof-vc-v2\n{expected_digest}".encode("utf-8")

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, message)
        return True, "VALID (verified offline)"
    except ImportError:
        if ed25519_verify_pure(pub_bytes, sig_bytes, message):
            return True, "VALID (verified offline, pure-python RFC 8032)"
        return False, "invalid_signature"
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
