"""Loads the repository's fail-closed verifier (bin/proof-verify.py) for the LangChain and CrewAI connectors.

The connectors never decide trust themselves: they call `evaluate_certificate`, which requires a valid Ed25519
signature from a PINNED key and reads score/domain/expiry from the signed payload. If the verifier cannot be
loaded, `evaluate` returns an UNVERIFIED result (fail closed)."""
import importlib.util
import os
from typing import Any, Dict

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "proof-verify.py")
_module = None


def _load():
    global _module
    if _module is None:
        spec = importlib.util.spec_from_file_location("proof_verify_core", _PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _module = mod
    return _module


def evaluate(cert: Any, domain: str, min_score: int = 80) -> Dict[str, Any]:
    try:
        return _load().evaluate_certificate(cert, domain, min_score=min_score)
    except Exception as exc:  # verifier missing or broken: never accept
        return {"status": "UNVERIFIED", "ok": False, "score": None, "reason": f"verifier_unavailable: {exc}",
                "signature": {"valid": False, "reason": "verifier_unavailable"}, "payload": None}
