"""Connector fail-closed tests (no network, no langchain/crewai needed): the shared core must reject
unsigned, tampered or wrong-domain certificates and must reject when the verifier cannot be loaded."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "integrations"))
import _proof_core  # noqa: E402


class ConnectorCore(unittest.TestCase):
    def test_unsigned_certificate_is_rejected(self):
        v = _proof_core.evaluate({"domain": "exemple.fr", "score": 99, "certified": True}, "exemple.fr")
        self.assertEqual(v["status"], "UNVERIFIED")
        self.assertFalse(v["ok"])

    def test_garbage_attestation_is_rejected(self):
        v = _proof_core.evaluate({"domain": "exemple.fr", "score": 99, "certified": True, "attestation": {"payload": {}}}, "exemple.fr")
        self.assertEqual(v["status"], "UNVERIFIED")

    def test_non_dict_certificate_is_rejected(self):
        self.assertEqual(_proof_core.evaluate(None, "exemple.fr")["status"], "UNVERIFIED")

    def test_missing_verifier_fails_closed(self):
        saved, _proof_core._PATH = _proof_core._PATH, "/nonexistent/proof-verify.py"
        _proof_core._module = None
        try:
            v = _proof_core.evaluate({"attestation": {}}, "exemple.fr")
            self.assertEqual(v["status"], "UNVERIFIED")
            self.assertIn("verifier_unavailable", v["reason"])
        finally:
            _proof_core._PATH, _proof_core._module = saved, None


if __name__ == "__main__":
    unittest.main()
