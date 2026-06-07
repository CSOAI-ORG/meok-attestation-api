"""Regression test for the /verify trust anchor.

Both documented VerifyRequest forms (canonical-JSON string AND JSON object) must
round-trip through sign->verify. The object form previously crashed with
"'dict' object has no attribute 'encode'" — see verify_attestation().

Run: MEOK_ATTESTATION_KEY=x MEOK_API_KEY_PEPPER=y python -m pytest tests/
"""
import os
import sys

os.environ.setdefault("MEOK_ATTESTATION_KEY", "test-key-deterministic")
os.environ.setdefault("MEOK_API_KEY_PEPPER", "test-pepper")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import index as idx  # noqa: E402

_PAYLOAD = {
    "entity": "Acme",
    "regulation": "EU_AI_ACT",
    "score": 92,
    "expires_utc": "2027-06-07T00:00:00+00:00",
}


def _sig(payload):
    return idx._sign_bytes(idx._canonical_payload(payload))


def test_canonical_string_form_verifies():
    canonical = idx._canonical_payload(_PAYLOAD).decode()
    ok, msg = idx.verify_attestation(
        {"payload": canonical, "signature_sha256_hmac": _sig(_PAYLOAD)}
    )
    assert ok is True, msg


def test_object_form_verifies():
    # The form that used to crash on dict.encode()
    ok, msg = idx.verify_attestation(
        {"payload": _PAYLOAD, "signature_sha256_hmac": _sig(_PAYLOAD)}
    )
    assert ok is True, msg
    assert "no attribute 'encode'" not in msg


def test_tampered_object_rejected_cleanly():
    tampered = {**_PAYLOAD, "score": 100}
    ok, msg = idx.verify_attestation(
        {"payload": tampered, "signature_sha256_hmac": _sig(_PAYLOAD)}
    )
    assert ok is False
    assert "mismatch" in msg
    assert "no attribute 'encode'" not in msg


if __name__ == "__main__":
    test_canonical_string_form_verifies()
    test_object_form_verifies()
    test_tampered_object_rejected_cleanly()
    print("ALL PASS")
