"""Tests for meok_attestation_api core — sign + verify + tamper detection + expiry."""
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow running tests from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from meok_attestation_api import (
    AttestationSigner,
    AttestationVerifier,
    canonical_payload,
    make_signer,
    make_verifier,
)


KEY = b"test-signing-key-for-unit-tests-only-do-not-use-in-prod"


def test_canonical_payload_is_deterministic():
    """Same input → same bytes regardless of dict ordering."""
    a = {"b": 1, "a": 2, "c": [3, 2, 1]}
    b = {"c": [3, 2, 1], "a": 2, "b": 1}
    assert canonical_payload(a) == canonical_payload(b)


def test_sign_pro_tier():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(
        regulation="EU AI Act",
        entity="Acme Corp",
        score=85.0,
        findings=["Art 9 risk mgmt in place", "Art 13 transparency documented"],
        articles_audited=["Art 9", "Art 13"],
    )
    assert cert["tier"] == "pro"
    assert cert["cert_id"].startswith("MEOK-") and "EU" in cert["cert_id"]
    assert "signature_sha256_hmac" in cert
    assert "verify_url" in cert
    assert "https://proofof.ai/v/" in cert["verify_url"]
    assert cert["assessment"] == "COMPLIANT"
    print(f"  ✓ pro cert_id={cert['cert_id']}")


def test_sign_free_tier_marks_unverified():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(
        regulation="DORA", entity="Acme", score=60.0, findings=[], tier="free"
    )
    assert cert["tier"] == "free"
    assert "UNVERIFIED" in cert["assessment"]
    assert "free_tier_notice" in cert
    assert "verify_url_unavailable" in cert
    assert "verify_url" not in cert
    print(f"  ✓ free cert_id={cert['cert_id']}")


def test_sign_partial_assessment():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="NIS2", entity="X", score=50.0, findings=[])
    assert cert["assessment"] == "PARTIAL"
    print("  ✓ score=50 → PARTIAL")


def test_sign_non_compliant():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="CRA", entity="X", score=10.0, findings=[])
    assert cert["assessment"] == "NON_COMPLIANT"
    print("  ✓ score=10 → NON_COMPLIANT")


def test_verify_valid_pro_cert():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="EU AI Act", entity="Acme", score=85.0, findings=[])
    verifier = AttestationVerifier(signing_key=KEY)
    ok, msg = verifier.verify(cert)
    assert ok, f"verify failed: {msg}"
    assert msg == "Signature valid"
    print("  ✓ pro cert round-trips")


def test_verify_with_dict_payload_also_works():
    """Accept both canonical-JSON-string and dict forms of payload."""
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="DORA", entity="X", score=80.0, findings=[])
    # Convert payload string to dict — verifier should re-canonicalise
    cert["payload"] = json.loads(cert["payload"])
    verifier = AttestationVerifier(signing_key=KEY)
    ok, msg = verifier.verify(cert)
    assert ok, f"dict payload verify failed: {msg}"
    print("  ✓ dict payload form verifies")


def test_verify_tampered_payload_fails():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="EU AI Act", entity="Acme", score=85.0, findings=[])
    # Tamper with score
    payload = json.loads(cert["payload"])
    payload["score_percent"] = 99.99
    cert["payload"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    verifier = AttestationVerifier(signing_key=KEY)
    ok, msg = verifier.verify(cert)
    assert not ok
    assert "tampered" in msg or "mismatch" in msg
    print("  ✓ tampered cert rejected")


def test_verify_wrong_key_fails():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(regulation="EU AI Act", entity="Acme", score=85.0, findings=[])
    verifier = AttestationVerifier(signing_key=b"different-key")
    ok, msg = verifier.verify(cert)
    assert not ok
    print("  ✓ wrong key rejected")


def test_verify_expired_cert_fails():
    signer = AttestationSigner(signing_key=KEY)
    cert = signer.sign(
        regulation="EU AI Act",
        entity="Acme",
        score=85.0,
        findings=[],
        validity_days=-1,  # already expired
    )
    verifier = AttestationVerifier(signing_key=KEY)
    ok, msg = verifier.verify(cert)
    assert not ok
    assert "expired" in msg.lower()
    print("  ✓ expired cert rejected")


def test_verify_missing_payload_fails():
    verifier = AttestationVerifier(signing_key=KEY)
    ok, msg = verifier.verify({"cert_id": "x", "signature_sha256_hmac": "y"})
    assert not ok
    assert "Missing" in msg
    print("  ✓ missing payload rejected")


def test_make_signer_accepts_hex_key():
    s = make_signer("deadbeef" * 8)
    cert = s.sign(regulation="EU AI Act", entity="X", score=80.0, findings=[])
    assert cert["cert_id"].startswith("MEOK-")
    print("  ✓ make_signer with hex key")


def test_make_signer_accepts_utf8_key():
    s = make_signer("hello-world-string-key")
    cert = s.sign(regulation="DORA", entity="X", score=80.0, findings=[])
    assert cert["cert_id"].startswith("MEOK-")
    print("  ✓ make_signer with utf-8 key")


def test_make_verifier_round_trip():
    s = make_signer("my-secret-key-1234")
    cert = s.sign(regulation="EU AI Act", entity="Acme", score=80.0, findings=[])
    v = make_verifier("my-secret-key-1234")
    ok, _ = v.verify(cert)
    assert ok
    print("  ✓ make_verifier round-trip")


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"✓ {t.__name__}")
        except AssertionError as e:
            print(f"✗ {t.__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed} test(s) FAILED")
        sys.exit(1)
    print(f"\n✅ All {len(tests)} tests passed")
