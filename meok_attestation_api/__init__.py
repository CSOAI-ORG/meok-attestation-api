"""
MEOK Attestation Core — pure stdlib HMAC signing/verification.

Extracted from api/index.py (Vercel serverless) into a proper Python package
so it can be `pip install meok-attestation-api` and used standalone.

The core principle: deterministic JSON canonicalisation + HMAC-SHA256.

Usage:
    from meok_attestation_api import AttestationSigner, AttestationVerifier

    signer = AttestationSigner(signing_key="...")
    cert = signer.sign(
        regulation="EU AI Act",
        entity="Acme Corp",
        score=85.0,
        findings=["Art 9 risk mgmt", "Art 13 transparency"],
    )

    verifier = AttestationVerifier(signing_key="...")
    ok, msg = verifier.verify(cert)

The signing key is a server-side secret. Clients only see the signed cert.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional


# ── Canonicalisation ────────────────────────────────────────────────────


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON for stable signatures. sort_keys + no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Tier assessment ────────────────────────────────────────────────────


def _assess(score: float) -> str:
    if score >= 70:
        return "COMPLIANT"
    if score >= 40:
        return "PARTIAL"
    return "NON_COMPLIANT"


# ── Signer ──────────────────────────────────────────────────────────────


@dataclass
class AttestationSigner:
    """HMAC-SHA256 signer for compliance attestations.

    Pure stdlib. The signing_key is the only state. No I/O, no network,
    no env-var reads — keep it testable and embeddable.
    """

    signing_key: bytes
    verify_base: str = "https://proofof.ai/v"
    issuer: str = "MEOK AI Labs"
    issuer_url: str = "https://meok.ai"

    def sign(
        self,
        regulation: str,
        entity: str,
        score: float,
        findings: list[str],
        articles_audited: Optional[list[str]] = None,
        tier: str = "pro",
        auditor_notes: str = "",
        validity_days: int = 365,
    ) -> dict[str, Any]:
        """Issue a signed attestation.

        Returns a dict with `cert_id`, `payload` (canonical JSON string),
        `signature_sha256_hmac`, and metadata. Free tier adds UNVERIFIED
        markers and omits the public verify URL.
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)

        raw = _assess(float(score))
        assessment = (
            f"{raw} (UNVERIFIED — free tier)" if tier == "free" else raw
        )

        payload = {
            "regulation": regulation,
            "entity": entity,
            "score_percent": round(float(score), 2),
            "assessment": assessment,
            "findings": findings or [],
            "articles_audited": articles_audited or [],
            "issued_utc": now.isoformat(),
            "expires_utc": expires.isoformat(),
            "tier": tier,
            "issuer": self.issuer,
            "issuer_url": self.issuer_url,
            "auditor_notes": auditor_notes,
            "legal_notice": (
                "This attestation is an automated self-assessment. It does not "
                "substitute for a competent-authority determination, accredited "
                "third-party audit, or legal counsel. MEOK AI Labs provides no "
                "warranty of regulatory correctness."
            ),
        }

        canonical = canonical_payload(payload)
        signature = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest()
        reg_prefix = "".join(c for c in regulation.upper() if c.isalnum())[:6] or "MEOK"
        cert_id = f"MEOK-{reg_prefix}-{signature[:12].upper()}"

        if tier == "free":
            return {
                "free_tier_notice": (
                    "This attestation is UNVERIFIED and cannot be shared with "
                    "auditors. Upgrade to Pro for verifiable signatures."
                ),
                "free_tier_limit": "3 attestations per day",
                "cert_id": cert_id,
                "issued_utc": now.isoformat(),
                "expires_utc": expires.isoformat(),
                "payload": canonical.decode("utf-8"),
                "signature_sha256_hmac": signature,
                "verify_url_unavailable": (
                    "Public verify URLs are a Pro feature."
                ),
                "assessment": assessment,
                "score_percent": payload["score_percent"],
                "regulation": regulation,
                "entity": entity,
                "tier": "free",
                "issuer": self.issuer,
            }

        return {
            "cert_id": cert_id,
            "issued_utc": now.isoformat(),
            "expires_utc": expires.isoformat(),
            "payload": canonical.decode("utf-8"),
            "signature_sha256_hmac": signature,
            "verify_url": f"{self.verify_base}/{cert_id}",
            "assessment": assessment,
            "score_percent": payload["score_percent"],
            "regulation": regulation,
            "entity": entity,
            "tier": tier,
            "issuer": self.issuer,
        }


# ── Verifier ────────────────────────────────────────────────────────────


@dataclass
class AttestationVerifier:
    """Independent HMAC verifier. Any third party can call verify() with the
    signing key and a cert dict to check tamper-evidence + expiry."""

    signing_key: bytes

    def verify(self, cert: dict[str, Any]) -> tuple[bool, str]:
        payload_field = cert.get("payload")
        sig = cert.get("signature_sha256_hmac")
        if not payload_field or not sig:
            return False, "Missing payload or signature"

        # Accept both documented forms of `payload`:
        #   • canonical-JSON string — exactly as emitted by /sign
        #   • JSON object — re-canonicalised here so the HMAC matches the signer
        if isinstance(payload_field, dict):
            payload_bytes = canonical_payload(payload_field)
            payload_str = payload_bytes.decode("utf-8")
        else:
            payload_str = payload_field
            payload_bytes = payload_str.encode("utf-8")

        try:
            expected = hmac.new(self.signing_key, payload_bytes, hashlib.sha256).hexdigest()
        except Exception as e:
            return False, f"Signature recomputation failed: {e}"

        if not hmac.compare_digest(expected, sig):
            return False, "Signature mismatch — cert tampered or wrong signing key"

        try:
            payload = json.loads(payload_str)
            expires = datetime.fromisoformat(payload["expires_utc"])
            if datetime.now(timezone.utc) > expires:
                return False, f"Cert expired on {payload['expires_utc']}"
        except Exception:
            return True, "Signature valid (expiry not checked — payload malformed)"

        return True, "Signature valid"


# ── Convenience module-level helpers ────────────────────────────────────


def make_signer(signing_key: str, **kwargs: Any) -> AttestationSigner:
    """Helper: accept a hex or utf-8 string key."""
    if isinstance(signing_key, str):
        try:
            key = bytes.fromhex(signing_key)
        except ValueError:
            key = signing_key.encode("utf-8")
    else:
        key = signing_key
    return AttestationSigner(signing_key=key, **kwargs)


def make_verifier(signing_key: str) -> AttestationVerifier:
    if isinstance(signing_key, str):
        try:
            key = bytes.fromhex(signing_key)
        except ValueError:
            key = signing_key.encode("utf-8")
    else:
        key = signing_key
    return AttestationVerifier(signing_key=key)


__all__ = [
    "AttestationSigner",
    "AttestationVerifier",
    "canonical_payload",
    "make_signer",
    "make_verifier",
]
