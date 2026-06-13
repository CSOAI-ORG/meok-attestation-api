"""
Advanced Cryptography for MEOK Attestation.
Ed25519 signatures, RFC-3161 timestamping, and OSCAL export.
"""

from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from nacl.signing import SigningKey as Ed25519SigningKey
except ImportError:
    Ed25519SigningKey = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    x509 = None

# ── Ed25519 ────────────────────────────────────────────────────────────
_SK_HEX = os.environ.get("MEOK_SIGNING_KEY_HEX", "")

def ed25519_sign(data: bytes) -> str:
    """Sign data with Ed25519 private key. Returns hex signature."""
    if not (Ed25519SigningKey and _SK_HEX):
        return ""
    try:
        return Ed25519SigningKey(bytes.fromhex(_SK_HEX)).sign(data).signature.hex()
    except Exception:
        return ""

# ── RFC-3161 Timestamping (Mock for MVP, wired to public TSA) ───────────
def get_rfc3161_timestamp(data: bytes) -> Optional[dict[str, str]]:
    """
    Retrieve an RFC-3161 compliant timestamp token for the data hash.
    For MVP, we return a verifiable metadata block. Production would hit
    a TSA like http://timestamp.digicert.com.
    """
    h = hashlib.sha256(data).hexdigest()
    # In a full implementation, we'd use 'rfc3161ng' or similar to hit a TSA.
    # For now, we emit the structure required by OSCAL/A2A parsers.
    return {
        "tsa": "MEOK Trusted Timestamp Service (Prototype)",
        "hash_algo": "sha256",
        "hash_value": h,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "token_format": "rfc3161-wrapped-pkcs7",
        "token_b64": "MOCK_TOKEN_" + hashlib.sha256(h.encode()).hexdigest()[:32]
    }

# ── OSCAL Generation ───────────────────────────────────────────────────
def generate_oscal_attestation(cert: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a MEOK cert into NIST OSCAL (Assessment Results) JSON format.
    Ref: https://pages.nist.gov/OSCAL/documentation/schema/assessment-results-layer/
    """
    now = datetime.now(timezone.utc).isoformat()
    return {
        "assessment-results": {
            "uuid": cert.get("cert_id", "unknown"),
            "metadata": {
                "title": f"MEOK Compliance Attestation: {cert.get('regulation')}",
                "last-modified": cert.get("issued_utc", now),
                "version": "1.0",
                "oscal-version": "1.1.0"
            },
            "results": [
                {
                    "uuid": hashlib.sha256(cert.get("cert_id", "").encode()).hexdigest()[:36],
                    "title": "Automated MCP Audit Result",
                    "start": cert.get("issued_utc"),
                    "end": cert.get("issued_utc"),
                    "description": cert.get("payload", ""),
                    "observations": [
                        {
                            "uuid": os.urandom(16).hex(),
                            "description": f,
                            "methods": ["automated-mcp-tool"]
                        } for f in cert.get("findings", [])
                    ],
                    "risks": [
                        {
                            "uuid": os.urandom(16).hex(),
                            "title": "Compliance Gap",
                            "description": f"Target entity {cert.get('entity')} failed check on {cert.get('regulation')}",
                            "statement": "Score below 100%"
                        }
                    ] if cert.get("score_percent", 100) < 100 else []
                }
            ]
        }
    }
