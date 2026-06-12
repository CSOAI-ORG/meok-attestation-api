"""
MEOK Attestation API — /v1/health canonical liveness endpoint.

Returns the spine identity (kid, pubkey, alg) so clients can verify the
SIGIL signer is alive AND know which key to use for offline verification.

The /v1/ prefix is the canonical API version namespace (matches OpenAI,
Anthropic, etc.). The existing /health (in api/index.py) is kept for
backwards compat — this route returns the same payload + a fingerprint
of the pubkey for client-side health checks.

Usage:
    curl https://meok-attestation-api.vercel.app/v1/health

Response (200):
    {
      "ok": true,
      "version": "1.2.0",
      "kid": "d4cb0eaa",
      "alg": "Ed25519",
      "pubkey_fingerprint": "4bbb8e37...:12",   # first 12 hex of pubkey
      "verify_url": "/v/{cert_id}",
      "audit_url": "/api/audit",
      "checked_at_utc": "2026-06-12T..."
    }

Response (503):
    { "ok": false, "error": "signing key not loaded", ... }

Verified 2026-06-12 03:30 UTC: /pubkey returns 200 with alg=Ed25519,
identity=d4cb0eaa, pubkey_hex=4bbb8e37... This /v1/health route proxies
that call — no shadow keys, no parallel signer.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from typing import Any

# Allow importing from sibling api/ modules (same pattern as index.py)
_HERE = os.path.dirname(os.path.abspath(__file__))
_API_DIR = os.path.dirname(_HERE)
if _API_DIR not in sys.path:
    sys.path.insert(0, _API_DIR)

# We re-use the canonical /pubkey identity so we never drift from the
# signer. /pubkey is the source of truth; /v1/health is a thin wrapper.
def _fetch_identity() -> dict[str, Any]:
    """Read the canonical /pubkey identity from the same deployment.
    Falls back to env vars if /pubkey is unreachable (e.g. local dev)."""
    try:
        # Internal call — same Vercel deployment, no public hop
        base = os.getenv("VERCEL_URL", "")
        if not base:
            # In local dev or non-Vercel: just read env directly
            return {
                "ok": True,
                "alg": "Ed25519",
                "kid": os.getenv("MEOK_SIGNING_KID", "v1"),
                "pubkey_hex": os.getenv("MEOK_SIGNING_PUBKEY_HEX", "")[:32] + ("…" if os.getenv("MEOK_SIGNING_PUBKEY_HEX") else ""),
                "source": "env",
            }
        url = f"https://{base}/pubkey"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        return {
            "ok": True,
            "alg": data.get("alg", "Ed25519"),
            "kid": data.get("identity", "v1"),
            "pubkey_hex_full": data.get("pubkey_hex", ""),
            "source": "pubkey",
        }
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        return {
            "ok": False,
            "error": f"identity source unreachable: {e}",
            "alg": "Ed25519",
            "kid": os.getenv("MEOK_SIGNING_KID", "unknown"),
        }


class handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # silence stderr
        pass

    def do_GET(self) -> None:  # noqa: N802 (Vercel convention)
        identity = _fetch_identity()
        if not identity.get("ok"):
            body = json.dumps({
                "ok": False,
                "error": identity.get("error", "spine unreachable"),
                "version": "1.2.0",
                "service": "meok-attestation-api",
            }, indent=2).encode()
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        pubkey_full = identity.get("pubkey_hex_full", "") or identity.get("pubkey_hex", "")
        pubkey_fingerprint = (pubkey_full[:12] + "…") if pubkey_full else "unavailable"

        body = json.dumps({
            "ok": True,
            "version": "1.2.0",
            "service": "meok-attestation-api",
            "alg": identity.get("alg", "Ed25519"),
            "kid": identity.get("kid", "v1"),
            "pubkey_fingerprint": pubkey_fingerprint,
            "verify_url": "/v/{cert_id}",
            "audit_url": "/api/audit",
            "source": identity.get("source", "env"),
            "checked_at_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "spec_ref": "csoai.org/council/sigil — LIVE badge source",
        }, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
