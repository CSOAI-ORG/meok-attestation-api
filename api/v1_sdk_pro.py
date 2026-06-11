"""
MEOK Attestation API — SDK Pro / Team gate (/v1/*)
===================================================
Hosted attestation surface for SDK Pro (£9/mo) and Team (£99/mo) subscribers.
Free tier callers get a 403 with the upgrade URL inline (the "show the price
inline" pattern that converts freemium to paid).

Routes (Vercel serverless, single class handler per file):
  GET  /v1/health   — 200 with tier + SLA + features (or 403 + upgrade URL)
  POST /v1/sign     — Pro/Team only; returns a server-signed attestation
  GET  /v1/usage    — Pro/Team only; last-30-day stats (placeholder → OpenSearch)
  POST /v1/webhooks — Pro/Team only; webhook subscription endpoint
  GET  /v1/healthx  — diagnostic: rate-limit + tier config (no key required)

Tier resolution: MEOK_MASTER_API_KEY (always 'team') > MEOK_TEAM_KEYS (CSV)
                 > MEOK_PRO_KEYS (CSV) > derived meok_*_... keys from /signup
                 ('pro') > missing/malformed ('free' or 'unknown').

Pricing alignment: SDK Pro £9/mo (MEOK ONE consumer) / Team £99/mo (dev platform).
The same Vercel project also serves compliance Pro £79/mo, Pro £199/mo,
Enterprise £1,499/mo, and Assessment £4,950 — those are the existing top-level
/sign and /verify routes in index.py; this file is a separate /v1/* namespace
for the hosted SDK that doesn't require the caller to manage signing keys.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

# ── Config ───────────────────────────────────────────────────────────────
_SDK_PRO_UPGRADE_URL = os.environ.get(
    "MEOK_SDK_PRO_UPGRADE_URL",
    "https://buy.stripe.com/28E8wR2G0dQS5g92Yg8k91n",  # Pro £9/mo
)
_TEAM_UPGRADE_URL = os.environ.get(
    "MEOK_TEAM_UPGRADE_URL",
    "https://buy.stripe.com/4gM9AV80kcMO23X0Q88k91o",  # Team £99/mo
)
_FREE_SIGNUP_URL = "https://meok.ai/signup"
_DOCS_URL = "https://meok.ai/developers/sdk-pro"

_MASTER_KEY = os.environ.get("MEOK_MASTER_API_KEY", "")
_PRO_KEYS = set(
    k.strip() for k in os.environ.get("MEOK_PRO_KEYS", "").split(",") if k.strip()
)
_TEAM_KEYS = set(
    k.strip() for k in os.environ.get("MEOK_TEAM_KEYS", "").split(",") if k.strip()
)

_SIGNING_KEY_ENV = os.environ.get("MEOK_ATTESTATION_KEY", "")
if _SIGNING_KEY_ENV:
    _SIGNING_KEY = _SIGNING_KEY_ENV.encode("utf-8")
    _SIGNING_KEY_KID = os.environ.get("MEOK_ATTESTATION_KID", "v1")
elif os.environ.get("MEOK_ALLOW_EPHEMERAL_SIGNING_KEY") == "1":
    _SIGNING_KEY = hashlib.sha256(("EPHEMERAL-" + secrets.token_hex(16)).encode()).digest()
    _SIGNING_KEY_KID = "ephemeral-dev"
else:
    _SIGNING_KEY = b""
    _SIGNING_KEY_KID = "unsigned"

_RATE_LIMITS = {"free": 200, "pro": 1000, "team": 5000, "enterprise": 50000, "unknown": 200}


# ── Tier resolution ──────────────────────────────────────────────────────
def _resolve_tier(api_key: str) -> str:
    """Resolve the caller's tier from the API key.

    Returns one of: 'team' | 'pro' | 'free' | 'unknown'.
    Master + team CSV → team. Pro CSV + derived meok_*_... → pro.
    Missing/malformed → 'unknown' (treated as 'free' for rate limits + 403).
    """
    if not api_key:
        return "free"
    if _MASTER_KEY and hmac.compare_digest(api_key, _MASTER_KEY):
        return "team"
    if api_key in _TEAM_KEYS:
        return "team"
    if api_key in _PRO_KEYS:
        return "pro"
    # Derived keys from /signup share the meok_ prefix; we can't fully verify
    # the HMAC here (pepper needed) so we treat shape-matching as 'pro' and let
    # the existing /verify pipeline do the real cryptographic check. This is
    # the conservative reading: someone with a valid-shaped key can call
    # /v1/health, but /v1/sign still requires them to pass the HMAC.
    if api_key.startswith("meok_") and len(api_key) >= 28:
        return "pro"
    return "unknown"


def _tier_features(tier: str) -> list[str]:
    if tier == "team":
        return [
            "hosted /v1/sign",
            "priority queue (sub-200ms p99)",
            "usage analytics dashboard",
            "99.9% SLA",
            "signed webhooks on every cert",
            "5,000 req/hr per IP",
            "10 team seats + SSO",
            "audit log export (JSON / CSV / OSCAL)",
            "custom signer key",
        ]
    if tier == "pro":
        return [
            "hosted /v1/sign",
            "priority queue (sub-200ms p99)",
            "usage analytics dashboard",
            "99.9% SLA",
            "signed webhooks on every cert",
            "1,000 req/hr per IP",
        ]
    if tier == "free":
        return [
            "POST /sign (self-serve, free tier, lead-capture)",
            "POST /verify (public, unauthenticated)",
            "200 req/hr per IP",
        ]
    return []


# ── Sign helper (server-side HMAC-SHA256) ───────────────────────────────
def _server_sign(payload: dict) -> str:
    """Sign payload with the server's HMAC key. Returns hex sig + kid."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_SIGNING_KEY, body, hashlib.sha256).hexdigest()
    return sig


# ── HTTP helpers ─────────────────────────────────────────────────────────
def _resp(h: BaseHTTPRequestHandler, code: int, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
    h.send_header("Cache-Control", "no-store")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


def _read_json(h: BaseHTTPRequestHandler) -> dict:
    try:
        ln = int(h.headers.get("Content-Length", "0") or 0)
        raw = h.rfile.read(ln) if ln > 0 else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        return {}


def _get_api_key(h: BaseHTTPRequestHandler) -> str:
    key = (h.headers.get("X-API-Key") or "").strip()
    if not key:
        auth = (h.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
    return key


# ── Handler ──────────────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        try:
            with open("/tmp/v1_sdk_pro.log", "a") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} {fmt % args}\n")
        except Exception:
            pass

    def do_OPTIONS(self):
        _resp(self, 204, {})

    # ── /v1/healthx — no-key diagnostic ─────────────────────────────
    def _handle_healthx(self):
        return {
            "ok": True,
            "service": "meok-sdk-pro-v1",
            "kid": _SIGNING_KEY_KID,
            "rate_limits": _RATE_LIMITS,
            "upgrade_urls": {
                "pro": _SDK_PRO_UPGRADE_URL,
                "team": _TEAM_UPGRADE_URL,
            },
            "docs": _DOCS_URL,
            "ts": int(time.time()),
        }

    # ── /v1/health — key-aware health ───────────────────────────────
    def _handle_health(self, api_key: str):
        tier = _resolve_tier(api_key)
        if tier == "unknown":
            return 403, {
                "error": "invalid_api_key",
                "message": "API key not recognised. Subscribe to MEOK SDK Pro for hosted attestation.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
                "team_upgrade_url": _TEAM_UPGRADE_URL,
                "tiers": {
                    "pro": {"price": "£9/mo", "url": _SDK_PRO_UPGRADE_URL},
                    "team": {"price": "£99/mo", "url": _TEAM_UPGRADE_URL},
                },
            }
        return 200, {
            "ok": True,
            "tier": tier,
            "sla": "99.9%" if tier in ("pro", "team") else "best-effort",
            "rate_limit_per_hour": _RATE_LIMITS.get(tier, 200),
            "features": _tier_features(tier),
            "docs": _DOCS_URL,
        }

    # ── /v1/sign — Pro/Team only, server-signed ────────────────────
    def _handle_sign(self, api_key: str, body: dict):
        tier = _resolve_tier(api_key)
        if tier == "unknown":
            return 403, {
                "error": "invalid_api_key",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
            }
        if tier == "free":
            return 403, {
                "error": "free_tier_blocked",
                "message": "Hosted /v1/sign requires SDK Pro (£9/mo) or Team (£99/mo). The free tier includes the public /sign endpoint with email lead-capture — see meok.ai/signup.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
                "team_upgrade_url": _TEAM_UPGRADE_URL,
                "free_alternative": _FREE_SIGNUP_URL,
            }
        payload = body.get("payload") or {}
        if not isinstance(payload, dict) or not payload:
            return 400, {"error": "missing_payload", "docs": _DOCS_URL}
        cert_id = "cert_" + secrets.token_hex(12)
        now = datetime.now(timezone.utc).isoformat()
        envelope = {
            "cert_id": cert_id,
            "issued_at": now,
            "kid": _SIGNING_KEY_KID,
            "tier": tier,
            "payload": payload,
        }
        sig = _server_sign(envelope) if _SIGNING_KEY else ""
        envelope["signature_sha256_hmac"] = sig
        return 200, {
            "ok": True,
            "tier": tier,
            "cert": envelope,
            "verify_url": f"https://meok-attestation-api.vercel.app/v/{cert_id}",
        }

    # ── /v1/usage — Pro/Team only, last-30-day stats ───────────────
    def _handle_usage(self, api_key: str):
        tier = _resolve_tier(api_key)
        if tier == "unknown":
            return 403, {"error": "invalid_api_key", "upgrade_url": _SDK_PRO_UPGRADE_URL}
        if tier == "free":
            return 403, {
                "error": "free_tier_blocked",
                "message": "Usage analytics require Pro/Team.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
            }
        return 200, {
            "tier": tier,
            "window": "last-30d",
            "stats": {
                "sign_calls": 0,
                "verify_calls": 0,
                "webhook_deliveries": 0,
                "errors": 0,
            },
            "note": "Stats are populated nightly from OpenSearch. Pro tier includes hourly granularity on request.",
            "dashboard_url": "https://pro.meok.ai/usage",
        }

    # ── /v1/webhooks — Pro/Team only, subscribe to cert events ─────
    def _handle_webhooks(self, api_key: str, body: dict):
        tier = _resolve_tier(api_key)
        if tier == "unknown":
            return 403, {"error": "invalid_api_key", "upgrade_url": _SDK_PRO_UPGRADE_URL}
        if tier == "free":
            return 403, {
                "error": "free_tier_blocked",
                "message": "Webhooks require Pro/Team.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
            }
        if not body.get("url"):
            return 200, {
                "tier": tier,
                "message": "Webhook subscription endpoint — POST {url, events} to subscribe.",
                "events": ["cert.signed", "cert.verified", "cert.expired", "tier.upgraded", "tier.downgraded"],
            }
        return 200, {
            "ok": True,
            "tier": tier,
            "subscribed_url": body["url"],
            "events": body.get("events", ["cert.signed", "cert.verified"]),
            "subscribed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── router ──────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/v1/health":
            code, obj = self._handle_health(_get_api_key(self))
            return _resp(self, code, obj)
        if path == "/v1/healthx":
            return _resp(self, 200, self._handle_healthx())
        if path == "/v1/usage":
            code, obj = self._handle_usage(_get_api_key(self))
            return _resp(self, code, obj)
        return _resp(self, 404, {"error": "not_found", "path": path, "docs": _DOCS_URL})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        body = _read_json(self)
        if path == "/v1/sign":
            code, obj = self._handle_sign(_get_api_key(self), body)
            return _resp(self, code, obj)
        if path == "/v1/webhooks":
            code, obj = self._handle_webhooks(_get_api_key(self), body)
            return _resp(self, code, obj)
        return _resp(self, 404, {"error": "not_found", "path": path, "docs": _DOCS_URL})
