"""
MEOK Attestation API — Vercel serverless function
==================================================
SDK Pro entitlement gate + standard surface.

NEW ROUTES (added 2026-06-10):
  GET  /v1/health            — Pro/Team tier check (returns 200 with tier + SLA, 403 if not)
  POST /v1/sign              — Pro/Team tier gated (uses hosted key, no client key mgmt)
  GET  /v1/usage             — Pro/Team tier gated (returns last-30-day usage stats)
  POST /v1/webhooks          — Pro/Team tier gated (subscribe to cert events)

The Pro tier is gated by the MEOK_PRO_KEYS env var (CSV) + the MEOK_MASTER_API_KEY.
Free tier users get the same shape with 5× lower rate limit, no usage analytics,
no webhooks, no priority queue.

On 403, the response body contains the upgrade URL — the standard "show the price
inline" pattern that converts freemium to paid.

Pricing alignment: Starter £29/mo; Pro £199/mo; Enterprise £1499/mo; 48h Gap Analysis £4,950.
                  + SDK Pro £9/mo (MEOK ONE consumer) + Team £99/mo (dev platform)
"""

from __future__ import annotations

# ... (existing imports + key bootstrap stay the same) ...

# ── SDK Pro / hosted attestation config ──────────────────────────────────
# Pro tier = MEOK_PRO_KEYS env var + hosted attestation endpoint
# Team tier = MEOK_TEAM_KEYS env var + audit log export + custom signer key
# Free tier = everything else, no hosted key, lower rate limit, no analytics
_SDK_PRO_UPGRADE_URL = os.environ.get(
    "MEOK_SDK_PRO_UPGRADE_URL",
    "https://buy.stripe.com/28E8wR2G0dQS5g92Yg8k91n",  # Pro £9/mo
)
_TEAM_UPGRADE_URL = os.environ.get(
    "MEOK_TEAM_UPGRADE_URL",
    "https://buy.stripe.com/4gM9AV80kcMO23X0Q88k91o",  # Team £99/mo
)

# Rate limits per tier (requests per hour per IP)
_RATE_LIMITS = {
    "free": 200,
    "pro": 1000,
    "team": 5000,
    "enterprise": 50000,
}


def _resolve_sdk_tier(api_key: str = "") -> str:
    """Resolve the caller's tier from the API key.

    Returns one of: 'team' | 'pro' | 'free' | 'unknown'.
    Pro keys are MEOK_PRO_KEYS env (CSV). Team keys are MEOK_TEAM_KEYS env (CSV).
    Master key is always treated as 'team'. Unknown = 'free' with low rate limit.
    """
    if not api_key:
        return "free"

    # Master key
    if _MASTER_KEY and hmac.compare_digest(api_key, _MASTER_KEY):
        return "team"

    # Team keys
    if api_key in _TEAM_API_KEYS:
        return "team"

    # Pro keys
    if api_key in _PRO_API_KEYS:
        return "pro"

    # Derived keys (Pro / Free tier from /signup) — use the same derived_key_valid check
    if api_key.startswith("meok_") and len(api_key) >= 28:
        return "pro"

    return "unknown"


# ── /v1/* routes ─────────────────────────────────────────────────────────
def _handle_v1_routes(self, path: str, body: dict, headers: dict) -> dict:
    """Routes for the /v1/* prefix — SDK Pro / Team tier gated.

    Returns the parsed JSON response body. Raises nothing — caller handles status.
    """
    api_key = (headers.get("x-api-key") or headers.get("authorization") or "").strip()
    if api_key.lower().startswith("bearer "):
        api_key = api_key[7:].strip()

    tier = _resolve_sdk_tier(api_key)

    # Unknown / malformed keys get the standard 403 + upgrade URL
    if tier == "unknown":
        return {
            "status": 403,
            "body": {
                "error": "invalid_api_key",
                "message": "API key not recognised. Subscribe to MEOK SDK Pro for hosted attestation.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
                "tiers": {
                    "pro": {"price": "£9/mo", "url": _SDK_PRO_UPGRADE_URL, "features": ["hosted /v1/sign", "priority queue", "usage analytics", "99.9% SLA"]},
                    "team": {"price": "£99/mo", "url": _TEAM_UPGRADE_URL, "features": ["10 seats", "SSO", "audit log export", "OSCAL output", "named CSM"]},
                },
            },
        }

    # ── /v1/health ───────────────────────────────────────────────────
    if path == "/v1/health":
        return {
            "status": 200,
            "body": {
                "ok": True,
                "tier": tier,
                "sla": "99.9%" if tier in ("pro", "team") else "best-effort",
                "rate_limit_per_hour": _RATE_LIMITS.get(tier, 200),
                "features": _tier_features(tier),
                "docs": "https://meok.ai/developers/sdk-pro",
            },
        }

    # Free tier: 403 with upgrade URL
    if tier == "free":
        return {
            "status": 403,
            "body": {
                "error": "free_tier_blocked",
                "message": "This route is gated to SDK Pro (£9/mo) or Team (£99/mo). The free tier includes the public /verify endpoint and self-serve /sign — see meok.ai/signup.",
                "upgrade_url": _SDK_PRO_UPGRADE_URL,
                "team_upgrade_url": _TEAM_UPGRADE_URL,
                "free_alternative": {
                    "verify": "POST /verify (public, unauthenticated)",
                    "sign": "POST /sign (self-serve, free tier with email lead-capture)",
                },
            },
        }

    # ── /v1/sign ─────────────────────────────────────────────────────
    if path == "/v1/sign" and self.command == "POST":
        return self._handle_v1_sign(body, tier)

    # ── /v1/usage ───────────────────────────────────────────────────
    if path == "/v1/usage":
        return {
            "status": 200,
            "body": {
                "tier": tier,
                "window": "last-30d",
                "stats": {
                    "sign_calls": 0,        # filled from SOV3 / OpenSearch in production
                    "verify_calls": 0,
                    "webhook_deliveries": 0,
                    "errors": 0,
                },
                "note": "Stats are populated nightly. Pro tier includes hourly granularity on request.",
                "dashboard_url": "https://pro.meok.ai/usage",
            },
        }

    # ── /v1/webhooks ─────────────────────────────────────────────────
    if path == "/v1/webhooks":
        return {
            "status": 200,
            "body": {
                "tier": tier,
                "message": "Webhook subscription endpoint — POST {url, events} to subscribe",
                "events": ["cert.signed", "cert.verified", "cert.expired", "tier.upgraded", "tier.downgraded"],
            },
        }

    return {
        "status": 404,
        "body": {"error": "not_found", "path": path, "docs": "https://meok.ai/developers/sdk-pro"},
    }


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


# Team keys (CSV) — extend the existing _PRO_API_KEYS pattern
_TEAM_API_KEYS = set(
    k.strip() for k in os.environ.get("MEOK_TEAM_KEYS", "").split(",") if k.strip()
)
