"""
MEOK key verification + server-side metering
============================================
POST /verify {api_key, tool} -> {allowed, tier, remaining, upgrade_url}

Persistent per-key daily metering via Vercel KV (Upstash REST). Free keys
(meok_free_*) capped at 200/day; pro/payg/CSOAI keys unlimited. FAIL-OPEN: if KV
is not configured or unreachable, allow (never break the MCPs). Env:
  KV_REST_API_URL, KV_REST_API_TOKEN   (auto-set when a Vercel KV store is added)
  MEOK_FREE_DAILY  (default 200)
"""
from __future__ import annotations
import json, os, re, urllib.request, urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOK = os.environ.get("KV_REST_API_TOKEN", "")
FREE_DAILY = int(os.environ.get("MEOK_FREE_DAILY", "200"))
# Grace cap for correctly-shaped pro keys NOT yet in the registry (pre-backfill
# legit keys OR forgeries). Generous so real customers never notice, but finite
# so a forged `meok_pro_<random hex>` can't get truly unlimited usage. Once the
# registry is backfilled, every real key is registered → genuinely unlimited.
PRO_GRACE_DAILY = int(os.environ.get("MEOK_PRO_GRACE_DAILY", "500"))
PRO_LINK = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"
PAYG_LINK = "https://proofof.ai/payg"

# A real derived key is meok_<tier>_<24 lowercase hex> (see derive_api_key).
_HEX24 = re.compile(r"^[0-9a-f]{24}$")

def _kv(*cmd):
    """Upstash REST: POST [cmd...] -> result. Returns None on any failure (fail-open)."""
    if not (KV_URL and KV_TOK): return None
    try:
        req = urllib.request.Request(KV_URL, data=json.dumps(list(cmd)).encode(),
            headers={"Authorization": f"Bearer {KV_TOK}", "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=4) as r:
            return json.load(r).get("result")
    except Exception:
        return None

def register_key(key: str, tier: str) -> None:
    """Record an issued key in the KV registry so metering can tell a REAL key
    from a forged prefix. Permanent (no expiry). No-op if KV unset (fail-open).
    Called at every mint site (provision/webhook/signup) + the backfill."""
    key = (key or "").strip()
    if not key:
        return
    _kv("SET", f"meok:validkey:{key}", (tier or "pro").lower())

def _registered_tier(key: str):
    """Registered tier for a key, or None if not in the registry."""
    return _kv("GET", f"meok:validkey:{(key or '').strip()}")

def _pro_shaped(key: str) -> bool:
    """True if the key has the structural shape of a real pro/payg key.
    Catches `meok_pro_test` / `meok_pro_anything` (non-hex suffix) cheaply,
    before any KV lookup. Does NOT prove authenticity — the registry does that."""
    if key.startswith(("meok_pro_", "meok_enterprise_")):
        return bool(_HEX24.match(key.rsplit("_", 1)[-1]))
    if key.startswith("payg_"):
        return len(key) > 8
    return False

def _resp(h, code, obj):
    b=json.dumps(obj).encode()
    h.send_response(code); h.send_header("Content-Type","application/json")
    h.send_header("Access-Control-Allow-Origin","*"); h.send_header("Content-Length",str(len(b)))
    h.end_headers(); h.wfile.write(b)

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self): _resp(self,204,{})
    def do_POST(self):
        try:
            ln=int(self.headers.get("Content-Length","0") or 0)
            body=json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            return _resp(self,400,{"error":"invalid JSON"})
        # Single source of truth — same registry-gated logic index.py embeds.
        return _resp(self, 200, _meter_check(body.get("api_key", ""), body.get("tool", "")))


def _fp(key: str) -> str:
    import hashlib
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()[:12]


def _meter(key: str, tier: str, limit: int, tool: str, ns: str = "meter") -> dict:
    """KV daily counter for `key` under namespace `ns`. Fail-open if KV unset."""
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    rk = f"meok:{ns}:{key}:{day}"
    n = _kv("INCR", rk)
    if n is None:
        return {"allowed": True, "tier": tier, "remaining": "unmetered",
                "note": "metering KV not configured (Vercel KV env vars not set)",
                "upgrade_url": PRO_LINK, "tool": tool}
    if n == 1:
        _kv("EXPIRE", rk, "90000")
    allowed = n <= limit
    out = {"allowed": allowed, "tier": tier, "used": n, "limit": limit,
           "remaining": max(0, limit - n), "tool": tool}
    if not allowed:
        out.update({"upgrade_url": PRO_LINK, "payg": PAYG_LINK,
                    "message": f"Limit {limit}/day reached. Pro (unlimited): {PRO_LINK}"})
    return out


def _meter_check(api_key: str, tool: str = "") -> dict:
    """Server-side metering + KEY-AUTHENTICITY gate (the fix for the
    `meok_pro_<forged>` = unlimited leak). Trust ladder:

      CSOAI-*                        -> internal, unlimited
      registered pro/enterprise/payg -> unlimited (validated vs KV registry)
      pro-shaped but NOT registered  -> GRACE-metered (PRO_GRACE_DAILY/day) + logged
      pro-prefixed but malformed     -> free-metered (catches meok_pro_test)
      meok_free_*                    -> free-metered (FREE_DAILY/day)
      anon (no key)                  -> allowed, unmetered (no identity to meter)

    Fail-open: if KV is unreachable/unconfigured, allow (never break the fleet).
    """
    key = (api_key or "").strip()

    # Internal CSOAI keys — yours, always unlimited.
    if key.startswith("CSOAI-"):
        return {"allowed": True, "tier": "pro", "remaining": "unlimited",
                "validated": "internal", "tool": tool}

    # Pro/payg class — unlimited ONLY when validated against the registry.
    if _pro_shaped(key):
        if not (KV_URL and KV_TOK):
            # KV not configured at all -> legacy fail-open (don't break prod).
            return {"allowed": True, "tier": "pro", "remaining": "unlimited",
                    "validated": "kv-unconfigured", "tool": tool}
        reg = _registered_tier(key)
        if reg in ("pro", "enterprise", "payg"):
            return {"allowed": True, "tier": reg, "remaining": "unlimited",
                    "validated": "registry", "tool": tool}
        # Correctly-shaped but unregistered: a pre-backfill legit key OR a
        # forgery. Grace-meter so real customers never notice but forgeries
        # can't run unlimited. Logged so backfill gaps are visible.
        print(f"[UNREGISTERED_PRO_KEY] fp={_fp(key)} tool={tool} — grace-metered")
        return _meter(key, "pro_grace", PRO_GRACE_DAILY, tool, ns="grace")

    # Free shape, or any pro-prefixed-but-malformed key -> metered free tier.
    if key.startswith(("meok_free_", "meok_pro_", "meok_enterprise_", "payg_")):
        return _meter(key, "free", FREE_DAILY, tool)

    # No recognised key -> anon. No identity to meter; allow + advertise free key.
    return {"allowed": True, "tier": "anon", "remaining": "unmetered",
            "note": "Get a free key (200/day): https://proofof.ai/get-key.html",
            "upgrade_url": PRO_LINK, "tool": tool}
