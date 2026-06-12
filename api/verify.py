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
import json, os, urllib.request, urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOK = os.environ.get("KV_REST_API_TOKEN", "")
FREE_DAILY = int(os.environ.get("MEOK_FREE_DAILY", "200"))
PRO_LINK = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"
PAYG_LINK = "https://proofof.ai/payg"

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
        key=(body.get("api_key") or "").strip()
        tier = "pro" if (key.startswith(("CSOAI-","meok_pro_","payg_")) ) else ("free" if key.startswith("meok_free_") else "anon")
        if tier in ("pro",):
            return _resp(self,200,{"allowed":True,"tier":"pro","remaining":"unlimited"})
        if tier == "anon":
            return _resp(self,200,{"allowed":True,"tier":"anon","remaining":"unmetered","note":"Get a free key (200/day): https://proofof.ai/get-key.html"})
        # free tier: metered per-key (no global counter)
        day=datetime.now(timezone.utc).strftime("%Y%m%d")
        ident = key
        rk=f"meok:meter:{ident}:{day}"
        n=_kv("INCR", rk)
        if n is None:                       # KV not configured -> fail open
            return _resp(self,200,{"allowed":True,"tier":tier,"remaining":"unmetered","note":"metering KV not configured"})
        if n==1: _kv("EXPIRE", rk, "90000")
        limit = FREE_DAILY
        allowed = n <= limit
        return _resp(self,200,{"allowed":allowed,"tier":tier,"used":n,"limit":limit,
            "remaining":max(0,limit-n),
            **({} if allowed else {"upgrade_url":PRO_LINK,"payg":PAYG_LINK,
               "message":f"Free limit {limit}/day reached. Pro (unlimited): {PRO_LINK}"})})


def _meter_check(api_key: str, tool: str = "") -> dict:
    """Pure-function form of the handler — returns the JSON dict for index.py to embed.
    Identical semantics: pro/payg/CSOAI = unlimited, anon = unmetered, free = KV-counted."""
    key = (api_key or "").strip()
    tier = "pro" if key.startswith(("CSOAI-", "meok_pro_", "payg_")) else (
        "free" if key.startswith("meok_free_") else "anon")
    if tier == "pro":
        return {"allowed": True, "tier": "pro", "remaining": "unlimited", "tool": tool}
    if tier == "anon":
        return {"allowed": True, "tier": "anon", "remaining": "unmetered",
                "note": "Get a free key (200/day): https://proofof.ai/get-key.html",
                "upgrade_url": PRO_LINK, "tool": tool}
    # free tier: KV-counted
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    rk = f"meok:meter:{key}:{day}"
    n = _kv("INCR", rk)
    if n is None:
        return {"allowed": True, "tier": tier, "remaining": "unmetered",
                "note": "metering KV not configured (Vercel KV env vars not set)",
                "upgrade_url": PRO_LINK, "tool": tool}
    if n == 1:
        _kv("EXPIRE", rk, "90000")
    limit = FREE_DAILY
    allowed = n <= limit
    out = {"allowed": allowed, "tier": tier, "used": n, "limit": limit,
           "remaining": max(0, limit - n), "tool": tool}
    if not allowed:
        out.update({"upgrade_url": PRO_LINK, "payg": PAYG_LINK,
                    "message": f"Free limit {limit}/day reached. Pro (unlimited): {PRO_LINK}"})
    return out
