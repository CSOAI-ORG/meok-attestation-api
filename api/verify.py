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
PRO_LINK = "https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j"
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
        # free + anon metered
        day=datetime.now(timezone.utc).strftime("%Y%m%d")
        ident = key or "anon"
        rk=f"meok:meter:{ident}:{day}"
        n=_kv("INCR", rk)
        if n is None:                       # KV not configured -> fail open
            return _resp(self,200,{"allowed":True,"tier":tier,"remaining":"unmetered","note":"metering KV not configured"})
        if n==1: _kv("EXPIRE", rk, "90000")
        limit = FREE_DAILY if tier=="free" else max(10, FREE_DAILY//4)  # anon gets less
        allowed = n <= limit
        return _resp(self,200,{"allowed":allowed,"tier":tier,"used":n,"limit":limit,
            "remaining":max(0,limit-n),
            **({} if allowed else {"upgrade_url":PRO_LINK,"payg":PAYG_LINK,
               "message":f"Free limit {limit}/day reached. Pro (unlimited): {PRO_LINK}"})})
