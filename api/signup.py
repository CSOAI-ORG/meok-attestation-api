"""
MEOK free MCP key signup — lead capture
=======================================
Turns anonymous `pip install`s into contactable leads.

  POST /signup  {email}  -> issues a free API key + creates/updates a Stripe
                           Customer (metadata.meok_tier=free, meok_free_key=...).
                           Every free user becomes a Stripe Customer = a lead in
                           the CRM, ready for nurture + upgrade to Pro / PAYG.
  GET  /signup           -> service info.

Storage decision (matches payg.py): Stripe IS the database. No extra datastore.
Required env: STRIPE_SECRET_KEY (already set on this project for payg.py).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

STRIPE_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
PRO_LINK = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # £79 Compliance Pro
PAYG_LINK = "https://proofof.ai/payg"
FREE_LIMIT = "200/day"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _stripe(method: str, path: str, params: dict | None = None) -> dict:
    url = f"https://api.stripe.com/v1{path}"
    data = urllib.parse.urlencode(params).encode() if params else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {STRIPE_KEY}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def _resp(h: BaseHTTPRequestHandler, code: int, obj: dict) -> None:
    body = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        _resp(self, 204, {})

    def do_GET(self):
        _resp(self, 200, {
            "service": "MEOK free MCP API key",
            "how": "POST {\"email\":\"you@org.com\"} to receive a free key",
            "free_limit": FREE_LIMIT, "upgrade": {"pro": PRO_LINK, "payg": PAYG_LINK},
        })

    def do_POST(self):
        try:
            ln = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            return _resp(self, 400, {"error": "invalid JSON body"})
        email = (body.get("email") or "").strip().lower()
        if not EMAIL_RE.match(email):
            return _resp(self, 400, {"error": "a valid email is required"})
        if not STRIPE_KEY:
            return _resp(self, 500, {"error": "server not configured (STRIPE_SECRET_KEY missing)"})
        try:
            found = _stripe("GET", "/customers/search?query=" + urllib.parse.quote(f"email:'{email}'"))
            custs = found.get("data", [])
            cust_id = custs[0]["id"] if custs else None
            key = (custs[0].get("metadata") or {}).get("meok_free_key") if custs else None
            if not key:
                key = "meok_free_" + secrets.token_urlsafe(24)
            meta = {
                "metadata[meok_tier]": "free",
                "metadata[meok_free_key]": key,
                "metadata[meok_source]": "mcp-signup",
                "metadata[meok_signed_up_at]": datetime.now(timezone.utc).isoformat(),
            }
            if cust_id:
                _stripe("POST", f"/customers/{cust_id}", meta)
            else:
                _stripe("POST", "/customers", {"email": email, **meta})
            return _resp(self, 200, {
                "ok": True, "api_key": key, "tier": "free", "free_limit": FREE_LIMIT,
                "next": f"Set MEOK_API_KEY={key} in your MCP client env for {FREE_LIMIT}.",
                "upgrade": {"pro_79_mo": PRO_LINK, "pay_as_you_go": PAYG_LINK},
            })
        except urllib.error.HTTPError as e:
            return _resp(self, 502, {"error": f"stripe error {e.code}"})
        except Exception as e:
            return _resp(self, 500, {"error": str(e)[:140]})
