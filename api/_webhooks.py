"""
Signed customer webhooks — Move #30.

Customers register an HTTPS URL + receive a webhook secret. When MEOK signs or
verifies an attestation that belongs to their API key, we POST the event to
their URL with an HMAC-SHA256 signature header.

Endpoints:
  POST /api/webhooks/subscribe        body: {url, events?}        → {webhook_id, secret}
  POST /api/webhooks/unsubscribe      body: {webhook_id, secret}  → {ok}
  GET  /api/webhooks/list?api_key=…   query                       → list

Outbound delivery:
  POST <customer url>
    Content-Type: application/json
    User-Agent: meok-webhook/1.0
    X-Meok-Event: sign | verify
    X-Meok-Signature: sha256=<hex>           (HMAC of body using customer's secret)
    X-Meok-Timestamp: <epoch ms>             (replay protection)
    X-Meok-Webhook-Id: <id>
    Body: { event_id, kind, cert_id, regulation, entity, score, tier, occurred_at }

Storage: same Upstash-Redis-or-in-memory pattern as _audit_ledger.

Customer verification snippet (TS / Python):
  - re-compute HMAC of raw body using shared secret
  - compare with X-Meok-Signature (timing-safe)
  - reject if X-Meok-Timestamp older than 5 min

Note: outbound delivery is fire-and-forget here. A production hardening pass
would queue to Vercel Background Functions / Inngest / QStash + add retries
with exponential backoff + DLQ. Marked as TODO at the bottom.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

_UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "").rstrip("/")
_UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
_MEM_WEBHOOKS: dict[str, dict[str, Any]] = {}  # webhook_id → record


def _upstash(command: list[str]) -> Any:
    if not _UPSTASH_URL or not _UPSTASH_TOKEN:
        return None
    body = json.dumps(command).encode("utf-8")
    req = urllib.request.Request(
        _UPSTASH_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {_UPSTASH_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8")).get("result")
    except Exception:  # noqa: BLE001
        return None


def subscribe(api_key: str, url: str, events: list[str] | None = None) -> dict[str, Any]:
    """Register a webhook for `api_key`. Returns the webhook record."""
    if not url.startswith("https://"):
        raise ValueError("webhook url must use https://")
    if events is None:
        events = ["sign", "verify"]
    webhook_id = "wh_" + uuid.uuid4().hex[:24]
    secret = "whsec_" + secrets.token_urlsafe(32)
    record: dict[str, Any] = {
        "webhook_id": webhook_id,
        "api_key_prefix": api_key[:16] + "…" if api_key else "(anonymous)",
        "url": url,
        "events": events,
        "secret": secret,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "active",
    }
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        # Hash store + index by api_key
        kv: list[str] = []
        for k, v in record.items():
            kv.extend([k, json.dumps(v) if not isinstance(v, str) else v])
        _upstash(["HSET", f"webhook:{webhook_id}", *kv])
        if api_key:
            _upstash(["SADD", f"webhook:by-key:{api_key[:32]}", webhook_id])
    else:
        _MEM_WEBHOOKS[webhook_id] = record
    return record


def unsubscribe(webhook_id: str, secret: str) -> bool:
    """Disable a webhook. Caller must prove ownership via secret."""
    rec: dict[str, Any] | None = None
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        fields = _upstash(["HGETALL", f"webhook:{webhook_id}"])
        if isinstance(fields, list):
            rec = dict(zip(fields[0::2], fields[1::2]))
    else:
        rec = _MEM_WEBHOOKS.get(webhook_id)
    if not rec:
        return False
    if not hmac.compare_digest(rec.get("secret", ""), secret):
        return False
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        _upstash(["HSET", f"webhook:{webhook_id}", "status", "disabled"])
    else:
        rec["status"] = "disabled"
    return True


def list_for(api_key: str) -> list[dict[str, Any]]:
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        ids = _upstash(["SMEMBERS", f"webhook:by-key:{api_key[:32]}"])
        out: list[dict[str, Any]] = []
        if isinstance(ids, list):
            for wid in ids:
                fields = _upstash(["HGETALL", f"webhook:{wid}"])
                if isinstance(fields, list):
                    rec = dict(zip(fields[0::2], fields[1::2]))
                    rec.pop("secret", None)  # Never leak secret on list
                    out.append(rec)
        return out
    # In-memory
    prefix = api_key[:16] + "…" if api_key else ""
    out2: list[dict[str, Any]] = []
    for r in _MEM_WEBHOOKS.values():
        if r.get("api_key_prefix") == prefix or (not api_key and r.get("api_key_prefix") == "(anonymous)"):
            r2 = dict(r)
            r2.pop("secret", None)
            out2.append(r2)
    return out2


def _hmac_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def deliver(event: dict[str, Any]) -> int:
    """Fire-and-forget delivery to every active webhook matching this event.

    Returns the number of webhooks notified. Failures are silent here — a
    production hardening pass would queue to Inngest / QStash with retries.
    """
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time() * 1000))
    delivered = 0

    # Gather candidate webhooks
    candidates: list[dict[str, Any]] = []
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        # In-real-world we'd index by event kind; for simplicity we currently
        # walk every webhook key. Volume-bounded by Upstash quota.
        ids = _upstash(["KEYS", "webhook:wh_*"])
        if isinstance(ids, list):
            for wid_key in ids:
                fields = _upstash(["HGETALL", wid_key])
                if isinstance(fields, list):
                    candidates.append(dict(zip(fields[0::2], fields[1::2])))
    else:
        candidates = list(_MEM_WEBHOOKS.values())

    for rec in candidates:
        if rec.get("status") != "active":
            continue
        events = rec.get("events", [])
        if isinstance(events, str):
            try:
                events = json.loads(events)
            except json.JSONDecodeError:
                events = [events]
        if event.get("kind") not in events:
            continue
        url = rec.get("url", "")
        secret = rec.get("secret", "")
        if not url or not secret:
            continue
        sig = _hmac_hex(secret, body)
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "meok-webhook/1.0",
                "X-Meok-Event": event.get("kind", "unknown"),
                "X-Meok-Signature": f"sha256={sig}",
                "X-Meok-Timestamp": ts,
                "X-Meok-Webhook-Id": rec.get("webhook_id", ""),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3):
                delivered += 1
        except Exception:  # noqa: BLE001
            # Silent fail in MVP — production needs retries + DLQ
            pass
    return delivered


# TODO production hardening:
#   1. Switch outbound delivery to Inngest / Vercel Background Functions / QStash
#   2. Exponential backoff retry (3, 9, 27, 81 seconds)
#   3. DLQ topic for terminally failed deliveries
#   4. Per-webhook circuit breaker after N consecutive failures
#   5. Replay endpoint for customer-side outage recovery
#   6. Dashboard at /api/webhooks/<id>/deliveries showing last 100 attempts
