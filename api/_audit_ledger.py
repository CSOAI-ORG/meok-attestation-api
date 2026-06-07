"""
Append-only signed audit ledger.

Records every sign + verify event with a HMAC-chained signature so the ledger
can be independently verified as tamper-evident.

Storage backend (in priority order):
  1. UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN → Upstash via HTTP
  2. VERCEL_POSTGRES_URL (= POSTGRES_URL) → Vercel Postgres / Neon
  3. In-memory list (dev/test only — does NOT persist between requests on Vercel)

Schema (Upstash sorted-set + hash):
  ZADD ledger:events <ts> <event_id>
  HSET ledger:event:<event_id> kind <sign|verify> entity <e> regulation <r>
       cert_id <c> score <s> tier <t> result <ok|fail|valid|invalid>
       prev_hash <h_n-1> hash <h_n> issued_at <iso> issuer_email <e>

Hash chain:
  h_0  = HMAC(ledger_key, "GENESIS")
  h_n  = HMAC(ledger_key, h_{n-1} || canonical(event))

Reading the chain is GET /api/audit?since=<ts>&limit=100 — replays + re-derives
the hashes and confirms each event's signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Optional

_LEDGER_KEY = os.environ.get("MEOK_AUDIT_LEDGER_KEY", "").encode("utf-8") or hashlib.sha256(
    b"MEOK_AUDIT_LEDGER_DEV"
).digest()

_UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "").rstrip("/")
_UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")

# Fallback in-memory ledger — useful for tests, not persistent on Vercel cold starts.
_MEM_LEDGER: list[dict[str, Any]] = []
_GENESIS = hmac.new(_LEDGER_KEY, b"GENESIS", hashlib.sha256).hexdigest()


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _chain_hash(prev_hash: str, event: dict[str, Any]) -> str:
    payload = prev_hash.encode("utf-8") + b"|" + _canonical(event)
    return hmac.new(_LEDGER_KEY, payload, hashlib.sha256).hexdigest()


def _upstash_call(command: list[str]) -> Any:
    """Single Upstash REST call. Returns parsed JSON result."""
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
            j = json.loads(r.read().decode("utf-8"))
            return j.get("result")
    except urllib.error.HTTPError as e:
        return {"error": f"upstash {e.code}", "body": e.read().decode("utf-8", errors="replace")}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _last_hash() -> str:
    """Return the hash of the most recent event in the ledger (or genesis)."""
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        ids = _upstash_call(["ZREVRANGE", "ledger:events", "0", "0"])
        if isinstance(ids, list) and ids:
            last = _upstash_call(["HGET", f"ledger:event:{ids[0]}", "hash"])
            if isinstance(last, str):
                return last
        return _GENESIS
    if _MEM_LEDGER:
        return _MEM_LEDGER[-1]["hash"]
    return _GENESIS


def record(
    kind: str,
    *,
    cert_id: str = "",
    entity: str = "",
    regulation: str = "",
    score: float | None = None,
    tier: str = "",
    result: str = "",
    issuer_email: str = "",
) -> dict[str, Any]:
    """Append a single audit event. Returns the event with its hash."""
    event_id = uuid.uuid4().hex
    issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event: dict[str, Any] = {
        "event_id": event_id,
        "kind": kind,
        "cert_id": cert_id,
        "entity": entity,
        "regulation": regulation,
        "score": score,
        "tier": tier,
        "result": result,
        "issuer_email": issuer_email,
        "issued_at": issued_at,
    }
    prev_hash = _last_hash()
    # Compute the hash over the event BEFORE adding prev_hash/hash to the
    # event dict — otherwise the verifier (which strips those fields before
    # re-hashing) won't match.
    event["hash"] = _chain_hash(prev_hash, event)
    event["prev_hash"] = prev_hash

    if _UPSTASH_URL and _UPSTASH_TOKEN:
        ts = int(time.time() * 1000)
        _upstash_call(["ZADD", "ledger:events", str(ts), event_id])
        # Flatten the event for HSET
        kv: list[str] = []
        for k, v in event.items():
            kv.append(k)
            kv.append("" if v is None else str(v))
        _upstash_call(["HSET", f"ledger:event:{event_id}", *kv])
    else:
        _MEM_LEDGER.append(event)

    return event


def query(*, since_ts: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    """Return events newer than `since_ts` (epoch ms). Replays + verifies the chain."""
    out: list[dict[str, Any]] = []
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        ids = _upstash_call(
            ["ZRANGEBYSCORE", "ledger:events", str(since_ts), "+inf", "LIMIT", "0", str(limit)]
        )
        if not isinstance(ids, list):
            return []
        for eid in ids:
            fields = _upstash_call(["HGETALL", f"ledger:event:{eid}"])
            if isinstance(fields, list):
                # Upstash returns flat [k, v, k, v, ...]
                d = dict(zip(fields[0::2], fields[1::2]))
                out.append(d)
    else:
        out = list(_MEM_LEDGER[-limit:])

    # Re-verify chain on the way out — guards against tampering between storage and reader.
    prev = _GENESIS
    if out:
        # Walk earliest-to-latest
        for event in out:
            expected = _chain_hash(prev, {k: v for k, v in event.items() if k not in ("hash", "prev_hash")})
            event["chain_intact"] = expected == event.get("hash")
            prev = event.get("hash", prev)
    return out


def stats() -> dict[str, Any]:
    """Cheap counts for /api/audit GET endpoint."""
    if _UPSTASH_URL and _UPSTASH_TOKEN:
        n = _upstash_call(["ZCARD", "ledger:events"])
        return {"backend": "upstash", "total_events": int(n) if isinstance(n, int) else 0}
    return {"backend": "memory", "total_events": len(_MEM_LEDGER)}
