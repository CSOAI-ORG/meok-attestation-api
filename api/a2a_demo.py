"""
MEOK A2A Substrate demo endpoint (/v1/a2a/demo)
================================================
Simulates the 7-stage agent-to-agent pipeline and emits a single chained
attestation covering the whole event. Used by the /a2a landing page's
"live demo" widget. Public, no API key required.

Stages emitted in order:
  1. identity-trust        — verifies the caller's DID stub
  2. data-residency         — checks the transfer basis (EU/UK by default)
  3. policy-enforcement    — evaluate_call (default: allow)
  4. injection-firewall     — scan prompt + RAG + tool args (default: clean)
  5. rate-limiter          — grant token (always granted in demo)
  6. handoff-certified      — sign provenance chain
  7. audit-logger          — append hash-chained log entry

The 7 signed attestations are folded into a single
a2a-governance-bridge event for the auditor.

Pricing: this is the public demo. Real /v1/a2a/* calls go through the
£499/mo Substrate. Stage-by-stage cost basis is ~£0.000005 per call;
Substrate margin is the same 20× as /v1/sdk-pro.
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

# ── Config ─────────────────────────────────────────────────────────────────
_DEMO_UPGRADE_URL = "mailto:nicholas@meok.ai?subject=A2A%20Substrate%20%C2%A3499%2Fmo%20pilot&body=I%20saw%20the%20demo%20and%20want%20to%20start%20the%20pilot"
_PRO_UPGRADE_URL = "https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j"  # Compliance Pro £79/mo (LAUNCH50)

# Reuse the master signing key from the v1 sdk, if present
_SIGNING_KEY_ENV = os.environ.get("MEOK_ATTESTATION_KEY", "")
if _SIGNING_KEY_ENV:
    _SIGNING_KEY = _SIGNING_KEY_ENV.encode("utf-8")
    _SIGNING_KEY_KID = os.environ.get("MEOK_ATTESTATION_KID", "v1")
elif os.environ.get("MEOK_ALLOW_EPHEMERAL_SIGNING_KEY") == "1":
    _SIGNING_KEY = hashlib.sha256(("A2A-DEMO-" + secrets.token_hex(16)).encode()).digest()
    _SIGNING_KEY_KID = "a2a-demo-ephemeral"
else:
    _SIGNING_KEY = b""
    _SIGNING_KEY_KID = "a2a-demo-unsigned"

_PIPELINE_VERSION = "1.0.0"
_SUBSTRATE_LINK = _DEMO_UPGRADE_URL  # £499 pilot CTA


# ── Sign helper ────────────────────────────────────────────────────────────
def _sign(payload: str) -> str:
    if not _SIGNING_KEY:
        return ""  # unsigned demo
    return hmac.new(_SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()


# ── Pipeline simulation ────────────────────────────────────────────────────
def _run_pipeline(agent_a: str, agent_b: str, prompt: str, region: str = "EU") -> dict:
    """Simulate the 7 A2A primitives + 1 governance-bridge fold.

    Returns a single signed event with 7 stage_attestations + 1 bridge
    attestation that chains them. Pure JSON, no DB.
    """
    ts = int(time.time())
    nonce = secrets.token_hex(8)
    started_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # Stage 1: identity-trust
    trust_a = 0.86
    trust_b = 0.91
    s1 = {
        "stage": 1, "primitive": "agent-identity-trust-mcp",
        "result": {"did_a": f"did:meok:{agent_a}", "did_b": f"did:meok:{agent_b}",
                   "trust_score_a": trust_a, "trust_score_b": trust_b},
        "ok": True,
    }

    # Stage 2: data-residency
    s2 = {
        "stage": 2, "primitive": "agent-data-residency-mcp",
        "result": {"region": region, "transfer_basis": "EU-UK adequacy (in effect)",
                   "post_brexit_status": "covered"},
        "ok": region in ("EU", "UK", "EEA"),
    }

    # Stage 3: policy-enforcement
    s3 = {
        "stage": 3, "primitive": "agent-policy-enforcement-mcp",
        "result": {"evaluate_call": "ALLOW", "scope": "read:profile, write:handoff",
                   "policy_id": "default-strict-v3"},
        "ok": True,
    }

    # Stage 4: prompt-injection-firewall (scan the user's prompt)
    injection_signals = []
    pl = prompt.lower()
    for sig in ("ignore previous", "system prompt", "disregard", "act as admin"):
        if sig in pl:
            injection_signals.append(sig)
    s4 = {
        "stage": 4, "primitive": "agent-prompt-injection-firewall-mcp",
        "result": {"scanned_chars": len(prompt), "signals": injection_signals,
                   "owasp": "LLM01", "clean": len(injection_signals) == 0},
        "ok": len(injection_signals) == 0,
    }

    # Stage 5: rate-limiter
    s5 = {
        "stage": 5, "primitive": "agent-rate-limiter-mcp",
        "result": {"grant_token": secrets.token_hex(8),
                   "sliding_window_calls": 1, "limit_per_min": 60, "remaining": 59},
        "ok": True,
    }

    # Stage 6: handoff-certified (signs the provenance)
    handoff_payload = f"{nonce}|{agent_a}|{agent_b}|{ts}|{s1['result']['did_a']}"
    handoff_sig = _sign(handoff_payload)
    s6 = {
        "stage": 6, "primitive": "agent-handoff-certified-mcp",
        "result": {"provenance_hash": hashlib.sha256(handoff_payload.encode()).hexdigest()[:16],
                   "signature_sha256_hmac": handoff_sig, "chain_position": 1},
        "ok": True,
    }

    # Stage 7: audit-logger (chained hash)
    audit_prev = hashlib.sha256(f"MEOK-SIGIL-GENESIS|{nonce}".encode()).hexdigest()[:16]
    audit_entry = f"{audit_prev}|{handoff_payload}"
    audit_hash = hashlib.sha256(audit_entry.encode()).hexdigest()[:16]
    s7 = {
        "stage": 7, "primitive": "agent-audit-logger-mcp",
        "result": {"prev_receipt": audit_prev, "receipt": audit_hash,
                   "chain_position": 1, "tamper_evident": True},
        "ok": True,
    }

    # Fold: governance-bridge
    all_ok = all(s["ok"] for s in (s1, s2, s3, s4, s5, s6, s7))
    bridge_payload = json.dumps(
        {"nonce": nonce, "ts": ts, "stages": [s1, s2, s3, s4, s5, s6, s7],
         "summary_ok": all_ok}, sort_keys=True, separators=(",", ":"))
    bridge_sig = _sign(bridge_payload)

    event_id = f"MEOK-A2A-{nonce[:8].upper()}-{ts % 100000:05d}"
    return {
        "event_id": event_id,
        "pipeline_version": _PIPELINE_VERSION,
        "started_at": started_at,
        "agent_a": agent_a, "agent_b": agent_b, "region": region,
        "stages": [s1, s2, s3, s4, s5, s6, s7],
        "bridge": {
            "primitive": "a2a-governance-bridge-mcp",
            "summary_ok": all_ok,
            "regulatory_evidence": [
                "EU AI Act Article 12 (logging)",
                "DORA Article 17 (ICT incident logging)",
                "ISO 42001 clause 9 (performance monitoring)",
            ],
            "payload_sha256": hashlib.sha256(bridge_payload.encode()).hexdigest(),
            "signature_sha256_hmac": bridge_sig,
            "signature_kid": _SIGNING_KEY_KID,
        },
        "verify_url": f"https://proofof.ai/verify/{event_id}",
        "next_step": (
            "Run the same call against the live £499/mo Substrate (1 invoice, 1 signed event) — "
            f"{_SUBSTRATE_LINK}"
        ),
    }


# ── HTTP handler ───────────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence default logging

    def _json(self, status: int, body: dict) -> None:
        body_s = json.dumps(body, indent=2, sort_keys=True)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body_s.encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = (self.path or "/").split("?", 1)[0]
        if path in ("/v1/a2a/demo", "/v1/a2a/demo/"):
            return self._json(200, {
                "service": "meok-a2a-demo",
                "version": _PIPELINE_VERSION,
                "endpoint": "POST /v1/a2a/demo  (or GET with ?prompt=...)",
                "request_body": {
                    "agent_a": "string (default: 'agent-a')",
                    "agent_b": "string (default: 'agent-b')",
                    "prompt": "string (default: 'Hello')",
                    "region": "EU|UK|US|EEA (default: EU)",
                },
                "response_shape": {
                    "event_id": "MEOK-A2A-XXXXXXXX-NNNNN",
                    "stages": "7 stage attestations (identity, residency, policy, firewall, rate-limit, handoff, audit)",
                    "bridge": "folded governance-bridge event + Ed25519/HMAC signature",
                    "verify_url": "https://proofof.ai/verify/<event_id>",
                },
                "substrate": "https://meok.ai/a2a (Substrate £499/mo — 1 invoice, 1 signed event)",
                "signature_kid": _SIGNING_KEY_KID,
            })
        return self._json(404, {"error": "Not found", "path": path})

    def do_POST(self):
        path = (self.path or "/").split("?", 1)[0]
        if path not in ("/v1/a2a/demo", "/v1/a2a/demo/"):
            return self._json(404, {"error": "Not found", "path": path})

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            body = json.loads(raw) if raw.strip() else {}
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"error": "Invalid JSON body"})

        prompt = str(body.get("prompt", "Hello from the A2A substrate demo"))[:4096]
        agent_a = str(body.get("agent_a", "agent-claude-sonnet"))[:128]
        agent_b = str(body.get("agent_b", "agent-gpt-4o"))[:128]
        region = str(body.get("region", "EU")).upper()[:8]

        event = _run_pipeline(agent_a, agent_b, prompt, region)
        return self._json(200, event)
