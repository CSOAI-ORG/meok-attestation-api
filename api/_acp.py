"""
ACP (Agent Communication Protocol) endpoint — Move #9.

Wraps the existing sign + verify endpoints in ACP-style message envelopes so
agent-to-agent runtimes (Linux Foundation ACP, IBM agent stack, etc.) can
discover MEOK as a compliance-rail without a custom client.

Spec reference:
  https://github.com/i-am-bee/acp  (one of several converging proposals)
  https://github.com/agntcy/acp-spec

Minimal surface:
  POST /acp  — receives an ACP message envelope, returns a result envelope.

Message kinds supported:
  - "agent.list_capabilities"  → returns the MEOK agent card
  - "agent.invoke"             → invokes a tool ("sign" | "verify")
  - "agent.health"             → liveness

This is a thin protocol-adapter — all real work goes through sign_attestation +
verify_attestation in index.py. Keeps a single source of truth for crypto + tier
resolution.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable

# Agent card — describes what this MEOK agent can do.
AGENT_CARD = {
    "id": "meok-trade-compliance",
    "name": "MEOK Trade Compliance",
    "description": "HMAC-signed compliance attestations across UK + EU + US + AU + Canada + air + sea + rail. EU AI Act + UK AI Bill bridge built in.",
    "version": "1.0.0",
    "publisher": {
        "name": "MEOK AI Labs / CSOAI LTD",
        "email": "nicholas@meok.ai",
        "url": "https://meok.ai",
    },
    "license": "MIT",
    "capabilities": [
        {
            "name": "sign",
            "description": "Issue a signed HMAC-SHA256 compliance attestation.",
            "input_schema": {
                "type": "object",
                "required": ["regulation", "entity", "score"],
                "properties": {
                    "regulation": {"type": "string", "examples": ["EU_AI_ACT_ANNEX_III"]},
                    "entity": {"type": "string"},
                    "score": {"type": "number", "minimum": 0, "maximum": 100},
                    "findings": {"type": "array", "items": {"type": "string"}},
                    "articles_audited": {"type": "array", "items": {"type": "string"}},
                },
            },
            "auth_required": True,
        },
        {
            "name": "verify",
            "description": "Public verification of a signed cert. No auth required.",
            "input_schema": {"type": "object", "properties": {"cert": {"type": "object"}}},
            "auth_required": False,
        },
    ],
    "auth": {
        "type": "api_key",
        "in": "header",
        "name": "X-API-Key",
    },
    "interop": {
        "openapi_url": "https://meok-attestation-api.vercel.app/openapi.json",
        "docs_url": "https://meok-attestation-api.vercel.app/docs",
        "llms_txt_url": "https://meok-attestation-api.vercel.app/llms.txt",
    },
}


def envelope(message_id: str, kind: str, payload: Any, *, in_reply_to: str | None = None) -> dict[str, Any]:
    """Wrap a payload in an ACP-style envelope."""
    env: dict[str, Any] = {
        "acp_version": "0.1",
        "message_id": message_id,
        "kind": kind,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload": payload,
    }
    if in_reply_to:
        env["in_reply_to"] = in_reply_to
    return env


def handle_acp(
    body: dict[str, Any],
    *,
    sign_fn: Callable[..., dict[str, Any]],
    verify_fn: Callable[[dict[str, Any]], tuple[bool, str]],
    api_key: str = "",
    check_api_key: Callable[[str, str], tuple[bool, str, str]] | None = None,
    email: str = "",
) -> tuple[int, dict[str, Any]]:
    """Dispatch an inbound ACP message. Returns (status_code, response_envelope)."""
    request_id = str(body.get("message_id") or uuid.uuid4().hex)
    kind = body.get("kind", "")
    payload = body.get("payload", {}) or {}

    if kind == "agent.health":
        return 200, envelope(uuid.uuid4().hex, "agent.health.reply", {"status": "ok"}, in_reply_to=request_id)

    if kind == "agent.list_capabilities":
        return 200, envelope(uuid.uuid4().hex, "agent.capabilities", AGENT_CARD, in_reply_to=request_id)

    if kind == "agent.invoke":
        tool = payload.get("tool", "")
        args = payload.get("args", {}) or {}
        if tool == "verify":
            cert = args.get("cert") or args
            valid, msg = verify_fn(cert)
            return 200, envelope(
                uuid.uuid4().hex,
                "agent.invoke.result",
                {"tool": "verify", "ok": True, "result": {"valid": valid, "message": msg}},
                in_reply_to=request_id,
            )
        if tool == "sign":
            if check_api_key and api_key:
                ok, msg, resolved_tier = check_api_key(api_key, email)
                if not ok:
                    return 401, envelope(
                        uuid.uuid4().hex,
                        "agent.invoke.error",
                        {"tool": "sign", "error": msg},
                        in_reply_to=request_id,
                    )
            else:
                resolved_tier = "free"
            try:
                cert = sign_fn(
                    regulation=args.get("regulation", ""),
                    entity=args.get("entity", ""),
                    score=float(args.get("score", 0)),
                    findings=args.get("findings", []),
                    articles_audited=args.get("articles_audited", []),
                    tier=resolved_tier,
                    auditor_notes=args.get("auditor_notes", ""),
                )
                return 200, envelope(
                    uuid.uuid4().hex,
                    "agent.invoke.result",
                    {"tool": "sign", "ok": True, "result": cert},
                    in_reply_to=request_id,
                )
            except Exception as e:  # noqa: BLE001
                return 500, envelope(
                    uuid.uuid4().hex,
                    "agent.invoke.error",
                    {"tool": "sign", "error": str(e)},
                    in_reply_to=request_id,
                )
        return 400, envelope(
            uuid.uuid4().hex,
            "agent.invoke.error",
            {"error": f"Unknown tool: {tool}", "available_tools": ["sign", "verify"]},
            in_reply_to=request_id,
        )

    return 400, envelope(
        uuid.uuid4().hex,
        "agent.error",
        {
            "error": f"Unknown ACP message kind: {kind}",
            "available_kinds": ["agent.health", "agent.list_capabilities", "agent.invoke"],
        },
        in_reply_to=request_id,
    )
