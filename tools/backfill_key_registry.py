#!/usr/bin/env python3
"""Backfill the KV key registry from existing Stripe customers (2026-06-16).

WHY: api/verify.py now grants `pro/unlimited` only to keys present in the KV
registry (`meok:validkey:<key>`). New keys self-register at mint time. This
script registers keys ALREADY in customers' hands so they jump straight to
unlimited instead of the (generous) 500/day grace cap.

NOTE: running this is NOT required before deploy — the grace cap + fail-open
mean no legit customer breaks. This just upgrades known customers to unlimited
on day 0 and clears the [UNREGISTERED_PRO_KEY] log noise.

USAGE (with production env loaded — `vercel env pull`):
    cd meok-attestation-api
    vercel env pull /tmp/att.env --environment=production --yes
    set -a; . /tmp/att.env; set +a
    python3 tools/backfill_key_registry.py            # dry-run (prints, no writes)
    python3 tools/backfill_key_registry.py --commit   # actually register
    rm /tmp/att.env

Reads: MEOK_API_KEY_PEPPER, STRIPE_SECRET_KEY, KV_REST_API_URL, KV_REST_API_TOKEN
"""
import hashlib
import hmac
import json
import os
import sys
import urllib.parse
import urllib.request

PEPPER = os.environ.get("MEOK_API_KEY_PEPPER", "").encode("utf-8")
STRIPE = os.environ.get("STRIPE_SECRET_KEY", "")
KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOK = os.environ.get("KV_REST_API_TOKEN", "")
COMMIT = "--commit" in sys.argv


def derive_api_key(email: str, tier: str) -> str:
    """Identical to api/index.py derive_api_key — keep in lockstep."""
    norm = f"{email.strip().lower()}|{tier.lower()}"
    h = hmac.new(PEPPER, norm.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"meok_{tier.lower()}_{h[:24]}"


def kv_set(key: str, tier: str):
    if not (KV_URL and KV_TOK):
        return None
    req = urllib.request.Request(
        KV_URL, data=json.dumps(["SET", f"meok:validkey:{key}", tier]).encode(),
        headers={"Authorization": f"Bearer {KV_TOK}", "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=6) as r:
        return json.load(r).get("result")


def stripe_get(path: str) -> dict:
    req = urllib.request.Request(
        f"https://api.stripe.com/v1{path}",
        headers={"Authorization": f"Bearer {STRIPE}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def search_tier(tier: str):
    """Yield (email, tier) for Stripe customers tagged metadata[meok_tier]=tier."""
    q = urllib.parse.quote(f"metadata['meok_tier']:'{tier}'")
    page = None
    while True:
        url = f"/customers/search?query={q}&limit=100" + (f"&page={page}" if page else "")
        resp = stripe_get(url)
        for c in resp.get("data", []):
            email = (c.get("email") or "").strip().lower()
            if email:
                yield email, tier
        if resp.get("has_more") and resp.get("next_page"):
            page = resp["next_page"]
        else:
            break


def main():
    if not PEPPER:
        sys.exit("MEOK_API_KEY_PEPPER not set — cannot derive keys.")
    if not STRIPE:
        sys.exit("STRIPE_SECRET_KEY not set — cannot list customers.")
    if not (KV_URL and KV_TOK):
        sys.exit("KV_REST_API_URL/TOKEN not set — nowhere to register.")

    mode = "COMMIT" if COMMIT else "DRY-RUN"
    print(f"== key-registry backfill ({mode}) ==")
    seen, registered = set(), 0
    for tier in ("enterprise", "pro"):
        try:
            for email, t in search_tier(tier):
                key = derive_api_key(email, t)
                if key in seen:
                    continue
                seen.add(key)
                fp = hashlib.sha256(key.encode()).hexdigest()[:12]
                if COMMIT:
                    kv_set(key, t)
                    registered += 1
                print(f"  {t:10s} {email:38s} fp={fp} {'registered' if COMMIT else '(would register)'}")
        except Exception as e:
            print(f"  ! {tier} search failed: {type(e).__name__}: {e}")
    print(f"== {registered if COMMIT else len(seen)} key(s) "
          f"{'registered' if COMMIT else 'found (dry-run, no writes)'} ==")
    if not COMMIT:
        print("Re-run with --commit to write to the registry.")


if __name__ == "__main__":
    main()
