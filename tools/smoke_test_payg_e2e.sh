#!/usr/bin/env bash
# End-to-end smoke test for the PAYG revenue loop.
# Run AFTER configuring Stripe webhook + creating Payment Links.
#
# Usage:
#   bash tools/smoke_test_payg_e2e.sh                   # health checks only
#   bash tools/smoke_test_payg_e2e.sh full TOKEN_HERE   # full deduct round-trip
#
# Exits non-zero on any failure so this can wrap into CI.

set -euo pipefail

API="https://meok-attestation-api.pages.dev/payg"
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
NC=$'\033[0m'

pass () { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
fail () { printf "  ${RED}✗${NC} %s\n" "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Preflight: does the host this test targets exist at all?
#
# Every run of this smoke test failed with a bare "exit code 6" and no message.
# Exit 6 is curl for "couldn't resolve host": meok-attestation-api.pages.dev has
# no DNS record. The test was not finding a broken API — it was testing an API
# that is not deployed. `set -e` plus an unchecked curl turned that into an
# opaque number.
#
# Checked 2026-08-05: meok-attestation-api.pages.dev does not resolve;
# os.meok.ai/payg/health and meok.ai/payg/health both return the 43,485-byte MEOK
# homepage, i.e. a soft-404, not the API. The PAYG endpoints are live nowhere.
HOST=$(printf '%s' "$API" | sed -E 's#^https?://([^/]+).*#\1#')
if ! getent hosts "$HOST" >/dev/null 2>&1 && ! nslookup "$HOST" >/dev/null 2>&1; then
  printf "  ${RED}✗${NC} %s\n" "host does not resolve: $HOST"
  echo ""
  echo "  The PAYG API is not deployed at this address, so there is nothing to smoke."
  echo "  Either deploy it, or point \$API at the address it actually lives on."
  echo "  This test is failing correctly; it is not a flake and not a credentials problem."
  exit 1
fi

echo "=== 1. /payg/health ==="
HEALTH=$(curl -s "$API/health")
echo "  body: $HEALTH"
echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['ok'], 'ok=false'; assert d['stripe_configured'], 'STRIPE_SECRET_KEY missing'; assert d['webhook_configured'], 'STRIPE_WEBHOOK_SECRET missing'; print('  parsed ok')" \
  && pass "health endpoint reachable + Stripe configured" \
  || fail "health endpoint failed — check Vercel env vars"

echo
echo "=== 2. /payg/webhook rejects unsigned ==="
WEBHOOK_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{}' "$API/webhook")
[ "$WEBHOOK_RESP" = "400" ] && pass "unsigned webhook rejected with 400" || fail "expected 400, got $WEBHOOK_RESP"

echo
echo "=== 3. /payg/balance with unknown token ==="
BAL_RESP=$(curl -s "$API/balance?token=definitely_does_not_exist")
echo "$BAL_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('error') == 'Token not found', f'expected Token not found, got {d}'; print('  parsed ok')" \
  && pass "unknown token returns 404 + topup_url" \
  || fail "balance endpoint malformed response"

echo
echo "=== 4. /payg/deduct with unknown token ==="
DED_RESP=$(curl -s -X POST -H "Content-Type: application/json" -d '{"token":"unknown","amount_gbp":0.05}' "$API/deduct")
echo "$DED_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('error') == 'Token not found', f'expected Token not found, got {d}'; print('  parsed ok')" \
  && pass "unknown token deduct returns 404 + topup_url" \
  || fail "deduct endpoint malformed response"

if [ "${1:-}" = "full" ] && [ -n "${2:-}" ]; then
  TOKEN="$2"
  echo
  echo "=== 5. FULL: /payg/balance with real token ==="
  REAL=$(curl -s "$API/balance?token=$TOKEN")
  echo "  body: $REAL"
  echo "$REAL" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  balance: £{d[\"balance_gbp\"]}, calls remaining: {d[\"calls_remaining\"]}')"
  pass "real token resolves to balance"

  echo
  echo "=== 6. FULL: deduct £0.05 ==="
  DED=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"amount_gbp\":0.05}" "$API/deduct")
  echo "  body: $DED"
  echo "$DED" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok'), f'deduct failed: {d}'; print(f'  new balance: £{d[\"balance_gbp\"]}')"
  pass "deduct successful + new balance returned"

  echo
  echo "=== 7. FULL: balance reflects deduction ==="
  REAL2=$(curl -s "$API/balance?token=$TOKEN")
  echo "$REAL2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  balance now: £{d[\"balance_gbp\"]}')"
  pass "balance reflects deduction"
fi

echo
echo "${GREEN}=========================="
echo "  PAYG E2E smoke OK"
echo "==========================${NC}"
