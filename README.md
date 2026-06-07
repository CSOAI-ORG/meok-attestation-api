# MEOK Attestation API

Public signing + verification surface for MEOK AI Labs compliance attestations.

## Endpoints

- `GET /` — docs + pricing
- `POST /sign` — issue a signed attestation (requires `api_key`)
- `POST /verify` — verify a full cert payload (public)
- `GET /verify/<cert_id>` — human-readable verify page
- `GET /health` — liveness

## Env vars (set via Vercel dashboard or `vercel env`)

| Var | Required | Notes |
|---|---|---|
| `MEOK_ATTESTATION_KEY` | yes (prod) | HMAC signing key. Rotate quarterly. |
| `MEOK_MASTER_API_KEY` | yes | Master key — Nick's own. |
| `MEOK_PRO_KEYS` | optional | Comma-separated list of Pro API keys. |
| `MEOK_VERIFY_URL` | optional | Base URL for verify links. Default: this deployment. |

## Deploy

```bash
vercel --prod
vercel env add MEOK_ATTESTATION_KEY production  # paste secure random string
vercel env add MEOK_MASTER_API_KEY production   # paste your master key
vercel --prod  # redeploy so env vars bind
```

## Client usage

```python
import json, urllib.request

req = urllib.request.Request(
    "https://meok-attestation-api.vercel.app/sign",
    data=json.dumps({
        "api_key": "YOUR_PRO_KEY",
        "regulation": "DORA",
        "entity": "Acme Bank PLC",
        "score": 82.5,
        "findings": ["Article 9 PASS", "Article 28 GAP"],
        "articles_audited": ["9", "28"],
    }).encode(),
    headers={"Content-Type": "application/json"},
)
cert = json.loads(urllib.request.urlopen(req).read())
print(cert["verify_url"])
```
