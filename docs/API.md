# deRoute API & Coding Tools Guide

Use deRoute from OpenCode, Cursor, Continue, Aider, the OpenAI TypeScript or Python SDK, or `curl`.

---

## 1. What each mode protects

deRoute offers two ways to connect your coding tools:

### Private mode (recommended): local proxy (`http://127.0.0.1:4141/v1`)
You run `node deroute-proxy.mjs --key drk_...` (or set `DEROUTE_ACCESS_KEY`) on your own computer.

For every request on your machine:
1. **Local personal-detail filter**: Runs the fingerprinted mechanical filter with session-stable placeholders (`[EMAIL_1]`, `[ENTITY_1]`, etc.) before anything leaves your computer.
2. **Seven seal checks**: Verifies all seven hardware and transparency checks on the sealed computer.
3. **End-to-end locking**: Encrypts your prompt with RFC 9180 HPKE directly to the attested enclave key and sends only ciphertext through our relay (`/api/relay/v1/`).
4. **One anonymous token per request**: Attaches one blind-signed credit token in `x-drouter-credit` (`formatCreditHeader(token)`) and records spent nullifiers locally in `~/.config/deroute/spent.json` so a restart never reuses a token.
5. **Local restore**: Restores hidden placeholders inside the response stream on your machine.
6. **Free-tier fallback**: When the access key runs out of unspent tokens, the proxy falls back to the free tier and reports this in a response header and on `stderr`.

Our server and relay never see your plaintext prompts, responses, or which wallet minted your tokens.

### Hosted mode (convenient): direct gateway (`https://drouter-demo.vercel.app/api/v1`)
Your coding tool sends requests directly to `POST https://drouter-demo.vercel.app/api/v1/chat/completions` with `Authorization: Bearer drk_...` (or an explicit `x-drouter-credit` header).

> **Plain privacy notice**: In hosted mode our server filters your words before forwarding them to the sealed computer, so our server sees them. Use the local proxy if you do not want that.

Our server never logs request bodies or access keys.

---

## 2. Access key format (`drk_...`)

An access key is created in your browser on `/account` by **moving** anonymous tokens out of your browser wallet so the browser can never spend the same token twice. The server never issues or stores access keys.

- **Format**:
  ```text
  drk_<base64url_unpadded(utf8(canonicalJson({
    v: 1,
    origin: "https://drouter-demo.vercel.app",
    tokens: [
      { t: "<token hex>", s: "<signature hex>", d: <denomination> },
      ...
    ]
  })))>
  ```
- **`canonicalJson`**: Deterministic sorted-key JSON serialization (`src/lib/transparency/log.ts`).
- **Tokens**: Each entry `{ t, s, d }` corresponds to a `BlindCreditToken` (`{ token: t, signature: s, denomination: d }`). When spent individually in a request header, it is formatted via `formatCreditHeader(token)` (`src/lib/credits/blind.ts`).
- **Strict validation (`decodeAccessKey`)**:
  - Must start with `drk_` followed by canonical unpadded base64url bytes.
  - Must decode to valid UTF-8 JSON with exact top-level keys `v`, `origin`, and `tokens`.
  - `v` must be `1`.
  - `origin` must be `"https://drouter-demo.vercel.app"`.
  - `tokens` must contain **1 to 50** token objects, each with exact keys `t` (lowercase even-length hex), `s` (lowercase even-length hex), and `d` (`1`, `5`, or `20`), with no duplicate token nullifiers.
  - Unknown versions, unknown keys, malformed hex, wrong origin, duplicate tokens, or more than 50 tokens are rejected with HTTP `400`.

### How `Authorization: Bearer drk_...` spends credits in Hosted mode
- On `POST /api/v1/chat/completions`, when `Authorization: Bearer drk_...` is sent (and no explicit `x-drouter-credit` header overrides it), the server decodes the key and checks each token in order until it finds the first token whose nullifier is unspent.
- That token is spent for the request, and the response includes:
  - `X-DRouter-Credit-Verified: true`
  - `X-DRouter-Credit-Nullifier: <sha256 nullifier>`
  - `X-DRouter-Credit-Denomination: <1|5|20>`
  - `X-DRouter-Credits-Remaining: <count of unspent tokens remaining in that key>`
- If every token in the key has already been spent, the server returns HTTP `402` (`X-DRouter-Credits-Remaining: 0`) with a plain message to create a new access key on `/account`.
- Any other `Authorization: Bearer <value>` (for example `Bearer any-value`) falls back to the per-network free tier.

---

## 3. Verifying and rebuilding `deroute-proxy.mjs`

The local proxy is distributed as a single self-contained file requiring only **Node 20 or later**:

- Proxy bundle: `https://drouter-demo.vercel.app/downloads/deroute-proxy.mjs`
- SHA-256 checksum: `https://drouter-demo.vercel.app/downloads/deroute-proxy.mjs.sha256`

### Verify the downloaded file
```bash
curl -fsSLO https://drouter-demo.vercel.app/downloads/deroute-proxy.mjs
curl -fsSLO https://drouter-demo.vercel.app/downloads/deroute-proxy.mjs.sha256
shasum -a 256 -c deroute-proxy.mjs.sha256
```

### Run the local proxy
```bash
node deroute-proxy.mjs --key drk_YOUR_ACCESS_KEY
# Or via environment variable:
DEROUTE_ACCESS_KEY=drk_YOUR_ACCESS_KEY node deroute-proxy.mjs
```
The proxy listens on `http://127.0.0.1:4141/v1` and serves `GET /v1/models` and `POST /v1/chat/completions` (streaming and non-streaming).

### Rebuild the proxy from source
To verify that the published bundle matches the repository source code:
```bash
git clone https://github.com/thepigdestroyer/drouter
cd drouter
npm ci
npm run build:proxy
shasum -a 256 public/downloads/deroute-proxy.mjs
cat public/downloads/deroute-proxy.mjs.sha256
```
`npm run build:proxy` bundles the TypeScript sources and the `tinfoil` verification SDK with `esbuild` into `public/downloads/deroute-proxy.mjs` and writes its digest to `public/downloads/deroute-proxy.mjs.sha256`. Running `node scripts/drouter-cli.mjs proxy [--port 4141] [--key drk_...]` from a repository checkout verifies `public/downloads/deroute-proxy.mjs` against `public/downloads/deroute-proxy.mjs.sha256` and launches that bundle.

---

## 4. Setup for coding tools

Available model IDs from `GET /api/v1/models`:
- `kimi-k3`
- `glm-5-3`
- `deepseek-v4-1-flash`
- `gpt-oss-120b`
- `llama3-3-70b`
- `gemma4-31b`

In **Private mode**, use base URL `http://127.0.0.1:4141/v1` and API key `deroute-local`.
In **Hosted mode**, use base URL `https://drouter-demo.vercel.app/api/v1` and API key `drk_YOUR_ACCESS_KEY`.

### OpenCode (`opencode.json`)
Uses `@ai-sdk/openai-compatible` per [https://opencode.ai/docs/providers](https://opencode.ai/docs/providers):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "deroute": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "deRoute (Local Private Proxy)",
      "options": {
        "baseURL": "http://127.0.0.1:4141/v1",
        "apiKey": "deroute-local"
      },
      "models": {
        "kimi-k3": {
          "name": "Kimi K3 (2.8T MoE, 256K ctx) (deRoute)"
        },
        "glm-5-3": {
          "name": "GLM-5.3 (deRoute)"
        },
        "deepseek-v4-1-flash": {
          "name": "DeepSeek V4.1 Flash (deRoute)"
        },
        "gpt-oss-120b": {
          "name": "GPT-OSS 120B (deRoute)"
        },
        "llama3-3-70b": {
          "name": "Llama 3.3 70B (deRoute)"
        },
        "gemma4-31b": {
          "name": "Gemma 4 31B (deRoute)"
        }
      }
    }
  },
  "model": "deroute/kimi-k3"
}
```

### Cursor
1. Open **Cursor Settings -> Models -> OpenAI API Key**.
2. Enable **Override OpenAI Base URL** and set it to `http://127.0.0.1:4141/v1` (or `https://drouter-demo.vercel.app/api/v1` in hosted mode).
3. Set **OpenAI API Key** to `deroute-local` (or `drk_YOUR_ACCESS_KEY` in hosted mode).
4. Add model IDs from `GET /api/v1/models`: `kimi-k3`, `glm-5-3`, `deepseek-v4-1-flash`, `gpt-oss-120b`, `llama3-3-70b`, `gemma4-31b`.

### Continue (`~/.continue/config.yaml`)
```yaml
name: deRoute Config
version: 1.0.0
schema: v1
models:
  - name: deRoute Kimi K3
    provider: openai
    model: kimi-k3
    apiBase: http://127.0.0.1:4141/v1
    apiKey: deroute-local
    roles:
      - chat
      - edit
      - apply
```

### Aider
```bash
aider \
  --openai-api-base "http://127.0.0.1:4141/v1" \
  --openai-api-key "deroute-local" \
  --model "openai/kimi-k3"
```

### OpenAI SDK for TypeScript
```ts
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:4141/v1",
  apiKey: "deroute-local",
});

const completion = await client.chat.completions.create({
  model: "kimi-k3",
  messages: [{ role: "user", content: "Write a short unit test in TypeScript." }],
});

console.log(completion.choices[0]?.message?.content);
```

### OpenAI SDK for Python
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:4141/v1",
    api_key="deroute-local",
)

completion = client.chat.completions.create(
    model="kimi-k3",
    messages=[{"role": "user", "content": "Write a short unit test in Python."}],
)

print(completion.choices[0].message.content)
```

### curl
```bash
# List models:
curl -sS "http://127.0.0.1:4141/v1/models"

# Chat completion:
curl -sS -X POST "http://127.0.0.1:4141/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer deroute-local" \
  -d '{
    "model": "kimi-k3",
    "messages": [
      { "role": "user", "content": "Reply with one short sentence." }
    ]
  }'
```

---

## 5. Limits and rate tiers

- **Tokens per access key**: 1 to 50 blind-signed credit tokens (`denomination` in `1`, `5`, or `20`).
- **Request body size**: Up to 128 KB JSON (`MAX_CHAT_BODY_BYTES = 131072`), up to 64 messages per request, and up to `16384` `max_tokens`.
- **Credit-backed requests**: Requests with a valid `x-drouter-credit` token or an unspent token inside `Authorization: Bearer drk_...` bypass the per-IP free-tier rate limiter.
- **Free tier**: Requests without a credit header and without a `drk_...` bearer key use the per-IP free tier (5 requests per minute, burst 10). Free daily minting at `POST /api/credits` grants up to 10 free credits per UTC day per network before requiring a one-time USDC deposit invoice (`POST /api/credits/invoice`).
