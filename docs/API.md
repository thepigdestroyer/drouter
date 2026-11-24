# deRoute API keys for coding agents

[Get an API key](https://deroute.is-an.ai/api-keys). Sign in on the site, add free credits or claim prepaid Arc Testnet USDC credits, then create and copy a key. The account passkey or six words unlock your local vault; they are never API credentials. Passkeys, vaults and wallets are origin-specific. Existing users of the original Vercel site can sign in there and use their existing keys on the canonical gateway.

| Client setting | Value |
| --- | --- |
| Provider | OpenAI-compatible **Chat Completions** |
| Base URL | `https://deroute.is-an.ai/api/v1` |
| Model | `kimi-k3-1-pro` (discover other chat IDs at [`GET /models`](https://deroute.is-an.ai/api/v1/models)) |
| API key | Your own `drk_…` key, sent as `Authorization: Bearer` |

Direct HTTPS terminates at deRoute: the gateway can read the request and response, applies its filter, and verifies the upstream enclave. The browser chat and optional [local proxy](#local-proxy) filter and encrypt on the device. An agent or editor itself can still see the content you give it.

## Clients

- **OpenCode v2**: the [setup page](https://deroute.is-an.ai/api-keys) generates `opencode.jsonc` using `providers.deroute`, `@opencode/ai/providers/openai-compatible`, and `env: ["DEROUTE_API_KEY"]`. Set that variable in the OpenCode server environment, merge the config and select `deroute/kimi-k3-1-pro`.
- **Continue**: use the supplied `config.yaml` model entry with `provider: openai`, `apiBase`, `model`, and `capabilities: [tool_use]`. Set the named `DEROUTE_API_KEY` secret in Continue; do not commit a key to the config.
- **Cline / Roo Code**: select **OpenAI Compatible**, then enter the base URL, model ID and your key in the dedicated credential field. Use text Chat Completions, not Responses. Aider and OpenAI SDKs can also use this endpoint. Clients locked to a vendor endpoint or requiring Anthropic Messages or OpenAI Responses cannot use it directly.

For a temporary shell credential in Bash, run `read -rs DEROUTE_API_KEY; export DEROUTE_API_KEY` and paste at the hidden prompt. Do not paste keys into prompts, command lines or checked-in files. Remove it with `unset DEROUTE_API_KEY`.

### Python (`pip install openai`)

```python
import os
from openai import OpenAI

client = OpenAI(base_url="https://deroute.is-an.ai/api/v1",
                api_key=os.environ["DEROUTE_API_KEY"], max_retries=0)
for chunk in client.chat.completions.create(
    model="kimi-k3-1-pro", stream=True, max_tokens=512,
    messages=[{"role": "user", "content": "What does git status show?"}],
):
    if chunk.choices:
        print(chunk.choices[0].delta.content or "", end="")
```

### TypeScript / Node.js (`npm install openai`)

```ts
import OpenAI from "openai";
const apiKey = process.env.DEROUTE_API_KEY;
if (!apiKey) throw new Error("Set DEROUTE_API_KEY first");
const client = new OpenAI({ baseURL: "https://deroute.is-an.ai/api/v1", apiKey, maxRetries: 0 });
const reply = await client.chat.completions.create({
  model: "kimi-k3-1-pro", max_tokens: 512,
  messages: [{ role: "user", content: "Use the project_info tool." }],
  tools: [{ type: "function", function: { name: "project_info", parameters: { type: "object", properties: {} } } }],
  tool_choice: "auto",
});
// The client validates arguments, executes approved tools, and resubmits their results.
console.log(reply.choices[0]?.message.tool_calls?.map(call => call.type));
```

## Credits and request limits

The browser packages blind-signed wallet tokens, not identity or an operator credential, into a transferable bearer key. Issuance does not create a server-side key record. The default recovery copy is in tab memory; encrypted on-device recovery is opt-in. Save the key yourself before dismissing it. There is no remote recovery, revocation or top-up. Create small keys and replace them when spent. The UI offers 1 or 5 credits so the bearer fits common HTTP header limits; the wire format still accepts legacy bundles of 1–50 tokens. Use the proxy if a client rejects a large legacy header.

Hosted chat checks the signature and records the first available token’s nullifier before attempting inference. One token buys one request regardless of denomination. An upstream failure or a client retry can therefore cost a token. Successful keyed responses include `X-DRouter-Credit-Verified` and `X-DRouter-Credits-Remaining` (last-known count, not a cross-instance balance inquiry). Listing models is public and does not spend credits.

- `401`: malformed, unknown, invalidly signed or conflicting bearer credentials. Never falls back to anonymous use.
- `402`: key exhausted; create another. Free minting is also allowance-limited (10 credit units per IP per day, refilling gradually).
- `413` / `400`: shorten the request or remove unsupported content. Hosted text JSON: 128 KiB, 64 messages, 64 tools, up to 16,384 requested output tokens. A model’s context window is not the gateway payload limit.
- `429`: shared inference quota (40 requests/hour token bucket per running instance) or other rate limit; observe `Retry-After`.
- `503`: server configuration or credit ledger unavailable. `502`: upstream verification or inference failed.

Explicit single-token `x-drouter-credit` / `x-drouter-credit-token` remains available. Do not combine it with a `drk_` bearer. The existing capped demo tier accepts omitted credentials or exactly `Bearer drouter-anonymous`; it is not a production API key.

## Local proxy

Use Node 20+ on the same computer as the calling client. Some remote/cloud editors cannot reach loopback. The proxy verifies its filter fingerprint and the enclave, filters and seals prompts locally, restores responses locally and attaches individual signed tokens to the relay. Only spent nullifiers are written to `~/.config/deroute/spent.json`. With a supplied key it stops when exhausted.

```bash
curl -fsSLO https://deroute.is-an.ai/downloads/deroute-proxy.mjs && \
curl -fsSLO https://deroute.is-an.ai/downloads/deroute-proxy.mjs.sha256 && \
shasum -a 256 -c deroute-proxy.mjs.sha256 && \
DEROUTE_ACCESS_KEY="${DEROUTE_API_KEY:?Set your key first}" node deroute-proxy.mjs
```

Configure the client base URL as `http://127.0.0.1:4141/v1`, model `kimi-k3-1-pro`, and SDK placeholder key `deroute-local`. The real credit key belongs to the proxy process. To rebuild from this repository run `npm ci && npm run build:proxy`; the bundle and checksum are under `public/downloads/`.
