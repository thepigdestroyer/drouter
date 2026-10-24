# dRouter Server API, Relay, Gateway & Attestation Verifier Security Audit

Audit date: 2026-10-24
Target: Next.js 16.4.3 / React 19.3 / TypeScript server routes (`src/app/api/**`, `/v1/:path*` rewrite in `next.config.ts`, `src/proxy.ts`), oblivious relay (`src/lib/relay.ts`), OpenAI-compatible gateway (`src/lib/gateway/harness-config.ts`), Arc testnet registry (`src/lib/arc/**`), and Tinfoil attestation verifier (`src/lib/tinfoil/client.ts`, `src/lib/tinfoil/deep-inspect.ts`).

---

## 1. Executive Summary & Core Abuse Questions

1. **Were `/api/relay/v1/[...path]`, `/api/relay/[relayId]/v1/[...path]`, or `/api/v1/chat/completions` free open proxies to Tinfoil on our `TINFOIL_API_KEY`?**
   - **Confirmed (High Severity before fix)**:
     - `/api/v1/chat/completions` (and its `/v1/chat/completions` rewrite) accepted unauthenticated plaintext OpenAI chat requests from any origin (`Access-Control-Allow-Origin: *`), instantiated `new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY })`, and billed tokens to the server's `TINFOIL_API_KEY` with **no rate limit, no body size limit, and no `max_tokens` cap**.
     - `/api/relay/v1/[...path]` and `/api/relay/[relayId]/v1/[...path]` injected `Authorization: Bearer ${TINFOIL_API_KEY}` and forwarded arbitrary POST bodies to `https://*.tinfoil.sh/v1/${path.join("/")}` with **no rate limit, no body size cap, no `[...path]` endpoint allowlist, no `x-tinfoil-model` validation, and no check for the `ehbp-encapsulated-key` HPKE header**.
   - **After fix**:
     - Added privacy-preserving per-IP token-bucket rate limiters (`src/lib/ratelimit/index.ts`, keyed by `SHA-256(dailyRotatingSalt : namespace : ip)` in memory; raw IPs are never stored or logged) plus global hourly/minute token buckets across both relay and gateway routes.
     - Enforced strict v1 path allowlisting (`validateRelayPath`: only `chat/completions`, `completions`, `embeddings`, `models`, `audio/transcriptions`, `audio/speech`, `responses`), strict `x-tinfoil-model` allowlisting (`kimi-k3`, `glm-5-3`, `deepseek-v4-1-flash`, `gpt-oss-120b`, `llama3-3-70b`, `gemma4-31b`), mandatory `ehbp-encapsulated-key` header validation on relay routes, 256 KB body size ceiling on relay routes, and 128 KB body size ceiling + `max_tokens <= 16384` + `messages.length <= 64` on `/api/v1/chat/completions`.

2. **Could anyone drain the Arc verifier wallet via `/api/anchor`?**
   - **Confirmed (High Severity before fix)**:
     - `/api/anchor` used a per-IP fixed-window limiter of 30 requests/minute (1,800/hour per IP, unbounded across spoofed `X-Forwarded-For` headers) and submitted up to **2 on-chain transactions per call** (`anchorReceipt` + `recordVerification`) paid in USDC gas from `ARC_VERIFIER_PRIVATE_KEY` at >= 20 gwei on Arc testnet (chain 5042002). It also accepted arbitrary 32-byte `nodeId` values not registered on-chain.
   - **After fix**:
     - Tightened `/api/anchor` to a salted per-IP token bucket (burst 6, refill 6/hour) **plus a hard global bucket (20 on-chain transactions/hour across all callers)**, validated `nodeId` against the registered node allowlist (`nodeKeyFor(nodeId)`), added 1-hour receipt-hash deduplication so repeated submissions of the same receipt cost 0 gas, and capped request bodies at 4 KB.

3. **Could anyone fill MongoDB or Node heap via `/api/log`, `/api/freeze`, `/api/credits/*`, or `/api/accountability`?**
   - **Confirmed (Medium/High Severity before fix)**:
     - `/api/log` had no rate limit and no body size cap before `request.json()`, allowing unlimited insertions into `verifications` and `receipts`.
     - `/api/freeze` had no rate limit and no upper bound on `ciphertextHex` length, allowing multi-megabyte documents to be inserted into `frozen_blobs` and `globalThis.__drouterFreezeStore`.
     - `/api/credits/spend` accepted arbitrary-length `nodeId` strings and unbounded requests into `credit_nullifiers` and `spentNullifiers`.
     - `/api/accountability` grew module-level `recentClaims` and `heartbeatsByNode` arrays without bound on every POST.
   - **After fix**:
     - Added per-IP and global token-bucket rate limiters to `/api/log`, `/api/freeze`, `/api/freeze/[blobId]`, `/api/credits`, `/api/credits/spend`, `/api/credits/redeem`, and `/api/accountability`.
     - Enforced streaming byte limits (`readBoundedBytes` / `readBoundedJson`) before parsing JSON, capped `ciphertextHex` at 128 KB binary (256 KB hex), validated `blobId` and `nodeId` formats, and bounded `recentClaims` (max 50) and `heartbeatsByNode` (max 64 per node).

4. **Zero-Telemetry Verification**:
   - Audited all `console.*` calls, MongoDB writes, and `X-DRouter-*` response headers.
   - Removed raw `error` object logging from `src/lib/db.ts`, `src/lib/arc/registry.ts`, and `src/lib/sim/http.ts` so connection strings or request payloads can never be written to stdout/stderr logs.
   - Confirmed MongoDB (`verifications`, `receipts`, `relay_totals`) never stores prompts, completions, IP addresses, or user agents; timestamps are coarsened to the UTC hour (`coarsenToHour`), and relay traffic uses a single `$inc` document (`_id: "global"`).
   - Confirmed `X-DRouter-*` headers (`X-DRouter-Attested`, `X-DRouter-Node`, `X-DRouter-Enclave-Host`, `X-DRouter-Release`, `X-DRouter-Code-Fingerprint`, `X-DRouter-Enclave-Fingerprint`, `X-DRouter-Relay-Hop`) contain only public enclave/node metadata and nothing identifying the caller.

---

## 2. Complete Route Inventory & Before/After Audit Table

Global layer: `next.config.ts` rewrites `/v1/:path*` to `/api/v1/:path*` and sets `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Permissions-Policy`. `src/proxy.ts` enforces a 256 KB body size ceiling, global per-IP rate limiting (180 burst, 6/s refill), and rejects non-object JSON primitives (`null`, `[]`, `"..."`) on JSON POST routes.

| Route | Methods | Cost Exposure | Before Audit | After Hardening |
| :--- | :--- | :--- | :--- | :--- |
| `/api/relay/v1/[...path]` | `POST` | **High**: Tinfoil tokens (`TINFOIL_API_KEY`) + Mongo `$inc` | No rate limit; no body size cap; `[...path]` allowed any path segment; `isAllowedEnclave` allowed paths/query in URL and rejected `*.tinfoil.dev`; no `ehbp-encapsulated-key` check; echoed upstream 4xx/5xx bodies. | Salted IP limiter (20 burst, 0.5/s) + global limiter; 256 KB body cap; strict `validateRelayPath` allowlist; strict `isAllowedEnclave` (origin-only HTTPS `*.tinfoil.sh` / `*.tinfoil.dev`); `isAllowedRelayModel` check; mandatory `ehbp-encapsulated-key` check; generic 4xx/502 error JSON without upstream body leakage. |
| `/api/relay/[relayId]/v1/[...path]` | `POST` | **High**: Tinfoil tokens (`TINFOIL_API_KEY`) + Mongo `$inc` | Same as `/api/relay/v1/[...path]` (had `isValidRelayId` check). | Same hardening as `/api/relay/v1/[...path]` + `isValidRelayId` validation and `X-DRouter-Relay-Hop` header. |
| `/api/relay/attestation` | `GET, POST` | Outbound fetch to `atc.tinfoil.sh` | No rate limit; `POST` forwarded arbitrary `request.text()` body upstream without size cap or schema check. | Salted IP limiter (60 burst, 1/s); 4 KB JSON body cap on POST; strict validation of `enclaveUrl` (`isAllowedEnclave`) and `repo` allowlist. |
| `/api/relay/[relayId]/attestation` | `GET, POST` | Outbound fetch to `atc.tinfoil.sh` | Validated `relayId`, but `POST` forwarded arbitrary `request.text()` body without size cap or schema check. | Salted IP limiter (60 burst, 1/s); `isValidRelayId`; 4 KB JSON body cap + `enclaveUrl`/`repo` allowlist on POST. |
| `/api/relay/enclave-matrix` | `GET` | Outbound fetches to ATC, Tinfoil proxy & GitHub (60s cache) | No rate limit; hardcoded `Milan` in `amdKdsUrl` even for Genoa reports; decoded TCB using Turin byte offsets on Genoa reports. | Salted IP limiter (60 burst, 2/s); fixed Genoa/Milan/Turin CPUID detection & TCB byte offset decoding in `decodeSnpReportBytes`; dynamic `productName` in `amdKdsUrl`. |
| `/api/v1/chat/completions` (and `/v1/chat/completions`) | `POST, OPTIONS` | **High**: Tinfoil tokens (`TINFOIL_API_KEY`) when model != `sim-echo-1` | Open CORS (`*`); no rate limit; no body size cap; no `max_tokens` or message count cap; leaked `err.message` on 502. | Salted IP limiter (10 burst, 5/min for real Tinfoil; 40 burst, 1/s for `sim-echo-1`) + global Tinfoil limiter (40/hr); 128 KB body cap; max 64 messages, 131 KB/msg, `max_tokens <= 16384`, `0 <= temperature <= 2`; generic 502 error message. |
| `/api/v1/models` (and `/v1/models`) | `GET, OPTIONS` | Static in-memory list | Open CORS (`*`); no rate limit. | Salted IP limiter (120 burst, 5/s). |
| `/api/v1/verify` (and `/v1/verify`) | `GET, OPTIONS` | Outbound Tinfoil verification (60s cache) | No rate limit; reflected `req.url` origin into `harnessConfigs` without host character check. | Salted IP limiter (60 burst, 2/s); strict protocol and host regex check before building `harnessConfigs`. |
| `/api/anchor` | `POST` | **High**: Arc USDC gas (`ARC_VERIFIER_PRIVATE_KEY`, up to 2 txs/call) | 30 req/min per raw IP (no global cap); no body size cap; accepted unregistered `nodeId`s; no receipt deduplication. | Salted IP limiter (6 burst, 6/hr) + **global limiter (20 txs/hr)**; 4 KB body cap; `nodeKeyFor(nodeId)` allowlist; 1-hour receipt-hash deduplication. |
| `/api/log` | `GET, POST` | **Medium**: MongoDB reads & `verifications`/`receipts` inserts | No rate limit; no body size cap; `POST` accepted `null` JSON body (500 crash). | Salted IP limiter (GET 60 burst; POST 20/min) + global POST limiter (200/hr); 16 KB body cap; NUL-byte stripping; non-object JSON guard. |
| `/api/registry` | `GET` | Arc RPC read (`use cache` 15s) | No rate limit. | Salted IP limiter (120 burst, 4/s) + 15s `cacheLife`. |
| `/api/freeze` | `GET, POST` | **Medium**: MongoDB `frozen_blobs` + memory Map | No rate limit; no body or `ciphertextHex` size cap; reflected `err.message`. | Salted IP limiter (GET 60 burst; POST 15/min); 256 KB body cap; 128 KB binary `ciphertextHex` cap; `blobId` length check. |
| `/api/freeze/[blobId]` | `GET, DELETE` | MongoDB read/delete + memory Map | No rate limit; no `blobId` hex format validation before Mongo query. | Salted IP limiter (60 burst, 2/s); strict hex regex `^(0x)?[0-9a-fA-F]{2,128}$` on `blobId`. |
| `/api/credits` | `GET, POST` | CPU RSA-2048 blind signing (up to 32 tokens) | No rate limit; no body size cap; no length cap on each hex string before BigInt conversion. | Salted IP limiter (GET 60 burst; POST 20/min); 32 KB body cap; max 1024 hex chars per blinded token. |
| `/api/credits/spend` | `POST` | **Medium**: RSA verify + MongoDB `credit_nullifiers` insert + Map | No rate limit; no body size cap; unvalidated `nodeId` length. | Salted IP limiter (30 burst, 0.5/s); 8 KB body cap; `nodeId` regex `^[a-zA-Z0-9_-]{1,64}$`. |
| `/api/credits/redeem` | `POST` | MongoDB `updateMany` + Map scan | No rate limit; no body size cap. | Salted IP limiter (20/min); 4 KB body cap; `nodeId` validation. |
| `/api/sim/roots` | `GET` | CPU HKDF/P-384/Ed25519 root derivation | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/sim/[simId]/hello` | `POST` | CPU P-384 + ML-KEM-768 + X25519 + Ed25519 | No rate limit; no body size cap. | Salted IP limiter (120 burst, 4/s); 128 KB body cap; `simNodeSpec` allowlist (`sim-1..3`). |
| `/api/sim/[simId]/keyshare` | `POST` | CPU ML-KEM-768 decaps + X25519 + AES-GCM | No rate limit; no body size cap. | Salted IP limiter (120 burst, 4/s); 128 KB body cap; `simNodeSpec` allowlist. |
| `/api/sim/[simId]/turn` | `POST` | CPU AES-GCM open/seal + context ticket | No rate limit; no body size cap. | Salted IP limiter (120 burst, 4/s); 128 KB body cap; `MAX_CONTEXT_TOKENS` (4096) enforced. |
| `/api/sim/[simId]/close` | `POST` | CPU Ed25519 pop receipt signature | No rate limit; no body size cap. | Salted IP limiter (120 burst, 4/s); 128 KB body cap; `simNodeSpec` allowlist. |
| `/api/transparency` | `GET` | CPU Merkle tree + Ed25519 quorum tickets | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/ashi` | `GET` | CPU FHE Tier C analytical model | No rate limit (`alpha` query param already validated in `(0,1)`). | Salted IP limiter (120 burst, 4/s). |
| `/api/auditor` | `GET` | CPU SPRT mystery-shopper simulation | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/tiers` | `GET` | CPU P-256 TDX quote + Ed25519 SPDM checks | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/weights` | `GET, POST` | CPU ML-KEM-768 + X25519 + AES-GCM weight wrap | No rate limit; no body size cap on POST; unbounded string fields. | Salted IP limiter (60 burst, 2/s); 8 KB body cap; string field length caps (128/256 chars) and quorum bounds. |
| `/api/accountability` | `GET, POST` | CPU P-384/Ed25519 + in-memory store mutation | No rate limit; no body size cap; `recentClaims` and `heartbeatsByNode` grew unboundedly; reflected `nodeId`/`action` in 400 error. | Salted IP limiter (GET 60; POST 30); 8 KB body cap; capped `recentClaims` (50) and `heartbeatsByNode` (64); static error strings. |
| `/api/compartment` | `GET, POST` | CPU prompt splitting & risk curve | No rate limit; no body size cap or prompt length cap on POST. | Salted IP limiter (60 burst, 2/s); 64 KB body cap; 32 KB prompt cap; max 16 `availableNodes`. |
| `/api/sandbox` | `GET` | CPU microVM lifecycle simulation | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/threshold` | `GET, POST` | CPU GF(256) Shamir secret sharing | No rate limit; no body size cap; unbounded `k`/`n` parameters on POST. | Salted IP limiter (60 burst, 2/s); 8 KB body cap; enforced `2 <= k <= n <= 16`. |
| `/api/ohttp` | `GET, POST` | CPU RFC 9458 HPKE X25519 + AES-GCM | No rate limit; no body size cap or hex validation before `hexToBytes`. | Salted IP limiter (60 burst, 2/s); 64 KB body cap; even-length hex validation. |
| `/api/custody` | `GET` | CPU CTR-DRBG + prefix cache demo | No rate limit. | Salted IP limiter (120 burst, 4/s). |
| `/api/atlas` *(other owner)* | `GET, POST` | MongoDB Atlas search / ingest | `POST` crashed with HTTP 500 `TypeError` when body was JSON `null`; no body size cap. | Protected at `src/proxy.ts` (256 KB body cap, `null`/array JSON guard, global IP rate limit). See Requests for Other Owners. |
| `/api/gemini` *(other owner)* | `GET, POST` | Gemini 4 Argon workflow + optional user API key | No rate limit or body size cap in route. | Protected at `src/proxy.ts` (256 KB body cap, `null`/array JSON guard, global IP rate limit). See Requests for Other Owners. |

---

## 3. Verifier Audit: C1 to C7 Claimed vs. Actually Verified

Audited `src/lib/tinfoil/client.ts`, `src/lib/tinfoil/deep-inspect.ts`, `src/app/api/relay/enclave-matrix/route.ts`, `src/lib/sim/checks.ts`, and `@tinfoilsh/verifier` (`node_modules/@tinfoilsh/verifier/dist/**`).

| Check ID | Previous Label | Updated Label (Tinfoil) | What `sim-1..3` (`src/lib/sim/checks.ts`) Actually Verifies | What `tinfoil` (`@tinfoilsh/verifier` + `deep-inspect.ts`) Actually Verifies | Gap / Ground Truth Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C1** | `Hardware signature chain` | `Hardware signature chain` | Verifies P-384 ECDSA signature on the 1,184-byte SNP report (`0x000..0x29F`) under the simulated VCEK public key, verifies the VCEK statement under `roots.amdRoot`, checks report version 3, `chipId` match, `reportedTcb == currentTcb >= minTcb`, and guest policy (`debug=0, migrate=0, smt=0, bit17=1`). | `@tinfoilsh/verifier` (`steps.verifyEnclave`) parses the gzipped 1,184-byte AMD SEV-SNP report from `atc.tinfoil.sh/attestation`, parses the DER VCEK cert, verifies the X.509 signature chain (`ARK-Genoa -> SEV-Genoa ASK -> SEV-VCEK`) using WebCrypto RSASSA-PSS, verifies the ECDSA P-384 / SHA-384 signature over report bytes `0x000..0x29F`, checks VCEK OID extensions (`BL_SPL`, `TEE_SPL`, `SNP_SPL`, `UCODE`, `HWID == report.chipId`), and enforces `debug=false`, `migrateMa=false`, `cxlAllowed=false`, and minimum Genoa TCB (`bl>=7, snp>=14, ucode>=72`). | **Router vs Model Hop**: `@tinfoilsh/verifier` cryptographically verifies the **router enclave** (`router-0.tinfoil.sh`, AMD EPYC Genoa SEV-SNP, where `smt=true` is allowed). It does **not** directly verify the backend model enclave's Intel TDX quote in the browser. Also fixed a bug in `decodeSnpReportBytes` and `enclave-matrix` where Genoa TCB bytes were previously decoded using Turin bit offsets and linked to `/vcek/v1/Milan`. |
| **C2** | `Approved software` | `Approved software` | Compares `report.measurement` (48 bytes) directly against `roots.approvedMeasurement`. | `@tinfoilsh/verifier` (`steps.fetchDigest` + `steps.verifyCode`) loads the embedded Sigstore TUF root (`sigstore-trusted-root.js`), verifies the DSSE v0.3 bundle signature and Rekor transparency log inclusion proof against GitHub OIDC identity (`repo == tinfoilsh/confidential-model-router`, `refs/tags/*`), verifies `subject[0].digest.sha256 == bundle.digest`, and extracts `predicate.snp_measurement`. | Fully verified for the router enclave via `@freedomofpress/sigstore-browser`. |
| **C3** | `Fresh and bound to this session` | `HPKE key bound to enclave report` | Generates a fresh 32-byte `clientNonce` per session and recomputes `REPORT_DATA = SHA-512(clientNonce \|\| nodeIdentityPk \|\| custodyX25519Pk \|\| custodyMlkemPk \|\| manifestHash \|\| modelRoot)`. | `@tinfoilsh/verifier` (`steps.verifyCertificate`) extracts `tlsKeyFp = report.reportData[0..32]` and `hpkePublicKey = report.reportData[32..64]` from the hardware-signed SNP report, parses the enclave X.509 cert SANs (`*.hpke.*` and `*.hatt.*`), verifies the HPKE key and attestation document SHA-256 hash match the SANs, and `ehbp` seals each HTTP request body to `hpkePublicKey` using a fresh ephemeral HPKE sender key. | **Overclaim fixed**: Tinfoil's router attestation report is cached by ATC and does **not** contain a per-session browser nonce in `REPORT_DATA`. Instead, `REPORT_DATA[32..64]` binds the enclave's HPKE public key, and per-request freshness comes from ephemeral HPKE encapsulation (`ehbp-encapsulated-key`). Renamed label to `HPKE key bound to enclave report`. |
| **C4** | `Running code = released code` (Tinfoil) / `Registered chip and manifest` (Sim) | `Running code = released code` | Checks `chipId`, `manifestHash`, `SHA-256(canonicalBytes(manifest))`, `gpuIds`, and `identityPublicKey` against `roots.nodes`. | `@tinfoilsh/verifier` (`steps.compareMeasurements`) compares the 48-byte hex `snp_measurement` from the Sigstore in-toto predicate against `report.measurement` from the SEV-SNP hardware report. | Exact 48-byte SHA-384 launch measurement equality is verified for the router enclave. |
| **C5** | `GPUs in confidential mode` | `Router-attested confidential GPU pool` | Verifies 8 simulated Ed25519 GPU certificates under `roots.nvidiaRoot`, 8 GPU report signatures, `ccMode === true`, and per-GPU fresh nonces `SHA-256(clientNonce \|\| gpuIndex)`. | `verifyModelEnclaveStatus` (`deep-inspect.ts`) checks JSON fields from `inference.tinfoil.sh/.well-known/tinfoil-proxy` (`verifiedHosts > 0`, `verifiedHosts === configuredHosts`, `unverifiedHosts === 0`, `vmShape.gpus >= 1`) and regex-parses the GitHub release YAML (`tinfoil-deployment.json`) for `VLLM_DISABLE_UVA: "1"` and `VLLM_ALLREDUCE_USE_SYMM_MEM: "0"` / `--disable-custom-all-reduce`. | **Overclaim fixed**: The browser does **not** verify NVIDIA SPDM certificates or RIM measurements directly on Tinfoil; it relies transitively on the attested router's `.well-known/tinfoil-proxy` verification table and the GitHub deployment YAML (plus `FALLBACK_MODELS` when offline). Renamed label to `Router-attested confidential GPU pool` and clarified transitive verification in detail text. |
| **C6** | `Registry admission` / `Registry & quorum admission` | `Registry & quorum admission` | `session.ts` checks `registry.source === "arc"`, `node.status === "active"`, `Number(node.stake) >= 0.01`, and checks `/api/transparency` for `>= 5/7` quorum ticket signatures. | Same `registryAndQuorumCheck` in `src/components/session.ts`. Note: `session.ts` checks `ticket.signatures.length >= threshold` without calling `verifyQuorumTicket(ticket)` on the client (the server generates valid Ed25519 signatures in `/api/transparency`). | Documented in Requests for Other Owners (`src/components/session.ts` is owned by UI agent). |
| **C7** | `Committed model` | `Manifest-pinned model & dm-verity root` | Checks `evidence.modelId === modelId` and `evidence.modelRoot === roots.model.modelRoot`. | `verifyModelEnclaveStatus` checks that the model entry from `enclave-matrix` has non-empty `dmVerityRootHash`, `weightMpkHash` (or `containerImageDigest`), and `measurementRegisters.length > 0`. | **Overclaim fixed**: The browser does not cryptographically verify the model enclave's TDX `RTMR` quote against the `dm-verity` root hash itself; it reads the model manifest metadata from `enclave-matrix` and sends `X-Tinfoil-Model` to the attested router. Renamed label to `Manifest-pinned model & dm-verity root`. |

---

## 4. High-Concurrency Stress & Abuse Test Results

Executed via `scripts/stress-test.mjs` against an isolated production build (`next build && next start -p 3200`) in `/private/var/folders/bz/mcd91b7943dgjb_pkmry9wtc0000gn/T/opencode/drouter-stress` with `DROUTER_STUB_UPSTREAM=1` (0 real Tinfoil completions billed; 0 production requests sent).

### Workload Profile
- **Concurrency**: 200 in-flight requests
- **Total Requests**: 472 across all 32 API routes (plus `/v1/models` and `/v1/chat/completions` rewrites)
- **Attack & Fuzz Vectors Included**:
  - 6 rounds of concurrent GET sweeps across all 25 GET endpoints
  - 4 rounds of concurrent POST sweeps across all 19 POST endpoints
  - Malformed JSON (`{malformed_json: true,`), embedded NUL bytes (`\x00`), astral Unicode sequences, JSON `null`, `[]`, and primitive strings across all POST endpoints
  - 2 MB oversized JSON payloads across all POST endpoints
  - Disallowed HTTP methods (`DELETE`, `PUT`) across GET endpoints
  - SSRF & path traversal vectors (`/api/relay/v1/..%2f..%2fadmin`, `/api/relay/v1/%2e%2e/secret`, `x-tinfoil-enclave-url: https://evil.com`, `//evil.com`, `:8443`, `/api/relay/..%2fevil/v1/chat/completions`, `/api/freeze/..%2f..%2fetc%2fpasswd`, `/api/sim/..%2fsim-1/hello`)
  - Single-IP burst flood (30 rapid POSTs to `/api/anchor`) to verify 429 + `Retry-After`

### Measured Results
- **Total Duration**: `10.48 s` (472 requests at 200 concurrency)
- **Latency**:
  - **p50**: `713.12 ms`
  - **p95**: `3,443.38 ms`
  - **p99**: `10,374.40 ms` (dominated by synchronous P-384 / ML-KEM-768 / 5-of-7 Ed25519 crypto in simulated handshakes under 200-way contention)
- **Status Code Histogram**:
  - `200 OK`: **227** (valid GET/POST requests)
  - `400 Bad Request`: **148** (malformed JSON, `null`/`[]` bodies, SSRF/traversal attempts, invalid parameters)
  - `401 Unauthorized`: **12** (rejected invalid/forged tokens on `/api/ohttp` / `/api/credits/spend`)
  - `404 Not Found`: **8** (non-existent `blobId` / `simId` traversal)
  - `405 Method Not Allowed`: **30** (`DELETE` / `PUT` on GET-only routes)
  - `413 Payload Too Large`: **23** (all 2 MB body probes rejected cleanly before memory allocation)
  - `429 Too Many Requests`: **24** (rate-limit bursts blocked with `Retry-After` headers)
  - `500 Internal Server Error`: **0**
- **Stack Trace / Secret Leaks**: **0**
- **Server Memory (RSS)**: `118.6 MB` before stress run -> `306.1 MB` after 472 requests (including 23 x 2 MB payload rejections), no crash or OOM.

---

## 5. Open Issues & Requests for Other Owners

1. **`src/app/api/atlas/route.ts` (Atlas owner)**:
   - In `POST /api/atlas`, `body = (await request.json()) as Record<string, unknown>` does not check `if (!body || typeof body !== "object" || Array.isArray(body))` before reading `body.action`. Sending a literal `null` JSON body throws `TypeError: Cannot read properties of null (reading 'action')` (mitigated globally in `src/proxy.ts`, but should also be guarded inside `src/app/api/atlas/route.ts`).
   - Also cap `limit` in `GET` and `POST /api/atlas` (e.g., `Math.min(50, limit)`) so callers cannot request `limit=1000000`.
2. **`src/app/api/gemini/route.ts` (Gemini owner)**:
   - Add a length cap on `body.taskPrompt` (e.g. `<= 32_768` chars) in `POST /api/gemini` in addition to the 256 KB proxy ceiling.
3. **`src/lib/forensics/bundle.ts` (Forensics owner)**:
   - `npx tsc --noEmit` reports two missing properties (`originVerified`, `popOriginVerified`) on return objects at lines 337 and 448 of `src/lib/forensics/bundle.ts`.
4. **`tests/threshold/threshold.test.ts` (Threshold owner)**:
   - Test `"fails to reconstruct the secret when given fewer than k=3 shares"` calls `combineShares(shares.slice(0, 2), 3)` expecting a wrong string return, whereas `combineShares` in `src/lib/threshold/shamir.ts:232` throws `Error("Insufficient shares to reconstruct secret")`.
5. **`src/components/session.ts` (UI owner)**:
   - In `registryAndQuorumCheck`, consider calling `verifyQuorumTicket(ticket)` from `@/lib/transparency/quorum` on the client rather than only checking `ticket.signatures.length >= threshold`.
