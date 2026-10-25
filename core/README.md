# deroute-core

`deroute-core` is the small, stateless Node 22 ESM service that runs inside an attested confidential enclave container for **deRoute** (Google Cloud Confidential Space or Tinfoil).

By moving whole-library knowledge retrieval, content-free Gemini control-plane planning, egress receipt signing, and transparency log tree-head signing into a measured enclave container, every user's browser can cryptographically verify the service rather than trusting the operator.

## Endpoints

With `CORE_KEY_SOURCE=boot` (Google Cloud Confidential Space), `deroute-core` serves HTTPS on `0.0.0.0:8443` using an ephemeral in-memory ECDSA P-256 self-signed X.509 certificate (`CN=deroute-core`, 30-day validity) generated at boot by `core/src/tls.js`. With `CORE_KEY_SOURCE=tinfoil`, it serves HTTP on `0.0.0.0:8080` behind the Tinfoil enclave proxy shim:

| Method & Path | Exposure | Purpose |
| --- | --- | --- |
| `GET /attestation` | Public (`core-proxy`) | Requests a Google Cloud Confidential Space PKI token over `/run/container_launcher/teeserver.sock` bound to `[keysDigest, tlsSpkiSha256]` and returns `{ token, keys: { egress, tree }, keysDigest, tlsSpkiSha256, tlsCertPem, refreshedAtSec, expiresAtSec }`. Returns HTTP `503` if the token is missing, expired, or unavailable. |
| `GET /health` | Public (`core-proxy` / `shim`) | Readiness probe returning service version, `keySource`, and key source status (`attested-mount` or `ephemeral-boot`). Exposes no secrets. |
| `GET /keys` | Public (`core-proxy` / `shim`) | Returns the raw 32-byte hex (`publicKeyHex`) and 44-byte RFC 8410 SPKI DER hex (`spkiHex`) public keys for `egress-signing` and `tree-signing`, plus `keysDigest` / `publicKeysSha256` (`sha256(canonicalJson({ egress, tree }))`) and `tlsSpkiSha256` (when `CORE_KEY_SOURCE=boot`). |
| `GET /knowledge/corpus` | Public (`core-proxy` / `shim`) | Returns the entire public knowledge base from MongoDB `drouter.enclave_intelligence` (`docId`, `title`, `category`, `summary`, `tags`, `sourceUrl`, `retrievedAt`, 768-dim `embedding`) sorted deterministically with `contentSha256`. Rejects all query parameters (`HTTP 400`). |
| `POST /agent/plan` | Public (`core-proxy` / `shim`) | Validates a content-free `TaskDescriptor`, enforces `assertContentFree` on the descriptor and outbound Gemini payload (`store: false`), signs a canonical egress receipt with `egress-signing`, calls `@google/genai` (`client.interactions.create`), and validates every returned tool call against the strict allowlist and argument schema. If `GEMINI_API_KEY` is absent, returns `503` with `planner: "unavailable"` and the signed egress receipt (never fakes output). |
| `POST /transparency/sign-tree-head` | Operator-only (excluded from public proxy allowlist) | Requires a constant-time Bearer token matching `CORE_OPERATOR_TOKEN` (fails closed when unset), recomputes the RFC 6962 Merkle root from `drouter.transparency_log` in MongoDB to verify `(treeSize, rootHash)`, and signs the canonical `drouter/transparency/sth/v1` payload with `tree-signing`. |

## Key sources (`CORE_KEY_SOURCE`) and boot TLS (`core/src/tls.js`)

`deroute-core` requires `CORE_KEY_SOURCE` to be explicitly set at startup and refuses to start if missing or unknown:

- `CORE_KEY_SOURCE=boot` (Google Cloud Confidential Space):
  - Generates both Ed25519 key pairs (`egress-signing` and `tree-signing`) in memory at boot (`core/src/keys.js`).
  - Generates an ECDSA P-256 key pair and 30-day self-signed X.509 certificate (`CN=deroute-core`) in memory at boot (`core/src/tls.js`) using `@peculiar/x509@2.2.0` and `reflect-metadata@0.2.2`. Private keys are never written to disk.
  - Calls `configureAttestation({ keyRing, tlsCertPem })` at boot (`core/src/attestation-gcp.js`), binding both `keysDigest` and `tlsSpkiSha256` into the Google-signed PKI attestation token nonces (`eat_nonce`).
- `CORE_KEY_SOURCE=tinfoil`:
  - Loads the attested Ed25519 keys from `/run/tinfoil/keys/<id>/private_key.pem` and `public_key.pem`, verifying the RFC 8410 PKCS#8 header and SPKI public key match.

## Secrets loader (`CORE_SECRETS_SOURCE`, `core/src/secrets-gcp.js`)

`deroute-core` loads `MONGODB_URI`, `GEMINI_API_KEY`, and `CORE_OPERATOR_TOKEN` before serving and refuses to start on any unknown `CORE_SECRETS_SOURCE`:

- `CORE_SECRETS_SOURCE=gcp-secret-manager`: Fetches a service-account access token (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`) and project ID (`.../computeMetadata/v1/project/project-id`) with `Metadata-Flavor: Google`, then reads `MONGODB_URI`, `GEMINI_API_KEY`, and `CORE_OPERATOR_TOKEN` from `https://secretmanager.googleapis.com/v1/projects/<p>/secrets/<name>/versions/latest:access`. Holds secret values in memory only (non-enumerable, redacted from `util.inspect`), never logs them, never falls back to `process.env`, and fails closed if any secret is missing.
- `CORE_SECRETS_SOURCE=env` (default for Tinfoil): Reads `MONGODB_URI`, `GEMINI_API_KEY`, and `CORE_OPERATOR_TOKEN` from environment variables.

## Confidential Space launch policy and non-root socket access (`core/Dockerfile`)

`core/Dockerfile` sets the Google Cloud Confidential Space launch-policy labels:

- `tee.launch_policy.allow_env_override="CORE_KEY_SOURCE,CORE_PUBLIC_ORIGIN,CORE_SECRETS_SOURCE"`
- `tee.launch_policy.log_redirect="never"`
- `tee.launch_policy.monitoring_memory_allow="never"`
- `EXPOSE 8443` and `USER 1000:1000`

In Google Cloud Confidential Space (`github.com/google/go-tpm-tools/launcher`), the launcher creates `/tmp/container_launcher` with mode `0755`, bind-mounts it into the workload at `/run/container_launcher`, and explicitly calls `os.Chmod("/tmp/container_launcher/teeserver.sock", 0777)` (`srwxrwxrwx`) in `listenUnixSocket()`. As a result, the non-root container user (`USER 1000:1000`) can connect to `/run/container_launcher/teeserver.sock` without root privileges.

## What the enclave can and cannot see

### What `deroute-core` can see
- **Public corpus documents** stored in `drouter.enclave_intelligence` (16 curated confidential-compute provider profiles, hardware advisories, and cryptographic specifications).
- **Content-free `TaskDescriptor` objects** submitted to `POST /agent/plan`:
  - `taskKind` enum (`summarize`, `analyze`, `draft`, `review`, `question`)
  - Opaque `inputHandle` literal (`"$INPUT"`)
  - `inputTokenEstimate` rounded up to a power-of-two bucket (`1, 2, 4, ..., 1048576`)
  - `redactionCounts` per category capped at `5` (`0..5`)
  - Boolean `verification` flags
  - `allowedTools` enum list in canonical order
- **Verified Merkle tree heads** (`treeSize`, `rootHash`, coarse `timestampSec`) cross-checked against `drouter.transparency_log`.
- **Enclave secrets** (`MONGODB_URI`, `GEMINI_API_KEY`, `CORE_OPERATOR_TOKEN`) and Ed25519/ECDSA keys (`egress-signing`, `tree-signing`, boot TLS key).

### What `deroute-core` cannot see
- **No user prompts, completions, or search queries**:
  - `GET /knowledge/corpus` rejects query parameters and returns the identical whole corpus to every caller so neither `deroute-core` nor MongoDB Atlas learns which topic or document a user cares about (information-theoretic retrieval privacy).
  - `POST /agent/plan` rejects any extra fields, free-text strings, unbucketed token counts, uncapped redaction counts, or smuggled hex/JSON/number/array payloads via `validateTaskDescriptor` and `assertContentFree`.
- **No persistent logs or caller IP records**:
  - The container enforces `tee.launch_policy.log_redirect=never` and `tee.launch_policy.monitoring_memory_allow=never`, never logs request bodies or headers, and never receives or stores caller IP addresses (stripped by the Vercel `core-proxy`).

## Local development and testing

Run the unit and HTTP/HTTPS integration test suite:

```bash
cd core
npm test
```
