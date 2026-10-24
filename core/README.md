# deroute-core

`deroute-core` is the small, stateless Node 22 ESM service that runs inside an attested confidential enclave container for **deRoute**.

By moving whole-library knowledge retrieval, content-free Gemini control-plane planning, egress receipt signing, and transparency log tree-head signing into a measured enclave container, every user's browser can cryptographically verify the service rather than trusting the operator.

## Endpoints

`deroute-core` listens on `0.0.0.0:8080`. Public traffic through the Tinfoil `shim` is restricted to `/health`, `/keys`, `/knowledge/corpus`, and `/agent/plan`:

| Method & Path | Exposure | Purpose |
| --- | --- | --- |
| `GET /health` | Public (`shim`) | Readiness probe returning service version, `keySource`, and key source status (`attested-mount` or `ephemeral-boot`). Exposes no secrets. |
| `GET /keys` | Public (`shim`) | Returns the raw 32-byte hex (`publicKeyHex`) and 44-byte RFC 8410 SPKI DER hex (`spkiHex`) public keys for `egress-signing` and `tree-signing`, plus `publicKeysSha256` (`sha256(canonicalJson({ egress, tree }))`). |
| `GET /knowledge/corpus` | Public (`shim`) | Returns the entire public knowledge base from MongoDB `drouter.enclave_intelligence` (`docId`, `title`, `category`, `summary`, `tags`, `sourceUrl`, `retrievedAt`, 768-dim `embedding`) sorted deterministically with `contentSha256`. Rejects all query parameters (`HTTP 400`). |
| `POST /agent/plan` | Public (`shim`) | Validates a content-free `TaskDescriptor`, enforces `assertContentFree` on the descriptor and outbound Gemini payload (`store: false`), signs a canonical egress receipt with `egress-signing`, calls `@google/genai` (`client.interactions.create`), and validates every returned tool call against the strict allowlist and argument schema. If `GEMINI_API_KEY` is absent, returns `503` with `planner: "unavailable"` and the signed egress receipt (never fakes output). |
| `POST /transparency/sign-tree-head` | Operator-only (excluded from public `shim.paths`) | Requires a constant-time Bearer token matching `CORE_OPERATOR_TOKEN` (fails closed when unset), recomputes the RFC 6962 Merkle root from `drouter.transparency_log` in MongoDB to verify `(treeSize, rootHash)`, and signs the canonical `drouter/transparency/sth/v1` payload with `tree-signing`. |

## Key sources (`CORE_KEY_SOURCE`)

`deroute-core` requires `CORE_KEY_SOURCE` to be explicitly set at startup and refuses to start if missing or unknown:

- `CORE_KEY_SOURCE=tinfoil`: Loads the attested Ed25519 keys from `/run/tinfoil/keys/<id>/private_key.pem` and `public_key.pem`, verifying the RFC 8410 PKCS#8 header and SPKI public key match.
- `CORE_KEY_SOURCE=boot`: Generates both Ed25519 key pairs in memory at boot (never written to disk) and exposes `publicKeysSha256` (`sha256(canonicalJson({ egress, tree }))`) on `GET /keys` so a platform attestation (Google Confidential Space token nonce or Intel TDX `report_data`) can bind them.

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
- **Enclave secrets** (`MONGODB_URI`, `GEMINI_API_KEY`, `CORE_OPERATOR_TOKEN`) and Ed25519 keys (`egress-signing`, `tree-signing`).

### What `deroute-core` cannot see
- **No user prompts, completions, or search queries**:
  - `GET /knowledge/corpus` rejects query parameters and returns the identical whole corpus to every caller so neither `deroute-core` nor MongoDB Atlas learns which topic or document a user cares about (information-theoretic retrieval privacy).
  - `POST /agent/plan` rejects any extra fields, free-text strings, unbucketed token counts, uncapped redaction counts, or smuggled hex/JSON/number/array payloads via `validateTaskDescriptor` and `assertContentFree`.
- **No persistent logs or caller IP records**:
  - The container runs with a read-only root filesystem (`read_only: true`), never logs request bodies or headers, and never stores caller IP addresses.

## Local development and testing

Run the unit and HTTP integration test suite:

```bash
cd core
npm test
```
