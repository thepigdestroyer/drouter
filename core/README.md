# deroute-core

`deroute-core` is the small, stateless Node 22 ESM service that runs inside a [Tinfoil Container](https://docs.tinfoil.sh/containers/overview) (an attested Intel TDX / AMD SEV-SNP Confidential VM) for **deRoute**.

By moving whole-library knowledge retrieval, content-free Gemini control-plane planning, egress receipt signing, and transparency log tree-head signing into a measured enclave container, every user's browser can cryptographically verify the service rather than trusting the operator.

## Endpoints

`deroute-core` listens on `0.0.0.0:8080` and exposes only the five paths listed in the Tinfoil `shim`:

| Method & Path | Purpose |
| --- | --- |
| `GET /health` | Readiness probe returning service version and whether `egress-signing` and `tree-signing` keys were loaded from `/run/tinfoil/keys` (`attested-mount`). Exposes no secrets. |
| `GET /keys` | Returns the raw 32-byte hex (`publicKeyHex`) and 44-byte RFC 8410 SPKI DER hex (`spkiHex`) public keys for `egress-signing` and `tree-signing`. |
| `GET /knowledge/corpus` | Returns the entire public knowledge base from MongoDB `drouter.enclave_intelligence` (`docId`, `title`, `category`, `summary`, `tags`, `sourceUrl`, `retrievedAt`, 768-dim `embedding`) sorted deterministically with `contentSha256`. Rejects all query parameters (`HTTP 400`). |
| `POST /agent/plan` | Validates a content-free `TaskDescriptor`, enforces `assertContentFree` on the descriptor and outbound Gemini payload, signs a canonical egress receipt with `egress-signing`, calls `@google/genai` (`client.interactions.create`), and validates every returned tool call against the strict allowlist and argument schema. If `GEMINI_API_KEY` is absent, returns `503` with `planner: "unavailable"` and the signed egress receipt (never fakes output). |
| `POST /transparency/sign-tree-head` | Validates a Merkle tree head (`treeSize`, 64-hex `rootHash`, UTC-hour `timestampSec`) and signs the canonical `drouter/transparency/sth/v1` payload with `tree-signing`. |

## What the enclave can and cannot see

### What `deroute-core` can see
- **Public corpus documents** stored in `drouter.enclave_intelligence` (16 curated confidential-compute provider profiles, hardware advisories, and cryptographic specifications).
- **Content-free `TaskDescriptor` objects** submitted to `POST /agent/plan`:
  - `taskKind` enum (`summarize`, `analyze`, `draft`, `review`, `question`)
  - Opaque `inputHandle` literal (`"$INPUT"`)
  - `inputTokenEstimate` rounded up to a power-of-two bucket (`1, 2, 4, ..., 1048576`)
  - `redactionCounts` per category capped at `5` (`0..5`)
  - Boolean `verification` flags
  - `allowedTools` enum list
- **Merkle tree heads** (`treeSize`, `rootHash`, coarse `timestampSec`) submitted to `POST /transparency/sign-tree-head`.
- **Enclave secrets** (`MONGODB_URI`, `GEMINI_API_KEY`, `TINFOIL_API_KEY`) injected by the Tinfoil CVM runtime and attested Ed25519 keys (`egress-signing`, `tree-signing`) mounted at `/run/tinfoil/keys/<id>/`.

### What `deroute-core` cannot see
- **No user prompts, completions, or search queries**:
  - `GET /knowledge/corpus` rejects query parameters and returns the identical whole corpus to every caller so neither `deroute-core` nor MongoDB Atlas learns which topic or document a user cares about (information-theoretic retrieval privacy).
  - `POST /agent/plan` rejects any extra fields, free-text strings, unbucketed token counts, uncapped redaction counts, or smuggled hex strings via `validateTaskDescriptor` and `assertContentFree`.
- **No persistent logs or caller IP records**:
  - The container runs with a read-only root filesystem (`read_only: true`), never logs request bodies or headers, and never stores caller IP addresses.

## How a browser verifies `deroute-core`

1. **Hardware & release attestation via `SecureClient`**:
   The browser connects with `new SecureClient({ enclaveURL, configRepo: "thepigdestroyer/deroute-core-config" })` from the `tinfoil` npm package. Before any HTTP request is sent, `SecureClient` verifies the hardware attestation quote (AMD SEV-SNP / Intel TDX) and checks the Sigstore Rekor transparency log to confirm the enclave's measurement matches the signed release of `tinfoil-config.yml` and pinned `ghcr.io/thepigdestroyer/deroute-core@sha256:...` image digest.
2. **Attested key verification**:
   The enclave's attestation document includes `crypto_material` entries (`format: "https://tinfoil.sh/key/spki/v1"`) for `egress-signing` and `tree-signing`. The browser matches those SPKI hex keys against `GET /keys`.
3. **Egress receipt verification**:
   Every response from `POST /agent/plan` returns `egressReceipt: { canonicalRequest, sha256, epochHourSec, kind: "gemini-egress", signature, publicKey, spkiPublicKey }`. The browser recomputes `sha256(canonicalRequest)`, verifies that `JSON.parse(canonicalRequest)` contains only content-free handles/enums/booleans/numbers, and verifies the Ed25519 `signature` under the attested `egress-signing` `publicKey`, showing the user the exact bytes sent to Google.

## Local development and testing

Run the unit and HTTP integration test suite (6 test suites covering descriptor validation, `assertContentFree`, attested PEM key loading, egress receipt signing/verification, tree-head signing, whole-library corpus shape, and HTTP/CORS/size-limit rules):

```bash
cd core
npm test
```
