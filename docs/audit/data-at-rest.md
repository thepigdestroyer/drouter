# deRoute Data-at-Rest & MongoDB Atlas Privacy Audit

Audit date: 2026-10-25 (updated for Wave 5 & Wave 6)
Database: `drouter` (MongoDB Atlas 8.0, application role `drouter-app` with `readWrite` on `drouter` only)
Scope: `src/lib/db.ts`, `src/app/api/log/route.ts`, `src/lib/credits/ledger.ts`, `src/lib/freeze/store.ts`, `src/lib/atlas/hybrid-search.ts`, `src/lib/transparency/store.ts`, `src/lib/accountability/store.ts`, `src/lib/auditor/store.ts`, and live inspection of all collections in `drouter`.

---

## 1. Zero-PII & Timestamp Coarsening Policy

deRoute enforces four strict invariants for all data at rest in MongoDB:
1. **No plaintext prompts or completions**: User prompts and model completions are HPKE-encrypted in the browser directly to the verified enclave (`router-0.tinfoil.sh` / model enclave) or sealed with a client-only AES-256-GCM key (`K_freeze` in `frozen_blobs`) before leaving the browser.
2. **No network identifiers or PII**: Raw IP addresses, User-Agent strings, email addresses, and authorization headers are never written to any collection. Rate limiting uses in-memory daily rotating salted SHA-256 hashes (`src/lib/ratelimit/index.ts`), and `/api/log` explicitly rejects any payload containing `prompt`, `completion`, `messages`, `ip`, `userAgent`, `email`, or email/IPv4 string patterns.
3. **UTC hour coarsening**: All public transparency timestamps (`at`, `lastEpochHour`, `coarsenedAt`, `updatedAt`) are rounded down to the UTC hour boundary (`ms - (ms % 3_600_000)`) via `coarsenToHour()` so database records cannot be correlated with individual network requests.
4. **Bounded retention via TTL indexes**: Ephemeral transparency collections automatically expire via MongoDB TTL indexes (`verifications`, `receipts`, and `relay_events` after 30 days; `relay_totals` after 90 days of inactivity).

---

## 2. Live Cluster Inventory & Remediation Summary

Every collection in the `drouter` database was queried and scanned for prompts, completions, IPv4/IPv6 addresses, User-Agent strings, email addresses, and non-coarsened (exact) timestamps:

| Collection | Owner Module | Pre-Audit Docs | Offending Docs Deleted | Post-Audit Docs | Reason for Deletion |
| :--- | :--- | ---: | ---: | ---: | :--- |
| `relay_totals` | `src/lib/db.ts` | 1 | 0 | 1 | Clean (`lastEpochHour` aligned to UTC hour; aggregate counters only). |
| `verifications` | `src/lib/db.ts` | 4 | 4 | 0 | Contained legacy exact millisecond timestamps in `at` (`mod 3600000 != 0`) from pre-coarsening test runs. No PII or prompts. |
| `receipts` | `src/lib/db.ts` | 0 | 0 | 0 | Empty collection. |
| `relay_events` | `src/lib/db.ts` (legacy) | 1 | 1 | 0 | Legacy per-request relay event containing an exact timestamp in `at`. Replaced by `relay_totals` `$inc` counter. |
| `credit_nullifiers` | `src/lib/credits/ledger.ts` | 1 | 1 | 0 | Contained an exact millisecond timestamp in `spentAt` (`Date.now()`). No PII or prompts. |
| `frozen_blobs` | `src/lib/freeze/store.ts` | 1 | 1 | 0 | Contained exact Unix second timestamps in `createdAt` / `expiresAt`. Payload was AES-256-GCM ciphertext (`ciphertextHex`). |
| `agent_verification_receipts` | `src/lib/atlas/hybrid-search.ts` | 2 | 0 | 2 | Clean (`coarsenedAt` aligned to UTC hour `T...:00:00.000Z`; Ed25519-signed attestation summaries only). |
| `enclave_intelligence` | `src/lib/atlas/hybrid-search.ts` | 16 | 0 | 16 | Clean (`updatedAt` aligned to UTC hour; static hardware/enclave reference documentation and 768-dim embeddings). |
| `transparency_log` & `verifier_submissions` | `src/lib/transparency/store.ts` | 0 (restarted 2026-10-25) | 0 | Live | Append-only RFC 6962 Merkle leaves and verifier public-key fingerprints (`epochHourSec` coarsened to UTC hour; see [docs/transparency-log-restart.md](../transparency-log-restart.md)). |
| `monitor_runs` & `auditor_runs` | `src/lib/accountability/store.ts`, `src/lib/auditor/store.ts` | 0 | 0 | Live | Hourly 6-enclave continuous monitoring runs and daily SPRT mystery-shopper runs (`epochHourSec` / `at` coarsened to UTC hour). |
| `credit_invoices` & `credit_payments` | `src/lib/credits/ledger.ts` | 0 | 0 | Live | One-time deposit address derivation indices (`CREDITS_DEPOSIT_XPUB`), `claimHash`, coarse `expiresAt`, and sender-stripped `{ txHash, amount }` records. |

Total offending documents deleted across all collections: **7** (`verifications`: 4, `relay_events`: 1, `credit_nullifiers`: 1, `frozen_blobs`: 1). Zero documents contained plaintext prompts, completions, raw IPs, User-Agents, or emails.

---

## 3. Collection Schemas, Purpose, Fields & Retention

### 3.1 `verifications`
- **Purpose**: Public transparency log of client-side hardware attestation checks (C1 through C7).
- **Writer / Reader**: `logVerification()` and `recentActivity()` in `src/lib/db.ts` via `POST /api/log` and `GET /api/log`.
- **Fields**:
  - `nodeId` (`string`, max 80 chars): On-chain or simulated node identifier.
  - `nodeName` (`string`, max 80 chars): Human-readable node label.
  - `kind` (`"tinfoil" | "sim"`): Enclave hardware class.
  - `ok` (`boolean`): Overall verification verdict.
  - `checks` (`Array<{ id: string; status: "pass" | "fail" | "skip" }>`, max 12 items): Per-check status codes without raw user data.
  - `measurement` (`string`, max 300 chars): Hex measurement digest / enclave fingerprint.
  - `evidenceHash` (`string`, hex): SHA-256 commitment over the verification evidence bundle.
  - `releaseDigest` (`string`, optional): Signed software release tag or SHA-256 digest.
  - `enclaveHost` (`string`, optional): Attested enclave hostname (for example `router-0.tinfoil.sh`).
  - `at` (`Date`): Timestamp coarsened to the start of the UTC hour (`coarsenToHour`).
- **Retention**: **30 days** via TTL index `at_ttl_30d` on `{ at: 1 }` (`expireAfterSeconds: 2592000`).

### 3.2 `receipts`
- **Purpose**: Public transparency log of session key destruction (`PopReceipt`) commitments and optional Circle Arc testnet anchor transactions.
- **Writer / Reader**: `logReceipt()` and `recentActivity()` in `src/lib/db.ts` via `POST /api/log` and `GET /api/log`.
- **Fields**:
  - `nodeId` (`string`, max 80 chars): Node identifier.
  - `receiptHash` (`string`, hex): SHA-256 hash of the signed session pop receipt.
  - `signatureVerified` (`boolean`): Whether the Ed25519 pop signature passed verification.
  - `anchorTx` (`string | null`, hex): Optional Circle Arc testnet transaction hash (`chainId 5042002`).
  - `at` (`Date`): Timestamp coarsened to the start of the UTC hour (`coarsenToHour`).
- **Retention**: **30 days** via TTL index `at_ttl_30d` on `{ at: 1 }` (`expireAfterSeconds: 2592000`).

### 3.3 `relay_totals`
- **Purpose**: Single-document global aggregate counter of encrypted bytes relayed through the oblivious relay (`_id: "global"`). Eliminates per-request rows and per-turn timing correlation.
- **Writer / Reader**: `logRelay()` and `recentActivity()` in `src/lib/db.ts`.
- **Fields**:
  - `_id` (`"global"`): Fixed singleton document key.
  - `requests` (`number`): Cumulative count of encrypted relay requests (`$inc`).
  - `bytesUp` (`number`): Cumulative padded encrypted request bytes (`$inc`).
  - `bytesDown` (`number`): Cumulative encrypted response bytes (`$inc`).
  - `lastEpochHour` (`Date`): UTC hour bucket of the most recent update (`coarsenToHour`).
- **Retention**: **90 days of inactivity** via TTL index `lastEpochHour_ttl_90d` on `{ lastEpochHour: 1 }` (`expireAfterSeconds: 7776000`).

### 3.4 `relay_events` (Deprecated Legacy Collection)
- **Purpose**: Legacy collection previously used for relay byte accounting before migration to `relay_totals`. No longer written to by any code path; read only in `recentActivity()` as a backward-compatible aggregate sum.
- **Fields**: `enclaveHost` (`string`), `bytesUp` (`number`), `bytesDown` (`number`), `status` (`number`), `at` (`Date`).
- **Retention**: **30 days** via TTL index `at_ttl_30d` on `{ at: 1 }` (`expireAfterSeconds: 2592000`). Currently 0 documents.

### 3.5 `credit_nullifiers`
- **Purpose**: Double-spend prevention ledger for unlinkable RSA blind-signed credit tokens.
- **Owner**: `src/lib/credits/ledger.ts` (Agent 5).
- **Fields**:
  - `nullifier` (`string`, hex): SHA-256 nullifier derived from the unblinded random token secret. Unlinkable to the minting request.
  - `denomination` (`number`): Credit denomination (`1`, `5`, or `20`).
  - `nodeId` (`string`): Target node identifier.
  - `spentAt` (`number`): Spend timestamp (see section 4 for coarsening recommendation to owner).
  - `redeemed` (`boolean`): Whether the operator batch-redeemed the credit.
- **Retention**: Persistent across the credit epoch; owner should add a TTL index or coarsen `spentAt` to the UTC hour.

### 3.6 `frozen_blobs`
- **Purpose**: Encrypted session state bubbles for client-controlled freeze and resume across enclaves.
- **Owner**: `src/lib/freeze/store.ts` (Agent 14).
- **Fields**:
  - `blobId` (`string`, hex): Random 16-byte identifier.
  - `sessionIdHex` (`string`, hex): Session commitment hash.
  - `nonceHex` (`string`, 24 hex chars): 12-byte AES-256-GCM IV.
  - `aadHex` (`string`, hex): Authenticated additional data.
  - `ciphertextHex` (`string`, hex, max 128 KB binary): AES-256-GCM ciphertext sealed in the browser under `K_freeze`. The server never receives `freezeSecretHex` or plaintext `messages`.
  - `byteLength` (`number`): Ciphertext byte length.
  - `modelId` (`string`): Model identifier for session restoration.
  - `createdAt` (`number`): Creation timestamp (coarsened to UTC hour recommended).
  - `expiresAt` (`number`): Expiration timestamp (default 7 days after creation).
- **Retention**: **7 days** (`DEFAULT_TTL_SECONDS = 604800` enforced in `src/lib/freeze/store.ts`).

### 3.7 `agent_verification_receipts`
- **Purpose**: Ed25519-signed verification receipts emitted by the Gemini 4 Argon / local deterministic attestation orchestrator.
- **Owner**: `src/lib/atlas/hybrid-search.ts` (Agent 18).
- **Fields**: `receiptId`, `coarsenedAt` (ISO string rounded to UTC hour `YYYY-MM-DDTHH:00:00.000Z`), `mode`, `primaryModel`, `enclaveModel`, `routerHost`, `enclaveHost`, `overallPassed`, `faultInjected`, `selfHealed`, `humanGateState`, `checksSummary`, `forensicProofDigestHex`, `ed25519SignatureHex`, `signerPublicKeyHex`, `summary`, `embedding` (512-dim float array), `embeddingModel`, `embeddingDimensions`.
- **Retention**: Indexed on `receiptId` and `coarsenedAt`. Stores only cryptographic attestation metadata.

### 3.8 `enclave_intelligence`
- **Purpose**: Curated knowledge base of hardware attestation specifications (AMD SEV-SNP, Intel TDX, NVIDIA H100/B200 CC, Sigstore Rekor, EHBP/HPKE) queried via MongoDB 8.0 native `$vectorSearch`, `$search`, and `$rankFusion`.
- **Owner**: `src/lib/atlas/hybrid-search.ts` (Agent 18).
- **Fields**: `docId`, `title`, `category`, `summary`, `tags`, `metadata`, `updatedAt` (coarsened ISO hour), `embedding` (768-dim float array), `embeddingModel`, `embeddingDimensions`.
- **Retention**: Static reference corpus (16 documents) seeded idempotently via `scripts/atlas-indexes.mjs` and served as a whole corpus via `GET /api/knowledge/corpus`.
