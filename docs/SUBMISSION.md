# Hackathon Submission: deRoute (Google DeepMind Gemini 4 Argon & MongoDB Atlas Tracks)

- **Live Deployment**: https://drouter-demo.vercel.app
- **Agent & Atlas Page**: https://drouter-demo.vercel.app/argon
- **Audit & Transparency Page**: https://drouter-demo.vercel.app/audit
- **Short Description (<= 150 words)**: [docs/HACKATHON_DESCRIPTION.md](HACKATHON_DESCRIPTION.md)

---

## 1. Plain Summary of What Is Built and Deployed

**deRoute** lets a non-technical user (modeled in code by `DEMO_PERSONA`: `"Example: a fictional hospital data scientist"` reviewing Phase II clinical trial survival code and case notes) use frontier AI models without exposing personal details or secrets to Google, MongoDB, the enclave host, or deRoute:

1. **Two-pass personal-detail filtering before anything leaves the enclave boundary**:
   - **Pass 1 (on-device deterministic filter)**: `mechanicalRedact` (`src/lib/privacy/mechanical.ts`) strips secrets, emails, phones, addresses, dates, 4+ digit sequences, multi-word names, high-entropy strings, and custom `"Always hide"` terms in the browser using the serialisable ruleset `MECHANICAL_RULESET` (`version: "1.0.1"`). Its SHA-256 fingerprint (`0x0928121dfa0558ab8e59af0298aa76c5b9a3674012d2ff162b66df79bba20f28`) is anchored on Circle Arc Testnet in transaction `0x09055dc1b5d6a79de9d96824ee76213b2c238a8bfd744ab143405d30db1fe730`, verified by the browser on every load (`FilterFingerprintBadge`).
   - **Pass 2 (attested Tinfoil enclave filter)**: `attestedPiiFilter` (`src/lib/privacy/attested-filter.ts`) sends the mechanically redacted text over RFC 9180 HPKE through `/api/relay/v1/` to Tinfoil's live `pii-filter` enclave (`https://pii-filter.tinfoil.sh`, repo `tinfoilsh/confidential-pii-cpu`) to catch any remaining unstructured personal details, falling back cleanly to Pass 1 if unreachable.
   - **Reversible symmetry masking**: `createSymmetryTransform` (`src/lib/symmetry/homomorphism.ts`) shifts dates, scales currency amounts, and replaces institution/study names with reversible aliases in the browser, then pads the payload to 4,096-byte power-of-two JSON buckets.
2. **Split-knowledge Gemini 4 Argon control plane (`POST /api/gemini/plan`)**:
   - The browser never sends task text to our server or to Google. It builds a content-free `TaskDescriptor` (`taskKind`, `"$INPUT"`, power-of-two `inputTokenEstimate`, coarse `0..2` `redactionCounts`, boolean `verification` flags, and `allowedTools`), verifies it locally with `assertGoogleBoundMessage("taskDescriptor")` and `assertContentFree`, and posts only that descriptor to `POST /api/gemini/plan`.
   - Every Google-bound message is locked behind the closed-schema egress gate (`src/lib/gemini/egress-schemas.ts`) with a stated mathematical capacity bound of **56.35 bits** (7.04 bytes) for a `TaskDescriptor` and **66.89 bits** (8.36 bytes) for a `createRequest`.
   - Each plan response carries a verifiable `GeminiEgressReceipt` over the exact canonical JSON bytes sent to Google, either signed by the hardware-attested `egress-signing` Ed25519 key when `deroute-core` on Google Cloud Confidential Space is deployed, or appended to the RFC 6962 transparency log and signed by the operator tree-head key (`"Recorded by our server"`).
   - The browser executes the validated plan: it checks live enclave attestation (`/api/relay/enclave-matrix` and `/api/registry`), downloads and ranks the whole public knowledge corpus locally (`/api/knowledge/corpus`), sends the redacted and symmetry-masked prompt directly to the attested Tinfoil enclave (`gemma4-31b` or `kimi-k3`) over RFC 9180 HPKE via `openTinfoilSession()`, and restores original names and numbers on the device.
3. **Whole-library knowledge retrieval and MongoDB Atlas 8.0 native `$rankFusion`**:
   - During confidential agent runs, the browser fetches `GET /api/knowledge/corpus` (which returns all 16 curated documents from `drouter.enclave_intelligence` in deterministic order with `contentSha256` and rejects any query parameters with HTTP 400) and ranks them locally with BM25 (`rankLocally`), so MongoDB Atlas learns nothing about what the user is looking up.
   - For the public reference search explorer (`src/components/atlas-explorer.tsx`), users can either toggle `"Search on my device only"` (zero network calls) or run a live MongoDB 8.0 hybrid search (`POST /api/atlas`) where queries are redacted in the browser with `mechanicalRedact` and on the server with `redactForAtlasBoundary` (`mechanicalRedact` + `attestedPiiFilter`) before executing native `$rankFusion` combining `$vectorSearch` (`drouter_vector_index`, 768-dimensional embeddings from Tinfoil's attested `nomic-embed-text` enclave) and `$search` (`drouter_text_search`).
4. **Unlinkable payments, passkey accounts, and continuous verification**:
   - **Payments**: One-time deposit addresses derived per invoice from `CREDITS_DEPOSIT_XPUB` (`m/44'/60'/0'/0`) on Circle Arc Testnet (`chainId 5042002`) with fixed USDC denominations (`0.0001`, `0.0005`, `0.002` USDC) and 2,048-bit Chaumian RSA blind-signed credits (`CREDITS_ISSUER_RSA_PQ`). Sender wallet addresses are stripped at log ingestion and never stored.
   - **Accounts**: Client-side WebAuthn PRF passkeys (`src/lib/auth/passkey.ts`) with a 6-word BIP39 passphrase fallback (`src/lib/auth/vault.ts`, 210,000 PBKDF2-HMAC-SHA-512 rounds + HKDF-SHA-384 + AES-256-GCM), zero emails or server account records.
   - **Verification**: Hourly GitHub Actions monitoring (`.github/workflows/monitor.yml` -> `GET /api/cron/monitor`) of all 6 real Tinfoil enclaves (`tinfoil-router`, `kimi-k3`, `glm-5-3`, `deepseek-v4-1-flash`, `gpt-oss-120b`, `llama3-3-70b`) with an Arc-anchored RFC 6962 transparency log, plus independent CLI verification via `node scripts/drouter-cli.mjs verify --submit`.

---

## 2. Models and External Services Used Statement

### Google DeepMind Build with Gemini 4 Argon Track

| Model / Component | Status in Code | How It Is Used |
| :--- | :--- | :--- |
| `gemini-4-argon` | Live when `GEMINI_API_KEY` (or `deroute-core`) is configured; honest HTTP `503 planner: "unavailable"` (`plan: null`) when absent | Invoked via the official `@google/genai` (v2.31.0) Interactions API (`client.interactions.create`) in `POST /api/gemini/plan` and `core/src/planner.js` with `generation_config: { thinking_level: "low" \| "medium" \| "high", max_output_tokens: 131072 }`, `background: true`, and `store: false`. Legacy parameters (`thinking_budget`, `temperature`, `top_p`, `top_k`, `cached_content`) are rejected by `validateArgonRequestConfig`. Plans over 5 content-free tools (`scrub_and_symmetry_mask`, `verify_two_hop_enclave_and_quorum`, `search_atlas_hybrid_kb`, `invoke_attested_enclave`, `anchor_arc_settlement_with_human_gate`) using only opaque handles (`$INPUT`, `$RESULT_1..16`). |
| `gemma4-31b` / `kimi-k3` | Live attested Tinfoil enclaves | Invoked directly from the browser via `openTinfoilSession()` over RFC 9180 HPKE Encrypted HTTP Body (`ehbp`) through `/api/relay/v1/` on `gemma4-31b-inf10-0.tinfoil.containers.tinfoil.dev` or `kimi-k3-inf14.tinfoil.containers.tinfoil.dev` (Intel TDX + 8x NVIDIA Confidential Computing GPUs, `max-model-len` 262,144 tokens for `kimi-k3`) behind `router-0.tinfoil.sh` (AMD EPYC Genoa SEV-SNP). |
| `pii-filter` | Live attested Tinfoil enclave | Invoked in Stage 1 via `attestedPiiFilter()` (`https://pii-filter.tinfoil.sh`, repo `tinfoilsh/confidential-pii-cpu`) over RFC 9180 HPKE through `/api/relay/v1/` after on-device `mechanicalRedact`. |
| `nomic-embed-text` | Live attested Tinfoil enclave | Used by `src/lib/atlas/embeddings.ts` and `scripts/atlas-indexes.mjs` to compute 768-dimensional embeddings inside an attested Tinfoil enclave for MongoDB Atlas Vector Search (`drouter_vector_index`). |
| Companion models in `ARGON_TOOLKIT_MANIFEST` (`gemini-3.8-flash`, `gemini-3.5-flash-lite`, `antigravity-preview-09-2026`, `deep-research-preview-04-2026`, `gemma-4-e4b`, `gemini-3.8-live`, `gemini-3.8-flash-tts`) | Explicitly marked `statusInDemo: "not-used"` | Not invoked so zero search queries, document titles, or attestation strings ever reach non-enclave models; Stage 1 redaction, Stage 2/3 attestation and whole-corpus BM25 ranking, Stage 5 human-in-the-loop gating, and Stage 6 Ed25519 forensic signing run deterministically in TypeScript. |

### MongoDB Atlas Track

- **Cluster**: MongoDB Atlas M0 cluster `drouter` (MongoDB 8.0.34 Enterprise), database `drouter`, scoped user `drouter-app` (`readWrite@drouter`).
- **Whole-Library Retrieval (`GET /api/knowledge/corpus`)**: Serves all 16 documents from `drouter.enclave_intelligence` in deterministic order with `contentSha256` and public caching headers, rejecting any query parameters (`HTTP 400`) so private agent runs leak zero lookup metadata to MongoDB.
- **Atlas Search (`$search`)**: Index `drouter_text_search` (`READY`) on `drouter.enclave_intelligence`.
- **Atlas Vector Search (`$vectorSearch`)**: Index `drouter_vector_index` (`READY`, 768 dimensions, `cosine` similarity) on `drouter.enclave_intelligence`.
- **Native Hybrid Search (`$rankFusion`)**: Combines `$vectorSearch` and `$search` pipelines using MongoDB 8.0's native `$rankFusion` stage (`scoreDetails: true`) after browser `mechanicalRedact` and server `redactForAtlasBoundary`.
- **Zero-PII Coarsened Collections**: `enclave_intelligence`, `agent_verification_receipts`, `transparency_log`, `verifier_submissions`, `monitor_runs`, `auditor_runs`, `credit_invoices`, `credit_payments`, `credit_nullifiers`, `frozen_blobs`, `verifications`, `receipts`, and `relay_totals` store zero prompts, completions, raw IPs, or payer wallet addresses, and coarsen all timestamps to the UTC hour (`YYYY-MM-DDTHH:00:00.000Z`).

---

## 3. Three-Minute Live Demo Script

*Preparation:* Open `https://drouter-demo.vercel.app/argon` (or `http://localhost:3000/argon`) in the browser and have a terminal open in `/Users/mj/Documents/Opencode/drouter-demo`. All examples use the built-in fictional hospital data scientist persona (`DEMO_PERSONA`).

### 0:00 - 0:45 | On-Device Filter Fingerprint, Dual-Pass Redaction & Split-Knowledge Descriptor
- **On screen**: Point to the personal-detail filter badge on `/argon` (`Personal-detail filter v1.0.1: matches the published version`) and open `TechDetails` to show the Circle Arc Testnet transaction link (`0x09055dc1b5d6a79de9d96824ee76213b2c238a8bfd744ab143405d30db1fe730`) and the sample clinical study task (`ONC-2041`, `COHORT-2026-08-14`, `£125,000.00`, `dana.reyes@example.org`, `sk-test-4f9a2c7e1b8d6a3f5e0c`).
- **Say**: "In deRoute, your private task never goes to our server or to Google. First, your browser checks that its deterministic personal-detail filter matches the SHA-256 fingerprint published on Circle Arc Testnet. Second, your browser strips personal details and keys locally, runs a second pass inside Tinfoil's attested `pii-filter` enclave over HPKE, and applies reversible symmetry masks to dates, budgets, and study names. Only a content-free `TaskDescriptor` capped at 56.35 bits ever leaves your browser for `POST /api/gemini/plan`."

### 0:45 - 1:30 | Closed-Schema Gemini 4 Argon Planner & Signed Egress Receipt
- **Action**: Click **Run private check** on `/argon` (or inspect the Stage 4 `TechDetails` panel showing the canonical bytes sent to Google and the egress receipt), and run in the terminal:
  ```bash
  curl -s http://localhost:3000/api/gemini | jq '{primaryModel, dataSentToGoogle, taskDescriptor}'
  ```
- **Say**: "Gemini 4 Argon plans the workflow via `@google/genai` `client.interactions.create` (`thinking_level`, `background: true`, `store: false`), operating only on opaque handles like `$INPUT`. Our closed-schema egress gate (`assertGoogleBoundMessage` and `assertContentFree`) rejects any free text, extra keys, or unbucketed numbers. Inside `TechDetails`, you can inspect the exact canonical JSON bytes Google received and the signed egress receipt anchored in our RFC 6962 transparency log."

### 1:30 - 2:15 | Whole-Library Corpus vs. MongoDB Atlas 8.0 Native `$rankFusion`
- **Action**: Scroll to the **Public reference library** section on `/argon`, show the `"Search on my device only"` toggle, and run in the terminal:
  ```bash
  curl -s http://localhost:3000/api/knowledge/corpus | jq '{documentCount, contentSha256, firstDoc: .documents[0].title}'
  curl -s "http://localhost:3000/api/atlas?q=Kimi+K3+8x+GPU+confidential+enclave" | jq '{engines, filterRan, topHit: .results[0].docId, rrfScore: .results[0].rrfScore}'
  ```
- **Say**: "For confidential runs, the browser downloads the entire 16-document reference corpus from `/api/knowledge/corpus` with zero query parameters, verifies `contentSha256`, and ranks locally with BM25 so MongoDB learns nothing about what a user looks up. For public exploration, `/api/atlas` runs `mechanicalRedact` in the browser and `attestedPiiFilter` on the server before executing native MongoDB 8.0 `$rankFusion` combining 768-dimensional `$vectorSearch` (`drouter_vector_index`) and `$search` (`drouter_text_search`)."

### 2:15 - 3:00 | End-to-End HPKE Enclave Execution, Local Restoration & Independent CLI Verification
- **Action**: Show the restored output on `/argon` alongside the masked enclave completion, then run in the terminal:
  ```bash
  node scripts/drouter-cli.mjs verify --submit --upstream https://drouter-demo.vercel.app
  ```
- **Say**: "The browser sends the masked prompt directly to Tinfoil's attested enclave over RFC 9180 HPKE and restores `ONC-2041`, `£125,000.00`, and `dana.reyes@example.org` on the device. Any external write to Circle Arc Testnet is held behind a human approval gate. Finally, anyone can verify all 6 live Tinfoil enclaves from their terminal with `drouter-cli.mjs verify --submit`, which signs checks C1 through C7 with a local Ed25519 key and returns a verified RFC 6962 Merkle inclusion proof."
