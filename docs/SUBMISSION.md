# Hackathon Submission: dRouter (Google DeepMind Gemini 4 Argon & MongoDB Atlas Tracks)

## 1. Models and Agents Used Statement

### Google DeepMind Build with Gemini 4 Argon Track

- **Primary Orchestrator Model**: `gemini-4-argon` via the official `@google/genai` (v2.31.0) Interactions API (`new GoogleGenAI({ apiKey }).interactions.create(...)`).
  - Configured with `generation_config: { thinking_level: "low" | "medium" | "high", max_output_tokens: 131072 }` and `background: true`.
  - Legacy sampling and caching parameters (`thinking_budget`, `temperature`, `top_p`, `top_k`, `cached_content`) are rejected by `validateArgonRequestConfig` in `src/lib/gemini/interactions.ts`.
  - Executes a multi-turn function-calling loop over 6 confidential tools (`scrub_and_symmetry_mask`, `verify_two_hop_enclave_and_quorum`, `search_atlas_hybrid_kb`, `run_antigravity_vmpl0_and_memory_audit`, `invoke_attested_enclave`, `anchor_arc_settlement_with_human_gate`).
- **Companion Subagent Models**:
  - `gemini-3.8-flash`: Invoked in parallel via `client.interactions.create` in Stage 2 to summarize MongoDB Atlas Hybrid Search (`$rankFusion`) and Tinfoil 2-hop hardware attestation results.
  - `gemini-3.5-flash-lite`: Invoked in parallel via `client.interactions.create` in Stage 2 to summarize the 5-of-7 Ed25519 hardware verifier quorum check.
- **Attested Confidential Enclave Models (Tinfoil)**:
  - `gemma4-31b` (`gemma4-31b-inf10-0.tinfoil.containers.tinfoil.dev`, mapped from `gemma-4-31b-it`) and `kimi-k3` (`kimi-k3-inf14.tinfoil.containers.tinfoil.dev`, Intel TDX + 8x NVIDIA Confidential Computing GPUs, `max-model-len` 262,144 tokens), routed via `router-0.tinfoil.sh` (AMD SEV-SNP) over RFC 9180 HPKE Encrypted HTTP Body (EHBP).
- **Models Listed in Toolkit Manifest as Not Used in This Demo**:
  - `antigravity-preview-09-2026`, `deep-research-preview-04-2026`, `gemma-4-e4b`, `gemini-3.8-live`, and `gemini-3.8-flash-tts` are explicitly marked `statusInDemo: "not-used"` because Stage 1 PII scrubbing, Stage 3 1,344-state VMPL0 formal verification, and Stage 6 Ed25519 forensic signing run in deterministic local TypeScript.
- **Truthful Reporting (`mode` and `modelCalls`)**:
  - Every `/api/gemini` response includes `mode: "live" | "simulated"` and `modelCalls: Array<{ model, purpose, ok, latencyMs, inputTokens, outputTokens, error }>`. Only models that were actually called over the network appear in `modelCalls`.

### MongoDB Atlas Track

- **Cluster**: MongoDB Atlas M0 cluster `drouter` (MongoDB 8.0.34 Enterprise), database `drouter`.
- **Atlas Search (`$search`)**: Index `drouter_text_search` (`READY`) on `drouter.enclave_intelligence`.
- **Atlas Vector Search (`$vectorSearch`)**: Index `drouter_vector_index` (`READY`, 128 dimensions, `cosine` similarity) on `drouter.enclave_intelligence`.
- **Native Hybrid Search (`$rankFusion`)**: Combines `$vectorSearch` and `$search` sub-pipelines using MongoDB 8.0's native `$rankFusion` stage with `scoreDetails: true`.
- **Embeddings**: Uses live Voyage AI (`VOYAGE_API_KEY`) when configured, or deterministic 128-d unit vectors reported honestly in `engines.embedding` as `"local-hashed-128 (stand-in)"`.
- **Agent Verification Receipts (`agent_verification_receipts`)**: Stores per-run Ed25519-signed agent verification receipts with UTC-hour coarsened timestamps and zero prompts or PII, searchable alongside `enclave_intelligence`.
- **Multi-Collection `$facet` Aggregation**: Aggregates telemetry across `enclave_intelligence`, `agent_verification_receipts`, `verifications`, `receipts`, `relay_totals`, `credit_nullifiers`, and `frozen_blobs`.

---

## 2. Three-Minute Live Demo Script

*Preparation before going on stage:*
1. Have the app open at `https://drouter-demo.vercel.app/argon` (or `http://localhost:3000/argon`) and a terminal ready in `/Users/mj/Documents/Opencode/drouter-demo`.
2. Ensure `DEMO_PERSONA` has been updated to name a real, consenting user if pitching live.

### 0:00 - 0:30 | Problem & Privacy Boundary (Stage 1)
- **On screen**: Show the `/argon` page header and the unredacted research task prompt containing an API credential (`sk-test-4f9a2c7e1b8d6a3f5e0c`), email (`dana.reyes@example.org`), cohort date (`2026-08-14`), grant budget (`£125,000.00`), and trial code (`RTH-ONC-207`).
- **Say**: "Researchers analyzing sensitive clinical trial pipelines cannot send raw patient cohort IDs or credentials to cloud LLMs. In Stage 1, dRouter scrubs secrets and PII locally into placeholders, applies a homomorphic symmetry transform to dates, currency figures, and institution names, and pads the JSON payload to a 4,096-byte RFC 8259 bucket. Our code enforces a hard privacy invariant: before any call to Google's Interactions API, we assert zero original sensitive tokens exist in the outbound payload."

### 0:30 - 1:15 | Live MongoDB Atlas `$rankFusion` Hybrid Search & Tinfoil 2-Hop Attestation (Stage 2)
- **Action**: Run in terminal:
  ```bash
  curl -s "http://localhost:3000/api/atlas?q=Kimi+K3+8x+GPU+confidential+enclave" | jq '{engines, topHit: .results[0].docId, rrfScore: .results[0].rrfScore, matchingReceiptsCount: (.matchingReceipts | length)}'
  ```
- **Say**: "In Stage 2, the agent queries MongoDB Atlas on our live 8.0.34 cluster. Look at the `engines` field: `vectorSearch: atlas`, `textSearch: atlas`, and `fusion: $rankFusion`. Atlas runs native `$rankFusion` combining `$vectorSearch` on `drouter_vector_index` and `$search` on `drouter_text_search`, and also searches past agent verification receipts in `agent_verification_receipts`. Simultaneously, dRouter verifies Tinfoil's 2-hop attestation: `router-0.tinfoil.sh` on AMD SEV-SNP and `kimi-k3-inf14.tinfoil.containers.tinfoil.dev` on Intel TDX with NVIDIA Confidential Computing GPUs."

### 1:15 - 2:00 | Real Fault Injection, 1,344-State VMPL0 Check & Self-Healing (Stage 3)
- **On screen**: Point to Stage 3 on `/argon` with **FAULT INJECTED** enabled.
- **Say**: "Judges asked for a real verification loop with concrete pass/fail signals. When we inject a fault on `simulated-compromised-node`, we tamper the real verifier inputs: we corrupt the enclave dm-verity measurement and confidential GPU flags passed to `verifyModelEnclaveStatus`, and we inject a plaintext egress rule into `verifyMonitorPolicyExhaustive`, which checks all 1,344 VMPL0 states. Attempt 1 fails with `I1_NoPlaintextEgress`, `C5_ConfidentialGpuFlagsTampered`, and `C7_DmVerityMeasurementTampered`. The orchestrator catches the failure, quarantines the faulty node, fails over to the attested Tinfoil enclave host, and passes all 1,344 states and the V1/V6 DDR5 memory-bus entropy audit on Attempt 2."

### 2:00 - 2:35 | Gemini 4 Argon Interactions API, Enclave Inference & Local Restoration (Stage 4)
- **Action**: Run in terminal:
  ```bash
  curl -s -X POST http://localhost:3000/api/gemini \
    -H "Content-Type: application/json" \
    -d '{"thinkingLevel":"high","injectFaultToTestSelfHealing":true,"humanApprovedExternalAction":false,"preferredEnclaveModel":"gemma4-31b"}' \
    | jq '{mode, modelCalls, humanGateState, maskedOutput: .autonomousRun.stages.stage4.enclaveCompletionMasked, restoredOutput: .autonomousRun.stages.stage4.restoredClientOutput}'
  ```
- **Say**: "Stage 4 validates the Gemini 4 Argon contract (`thinking_level: high`, `background: true`, rejecting `temperature` and `thinking_budget`), dispatches the masked prompt over RFC 9180 HPKE to Tinfoil's live `gemma4-31b` enclave, and records the real network call in `modelCalls`. Notice that the enclave only ever sees `ASSAY-774` and `Northvale Institute`, and dRouter restores `RTH-ONC-207` and `Riverside Teaching Hospital` locally on the client."

### 2:35 - 3:00 | Human-in-the-Loop Control Gate & CLI Verification (Stages 5 & 6)
- **On screen**: Click **Approve Circle Arc Tx** on `/argon` (or show `humanGateState: "paused_awaiting_human"` transitioning to `"executed_with_human_approval"`), and run:
  ```bash
  node scripts/drouter-cli.mjs verify --upstream http://localhost:3000
  ```
- **Say**: "Finally, in Stage 5, any action affecting money or external state on Circle Arc Testnet (`0xbc8085c2b6fe6e0db05f169925c0b841828f4481`) is held in `blocked_pending_human` until the human operator explicitly approves it. Stage 6 signs the canonical verification digest with Ed25519 and stores a coarsened, prompt-free receipt in MongoDB Atlas."
