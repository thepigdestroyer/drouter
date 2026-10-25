## Split-Knowledge Agent Lifecycle (`05-agent-lifecycle`)

The autonomous agent workflow in `src/lib/agent-client/index.ts` separates control-plane planning from confidential data execution so Google Gemini never sees user text or redacted text. The browser runs on-device mechanical redaction followed by an attested second pass through the `pii-filter` enclave, sends only a content-free `TaskDescriptor` to `POST /api/gemini/plan`, executes the returned plan steps in the browser (fetching the whole public corpus and sending the redacted task over HPKE to the model enclave), restores names on the device, and verifies the signed egress receipt with its Merkle inclusion proof.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#f3f1ec","primaryTextColor":"#151515","primaryBorderColor":"#151515","lineColor":"#595752","secondaryColor":"#ffffff","tertiaryColor":"#f3f1ec","fontFamily":"Georgia, serif"}}}%%
sequenceDiagram
  autonumber
  actor User as User
  participant Browser as Browser (src/lib/agent-client/index.ts)
  participant Relay as Vercel Relay & Routes (/api/relay/*, /api/knowledge/corpus)
  participant PiiEnclave as Tinfoil pii-filter Enclave (D4)
  participant PlanRoute as Planner Route (POST /api/gemini/plan)
  participant Gemini as Google Gemini Control Plane (gemini-4-argon)
  participant ModelEnclave as Tinfoil Model Enclave (gemma4-31b / kimi-k3)

  User->>Browser: Submits private task + Always-Hide terms
  Browser->>Browser: Stage 1 Pass 1: On-device mechanicalRedact (D3)
  Browser->>Relay: HPKE-encrypted mechanically scrubbed text (useRelay: true)
  Relay->>PiiEnclave: Forward HPKE ciphertext + Bearer TINFOIL_API_KEY
  PiiEnclave-->>Relay: Attested second-pass spans ([ATTESTED_PII_n])
  Relay-->>Browser: Return attestedPiiFilter result (verified: true)
  Browser->>Browser: Apply createSymmetryTransform() + 4096 B bucket padding<br/>Build content-free TaskDescriptor (~56 bits) & run local egress gate

  Browser->>PlanRoute: POST /api/gemini/plan (canonicalJson(taskDescriptor) only)
  Note over PlanRoute: Closed-Schema Egress Gate:<br/>buildGeminiCreateRequestFromDescriptor(),<br/>assertGoogleBoundMessage("createRequest"),<br/>and assertContentFree() (~67 bits max capacity)
  PlanRoute->>Gemini: client.interactions.create(createRequest) over opaque handles ($INPUT)
  Gemini-->>PlanRoute: Function-call steps (scrub, verify_two_hop, search_kb, invoke_enclave, anchor_arc)
  Note over PlanRoute: Validate each tool call (assertValidToolCall, assertClosedPlanSchema),<br/>append event to Merkle transparency log (appendVerificationEventToLog),<br/>and sign GeminiEgressReceipt with auditPath inclusion proof
  PlanRoute-->>Browser: ClosedAgentPlan + GeminiEgressReceipt (with transparencyLog inclusion proof)

  Browser->>Browser: Verify egressReceipt signature, sha256, canonicalRequest & inclusion proof
  Browser->>Relay: Execute plan verification & knowledge steps:<br/>GET /api/relay/enclave-matrix, GET /api/registry, GET /api/knowledge/corpus
  Relay-->>Browser: Live 2-hop attestation matrix, Arc registry nodes & whole 16-doc public corpus
  Browser->>Browser: Verify 7 checks (automatic failover gemma4-31b <-> kimi-k3 if needed)<br/>& rank whole public corpus locally in browser memory (BM25)

  Browser->>Relay: openTinfoilSession(): Send redacted task encrypted with RFC 9180 HPKE
  Relay->>ModelEnclave: Forward HPKE ciphertext to attested model enclave
  ModelEnclave-->>Relay: Stream HPKE-encrypted completion over placeholders
  Relay-->>Browser: Stream encrypted response frames
  Browser->>Browser: Decrypt response, restore names & shifted values on device (restoreAll),<br/>verify T^-1(f(T(x))) = f(x), and sign Ed25519 forensic digest
  Browser-->>User: Restored answer + verified EgressReceipt & Merkle inclusion proof
```

- **Two-Pass Redaction and Symmetry Masking (`runBrowserRedactionPipeline`)**: Stage 1 runs `mechanicalRedact` (D3) on the device first, sends the mechanically scrubbed text over HPKE through `/api/relay` to Tinfoil's attested `pii-filter` enclave (`attestedPiiFilter`, D4) for a second pass (`[ATTESTED_PII_n]`), applies reversible date/numeric/entity symmetry masking (`createSymmetryTransform`), and aligns the payload to a `4096`-byte power-of-two bucket.
- **Content-Free `TaskDescriptor` and Closed-Schema Egress Gate (`requestAgentPlanFromBrowser`, `src/app/api/gemini/plan/route.ts`)**: The browser distills the task into a content-free `TaskDescriptor` (`taskKind`, power-of-two `inputTokenEstimate`, bucketed `redactionCounts`, `verification` booleans, and `allowedTools`), verifies it locally with `assertOutboundPrivacyInvariant`, `assertGoogleBoundMessage("taskDescriptor")`, and `assertContentFree`, and posts only that descriptor to `POST /api/gemini/plan`, which re-verifies the closed schema before calling `gemini-4-argon` (`client.interactions.create`).
- **In-Browser Step Execution and Whole-Corpus Ranking (`runBrowserAgentWorkflow`)**: After validating the returned `ClosedAgentPlan` (`assertClosedPlanSchema`), the browser executes the verification and knowledge steps locally by fetching `/api/relay/enclave-matrix`, `/api/registry`, and the entire 16-document public knowledge corpus (`GET /api/knowledge/corpus` with zero query parameters, ranked in browser memory via `fetchWholeCorpusAndRankInBrowser`).
- **Direct Browser-to-Enclave HPKE Execution and Homomorphic Restoration (`openTinfoilSession`, `restoreAll`)**: The browser evaluates the target model enclave (`gemma4-31b` or `kimi-k3`, with automatic failover if hardware checks fail), sends the redacted prompt directly to the attested Tinfoil enclave over RFC 9180 HPKE, and runs `restoreAll()` and `verifyRedactionAndSymmetryRestore()` on the device to confirm $T^{-1}(f(T(x))) = f(x)$.
- **Signed Egress Receipt with Merkle Inclusion Proof (`verifyEgressReceiptClient`, `appendVerificationEventToLog`)**: `POST /api/gemini/plan` records the request SHA-256 in the append-only Merkle transparency log and returns a `GeminiEgressReceipt` containing the exact `canonicalRequest`, `sha256`, signer public key, and `transparencyLog` inclusion proof (`leafIndex`, `leafHash`, `treeSize`, `rootHash`, `auditPath`, `treeHeadSignature`), which the browser cryptographically verifies alongside its own Ed25519-signed Stage 6 forensic proof digest.
