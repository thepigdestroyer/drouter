## Split-Knowledge Agent Lifecycle (`05-agent-lifecycle`)

The autonomous agent workflow in `src/lib/agent-client/index.ts` separates control-plane planning from confidential data execution so Google Gemini never sees user text or redacted text. The browser runs on-device mechanical redaction followed by an attested second pass through the `pii-filter` enclave, sends only a content-free `TaskDescriptor` to `POST /api/gemini/plan`, executes the returned plan steps in the browser (fetching the whole public corpus and sending the redacted task over HPKE to the model enclave), restores names on the device, and verifies the signed egress receipt with its Merkle inclusion proof.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"Georgia, serif","fontSize":"16px","actorBkg":"#151515","actorTextColor":"#f3f1ec","actorBorder":"#151515","actorLineColor":"#8a8780","signalColor":"#151515","signalTextColor":"#151515","noteBkgColor":"#ffffff","noteBorderColor":"#d9531e","noteTextColor":"#151515","sequenceNumberColor":"#ffffff","labelBoxBkgColor":"#151515","labelTextColor":"#f3f1ec"},"themeCSS":".messageLine0,.messageLine1{stroke-width:2.4px;} .messageText{font-weight:600;} marker path{fill:#151515;stroke:#151515;}","sequence":{"mirrorActors":false,"wrap":true,"width":210,"actorMargin":120,"messageMargin":34,"boxMargin":14,"noteMargin":12}}}%%
sequenceDiagram
  autonumber
  participant U as You
  participant B as Your browser
  participant S as deRoute server and relay
  participant P as Personal-detail filter (Tinfoil)
  participant G as Gemini 4 Argon
  participant M as Sealed computer (Tinfoil)

  rect rgb(243, 241, 236)
    Note over U,P: STEP 1 · Prepare the task on your device
    U->>B: Type a task (plus your always-hide words)
    Note right of B: First filter: hide names, numbers and secrets
    B->>S: Filtered text, encrypted to the filter's sealed computer
    S->>P: Forward the ciphertext only
    P-->>B: Extra details to hide (through the relay)
    Note right of B: Build a task description with none of your words
  end

  rect rgb(255, 255, 255)
    Note over B,G: STEP 2 · Gemini plans without your words
    B->>S: Task description only
    Note right of S: Closed-schema gate: exact shape, about 67 bits at most
    S->>G: Content-free planning request
    G-->>S: Plan of tool steps
    Note right of S: Check the plan's shape, log a receipt
    S-->>B: Plan plus receipt and log proof
    Note right of B: Check the receipt and its proof
  end

  rect rgb(243, 241, 236)
    Note over B,M: STEP 3 · Do the work inside a sealed computer
    B->>S: Fetch hardware proofs, registry and the public library
    Note right of B: Run checks C1 to C7, search the library locally
    B->>S: Filtered task, encrypted to the sealed computer
    S->>M: Forward the ciphertext only
    M-->>B: Encrypted answer (through the relay)
  end

  rect rgb(255, 255, 255)
    Note over U,S: STEP 4 · Back on your device
    Note right of B: Decrypt, put hidden details back, check the restore
    B->>U: Answer, plus what Google received and the receipt
  end
```

- **Two-Pass Redaction and Symmetry Masking (`runBrowserRedactionPipeline`)**: Stage 1 runs `mechanicalRedact` (D3) on the device first, sends the mechanically scrubbed text over HPKE through `/api/relay` to Tinfoil's attested `pii-filter` enclave (`attestedPiiFilter`, D4) for a second pass (`[ATTESTED_PII_n]`), applies reversible date/numeric/entity symmetry masking (`createSymmetryTransform`), and aligns the payload to a `4096`-byte power-of-two bucket.
- **Content-Free `TaskDescriptor` and Closed-Schema Egress Gate (`requestAgentPlanFromBrowser`, `src/app/api/gemini/plan/route.ts`)**: The browser distills the task into a content-free `TaskDescriptor` (`taskKind`, power-of-two `inputTokenEstimate`, bucketed `redactionCounts`, `verification` booleans, and `allowedTools`), verifies it locally with `assertOutboundPrivacyInvariant`, `assertGoogleBoundMessage("taskDescriptor")`, and `assertContentFree`, and posts only that descriptor to `POST /api/gemini/plan`, which re-verifies the closed schema before calling `gemini-4-argon` (`client.interactions.create`).
- **In-Browser Step Execution and Whole-Corpus Ranking (`runBrowserAgentWorkflow`)**: After validating the returned `ClosedAgentPlan` (`assertClosedPlanSchema`), the browser executes the verification and knowledge steps locally by fetching `/api/relay/enclave-matrix`, `/api/registry`, and the entire 16-document public knowledge corpus (`GET /api/knowledge/corpus` with zero query parameters, ranked in browser memory via `fetchWholeCorpusAndRankInBrowser`).
- **Direct Browser-to-Enclave HPKE Execution and Homomorphic Restoration (`openTinfoilSession`, `restoreAll`)**: The browser evaluates the target model enclave (`gemma4-31b` or `kimi-k3`, with automatic failover if hardware checks fail), sends the redacted prompt directly to the attested Tinfoil enclave over RFC 9180 HPKE, and runs `restoreAll()` and `verifyRedactionAndSymmetryRestore()` on the device to confirm $T^{-1}(f(T(x))) = f(x)$.
- **Signed Egress Receipt with Merkle Inclusion Proof (`verifyEgressReceiptClient`, `appendVerificationEventToLog`)**: `POST /api/gemini/plan` records the request SHA-256 in the append-only Merkle transparency log and returns a `GeminiEgressReceipt` containing the exact `canonicalRequest`, `sha256`, signer public key, and `transparencyLog` inclusion proof (`leafIndex`, `leafHash`, `treeSize`, `rootHash`, `auditPath`, `treeHeadSignature`), which the browser cryptographically verifies alongside its own Ed25519-signed Stage 6 forensic proof digest.
