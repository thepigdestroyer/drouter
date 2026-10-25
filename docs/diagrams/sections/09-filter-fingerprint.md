## On-Device Filter Fingerprint & Circle Arc Verification (`09-filter-fingerprint`)

All regular expressions, Unicode homoglyph tables, entropy thresholds, and allowlists for the on-device personal-detail filter live in a single serializable object (`MECHANICAL_RULESET`) whose canonical SHA-256 fingerprint is anchored on Circle Arc. Before sending any prompt, the browser recomputes that SHA-256 fingerprint locally, compares it against `published-fingerprint.json` and the Circle Arc transaction receipt log, and blocks sending if the running filter does not match.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#f3f1ec","primaryTextColor":"#151515","primaryBorderColor":"#151515","lineColor":"#595752","secondaryColor":"#ffffff","tertiaryColor":"#f3f1ec","fontFamily":"Georgia, serif"}}}%%
flowchart TD
  subgraph Ruleset["Serializable Redaction Ruleset (mechanical-ruleset.ts)"]
    Rules["MECHANICAL_RULESET (v1.0.1)<br/>placeholderPatterns, unicodeNormalization,<br/>entropyRules, patterns, thresholds, wordLists"]
    Canonical["canonicalJson(MECHANICAL_RULESET)<br/>Deterministic sorted-key JSON serialization"]
    FpHash["rulesetFingerprint()<br/>0x + sha256(utf8(canonicalJson))<br/>0x0928121dfa0558ab...bba20f28"]
    Rules --> Canonical --> FpHash
  end

  subgraph Publish["Anchor & Publish (scripts/publish-filter-fingerprint.mjs --confirm)"]
    ReceiptHash["computeFilterAnchorReceiptHash()<br/>keccak256('deroute-filter:' + version + ':' + fingerprint)"]
    ArcAnchor["anchorReceipt(anchorReceiptHash)<br/>Circle Arc Testnet (chainId 5042002)<br/>anchorTx: 0x09055dc1b5d6a79d...db1fe730"]
    PubJson["src/lib/privacy/published-fingerprint.json<br/>{ version, fingerprint, anchorTx, chainId, anchoredAt }"]
    ReceiptHash --> ArcAnchor --> PubJson
  end

  FpHash --> ReceiptHash

  subgraph BrowserVerify["Browser Verification (src/lib/privacy/fingerprint.ts)"]
    EvalLocal["evaluateLocalFilterFingerprint()<br/>Recomputes rulesetFingerprint(MECHANICAL_RULESET)<br/>and compares version & fingerprint against published-fingerprint.json"]
    CheckReceipt["checkArcTransactionReceipt(anchorTx)<br/>JSON-RPC eth_getTransactionReceipt on Arc RPC<br/>Verifies receipt.status === '0x1' & log topics contain anchorReceiptHash"]
    AllowSend["state: 'match', arcReceiptVerified: true<br/>blockingSend: false (Prompt Scrubbing & Send Permitted)"]
    BlockSend["state: 'mismatch', blockingSend: true<br/>Sending Blocked in Browser Before Any Network Call"]
  end

  FpHash --> EvalLocal
  PubJson --> EvalLocal
  EvalLocal -->|computed !== publishedFp or version mismatch| BlockSend
  EvalLocal -->|Local Fingerprint Matches| CheckReceipt
  ArcAnchor -.->|Receipt Logs| CheckReceipt
  CheckReceipt -->|status 0x1 & topic matched| AllowSend

  style BlockSend stroke:#d9531e,stroke-width:2.5px,fill:#ffffff,color:#151515
```

- **Canonical Ruleset Serialization (`MECHANICAL_RULESET`)**: `src/lib/privacy/mechanical-ruleset.ts` defines every pattern source, flag, Unicode normalization range, homoglyph map, entropy threshold, and word list in a pure data structure (`version: "1.0.1"`), which `rulesetFingerprint()` (`src/lib/privacy/fingerprint.ts`) hashes as `0x` + `sha256(utf8(canonicalJson(ruleset)))` (`0x0928121dfa0558ab8e59af0298aa76c5b9a3674012d2ff162b66df79bba20f28`).
- **Circle Arc Receipt Anchoring (`publish-filter-fingerprint.mjs`)**: Running `node scripts/publish-filter-fingerprint.mjs --confirm` computes `computeFilterAnchorReceiptHash(version, fingerprint) = keccak256("deroute-filter:" + version + ":" + fingerprint)`, anchors it on Circle Arc (`chainId: 5042002`) via `anchorReceipt()`, waits for receipt confirmation, and writes `{ version, fingerprint, anchorTx, chainId, anchoredAt }` to `src/lib/privacy/published-fingerprint.json` (`anchorTx: 0x09055dc1b5d6a79de9d96824ee76213b2c238a8bfd744ab143405d30db1fe730`).
- **Local Recomputation & Comparison (`evaluateLocalFilterFingerprint`)**: On page load and before sending, the browser recomputes `rulesetFingerprint(MECHANICAL_RULESET)` over the in-memory filter rules and compares both `version` and `computedFingerprint` against `published-fingerprint.json`.
- **Direct On-Chain Receipt Log Verification (`checkArcTransactionReceipt`)**: When the local hash matches, `verifyFilterFingerprint()` issues a read-only `eth_getTransactionReceipt` JSON-RPC call to `ARC_PUBLIC_RPC_URL` (`https://rpc.testnet.arc.network`) and verifies that `receipt.status === "0x1"` and that `receipt.logs` contains a topic matching `computeFilterAnchorReceiptHash(version, computed)`.
- **Fail-Closed Send Blocking (`blockingSend: true`)**: If the browser's computed fingerprint or version diverges from `published-fingerprint.json`, `evaluateLocalFilterFingerprint()` returns `state: "mismatch"` and `blockingSend: true`, preventing any prompt from being sent.
