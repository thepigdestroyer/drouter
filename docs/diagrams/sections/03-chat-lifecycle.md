## Confidential Chat Lifecycle (`03-chat-lifecycle`)

When a user sends a chat message, the browser first verifies that its local personal-detail filter matches the published ruleset anchored on Circle Arc Testnet and scrubs sensitive terms on the device. It then verifies all seven enclave checks (`C1` through `C7`), pads and HPKE-encrypts the scrubbed prompt to the enclave's attested public key, attaches an unlinkable blind-signed credit token for the relay, and restores the hidden details locally after decrypting the enclave's reply.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"Georgia, serif","fontSize":"16px","actorBkg":"#151515","actorTextColor":"#f3f1ec","actorBorder":"#151515","actorLineColor":"#8a8780","signalColor":"#151515","signalTextColor":"#151515","noteBkgColor":"#ffffff","noteBorderColor":"#d9531e","noteTextColor":"#151515","sequenceNumberColor":"#ffffff","labelBoxBkgColor":"#151515","labelTextColor":"#f3f1ec"},"themeCSS":".messageLine0,.messageLine1{stroke-width:2.4px;} .messageText{font-weight:600;} marker path{fill:#151515;stroke:#151515;}","sequence":{"mirrorActors":false,"wrap":true,"width":210,"actorMargin":120,"messageMargin":34,"boxMargin":14,"noteMargin":12}}}%%
sequenceDiagram
  autonumber
  participant U as You
  participant B as Your browser
  participant A as Circle Arc
  participant R as deRoute relay
  participant E as Sealed computer (Tinfoil)

  rect rgb(243, 241, 236)
    Note over U,A: STEP 1 · On your device
    U->>B: Type a message
    B->>A: Is my filter the published one?
    A-->>B: Yes: fingerprint receipt matches
    Note right of B: Hide names, numbers and secrets
  end

  rect rgb(255, 255, 255)
    Note over B,E: STEP 2 · Check the sealed computer before sending
    B->>R: Ask for the hardware proof
    R->>E: Forward the request
    E-->>B: Signed hardware report (through the relay)
    Note right of B: Run checks C1 to C7 (any failure blocks sending)
  end

  rect rgb(243, 241, 236)
    Note over B,E: STEP 3 · Send it sealed
    Note right of B: Pad to a fixed size, then encrypt (HPKE)
    B->>R: Ciphertext plus one blind-signed credit
    Note right of R: Spend one credit (nullifier), add the API key
    R->>E: Forward the ciphertext only
  end

  rect rgb(255, 255, 255)
    Note over B,E: STEP 4 · The answer comes back sealed
    Note left of E: Decrypt inside, run the model, encrypt the reply
    E-->>R: Encrypted reply
    R-->>B: Encrypted reply, at a steady pace
    B->>U: Decrypted, hidden details put back
  end
```

- **On-Device Filter and Fingerprint Gate (`src/components/privacy/filter-fingerprint-badge.tsx`, `src/components/console/send-pipeline.ts`)**: Before any message is prepared, `assertFilterFingerprintAllowsSend()` recomputes the SHA-256 digest of `MECHANICAL_RULESET` in the browser and compares it against `published-fingerprint.json` (whose anchor transaction is verified on Circle Arc Testnet via `eth_getTransactionReceipt`); any mismatch throws `FilterFingerprintMismatchError` and blocks sending.
- **Client-Side Redaction and Padding (`src/components/console/send-pipeline.ts`, `src/lib/relay.ts`)**: `prepareOutboundTurn()` loads active custom scrub terms from the unlocked local vault, runs `preparePrompt()` to replace PII and secrets with numbered placeholders (`[EMAIL_1]`, `[SECRET_1]`), and pads the outbound JSON payload with RFC 8259 trailing spaces to a power-of-two byte bucket (`padJsonPayloadToBucket`, minimum `4096` bytes) immediately prior to HPKE sealing.
- **Browser-Verified Seven Checks (`src/lib/tinfoil/client.ts`)**: `openTinfoilSession()` verifies the enclave attestation bundle and deep matrix in the browser across `C1` (`Hardware signature chain`), `C2` (`Approved software`), `C3` (`HPKE key bound to enclave report`), `C4` (`Running code = released code`), `C5` (`Router-attested confidential GPU pool`), `C6` (`Registry admission`), and `C7` (`Manifest-pinned model & dm-verity root`) before sealing the request with an ephemeral RFC 9180 HPKE sender key (`ehbp-encapsulated-key`).
- **Blind-Signed Credit Spend and Oblivious Relay (`src/lib/credits/**`, `src/app/api/relay/v1/[...path]/route.ts`)**: If the browser attaches an unblinded Chaumian RSA credit token in `x-drouter-credit`, the relay verifies its signature against the denomination's coprime exponent (`65537`, `65539`, or `65543` over a Full-Domain Hash in `Z_n^*`), atomically inserts `sha256("drouter/v1/credit-nullifier:" + token)` into `credit_nullifiers` to prevent double-spending, raises the ciphertext body cap to `512 KB`, and adds `Authorization: Bearer ${TINFOIL_API_KEY}` without ever seeing plaintext.
- **Cadence-Paced Encrypted Stream and Local Restoration (`src/lib/relay.ts`, `src/components/console/send-pipeline.ts`)**: The enclave returns an HPKE-encrypted stream (`ehbp-response-nonce`) which the relay flushes on a fixed interval (`pacedStream`, `50 ms`) and the browser decrypts and passes through `prepared.restore()` so original names and identifiers reappear only on the user's screen.
