## Confidential Chat Lifecycle (`03-chat-lifecycle`)

When a user sends a chat message, the browser first verifies that its local personal-detail filter matches the published ruleset anchored on Circle Arc Testnet and scrubs sensitive terms on the device. It then verifies all seven enclave checks (`C1` through `C7`), pads and HPKE-encrypts the scrubbed prompt to the enclave's attested public key, attaches an unlinkable blind-signed credit token for the relay, and restores the hidden details locally after decrypting the enclave's reply.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#f3f1ec","primaryTextColor":"#151515","primaryBorderColor":"#151515","lineColor":"#595752","secondaryColor":"#ffffff","tertiaryColor":"#f3f1ec","fontFamily":"Georgia, serif"}}}%%
sequenceDiagram
  autonumber
  actor User as User
  participant Browser as Browser (send-pipeline.ts & tinfoil/client.ts)
  participant Arc as Circle Arc Testnet (chainId 5042002)
  participant Relay as Vercel Oblivious Relay (/api/relay/v1/*)
  participant Enclave as Tinfoil Enclave (Router + Model CVM)

  User->>Browser: Types raw prompt with personal details
  Browser->>Browser: Recompute SHA-256 of MECHANICAL_RULESET (verifyFilterFingerprint)
  Browser->>Arc: Read-only eth_getTransactionReceipt(anchorTx) for published-fingerprint.json
  Arc-->>Browser: Confirm on-chain filter fingerprint receipt (or block send on mismatch)
  Note over Browser: assertFilterFingerprintAllowsSend() passes,<br/>preparePrompt() scrubs PII/secrets/vault terms,<br/>normalizes style, and pops 1 blind credit (takeCreditHeader)

  Browser->>Relay: GET /api/relay/attestation & GET /api/relay/enclave-matrix
  Relay->>Enclave: Fetch AMD SEV-SNP report, VCEK, Sigstore bundle & proxy table
  Enclave-->>Relay: Attestation bundle + model enclave matrix
  Relay-->>Browser: Return attestation bundle & deep inspection matrix

  Note over Browser: Verify Seven Checks (checksFromDocument):<br/>C1: Hardware signature chain<br/>C2: Approved software<br/>C3: HPKE key bound to enclave report<br/>C4: Running code = released code<br/>C5: Router-attested confidential GPU pool<br/>C6: Registry admission<br/>C7: Manifest-pinned model & dm-verity root

  Browser->>Browser: Pad JSON to 4096 B power-of-two bucket (padJsonPayloadToBucket)<br/>& seal with RFC 9180 HPKE to enclave hpkePublicKey

  Browser->>Relay: POST /api/relay/v1/chat/completions<br/>(HPKE ciphertext + ehbp-encapsulated-key + x-drouter-credit)
  Note over Relay: verifyAndSpendCreditHeader():<br/>Verify Chaumian RSA blind signature (e in 65537, 65539, 65543),<br/>atomically record nullifier in credit_nullifiers,<br/>refill rate bucket, and inject Authorization: Bearer TINFOIL_API_KEY

  Relay->>Enclave: Forward HPKE ciphertext + ehbp-encapsulated-key + Bearer API key
  Enclave->>Enclave: Decrypt inside enclave RAM, run model on redacted text, HPKE-encrypt stream
  Enclave-->>Relay: Encrypted SSE stream + ehbp-response-nonce
  Relay-->>Browser: Pace frames (pacedStream, 50 ms cadence) + X-DRouter-Credit-Nullifier

  Browser->>Browser: Decrypt HPKE stream & restore placeholders via prepared.restore()
  Browser-->>User: Render restored response with local privacy & attestation receipt
```

- **On-Device Filter and Fingerprint Gate (`src/components/privacy/filter-fingerprint-badge.tsx`, `src/components/console/send-pipeline.ts`)**: Before any message is prepared, `assertFilterFingerprintAllowsSend()` recomputes the SHA-256 digest of `MECHANICAL_RULESET` in the browser and compares it against `published-fingerprint.json` (whose anchor transaction is verified on Circle Arc Testnet via `eth_getTransactionReceipt`); any mismatch throws `FilterFingerprintMismatchError` and blocks sending.
- **Client-Side Redaction and Padding (`src/components/console/send-pipeline.ts`, `src/lib/relay.ts`)**: `prepareOutboundTurn()` loads active custom scrub terms from the unlocked local vault, runs `preparePrompt()` to replace PII and secrets with numbered placeholders (`[EMAIL_1]`, `[SECRET_1]`), and pads the outbound JSON payload with RFC 8259 trailing spaces to a power-of-two byte bucket (`padJsonPayloadToBucket`, minimum `4096` bytes) immediately prior to HPKE sealing.
- **Browser-Verified Seven Checks (`src/lib/tinfoil/client.ts`)**: `openTinfoilSession()` verifies the enclave attestation bundle and deep matrix in the browser across `C1` (`Hardware signature chain`), `C2` (`Approved software`), `C3` (`HPKE key bound to enclave report`), `C4` (`Running code = released code`), `C5` (`Router-attested confidential GPU pool`), `C6` (`Registry admission`), and `C7` (`Manifest-pinned model & dm-verity root`) before sealing the request with an ephemeral RFC 9180 HPKE sender key (`ehbp-encapsulated-key`).
- **Blind-Signed Credit Spend and Oblivious Relay (`src/lib/credits/**`, `src/app/api/relay/v1/[...path]/route.ts`)**: If the browser attaches an unblinded Chaumian RSA credit token in `x-drouter-credit`, the relay verifies its signature against the denomination's coprime exponent (`65537`, `65539`, or `65543` over a Full-Domain Hash in `Z_n^*`), atomically inserts `sha256("drouter/v1/credit-nullifier:" + token)` into `credit_nullifiers` to prevent double-spending, raises the ciphertext body cap to `512 KB`, and adds `Authorization: Bearer ${TINFOIL_API_KEY}` without ever seeing plaintext.
- **Cadence-Paced Encrypted Stream and Local Restoration (`src/lib/relay.ts`, `src/components/console/send-pipeline.ts`)**: The enclave returns an HPKE-encrypted stream (`ehbp-response-nonce`) which the relay flushes on a fixed interval (`pacedStream`, `50 ms`) and the browser decrypts and passes through `prepared.restore()` so original names and identifiers reappear only on the user's screen.
