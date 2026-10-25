## Anonymous Deposit Invoices & RSA Blind-Signed Credits (`08-payments`)

To pay for enclave inference without linking a wallet address to any prompt or session, the browser requests a one-time deposit address using only the SHA-256 hash of a local secret, deposits fixed-denomination USDC on Circle Arc, and claims RSA blind-signed credit tokens. When the browser later spends an unblinded token, the server verifies the RSA signature and records a SHA-256 nullifier, making the spend mathematically unlinkable to the invoice or on-chain payment.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"Georgia, serif","fontSize":"16px","actorBkg":"#151515","actorTextColor":"#f3f1ec","actorBorder":"#151515","actorLineColor":"#8a8780","signalColor":"#151515","signalTextColor":"#151515","noteBkgColor":"#ffffff","noteBorderColor":"#d9531e","noteTextColor":"#151515","sequenceNumberColor":"#ffffff","labelBoxBkgColor":"#151515","labelTextColor":"#f3f1ec"},"themeCSS":".messageLine0,.messageLine1{stroke-width:2.4px;} .messageText{font-weight:600;} marker path{fill:#151515;stroke:#151515;}","sequence":{"mirrorActors":false,"wrap":true,"width":210,"actorMargin":120,"messageMargin":34,"boxMargin":14,"noteMargin":12}}}%%
sequenceDiagram
  autonumber
  participant B as Your browser
  participant S as deRoute credits service
  participant A as Circle Arc (USDC)
  participant D as Database

  rect rgb(243, 241, 236)
    Note over B,D: STEP 1 · Ask for a one-time payment address
    Note right of B: Make a secret claim code and keep it on the device
    B->>S: Only the claim code's hash, plus the amount (1, 5 or 20 credits)
    Note right of S: Derive a fresh deposit address, never reused
    S->>D: Store the invoice (hash only, no wallet, no IP)
    S-->>B: One-time deposit address
  end

  rect rgb(255, 255, 255)
    Note over B,D: STEP 2 · Pay and collect blind-signed credits
    B->>A: Send USDC to the one-time address (from any wallet)
    Note right of B: Blind the credit tokens so the server cannot see them
    B->>S: Claim code plus blinded tokens
    S->>A: Was the address paid enough?
    A-->>S: Payment confirmed (sender is discarded)
    Note right of S: Sign the blinded tokens
    S-->>B: Blind signatures
    Note right of B: Unblind, check, store encrypted on the device
  end

  rect rgb(243, 241, 236)
    Note over B,D: STEP 3 · Spend a credit without a name
    B->>S: One credit with each message
    Note right of S: Valid signature? Record its one-time nullifier
    S->>D: Nullifier only (a second spend is refused)
  end
```

- **Watch-Only BIP32 Deposit Derivation (`deriveDepositAddress`)**: `src/lib/credits/ledger.ts` derives a fresh child address on Circle Arc Testnet (`chainId: 5042002`) from the public `CREDITS_DEPOSIT_XPUB` (`m/44'/60'/0'/0/<derivationIndex>`) while keeping the spending private key offline, and enforces fixed USDC denominations (`0.0001`, `0.0005`, or `0.002` USDC for `1`, `5`, or `20` credits) to prevent amount fingerprinting.
- **Hash-Committed Claim Secret & Sender Stripping**: The browser sends only `claimHash = sha256(claimSecret)` to `POST /api/credits/invoice` (which rejects requests containing `claimSecret` or payer addresses). On `POST /api/credits/claim`, `getUsdcTransferLogs()` queries ERC-20 `Transfer(to: depositAddress)` events on `0x3600000000000000000000000000000000000000` and strips `args.from` and `topics[1]` at ingestion so payer wallet addresses never enter memory or `credit_payments`.
- **Denomination-Bound RSA Full-Domain-Hash Blind Signatures**: `src/lib/credits/blind.ts` maps each random `tokenHex` and denomination into $\mathbb{Z}_n^*$ via HKDF-SHA-256 (`hashTokenMessage`) and uses distinct coprime public exponents per denomination (`1 -> 65537`, `5 -> 65539`, `20 -> 65543`) so a low-denomination signature cannot be forged into a high-denomination credit.
- **Encrypted Local Wallet Storage**: After unblinding `s = s' \cdot r^{-1} \bmod n` and verifying `verifyTokenSignature(creditToken, pub)` locally, `src/lib/credits/client.ts` encrypts the unspent tokens in `localStorage` (`drouter.credits.v1`) with AES-256-GCM under the active vault session key (or an ephemeral in-memory CSPRNG key) and AAD `drouter/v1/credits-wallet`.
- **Nullifier Double-Spend Protection**: When a credit is spent via `x-drouter-credit` or `POST /api/credits/spend`, the server verifies $s^{e_{\text{denom}}} \bmod n = \text{FDH}(\text{tokenHex}, \text{denom}, n)$ and atomically inserts `nullifier = sha256("drouter/v1/credit-nullifier:" + tokenHex)` into `credit_nullifiers` with a coarsened UTC-hour `spentAt` timestamp.
