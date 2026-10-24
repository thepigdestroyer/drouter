# Security Policy

## Reporting a Vulnerability

If you discover a security or privacy vulnerability in dRouter, please report it privately so we can verify and remediate the issue before public disclosure.

- **GitHub Private Vulnerability Reporting**: Open a private security advisory at `https://github.com/thepigdestroyer/drouter/security/advisories/new`.
- **What to include**: Affected file paths or API endpoints, step-by-step reproduction instructions, a proof-of-concept request or test case, and the impact on prompt confidentiality, hardware attestation verification, or server resource limits.
- **Response target**: We acknowledge reports within 48 hours and aim to publish a fix or mitigation within 7 days.
- **Safe harbor**: Do not test denial-of-service, rate-limit exhaustion, or paid inference consumption against the live demo (`https://drouter-demo.vercel.app`). Run exploit reproductions against a local instance with `DROUTER_STUB_UPSTREAM=1`.

---

## Scope

### In Scope

1. **Client-Side Attestation Verification & Cryptography**:
   - Browser and CLI verification of AMD SEV-SNP reports, VCEK certificate chains, and Sigstore Rekor provenance (`src/lib/tinfoil/`, `src/lib/sim/`, `scripts/drouter-cli.mjs`).
   - RFC 9180 HPKE Encrypted HTTP Body (EHBP) sealing, RFC 9458 Oblivious HTTP framing (`src/lib/ohttp/`), and AES-256-GCM session freeze/resume (`src/lib/freeze/`).
   - Client passphrase vault key derivation (PBKDF2-HMAC-SHA512 + HKDF-SHA256) and Ed25519 export signatures (`src/lib/auth/vault.ts`).
   - Unlinkable RSA blind-signed credit tokens and per-denomination public exponents (`src/lib/credits/`).
2. **Local Privacy & De-Identification Pipeline**:
   - Deterministic PII and secret scrubbing (`src/lib/privacy/scrubber.ts`), homomorphic symmetry masking (`src/lib/symmetry/homomorphism.ts`), stylometric normalization (`src/lib/stylometry/`), and the outbound privacy invariant before Google Interactions API calls (`src/lib/gemini/interactions.ts`).
3. **Server API Routes, Oblivious Relay & Cost Controls**:
   - SSRF, path traversal, header injection, and open-proxy protections on `/api/relay/**` and `/api/v1/**` (`src/lib/relay.ts`, `src/proxy.ts`).
   - Rate limiting, bounded body readers, and gas/token caps on `/api/anchor`, `/api/sandbox`, `/api/atlas`, `/api/cron/auditor`, and `/api/health`.
   - Zero-telemetry storage invariants on MongoDB (`drouter` database): no prompts, completions, raw IP addresses, user agents, or sub-hour timestamps may ever be persisted.

### Out of Scope

- Denial-of-service or load testing against `https://drouter-demo.vercel.app`.
- Compromised client browsers, malicious browser extensions, or OS-level malware on the user's device.
- Hardware vulnerabilities in AMD SEV-SNP, Intel TDX, or NVIDIA Confidential Computing firmware that require vendor microcode updates.
- Third-party infrastructure operated by Tinfoil (`*.tinfoil.sh`, `*.tinfoil.dev`), Circle Arc Testnet (`5042002`), or MongoDB Atlas.

---

## Known Limitations

1. **Compromised Client Device or Browser XSS**:
   - All scrubbers, symmetry keys, vault passphrases, and plaintext prompts live in browser JavaScript memory. A malicious extension or XSS payload on the client can read prompts before encryption.
2. **Regex-Based Scrubbing vs. Unstructured Context**:
   - `src/lib/privacy/scrubber.ts`, `src/lib/symmetry/homomorphism.ts`, and `src/lib/risk/analyzer.ts` use deterministic regular expressions and custom term lists rather than a local neural NER model. Uncommon names or domain-specific confidential facts not added to custom scrub terms may not be redacted automatically.
3. **Tinfoil Router vs. Model Enclave Verification & Sidecars**:
   - In the browser, `@tinfoilsh/verifier` cryptographically verifies the AMD EPYC Genoa SEV-SNP report and Sigstore Rekor bundle for the Tinfoil ingress router (`router-0.tinfoil.sh`). Model worker enclaves (`kimi-k3-inf14.tinfoil.containers.tinfoil.dev`, `gemma4-31b-inf10-0.tinfoil.containers.tinfoil.dev`) run on Intel TDX + NVIDIA Confidential Computing GPUs (`max-model-len` 262,144 tokens for Kimi K3) and are verified transitively via the router's `.well-known/tinfoil-proxy` table and GitHub deployment manifest.
   - Tinfoil's router enclave runs an acceptable-use safeguards classifier sidecar (`gpt-oss-safeguard-120b` + `kimi-k3` review) that reports policy violations to `https://api.tinfoil.sh`, plus a token usage reporter.
4. **Same-Origin Relay in the Demo Deployment**:
   - Although RFC 8259 power-of-two JSON bucket padding, 50 ms stream pacing, and RFC 9458 OHTTP framing are implemented, the `/api/relay/**` endpoints in this demo run on the same Next.js deployment as the web UI, so the hosting platform observes client IP addresses at the HTTP transport layer.
5. **Simulated Subsystems & Demo Seeds**:
   - Nodes `sim-1`, `sim-2`, and `sim-3` are software simulations derived from `SIM_HARDWARE_SEED`.
   - The 5-of-7 verifier quorum (`src/lib/transparency/quorum.ts`), 3-of-5 Shamir regional checkers (`src/lib/threshold/shamir.ts`), VMPL0 1,344-state truth table (`src/lib/monitor/policy.ts`), two-hop GPU custody memory-bus audit (`src/lib/custody/`), and ASHI Tier C FHE benchmarks (`src/lib/ashi/`) execute real cryptographic or mathematical checks in TypeScript using deterministic demo seeds rather than distributed multi-organization hardware.
   - Vercel Sandbox (`src/lib/sandbox/microvm.ts`) executes code in an isolated Firecracker microVM (`@vercel/sandbox`), which is not a hardware-attested TEE enclave.
6. **Blind Credit Key Size Fallback**:
   - Production uses a 2,048-bit RSA modulus loaded from `CREDITS_ISSUER_RSA_PQ`. When `CREDITS_ISSUER_RSA_PQ` is unset in local development or tests, `src/lib/credits/blind.ts` falls back to a deterministic 1,024-bit key derived from `CREDITS_ISSUER_SEED` or `SIM_HARDWARE_SEED`.
7. **Dependency Audit Notes (`npm audit`)**:
   - `solc@0.8.38` (devDependency used only offline by `scripts/arc-compile.mjs`) depends on `tmp@0.2.6` (`GHSA-7c78-jf6q-g5cm`), which is never bundled or reachable in production.
   - `@vercel/sandbox@3.9.0` transitively pulls `@vercel/oidc -> @vercel/cli-config -> zod` (`GHSA-mrhx-c7xc-m3w5`); our `/api/sandbox` route validates request payloads with bounded byte readers (`readBoundedJson`, max 16 KB) before invoking the SDK, so oversized collection validation in `@vercel/cli-config` is not reachable from untrusted input.
