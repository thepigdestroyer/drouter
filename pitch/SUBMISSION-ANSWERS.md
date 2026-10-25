# Encode London 2026: submission answers for deRoute

Copy each answer into the matching field on the Encode platform. Items in [square brackets] are for you to fill in. Everything else matches what is built and live on 25 October 2026.

## Where to enter
- **Google DeepMind: Build with Gemini 4 Argon** (main fit)
- **MongoDB: Build Anything, Change Everything with MongoDB Atlas** (main fit)
- **Open challenge: Agents That Ship** (optional; the Agent page plans, uses tools, verifies itself and asks before risky steps)

## Project name
deRoute

## Tagline (short)
Private AI you can verify: your words are filtered on your device and only a verified sealed computer can read them.

## Links
- Live app: https://drouter-demo.vercel.app
- GitHub (public): https://github.com/thepigdestroyer/drouter
- Architecture in pictures: https://github.com/thepigdestroyer/drouter/blob/main/docs/ARCHITECTURE.md
- Pitch deck: `pitch/deck/index.html` in the repo (https://github.com/thepigdestroyer/drouter/tree/main/pitch/deck)
- Demo video: [paste your video link]

## Short description (about 100 words)
People need AI most for the things they cannot share: patient notes, client files, private code. Today that means trusting a company's privacy policy. deRoute replaces trust with proof. Your browser hides personal details on your device with a filter whose fingerprint is published on Circle Arc, checks seven hardware proofs before sending anything, and seals your message so only an attested Tinfoil sealed computer can read it. Gemini 4 Argon plans multi-step tasks from a description that contains none of your words, behind a gate that caps what it can receive at about 67 bits. MongoDB Atlas powers the public library and hybrid search.

## The problem, and who it is for
Problem: sensitive work and AI do not mix. A junior doctor cannot paste patient notes into a chatbot, a lawyer cannot paste a client contract, a developer cannot paste production secrets. Privacy policies are promises nobody can check.

Who it is for: [Name a real person who agreed to be named, for example "Priya, a junior doctor at a London hospital trust, who wants AI help summarising case notes but cannot send patient details to an AI company". Do not use the fictional example persona from the app here.]

What changes for them: they type normally; names, dates, numbers and secrets are hidden on their device before anything leaves; anything they wrap in ££ like ££this££ is hidden too; the AI runs inside hardware that proves which code it runs; and they can see exactly what Google received.

## How it works (the seven building blocks)
1. **On-device filter.** Deterministic rules hide names, emails, phone numbers, dates, money, account numbers, keys, internal hostnames and file paths. The rule set's fingerprint is published on Circle Arc (filter v1.0.5, tx 0xfad634d280cdb2a5b6dbf7010325f1d4ade646e2dc37765bab0e2037a140eaa3) and the browser refuses to send if its filter does not match. A second pass runs inside Tinfoil's sealed personal-detail filter.
2. **Sealed computers.** Prompts are processed only inside hardware-isolated Tinfoil enclaves (AMD SEV-SNP router, Intel TDX, NVIDIA confidential GPUs). Before sending, the browser runs seven checks (C1 to C7): hardware signature chain, approved software, encryption key bound to the enclave, running code equals released code, confidential GPU pool, registry admission, pinned model.
3. **Open registry on Circle Arc.** Nodes are admitted on-chain with a USDC stake; anyone can check who may serve.
4. **End-to-end encryption through a blind relay.** HPKE (RFC 9180) to the enclave's attested key, fixed-size padding; our relay only forwards ciphertext.
5. **Unlinkable payments.** One-time deposit addresses and blind-signed credits with one-time spend codes; passkey accounts with no email.
6. **Content-free Gemini planner and private knowledge.** Gemini 4 Argon plans agent tasks from a description with none of the user's words; private runs download the whole public library so MongoDB never learns what anyone looked up.
7. **Public accountability.** An hourly monitor checks the six real sealed computers; results go into an RFC 6962 transparency log anchored on Arc; anyone can verify with `node scripts/drouter-cli.mjs verify --submit`.

**Also usable from coding tools.** OpenCode and other OpenAI-compatible tools and scripts can use deRoute with an anonymous `drk_` access key bundled from blind-signed credits in the browser. Private mode is a single downloadable file, `deroute-proxy.mjs` (sha256 published), that runs on the user's own computer: it applies the same published filter, runs the seven checks and encrypts to the sealed computer before anything leaves. Hosted mode is simpler and clearly labelled as visible to our server.

## Gemini: which models and agents we used, and how (required by the Gemini bounty)
- **gemini-4-argon** is the lead planner on the Agent page, called with the `@google/genai` SDK through the Interactions API (`client.interactions.create`), `thinking_level: "medium"`, `store: false` (Google keeps no copy), with five function-calling tools. It receives only a content-free task description (task kind, power-of-two size bucket, rounded counts of hidden details, which checks to run, allowed tools) and returns a plan of tool calls that refer to opaque handles such as `$INPUT`.
- **Verification loop with pass/fail signals:** every Google-bound request must match an exact schema and pass a content-free check before it is sent (maximum about 67 bits per request); Gemini's returned plan is validated against the same closed schemas before use; the seven attestation checks must pass before the sealed computer runs the task (real failover to another model if they fail); the restore of hidden details is verified on the device; the sha256 of the exact bytes Google received is appended to the transparency log and the browser verifies the inclusion proof.
- **gemma-4-31b** (open model) is available on the Agent page running inside a Tinfoil sealed computer.
- **Human control:** the agent never writes to an external system on its own. Recording a public receipt on Circle Arc waits for the user's explicit approval, and only after a successful run; payments always need the user.
- **Why Argon:** it plans long, tool-using workflows well from very little information, which is exactly what a planner that is never allowed to see the content needs. Next step (built, reviewed, not yet deployed): run the planner inside Google Cloud Confidential Space so Google's own attestation proves the planner code.

## MongoDB Atlas: features used (required by the MongoDB bounty)
- **Atlas Vector Search** (`$vectorSearch`, 768-dimension embeddings, index `drouter_vector_index`).
- **Atlas Search** full text (`$search`, index `drouter_text_search`).
- **Hybrid Search** (`$rankFusion` combining both), MongoDB 8.0.
- Core data: the public reference library (`enclave_intelligence`, 16 sourced documents, embeddings computed with `nomic-embed-text` inside a Tinfoil sealed computer), the RFC 6962 transparency log and signed tree heads, hourly monitoring runs, independent verifications, and anonymous payment records (claim-code hashes, amounts without senders, one-time spend codes).
- Privacy by design: MongoDB never stores messages, names or IP addresses; public search text is filtered on the device and on the server first; private agent runs download the whole library (identical for everyone, hash checked) so lookups reveal nothing.

## Agents That Ship (if entering): tools, steps and where a human approves
- Tools: on-device filter, sealed personal-detail filter, Gemini 4 Argon planner, attestation checks, local library search, sealed-computer execution, Arc receipt anchoring.
- Steps: filter on device, build content-free description, plan with Gemini, validate the plan, verify the sealed computers, run the task sealed, restore names on device, show receipts.
- Human approval: before recording anything on chain, before any payment, and the user can see exactly what Google received.

## Tech stack
Next.js 16 on Vercel, TypeScript, Tinfoil (SecureClient, EHBP/HPKE, attested enclaves), Google Gemini 4 Argon (`@google/genai` Interactions API), MongoDB Atlas 8.0 (Vector Search, Atlas Search, `$rankFusion`), Circle Arc testnet (registry, receipts, USDC), WebAuthn passkeys, RSA blind signatures, RFC 6962 Merkle log, GitHub Actions (hourly monitor), Vitest (51 suites, 465 tests).

## Built during the hackathon
First commit 24 October 2026 14:41 BST; every commit since is in the public repo history.

## Challenges we ran into
Proving privacy instead of promising it: a generic "does this look like content" filter kept being bypassed in review, so we replaced it with exact message schemas and measured the worst-case capacity. Making the browser verify hardware proofs, Arc records and log inclusion proofs itself. Keeping placeholders stable across a whole conversation so hidden details always come back correctly.

## What's next
Deploy the planner inside Google Cloud Confidential Space; more independent operators in the Arc registry; a signed, reproducible release of the local proxy for coding tools, with automatic updates when a new filter version is published on Arc.

## Team
[Names and roles]
