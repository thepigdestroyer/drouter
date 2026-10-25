# deRoute: 2-minute video pitch script

Prepared 25 October 2026. Every spoken claim was checked against the repo and the live site (https://drouter-demo.vercel.app). The live checks included a signed-in headless Chrome session on Chat, Agent, Proof and Network, one real chat message, and `node scripts/drouter-cli.mjs verify`. Section 8 lists the evidence for each claim.

Tracks: Google DeepMind Gemini 4 Argon, MongoDB Atlas.

---

## 0. Read first: fix these four things before recording

These are live production problems I found today. Each one shows up on camera if it is not fixed.

| # | Problem (seen live on 25 Oct) | What it looks like on camera | Fix or workaround |
| :- | :- | :- | :- |
| 1 | FIXED 25 Oct (commit e2483a1 and a working key): live `/api/gemini/plan` returns HTTP 200 with a `gemini-4-argon` plan and its egress receipt. |
| 2 | FIXED 25 Oct (commits 8c0e618, cb19eea): the security policy now allows `https://rpc.testnet.arc.io`, so the filter badge can confirm its Arc receipt. |
| 3 | FIXED 25 Oct (commit 0542b27): the second filter pass runs inside Tinfoil's sealed `pii-filter`; the relay sends that enclave to `/redact` only. |
| 4 | FIXED 25 Oct (commit b5035cb): `/explain` ("How it works") loads normally again; the game uses its public demo key in the browser. |

---

## 1. Running order and timing

Speaking pace assumed: about 150 words per minute (2.5 words per second). Times are relative to the start of each part. Absolute time = length of your recorded intro + these times.

| Section | Time | Spoken words | What is on screen |
| :- | :- | -: | :- |
| Intro (already recorded) | your cut | n/a | Presenter: the problem |
| Bridge (opens Part 1) | P1 0:00-0:03 | 8 | Presenter walking |
| Block 1: The filter | P1 0:03-0:12 | 22 | Presenter + lower-third 1 |
| Block 2: Sealed computers | P1 0:12-0:19 | 17 | Presenter + lower-third 2 |
| Block 3: Open registry | P1 0:19-0:25 | 16 | Presenter + lower-third 3 |
| Block 4: Blind relay | P1 0:25-0:33 | 19 | Presenter + lower-third 4 |
| Block 5: Unlinkable payments | P1 0:33-0:40 | 18 | Presenter + lower-third 5 |
| Block 6: Blind planning | P1 0:40-0:51 | 29 | Presenter + lower-third 6 |
| Block 7: Public receipts | P1 0:51-1:00 | 23 | Presenter + lower-third 7 |
| **Part 1 total** | **about 60 s** | **152** | |
| S1 Seal check | P2 0:00-0:08 | 21 | `/app` |
| S2 Hide, send, restore | P2 0:08-0:22 | 35 | `/app` |
| S3 Gemini 4 Argon agent | P2 0:22-0:38 | 39 | `/argon` |
| S4 MongoDB Atlas | P2 0:38-0:47 | 24 | `/argon`, library section |
| S5 Hourly monitor | P2 0:47-0:50 | 6 | `/audit` (nav label "Proof") |
| S6 Verify yourself | P2 0:50-0:56 | 14 | Terminal |
| S7 Closer | P2 0:56-1:00 | 8 | End card |
| **Part 2 total** | **about 60 s** | **147** | |
| **Total spoken (Parts 1 and 2)** | **about 2:00** | **299** | |

If Part 2 runs long, cut S5's line first. The picture already says "6 of 6 intact".

---

## 2. Bridge line (first line of Part 1, right after your intro)

> deRoute replaces trust with proof. Seven building blocks.

Spoken as "dee-route" (or match however you say it in the intro).

---

## 3. Part 1: walk and talk (about 60 seconds, 152 words)

Short sentences, one breath each. Numbers are the signposts: hit "One", "Two", and so on with a small pause after each. Each lower-third is optional. Show it for the length of the block, bottom-left, two lines at most.

**P1 0:00-0:03 · Bridge (8 words)**
> deRoute replaces trust with proof. Seven building blocks.

**P1 0:03-0:12 · Block 1: The filter (22 words)**
> One: the filter. Your browser hides emails, phone numbers and keys first. Its fingerprint lives on Circle Arc. No match, no send.

Lower-third: `1 · On-device personal-detail filter v1.0.4 · fingerprint anchored on Circle Arc Testnet (tx 0xff43cfff...eaef5e7d) · second pass in Tinfoil's sealed pii-filter`

**P1 0:12-0:19 · Block 2: Sealed computers (17 words)**
> Two: sealed computers. Prompts open only inside sealed AMD, Intel and NVIDIA hardware, after seven browser checks.

Lower-third: `2 · Tinfoil sealed computers: AMD SEV-SNP router, Intel TDX or AMD SEV-SNP model hosts with NVIDIA confidential GPUs · browser checks C1 to C7`
Optional full-screen card (1.5 s): `C1 hardware signature chain · C2 approved software · C3 encryption key bound to the enclave report · C4 running code = released code · C5 router-attested confidential GPU pool · C6 registry admission · C7 manifest-pinned model + dm-verity root`

**P1 0:19-0:25 · Block 3: Open registry (16 words)**
> Three: an open registry. Machines join on-chain by staking USDC, and anyone can audit the list.

Lower-third: `3 · DRouterRegistry on Circle Arc Testnet (0xbc8085c2...0b841828f4481) · join by staking USDC · 6 sealed computers active`

**P1 0:25-0:33 · Block 4: Blind relay (19 words)**
> Four: a blind relay. Messages are locked to the machine's key, padded to standard sizes. We forward sealed bytes.

Lower-third: `4 · HPKE (RFC 9180) to the enclave's attested key · padded to 4,096-byte buckets · our relay adds the API key and sees only ciphertext`

**P1 0:33-0:40 · Block 5: Unlinkable payments (18 words)**
> Five: unlinkable payments. One-time deposit addresses, blind-signed credits, passkeys, no email. Spending can't be traced to your wallet.

Lower-third: `5 · One-time USDC deposit address per invoice · 2,048-bit RSA blind-signed credits · nullifiers stop double-spends · passkey or 6-word sign-in, no email`

**P1 0:40-0:51 · Block 6: Blind planning (29 words)**
> Six: blind planning. Gemini 4 Argon plans from a checklist without your words, capped at about 67 bits. Lookups fetch the whole library, so MongoDB never learns your topic.

Say "sixty-seven". Lower-third: `6 · Gemini 4 Argon planner behind a closed-schema egress gate (about 67 bits per request) · private lookups download all 16 docs · public search: Atlas $vectorSearch + $search + $rankFusion`

**P1 0:51-1:00 · Block 7: Public receipts (23 words)**
> Seven: public receipts. Hourly checks on all six sealed computers, logged and anchored on Arc. Or run one command and check for yourself.

Lower-third: `7 · Hourly monitor of 6 sealed computers · RFC 6962 transparency log anchored on Arc · node scripts/drouter-cli.mjs verify --submit`

Delivery notes:
- Block 6 is the longest and carries both tracks. Slow down on "Gemini 4 Argon" and "MongoDB".
- Breathe after "No match, no send", after "USDC", and after "67 bits".
- Cut to the screen recording on the last word of block 7.

---

## 4. Part 2: screen-recorded demo (about 60 seconds, 147 words)

Before recording, complete everything in section 7. Record each shot as its own clip and edit them together. Cut every wait (seal check, model reply, planner run) but never fake a result.

Navigation rule: the account session lives in memory. Typing a URL or reloading signs you out. Move between pages only with the top nav (Chat, Agent, Proof).

### S1 · P2 0:00-0:08 · Seal check (21 words)
- **Page**: https://drouter-demo.vercel.app/app (top nav "Chat"), already signed in.
- **Action**: Start on the seal card. Click "Show technical details (7/7 checks passed)".
- **On screen**: chip "SEALED AND PRIVATE"; text "Sealed and private. Your messages can only be opened by a sealed computer."; list C1 "Hardware signature chain" to C7 "Manifest-pinned model & dm-verity root", each marked PASS. C5 reads "8× NVIDIA confidential GPUs attested by router".
- **Hold**: 3 s on the C1 to C7 list, then click "Hide".
- **VO**:
> The live site. No email, no password. My browser checked the sealed computer before unlocking the chat: seven of seven pass.

### S2 · P2 0:08-0:22 · Hide, send, restore (35 words)
- **Page**: same page.
- **Action**:
  1. Scroll to the card under the chat. Click "Anonymous tokens: 0 left (Add 5 free)". The label changes to "5 left".
  2. Click the message box and paste the chat input from section 7.5.
  3. In the card below, "Live draft check: 2 personal details hidden" appears. Click its "Show technical details".
  4. Scroll back up and click "Send". Cut the wait (my test reply took about 10 s).
- **On screen**: "Padded size: 4,096 B"; "Replaced in browser: [EMAIL_1] (EMAIL) [SECRET_1] (SECRET)"; outbound line "Write a two-line note to [EMAIL_1] ... keep test key [SECRET_1] private."; under your bubble "2 personal details hidden"; the Kimi K3 reply shows `dana.reyes@example.org` restored. The token label drops to "4 left".
- **Hold**: 2 s on the placeholder line, 2 s on the restored reply.
- **VO**:
> I add five free blind-signed tokens, then type a contact email and a test key. My browser swaps them for placeholders and pads the message. The reply comes back, details restored on my screen only.

### S3 · P2 0:22-0:38 · Gemini 4 Argon plans without your words (39 words)
- **Page**: https://drouter-demo.vercel.app/argon (top nav "Agent"). Record as a separate clip because the expert settings reset when you leave the page.
- **Before you hit record**: let the automatic first run finish. Open "For experts", set Thinking level **LOW** and Enclave model **kimi-k3**, close "For experts", and scroll to the top.
- **Action**:
  1. Point at the badge above the Run button: "Personal-detail filter v1.0.4: matches the published version" with "Verified".
  2. Click "Run" (it changes to "Running..."). Cut the wait.
  3. Show the badge "Planned by Gemini 4 Argon" and the timeline: "2. Checking the seal: 7 of 7 safety checks passed" and "3. Thinking: Planned by Gemini 4 Argon. Gemini planned the steps without seeing your words. The sealed computer finished the work..."
  4. Scroll to the top card, which has three columns: "What Google can see", "What Google never sees", "What the sealed computer sees". Click its "Show technical details".
- **On screen**: "Content-free TaskDescriptor sent to POST /api/gemini/plan" (fields `taskKind`, `inputHandle: "$INPUT"`, `inputTokenEstimate`, `redactionCounts`, `verification`, `allowedTools`) and "Exact canonical bytes Google received:".
- **Hold**: 3 s on the TaskDescriptor JSON. Zoom in during editing if needed. Do not click "Allow" on the approval card.
- **VO**:
> The agent's filter matches its fingerprint on Circle Arc, or Run is blocked. Gemini 4 Argon plans. A sealed computer does the work. Here are the exact bytes Google received: task type, counts, check results. None of my text.

### S4 · P2 0:38-0:47 · MongoDB Atlas (24 words)
- **Page**: same `/argon` page. Scroll to "Search what we know about private AI", then "Public reference library".
- **Action**:
  1. Tick "Search on my device only". The line "Ranks the downloaded reference library on your device and sends nothing." appears.
  2. Untick it, then click "Show search engine details".
- **On screen**: "Engines: vector: atlas | text: atlas | fusion: $rankFusion | embedding: nomic-embed-text (Tinfoil attested enclave)" and "Index status: drouter_text_search [search]: READY | drouter_vector_index [vectorSearch 768d]: READY (16 docs) | Atlas connected".
- **Hold**: 3 s on the Engines line.
- **VO**:
> My browser downloads the whole library, so MongoDB can't tell what I looked up. Public search runs on Atlas, fusing vector and text search.

### S5 · P2 0:47-0:50 · Hourly monitor (6 words)
- **Page**: https://drouter-demo.vercel.app/audit (top nav "Proof").
- **On screen**: "Checked every hour: 6 of 6 sealed computers", the "6 of 6 intact" chip, and "Latest hourly run (... UTC): checked 6 sealed computers, all intact".
- **Hold**: 3 s.
- **VO**:
> Hourly monitor: six of six intact.

### S6 · P2 0:50-0:56 · Verify it yourself (14 words)
- **Screen**: terminal in the repo root, font 20 pt or larger, running `node scripts/drouter-cli.mjs verify --submit`. Cut the wait.
- **On screen**: "Checklist (C1-C7):" with seven `[PASS]` lines, then "=== Independent Verifier Submission ===" with "Submission Status : ACCEPTED" and an "RFC 6962 Leaf" line.
- **Hold**: 3 s on the PASS lines plus the ACCEPTED line.
- **VO**:
> And anyone can rerun the checks and sign the result into the public log.

### S7 · P2 0:56-1:00 · Closer (8 words)
- **Screen**: end card with the deRoute logo, `drouter-demo.vercel.app`, `github.com/thepigdestroyer/drouter`, and "Gemini 4 Argon · MongoDB Atlas".
- **VO** (default closer, option B below):
> Private AI you can check, not just trust.

---

## 5. Three alternative one-line closers

- A. "deRoute. Don't trust us. Check us." (6 words. If you use it, block 7 already ends on "check for yourself", so the two lines do not repeat word for word.)
- B. "Private AI you can check, not just trust." (8 words, the default above)
- C. "deRoute: trust that holds when it matters most." (8 words. This one echoes the intro's "when you need it most".)

---

## 6. Teleprompter: Part 1 (one line per breath)

```text
deRoute replaces trust with proof.
Seven building blocks.

One: the filter.
Your browser hides emails, phone numbers and keys first.
Its fingerprint lives on Circle Arc.
No match, no send.

Two: sealed computers.
Prompts open only inside sealed AMD, Intel and NVIDIA hardware,
after seven browser checks.

Three: an open registry.
Machines join on-chain by staking U-S-D-C,
and anyone can audit the list.

Four: a blind relay.
Messages are locked to the machine's key,
padded to standard sizes.
We forward sealed bytes.

Five: unlinkable payments.
One-time deposit addresses, blind-signed credits,
passkeys, no email.
Spending can't be traced to your wallet.

Six: blind planning.
Gemini 4 Argon plans from a checklist without your words,
capped at about sixty-seven bits.
Lookups fetch the whole library,
so MongoDB never learns your topic.

Seven: public receipts.
Hourly checks on all six sealed computers,
logged and anchored on Arc.
Or run one command and check for yourself.
```

---

## 7. Pre-recording checklist

### 7.1 Fix or confirm the four issues in section 0
- [ ] Gemini planner returns a plan (see 7.4).
- [ ] The filter badge shows "matches the published version" with "Verified", or you use the explorer-link workaround.
- [ ] Agent step 1 says "second check inside a sealed computer: yes", or you use the "today" caption for block 1.
- [ ] Optional: "How it works" (`/explain`) is safe to show on camera again.

### 7.2 Account creation
- [ ] Use a fresh Chrome profile with no extensions. A browser extension can read prompts before encryption (README section 5.2).
- [ ] Go to https://drouter-demo.vercel.app/login. Click "Create a deRoute account" and confirm with Touch ID.
- [ ] If the page says "Fingerprint or face sign-in is not available in this browser yet", use "Create with 6 secret words" instead: copy the words, tick "I saved these 6 words in a safe place", then click "Create account with 6 words". Either way, the VO line "No email, no password" stays true.
- [ ] After sign-in, do not reload or type URLs. The session is held in memory and a reload asks you to sign in again. Use the top nav (Chat, Agent, Proof). The footer "Network" link also navigates in-app.

### 7.3 Can a new account chat without buying credits? Yes.
- From the code: with 0 tokens, the relay serves the request under a per-network free limit (`src/app/api/relay/v1/[...path]/route.ts`: burst of 20, refill 0.5 per second). The UI says so too: "at 0 tokens, chatting still works under the standard daily limit".
- To show unlinkable credits on camera, click "Anonymous tokens: 0 left (Add 5 free)". That mints 5 free blind-signed tokens (`POST /api/credits`). Each send spends one: the label drops, and the message's technical details show "Anonymous token header x-drouter-credit attached (0x...)". I tested this live.
- Free allowance: 10 credit units per day per salted network-address hash, refilling gradually (`/api/credits` reports `freeDailyAllowance: 10`). Rehearsals use it up. **I minted 5 from this Mac's network during testing on 25 Oct.** If the allowance runs out, the page shows "Your free daily anonymous token allowance has been used for today". Either skip the token click (chat still works) or record from another network.
- Do not buy tokens on camera. "Get more anonymous tokens" shows a one-time deposit address. Paying needs Arc Testnet USDC and is not part of the demo.

### 7.4 Gemini key configured and working
- [x] In Vercel production, `GEMINI_API_KEY` is set and working (verified 25 Oct). Changing env vars needs a redeploy.
- [ ] Check with:

```bash
curl -s -X POST https://drouter-demo.vercel.app/api/gemini/plan \
  -H 'content-type: application/json' \
  -d '{"allowedTools":["scrub_and_symmetry_mask","verify_two_hop_enclave_and_quorum","search_atlas_hybrid_kb","invoke_attested_enclave","anchor_arc_settlement_with_human_gate"],"inputHandle":"$INPUT","inputTokenEstimate":128,"redactionCounts":{"DATE":1,"DIGITS":2,"EMAIL":1,"SECRET":1,"TOTAL":2},"taskKind":"summarize","verification":{"attestedPiiFilterVerified":false,"bucketAligned4096":true,"mechanicalRedactionPassed":true}}'
```

  Pass: `"ok":true` with a `"plan"` and an `"egressReceipt"`. Verified 25 Oct: HTTP 200, planner `gemini-4-argon`, with an egress receipt. The planner has a hard 20-second limit, which is why S3 uses Thinking level LOW.

### 7.5 Example inputs that visibly trigger on-device hiding (fictional persona from the code only)
- **Chat (`/app`)**, verified live:
  `Write a two-line note to dana.reyes@example.org saying the cohort review moved to Friday. Keep test key sk-test-4f9a2c7e1b8d6a3f5e0c private.`
  Expected: "2 personal details hidden", `[EMAIL_1]` and `[SECRET_1]`, padded size 4,096 B. The reply restores the email.
- **Do not type a person's name, a date or a money amount in Chat.** The chat's scrubber does not hide personal names, `COHORT-2026-08-14` or `£125,000.00`. The Agent page's filter does.
- **Agent (`/argon`)**: use the pre-filled task. Click the "Example: a fictional hospital data scientist" card to reset it. Today, step 1 reads "5 personal details hidden; ... (2 numbers, 1 date, 1 email, 1 secret key)". The count may rise once the sealed second pass works.
- The model writes its own reply text. Kimi K3 used a long dash in my test reply. If you want none on screen, add "Use no dashes." to the chat input.

### 7.6 Browser, zoom and window
- [ ] Chrome desktop, light theme (the site is light only), bookmarks bar hidden, Do Not Disturb on, no other tabs except the Arc explorer tab.
- [ ] Window content area 1920×1080 at 150% zoom, or 1600×900 at 125% zoom. Both give a 1280×720 CSS layout: the desktop nav shows and text is readable at 1080p.
- [ ] Record at 1080p or higher. On a Retina screen, record the window and export at 1080p.

### 7.7 Pages to pre-load and warm up (in this order, right before recording)
- [ ] Wake the serverless functions:

```bash
for p in api/health api/registry api/relay/enclave-matrix api/accountability api/transparency api/knowledge/corpus "api/atlas?q=Tinfoil+confidential+GPU+model+router"; do curl -s -o /dev/null -w "%{http_code} $p\n" "https://drouter-demo.vercel.app/$p"; done
```

  Expect `200` for each.
- [ ] Sign in (7.2), then open Chat and wait for "Sealed and private" and "7/7 checks passed".
- [ ] Open Agent and let the automatic first run finish. Each Agent page load runs the default task, including a planner call.
- [ ] Open Proof and check that "Latest hourly run" is from the last hour or two.
- [ ] In a second tab, open https://explorer.testnet.arc.io/tx/0xff43cfff01759aed0c61eeef85d40235ea5c96c82f6b86f9c7f4e3b9eaef5e7d (the filter anchor) as backup B-roll.
- [ ] Terminal: in a clone of the repo, run `npm install`, then do one dry run of `node scripts/drouter-cli.mjs verify` without `--submit`. I ran it on 25 Oct and C1 to C7 all passed. Use `--submit` only for the real take, because each submission adds a real signed entry to the public log. Afterwards, the Proof page counter rises by one (it showed 1 signed check on 25 Oct).

### 7.8 Final dry run
- [ ] Read Part 1 aloud with a stopwatch. Aim for 58 to 62 s.
- [ ] Rehearse Part 2 once end to end. If the Gemini run takes long, plan the jump cut.

---

## 8. Fact sheet: where each spoken claim is proven

| Spoken claim | Evidence |
| :- | :- |
| Filter v1.0.4; fingerprint on Circle Arc; no match, no send | `src/lib/privacy/mechanical-ruleset.ts` (`version: "1.0.4"`), `src/lib/privacy/published-fingerprint.json`. Recomputed fingerprint `0x5bc6cc77...ec8d9e09` matches. Arc RPC: tx `0xff43cfff...eaef5e7d` status success, `ReceiptAnchored` with hash `0x81889241...d1aa27`. A mismatch blocks Chat (`canSend`, `assertFilterFingerprintAllowsSend`) and Agent Run (`filterBlocked`). |
| Hides emails, phone numbers and keys first | Live test: `[EMAIL_1]`, `[SECRET_1]`; `[PHONE_1]` for `415-555-0199` (code test). Runs in the browser before encryption (`prepareOutboundTurn`, `runBrowserRedactionPipeline`). |
| Sealed AMD, Intel and NVIDIA hardware; seven browser checks | `src/lib/tinfoil/client.ts` `checksFromDocument` (C1-C5, C7) and `src/components/session.ts` (C6). Live on `/app`: 7/7 PASS. C1 "VCEK -> SEV-Genoa -> ARK-Genoa", C5 "8× NVIDIA confidential GPUs ... TDX + CC mode". CLI `verify`: 7 PASS. |
| Machines join on-chain by staking USDC; anyone can audit | `contracts/DRouterRegistry.sol` `registerNode` is payable with `minStake`. Live `/api/registry`: `source: arc`, 6 active nodes, 0.01 USDC stake each, contract `0xbc8085c2b6fe6e0db05f169925c0b841828f4481`. |
| Locked to the machine's key, padded, relay forwards sealed bytes | C3 "HPKE key bound to enclave report". Relay requires `ehbp-encapsulated-key`, adds `TINFOIL_API_KEY`, logs byte counts only (`src/app/api/relay/v1/[...path]/route.ts`). Live: "Padded size: 4,096 B". |
| One-time addresses, blind-signed credits, passkeys, no email | Live `POST /api/credits/invoice` returned a fresh `depositAddress`. `/api/credits` `keyBits: 2048`. A spent token attached `x-drouter-credit` with a nullifier. `/login`: passkey or 6 words, no email field. |
| Gemini 4 Argon plans from a checklist without your words, about 67 bits | `POST /api/gemini/plan` takes only the `TaskDescriptor`; model `gemini-4-argon`; one `interactions.create` call per plan (`src/app/api/gemini/plan/route.ts`). Bound of 66.89 bits per create request is stated in README section 2.4. I re-did the arithmetic from the stated domain sizes and it matches. |
| Lookups fetch the whole library; MongoDB never learns your topic | Live `GET /api/knowledge/corpus`: 16 documents with `contentSha256`; any query string gives HTTP 400. Fetched during the Agent run (seen in network log). |
| Public search on Atlas, fusing vector and text | Live `/api/atlas`: `vectorSearch: atlas`, `textSearch: atlas`, `fusion: $rankFusion`; indexes `drouter_text_search` and `drouter_vector_index` (768d) READY. |
| Hourly checks on all six, logged and anchored on Arc | Live `/api/accountability`: latest run 07:00 UTC 25 Oct, 6/6 verified, transparency tree size 25, anchor tx on Arc. `.github/workflows/monitor.yml` runs at 17 and 47 past each hour (the second slot is a backup; one run per hour is recorded). |
| Anyone can rerun the checks and sign into the public log | `scripts/drouter-cli.mjs verify --submit`. Default upstream is the production site. |

---

## 9. Do not say (true limits a judge could catch)

- **Do not say Google Cloud Confidential Space is live.** `deroute-core` is built but not deployed: `/api/core/attestation` returns 503 `{"core":"not-deployed"}`. Today's egress receipt is labelled "Recorded by our server", not hardware-signed.
- **Do not say "mainnet".** Everything on Arc is Circle Arc **Testnet** (chain 5042002). The captions say so.
- **Do not say "fully decentralized" or "anyone runs nodes today".** Joining the registry is open, but all six registered nodes are Tinfoil machines, and the contract owner can suspend or slash. The browser reads the registry through deRoute's `/api/registry` rather than an Arc RPC.
- **Do not say "a seal check before every message".** The seven checks run when the chat opens and on "Check seal again". Each send is refused if any stored check failed. "Before unlocking the chat" is the accurate wording.
- **Do not say Chat hides names.** Chat's scrubber hides emails, phone numbers, keys, addresses, account numbers and your "Always hide" words, but not personal names. The Agent filter does hide names.
- **Do not say nobody can see your IP address.** The relay hides it from Tinfoil, not from Vercel or deRoute (README section 5.1).
- **Do not say Tinfoil sees nothing.** Tinfoil's router runs a disclosed safety classifier that reports policy violations to `api.tinfoil.sh`.
