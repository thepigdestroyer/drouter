# deRoute: 3-minute judging pitch script (411 scripted words, about 426 with your named user)

**Overview:** 3:00 total at about 145 words per minute, 411 scripted words plus about 15 for your named user (about 426 words) · slide 1 about 40 s · slide 2 about 50 s · slide 3 about 35 s · slide 4 about 45 s · close 10 s.

How to read this: one line is one breath. Press right arrow, space or click at each `[CLICK ...]` cue, then speak the lines under it. The cues match the build steps in `SPEC.md` (`data-step` 1, 2, 3 ... on each slide). Left arrow steps back one build.

---

## Slide 1: Intro and problem · 0:00 to 0:40 · 84 words (plus about 15 for your named user)

```text
This is deRoute.
Private AI you can verify.

[CLICK 1: three people appear: clinician, lawyer, developer]
Some people need AI most for the work they can't share.
A clinician with patient notes.
A lawyer with client contracts.
A developer with production keys.
[Name your real user here: "<name>, a <role> who ..."]

[CLICK 2: the message flows through app, cloud and model host, each with an open eye]
Today, their words pass through an app, a cloud and a model host.
Each one can read them.
All they get is a privacy policy: a promise they can't check.

[CLICK 3: the eyes close into seals, orange seal on the last]
deRoute shuts those eyes.
Your words open only inside a sealed computer.
You don't trust us. You check the proof.

[CLICK: next slide]
```

---

## Slide 2: How we guarantee the bubble and the pipeline · 0:40 to 1:30 · 116 words

```text
Here's the pipeline.

[CLICK 1: your device: words turn into placeholder chips, Arc badge below]
On your device, a filter swaps personal details for placeholders.
Its fingerprint is on Arc, a public blockchain.
If your copy doesn't match, nothing is sent.

[CLICK 2: three sealed 4,096-byte blocks, then the blind relay]
Then your message is sealed for one machine only,
and padded to four kilobytes, so size gives nothing away.
Our relay passes it on blind.

[CLICK 3: the bubble: seven checks light up, C1 to C7 (they take about 2 seconds; keep talking)]
This is the bubble: a sealed computer even its operator can't see into.
Your browser runs seven checks first.
Genuine hardware? Our released code? The pinned model?
If one fails, nothing is sent.

[CLICK 4: the reply comes back and the chips turn back into real words]
The reply comes back,
and your details are put back on your device.

[CLICK 5: hourly checks, public log]
And every hour, we recheck all six sealed computers,
with the results in a public log.

[CLICK: next slide]
```

---

## Slide 3: Arc payments and the open registry · 1:30 to 2:05 · 80 words

```text
Paying shouldn't give you away either.

[CLICK 1: a wallet pays USDC into a one-time deposit address]
You pay in USDC, a digital dollar, on Arc,
to a deposit address that's used once.

[CLICK 2: the payment becomes credits, stamped "blind"]
That buys credits we sign blind,
like signing through a sealed envelope.
We never see what we signed.

[CLICK 3: one-time spend codes drop into the jar, broken chain]
Each message spends one credit with a one-time code,
so nothing is spent twice,
and nothing links your payment to your prompts.
Sign-in is a passkey. No email.

[CLICK 4: sealed computers stake USDC in the open registry on Arc]
And sealed computers join an open registry on Arc
by staking USDC.

[CLICK: next slide]
```

---

## Slide 4: Gemini 4 Argon and MongoDB Atlas · 2:05 to 2:50 · 106 words

```text
Now, our two tracks.

[CLICK 1: content-free outline passes the 67-bit gate to Gemini inside Confidential Space; plan comes back]
Gemini 4 Argon plans our agent's steps
from an outline with none of your words:
task type, rough size, counts, checks.
A strict gate caps each request at about sixty-seven bits,
fixed choices, never free text.
The planner runs in Google Confidential Space, a sealed machine,
and passes eleven of eleven checks.
Gemini plans. It never reads.

[CLICK 2: all sixteen library documents travel to the device]
MongoDB Atlas holds our public reference library.
For private runs, your device downloads the whole library,
the same for everyone,
so MongoDB never learns what you looked up.

[CLICK 3: $vectorSearch and $search merge into $rankFusion]
Public search runs on Atlas:
vector search for meaning, Atlas Search for keywords,
merged with rank fusion.
```

### Close · 2:50 to 3:00 · 25 words

```text
[CLICK 4: closing strip with the deRoute mark, links and QR code]
It's live right now. Scan the code,
or go to drouter-demo dot vercel dot app.

Private AI you can check, not just trust.
Thank you.

[END: last slide; leave the QR code up for questions]
```

---

## Likely judge questions (30 seconds each, at most)

**1. What if the filter misses something?**
Then it still only reaches the sealed computer. The message is encrypted to that machine's verified key, so the relay, the cloud and the host operator still can't read it. The filter is the first layer, and it's why even the model sees placeholders. You can also force-hide anything by wrapping it in double pound signs, and once something is hidden, it stays hidden for the whole conversation.

**2. How do you know the sealed computer runs your code?**
Before sending anything, your browser checks the machine's signed hardware report. Seven checks: a genuine hardware signature, approved software, an encryption key bound to that hardware, running code that equals our public release, confidential GPUs, admission in the Arc registry, and the pinned model. If any fails, nothing is sent. Every hour a monitor rechecks all six machines into a public log, and anyone can rerun them with one command.

**3. What does Google see, exactly?**
One small outline: the task type, a power-of-two size bucket, rounded counts of hidden details, which checks to run, and which tools are allowed. No user text, no names, no search queries. A closed-schema gate rejects anything outside that exact form, which caps each request at about sixty-seven bits. We call Gemini with storage turned off, and every Google-bound request is signed by the Confidential Space machine's hardware key and logged.

**4. Why MongoDB if lookups are private?**
Because the database still does real work; it just never gets anyone's secrets. Atlas runs our public hybrid search: vector search on seven-hundred-sixty-eight-dimension embeddings plus full-text search, fused with rank fusion on MongoDB 8.0. It also stores the transparency log, the hourly monitor runs and anonymous payment records. Private runs download the whole sixteen-document library, so lookups reveal nothing. No collection holds prompts, names or IP addresses.

**5. How do payments stay unlinkable?**
Three breaks in the chain. Each invoice gets a one-time USDC deposit address on Arc. That payment buys credits we sign blind, with twenty-forty-eight-bit RSA blind signatures, so when a credit is spent we can't match it to its payment. Each credit is spent with a one-time code, which stops double spending without saying who you are. And accounts are a passkey or six words, never an email.

**6. What's real, and what's testnet?**
Arc is testnet: the filter fingerprint, the registry stakes, the log anchors and the USDC payments are on Circle's Arc testnet, so it's test money. Everything else is live: the app, the on-device filter, the six sealed computers and their hourly checks, Gemini 4 Argon planning in Confidential Space, and MongoDB Atlas search. We built all of it during this hackathon, and the code is public on GitHub.

---

## Delivery tips

- **Pace:** about 145 words per minute, one line per breath. Time checks: slide 2 by 0:40, slide 3 by 1:30, slide 4 by 2:05, closing strip by 2:50.
- **If you run long:** drop "the same for everyone" and "fixed choices, never free text". That saves about 4 seconds.
- **Rehearse a single build:** open `https://deroute-deck.vercel.app/#2.3` to start slide 2 at click 3 (`#n` alone shows slide n fully built).
- **Click, then talk:** each cue sits just before the line about that visual. Press, let it fade in for half a second, then speak.
- **Pause for one beat** after "the work they can't share", after your named user, after each "nothing is sent", and after "sixty-seven bits". Stop for two full seconds before "Private AI you can check, not just trust." Say nothing after "Thank you."
- **Point at:** the open eyes, then the orange seal (slide 1); the placeholder chips, then the seven dots around the bubble (slide 2); the broken chain (slide 3); the sixty-seven-bit gate, then the sixteen documents moving to the device (slide 4); the QR code at the end.
- **Say it right:** "dee-route", "U-S-D-C", "Gemini four Argon". Spell the URL the way your team says it.
- **Your named user:** name and role only, with their permission, in one sentence of about 15 words.
- **Don't say:** "mainnet", "fully decentralized" or "nobody can see your IP address". Say "Arc testnet", "open registry" and "our relay is blind to your message".
