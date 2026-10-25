import { connection } from "next/server";
import { Suspense } from "react";
import { AuthPill } from "@/components/auth-pill";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { SPEC_V2_ROADMAP } from "@/lib/providers/catalog";
import { getAllProvidersLiveStatus } from "@/lib/providers/live-status";
import { ProviderCatalogClient } from "./provider-catalog-client";
import {
  ARCHITECTURE_DOCS_GITHUB_URL,
  ATLAS_TECHNICAL_SPEC,
  BACKEND_PARTNERS,
  BACKEND_PARTNERS_INTRO,
  CONFIDENTIAL_SPACE_DOCS_GITHUB_URL,
  GOOGLE_EGRESS_CAPACITY_TABLE,
  SPLIT_KNOWLEDGE_EXPLAINER,
} from "./backend-partners-data";

export {
  ARCHITECTURE_DOCS_GITHUB_URL,
  ATLAS_TECHNICAL_SPEC,
  BACKEND_PARTNERS,
  BACKEND_PARTNERS_INTRO,
  CONFIDENTIAL_SPACE_DOCS_GITHUB_URL,
  GOOGLE_EGRESS_CAPACITY_TABLE,
  SPLIT_KNOWLEDGE_EXPLAINER,
};

export const HONEST_LIMITS = [
  {
    plainTitle: "The AI reads your words inside a sealed computer",
    plainSummary:
      "To answer quickly, the AI unlocks your message inside a sealed computer chip. Pure math tricks that never unlock your words are still far too slow for full chat answers today.",
    title:
      "Plaintext runs inside attested hardware enclaves (not frontier LLM FHE)",
    detail:
      "The launch tier decrypts and runs prompts inside hardware-attested Trusted Execution Environments (TEEs). Pure homomorphic encryption (FHE) and multi-party computation (MPC) cannot reach usable interactive speed for frontier models today.",
  },
  {
    plainTitle: "Our pure-math mode only handles tiny sorting tasks",
    plainSummary:
      "We include a special math mode that scores a short list of numbers without ever unlocking them, but it can only do simple sorting, not write full paragraphs.",
    title:
      "FHE Tier C is a real small CKKS linear classifier, not a frontier LLM",
    detail:
      "Live Tier C (node-seal 7.0.0 / Microsoft SEAL 4.1.2 WASM at /api/ashi) executes a real CKKS homomorphic linear computation (4x128 matrix-vector dot products plus encrypted squared L2 norm over a 128-dimensional embedding vector, N=4096, 128-bit security) where the server never sees plaintext or the secret key.",
  },
  {
    plainTitle: "The code runner is a clean temporary room, not a sealed chip",
    plainSummary:
      "When the agent runs a small program for you, it uses a fresh, isolated temporary computer that wipes itself afterward, but that room does not have the same hardware seal as the main AI computer.",
    title:
      "Vercel Sandbox is an isolated Firecracker microVM, not a hardware TEE",
    detail:
      "Tool execution at /api/sandbox runs inside a Vercel Sandbox Firecracker microVM (@vercel/sandbox 3.9.0, 1 vCPU, ephemeral filesystem, zero host environment variables passed). It provides hypervisor-level microVM isolation, not an AMD SEV-SNP or Intel TDX hardware-attested enclave.",
  },
  {
    plainTitle: "Each chat has a size limit",
    plainSummary:
      "The main sealed AI brain (Kimi K3) can hold about 200,000 words at once (262,144 pieces of text), while the outer planner only sees safe summaries with your personal details removed.",
    title: "Tinfoil router and Kimi K3 enclave topology (262,144 token limit)",
    detail:
      "The live Tinfoil router (router-0.tinfoil.sh) attests with AMD SEV-SNP. The Kimi K3 model enclave (kimi-k3-inf14.tinfoil.containers.tinfoil.dev) runs on Intel TDX plus NVIDIA confidential-computing GPUs with a maximum context length of 262,144 tokens, not 1M. Gemini 4 Argon supports 1,000,000 tokens for outer orchestration over scrubbed metadata.",
  },
  {
    plainTitle: "A safety filter checks for harmful misuse",
    plainSummary:
      "The sealed router runs an automated safety check inside the seal to block severe misuse and reports rule violations to Tinfoil.",
    title: "Tinfoil safeguards classifier and usage sidecars",
    detail:
      "Tinfoil's router runs a safeguards acceptable-use classifier sidecar (gpt-oss-safeguard-120b with kimi-k3 review) that reports policy violations to https://api.tinfoil.sh, plus a usage reporter.",
  },
  {
    plainTitle: "Device sign-in sync knows this website exists",
    plainSummary:
      "When you sign in with your fingerprint, face, or device, deRoute never learns who you are, but Apple or Google sync knows that your device saved a login for this site.",
    title: "WebAuthn PRF passkey sync metadata visibility",
    detail:
      "Passkey credentials use WebAuthn PRF with attestation='none' and a random 32-byte user handle so our server stores nothing and never learns your identity. However, your OS passkey provider (iCloud Keychain or Google Password Manager) can observe the relying party domain (rpId) when syncing your passkey end-to-end encrypted.",
  },
  {
    plainTitle: "Hardware seals are strong, not magic",
    plainSummary:
      "A sealed computer locks out the server owner's software, but a determined attacker with physical lab tools or an undiscovered chip flaw is still a real-world risk.",
    title: "TEEs are not perfect (physical memory-bus attacks exist)",
    detail:
      "Hardware enclaves reduce trust in the cloud host, but they are not invincible. Physical memory-bus interposers such as TEE.fail can probe deterministic CPU RAM lines on socketed DDR5 DIMMs, and silicon firmware bugs remain a real risk.",
  },
  {
    plainTitle: "Outside observers can still see when you connect",
    plainSummary:
      "Even though every message looks the same size from outside and is locked, the network can still see the time you connected and roughly how many blocks you sent.",
    title: "Timing and size buckets remain visible",
    detail:
      "Encryption and 4,096-byte bucket padding hide your text, but the relay and network operator still observe when a request happens and which coarse byte bucket it falls into.",
  },
] as const;

const WHO_IT_IS_FOR = [
  {
    title: "People asking personal life, health, or money questions",
    description:
      "Ask sensitive questions without tying them to your email address or leaving a permanent copy on a company server.",
  },
  {
    title: "Writers, researchers, and small teams",
    description:
      "Draft notes, review documents, or think through hard problems knowing your personal details are hidden before anything leaves your device.",
  },
  {
    title: "Anyone who prefers proof over privacy promises",
    description:
      "Instead of trusting a fine-print policy, your browser runs a seal check on the sealed computer and lets you verify every record in a public receipt book.",
  },
] as const;

async function LiveProviderDirectorySection() {
  await connection();
  const liveStatusById = await getAllProvidersLiveStatus();
  return <ProviderCatalogClient liveStatusById={liveStatusById} />;
}

const GEMINI_PARTNER = BACKEND_PARTNERS[0];
const ATLAS_PARTNER = BACKEND_PARTNERS[1];

export default function AboutArchitecturePage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/about" rightSlot={<AuthPill />} />

      <main className="mx-auto w-full max-w-5xl flex-1 min-w-0 space-y-12 px-4 py-10 sm:px-6">
        {/* 1. What deRoute is & What the name means */}
        <InkReveal>
          <section className="space-y-6 border-b border-rule pb-8">
            <div className="space-y-3">
              <div className="ep-label">About deRoute</div>
              <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
                Private AI that locks out the middleman
              </h1>
              <p className="max-w-[68ch] text-base sm:text-lg leading-relaxed text-ink-2">
                Normal AI websites ask you to trust their privacy policy while
                reading your words in plain text at the front door. deRoute
                hides your personal details on your own device, makes every
                message look the same size from outside, and locks your question
                so only a sealed computer can open it.
              </p>
            </div>

            {/* What the name means */}
            <div className="ep-inset p-5 space-y-2">
              <div className="ep-label">What the name means</div>
              <h2 className="font-serif text-lg sm:text-xl font-medium text-ink">
                deRoute = decentralized-encrypted route
              </h2>
              <p className="max-w-[68ch] text-sm sm:text-base leading-relaxed text-ink-2">
                The name <span className="font-medium text-ink">deRoute</span>{" "}
                is short for{" "}
                <span className="font-medium text-ink">
                  decentralized-encrypted route
                </span>
                . Instead of handing your plain words to one central company,
                your browser checks the seal on an independent sealed computer
                and sends your locked message along a route that our web server
                cannot read.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <InkButton href="/app" variant="accent">
                Open chat
              </InkButton>
              <InkButton href="/explain" variant="ghost">
                How it works
              </InkButton>
              <InkButton href="/audit" variant="ghost">
                See the proof
              </InkButton>
            </div>
          </section>
        </InkReveal>

        {/* 2. Who it is for */}
        <InkReveal delayMs={60}>
          <section aria-label="Who deRoute is for" className="space-y-4">
            <div className="space-y-1">
              <div className="ep-label">Who it is for</div>
              <h2 className="ep-display text-2xl sm:text-3xl">
                Built for anyone who wants a private conversation
              </h2>
              <p className="max-w-[68ch] text-sm text-ink-2 leading-relaxed">
                You do not need any technical background to use deRoute. Sign in
                with your fingerprint, face, or device in 10 seconds with no
                email and no password.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {WHO_IT_IS_FOR.map((item) => (
                <div key={item.title} className="ep-card p-5 space-y-2">
                  <h3 className="font-serif text-base font-medium text-ink">
                    {item.title}
                  </h3>
                  <p className="text-sm leading-relaxed text-ink-2">
                    {item.description}
                  </p>
                </div>
              ))}
            </div>
          </section>
        </InkReveal>

        {/* 3. Honest limits in plain words */}
        <InkReveal delayMs={100}>
          <section aria-label="Honest limits" className="space-y-4">
            <div className="space-y-1">
              <div className="ep-label">Honest limits</div>
              <h2 className="ep-display text-2xl sm:text-3xl">
                What deRoute can and cannot do
              </h2>
              <p className="max-w-[68ch] text-sm text-ink-2 leading-relaxed">
                A sealed computer is much stronger than a company promise, but
                no system is magic. Here are the honest limits in plain words.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {HONEST_LIMITS.map((limit) => (
                <div key={limit.title} className="ep-card p-4 space-y-1.5">
                  <h3 className="font-serif text-base font-medium text-ink">
                    {limit.plainTitle}
                  </h3>
                  <p className="text-sm leading-relaxed text-ink-2">
                    {limit.plainSummary}
                  </p>
                </div>
              ))}
            </div>

            <TechDetails label="Show technical details">
              <div className="space-y-6 pt-2 text-xs">
                <div className="space-y-3">
                  <div className="ep-label">
                    Technical ground truth and boundary specifications
                  </div>
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    {HONEST_LIMITS.map((limit) => (
                      <div
                        key={limit.title}
                        className="ep-card p-3.5 space-y-1 text-ink-2"
                      >
                        <div className="font-serif text-sm font-medium text-ink">
                          {limit.title}
                        </div>
                        <p className="leading-relaxed">{limit.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-3 border-t border-rule pt-4">
                  <div className="ep-label">Research roadmap (Spec v2)</div>
                  <div className="space-y-2.5">
                    {SPEC_V2_ROADMAP.map((item) => (
                      <div
                        key={item.id}
                        className="ep-card p-3.5 space-y-1.5 text-ink-2"
                      >
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <span className="font-serif text-sm font-medium text-ink">
                            {item.number}. {item.title}
                          </span>
                          <span className="ep-muted-chip">
                            {item.tierTarget}
                          </span>
                        </div>
                        <p>{item.bottleneckSolved}</p>
                        <p className="text-ink-3">
                          Mechanism: {item.mechanism} | Artifact:{" "}
                          {item.verificationArtifact}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </TechDetails>
          </section>
        </InkReveal>

        {/* 4. Backend partners (Google Gemini 4 Argon & MongoDB Atlas) */}
        <InkReveal delayMs={120}>
          <section
            id="backend-partners"
            aria-label="Backend partners"
            className="space-y-6 scroll-mt-6"
          >
            <div className="space-y-1.5">
              <div className="ep-label">{BACKEND_PARTNERS_INTRO.eyebrow}</div>
              <h2 className="ep-display text-2xl sm:text-3xl">
                {BACKEND_PARTNERS_INTRO.heading}
              </h2>
              <p className="max-w-[68ch] text-sm text-ink-2 leading-relaxed">
                {BACKEND_PARTNERS_INTRO.lead}
              </p>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              {/* Partner 1: Gemini 4 Argon */}
              <div className="ep-card p-5 space-y-4 flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 border-b border-rule pb-3">
                    <div className="min-w-0">
                      <div className="ep-label">{GEMINI_PARTNER.roleLabel}</div>
                      <h3 className="font-serif text-xl font-medium text-ink">
                        {GEMINI_PARTNER.name}
                      </h3>
                    </div>
                    <span className="ep-pass self-start shrink-0">
                      Content-free planner
                    </span>
                  </div>

                  <div className="ep-inset p-3.5">
                    <p className="font-serif text-sm sm:text-base font-medium text-ink">
                      &ldquo;{GEMINI_PARTNER.plainPrivacyLine}&rdquo;
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <div className="ep-label">Why it is needed</div>
                    <p className="text-sm leading-relaxed text-ink-2">
                      {GEMINI_PARTNER.whyNeeded}
                    </p>
                  </div>

                  <div className="space-y-2">
                    <div className="ep-label">How it works</div>
                    <ul className="space-y-2 text-sm leading-relaxed text-ink-2 list-disc pl-4">
                      {GEMINI_PARTNER.howItWorks.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="ep-inset p-3.5 space-y-1.5">
                    <div className="ep-label">Honest status notes</div>
                    <ul className="space-y-1.5 text-xs leading-relaxed text-ink-2 list-disc pl-4">
                      {GEMINI_PARTNER.honestNotes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <div className="ep-label">
                    What Google Gemini sees vs. never sees
                  </div>
                  <div className="overflow-x-auto rounded border border-rule">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                          <th className="py-2.5 px-3 w-1/2">What they see</th>
                          <th className="py-2.5 px-3 w-1/2 border-l border-rule">
                            What they never see
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-rule align-top">
                        {GEMINI_PARTNER.visibilityRows.map((row) => (
                          <tr key={row.whatTheySee}>
                            <td className="py-2.5 px-3 leading-relaxed text-ink-2">
                              {row.whatTheySee}
                            </td>
                            <td className="py-2.5 px-3 leading-relaxed text-ink border-l border-rule font-medium">
                              {row.whatTheyNeverSee}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Partner 2: MongoDB Atlas */}
              <div className="ep-card p-5 space-y-4 flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 border-b border-rule pb-3">
                    <div className="min-w-0">
                      <div className="ep-label">{ATLAS_PARTNER.roleLabel}</div>
                      <h3 className="font-serif text-xl font-medium text-ink">
                        {ATLAS_PARTNER.name}
                      </h3>
                    </div>
                    <span className="ep-pass self-start shrink-0">
                      Public facts &amp; receipts
                    </span>
                  </div>

                  <div className="ep-inset p-3.5">
                    <p className="font-serif text-sm sm:text-base font-medium text-ink">
                      &ldquo;{ATLAS_PARTNER.plainPrivacyLine}&rdquo;
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <div className="ep-label">Why it is needed</div>
                    <p className="text-sm leading-relaxed text-ink-2">
                      {ATLAS_PARTNER.whyNeeded}
                    </p>
                  </div>

                  <div className="space-y-2">
                    <div className="ep-label">How it works</div>
                    <ul className="space-y-2 text-sm leading-relaxed text-ink-2 list-disc pl-4">
                      {ATLAS_PARTNER.howItWorks.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="ep-inset p-3.5 space-y-1.5">
                    <div className="ep-label">Timing privacy</div>
                    <ul className="space-y-1.5 text-xs leading-relaxed text-ink-2 list-disc pl-4">
                      {ATLAS_PARTNER.honestNotes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <div className="ep-label">
                    What MongoDB Atlas sees vs. never sees
                  </div>
                  <div className="overflow-x-auto rounded border border-rule">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                          <th className="py-2.5 px-3 w-1/2">What they see</th>
                          <th className="py-2.5 px-3 w-1/2 border-l border-rule">
                            What they never see
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-rule align-top">
                        {ATLAS_PARTNER.visibilityRows.map((row) => (
                          <tr key={row.whatTheySee}>
                            <td className="py-2.5 px-3 leading-relaxed text-ink-2">
                              {row.whatTheySee}
                            </td>
                            <td className="py-2.5 px-3 leading-relaxed text-ink border-l border-rule font-medium">
                              {row.whatTheyNeverSee}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            {/* Split knowledge explainer */}
            <div className="ep-inset p-5 space-y-2">
              <div className="ep-label">{SPLIT_KNOWLEDGE_EXPLAINER.eyebrow}</div>
              <h3 className="font-serif text-lg sm:text-xl font-medium text-ink">
                {SPLIT_KNOWLEDGE_EXPLAINER.heading}
              </h3>
              <p className="max-w-[72ch] text-sm sm:text-base leading-relaxed text-ink-2">
                {SPLIT_KNOWLEDGE_EXPLAINER.body}
              </p>
            </div>

            {/* Technical details: closed-schema capacity table, Atlas index & pipeline spec, and GitHub architecture links */}
            <TechDetails label="Show technical details">
              <div className="space-y-6 pt-2 text-xs">
                <div className="space-y-2">
                  <div className="ep-label">
                    Gemini 4 Argon Closed-Schema Egress Gate and Information Capacity Bound
                  </div>
                  <p className="text-ink-2 leading-relaxed max-w-[76ch]">
                    Every outbound request to Google Gemini (
                    <code className="font-mono text-ink">
                      client.interactions.create
                    </code>{" "}
                    with <code className="font-mono text-ink">model: &quot;gemini-4-argon&quot;</code>{" "}
                    and <code className="font-mono text-ink">store: false</code>) must pass{" "}
                    <code className="font-mono text-ink">
                      assertGoogleBoundMessage
                    </code>{" "}
                    and{" "}
                    <code className="font-mono text-ink">assertContentFree</code>{" "}
                    in{" "}
                    <code className="font-mono text-ink">
                      src/lib/gemini/egress-schemas.ts
                    </code>
                    . All SHA-256 digests are replaced with opaque handles (
                    <code className="font-mono text-ink">$DOC_1..16</code>,{" "}
                    <code className="font-mono text-ink">$RECEIPT_1..16</code>,{" "}
                    <code className="font-mono text-ink">$DIGEST_1..16</code>) before
                    any follow-up turn. The exact{" "}
                    <code className="font-mono text-ink">canonicalRequest</code>{" "}
                    bytes sent to Google are hashed with SHA-256 into the RFC 6962
                    Merkle transparency log and returned in a signed{" "}
                    <code className="font-mono text-ink">
                      GeminiEgressReceipt
                    </code>{" "}
                    verified in the browser by{" "}
                    <code className="font-mono text-ink">
                      verifyEgressReceiptClient
                    </code>
                    .
                  </p>

                  <div className="overflow-x-auto rounded border border-rule">
                    <table className="w-full text-left text-[11px] border-collapse">
                      <thead>
                        <tr className="border-b border-rule bg-paper-2 font-mono uppercase text-ink-3">
                          <th className="py-2 px-3">Message type (kind)</th>
                          <th className="py-2 px-3 border-l border-rule">
                            Variable fields &amp; domain sizes
                          </th>
                          <th className="py-2 px-3 border-l border-rule">
                            Max cardinality
                          </th>
                          <th className="py-2 px-3 border-l border-rule">
                            Max capacity
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-rule align-top">
                        {GOOGLE_EGRESS_CAPACITY_TABLE.map((row) => (
                          <tr key={row.messageKind}>
                            <td className="py-2 px-3 font-mono text-ink">
                              {row.messageKind}
                            </td>
                            <td className="py-2 px-3 border-l border-rule text-ink-2 leading-relaxed">
                              {row.variableFields}
                            </td>
                            <td className="py-2 px-3 border-l border-rule font-mono text-ink-2">
                              {row.maxCardinality}
                            </td>
                            <td className="py-2 px-3 border-l border-rule font-mono font-medium text-ink">
                              {row.maxCapacity}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="space-y-3 border-t border-rule pt-4">
                  <div className="ep-label">
                    MongoDB Atlas Indexes, Pipeline Stages, and Collections
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 font-mono text-[11px]">
                    <div className="ep-card p-3 space-y-1">
                      <div className="text-ink font-medium">Database</div>
                      <div className="text-ink-2">
                        {ATLAS_TECHNICAL_SPEC.databaseName} (test:{" "}
                        {ATLAS_TECHNICAL_SPEC.testDatabaseName})
                      </div>
                    </div>
                    <div className="ep-card p-3 space-y-1">
                      <div className="text-ink font-medium">
                        Search &amp; Vector Indexes
                      </div>
                      <div className="text-ink-2">
                        {ATLAS_TECHNICAL_SPEC.vectorIndexName} (768-dim cosine)
                        &amp; {ATLAS_TECHNICAL_SPEC.textIndexName} (Lucene)
                      </div>
                    </div>
                    <div className="ep-card p-3 space-y-1">
                      <div className="text-ink font-medium">
                        Aggregation Pipeline Stages
                      </div>
                      <div className="text-ink-2">
                        {ATLAS_TECHNICAL_SPEC.pipelineStages.join(", ")}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                    {ATLAS_TECHNICAL_SPEC.collections.map((col) => (
                      <div
                        key={col.name}
                        className="ep-card p-3 space-y-1 text-ink-2"
                      >
                        <div className="font-mono text-xs font-medium text-ink">
                          {col.name}
                        </div>
                        <p className="text-[11px] leading-relaxed">
                          {col.purpose}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-4 border-t border-rule pt-4 font-mono text-xs">
                  <a
                    href={ARCHITECTURE_DOCS_GITHUB_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ep-link"
                  >
                    docs/ARCHITECTURE.md on GitHub -&gt;
                  </a>
                  <a
                    href={CONFIDENTIAL_SPACE_DOCS_GITHUB_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ep-link"
                  >
                    docs/confidential-space.md on GitHub -&gt;
                  </a>
                </div>
              </div>
            </TechDetails>
          </section>
        </InkReveal>

        {/* 5. Simplified Provider Comparison */}
        <InkReveal delayMs={140}>
          <Suspense
            fallback={
              <div className="ep-card p-5 font-mono text-xs text-ink-3">
                Checking private AI providers (cached 1 hour)...
              </div>
            }
          >
            <LiveProviderDirectorySection />
          </Suspense>
        </InkReveal>
      </main>

      <SpecimenFooter />
    </div>
  );
}
