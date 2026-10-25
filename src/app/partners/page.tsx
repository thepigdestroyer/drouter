import type { Metadata } from "next";
import { AuthPill } from "@/components/auth-pill";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  ARCHITECTURE_DOCS_GITHUB_URL,
  ATLAS_TECHNICAL_SPEC,
  BACKEND_PARTNERS,
  BACKEND_PARTNERS_INTRO,
  CONFIDENTIAL_SPACE_DOCS_GITHUB_URL,
  GOOGLE_EGRESS_CAPACITY_TABLE,
  SPLIT_KNOWLEDGE_EXPLAINER,
} from "@/app/about/backend-partners-data";

export {
  ARCHITECTURE_DOCS_GITHUB_URL,
  ATLAS_TECHNICAL_SPEC,
  BACKEND_PARTNERS,
  BACKEND_PARTNERS_INTRO,
  CONFIDENTIAL_SPACE_DOCS_GITHUB_URL,
  GOOGLE_EGRESS_CAPACITY_TABLE,
  SPLIT_KNOWLEDGE_EXPLAINER,
};

export const metadata: Metadata = {
  title: "Backend partners · deRoute",
  description: BACKEND_PARTNERS_INTRO.lead,
};

const GEMINI_PARTNER = BACKEND_PARTNERS[0];
const ATLAS_PARTNER = BACKEND_PARTNERS[1];

export default function BackendPartnersPage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/partners" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        className="mx-auto w-full max-w-5xl flex-1 min-w-0 space-y-12 px-4 py-10 sm:px-6"
      >
        <InkReveal>
          <section
            id="backend-partners"
            aria-label="Backend partners"
            className="space-y-6 scroll-mt-6"
          >
            <div className="space-y-1.5">
              <div className="ep-label">{BACKEND_PARTNERS_INTRO.eyebrow}</div>
              <h1 className="ep-display text-2xl sm:text-3xl">
                {BACKEND_PARTNERS_INTRO.heading}
              </h1>
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
      </main>

      <SpecimenFooter />
    </div>
  );
}
