import type { Metadata } from "next";
import Link from "next/link";
import { AuthPill } from "@/components/auth-pill";
import { EnclaveGauntlet } from "@/components/game/enclave-gauntlet";
import { PacketSniffer } from "@/components/packet-sniffer";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";

export const metadata: Metadata = {
  title: "How it works · dRouter",
  description:
    "How your browser verifies confidential hardware, encrypts your prompt, runs the model inside sealed memory, and destroys the session key when you leave.",
};

export default function ExplainPage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/explain" rightSlot={<AuthPill />} />

      <main className="mx-auto w-full max-w-5xl flex-1 space-y-12 px-4 py-10 sm:px-6">
        {/* Hero */}
        <section className="space-y-4 border-b border-rule pb-8">
          <div className="ep-label">How it works</div>
          <h1 className="ep-display text-3xl sm:text-4xl">
            Four steps from your browser to sealed hardware and back.
          </h1>
          <p className="max-w-[68ch] text-base leading-relaxed text-ink-2">
            Instead of trusting a cloud privacy policy, your browser checks a signed hardware report and encrypts your prompt directly to the enclave before sending a single word.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <Link href="/" className="ep-btn">
              Open console
            </Link>
            <Link href="/about" className="ep-btn-ghost">
              Limits &amp; provider directory
            </Link>
          </div>
        </section>

        {/* 4-Step Story with Inline Ink SVG Diagrams */}
        <section className="space-y-4">
          <div className="ep-label">The four steps</div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* Step 1 */}
            <div className="ep-card p-4 flex flex-col justify-between gap-4">
              <div className="space-y-2">
                <div className="ep-label">Step 1 · Verify</div>
                <svg
                  viewBox="0 0 120 64"
                  className="h-14 w-full text-ink"
                  fill="none"
                  aria-hidden="true"
                >
                  <rect
                    x="8"
                    y="12"
                    width="38"
                    height="40"
                    rx="3"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <line
                    x1="15"
                    y1="23"
                    x2="39"
                    y2="23"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                  <line
                    x1="15"
                    y1="31"
                    x2="34"
                    y2="31"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                  <path
                    d="M48 32 H74"
                    stroke="currentColor"
                    strokeWidth="1.2"
                    strokeDasharray="3 3"
                  />
                  <circle
                    cx="92"
                    cy="32"
                    r="16"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M85 32 L90 37 L100 26"
                    stroke="var(--color-accent)"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                <p className="text-sm leading-relaxed text-ink">
                  Your browser checks the hardware&apos;s signed report before sending anything.
                </p>
              </div>
            </div>

            {/* Step 2 */}
            <div className="ep-card p-4 flex flex-col justify-between gap-4">
              <div className="space-y-2">
                <div className="ep-label">Step 2 · Scrub &amp; Encrypt</div>
                <svg
                  viewBox="0 0 120 64"
                  className="h-14 w-full text-ink"
                  fill="none"
                  aria-hidden="true"
                >
                  <rect
                    x="8"
                    y="18"
                    width="34"
                    height="28"
                    rx="3"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <line
                    x1="14"
                    y1="28"
                    x2="36"
                    y2="28"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                  <line
                    x1="14"
                    y1="36"
                    x2="30"
                    y2="36"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                  <path
                    d="M46 32 H72"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M68 28 L73 32 L68 36"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <rect
                    x="78"
                    y="26"
                    width="28"
                    height="22"
                    rx="3"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M84 26 V20 C84 15.5 100 15.5 100 20 V26"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <circle cx="92" cy="37" r="2" fill="currentColor" />
                </svg>
                <p className="text-sm leading-relaxed text-ink">
                  It scrubs personal details and encrypts the message to that hardware&apos;s key.
                </p>
              </div>
            </div>

            {/* Step 3 */}
            <div className="ep-card p-4 flex flex-col justify-between gap-4">
              <div className="space-y-2">
                <div className="ep-label">Step 3 · Run in Enclave</div>
                <svg
                  viewBox="0 0 120 64"
                  className="h-14 w-full text-ink"
                  fill="none"
                  aria-hidden="true"
                >
                  <rect
                    x="24"
                    y="10"
                    width="72"
                    height="44"
                    rx="4"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeDasharray="4 2"
                  />
                  <rect
                    x="38"
                    y="18"
                    width="44"
                    height="28"
                    rx="2"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <line
                    x1="46"
                    y1="27"
                    x2="74"
                    y2="27"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                  <line
                    x1="46"
                    y1="35"
                    x2="66"
                    y2="35"
                    stroke="currentColor"
                    strokeWidth="1.2"
                  />
                </svg>
                <p className="text-sm leading-relaxed text-ink">
                  The sealed hardware runs the model and nobody outside can read memory.
                </p>
              </div>
            </div>

            {/* Step 4 */}
            <div className="ep-card p-4 flex flex-col justify-between gap-4">
              <div className="space-y-2">
                <div className="ep-label">Step 4 · Destroy Key</div>
                <svg
                  viewBox="0 0 120 64"
                  className="h-14 w-full text-ink"
                  fill="none"
                  aria-hidden="true"
                >
                  <circle
                    cx="40"
                    cy="32"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M50 32 H86 M76 32 V40 M84 32 V38"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                  <line
                    x1="28"
                    y1="16"
                    x2="92"
                    y2="48"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
                <p className="text-sm leading-relaxed text-ink">
                  The session key is destroyed when you leave.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Interactive 4-round Game */}
        <section className="space-y-3">
          <div className="space-y-1">
            <div className="ep-label">Interactive Walkthrough</div>
            <h2 className="ep-display text-2xl">Test each guarantee in four quick rounds</h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Play through the four rounds below to see how hardware attestation, blind credits, and memory wiping work in practice.
            </p>
          </div>
          <EnclaveGauntlet />
        </section>

        {/* What each party sees */}
        <section className="space-y-3">
          <div className="space-y-1">
            <div className="ep-label">Wire Inspection</div>
            <h2 className="ep-display text-2xl">What each party sees</h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Type any sample message below to compare what stays on your device, what crosses the network relay, and what enters enclave memory.
            </p>
          </div>
          <PacketSniffer />
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
