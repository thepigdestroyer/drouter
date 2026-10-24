import Link from "next/link";
import { Console } from "@/components/console";
import { SpecimenHeader, SpecimenFooter } from "@/components/specimen-chrome";
import { AuthPill } from "@/components/auth-pill";

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden bg-paper text-ink">
      <SpecimenHeader activePath="/" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-10 px-4 py-8 sm:px-6 sm:py-12"
      >
        <section aria-labelledby="home-hero-heading" className="max-w-[70ch]">
          <div className="ep-label">Confidential AI Router</div>
          <h1
            id="home-hero-heading"
            className="ep-display mt-2 text-3xl sm:text-4xl lg:text-5xl"
          >
            Ask frontier AI models without anyone, including us, reading your prompt.
          </h1>
          <p className="mt-3 text-base text-ink-2">
            Your browser checks the hardware first, then encrypts your message so only that sealed hardware can open it.
          </p>
        </section>

        <section aria-label="Encrypted chat console">
          <Console />
        </section>

        <section
          aria-label="Learn more and verify"
          className="grid grid-cols-1 gap-4 border-t border-rule pt-8 sm:grid-cols-3"
        >
          <Link
            href="/explain"
            className="ep-card flex flex-col justify-between p-5 transition-colors hover:bg-paper-2"
          >
            <div>
              <div className="ep-label">Interactive Guide</div>
              <h2 className="ep-display mt-1.5 text-xl">How it works</h2>
              <p className="mt-2 text-sm text-ink-2">
                See what leaves your browser on the wire and try four short experiments on memory encryption and blind credits.
              </p>
            </div>
            <span className="mt-4 text-xs font-medium text-ink underline underline-offset-4">
              Open guide
            </span>
          </Link>

          <Link
            href="/argon"
            className="ep-card flex flex-col justify-between p-5 transition-colors hover:bg-paper-2"
          >
            <div>
              <div className="ep-label">Autonomous Workflow</div>
              <h2 className="ep-display mt-1.5 text-xl">Watch the agent</h2>
              <p className="mt-2 text-sm text-ink-2">
                Inspect how the Gemini 4 Argon agent verifies enclave proofs, scrubs sensitive tokens, and pauses for human approval.
              </p>
            </div>
            <span className="mt-4 text-xs font-medium text-ink underline underline-offset-4">
              Open agent
            </span>
          </Link>

          <Link
            href="/audit"
            className="ep-card flex flex-col justify-between p-5 transition-colors hover:bg-paper-2"
          >
            <div>
              <div className="ep-label">Hardware &amp; Logs</div>
              <h2 className="ep-display mt-1.5 text-xl">Check the proof</h2>
              <p className="mt-2 text-sm text-ink-2">
                Audit the AMD SEV-SNP and Intel TDX attestation reports, Sigstore build provenance, and adversarial threat checks.
              </p>
            </div>
            <span className="mt-4 text-xs font-medium text-ink underline underline-offset-4">
              Open proof
            </span>
          </Link>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
