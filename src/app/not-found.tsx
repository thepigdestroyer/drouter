import type { Metadata } from "next";
import Link from "next/link";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";

export const metadata: Metadata = {
  title: "Page Not Found",
  description: "The requested route does not exist on dRouter.",
};

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink">
      <SpecimenHeader rightSlot={<AuthPill />} />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center gap-6 px-4 py-14 sm:px-6"
      >
        <section aria-labelledby="not-found-heading" className="ep-card p-6 sm:p-8 space-y-5">
          <div className="space-y-2 border-b border-rule pb-5">
            <div className="ep-label">HTTP 404 · Route Not Found</div>
            <h1 id="not-found-heading" className="ep-display text-3xl sm:text-4xl">
              This page does not exist.
            </h1>
            <p className="max-w-[60ch] text-sm sm:text-base text-ink-2">
              The address you opened does not match any route in dRouter. Choose one of the verified pages below.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Link
              href="/"
              className="ep-inset p-4 transition-colors hover:bg-paper-3 block"
            >
              <div className="ep-label">Console</div>
              <div className="font-serif text-lg text-ink mt-0.5">Encrypted chat</div>
              <p className="mt-1 text-xs text-ink-2">
                Verify hardware enclaves and send HPKE-encrypted prompts.
              </p>
            </Link>

            <Link
              href="/explain"
              className="ep-inset p-4 transition-colors hover:bg-paper-3 block"
            >
              <div className="ep-label">Guide</div>
              <div className="font-serif text-lg text-ink mt-0.5">How it works</div>
              <p className="mt-1 text-xs text-ink-2">
                Inspect wire frames and try the interactive walkthrough.
              </p>
            </Link>

            <Link
              href="/audit"
              className="ep-inset p-4 transition-colors hover:bg-paper-3 block"
            >
              <div className="ep-label">Verification</div>
              <div className="font-serif text-lg text-ink mt-0.5">Proof and audit</div>
              <p className="mt-1 text-xs text-ink-2">
                Check external hardware certificates, Sigstore logs, and threat scenarios.
              </p>
            </Link>

            <Link
              href="/network"
              className="ep-inset p-4 transition-colors hover:bg-paper-3 block"
            >
              <div className="ep-label">Registry</div>
              <div className="font-serif text-lg text-ink mt-0.5">Network directory</div>
              <p className="mt-1 text-xs text-ink-2">
                View registered nodes on Circle Arc Testnet and hour-coarsened logs.
              </p>
            </Link>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Link href="/" className="ep-btn">
              Return to console
            </Link>
            <Link href="/login" className="ep-btn-ghost">
              Passphrase vault
            </Link>
          </div>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
