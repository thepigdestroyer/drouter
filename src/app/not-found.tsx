import type { Metadata } from "next";
import Link from "next/link";
import { AuthPill } from "@/components/auth-pill";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";

export const metadata: Metadata = {
  title: "Page not found",
  description: "We could not find that page on deRoute.",
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
        <InkReveal>
          <section
            aria-labelledby="not-found-heading"
            className="ep-card space-y-5 p-6 sm:p-8"
          >
            <div className="space-y-2 border-b border-rule pb-5">
              <div className="ep-label">Page not found</div>
              <h1
                id="not-found-heading"
                className="ep-display text-3xl sm:text-4xl"
              >
                We could not find that page.
              </h1>
              <p className="max-w-[60ch] text-sm text-ink-2 sm:text-base">
                The link you followed may be out of date, or the address may
                have a typo. Pick one of the pages below to keep going.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Link
                href="/"
                className="ep-inset block p-4 transition-colors hover:bg-paper-3"
              >
                <div className="ep-label">Start here</div>
                <div className="mt-0.5 font-serif text-lg text-ink">
                  Home page
                </div>
                <p className="mt-1 text-xs text-ink-2">
                  See what deRoute does in plain words and why nobody can read
                  your questions.
                </p>
              </Link>

              <Link
                href="/explain"
                className="ep-inset block p-4 transition-colors hover:bg-paper-3"
              >
                <div className="ep-label">Interactive guide</div>
                <div className="mt-0.5 font-serif text-lg text-ink">
                  How it works
                </div>
                <p className="mt-1 text-xs text-ink-2">
                  Follow your message step by step and play the quick privacy
                  game.
                </p>
              </Link>

              <Link
                href="/app"
                className="ep-inset block p-4 transition-colors hover:bg-paper-3"
              >
                <div className="ep-label">Private chat</div>
                <div className="mt-0.5 font-serif text-lg text-ink">
                  Ask an AI model
                </div>
                <p className="mt-1 text-xs text-ink-2">
                  Hide your personal details automatically and talk to a sealed
                  computer.
                </p>
              </Link>

              <Link
                href="/about"
                className="ep-inset block p-4 transition-colors hover:bg-paper-3"
              >
                <div className="ep-label">Honest overview</div>
                <div className="mt-0.5 font-serif text-lg text-ink">
                  About deRoute
                </div>
                <p className="mt-1 text-xs text-ink-2">
                  Read what deRoute protects today and where its honest limits
                  are.
                </p>
              </Link>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <InkButton href="/" variant="primary">
                Go to home page
              </InkButton>
              <InkButton href="/login" variant="ghost">
                Sign in
              </InkButton>
            </div>
          </section>
        </InkReveal>
      </main>

      <SpecimenFooter />
    </div>
  );
}
