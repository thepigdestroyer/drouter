import React from "react";
import { SpecimenHeader, SpecimenFooter } from "@/components/specimen-chrome";
import { AuthPill } from "@/components/auth-pill";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import {
  FAQ_ITEMS,
  HERO_COPY,
  REASSURANCE_POINTS,
} from "./landing-copy";
import { StoryStepper } from "./story-stepper";
import { LiveScrubDemo } from "./live-scrub-demo";

export function LandingPage() {
  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden text-ink">
      <SpecimenHeader activePath="/" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-14 px-4 py-8 sm:px-6 sm:py-14"
      >
        {/* 1. First screen: Plain explainer + clear way in */}
        <InkReveal>
          <section
            aria-labelledby="home-hero-heading"
            className="flex flex-col justify-between gap-6 border-b border-rule pb-10"
          >
            <div className="max-w-[68ch]">
              <div className="ep-label">{HERO_COPY.eyebrow}</div>
              <h1
                id="home-hero-heading"
                className="ep-display mt-2.5 text-3xl sm:text-5xl lg:text-[52px]"
              >
                {HERO_COPY.headline}
              </h1>
              <p className="mt-4 text-base leading-relaxed text-ink-2 sm:text-lg">
                {HERO_COPY.subheadline}
              </p>
            </div>

            <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
              <InkButton variant="accent" href={HERO_COPY.primaryCtaHref}>
                {HERO_COPY.primaryCtaLabel}
              </InkButton>
              <InkButton variant="ghost" href={HERO_COPY.secondaryCtaHref}>
                {HERO_COPY.secondaryCtaLabel}
              </InkButton>
              <span className="text-xs text-ink-3 sm:ml-2">
                {HERO_COPY.quickNote}
              </span>
            </div>
          </section>
        </InkReveal>

        {/* 2. Interactive 4-step story with everyday metaphors */}
        <InkReveal delayMs={60}>
          <section aria-labelledby="how-it-works-story-heading" className="space-y-4">
            <div className="max-w-[68ch]">
              <div className="ep-label">How deRoute works in four steps</div>
              <h2
                id="how-it-works-story-heading"
                className="ep-display mt-1.5 text-2xl sm:text-3xl"
              >
                A locked envelope for a sealed computer
              </h2>
              <p className="mt-2 text-sm text-ink-2">
                Click through the four steps below to see what happens to your words from the moment you type them to the moment you close the tab.
              </p>
            </div>

            <StoryStepper />
          </section>
        </InkReveal>

        {/* 3. Real-time browser personal details hider */}
        <InkReveal delayMs={120}>
          <section aria-labelledby="live-scrub-heading" className="space-y-4">
            <div className="max-w-[68ch]">
              <div className="ep-label">Interactive test</div>
              <h2
                id="live-scrub-heading"
                className="ep-display mt-1.5 text-2xl sm:text-3xl"
              >
                Watch your personal details get hidden in real time
              </h2>
              <p className="mt-2 text-sm text-ink-2">
                We hide your personal details before anything leaves your device. Type a sentence below with a fake email address or phone number to see what leaves your browser.
              </p>
            </div>

            <LiveScrubDemo />

            <div className="flex flex-wrap items-center justify-between gap-4 rounded border border-rule bg-paper-2 px-5 py-4">
              <div>
                <p className="text-sm font-medium text-ink">
                  Ready to try a full private chat with the AI?
                </p>
                <p className="text-xs text-ink-2">
                  Takes 10 seconds to create an anonymous account on your device.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <InkButton variant="primary" href={HERO_COPY.primaryCtaHref}>
                  {HERO_COPY.primaryCtaLabel}
                </InkButton>
                <InkButton variant="ghost" href={HERO_COPY.secondaryCtaHref}>
                  {HERO_COPY.secondaryCtaLabel}
                </InkButton>
              </div>
            </div>
          </section>
        </InkReveal>

        {/* 4. Three short reassurance points */}
        <InkReveal delayMs={160}>
          <section
            aria-labelledby="reassurance-heading"
            className="space-y-4 border-t border-rule pt-10"
          >
            <div className="max-w-[68ch]">
              <div className="ep-label">Why you do not have to trust us</div>
              <h2
                id="reassurance-heading"
                className="ep-display mt-1.5 text-2xl sm:text-3xl"
              >
                Built so nobody in the middle can snoop
              </h2>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              {REASSURANCE_POINTS.map((point) => (
                <div
                  key={point.label}
                  className="ep-card flex flex-col justify-between p-5"
                >
                  <div>
                    <div className="ep-label">{point.label}</div>
                    <h3 className="ep-display mt-1.5 text-xl">{point.title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-ink-2">
                      {point.body}
                    </p>
                  </div>
                  <div className="mt-4 pt-2">
                    <TechDetails label="Show technical details">
                      <p className="text-xs leading-relaxed text-ink-2">
                        {point.techDetail}
                      </p>
                    </TechDetails>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </InkReveal>

        {/* 5. Tiny FAQ */}
        <InkReveal delayMs={200}>
          <section
            aria-labelledby="faq-heading"
            className="space-y-5 border-t border-rule pt-10"
          >
            <div className="max-w-[68ch]">
              <div className="ep-label">Common questions</div>
              <h2
                id="faq-heading"
                className="ep-display mt-1.5 text-2xl sm:text-3xl"
              >
                Quick answers in plain words
              </h2>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {FAQ_ITEMS.map((item) => (
                <div
                  key={item.question}
                  className="ep-card flex flex-col justify-between p-5"
                >
                  <div>
                    <h3 className="ep-display text-xl">{item.question}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-ink-2">
                      {item.answer}
                    </p>
                  </div>
                  <div className="mt-4 pt-2">
                    <TechDetails label="Show technical details">
                      <p className="text-xs leading-relaxed text-ink-2">
                        {item.techDetail}
                      </p>
                    </TechDetails>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </InkReveal>
      </main>

      <SpecimenFooter />
    </div>
  );
}
