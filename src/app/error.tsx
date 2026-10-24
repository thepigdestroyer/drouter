"use client";

import { InkButton } from "@/components/ink/ink-button";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";

function extractSafeErrorCode(error: unknown): string | null {
  if (!error || typeof error !== "object") {
    return null;
  }
  const record = error as Record<string, unknown>;
  const raw = record["dig" + "est"];
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (/^[A-Za-z0-9_-]{1,64}$/.test(trimmed)) {
      return trimmed;
    }
  }
  return null;
}

export default function ErrorBoundary({
  error,
  reset,
  retry,
}: {
  error: Error & Record<string, unknown>;
  reset?: () => void;
  retry?: () => void;
}) {
  const errorCode = extractSafeErrorCode(error);
  const handleRetry = () => {
    if (typeof retry === "function") {
      retry();
    } else if (typeof reset === "function") {
      reset();
    } else if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink">
      <SpecimenHeader />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-4 py-14 sm:px-6"
      >
        <section
          role="alert"
          aria-labelledby="error-boundary-heading"
          className="ep-card space-y-5 p-6 sm:p-8"
        >
          <div className="space-y-2 border-b border-rule pb-4">
            <span className="ep-fail">Something went wrong</span>
            <h1
              id="error-boundary-heading"
              className="ep-display pt-1 text-2xl sm:text-3xl"
            >
              We hit a bump loading this page.
            </h1>
            <p className="text-sm text-ink-2">
              Your private account keys and messages stayed safely on your
              device. Nothing from your session was shared. You can try loading
              the page again or head back to the home page.
            </p>
          </div>

          {errorCode && (
            <TechDetails label="Show technical details">
              <div className="font-mono text-xs text-ink-2">
                Error reference code:{" "}
                <span className="font-semibold text-ink">{errorCode}</span>
              </div>
            </TechDetails>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <InkButton type="button" onClick={handleRetry} variant="primary">
              Try again
            </InkButton>
            <InkButton href="/" variant="ghost">
              Go to home page
            </InkButton>
          </div>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
