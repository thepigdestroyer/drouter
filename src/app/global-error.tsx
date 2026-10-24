"use client";

import "./globals.css";

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

export default function GlobalError({
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
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-paper text-ink">
        <title>Something went wrong | deRoute</title>
        <main
          id="main-content"
          tabIndex={-1}
          className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-4 py-14 sm:px-6"
        >
          <section
            role="alert"
            aria-labelledby="global-error-heading"
            className="ep-card space-y-5 p-6 sm:p-8"
          >
            <div className="space-y-2 border-b border-rule pb-4">
              <span className="ep-fail">Something went wrong</span>
              <h1
                id="global-error-heading"
                className="ep-display pt-1 text-2xl sm:text-3xl"
              >
                deRoute ran into an unexpected problem.
              </h1>
              <p className="text-sm text-ink-2">
                Your private account keys and messages stayed safely on your
                device. Try reloading the page or returning to the home screen.
              </p>
            </div>

            {errorCode && (
              <details className="ep-tech-details rounded border border-rule bg-paper/85 text-ink">
                <summary className="ep-tech-summary cursor-pointer px-3.5 py-2 text-xs font-mono text-ink-2">
                  Show technical details
                </summary>
                <div className="border-t border-rule bg-paper-2 p-3 font-mono text-xs text-ink-2">
                  Error reference code:{" "}
                  <span className="font-semibold text-ink">{errorCode}</span>
                </div>
              </details>
            )}

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button type="button" onClick={handleRetry} className="ep-btn">
                Try again
              </button>
              <a href="/" className="ep-btn-ghost">
                Go to home page
              </a>
            </div>
          </section>
        </main>
      </body>
    </html>
  );
}
