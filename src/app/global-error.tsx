"use client";

import "./globals.css";

function extractSafeDigest(error: unknown): string | null {
  if (
    error &&
    typeof error === "object" &&
    "digest" in error &&
    typeof (error as { digest?: unknown }).digest === "string"
  ) {
    const raw = (error as { digest: string }).digest.trim();
    if (/^[A-Za-z0-9_-]{1,64}$/.test(raw)) {
      return raw;
    }
  }
  return null;
}

export default function GlobalError({
  error,
  reset,
  retry,
}: {
  error: Error & { digest?: string };
  reset?: () => void;
  retry?: () => void;
}) {
  const digest = extractSafeDigest(error);
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
        <title>Application Error · dRouter</title>
        <main
          id="main-content"
          tabIndex={-1}
          className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-4 py-14 sm:px-6"
        >
          <section
            role="alert"
            aria-labelledby="global-error-heading"
            className="ep-card p-6 sm:p-8 space-y-5"
          >
            <div className="space-y-2 border-b border-rule pb-4">
              <span className="ep-fail">Application error</span>
              <h1 id="global-error-heading" className="ep-display text-2xl sm:text-3xl pt-1">
                dRouter encountered an unexpected error.
              </h1>
              <p className="text-sm text-ink-2">
                Stack traces and runtime details are suppressed to keep local session state and credentials private.
              </p>
            </div>

            {digest && (
              <div className="ep-inset p-3 font-mono text-xs text-ink-2">
                Reference digest: <span className="text-ink font-semibold">{digest}</span>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button type="button" onClick={handleRetry} className="ep-btn">
                Try again
              </button>
              <a href="/" className="ep-btn-ghost">
                Reload console
              </a>
            </div>
          </section>
        </main>
      </body>
    </html>
  );
}
