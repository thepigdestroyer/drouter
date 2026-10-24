"use client";

import React, { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import {
  getCurrentVaultSession,
  subscribeVaultSession,
  type VaultSession,
} from "@/lib/auth/vault";

export interface AuthGateProps {
  children: React.ReactNode;
}

function isUnsafePathCandidate(candidate: string): boolean {
  return (
    !candidate.startsWith("/") ||
    candidate.startsWith("//") ||
    candidate.includes("\\") ||
    candidate.includes("://") ||
    /[\u0000-\u0020\u007f]/.test(candidate)
  );
}

/**
 * Validates that a `?next=` redirect target is a safe same-site path starting with a single `/`.
 */
export function sanitizeNextPath(
  raw: string | null | undefined,
  fallback = "/app",
): string {
  if (typeof raw !== "string") return fallback;
  const trimmed = raw.trim();
  if (isUnsafePathCandidate(trimmed)) {
    return fallback;
  }

  let current = trimmed;
  for (let pass = 0; pass < 3; pass++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      return fallback;
    }
    if (isUnsafePathCandidate(decoded)) {
      return fallback;
    }
    if (decoded === current) {
      break;
    }
    current = decoded;
  }

  return trimmed;
}

export function buildLoginRedirectHref(pathname: string | null | undefined): string {
  const safePath = sanitizeNextPath(pathname, "/app");
  return `/login?next=${safePath}`;
}

export function AuthGate({ children }: AuthGateProps): React.JSX.Element {
  const pathname = usePathname();
  const [session, setSession] = useState<VaultSession | null>(null);

  useEffect(() => {
    setSession(getCurrentVaultSession());
    return subscribeVaultSession(() => {
      setSession(getCurrentVaultSession());
    });
  }, []);

  if (session) {
    return <>{children}</>;
  }

  const loginHref = buildLoginRedirectHref(pathname);

  return (
    <div className="mx-auto w-full max-w-xl px-4 py-12 sm:px-6">
      <InkReveal>
        <section
          aria-labelledby="auth-gate-heading"
          className="ep-card space-y-5 p-6 sm:p-8"
        >
          <div className="space-y-2">
            <div className="ep-label">Private account required</div>
            <h2 id="auth-gate-heading" className="ep-display text-2xl sm:text-3xl">
              Sign in to continue
            </h2>
            <p className="text-sm leading-relaxed text-ink-2">
              You need a deRoute account to use this. It takes 10 seconds and we never learn who you are.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 border-t border-rule pt-4">
            <InkButton variant="accent" href={loginHref}>
              Sign in
            </InkButton>
            <InkButton variant="ghost" href="/explain">
              See how it works
            </InkButton>
          </div>
        </section>
      </InkReveal>
    </div>
  );
}

export default AuthGate;
