"use client";

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { InkButton } from "@/components/ink/ink-button";
import {
  getCurrentVaultSession,
  lockVault,
  subscribeVaultSession,
  type VaultSession,
} from "@/lib/auth/vault";

export interface AuthPillProps {
  className?: string;
}

export function AuthPill({ className = "" }: AuthPillProps): React.JSX.Element {
  const [session, setSession] = useState<VaultSession | null>(null);

  useEffect(() => {
    setSession(getCurrentVaultSession());
    return subscribeVaultSession(() => {
      setSession(getCurrentVaultSession());
    });
  }, []);

  if (!session) {
    return (
      <InkButton
        href="/login"
        variant="ghost"
        aria-label="Sign in to deRoute"
        className={`px-3 py-1 text-xs ${className}`.trim()}
      >
        Sign in
      </InkButton>
    );
  }

  return (
    <div
      role="group"
      aria-label="Account menu"
      className={`inline-flex items-center gap-2 rounded border border-ink bg-paper/90 px-2.5 py-1 text-xs text-ink ${className}`.trim()}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-ink" aria-hidden="true" />
      <Link
        href="/account"
        className="font-medium text-ink hover:underline"
        title="Manage your deRoute account"
      >
        Account
      </Link>
      {session.payload.customScrubTerms.length > 0 && (
        <span
          className="font-mono text-[11px] text-ink-3"
          title={`${session.payload.customScrubTerms.length} custom words always hidden`}
        >
          ({session.payload.customScrubTerms.length})
        </span>
      )}
      <button
        type="button"
        onClick={() => lockVault()}
        aria-label="Sign out of deRoute"
        className="ml-1 border-l border-rule pl-2 font-mono text-[11px] text-ink-3 hover:text-ink cursor-pointer"
      >
        Sign out
      </button>
    </div>
  );
}

export default AuthPill;
