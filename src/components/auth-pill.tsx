"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  getCurrentVaultSession,
  lockVault,
  subscribeVaultSession,
  type VaultSession,
} from "@/lib/auth/vault";

export interface AuthPillProps {
  className?: string;
}

export function AuthPill({ className = "" }: AuthPillProps) {
  const [session, setSession] = useState<VaultSession | null>(null);

  useEffect(() => {
    setSession(getCurrentVaultSession());
    return subscribeVaultSession(() => {
      setSession(getCurrentVaultSession());
    });
  }, []);

  if (!session) {
    return (
      <Link
        href="/login"
        className={`ep-btn-ghost px-3 py-1 text-xs ${className}`}
      >
        Sign in
      </Link>
    );
  }

  return (
    <div
      className={`inline-flex items-center gap-2 rounded border border-ink bg-paper px-2.5 py-1 text-xs text-ink ${className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-ink" aria-hidden="true" />
      <Link
        href="/login"
        className="font-medium text-ink hover:underline"
        title={`Vault ID: ${session.vaultId}`}
      >
        Vault unlocked
      </Link>
      {session.payload.customScrubTerms.length > 0 && (
        <span className="font-mono text-[11px] text-ink-3">
          ({session.payload.customScrubTerms.length})
        </span>
      )}
      <button
        type="button"
        onClick={() => lockVault()}
        className="ml-1 border-l border-rule pl-2 font-mono text-[11px] text-ink-3 hover:text-ink"
      >
        Lock
      </button>
    </div>
  );
}

export default AuthPill;
