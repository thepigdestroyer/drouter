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

function formatShortVaultId(vaultId: string): string {
  if (vaultId.length <= 11) {
    return `${vaultId}…`;
  }
  return `${vaultId.slice(0, 11)}…`;
}

export function AuthPill({ className = "" }: AuthPillProps) {
  const [session, setSession] = useState<VaultSession | null>(() => getCurrentVaultSession());

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
        className={`inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/80 px-3 py-1 text-xs font-medium text-zinc-300 transition hover:border-emerald-700/60 hover:bg-zinc-900 hover:text-emerald-200 ${className}`}
      >
        <span className="h-2 w-2 rounded-full bg-zinc-500" />
        <span>Anonymous Session · Unlock ZK Vault</span>
      </Link>
    );
  }

  const modeLabel = session.persistEncrypted ? "Encrypted Local" : "RAM-only";

  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border border-emerald-800/60 bg-emerald-950/40 px-3 py-1 text-xs text-emerald-200 ${className}`}
    >
      <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
      <Link
        href="/login"
        className="font-mono text-[11px] font-medium text-emerald-200 hover:text-white hover:underline"
        title={`Unlocked Zero-Knowledge Vault (${session.vaultId})`}
      >
        ZK Vault · {formatShortVaultId(session.vaultId)} ({modeLabel})
      </Link>
      {session.payload.customScrubTerms.length > 0 && (
        <span className="rounded bg-emerald-900/60 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
          {session.payload.customScrubTerms.length} terms
        </span>
      )}
      <button
        type="button"
        onClick={() => lockVault()}
        className="rounded border border-emerald-700/60 bg-zinc-950/70 px-1.5 py-0.5 text-[10px] font-semibold text-zinc-300 transition hover:border-amber-600/60 hover:text-amber-200"
      >
        Lock
      </button>
    </div>
  );
}

export default AuthPill;
