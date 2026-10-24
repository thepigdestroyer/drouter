"use client";

import { useMemo } from "react";
import type { ScrubResult } from "@/lib/types";

export interface PrivacyBarProps {
  scrubEnabled: boolean;
  onToggleScrub: (next: boolean) => void;
  lastScrubbed?: ScrubResult | null;
  draftText: string;
  creditBalance: number;
  onMintCredits: () => Promise<void>;
  mintingCredits?: boolean;
  lastNullifier?: string | null;
}

function scrubDraftPreview(input: string): ScrubResult {
  if (!input) {
    return { scrubbed: "", replacements: [] };
  }

  const replacements: { placeholder: string; kind: string }[] = [];
  const counters: Record<string, number> = {};
  const nextTag = (prefix: string, kind: string) => {
    const idx = (counters[prefix] ?? 0) + 1;
    counters[prefix] = idx;
    const placeholder = `[${prefix}_${idx}]`;
    replacements.push({ placeholder, kind });
    return placeholder;
  };

  let scrubbed = input;

  // API keys / bearer secrets (tk_..., sk-...)
  scrubbed = scrubbed.replace(/\b(?:sk-[A-Za-z0-9_-]{6,}|tk_[A-Za-z0-9_-]{6,})\b/g, () =>
    nextTag("SECRET", "api-key"),
  );

  // Emails
  scrubbed = scrubbed.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, () =>
    nextTag("EMAIL", "email"),
  );

  // 0x hex addresses / keys
  scrubbed = scrubbed.replace(/\b0x[a-fA-F0-9]{8,}\b/g, () =>
    nextTag("ADDR", "hex-address"),
  );

  // IPv4 addresses
  scrubbed = scrubbed.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, () =>
    nextTag("IP", "ip"),
  );

  // Phone numbers
  scrubbed = scrubbed.replace(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g, () =>
    nextTag("PHONE", "phone"),
  );

  return { scrubbed, replacements };
}

function computeBucketMetrics(draftText: string): {
  estimatedTokens: number;
  exponentJ: number;
  bucketTokens: number;
} {
  const trimmed = draftText.trim();
  const estimatedTokens = trimmed.length === 0 ? 0 : Math.max(1, Math.ceil(trimmed.length / 4));
  if (estimatedTokens <= 1024) {
    return { estimatedTokens, exponentJ: 0, bucketTokens: 1024 };
  }
  const exponentJ = Math.max(0, Math.ceil(Math.log2(estimatedTokens / 1024)));
  const bucketTokens = Math.pow(2, exponentJ) * 1024;
  return { estimatedTokens, exponentJ, bucketTokens };
}

function shortHex(hex: string, lead = 10, tail = 6): string {
  if (hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}…${hex.slice(-tail)}`;
}

export function PrivacyBar({
  scrubEnabled,
  onToggleScrub,
  lastScrubbed,
  draftText,
  creditBalance,
  onMintCredits,
  mintingCredits = false,
  lastNullifier,
}: PrivacyBarProps) {
  const liveScrub = useMemo(() => {
    if (draftText.trim().length > 0) {
      return scrubDraftPreview(draftText);
    }
    return lastScrubbed ?? { scrubbed: "", replacements: [] };
  }, [draftText, lastScrubbed]);

  const bucket = useMemo(() => computeBucketMetrics(draftText), [draftText]);

  return (
    <div className="border-t border-zinc-800 bg-zinc-950/90 px-3 py-2 text-xs">
      <div className="grid grid-cols-1 gap-2 xl:grid-cols-3">
        {/* Pill 1: Client PII Scrubber */}
        <div className="flex flex-col justify-between gap-1.5 rounded-md border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-zinc-300">Client PII Scrubber</span>
            <button
              type="button"
              onClick={() => onToggleScrub(!scrubEnabled)}
              className={`rounded px-2 py-0.5 text-[11px] font-semibold transition ${
                scrubEnabled
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-700/60"
                  : "bg-zinc-800 text-zinc-400 border border-zinc-700"
              }`}
            >
              Scrubber: {scrubEnabled ? "ON" : "OFF"}
            </button>
          </div>
          {scrubEnabled ? (
            liveScrub.replacements.length > 0 ? (
              <div className="space-y-1">
                <div className="flex flex-wrap gap-1">
                  {liveScrub.replacements.map((r, i) => (
                    <span
                      key={`${r.placeholder}-${i}`}
                      className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-300"
                    >
                      {r.placeholder} ({r.kind})
                    </span>
                  ))}
                </div>
                <p className="truncate font-mono text-[11px] text-zinc-400" title={liveScrub.scrubbed}>
                  {liveScrub.scrubbed}
                </p>
              </div>
            ) : (
              <p className="text-[11px] text-zinc-500">
                Replaces emails, phones, keys (<code className="font-mono">tk_…</code>,{" "}
                <code className="font-mono">sk-…</code>), IPs &amp; <code className="font-mono">0x</code> addrs with{" "}
                <code className="font-mono">[EMAIL_1]</code>, <code className="font-mono">[SECRET_1]</code> pre-HPKE.
              </p>
            )
          ) : (
            <p className="text-[11px] text-zinc-500">
              Scrubbing paused — raw prompt goes directly into client HPKE encryption.
            </p>
          )}
        </div>

        {/* Pill 2: Bucket Padding & Cadence (Spec §6) */}
        <div className="flex flex-col justify-between gap-1.5 rounded-md border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-zinc-300">Bucket Padding &amp; Cadence (§6)</span>
            <span className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
              50 ms fixed frame cadence
            </span>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-400">
            <span>
              Draft: <strong className="font-mono text-zinc-200">{bucket.estimatedTokens}</strong> est. tok
            </span>
            <span>
              Bucket:{" "}
              <strong className="font-mono text-emerald-300">
                {bucket.bucketTokens.toLocaleString()} tok
              </strong>{" "}
              <span className="font-mono text-zinc-500">(2^{bucket.exponentJ} × 1,024)</span>
            </span>
          </div>
        </div>

        {/* Pill 3: Unlinkable Blind Credits (Spec §7) */}
        <div className="flex flex-col justify-between gap-1.5 rounded-md border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-zinc-300">
              Unlinkable Blind Credits (§7):{" "}
              <strong className="font-mono text-emerald-300">{creditBalance}</strong>
            </span>
            <button
              type="button"
              onClick={() => void onMintCredits()}
              disabled={mintingCredits}
              className="rounded border border-emerald-700/70 bg-emerald-950/60 px-2 py-0.5 text-[11px] font-semibold text-emerald-200 hover:bg-emerald-900/60 disabled:opacity-40"
            >
              {mintingCredits ? "Minting…" : "Mint +5 blind credits"}
            </button>
          </div>
          <div className="text-[11px] text-zinc-500">
            {lastNullifier ? (
              <span>
                Spent nullifier:{" "}
                <code className="font-mono text-zinc-300">{shortHex(lastNullifier)}</code>
              </span>
            ) : (
              <span>RSA blind-signed tokens prevent payment-to-session correlation.</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default PrivacyBar;
