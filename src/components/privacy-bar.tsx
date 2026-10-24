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
  zeroTelemetry?: boolean;
  onToggleZeroTelemetry?: (next: boolean) => void;
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

  scrubbed = scrubbed.replace(
    /\b(?:sk-[A-Za-z0-9_-]{6,}|tk_[A-Za-z0-9_-]{6,})\b/g,
    () => nextTag("SECRET", "api-key"),
  );

  scrubbed = scrubbed.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    () => nextTag("EMAIL", "email"),
  );

  scrubbed = scrubbed.replace(/\b0x[a-fA-F0-9]{8,}\b/g, () =>
    nextTag("ADDR", "hex-address"),
  );

  scrubbed = scrubbed.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, () =>
    nextTag("IP", "ip"),
  );

  scrubbed = scrubbed.replace(
    /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
    () => nextTag("PHONE", "phone"),
  );

  return { scrubbed, replacements };
}

function computeBucketMetrics(draftText: string): {
  estimatedTokens: number;
  bucketTokens: number;
} {
  const trimmed = draftText.trim();
  const estimatedTokens =
    trimmed.length === 0 ? 0 : Math.max(1, Math.ceil(trimmed.length / 4));
  if (estimatedTokens <= 1024) {
    return { estimatedTokens, bucketTokens: 1024 };
  }
  const exponentJ = Math.max(0, Math.ceil(Math.log2(estimatedTokens / 1024)));
  const bucketTokens = Math.pow(2, exponentJ) * 1024;
  return { estimatedTokens, bucketTokens };
}

function shortHex(hex: string, lead = 10, tail = 6): string {
  if (hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
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
  zeroTelemetry = true,
  onToggleZeroTelemetry,
}: PrivacyBarProps) {
  const liveScrub = useMemo(() => {
    if (draftText.trim().length > 0) {
      return scrubDraftPreview(draftText);
    }
    return lastScrubbed ?? { scrubbed: "", replacements: [] };
  }, [draftText, lastScrubbed]);

  const bucket = useMemo(() => computeBucketMetrics(draftText), [draftText]);

  return (
    <div className="space-y-3 text-xs text-ink-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[70ch]">
          <strong className="font-medium text-ink">How this turn is protected:</strong>{" "}
          Your browser scrubs personal identifiers locally, pads the payload to{" "}
          <span className="font-mono text-ink">
            {bucket.bucketTokens.toLocaleString()}
          </span>{" "}
          tokens, spends one blind-signed credit, and encrypts the message with HPKE so the relay cannot read it.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onToggleScrub(!scrubEnabled)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            PII scrubber: {scrubEnabled ? "On" : "Off"}
          </button>

          {onToggleZeroTelemetry && (
            <button
              type="button"
              onClick={() => onToggleZeroTelemetry(!zeroTelemetry)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Zero telemetry: {zeroTelemetry ? "On" : "Off"}
            </button>
          )}

          <button
            type="button"
            onClick={() => void onMintCredits()}
            disabled={mintingCredits}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {mintingCredits
              ? "Minting..."
              : `Blind credits: ${creditBalance} (+5)`}
          </button>
        </div>
      </div>

      {scrubEnabled && liveScrub.replacements.length > 0 && (
        <div className="ep-inset p-2.5">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="ep-label">Scrubbed in browser:</span>
            {liveScrub.replacements.map((r, i) => (
              <span key={`${r.placeholder}-${i}`} className="ep-pass">
                {r.placeholder} ({r.kind})
              </span>
            ))}
          </div>
          <p className="mt-1 ep-mono">{liveScrub.scrubbed}</p>
        </div>
      )}

      {lastNullifier && (
        <div className="font-mono text-[11px] text-ink-3">
          Last unlinkable credit nullifier: {shortHex(lastNullifier)}
        </div>
      )}

      <div className="ep-inset p-3">
        <div className="ep-label">What this does not hide</div>
        <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-ink-2 break-words">
          <li>
            Tinfoil&apos;s safeguards classifier (gpt-oss-safeguard-120b with kimi-k3 review) sees prompts inside the enclave and reports policy violations to{" "}
            <span className="font-mono">https://api.tinfoil.sh</span>.
          </li>
          <li>
            Tinfoil&apos;s usage reporter counts token usage inside the enclave.
          </li>
          <li>
            Kimi K3 context here is 262,144 tokens (not 1M).
          </li>
          <li>
            Nodes sim-1, sim-2, and sim-3 are simulated in software.
          </li>
          <li>
            The Circle Arc registry (
            <span className="font-mono break-all">
              0xbc8085c2b6fe6e0db05f169925c0b841828f4481
            </span>
            , chain 5042002) is a testnet.
          </li>
        </ul>
      </div>
    </div>
  );
}

export default PrivacyBar;
