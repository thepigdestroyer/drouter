"use client";

import { useMemo } from "react";
import type { ScrubResult } from "@/lib/types";
import {
  previewDraftPrivacy,
  type MessagePrivacyReport,
} from "@/components/console/send-pipeline";

export interface PrivacyBarProps {
  scrubEnabled: boolean;
  onToggleScrub: (next: boolean) => void;
  normalizeStyle?: boolean;
  onToggleNormalizeStyle?: (next: boolean) => void;
  lastScrubbed?: ScrubResult | null;
  lastPrivacyReport?: MessagePrivacyReport | null;
  customTermsCount?: number;
  draftText: string;
  creditBalance: number | null;
  onMintCredits: () => Promise<void>;
  mintingCredits?: boolean;
  lastNullifier?: string | null;
  zeroTelemetry?: boolean;
  onToggleZeroTelemetry?: (next: boolean) => void;
}

function shortHex(hex: string, lead = 10, tail = 6): string {
  if (hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

export function PrivacyBar({
  scrubEnabled,
  onToggleScrub,
  normalizeStyle = false,
  onToggleNormalizeStyle,
  lastScrubbed,
  lastPrivacyReport,
  customTermsCount,
  draftText,
  creditBalance,
  onMintCredits,
  mintingCredits = false,
  lastNullifier,
  zeroTelemetry = true,
  onToggleZeroTelemetry,
}: PrivacyBarProps) {
  const draftPrepared = useMemo(() => {
    const trimmed = draftText.trim();
    if (!trimmed) return null;
    return previewDraftPrivacy(draftText, {
      scrubEnabled,
      normalizeStyle,
    });
  }, [draftText, scrubEnabled, normalizeStyle]);

  const activeCustomTermsCount =
    customTermsCount ?? draftPrepared?.customTerms.length ?? 0;

  const activeRedactions = useMemo(() => {
    if (draftPrepared) {
      return scrubEnabled ? draftPrepared.prepared.report.redactions : [];
    }
    if (lastPrivacyReport) {
      return lastPrivacyReport.redactions;
    }
    return lastScrubbed?.replacements ?? [];
  }, [draftPrepared, lastPrivacyReport, lastScrubbed, scrubEnabled]);

  const activeOutboundPreview = useMemo(() => {
    if (draftPrepared) {
      return scrubEnabled ? draftPrepared.prepared.outboundText : draftText;
    }
    if (lastPrivacyReport) {
      return lastPrivacyReport.outboundPreview;
    }
    return lastScrubbed?.scrubbed ?? "";
  }, [draftPrepared, draftText, lastPrivacyReport, lastScrubbed, scrubEnabled]);

  const activeBucketBytes =
    draftPrepared?.prepared.bucketBytes ??
    lastPrivacyReport?.bucketBytes ??
    null;

  const activeRiskBefore =
    draftPrepared?.prepared.report.riskBefore ??
    lastPrivacyReport?.riskBefore ??
    null;

  const activeRiskAfter =
    draftPrepared !== null
      ? scrubEnabled
        ? draftPrepared.prepared.report.riskAfter
        : draftPrepared.prepared.report.riskBefore
      : (lastPrivacyReport?.riskAfter ?? null);

  const activeStyleChanges =
    draftPrepared?.prepared.report.styleChanges ??
    lastPrivacyReport?.styleChanges ??
    0;

  const creditLabel = mintingCredits
    ? "Minting..."
    : creditBalance === null
      ? "Blind credits: Loading"
      : `Blind credits: ${creditBalance} (+5)`;

  return (
    <div className="space-y-3 text-xs text-ink-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[70ch]">
          <strong className="font-medium text-ink">
            How this turn is protected:
          </strong>{" "}
          Your browser runs <code className="font-mono">preparePrompt</code>{" "}
          locally (scrubbing identifiers and{" "}
          <span className="font-mono text-ink">{activeCustomTermsCount}</span>{" "}
          vault custom term{activeCustomTermsCount === 1 ? "" : "s"}), pads the
          wire payload to{" "}
          <span className="font-mono text-ink">
            {activeBucketBytes !== null
              ? `${activeBucketBytes.toLocaleString("en-US")} B`
              : "a power-of-two byte bucket"}
          </span>
          , attaches an <code className="font-mono">x-drouter-credit</code>{" "}
          header when a blind token is in your wallet, and encrypts the body
          with HPKE so the relay cannot read it.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onToggleScrub(!scrubEnabled)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            PII scrubber: {scrubEnabled ? "On" : "Off"}
          </button>

          {onToggleNormalizeStyle && (
            <button
              type="button"
              onClick={() => onToggleNormalizeStyle(!normalizeStyle)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Style normalizer: {normalizeStyle ? "On" : "Off"}
            </button>
          )}

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
            {creditLabel}
          </button>
        </div>
      </div>

      {/* Real per-message or live-draft privacy report */}
      {(draftPrepared !== null || lastPrivacyReport !== null) && (
        <div
          className="ep-inset p-3 space-y-2"
          data-testid="privacy-report-panel"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="ep-label">
              {draftPrepared !== null
                ? "Live draft privacy report"
                : "Last sent message privacy report"}
            </span>
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-ink">
              <span>
                Bucket:{" "}
                {activeBucketBytes !== null
                  ? `${activeBucketBytes.toLocaleString("en-US")} B`
                  : "Unavailable"}
              </span>
              <span>·</span>
              <span>
                Risk:{" "}
                {activeRiskBefore !== null && activeRiskAfter !== null
                  ? `${activeRiskBefore}/100 -> ${activeRiskAfter}/100`
                  : "Unavailable"}
              </span>
              <span>·</span>
              <span>Redactions: {activeRedactions.length}</span>
              {activeStyleChanges > 0 && (
                <>
                  <span>·</span>
                  <span>Style edits: {activeStyleChanges}</span>
                </>
              )}
            </div>
          </div>

          {activeRedactions.length > 0 ? (
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="ep-label">Scrubbed in browser:</span>
                {activeRedactions.map((r, i) => (
                  <span key={`${r.placeholder}-${i}`} className="ep-pass">
                    {r.placeholder} ({r.kind})
                  </span>
                ))}
              </div>
              {activeOutboundPreview && (
                <p className="ep-mono text-ink">{activeOutboundPreview}</p>
              )}
            </div>
          ) : (
            <p className="text-xs text-ink-3">
              No personal identifiers or custom vault terms matched in this
              message.
            </p>
          )}

          {lastPrivacyReport && draftPrepared === null && (
            <div className="border-t border-rule pt-1.5 font-mono text-[11px] text-ink-3">
              {lastPrivacyReport.creditAttached
                ? `x-drouter-credit attached${
                    lastPrivacyReport.creditNullifier
                      ? ` (nullifier ${shortHex(lastPrivacyReport.creditNullifier)})`
                      : ""
                  }`
                : "Credit header: not attached (wallet had 0 credits; request used per-IP free tier)"}
            </div>
          )}
        </div>
      )}

      {lastNullifier && !lastPrivacyReport && (
        <div className="font-mono text-[11px] text-ink-3">
          Last unlinkable credit nullifier: {shortHex(lastNullifier)}
        </div>
      )}

      <div className="ep-inset p-3">
        <div className="ep-label">What this does not hide</div>
        <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-ink-2 break-words">
          <li>
            Tinfoil&apos;s safeguards classifier (gpt-oss-safeguard-120b with
            kimi-k3 review) sees prompts inside the enclave and reports policy
            violations to{" "}
            <span className="font-mono">https://api.tinfoil.sh</span>.
          </li>
          <li>
            Tinfoil&apos;s usage reporter counts token usage inside the enclave.
          </li>
          <li>Kimi K3 context here is 262,144 tokens (not 1M).</li>
          <li>Nodes sim-1, sim-2, and sim-3 are simulated in software.</li>
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
