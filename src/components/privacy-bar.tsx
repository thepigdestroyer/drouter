"use client";

import { useMemo } from "react";
import type { ScrubResult } from "@/lib/types";
import {
  previewDraftPrivacy,
  type MessagePrivacyReport,
} from "@/components/console/send-pipeline";
import { TechDetails } from "@/components/ink/tech-details";

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
    ? "Adding tokens..."
    : creditBalance === null
      ? "Anonymous tokens: Loading"
      : `Anonymous tokens: ${creditBalance} left (Add 5)`;

  return (
    <div className="space-y-3 text-xs text-ink-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[70ch]">
          <strong className="font-medium text-ink">
            How we protect each message:
          </strong>{" "}
          We hide your personal details before anything leaves your device
          {activeCustomTermsCount > 0
            ? ` (including ${activeCustomTermsCount} custom hidden word${
                activeCustomTermsCount === 1 ? "" : "s"
              } from your account)`
            : ""}
          , make every message look the same size from outside, attach a prepaid
          anonymous token that cannot be traced back to you, and lock your
          message so only the sealed computer can open it.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onToggleScrub(!scrubEnabled)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            Hide personal details: {scrubEnabled ? "On" : "Off"}
          </button>

          {onToggleNormalizeStyle && (
            <button
              type="button"
              onClick={() => onToggleNormalizeStyle(!normalizeStyle)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Disguise writing style: {normalizeStyle ? "On" : "Off"}
            </button>
          )}

          {onToggleZeroTelemetry && (
            <button
              type="button"
              onClick={() => onToggleZeroTelemetry(!zeroTelemetry)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Private logs only: {zeroTelemetry ? "On" : "Off"}
            </button>
          )}

          <button
            type="button"
            onClick={() => void onMintCredits()}
            disabled={mintingCredits}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
            title="Prepaid anonymous tokens cannot be traced back to you"
          >
            {creditLabel}
          </button>
        </div>
      </div>

      {/* Live draft or last sent plain summary */}
      {(draftPrepared !== null || lastPrivacyReport !== null) && (
        <div
          className="ep-inset p-3 space-y-2"
          data-testid="privacy-report-panel"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              {draftPrepared !== null ? "Live draft check:" : "Last message:"}{" "}
              {activeRedactions.length === 0
                ? "No personal details needed hiding"
                : `${activeRedactions.length} personal detail${
                    activeRedactions.length === 1 ? "" : "s"
                  } hidden`}
            </span>
            <span className="text-ink-3">
              Every message looks the same size from outside
            </span>
          </div>

          <TechDetails label="Show technical details">
            <div className="mt-2 space-y-2 border-t border-rule pt-2">
              <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-ink">
                <span>
                  Padded size:{" "}
                  {activeBucketBytes !== null
                    ? `${activeBucketBytes.toLocaleString("en-US")} B`
                    : "Unavailable"}
                </span>
                <span>·</span>
                <span>
                  Risk score:{" "}
                  {activeRiskBefore !== null && activeRiskAfter !== null
                    ? `${activeRiskBefore}/100 -> ${activeRiskAfter}/100`
                    : "Unavailable"}
                </span>
                <span>·</span>
                <span>Hidden items: {activeRedactions.length}</span>
                {activeStyleChanges > 0 && (
                  <>
                    <span>·</span>
                    <span>Style changes: {activeStyleChanges}</span>
                  </>
                )}
              </div>

              {activeRedactions.length > 0 && (
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="ep-label">Replaced in browser:</span>
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
              )}

              {lastPrivacyReport && draftPrepared === null && (
                <div className="border-t border-rule pt-1.5 font-mono text-[11px] text-ink-3">
                  {lastPrivacyReport.creditAttached
                    ? `Anonymous token header x-drouter-credit attached${
                        lastPrivacyReport.creditNullifier
                          ? ` (${shortHex(lastPrivacyReport.creditNullifier)})`
                          : ""
                      }`
                    : "Anonymous token: not attached (0 tokens left; sent using standard limit)"}
                </div>
              )}
            </div>
          </TechDetails>
        </div>
      )}

      {lastNullifier && !lastPrivacyReport && (
        <TechDetails label="Show anonymous token receipt">
          <div className="mt-1 font-mono text-[11px] text-ink-3">
            Last spent token receipt: {shortHex(lastNullifier)}
          </div>
        </TechDetails>
      )}

      <TechDetails label="What this does and does not hide">
        <div className="ep-inset mt-2 p-3">
          <ul className="list-disc space-y-1 pl-4 text-xs text-ink-2 break-words">
            <li>
              Personal details (emails, phone numbers, keys, and your custom
              words) are hidden in your browser before your message is locked.
            </li>
            <li>
              Tinfoil&apos;s safety filter runs inside the sealed computer and
              reports severe policy violations to{" "}
              <span className="font-mono">https://api.tinfoil.sh</span>.
            </li>
            <li>
              Token counts are measured inside the sealed computer for billing.
            </li>
            <li>
              Practice mode servers (sim-1, sim-2, sim-3) run in software for
              testing.
            </li>
            <li>
              The public receipt book (
              <span className="font-mono break-all">
                0xbc8085c2b6fe6e0db05f169925c0b841828f4481
              </span>
              , chain 5042002) is a public test network.
            </li>
          </ul>
        </div>
      </TechDetails>
    </div>
  );
}

export default PrivacyBar;
