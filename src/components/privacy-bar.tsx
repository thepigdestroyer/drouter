"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ScrubResult } from "@/lib/types";
import {
  claimPaidCredits,
  requestCreditInvoice,
  storedCreditBalance,
  type CreditInvoiceClientHandle,
} from "@/lib/credits/client";
import {
  previewDraftPrivacy,
  type MessagePrivacyReport,
} from "@/components/console/send-pipeline";
import type { MechanicalSession } from "@/lib/privacy/mechanical";
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
  session?: MechanicalSession;
  creditBalance: number | null;
  onMintCredits: () => Promise<void>;
  onCreditBalanceChange?: (nextBalance: number) => void;
  mintingCredits?: boolean;
  lastNullifier?: string | null;
  zeroTelemetry?: boolean;
  onToggleZeroTelemetry?: (next: boolean) => void;
}

const TOKEN_PACKS: Array<{ denomination: 1 | 5 | 20; amountUsdc: string }> = [
  { denomination: 1, amountUsdc: "0.0001" },
  { denomination: 5, amountUsdc: "0.0005" },
  { denomination: 20, amountUsdc: "0.002" },
];

function shortHex(hex: string, lead = 10, tail = 6): string {
  if (hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

export function formatRedactionKindLabel(kind: string): string {
  if (kind === "MARKED") return "marked by you";
  return kind;
}

export function friendlyCreditFlowError(rawError?: string | null): string {
  if (!rawError) return "";
  if (/no confirmed usdc|transfer log|insufficient usdc/i.test(rawError)) {
    return "We have not detected your USDC payment at this deposit address yet. Wait a few seconds after sending and click the button again.";
  }
  if (/expired|410/i.test(rawError)) {
    return "This one-time deposit address has expired. Click New deposit address to get a fresh one.";
  }
  if (/already been claimed|409/i.test(rawError)) {
    return "These tokens have already been claimed. Click New deposit address if you want to buy another pack.";
  }
  return "Could not complete token request right now. Please try again in a moment.";
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
  session,
  creditBalance,
  onMintCredits,
  onCreditBalanceChange,
  mintingCredits = false,
  lastNullifier,
  zeroTelemetry = true,
  onToggleZeroTelemetry,
}: PrivacyBarProps) {
  const [buyTokensOpen, setBuyTokensOpen] = useState(false);
  const [selectedPack, setSelectedPack] = useState<1 | 5 | 20>(5);
  const [invoice, setInvoice] = useState<CreditInvoiceClientHandle | null>(null);
  const [loadingInvoice, setLoadingInvoice] = useState(false);
  const [claimingTokens, setClaimingTokens] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState(false);
  const [creditFlowNotice, setCreditFlowNotice] = useState<string | null>(null);
  const [creditFlowRawError, setCreditFlowRawError] = useState<string | null>(
    null,
  );

  const loadInvoice = useCallback(async (pack: 1 | 5 | 20) => {
    setLoadingInvoice(true);
    setCreditFlowRawError(null);
    setCreditFlowNotice(null);
    setCopiedAddress(false);
    try {
      const origin =
        typeof window !== "undefined" ? window.location.origin : "";
      const nextInvoice = await requestCreditInvoice(origin, pack);
      setInvoice(nextInvoice);
    } catch (e) {
      setCreditFlowRawError(
        (e as Error).message || "Could not create deposit address",
      );
    } finally {
      setLoadingInvoice(false);
    }
  }, []);

  const handleToggleBuyTokens = useCallback(() => {
    setBuyTokensOpen((prev) => !prev);
  }, []);

  useEffect(() => {
    if (
      buyTokensOpen &&
      !invoice &&
      !loadingInvoice &&
      !creditFlowRawError &&
      !creditFlowNotice
    ) {
      void loadInvoice(selectedPack);
    }
  }, [
    buyTokensOpen,
    creditFlowNotice,
    creditFlowRawError,
    invoice,
    loadInvoice,
    loadingInvoice,
    selectedPack,
  ]);

  const handleSelectPack = useCallback(
    (pack: 1 | 5 | 20) => {
      setSelectedPack(pack);
      void loadInvoice(pack);
    },
    [loadInvoice],
  );

  const handleCopyDepositAddress = useCallback(async () => {
    if (!invoice?.depositAddress) return;
    try {
      await navigator.clipboard.writeText(invoice.depositAddress);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    } catch {
      setCopiedAddress(false);
    }
  }, [invoice]);

  const handleClaimPaidTokens = useCallback(async () => {
    if (!invoice || claimingTokens) return;
    setClaimingTokens(true);
    setCreditFlowRawError(null);
    setCreditFlowNotice(null);
    try {
      const origin =
        typeof window !== "undefined" ? window.location.origin : "";
      await claimPaidCredits(origin, {
        invoiceId: invoice.invoiceId,
        claimSecret: invoice.claimSecret,
        count: invoice.denomination,
        denomination: 1,
      });
      const updated = storedCreditBalance();
      onCreditBalanceChange?.(updated);
      setCreditFlowNotice(
        `Added ${invoice.denomination} anonymous token${
          invoice.denomination === 1 ? "" : "s"
        } to your browser wallet.`,
      );
      setInvoice(null);
    } catch (e) {
      setCreditFlowRawError(
        (e as Error).message || "Could not claim paid tokens",
      );
    } finally {
      setClaimingTokens(false);
    }
  }, [claimingTokens, invoice, onCreditBalanceChange]);

  const draftPrepared = useMemo(() => {
    const trimmed = draftText.trim();
    if (!trimmed) return null;
    return previewDraftPrivacy(draftText, {
      scrubEnabled,
      normalizeStyle,
      session,
    });
  }, [draftText, scrubEnabled, normalizeStyle, session]);

  const activeCustomTermsCount =
    customTermsCount ?? draftPrepared?.customTerms.length ?? 0;

  const activeRedactions = useMemo(() => {
    if (draftPrepared) {
      return draftPrepared.prepared.report.redactions;
    }
    if (lastPrivacyReport) {
      return lastPrivacyReport.redactions;
    }
    return lastScrubbed?.replacements ?? [];
  }, [draftPrepared, lastPrivacyReport, lastScrubbed]);

  const activeOutboundPreview = useMemo(() => {
    if (draftPrepared) {
      return draftPrepared.prepared.outboundText;
    }
    if (lastPrivacyReport) {
      return lastPrivacyReport.outboundPreview;
    }
    return lastScrubbed?.scrubbed ?? "";
  }, [draftPrepared, lastPrivacyReport, lastScrubbed]);

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
      ? draftPrepared.prepared.report.riskAfter
      : (lastPrivacyReport?.riskAfter ?? null);

  const activeStyleChanges =
    draftPrepared?.prepared.report.styleChanges ??
    lastPrivacyReport?.styleChanges ??
    0;

  const creditLabel = mintingCredits
    ? "Adding free tokens..."
    : creditBalance === null
      ? "Anonymous tokens: Loading"
      : `Anonymous tokens: ${creditBalance} left (Add 5 free)`;

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
          anonymous token when available so requests cannot be linked to your
          network address (at 0 tokens, chatting still works under the standard
          daily limit), and lock your message so only the sealed computer can
          open it.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            aria-pressed={scrubEnabled}
            onClick={() => onToggleScrub(!scrubEnabled)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            Hide personal details: Always on
          </button>

          {onToggleNormalizeStyle && (
            <button
              type="button"
              aria-pressed={normalizeStyle}
              onClick={() => onToggleNormalizeStyle(!normalizeStyle)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Disguise writing style: {normalizeStyle ? "On" : "Off"}
            </button>
          )}

          {onToggleZeroTelemetry && (
            <button
              type="button"
              aria-pressed={!zeroTelemetry}
              onClick={() => onToggleZeroTelemetry(!zeroTelemetry)}
              className="ep-btn-ghost px-2.5 py-1 text-xs"
              title="When off, verification receipts stay only in your browser and are not published to the public receipt book"
            >
              Share receipts publicly: {zeroTelemetry ? "Off" : "On"}
            </button>
          )}

          <button
            type="button"
            onClick={() => void onMintCredits()}
            disabled={mintingCredits}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
            title="Claim your free daily allowance of prepaid anonymous tokens"
          >
            {creditLabel}
          </button>

          <button
            type="button"
            aria-expanded={buyTokensOpen}
            onClick={handleToggleBuyTokens}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {buyTokensOpen ? "Hide token top-up" : "Get more anonymous tokens"}
          </button>
        </div>
      </div>

      {buyTokensOpen && (
        <div
          className="ep-inset space-y-3 p-3.5 text-xs text-ink"
          data-testid="paid-credits-panel"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="space-y-0.5">
              <div className="font-medium text-ink">
                Get more anonymous tokens
              </div>
              <p className="text-xs text-ink-2">
                Pay from any wallet. For best privacy use a fresh wallet. We
                never ask for your address.
              </p>
            </div>

            <div
              className="inline-flex rounded border border-rule-2 bg-paper p-0.5 text-xs"
              role="group"
              aria-label="Choose token pack"
            >
              {TOKEN_PACKS.map((pack) => (
                <button
                  key={pack.denomination}
                  type="button"
                  aria-pressed={selectedPack === pack.denomination}
                  disabled={loadingInvoice || claimingTokens}
                  onClick={() => handleSelectPack(pack.denomination)}
                  className={`rounded px-2.5 py-1 font-medium transition-colors ${
                    selectedPack === pack.denomination
                      ? "bg-ink text-paper"
                      : "text-ink-2 hover:text-ink"
                  }`}
                >
                  {pack.denomination}{" "}
                  {pack.denomination === 1 ? "token" : "tokens"} (
                  {pack.amountUsdc} USDC)
                </button>
              ))}
            </div>
          </div>

          {creditFlowNotice && (
            <p className="rounded border border-rule bg-paper px-2.5 py-1.5 text-xs text-ink">
              {creditFlowNotice}
            </p>
          )}

          {creditFlowRawError && (
            <p
              role="alert"
              className="rounded border border-accent bg-accent-soft px-2.5 py-1.5 text-xs text-accent"
            >
              {friendlyCreditFlowError(creditFlowRawError)}
            </p>
          )}

          {loadingInvoice ? (
            <p className="text-xs text-ink-2">
              Generating a fresh one-time deposit address...
            </p>
          ) : invoice ? (
            <div className="space-y-2.5">
              <div className="grid grid-cols-1 gap-2 rounded border border-rule bg-paper p-2.5 sm:grid-cols-[1fr_auto] sm:items-center">
                <div className="space-y-1">
                  <div className="text-[11px] text-ink-3">
                    Send exactly{" "}
                    <strong className="font-semibold text-ink">
                      {invoice.amountUsdc} USDC
                    </strong>{" "}
                    for{" "}
                    <strong className="font-semibold text-ink">
                      {invoice.denomination} anonymous{" "}
                      {invoice.denomination === 1 ? "token" : "tokens"}
                    </strong>{" "}
                    to this one-time deposit address:
                  </div>
                  <div
                    className="ep-mono break-all text-xs text-ink"
                    data-testid="credit-deposit-address"
                  >
                    {invoice.depositAddress}
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => void handleCopyDepositAddress()}
                    className="ep-btn-ghost px-2.5 py-1 text-xs"
                  >
                    {copiedAddress ? "Copied address" : "Copy address"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadInvoice(selectedPack)}
                    disabled={loadingInvoice || claimingTokens}
                    className="ep-btn-ghost px-2.5 py-1 text-xs"
                  >
                    New deposit address
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => void handleClaimPaidTokens()}
                  disabled={claimingTokens}
                  className="ep-btn px-3.5 py-1.5 text-xs font-medium"
                >
                  {claimingTokens
                    ? "Checking payment and minting tokens..."
                    : "I have paid, give me my tokens"}
                </button>
                <span className="text-[11px] text-ink-3">
                  Your secret claim key stays only in this browser.
                </span>
              </div>
            </div>
          ) : (
            <div>
              <button
                type="button"
                onClick={() => void loadInvoice(selectedPack)}
                className="ep-btn-ghost px-3 py-1 text-xs"
              >
                Get a fresh deposit address
              </button>
            </div>
          )}

          <TechDetails label="Show technical details">
            <div className="mt-2 space-y-1.5 border-t border-rule pt-2 font-mono text-[11px] text-ink-2">
              <div>
                Network: Circle Arc Testnet (chain ID{" "}
                {invoice?.chainId ?? 5042002})
              </div>
              <div className="break-all">
                USDC contract:{" "}
                {invoice?.usdcContract ??
                  "0x3600000000000000000000000000000000000000"}{" "}
                (decimals: {invoice?.usdcDecimals ?? 6})
              </div>
              {invoice && (
                <>
                  <div className="break-all">
                    Invoice ID: {invoice.invoiceId}
                  </div>
                  <div className="break-all">
                    Claim hash (SHA-256 of browser-only secret):{" "}
                    {invoice.claimHash}
                  </div>
                </>
              )}
              <div>
                Protocol: 2048-bit RSA-FDH blind signatures. The server verifies
                the ERC-20 Transfer log to the one-time child deposit address
                without storing your sender wallet address, and signs your
                blinded tokens so spent tokens cannot be linked to your payment.
              </div>
              {creditFlowRawError && (
                <div className="text-accent">
                  Raw error: {creditFlowRawError}
                </div>
              )}
            </div>
          </TechDetails>
        </div>
      )}

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

          {activeRedactions.length > 0 && (
            <div className="space-y-1">
              <div
                className="flex flex-wrap items-center gap-1.5"
                data-testid="privacy-bar-redactions"
              >
                <span className="ep-label">Hidden in browser:</span>
                {activeRedactions.map((r, i) => (
                  <span key={`${r.placeholder}-${i}`} className="ep-pass">
                    {r.placeholder} ({formatRedactionKindLabel(r.kind)})
                  </span>
                ))}
              </div>
              {activeOutboundPreview && (
                <p
                  className="ep-mono text-ink"
                  data-testid="privacy-bar-outbound-preview"
                >
                  {activeOutboundPreview}
                </p>
              )}
            </div>
          )}

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
                        {r.placeholder} ({formatRedactionKindLabel(r.kind)})
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
