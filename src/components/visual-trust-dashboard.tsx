"use client";

import React, { useState } from "react";
import type { CheckResult, NodeRecord } from "@/lib/types";
import { CheckList, EvidenceTable } from "@/components/trust-panel";
import { TechDetails } from "@/components/ink/tech-details";

export type InspectorTab =
  | "overview"
  | "silicon"
  | "gpu"
  | "provenance"
  | "onchain"
  | "privacy";

export interface VisualTrustDashboardProps {
  phase: "idle" | "verifying" | "ready" | "streaming" | "closed" | "error";
  node: NodeRecord | null;
  model: string;
  checks: CheckResult[];
  scrubEnabled: boolean;
  zeroTelemetry: boolean;
  onToggleZeroTelemetry: (next: boolean) => void;
  creditBalance: number | null;
  evidence: Record<string, string>;
  onOpenInspector: (initialTab?: InspectorTab) => void;
  onOpenTerminalModal: () => void;
  onExportProof?: () => void;
  canExportProof?: boolean;
  onRetryVerify?: () => void;
  onDismissError?: () => void;
  errorMessage?: string | null;
  verifyAnchorUrl?: string | null;
  publishingProof?: boolean;
  onPublishProof?: () => void;
}

export function friendlyFailureReason(
  errorMessage?: string | null,
  failedChecks: CheckResult[] = [],
): string {
  if (failedChecks.length > 0) {
    const first = failedChecks[0];
    if (first.id === "C1") {
      return "We could not verify the hardware seal on the server. Sending is paused to keep your messages safe.";
    }
    if (first.id === "C2" || first.id === "C4") {
      return "We could not confirm that the server is running the approved open-source software. Sending is paused.";
    }
    if (first.id === "C3") {
      return "We could not lock a fresh session key to the sealed computer. Sending is paused.";
    }
    if (first.id === "C5" || first.id === "C7") {
      return "We could not verify the AI model server seal right now. Sending is paused.";
    }
    if (first.id === "C6") {
      return "This server is not currently approved in the public directory. Sending is paused.";
    }
  }
  if (errorMessage) {
    if (/registry/i.test(errorMessage)) {
      return "We could not reach the server directory right now. Please try again in a moment.";
    }
    return "We could not finish checking the server seal. Sending is paused until the seal check passes.";
  }
  return "The seal check did not pass. Sending is paused until we can confirm the server is sealed.";
}

function AnimatedInkSeal({
  state,
}: {
  state: "verified" | "verifying" | "error" | "idle";
}) {
  const isError = state === "error";
  const isVerifying = state === "verifying";
  const isVerified = state === "verified";

  return (
    <span
      className="relative inline-flex h-6 w-6 shrink-0 items-center justify-center"
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 28 28"
        className={`h-6 w-6 ${
          isVerifying ? " motion-safe:animate-spin" : ""
        }`}
      >
        <circle
          cx="14"
          cy="14"
          r="11.5"
          fill="none"
          stroke={isError ? "var(--color-accent)" : "var(--color-ink)"}
          strokeWidth="1.5"
          strokeDasharray={isVerifying ? "18 10" : "none"}
          className="transition-all duration-500"
        />
        <circle
          cx="14"
          cy="14"
          r={isVerified ? "7" : isVerifying ? "5" : "6"}
          fill={
            isError
              ? "var(--color-accent)"
              : isVerified
                ? "var(--color-ink)"
                : "transparent"
          }
          stroke={isError ? "var(--color-accent)" : "var(--color-ink)"}
          strokeWidth="1.2"
          className="transition-all duration-500 motion-safe:animate-pulse"
        />
        {isVerified && (
          <path
            d="M10.5 14.2L12.8 16.5L17.6 11.5"
            fill="none"
            stroke="var(--color-paper)"
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}
        {isError && (
          <path
            d="M14 10v5M14 17.5h.01"
            fill="none"
            stroke="#fff"
            strokeWidth="1.75"
            strokeLinecap="round"
          />
        )}
      </svg>
    </span>
  );
}

export function VisualTrustDashboard({
  phase,
  node,
  model,
  checks,
  evidence,
  onOpenInspector,
  onOpenTerminalModal,
  onExportProof,
  canExportProof = false,
  onRetryVerify,
  onDismissError,
  errorMessage,
  verifyAnchorUrl,
  publishingProof,
  onPublishProof,
}: VisualTrustDashboardProps) {
  const [expertsMenuOpen, setExpertsMenuOpen] = useState(false);

  const passedChecks = checks.filter((c) => c.status === "pass").length;
  const failedChecks = checks.filter((c) => c.status === "fail");
  const hasFailure = phase === "error" || failedChecks.length > 0;
  const isVerified =
    (phase === "ready" || phase === "streaming") &&
    !hasFailure &&
    checks.length > 0;

  const chipIdValue =
    evidence["Chip ID"] ||
    evidence.chipId ||
    (phase === "verifying"
      ? "Loading"
      : phase === "idle"
        ? "Unavailable (run seal check first)"
        : "Unavailable");

  const plainReason = friendlyFailureReason(errorMessage, failedChecks);

  const rawFailureDetail =
    errorMessage ||
    (failedChecks.length > 0
      ? failedChecks
          .map((c) => `${c.id} (${c.label}): ${c.detail}`)
          .join(" · ")
      : null);

  const checkSummaryLabel =
    checks.length > 0
      ? `${passedChecks}/${checks.length} checks passed`
      : phase === "verifying"
        ? "Checking seal..."
        : "Waiting for seal check";

  const sealState: "verified" | "verifying" | "error" | "idle" = hasFailure
    ? "error"
    : isVerified
      ? "verified"
      : phase === "verifying"
        ? "verifying"
        : "idle";

  return (
    <div className="ep-card p-4 sm:p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <AnimatedInkSeal state={sealState} />
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              {hasFailure ? (
                <span
                  className="ep-fail"
                  data-testid="attestation-status-badge"
                >
                  Not safe to send right now
                </span>
              ) : isVerified ? (
                <span
                  className="ep-pass"
                  data-testid="attestation-status-badge"
                >
                  {node?.kind === "sim"
                    ? "Practice mode ready"
                    : "Sealed and private"}
                </span>
              ) : (
                <span
                  className="ep-muted-chip"
                  data-testid="attestation-status-badge"
                >
                  {phase === "verifying"
                    ? "Checking seal..."
                    : phase === "closed"
                      ? "Chat ended"
                      : "Getting ready"}
                </span>
              )}
              {node?.kind === "sim" && (
                <span className="ep-muted-chip">Practice mode</span>
              )}
            </div>

            <p className="text-sm font-medium text-ink sm:text-base">
              {hasFailure
                ? `Not safe to send right now. ${plainReason}`
                : isVerified
                  ? node?.kind === "sim"
                    ? "Practice mode active. Your messages stay in a safe practice sandbox and do not use real sealed computers."
                    : "Sealed and private. Your messages can only be opened by a sealed computer."
                  : phase === "verifying"
                    ? "We are checking that the sealed computer is genuine before opening your chat..."
                    : phase === "closed"
                      ? "Chat closed. Your temporary keys were wiped from this browser."
                      : "We check the seal on the computer before any message can leave your device."}
            </p>

            {hasFailure && onRetryVerify && (
              <div className="pt-1">
                <button
                  type="button"
                  onClick={onRetryVerify}
                  className="ep-btn-accent px-3.5 py-1.5 text-xs"
                >
                  Retry
                </button>
              </div>
            )}

            {!hasFailure && errorMessage && (
              <div
                role="alert"
                className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded border border-accent bg-accent-soft px-3 py-1.5 text-xs text-accent"
              >
                <span>{errorMessage}</span>
                {onDismissError && (
                  <button
                    type="button"
                    onClick={onDismissError}
                    className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                  >
                    Dismiss
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Small "For experts" menu */}
        <div className="relative self-start sm:self-center shrink-0">
          <details
            open={expertsMenuOpen}
            onToggle={(e) =>
              setExpertsMenuOpen((e.currentTarget as HTMLDetailsElement).open)
            }
            className="relative"
          >
            <summary className="ep-btn-ghost cursor-pointer list-none px-3 py-1.5 text-xs select-none">
              For experts
            </summary>
            <div className="ep-card absolute right-0 z-20 mt-1.5 flex w-52 flex-col gap-1 p-2 shadow-sm">
              <button
                type="button"
                onClick={() => {
                  setExpertsMenuOpen(false);
                  onOpenInspector("overview");
                }}
                className="rounded px-2.5 py-1.5 text-left text-xs font-medium text-ink hover:bg-paper-2"
              >
                Inspect raw records
              </button>
              <button
                type="button"
                onClick={() => {
                  setExpertsMenuOpen(false);
                  onOpenTerminalModal();
                }}
                className="rounded px-2.5 py-1.5 text-left text-xs font-medium text-ink hover:bg-paper-2"
              >
                Use from terminal
              </button>
              {onExportProof && (
                <button
                  type="button"
                  onClick={() => {
                    setExpertsMenuOpen(false);
                    onExportProof();
                  }}
                  disabled={!canExportProof}
                  className="rounded px-2.5 py-1.5 text-left text-xs font-medium text-ink hover:bg-paper-2 disabled:opacity-45"
                >
                  Export proof
                </button>
              )}
            </div>
          </details>
        </div>
      </div>

      <div className="mt-3 border-t border-rule pt-2.5">
        <TechDetails label={`Show technical details (${checkSummaryLabel})`}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-ink-2">
              <span>Model ID: {model}</span>
              <span>·</span>
              <span>Chip ID: {chipIdValue}</span>
            </div>

            {rawFailureDetail && hasFailure && (
              <div className="ep-inset p-2.5 font-mono text-xs text-accent">
                {rawFailureDetail}
              </div>
            )}

            <CheckList checks={checks} pending={phase === "verifying"} />

            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-3">
                {onPublishProof && isVerified && !verifyAnchorUrl && (
                  <button
                    type="button"
                    disabled={publishingProof}
                    onClick={onPublishProof}
                    className="ep-btn-ghost px-2.5 py-1 text-xs"
                  >
                    {publishingProof
                      ? "Recording in public receipt book..."
                      : "Record seal check in public receipt book (optional)"}
                  </button>
                )}
                {verifyAnchorUrl && (
                  <a
                    href={verifyAnchorUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-link text-xs"
                  >
                    View entry in the public receipt book
                  </a>
                )}
              </div>

              <button
                type="button"
                onClick={() => onOpenInspector("silicon")}
                className="ep-link text-xs"
              >
                Open full hardware and release records
              </button>
            </div>

            {Object.keys(evidence).length > 0 && (
              <div className="ep-inset p-3">
                <div className="ep-label mb-2">Live hardware registers</div>
                <EvidenceTable evidence={evidence} />
              </div>
            )}
          </div>
        </TechDetails>
      </div>
    </div>
  );
}
