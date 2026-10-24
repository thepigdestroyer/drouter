"use client";

import React from "react";
import type { CheckResult, NodeRecord } from "@/lib/types";
import { CheckList, EvidenceTable } from "@/components/trust-panel";

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
  const passedChecks = checks.filter((c) => c.status === "pass").length;
  const failedChecks = checks.filter((c) => c.status === "fail");
  const failedCheck = failedChecks[0];
  const hasAttestationFailure =
    phase === "error" || failedChecks.length > 0;
  const isVerified =
    (phase === "ready" || phase === "streaming") &&
    !hasAttestationFailure &&
    checks.length > 0;

  const chipIdValue =
    evidence["Chip ID"] ||
    evidence.chipId ||
    (phase === "verifying"
      ? "Loading"
      : phase === "idle"
        ? "Unavailable (verify hardware first)"
        : "Unavailable (not reported by enclave)");

  const enclaveHostValue =
    evidence["Enclave host"] ||
    (phase === "verifying"
      ? "Loading"
      : "Unavailable (enclave host not reported)");

  const failureReason =
    errorMessage ||
    (failedChecks.length > 0
      ? failedChecks
          .map((c) => `${c.id} (${c.label}): ${c.detail}`)
          .join(" · ")
      : "Hardware verification did not complete. Sending is blocked until verification passes.");

  const checkSummaryLabel =
    checks.length > 0
      ? `${passedChecks}/${checks.length} passed`
      : phase === "verifying"
        ? "Loading"
        : "Unavailable (not verified yet)";

  return (
    <div className="ep-card p-4 sm:p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="max-w-[70ch]">
          <div className="flex flex-wrap items-center gap-2">
            {hasAttestationFailure ? (
              <span className="ep-fail" data-testid="attestation-status-badge">
                Not verified
              </span>
            ) : isVerified ? (
              <span className="ep-pass" data-testid="attestation-status-badge">
                {passedChecks}/{checks.length} checks passed
              </span>
            ) : (
              <span
                className="ep-muted-chip"
                data-testid="attestation-status-badge"
              >
                {phase === "verifying"
                  ? "Loading"
                  : phase === "closed"
                    ? "Session closed"
                    : "Standby"}
              </span>
            )}
            {node?.kind === "sim" && (
              <span className="ep-muted-chip">Simulated node</span>
            )}
          </div>

          <h2 className="ep-display mt-2 text-2xl sm:text-3xl">
            {hasAttestationFailure
              ? "Not verified"
              : isVerified
                ? node?.kind === "sim"
                  ? "Simulated session ready (software simulation only)."
                  : "Verified. Your message goes only to sealed hardware."
                : phase === "verifying"
                  ? "Checking enclave hardware..."
                  : phase === "closed"
                    ? "Session ended. Browser keys cleared."
                    : "Waiting to verify hardware."}
          </h2>

          <p className="mt-1.5 text-sm text-ink-2">
            {hasAttestationFailure
              ? `${
                  failureReason.endsWith(".")
                    ? failureReason
                    : `${failureReason}.`
                }${
                  failedCheck || phase === "error"
                    ? " Sending is blocked until hardware verification passes."
                    : ""
                }`
              : isVerified
                ? node?.kind === "sim"
                  ? `Connected to ${node.name} (Simulated in software from SIM_HARDWARE_SEED; no real TEE hardware is used in Simulated mode).`
                  : `Connected to attested router ${enclaveHostValue} and model enclave for ${model}.`
                : phase === "verifying"
                  ? "Your browser is checking the hardware quote, signed release, and registry before creating session keys."
                  : phase === "closed"
                    ? "Ephemeral session keys and local identifier placeholders have been wiped from browser memory."
                    : "Your browser verifies 7 hardware and software checks before sending any prompt."}
          </p>

          {hasAttestationFailure && onRetryVerify && (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={onRetryVerify}
                className="ep-btn-ghost px-3 py-1 text-xs"
              >
                Retry verification
              </button>
            </div>
          )}

          {!hasAttestationFailure && errorMessage && (
            <div
              role="alert"
              className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded border border-accent bg-accent-soft px-3 py-2 text-xs text-accent"
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

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onExportProof && (
            <button
              type="button"
              onClick={onExportProof}
              disabled={!canExportProof}
              title={
                canExportProof
                  ? "Download signed forensic session proof (.drouter-proof.json)"
                  : "Verify hardware first to export a session proof"
              }
              className="ep-btn-ghost px-3 py-1.5 text-xs disabled:opacity-45"
            >
              Export proof
            </button>
          )}
          <button
            type="button"
            onClick={() => onOpenInspector("overview")}
            className="ep-btn-ghost px-3 py-1.5 text-xs"
          >
            Inspect raw records
          </button>
          <button
            type="button"
            onClick={onOpenTerminalModal}
            className="ep-btn-ghost px-3 py-1.5 text-xs"
          >
            Use from terminal
          </button>
        </div>
      </div>

      <details className="mt-4 border-t border-rule pt-3">
        <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 text-xs font-medium text-ink hover:underline">
          <span>See the 7 checks ({checkSummaryLabel})</span>
          <span className="font-mono text-[11px] text-ink-3">
            Chip ID: {chipIdValue}
          </span>
        </summary>

        <div className="mt-3 space-y-4">
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
                    ? "Anchoring on Arc testnet..."
                    : "Anchor verification proof on Arc testnet (opt-in)"}
                </button>
              )}
              {verifyAnchorUrl && (
                <a
                  href={verifyAnchorUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="ep-link text-xs"
                >
                  View verification transaction on Arc testnet explorer
                </a>
              )}
            </div>

            <button
              type="button"
              onClick={() => onOpenInspector("silicon")}
              className="ep-link text-xs"
            >
              Open full hardware and Sigstore records
            </button>
          </div>

          {Object.keys(evidence).length > 0 && (
            <details className="ep-inset p-3">
              <summary className="cursor-pointer text-xs font-medium text-ink">
                Show live attested registers
              </summary>
              <div className="mt-2.5">
                <EvidenceTable evidence={evidence} />
              </div>
            </details>
          )}
        </div>
      </details>
    </div>
  );
}
