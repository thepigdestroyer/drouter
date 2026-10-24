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
  creditBalance: number;
  evidence: Record<string, string>;
  onOpenInspector: (initialTab?: InspectorTab) => void;
  onOpenTerminalModal: () => void;
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
  errorMessage,
  verifyAnchorUrl,
  publishingProof,
  onPublishProof,
}: VisualTrustDashboardProps) {
  const passedChecks = checks.filter((c) => c.status === "pass").length;
  const totalChecks = checks.length > 0 ? checks.length : 7;
  const failedCheck = checks.find((c) => c.status === "fail");
  const hasFailure = phase === "error" || Boolean(failedCheck);
  const isVerified =
    (phase === "ready" || phase === "streaming") &&
    !hasFailure &&
    checks.length > 0;

  const chipIdValue =
    evidence["Chip ID"] ||
    evidence.chipId ||
    (phase === "verifying" ? "Loading" : "Unavailable");

  const failureReason =
    errorMessage ||
    (failedCheck
      ? `${failedCheck.id} (${failedCheck.label}): ${failedCheck.detail}`
      : "Hardware verification did not complete. Your message was not sent.");

  return (
    <div className="ep-card p-4 sm:p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="max-w-[70ch]">
          <div className="flex flex-wrap items-center gap-2">
            {hasFailure ? (
              <span className="ep-fail">Not verified</span>
            ) : isVerified ? (
              <span className="ep-pass">
                {passedChecks}/{totalChecks} checks passed
              </span>
            ) : (
              <span className="ep-muted-chip">
                {phase === "verifying"
                  ? "Verifying"
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
            {hasFailure
              ? "Not verified"
              : isVerified
                ? "Verified. Your message goes only to sealed hardware."
                : phase === "verifying"
                  ? "Checking enclave hardware..."
                  : phase === "closed"
                    ? "Session ended. Browser keys cleared."
                    : "Waiting to verify hardware."}
          </h2>

          <p className="mt-1.5 text-sm text-ink-2">
            {hasFailure
              ? failureReason
              : isVerified
                ? node?.kind === "sim"
                  ? `Connected to ${node.name} (Simulated in software for testing).`
                  : `Connected to attested router ${evidence["Enclave host"] || "router-0.tinfoil.sh"} and model enclave for ${model}.`
                : phase === "verifying"
                  ? "Your browser is checking the hardware quote, signed release, and registry before creating session keys."
                  : phase === "closed"
                    ? "Ephemeral session keys and local identifier placeholders have been wiped from browser memory."
                    : "Your browser verifies 7 hardware and software checks before sending any prompt."}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
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
          <span>
            See the 7 checks ({passedChecks}/{totalChecks} passed)
          </span>
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
