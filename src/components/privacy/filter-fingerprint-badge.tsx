"use client";

import React, { useEffect, useState } from "react";
import { TechDetails } from "@/components/ink/tech-details";
import {
  ARC_TESTNET_CHAIN_ID,
  getPublishedFilterFingerprint,
  verifyFilterFingerprint,
  type FilterFingerprintStatus,
  type VerifyFilterFingerprintOptions,
} from "@/lib/privacy/fingerprint";
import { MECHANICAL_RULESET } from "@/lib/privacy/mechanical-ruleset";

function createInitialCheckingStatus(): FilterFingerprintStatus {
  const published = getPublishedFilterFingerprint();
  const version = MECHANICAL_RULESET.version;
  return {
    state: "checking",
    version,
    computedFingerprint: "",
    publishedFingerprint: published.fingerprint,
    anchorTx: published.anchorTx,
    anchorUrl: null,
    anchorReceiptHash: "",
    arcReceiptVerified: null,
    blockingSend: false,
    plainSummary: `Personal-detail filter v${version}: checking version...`,
    blockReason: null,
  };
}

/**
 * Recomputes the filter fingerprint in the browser after mount (never during render),
 * compares it with `published-fingerprint.json`, and checks the anchor receipt on Arc
 * via read-only `eth_getTransactionReceipt`.
 */
export function useFilterFingerprintStatus(
  opts?: VerifyFilterFingerprintOptions,
): FilterFingerprintStatus {
  const [status, setStatus] = useState<FilterFingerprintStatus>(() =>
    createInitialCheckingStatus(),
  );

  useEffect(() => {
    let cancelled = false;
    void verifyFilterFingerprint(opts).then((next) => {
      if (!cancelled) {
        setStatus(next);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [opts]);

  return status;
}

export interface FilterFingerprintBadgeProps {
  status?: FilterFingerprintStatus;
  verifyOptions?: VerifyFilterFingerprintOptions;
  defaultOpenTechDetails?: boolean;
}

export function renderFilterFingerprintSummaryText(
  status: FilterFingerprintStatus,
): string {
  if (status.state === "not-published") {
    return `Personal-detail filter v${status.version}: not yet published`;
  }
  if (status.state === "match") {
    return `Personal-detail filter v${status.version}: matches the published version`;
  }
  if (status.state === "receipt-missing") {
    return `Personal-detail filter v${status.version}: matches the published version (public receipt pending)`;
  }
  if (status.state === "mismatch") {
    return `Personal-detail filter v${status.version}: does not match the published version`;
  }
  return `Personal-detail filter v${status.version}: checking version...`;
}

export function FilterFingerprintBadge({
  status: externalStatus,
  verifyOptions,
  defaultOpenTechDetails = false,
}: FilterFingerprintBadgeProps): React.JSX.Element {
  const internalStatus = useFilterFingerprintStatus(verifyOptions);
  const status = externalStatus ?? internalStatus;
  const summaryText = renderFilterFingerprintSummaryText(status);
  const isMismatch = status.state === "mismatch";

  return (
    <div
      className="space-y-2 text-xs text-ink-2"
      data-testid="filter-fingerprint-badge"
      data-filter-state={status.state}
    >
      {isMismatch ? (
        <div
          role="alert"
          data-testid="filter-fingerprint-mismatch-alert"
          className="rounded border border-accent bg-accent-soft p-3 text-xs text-accent space-y-1"
        >
          <div className="font-semibold">{summaryText}</div>
          <p>
            {status.blockReason ??
              "Sending is blocked because the personal-detail filter running in this browser does not match the published version in the public receipt book."}
          </p>
        </div>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span
            className="font-medium text-ink"
            data-testid="filter-fingerprint-summary"
          >
            {summaryText}
          </span>
          {status.state === "match" && (
            <span className="ep-pass">Verified</span>
          )}
          {status.state === "not-published" && (
            <span className="ep-muted-chip">Unpublished</span>
          )}
          {status.state === "receipt-missing" && (
            <span className="ep-muted-chip">Receipt pending</span>
          )}
        </div>
      )}

      <TechDetails
        label="Show technical details (filter rule set)"
        defaultOpen={defaultOpenTechDetails}
      >
        <div className="space-y-1.5 font-mono text-[11px] text-ink-2">
          <div>Rule-set version: {status.version}</div>
          <div className="break-all">
            Browser SHA-256 fingerprint:{" "}
            {status.computedFingerprint || "Computing..."}
          </div>
          <div className="break-all">
            Published SHA-256 fingerprint:{" "}
            {status.publishedFingerprint ?? "Not yet published"}
          </div>
          {status.anchorReceiptHash && (
            <div className="break-all">
              Arc anchor digest (keccak256): {status.anchorReceiptHash}
            </div>
          )}
          <div>
            Arc network: chain ID {ARC_TESTNET_CHAIN_ID} (eth_getTransactionReceipt:{" "}
            {status.arcReceiptVerified === true
              ? "confirmed"
              : status.arcReceiptVerified === false
                ? "not found"
                : "not applicable"}
            )
          </div>
          {status.anchorTx && status.anchorUrl ? (
            <div className="pt-1">
              <a
                href={status.anchorUrl}
                target="_blank"
                rel="noreferrer"
                className="ep-link text-xs"
                data-testid="filter-fingerprint-tx-link"
              >
                View anchor transaction on Arc ({status.anchorTx.slice(0, 10)}...
                {status.anchorTx.slice(-6)})
              </a>
            </div>
          ) : (
            <div>Anchor transaction: none recorded yet</div>
          )}
        </div>
      </TechDetails>
    </div>
  );
}

export default FilterFingerprintBadge;
