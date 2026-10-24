"use client";

import type { CheckResult, NodeRecord, PopReceipt } from "@/lib/types";

const DEFAULT_CHECK_LABELS: Record<string, string> = {
  C1: "Hardware signature chain",
  C2: "Approved open-source release",
  C3: "Session key bound to hardware",
  C4: "Running code matches release",
  C5: "GPUs in confidential mode",
  C6: "Registry and quorum admission",
  C7: "Committed model weights",
};

export function CheckList({
  checks,
  pending,
}: {
  checks: CheckResult[];
  pending: boolean;
}) {
  const ids = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"];

  return (
    <ol className="divide-y divide-rule border-t border-b border-rule">
      {ids.map((id) => {
        const check = checks.find((c) => c.id === id);
        const status = check?.status;
        return (
          <li key={id} className="py-2.5 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-xs text-ink-3">{id}</span>
                <span className="font-medium text-ink">
                  {check?.label ?? DEFAULT_CHECK_LABELS[id] ?? "Check"}
                </span>
              </div>
              {status === "pass" ? (
                <span className="ep-pass">Pass</span>
              ) : status === "fail" ? (
                <span className="ep-fail">Fail</span>
              ) : (
                <span className="ep-muted-chip">
                  {pending ? "Checking" : status === "skip" ? "Skipped" : "Waiting"}
                </span>
              )}
            </div>
            {check?.detail && (
              <p className="mt-1 pl-7 text-xs text-ink-2">{check.detail}</p>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function EvidenceTable({
  evidence,
}: {
  evidence: Record<string, string>;
}) {
  const entries = Object.entries(evidence).filter(
    ([key]) =>
      key !== "chipId" &&
      key !== "tcb" &&
      key !== "guestPolicy" &&
      key !== "gpuEnclaveHost" &&
      key !== "gpuVmShape" &&
      key !== "pinnedWeights" &&
      key !== "dmVerityRoot" &&
      key !== "relayHop" &&
      key !== "lastBucketBytes",
  );

  if (entries.length === 0) {
    return <p className="text-xs text-ink-3">No hardware registers loaded yet.</p>;
  }

  return (
    <dl className="divide-y divide-rule border-t border-b border-rule text-xs">
      {entries.map(([key, value]) => (
        <div
          key={key}
          className="grid grid-cols-1 gap-1 py-2 sm:grid-cols-[10rem_1fr] sm:gap-3"
        >
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-3">
            {key}
          </dt>
          <dd className="ep-mono">{value || "Unavailable"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function NodeBadge({ node }: { node: NodeRecord }) {
  const real = node.kind === "tinfoil";
  return (
    <span className={real ? "ep-pass" : "ep-muted-chip"}>
      {real ? "Real enclave" : "Simulated"}
    </span>
  );
}

export function ReceiptView({
  receipt,
  anchorUrl,
}: {
  receipt: PopReceipt;
  anchorUrl?: string | null;
}) {
  return (
    <div className="ep-inset p-3.5 text-xs text-ink">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="font-medium text-ink">
          Session closed and ephemeral keys cleared
        </span>
        <span className={receipt.verified ? "ep-pass" : "ep-fail"}>
          {receipt.verified ? "Signed receipt" : "Invalid signature"}
        </span>
      </div>
      <EvidenceTable
        evidence={{
          "Session hash": receipt.sessionIdHash,
          "Time": new Date(receipt.time * 1000).toISOString(),
          "Measurement": receipt.measurement,
          "Signed by": receipt.signerPublicKey,
        }}
      />
      {anchorUrl && (
        <a
          className="ep-link mt-2 inline-block text-xs"
          href={anchorUrl}
          target="_blank"
          rel="noreferrer"
        >
          View receipt on Arc testnet explorer
        </a>
      )}
    </div>
  );
}
