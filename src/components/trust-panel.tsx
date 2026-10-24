"use client";

import type { CheckResult, NodeRecord, PopReceipt } from "@/lib/types";

const STATUS_STYLE: Record<CheckResult["status"], string> = {
  pass: "text-emerald-400",
  fail: "text-rose-400",
  skip: "text-zinc-500",
};
const STATUS_ICON: Record<CheckResult["status"], string> = { pass: "✓", fail: "✗", skip: "–" };

export function CheckList({ checks, pending }: { checks: CheckResult[]; pending: boolean }) {
  const ids = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"];
  return (
    <ol className="space-y-2">
      {ids.map((id) => {
        const check = checks.find((c) => c.id === id);
        return (
          <li key={id} className="rounded-md border border-zinc-800 bg-zinc-900/60 px-3 py-2">
            <div className="flex items-center gap-2 text-sm">
              <span className={`w-4 font-mono ${check ? STATUS_STYLE[check.status] : "text-zinc-600"}`}>
                {check ? STATUS_ICON[check.status] : pending ? "…" : "·"}
              </span>
              <span className="font-mono text-xs text-zinc-500">{id}</span>
              <span className="text-zinc-200">{check?.label ?? "Waiting"}</span>
            </div>
            {check && <p className="mt-1 pl-6 text-xs leading-relaxed text-zinc-400">{check.detail}</p>}
          </li>
        );
      })}
    </ol>
  );
}

export function EvidenceTable({ evidence }: { evidence: Record<string, string> }) {
  return (
    <dl className="space-y-1.5 text-xs">
      {Object.entries(evidence).map(([key, value]) => (
        <div key={key} className="grid grid-cols-[7.5rem_1fr] gap-2">
          <dt className="text-zinc-500">{key}</dt>
          <dd className="break-all font-mono text-zinc-300">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function NodeBadge({ node }: { node: NodeRecord }) {
  const real = node.kind === "tinfoil";
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
        real ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300"
      }`}
    >
      {real ? "Real enclave" : "Simulated hardware"}
    </span>
  );
}

export function ReceiptView({ receipt, anchorUrl }: { receipt: PopReceipt; anchorUrl?: string | null }) {
  return (
    <div className="rounded-md border border-sky-900 bg-sky-950/40 p-3 text-xs text-sky-100">
      <p className="mb-2 font-semibold">Bubble popped: session keys destroyed</p>
      <EvidenceTable
        evidence={{
          "Session hash": receipt.sessionIdHash,
          "Time": new Date(receipt.time * 1000).toISOString(),
          "Measurement": receipt.measurement,
          "Signed by": receipt.signerPublicKey,
          "Signature": receipt.verified ? "verified ✓" : "INVALID",
        }}
      />
      {anchorUrl && (
        <a className="mt-2 inline-block text-sky-300 underline" href={anchorUrl} target="_blank" rel="noreferrer">
          Receipt anchored on Arc ↗
        </a>
      )}
    </div>
  );
}
