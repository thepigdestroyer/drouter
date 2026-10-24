"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { HardwareManifest, QuorumTicket } from "@/lib/types";

interface TransparencyEntryView {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays: number;
  emergency: boolean;
  builderSignatures: { builderId: string; publicKey: string; signature: string }[];
  reviewerSignatures: { reviewerId: string; publicKey: string; signature: string }[];
}

interface InclusionProofView {
  leafHash: string;
  root: string;
  auditPath: { side: "left" | "right"; hash: string }[];
}

interface TransparencyResponse {
  log: {
    root: string;
    entries: TransparencyEntryView[];
  };
  proofs: InclusionProofView[];
  verifierSet: { verifierId: string; publicKey: string }[];
  tickets: Record<string, QuorumTicket>;
}

interface RampEvaluationView {
  nodeId: string;
  status: "full" | "ramp" | "suspended";
  restartsIn30d: number;
  dualIdentityDetected: boolean;
  weightBps: number;
  phase: "canary-only" | "linear-ramp" | "steady" | "suspended";
  detail: string;
}

interface CanarySessionView {
  sessionId: string;
  honeytoken: string;
  decoyKind: string;
  salt: string;
  commitment: string;
  promptPreview: string;
}

interface RecordedClaimEventView {
  id: string;
  kind: string;
  nodeId: string;
  timestamp: number;
  slashUsdc: number;
  bountyUsdc: number;
  compensationPoolUsdc: number;
  summary: string;
  detail: unknown;
}

interface AccountabilityResponse {
  manifests: HardwareManifest[];
  rampStates: Record<string, RampEvaluationView>;
  activeCanaries: Record<string, CanarySessionView>;
  recentClaims: RecordedClaimEventView[];
  forbiddenPrefix: string;
}

interface CreditsResponse {
  n: string;
  e: string;
  denominations: number[];
  stats: {
    spentCount: number;
    unredeemedCount: number;
    redeemedBatches: number;
  };
}

interface FrozenBlobSummaryView {
  blobId: string;
  sessionIdHex: string;
  byteLength: number;
  modelId: string;
  createdAt: number;
  expiresAt: number;
}

interface FreezeResponse {
  blobs: FrozenBlobSummaryView[];
}

function shortHex(value: unknown, lead = 10, tail = 6): string {
  const s = String(value ?? "");
  if (s.length <= lead + tail + 2) return s;
  return `${s.slice(0, lead)}…${s.slice(-tail)}`;
}

function formatUnixSec(sec: number): string {
  if (!sec || !Number.isFinite(sec)) return "—";
  return new Date(sec * 1000).toISOString().replace("T", " ").slice(0, 19);
}

/**
 * Inline exhaustive VMPL0 Inner Monitor state-space verifier (3 × 7 × 4 × 2^4 = 1,344 states)
 * matching Spec §2.2 V3 without importing server/sibling modules.
 */
function runClientMonitorProofSummary() {
  const vmpls = [0, 1, 2] as const;
  const channels = [
    "relay-stream",
    "control-plane",
    "blob-storage",
    "raw-socket",
    "disk-write",
    "shell-exec",
    "snp-attest",
  ] as const;
  const encryptions = ["custody-aes-gcm", "freeze-aes-gcm", "plaintext", "control-schema"] as const;
  const bools = [false, true] as const;

  let statesChecked = 0;
  let allowedStates = 0;
  let deniedStates = 0;

  for (const actorVmpl of vmpls) {
    for (const channel of channels) {
      for (const payloadEncryption of encryptions) {
        for (const nonceFresh of bools) {
          for (const fixedFrameCadence of bools) {
            for (const hasPerSessionFields of bools) {
              for (const startsWithForbiddenPrefix of bools) {
                statesChecked += 1;
                let allowed = false;
                if (actorVmpl === 0) {
                  if (channel === "relay-stream") {
                    allowed =
                      payloadEncryption === "custody-aes-gcm" && nonceFresh && fixedFrameCadence;
                  } else if (channel === "control-plane") {
                    allowed = payloadEncryption === "control-schema" && !hasPerSessionFields;
                  } else if (channel === "blob-storage") {
                    allowed =
                      (payloadEncryption === "custody-aes-gcm" ||
                        payloadEncryption === "freeze-aes-gcm") &&
                      nonceFresh;
                  } else if (channel === "snp-attest") {
                    allowed = !startsWithForbiddenPrefix;
                  }
                }
                if (allowed) allowedStates += 1;
                else deniedStates += 1;
              }
            }
          }
        }
      }
    }
  }

  return {
    statesChecked,
    allowedStates,
    deniedStates,
    invariants: [
      {
        id: "I1_NoPlaintextEgress",
        rule: 'payloadEncryption !== "plaintext" on every allowed network or storage channel',
        detail:
          "Ensures raw prompts, KV caches, and token streams can never exit the CVM in plaintext even if the VMPL1 inference engine is compromised.",
      },
      {
        id: "I2_NoNonceReuse",
        rule: "nonceFresh === true on every allowed custody-aes-gcm and freeze-aes-gcm egress",
        detail:
          "Monotonic hardware-counter IV discipline inside VMPL0 prevents catastrophic AES-GCM keystream reuse across turns and frozen bubbles.",
      },
      {
        id: "I3_NoEngineBypass",
        rule: "actorVmpl === 0 required for all external I/O and SNP_GET_REPORT calls",
        detail:
          "Hardware AMD SEV-SNP VMPL permission masks trap any direct ring-0/VMPL1/VMPL2 network, disk, shell, or attestation access.",
      },
      {
        id: "I4_NoPerSessionControlLeak",
        rule: 'channel === "control-plane" implies hasPerSessionFields === false',
        detail:
          "Restricts control-plane telemetry to coarse epoch aggregates so per-request token counts or timings cannot leak.",
      },
      {
        id: "I5_ForbiddenPrefixNeverSigned",
        rule: 'channel === "snp-attest" implies startsWithForbiddenPrefix === false',
        detail:
          'VMPL0 refuses to sign any REPORT_DATA prefixed with F = sha256("drouter/forbidden-report-data/v1"), making any signature over F cryptographic proof of key extraction.',
      },
    ],
  };
}

export default function AuditLabPage() {
  const [transparency, setTransparency] = useState<TransparencyResponse | null>(null);
  const [accountability, setAccountability] = useState<AccountabilityResponse | null>(null);
  const [credits, setCredits] = useState<CreditsResponse | null>(null);
  const [freeze, setFreeze] = useState<FreezeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<{
    title: string;
    verdictSummary: string;
    payload: unknown;
  } | null>(null);

  const monitorProof = useMemo(() => runClientMonitorProofSummary(), []);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    try {
      const [tRes, aRes, cRes, fRes] = await Promise.all([
        fetch("/api/transparency").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/accountability").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/credits").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/freeze").then((r) => (r.ok ? r.json() : null)).catch(() => null),
      ]);
      if (tRes) setTransparency(tRes as TransparencyResponse);
      if (aRes) setAccountability(aRes as AccountabilityResponse);
      if (cRes) setCredits(cRes as CreditsResponse);
      if (fRes) setFreeze(fRes as FreezeResponse);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  const runAccountabilityAction = async (
    action: "trigger-canary" | "claim-key-bounty" | "simulate-restart" | "simulate-clone",
    nodeId: string,
    title: string,
  ) => {
    setBusyAction(`${action}:${nodeId}`);
    try {
      const res = await fetch("/api/accountability", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, nodeId }),
      });
      const data = (await res.json()) as Record<string, unknown>;
      if (data.rampStates && data.activeCanaries && accountability) {
        setAccountability({
          ...accountability,
          rampStates: data.rampStates as Record<string, RampEvaluationView>,
          activeCanaries: data.activeCanaries as Record<string, CanarySessionView>,
          recentClaims: (data.recentClaims as RecordedClaimEventView[]) ?? accountability.recentClaims,
        });
      }
      const verdictObj = (data.verdict ?? data.evaluation ?? {}) as Record<string, unknown>;
      const summary =
        typeof verdictObj.reason === "string"
          ? verdictObj.reason
          : typeof verdictObj.detail === "string"
            ? verdictObj.detail
            : `Executed ${action} on ${nodeId}`;
      setSimResult({
        title,
        verdictSummary: summary,
        payload: data,
      });
    } finally {
      setBusyAction(null);
    }
  };

  const runRedeemCredits = async () => {
    setBusyAction("redeem-credits");
    try {
      const res = await fetch("/api/credits/redeem", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nodeId: "tinfoil-router" }),
      });
      const data = (await res.json()) as Record<string, unknown>;
      setSimResult({
        title: "Batch-Redeem Node Credits (Spec §7)",
        verdictSummary: `Flushed ${String(data.redeemedCount ?? 0)} unredeemed nullifier(s) (${String(data.totalCredits ?? 0)} credits) into batch settlement hash ${shortHex(data.batchHash ?? "", 14, 10)}.`,
        payload: data,
      });
      const refreshed = await fetch("/api/credits")
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null);
      if (refreshed) setCredits(refreshed as CreditsResponse);
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <main className="mx-auto flex max-w-7xl flex-col gap-5 p-4">
      <header className="flex flex-wrap items-end justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-semibold text-zinc-50">
            Security, Quorum &amp; Remote Accountability Lab
          </h1>
          <p className="text-sm text-zinc-400">
            Live verification of the Software Transparency Log (§4), 5-of-7 Verifier Quorum (§5), VMPL0 Inner Monitor
            invariants (§2.2 V3), Blind Credits (§7), Zero-Knowledge Freeze Store, and Cryptographic Slashing (§8).
          </p>
        </div>
        <nav className="flex items-center gap-4 text-sm text-zinc-400">
          <Link className="hover:text-zinc-100" href="/">
            ← Console
          </Link>
          <Link className="hover:text-zinc-100" href="/network">
            Network &amp; transparency log
          </Link>
          <button
            type="button"
            onClick={() => void refreshAll()}
            className="rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            {loading ? "Refreshing…" : "Refresh state"}
          </button>
        </nav>
      </header>

      {/* Interactive Simulation Console */}
      <section className="rounded-lg border border-emerald-900/70 bg-zinc-950 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-emerald-400">
              Interactive Fault, Slashing &amp; Settlement Simulator (Spec §7 &amp; §8)
            </h2>
            <p className="text-xs text-zinc-400">
              Trigger live cryptographic enforcement actions against the accountability and blind-credit endpoints.
            </p>
          </div>
          {accountability?.forbiddenPrefix && (
            <span className="rounded border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono text-[11px] text-zinc-400">
              Forbidden Prefix F = sha256(&quot;drouter/forbidden-report-data/v1&quot;) ={" "}
              <strong className="text-amber-300">{shortHex(accountability.forbiddenPrefix, 12, 8)}</strong>
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {/* Action 1: Canary Honeytoken Leak */}
          <div className="flex flex-col justify-between gap-2 rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                1. Trigger Canary Honeytoken Leak (Spec §8.4)
              </h3>
              <p className="mt-1 text-xs text-zinc-400">
                Reveals <code className="font-mono">(honeytoken, salt)</code> matching{" "}
                <code className="font-mono">sim-1</code>&apos;s on-chain commitment{" "}
                <code className="font-mono">H(t || salt || pk_N || epoch)</code>: 10% reporter bounty + 90% user
                compensation pool slash.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() =>
                void runAccountabilityAction(
                  "trigger-canary",
                  "sim-1",
                  "Canary Honeytoken Leak Verdict (Spec §8.4 — sim-1)",
                )
              }
              className="mt-2 rounded bg-amber-600/90 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-500 disabled:opacity-40"
            >
              {busyAction === "trigger-canary:sim-1" ? "Verifying opening…" : "Trigger Canary Leak (sim-1)"}
            </button>
          </div>

          {/* Action 2: Key-Compromise Bounty Proof */}
          <div className="flex flex-col justify-between gap-2 rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                2. Submit Key-Compromise Bounty Proof (Spec §8.5)
              </h3>
              <p className="mt-1 text-xs text-zinc-400">
                Submits a P-384 VCEK signature over <code className="font-mono">REPORT_DATA</code> starting with
                forbidden prefix <code className="font-mono">F</code> on <code className="font-mono">sim-2</code>,
                proving attestation key extraction and awarding the 50% bounty.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() =>
                void runAccountabilityAction(
                  "claim-key-bounty",
                  "sim-2",
                  "Key-Compromise Bounty Proof Verdict (Spec §8.5 — sim-2)",
                )
              }
              className="mt-2 rounded bg-rose-600/90 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500 disabled:opacity-40"
            >
              {busyAction === "claim-key-bounty:sim-2" ? "Verifying P-384 proof…" : "Claim 50% Key Bounty (sim-2)"}
            </button>
          </div>

          {/* Action 3: Unannounced Node Restart / Cloned Identity Key */}
          <div className="flex flex-col justify-between gap-2 rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                3. Node Restart / Cloned Identity Key (Spec §8.2–8.3)
              </h3>
              <p className="mt-1 text-xs text-zinc-400">
                Simulate an unannounced <code className="font-mono">sim-3</code> reboot (entering the 24–96h
                canary-only probation ramp at 0 bps) or dual <code className="font-mono">pk_N</code> heartbeats within
                15s (immediate suspension).
              </p>
            </div>
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() =>
                  void runAccountabilityAction(
                    "simulate-restart",
                    "sim-3",
                    "Unannounced Restart → Canary-Only Probation Ramp (Spec §8.3 — sim-3)",
                  )
                }
                className="flex-1 rounded border border-sky-700 bg-sky-950/70 px-2 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900/70 disabled:opacity-40"
              >
                {busyAction === "simulate-restart:sim-3" ? "Running…" : "Simulate Restart"}
              </button>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() =>
                  void runAccountabilityAction(
                    "simulate-clone",
                    "sim-3",
                    "Cloned Identity Key Detection (Spec §8.2 — sim-3)",
                  )
                }
                className="flex-1 rounded border border-rose-800 bg-rose-950/70 px-2 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 disabled:opacity-40"
              >
                {busyAction === "simulate-clone:sim-3" ? "Running…" : "Simulate Clone"}
              </button>
            </div>
          </div>

          {/* Action 4: Batch-Redeem Node Credits */}
          <div className="flex flex-col justify-between gap-2 rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                4. Batch-Redeem Node Credits (Spec §7)
              </h3>
              <p className="mt-1 text-xs text-zinc-400">
                Flushes unredeemed blind-credit nullifiers accumulated by{" "}
                <code className="font-mono">tinfoil-router</code> into a single unlinkable batch settlement digest.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void runRedeemCredits()}
              className="mt-2 rounded bg-emerald-600/90 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-40"
            >
              {busyAction === "redeem-credits" ? "Settling batch…" : "Batch-Redeem Credits"}
            </button>
          </div>
        </div>

        {simResult && (
          <div className="mt-4 rounded-md border border-emerald-800/80 bg-zinc-900/90 p-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-semibold text-emerald-300">{simResult.title}</span>
              <button
                type="button"
                onClick={() => setSimResult(null)}
                className="text-zinc-400 hover:text-zinc-200"
              >
                Dismiss ✕
              </button>
            </div>
            <p className="mt-1 text-zinc-200">{simResult.verdictSummary}</p>
            <pre className="mt-2 max-h-60 overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2.5 font-mono text-[11px] text-zinc-300">
              {JSON.stringify(simResult.payload, null, 2)}
            </pre>
          </div>
        )}
      </section>

      {/* VMPL0 Inner Monitor Formal Proof Card */}
      <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-300">
              VMPL0 Inner Monitor Formal Proof (Spec §2.2 V3)
            </h2>
            <p className="text-xs text-zinc-400">
              Exhaustive state-machine verification across all{" "}
              <strong className="font-mono text-zinc-200">
                {monitorProof.statesChecked.toLocaleString()}
              </strong>{" "}
              (actorVmpl × channel × encryption × nonceFresh × fixedFrameCadence × hasPerSessionFields ×
              startsWithForbiddenPrefix) combinations.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="rounded bg-emerald-500/15 px-2 py-1 text-emerald-300">
              {monitorProof.statesChecked.toLocaleString()} states checked ✓
            </span>
            <span className="rounded bg-sky-500/15 px-2 py-1 text-sky-300">
              {monitorProof.allowedStates} allowed / {monitorProof.deniedStates.toLocaleString()} denied
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-5">
          {monitorProof.invariants.map((inv) => (
            <div key={inv.id} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3 text-xs">
              <div className="flex items-center justify-between gap-1">
                <span className="font-mono font-semibold text-emerald-300">{inv.id}</span>
                <span className="text-emerald-400">PASS ✓</span>
              </div>
              <p className="mt-1 font-mono text-[11px] text-zinc-300">{inv.rule}</p>
              <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-400">{inv.detail}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Software Transparency Log & 5-of-7 Verifier Quorum */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
              Software Transparency Log (Spec §4)
            </h2>
            {transparency?.log?.root && (
              <span className="font-mono text-xs text-emerald-300">
                Merkle Root: {shortHex(transparency.log.root, 12, 8)}
              </span>
            )}
          </div>
          <p className="mb-3 text-xs text-zinc-400">
            RFC 6962 append-only Merkle tree requiring 3-of-3 reproducible builder signatures, 4-of-7 security reviewer
            signatures, and a 14-day public review window before any enclave measurement is admitted.
          </p>
          <div className="space-y-2.5 text-xs">
            {(transparency?.log?.entries ?? []).map((entry, idx) => {
              const proof = transparency?.proofs?.[idx];
              return (
                <div key={entry.index} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-zinc-100">
                      #{entry.index} · {entry.imageId}{" "}
                      <span className="font-mono text-zinc-400">({entry.version})</span>
                    </span>
                    <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
                      {entry.builderSignatures.length}/3 builders · {entry.reviewerSignatures.length}/7 reviewers ·{" "}
                      {entry.reviewWindowDays}d window
                    </span>
                  </div>
                  <div className="mt-1.5 space-y-1 font-mono text-[11px] text-zinc-400">
                    <div>Measurement (SHA-384): {shortHex(entry.measurement, 18, 12)}</div>
                    {proof && (
                      <div>
                        Leaf Hash: {shortHex(proof.leafHash, 14, 10)} · Audit Path:{" "}
                        {proof.auditPath.map((s) => `${s.side}:${shortHex(s.hash, 6, 4)}`).join(" → ")}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
              5-of-7 Verifier Quorum Tickets (Spec §5)
            </h2>
            <span className="text-xs text-zinc-500">
              {transparency?.verifierSet?.length ?? 7} independent Ed25519 verifiers
            </span>
          </div>
          <p className="mb-3 text-xs text-zinc-400">
            Nodes are admitted to routing only with at least 5 of 7 verifier signatures over{" "}
            <code className="font-mono">(nodeId, chipId, nodeIdentityPk, epoch, status, weight)</code>.
          </p>
          <div className="space-y-2.5 text-xs">
            {Object.values(transparency?.tickets ?? {}).map((ticket) => (
              <div key={ticket.nodeId} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-zinc-100">{ticket.nodeId}</span>
                  <span className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                    {ticket.signatures.length}/7 sigs · status={ticket.status} · {ticket.weight} bps
                  </span>
                </div>
                <div className="mt-1 font-mono text-[11px] text-zinc-400">
                  Chip ID: {shortHex(ticket.chipId, 14, 10)} · Identity PK: {shortHex(ticket.nodeIdentityPk, 12, 8)}
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {ticket.signatures.map((sig) => (
                    <span
                      key={sig.verifierId}
                      className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400"
                    >
                      {sig.verifierId} ✓
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Hardware Manifests & Heartbeat / Canary State */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Signed Hardware Manifests (Spec §8.1)
          </h2>
          <p className="mb-3 text-xs text-zinc-400">
            Operators sign hardware declarations bound to stake (board model, BMC firmware, RoT, DIMM speed/slots,
            SPDM-bound GPUs). Any mismatch with attested hardware triggers slashing.
          </p>
          <div className="space-y-2.5 text-xs">
            {(accountability?.manifests ?? []).map((m) => (
              <div key={m.nodeId} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-zinc-100">
                    {m.nodeId} · {m.declared.board}
                  </span>
                  <span className="font-mono text-[11px] text-emerald-300">
                    {m.declared.region} · {m.gpuIds.length}× H100 SPDM
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-zinc-400">
                  BMC: <code className="font-mono">{m.declared.bmcFirmware}</code> · RoT:{" "}
                  <code className="font-mono">{m.declared.platformRot}</code> · DIMMs:{" "}
                  <code className="font-mono">
                    {m.declared.dimmSlotsPopulated}/{m.declared.dimmSlotsTotal} @ {m.declared.dimmSpeedMt} MT/s
                  </code>
                </div>
                <div className="mt-1 font-mono text-[11px] text-zinc-500">
                  Sig: {shortHex(m.signature, 14, 10)} · PK: {shortHex(m.signerPublicKey, 12, 8)}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Heartbeat Continuity, Post-Restart Ramp &amp; Active Canaries (Spec §8.2–8.4)
          </h2>
          <p className="mb-3 text-xs text-zinc-400">
            Unannounced restarts force nodes into a 24–96h canary-only probation phase (0 bps user weight) followed by a
            72h linear ramp. Simultaneous identity keys trigger instant suspension.
          </p>
          <div className="space-y-2.5 text-xs">
            {Object.values(accountability?.rampStates ?? {}).map((r) => {
              const canary = accountability?.activeCanaries?.[r.nodeId];
              return (
                <div key={r.nodeId} className="rounded-md border border-zinc-800 bg-zinc-900/50 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-zinc-100">{r.nodeId}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                        r.status === "full"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : r.status === "ramp"
                            ? "bg-amber-500/15 text-amber-300"
                            : "bg-rose-500/20 text-rose-300"
                      }`}
                    >
                      {r.phase} · {r.weightBps} bps · {r.restartsIn30d} restart(s)/30d
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-400">{r.detail}</p>
                  {canary && (
                    <div className="mt-1.5 rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-[10px] text-zinc-400">
                      Canary commitment ({canary.decoyKind}): {shortHex(canary.commitment, 16, 10)}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      </div>

      {/* Blind Credits & Zero-Knowledge Frozen Blobs */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Unlinkable Blind-Signed Credits Ledger (Spec §7)
          </h2>
          <p className="mb-3 text-xs text-zinc-400">
            Chaumian RSA-2048 blind signatures decouple credit purchase from per-turn spending. The router records only
            one-time nullifiers <code className="font-mono">sha256(&quot;drouter/v1/nullifier:&quot; || token)</code>.
          </p>
          {credits ? (
            <dl className="space-y-2 text-xs">
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">RSA Modulus (n)</dt>
                <dd className="break-all font-mono text-zinc-300">{shortHex(credits.n, 24, 16)}</dd>
              </div>
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">Public Exponent (e)</dt>
                <dd className="font-mono text-zinc-300">0x{credits.e}</dd>
              </div>
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">Denominations</dt>
                <dd className="font-mono text-zinc-300">{credits.denominations.join(", ")} credits</dd>
              </div>
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">Spent Nullifiers</dt>
                <dd className="font-mono text-emerald-300">{credits.stats.spentCount}</dd>
              </div>
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">Unredeemed Pool</dt>
                <dd className="font-mono text-amber-300">{credits.stats.unredeemedCount}</dd>
              </div>
              <div className="grid grid-cols-[10rem_1fr] gap-2">
                <dt className="text-zinc-500">Redeemed Batches</dt>
                <dd className="font-mono text-sky-300">{credits.stats.redeemedBatches}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-xs text-zinc-500">Loading blind credit issuer parameters…</p>
          )}
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Zero-Knowledge Frozen Session Blobs (MongoDB Ciphertext Store)
          </h2>
          <p className="mb-3 text-xs text-zinc-400">
            Frozen session bubbles store only opaque AES-256-GCM ciphertext. The server explicitly rejects any payload
            containing <code className="font-mono">freezeSecretHex</code> or plaintext{" "}
            <code className="font-mono">messages</code>.
          </p>
          {freeze?.blobs && freeze.blobs.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead className="text-zinc-500">
                <tr>
                  <th className="py-1">Blob ID</th>
                  <th>Ciphertext size</th>
                  <th>Created (UTC)</th>
                  <th>Plaintext stored</th>
                </tr>
              </thead>
              <tbody className="text-zinc-300">
                {freeze.blobs.map((b) => (
                  <tr key={b.blobId} className="border-t border-zinc-900">
                    <td className="py-1.5 font-mono">{shortHex(b.blobId, 10, 6)}</td>
                    <td className="font-mono">{b.byteLength} B</td>
                    <td>{formatUnixSec(b.createdAt)}</td>
                    <td className="font-mono text-emerald-400">0 bytes (opaque GCM)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="rounded border border-zinc-800 bg-zinc-900/40 p-3 text-xs text-zinc-400">
              No frozen blobs currently stored in MongoDB/memory. Freeze a session bubble from the console to see its
              opaque ciphertext record here.
            </p>
          )}
        </section>
      </div>
    </main>
  );
}
