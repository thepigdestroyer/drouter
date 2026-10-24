"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
import {
  ExhibitSection,
  SpecimenFooter,
  SpecimenHeader,
} from "@/components/specimen-chrome";
import { ThreatMatrix } from "@/components/threat-matrix";
import type { HardwareManifest, QuorumTicket } from "@/lib/types";

interface TransparencyEntryView {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays: number;
  emergency: boolean;
  builderSignatures: {
    builderId: string;
    publicKey: string;
    signature: string;
  }[];
  reviewerSignatures: {
    reviewerId: string;
    publicKey: string;
    signature: string;
  }[];
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
  if (s.length <= lead + tail + 3) return s;
  return `${s.slice(0, lead)}...${s.slice(-tail)}`;
}

function formatUnixSec(sec: number): string {
  if (!sec || !Number.isFinite(sec)) return "n/a";
  return new Date(sec * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function runClientMonitorPolicyCheck() {
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
  const encryptions = [
    "custody-aes-gcm",
    "freeze-aes-gcm",
    "plaintext",
    "control-schema",
  ] as const;
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
                      payloadEncryption === "custody-aes-gcm" &&
                      nonceFresh &&
                      fixedFrameCadence;
                  } else if (channel === "control-plane") {
                    allowed =
                      payloadEncryption === "control-schema" &&
                      !hasPerSessionFields;
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
  };
}

const VERIFIABLE_CLAIMS = [
  {
    title: "Enclave source and build releases (GitHub)",
    claim:
      "Inspect the open-source Tinfoil confidential router and model container releases that produce the enclave measurements.",
    href: "https://github.com/tinfoilsh",
    linkLabel: "github.com/tinfoilsh",
  },
  {
    title: "Build provenance log (Sigstore Rekor)",
    claim:
      "Verify that enclave container digests are recorded in the public append-only Sigstore transparency log.",
    href: "https://search.sigstore.dev",
    linkLabel: "search.sigstore.dev",
  },
  {
    title: "Silicon root certificates (AMD KDS)",
    claim:
      "Fetch AMD Key Distribution Service VCEK certificate chains used to verify the AMD SEV-SNP hardware quote from router-0.tinfoil.sh.",
    href: "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
    linkLabel: "kdsintf.amd.com/vcek/v1/Milan/cert_chain",
  },
  {
    title: "Live enclave routing table (Tinfoil proxy)",
    claim:
      "Check the live proxy manifest mapping router-0.tinfoil.sh (AMD SEV-SNP) to model enclaves such as kimi-k3 (Intel TDX + NVIDIA CC GPUs, 262,144 max tokens).",
    href: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    linkLabel: "inference.tinfoil.sh/.well-known/tinfoil-proxy",
  },
  {
    title: "On-chain attestation registry (Circle Arc Testnet)",
    claim:
      "Inspect contract 0xbc8085c2b6fe6e0db05f169925c0b841828f4481 on Circle Arc Testnet (chain 5042002).",
    href: "https://explorer.testnet.arc.io/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
    linkLabel: "explorer.testnet.arc.io/address/0xbc80...4481",
  },
];

export default function AuditLabPage() {
  const [transparency, setTransparency] =
    useState<TransparencyResponse | null>(null);
  const [accountability, setAccountability] =
    useState<AccountabilityResponse | null>(null);
  const [credits, setCredits] = useState<CreditsResponse | null>(null);
  const [freeze, setFreeze] = useState<FreezeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<{
    title: string;
    verdictSummary: string;
    payload: unknown;
  } | null>(null);

  const monitorPolicyCheck = useMemo(() => runClientMonitorPolicyCheck(), []);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    try {
      const [tRes, aRes, cRes, fRes] = await Promise.all([
        fetch("/api/transparency")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/accountability")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/credits")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/freeze")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
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
    action:
      | "trigger-canary"
      | "claim-key-bounty"
      | "simulate-restart"
      | "simulate-clone",
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
          activeCanaries:
            data.activeCanaries as Record<string, CanarySessionView>,
          recentClaims:
            (data.recentClaims as RecordedClaimEventView[]) ??
            accountability.recentClaims,
        });
      }
      const verdictObj = (data.verdict ??
        data.evaluation ??
        {}) as Record<string, unknown>;
      const summary =
        typeof verdictObj.reason === "string"
          ? verdictObj.reason
          : typeof verdictObj.detail === "string"
            ? verdictObj.detail
            : `Simulated ${action} on ${nodeId}`;
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
        title: "Simulated batch credit settlement",
        verdictSummary: `Settled ${String(data.redeemedCount ?? 0)} unredeemed nullifier(s) (${String(data.totalCredits ?? 0)} credits) into batch digest ${shortHex(data.batchHash ?? "", 14, 10)}.`,
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
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/audit" rightSlot={<AuthPill />} />

      <main className="flex-1 w-full min-w-0">
        <div className="mx-auto w-full max-w-5xl px-4 pt-10 pb-4 sm:px-6 space-y-10">
        {/* Header */}
        <header className="space-y-3 border-b border-rule pb-8">
          <div className="ep-label">Proof and audit</div>
          <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
            Check our work
          </h1>
          <p className="max-w-[70ch] text-base sm:text-lg text-ink-2 leading-relaxed">
            Every live hardware and registry claim below links to an external
            authority you can verify yourself, while our slashing and quorum
            mechanisms run as interactive simulations on test nodes.
          </p>
        </header>

        {/* 1. External Claims You Can Verify Yourself */}
        <section
          aria-label="Claims you can verify yourself"
          className="space-y-4"
        >
          <div className="space-y-1">
            <div className="ep-label">Independent verification</div>
            <h2 className="font-serif text-2xl text-ink">
              Claims you can verify yourself
            </h2>
          </div>

          <div className="ep-card divide-y divide-rule">
            {VERIFIABLE_CLAIMS.map((item) => (
              <div
                key={item.href}
                className="p-4 sm:p-5 flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between"
              >
                <div className="space-y-1 max-w-[60ch]">
                  <h3 className="font-serif text-base font-medium text-ink">
                    {item.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-ink-2 leading-relaxed">
                    {item.claim}
                  </p>
                </div>
                <a
                  href={item.href}
                  target="_blank"
                  rel="noreferrer"
                  className="ep-link font-mono text-xs shrink-0 break-all"
                >
                  {item.linkLabel} -&gt;
                </a>
              </div>
            ))}
          </div>

          <div className="ep-inset p-4 text-xs text-ink-2 space-y-1">
            <div className="font-mono text-ink font-medium">
              Disclosure on upstream Tinfoil router sidecars:
            </div>
            <p className="max-w-[70ch] leading-relaxed">
              The live Tinfoil router (router-0.tinfoil.sh) attests with AMD
              SEV-SNP and runs an acceptable-use safeguards classifier sidecar
              reporting policy violations to https://api.tinfoil.sh, plus an
              attested usage reporter. The Kimi K3 model enclave runs on Intel
              TDX plus NVIDIA confidential-computing GPUs with a 262,144-token
              maximum context length.
            </p>
          </div>
        </section>

        {/* 2. Accountability Simulations */}
        <section
          aria-label="Accountability simulations"
          className="space-y-4"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="space-y-1">
              <div className="ep-label">Interactive sandbox</div>
              <h2 className="font-serif text-2xl text-ink">
                Accountability and slashing simulations
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="ep-muted-chip">Simulated nodes: sim-1, sim-2, sim-3</span>
              <button
                type="button"
                onClick={() => void refreshAll()}
                className="ep-btn-ghost text-xs py-1 px-2.5 cursor-pointer"
              >
                {loading ? "Refreshing..." : "Refresh state"}
              </button>
            </div>
          </div>

          <p className="max-w-[70ch] text-sm text-ink-2">
            Nodes <code className="font-mono text-xs">sim-1</code>,{" "}
            <code className="font-mono text-xs">sim-2</code>, and{" "}
            <code className="font-mono text-xs">sim-3</code> are simulated test
            nodes. Trigger any fault below to test how our accountability rules
            penalize misbehavior.
          </p>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {/* Sim 1: Canary Honeytoken */}
            <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-serif text-base font-medium text-ink">
                    1. Canary honeytoken leak (sim-1)
                  </h3>
                  <span className="ep-muted-chip">Simulated</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Reveals a canary honeytoken and salt matching sim-1&apos;s
                  commitment to simulate a 10% reporter bounty and 90% user pool
                  slash.
                </p>
              </div>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() =>
                  void runAccountabilityAction(
                    "trigger-canary",
                    "sim-1",
                    "Simulated canary honeytoken leak (sim-1)",
                  )
                }
                className="ep-btn text-xs self-start cursor-pointer"
              >
                {busyAction === "trigger-canary:sim-1"
                  ? "Running..."
                  : "Simulate canary leak"}
              </button>
            </div>

            {/* Sim 2: Key-Compromise Bounty */}
            <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-serif text-base font-medium text-ink">
                    2. Key-compromise bounty proof (sim-2)
                  </h3>
                  <span className="ep-muted-chip">Simulated</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Submits a signature over the forbidden prefix{" "}
                  <code className="font-mono">
                    {accountability?.forbiddenPrefix
                      ? shortHex(accountability.forbiddenPrefix, 10, 6)
                      : "F"}
                  </code>{" "}
                  on sim-2, proving key extraction and awarding a 50% bounty.
                </p>
              </div>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() =>
                  void runAccountabilityAction(
                    "claim-key-bounty",
                    "sim-2",
                    "Simulated key-compromise bounty (sim-2)",
                  )
                }
                className="ep-btn text-xs self-start cursor-pointer"
              >
                {busyAction === "claim-key-bounty:sim-2"
                  ? "Running..."
                  : "Simulate key bounty"}
              </button>
            </div>

            {/* Sim 3: Restart or Clone */}
            <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-serif text-base font-medium text-ink">
                    3. Unannounced restart or cloned key (sim-3)
                  </h3>
                  <span className="ep-muted-chip">Simulated</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Puts sim-3 into canary-only probation (0 bps routing weight)
                  after an unannounced reboot, or suspends it on duplicate key
                  heartbeats.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() =>
                    void runAccountabilityAction(
                      "simulate-restart",
                      "sim-3",
                      "Simulated unannounced restart (sim-3)",
                    )
                  }
                  className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                >
                  {busyAction === "simulate-restart:sim-3"
                    ? "Running..."
                    : "Simulate restart"}
                </button>
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() =>
                    void runAccountabilityAction(
                      "simulate-clone",
                      "sim-3",
                      "Simulated cloned key detection (sim-3)",
                    )
                  }
                  className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                >
                  {busyAction === "simulate-clone:sim-3"
                    ? "Running..."
                    : "Simulate clone"}
                </button>
              </div>
            </div>

            {/* Sim 4: Batch Redeem Blind Credits */}
            <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-serif text-base font-medium text-ink">
                    4. Batch-redeem blind credits
                  </h3>
                  <span className="ep-muted-chip">Simulated</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Flushes unredeemed Chaumian RSA-2048 blind-credit nullifiers
                  into a single batch settlement digest.
                </p>
              </div>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void runRedeemCredits()}
                className="ep-btn-ghost text-xs py-1.5 px-3 self-start cursor-pointer"
              >
                {busyAction === "redeem-credits"
                  ? "Settling..."
                  : "Batch-redeem credits"}
              </button>
            </div>
          </div>

          {/* Simulation Verdict Output */}
          {simResult && (
            <div className="ep-inset p-4 space-y-2 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-serif text-sm font-medium text-ink">
                  {simResult.title}
                </span>
                <button
                  type="button"
                  onClick={() => setSimResult(null)}
                  className="ep-link font-mono text-xs cursor-pointer"
                >
                  Dismiss
                </button>
              </div>
              <p className="text-ink-2">{simResult.verdictSummary}</p>
              <details>
                <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                  Show details
                </summary>
                <pre className="mt-2 ep-card p-3 max-h-60 overflow-auto font-mono text-[11px] text-ink-2">
                  {JSON.stringify(simResult.payload, null, 2)}
                </pre>
              </details>
            </div>
          )}

          {/* Collapsible Simulated State Details */}
          <details className="ep-card p-4 sm:p-5">
            <summary className="cursor-pointer font-serif text-base font-medium text-ink select-none">
              Show simulated node state, quorum tickets, credit counters, and
              frozen blobs
            </summary>

            <div className="mt-4 space-y-6 border-t border-rule pt-4 text-xs">
              {/* Node Ramp States */}
              <div className="space-y-2">
                <div className="ep-label">Simulated node ramp state</div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  {Object.values(accountability?.rampStates ?? {}).map((r) => (
                    <div key={r.nodeId} className="ep-inset p-3 space-y-1">
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-ink font-medium">{r.nodeId}</span>
                        <span
                          className={
                            r.status === "full" ? "ep-pass" : "ep-fail"
                          }
                        >
                          {r.phase} ({r.weightBps} bps)
                        </span>
                      </div>
                      <p className="text-ink-2">{r.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Monitor Policy Table Check */}
              <div className="space-y-1.5">
                <div className="ep-label">
                  Monitor exit policy table (JavaScript state enumeration)
                </div>
                <p className="text-ink-2">
                  Checked {monitorPolicyCheck.statesChecked.toLocaleString()}{" "}
                  combinations in browser memory:{" "}
                  {monitorPolicyCheck.allowedStates} allowed,{" "}
                  {monitorPolicyCheck.deniedStates.toLocaleString()} denied.
                </p>
              </div>

              {/* Simulated Transparency & Quorum */}
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <div className="ep-label">
                    Simulated transparency log entries
                  </div>
                  <div className="space-y-2">
                    {(transparency?.log?.entries ?? []).map((entry) => (
                      <div
                        key={entry.index}
                        className="ep-inset p-2.5 font-mono space-y-1 text-ink-2"
                      >
                        <div className="text-ink font-medium">
                          #{entry.index} {entry.imageId} ({entry.version})
                        </div>
                        <div>
                          Measurement: {shortHex(entry.measurement, 14, 8)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="ep-label">
                    Simulated 5-of-7 quorum tickets
                  </div>
                  <div className="space-y-2">
                    {Object.values(transparency?.tickets ?? {}).map((ticket) => (
                      <div
                        key={ticket.nodeId}
                        className="ep-inset p-2.5 font-mono space-y-1 text-ink-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-ink font-medium">
                            {ticket.nodeId}
                          </span>
                          <span>
                            {ticket.signatures.length}/7 sigs ({ticket.weight}{" "}
                            bps)
                          </span>
                        </div>
                        <div>Chip ID: {shortHex(ticket.chipId, 12, 8)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Blind Credits & Client-Encrypted Frozen Blobs */}
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <div className="ep-label">Blind-signed credit counters</div>
                  {credits ? (
                    <div className="ep-inset p-3 font-mono space-y-1 text-ink-2">
                      <div>Modulus (n): {shortHex(credits.n, 16, 10)}</div>
                      <div>
                        Spent nullifiers: {credits.stats.spentCount} | Unredeemed:{" "}
                        {credits.stats.unredeemedCount} | Batches:{" "}
                        {credits.stats.redeemedBatches}
                      </div>
                    </div>
                  ) : (
                    <p className="text-ink-3">Loading credit stats...</p>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="ep-label">
                    Client-encrypted frozen session blobs (AES-256-GCM)
                  </div>
                  {freeze?.blobs && freeze.blobs.length > 0 ? (
                    <div className="ep-inset p-3 font-mono space-y-1 text-ink-2">
                      {freeze.blobs.map((b) => (
                        <div
                          key={b.blobId}
                          className="flex items-center justify-between"
                        >
                          <span>{shortHex(b.blobId, 10, 6)}</span>
                          <span>
                            {b.byteLength} B ({formatUnixSec(b.createdAt)})
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="ep-inset p-3 text-ink-3">
                      No frozen ciphertext blobs currently stored.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </details>
        </section>

        </div>

        {/* 3. What if someone cheats? */}
        <ExhibitSection
          tag="Threat matrix"
          title="What if someone cheats?"
          subtitle="Inspect seven real-world compromise scenarios and the technical checks that block them."
        >
          <ThreatMatrix />
        </ExhibitSection>
      </main>

      <SpecimenFooter />
    </div>
  );
}
