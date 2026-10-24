"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { AuthGate } from "@/components/auth/auth-gate";
import { AuthPill } from "@/components/auth-pill";
import {
  type AccountabilityResponse,
  type AuditorResponse,
  buildPlainTrustPoints,
  buildVerifiableClaims,
  type CanarySessionView,
  formatUnixSec,
  type RampEvaluationView,
  type RecordedClaimEventView,
  shortHex,
  type TransparencyResponse,
} from "@/components/audit/audit-helpers";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import {
  SpecimenFooter,
  SpecimenHeader,
} from "@/components/specimen-chrome";
import { ThreatMatrix } from "@/components/threat-matrix";
import {
  verifyConsistencyProofClient,
  verifyInclusionProofClient,
  verifySignedTreeHeadClient,
} from "@/lib/transparency/log";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";

interface CreditsResponse {
  n: string;
  e: string;
  denominations: number[];
  issuerAddress?: string;
  chainId?: number;
  usdcPerCredit?: string;
  simulated?: boolean;
  stats: {
    spentCount: number;
    unredeemedCount: number;
    redeemedBatches: number;
    paidRedemptions?: number;
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
  simulated?: boolean;
}

interface ActionResultView {
  title: string;
  plainSummary: string;
  verdictSummary: string;
  txHash: string | null;
  explorerUrl: string | null;
  onChain: boolean;
  simulated: boolean;
  evidenceHash?: string | null;
  payload: unknown;
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

export default function AuditLabPage() {
  const [matrix, setMatrix] = useState<DeepAttestationBundle | null>(null);
  const [transparency, setTransparency] =
    useState<TransparencyResponse | null>(null);
  const [accountability, setAccountability] =
    useState<AccountabilityResponse | null>(null);
  const [auditor, setAuditor] = useState<AuditorResponse | null>(null);
  const [credits, setCredits] = useState<CreditsResponse | null>(null);
  const [freeze, setFreeze] = useState<FreezeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<ActionResultView | null>(
    null,
  );

  const monitorPolicyCheck = useMemo(() => runClientMonitorPolicyCheck(), []);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    try {
      const [mRes, tRes, aRes, audRes, cRes, fRes] = await Promise.all([
        fetch("/api/relay/enclave-matrix")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/transparency")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/accountability")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/auditor")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/credits")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/freeze")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
      ]);
      if (mRes) setMatrix(mRes as DeepAttestationBundle);
      if (tRes) setTransparency(tRes as TransparencyResponse);
      if (aRes) setAccountability(aRes as AccountabilityResponse);
      if (audRes) setAuditor(audRes as AuditorResponse);
      if (cRes) setCredits(cRes as CreditsResponse);
      if (fRes) setFreeze(fRes as FreezeResponse);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  const verifiableClaims = useMemo(
    () =>
      buildVerifiableClaims({
        matrix,
        accountability,
        transparency,
      }),
    [matrix, accountability, transparency],
  );

  const plainTrustPoints = useMemo(
    () =>
      buildPlainTrustPoints({
        matrix,
        accountability,
        transparency,
      }),
    [matrix, accountability, transparency],
  );

  const sthVerification = useMemo(() => {
    if (!transparency?.signedTreeHead) return null;
    return verifySignedTreeHeadClient(
      transparency.signedTreeHead,
      transparency.operatorPublicKey,
    );
  }, [transparency]);

  const consistencyVerification = useMemo(() => {
    const cp =
      transparency?.verificationLog?.consistencyProof ??
      transparency?.consistencyProof;
    if (!cp) return null;
    return verifyConsistencyProofClient(cp);
  }, [transparency]);

  const runAccountabilityAction = async (
    action:
      | "trigger-canary"
      | "claim-key-bounty"
      | "simulate-restart"
      | "simulate-clone",
    nodeId: string,
    title: string,
    plainSummary: string,
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
          txHash:
            typeof data.txHash === "string"
              ? data.txHash
              : accountability.txHash,
          explorerUrl:
            typeof data.explorerUrl === "string"
              ? data.explorerUrl
              : accountability.explorerUrl,
          onChain:
            typeof data.onChain === "boolean"
              ? data.onChain
              : accountability.onChain,
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
            : typeof data.error === "string"
              ? data.error
              : `Executed ${action} on ${nodeId}`;

      const txHash = typeof data.txHash === "string" ? data.txHash : null;
      const explorerUrl =
        typeof data.explorerUrl === "string" ? data.explorerUrl : null;
      const onChain = Boolean(data.onChain);
      const evidenceHash =
        typeof data.evidenceHash === "string" ? data.evidenceHash : null;

      if (evidenceHash) {
        const nodeManifest = accountability?.manifests?.find(
          (m) => m.nodeId === nodeId,
        );
        await fetch("/api/transparency", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            nodeId,
            nodeKind: nodeId === "tinfoil-router" ? "tinfoil" : "sim",
            ok: false,
            measurement:
              nodeManifest?.chipId ??
              "drouter-sim-node-image/v0.1.0",
            evidenceHash,
            anchorOnArc: false,
          }),
        }).catch(() => null);
        const refreshedTrans = await fetch("/api/transparency")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null);
        if (refreshedTrans) {
          setTransparency(refreshedTrans as TransparencyResponse);
        }
      }

      setActionResult({
        title,
        plainSummary,
        verdictSummary: summary,
        txHash,
        explorerUrl,
        onChain,
        simulated: Boolean(data.simulated),
        evidenceHash,
        payload: data,
      });
    } finally {
      setBusyAction(null);
    }
  };

  const runAnchorTransparencyRoot = async () => {
    setBusyAction("anchor-root");
    try {
      const rootHex =
        transparency?.signedTreeHead?.rootHash ??
        transparency?.verificationLog?.root ??
        transparency?.log?.root ??
        "";
      if (!rootHex) return;

      const receiptHash = rootHex.startsWith("0x") ? rootHex : `0x${rootHex}`;
      const routerNode =
        accountability?.registryNodes?.find((n) => n.kind === "tinfoil") ??
        accountability?.registryNodes?.[0];
      const nodeIdHex =
        routerNode?.id ??
        "0x2696913aef54b88e8338ba4a362549e7c70465faa781aaa12240d20a247df29a";

      const res = await fetch("/api/anchor", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          receiptHash,
          nodeId: nodeIdHex,
        }),
      });
      const data = (await res.json()) as Record<string, unknown>;
      const txHash =
        typeof data.txHash === "string"
          ? data.txHash
          : typeof data.anchorTx === "string"
            ? data.anchorTx
            : null;
      const explorerUrl =
        typeof data.explorerUrl === "string"
          ? data.explorerUrl
          : typeof data.anchorUrl === "string"
            ? data.anchorUrl
            : null;
      const onChain = Boolean(data.onChain ?? txHash);

      setActionResult({
        title: "Public receipt book stamp",
        plainSummary:
          "We stamped the latest summary of server checks into the public receipt book.",
        verdictSummary: txHash
          ? `Anchored Merkle root ${shortHex(receiptHash, 12, 8)} on Circle Arc Testnet in transaction ${shortHex(txHash, 12, 8)}.`
          : typeof data.error === "string"
            ? data.error
            : `Submitted Merkle root ${shortHex(receiptHash, 12, 8)} to /api/anchor.`,
        txHash,
        explorerUrl,
        onChain,
        simulated: Boolean(data.simulated),
        evidenceHash: receiptHash,
        payload: data,
      });

      const refreshedTrans = await fetch("/api/transparency")
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null);
      if (refreshedTrans) {
        setTransparency(refreshedTrans as TransparencyResponse);
      }
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
      const batchHash =
        typeof data.batchHash === "string" ? data.batchHash : "";
      setActionResult({
        title: "Anonymous token batch settlement",
        plainSummary:
          "We settled used anonymous tokens in a single batch without linking any token back to a person.",
        verdictSummary: `Settled ${String(data.redeemedCount ?? 0)} unredeemed nullifier(s) (${String(data.totalCredits ?? 0)} credits) into batch digest ${shortHex(batchHash, 14, 10)}.`,
        txHash: typeof data.txHash === "string" ? data.txHash : null,
        explorerUrl:
          typeof data.explorerUrl === "string" ? data.explorerUrl : null,
        onChain: Boolean(data.onChain),
        simulated: Boolean(data.simulated),
        evidenceHash: batchHash ? `0x${batchHash}` : null,
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

  const latestClaimWithTx = useMemo(() => {
    const claims = accountability?.recentClaims ?? [];
    return claims.find((c) => Boolean(c.txHash)) ?? claims[0] ?? null;
  }, [accountability]);

  const latestExplorerUrl =
    actionResult?.explorerUrl ??
    accountability?.explorerUrl ??
    latestClaimWithTx?.explorerUrl ??
    transparency?.anchorExplorerUrl ??
    null;

  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/audit" rightSlot={<AuthPill />} />

      <main className="flex-1 w-full min-w-0">
        <AuthGate>
          <div className="mx-auto w-full max-w-5xl px-4 pt-10 pb-12 sm:px-6 space-y-12">
            {/* Header */}
            <header className="space-y-3 border-b border-rule pb-8">
              <div className="ep-label">Proof</div>
              <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
                Why you can trust deRoute
              </h1>
              <p className="max-w-[68ch] text-base sm:text-lg text-ink-2 leading-relaxed">
                You do not have to take our word for it. Every chat goes to a
                sealed computer whose lock and public receipt book you can check
                for yourself in one click.
              </p>
            </header>

            {/* 1. Why you can trust this in 3 plain points */}
            <InkReveal>
              <section
                aria-label="Why you can trust this"
                className="space-y-5"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div className="space-y-1">
                    <div className="ep-label">Three plain checks</div>
                    <h2 className="font-serif text-2xl sm:text-3xl text-ink">
                      Why you can trust this
                    </h2>
                  </div>
                  <span className="ep-muted-chip">
                    {matrix
                      ? "Live seal check active"
                      : "Loading live records..."}
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  {plainTrustPoints.map((point) => (
                    <div
                      key={point.id}
                      className="ep-card p-5 flex flex-col justify-between space-y-5"
                    >
                      <div className="space-y-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs uppercase text-ink-3">
                            Point {point.stepNumber}
                          </span>
                          <span className="ep-pass">{point.badge}</span>
                        </div>
                        <h3 className="font-serif text-lg font-medium text-ink leading-snug">
                          {point.title}
                        </h3>
                        <p className="text-sm text-ink-2 leading-relaxed">
                          {point.description}
                        </p>
                      </div>

                      <div className="pt-2">
                        <a
                          href={point.href}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-btn w-full justify-center text-center text-sm py-2.5 px-4 inline-flex items-center gap-2"
                        >
                          <span>{point.buttonLabel}</span>
                          <span aria-hidden="true">-&gt;</span>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Secret shopper summary in plain words */}
                <div className="ep-inset p-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="space-y-0.5">
                    <div className="font-serif text-base font-medium text-ink">
                      Secret shopper check on the AI brain
                    </div>
                    <p className="text-sm text-ink-2">
                      We also send surprise test questions to make sure the
                      sealed computer is still running the real AI brain and not
                      a cheaper substitute.
                    </p>
                  </div>
                  <span className="ep-pass shrink-0">
                    {auditor?.latestRun
                      ? `${auditor.latestRun.passedCount} of ${auditor.latestRun.probesCount} test questions passed`
                      : "Secret shopper ready"}
                  </span>
                </div>

                {/* Technical details for all 5 external verifiable claims + sidecar disclosure + auditor */}
                <TechDetails label="Show technical details">
                  <div className="space-y-5 pt-2 text-xs">
                    <div className="space-y-2">
                      <div className="ep-label">
                        All 5 external records and cryptographic links
                      </div>
                      <div className="ep-card divide-y divide-rule">
                        {verifiableClaims.map((item) => (
                          <div
                            key={item.id}
                            className="p-4 flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between"
                          >
                            <div className="space-y-1 max-w-[60ch] min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-serif text-sm font-medium text-ink">
                                  {item.title}
                                </span>
                                <span className="ep-pass break-all">
                                  {item.liveRecordBadge}
                                </span>
                              </div>
                              <p className="text-ink-2 leading-relaxed break-words">
                                {item.claim}
                              </p>
                            </div>
                            <div className="flex flex-col sm:items-end gap-1 sm:shrink-0 font-mono text-[11px]">
                              <a
                                href={item.href}
                                target="_blank"
                                rel="noreferrer"
                                className="ep-link break-all"
                              >
                                {item.linkLabel} -&gt;
                              </a>
                              {item.secondaryHref && item.secondaryLabel && (
                                <a
                                  href={item.secondaryHref}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="ep-link text-ink-3 break-all"
                                >
                                  {item.secondaryLabel} -&gt;
                                </a>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="ep-inset p-3.5 text-ink-2 space-y-1">
                      <div className="font-mono text-ink font-medium">
                        Disclosure on upstream Tinfoil router sidecars:
                      </div>
                      <p className="leading-relaxed">
                        The live Tinfoil router (router-0.tinfoil.sh) attests
                        with AMD SEV-SNP and runs an acceptable-use safeguards
                        classifier sidecar reporting policy violations to
                        https://api.tinfoil.sh, plus an attested usage reporter.
                        The Kimi K3 model enclave runs on Intel TDX plus NVIDIA
                        confidential-computing GPUs with a 262,144-token maximum
                        context length.
                      </p>
                    </div>

                    <div className="ep-card p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-serif text-sm font-medium text-ink">
                          Mystery-shopper SPRT model audit (/api/auditor)
                        </span>
                        <span className="ep-muted-chip">
                          {auditor?.protocol ?? "mystery-shopper-sprt-v1"}
                        </span>
                      </div>
                      {auditor?.latestRun ? (
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono">
                          <div className="ep-inset p-2.5">
                            <div className="ep-label">Canary probes</div>
                            <div className="text-ink font-medium">
                              {auditor.latestRun.passedCount} /{" "}
                              {auditor.latestRun.probesCount} (
                              {Math.round(
                                auditor.latestRun.empiricalPassRate * 100,
                              )}
                              %)
                            </div>
                          </div>
                          <div className="ep-inset p-2.5">
                            <div className="ep-label">Cumulative SPRT LLR</div>
                            <div className="text-ink font-medium">
                              {auditor.latestRun.cumulativeSprtStatistic.toFixed(
                                4,
                              )}
                            </div>
                          </div>
                          <div className="ep-inset p-2.5">
                            <div className="ep-label">Bounds [B, A]</div>
                            <div className="text-ink font-medium">
                              [{auditor.latestRun.lowerBoundB.toFixed(2)}, +
                              {auditor.latestRun.upperBoundA.toFixed(2)}]
                            </div>
                          </div>
                          <div className="ep-inset p-2.5">
                            <div className="ep-label">Mean latency</div>
                            <div className="text-ink font-medium">
                              {auditor.latestRun.meanLatencyMs} ms
                            </div>
                          </div>
                        </div>
                      ) : (
                        <p className="text-ink-2">
                          {auditor?.statusMessage ??
                            "Awaiting first mystery-shopper run."}
                        </p>
                      )}
                    </div>
                  </div>
                </TechDetails>
              </section>
            </InkReveal>

            {/* 2. What if someone cheats? (Interactive Villain Picker) */}
            <InkReveal delayMs={60}>
              <ThreatMatrix />
            </InkReveal>

            {/* 3. Practice accountability actions */}
            <InkReveal delayMs={120}>
              <section
                aria-label="Practice accountability actions"
                className="space-y-5"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2 border-t border-rule pt-8">
                  <div className="space-y-1">
                    <div className="ep-label">Practice drills</div>
                    <h2 className="font-serif text-2xl sm:text-3xl text-ink">
                      Practice catching a misbehaving server
                    </h2>
                    <p className="max-w-[65ch] text-sm text-ink-2 leading-relaxed">
                      Run a safe practice drill on our test servers (sim-1,
                      sim-2, sim-3). When a practice server breaks the rules,
                      deRoute catches it and writes a real receipt into the
                      public receipt book.
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="ep-muted-chip">Practice</span>
                    <button
                      type="button"
                      onClick={() => void refreshAll()}
                      className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                    >
                      {loading ? "Refreshing..." : "Refresh records"}
                    </button>
                  </div>
                </div>

                {/* Latest receipt banner when available */}
                {latestExplorerUrl && (
                  <div className="ep-inset p-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-sm">
                    <div className="space-y-0.5">
                      <span className="ep-label">
                        Latest receipt in the public receipt book
                      </span>
                      <div className="text-ink">
                        A live receipt from a server check is ready to inspect.
                      </div>
                    </div>
                    <a
                      href={latestExplorerUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="ep-btn-ghost text-xs py-1.5 px-3 shrink-0 self-start sm:self-center"
                    >
                      Check receipt yourself -&gt;
                    </a>
                  </div>
                )}

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  {/* Practice 1 */}
                  <div className="ep-card p-5 flex flex-col justify-between space-y-4 min-w-0">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <h3 className="font-serif text-base font-medium text-ink">
                          1. Catch a leaked trap phrase (sim-1)
                        </h3>
                        <span className="ep-muted-chip">Practice</span>
                      </div>
                      <p className="text-sm text-ink-2 leading-relaxed">
                        Send a secret trap phrase through practice server 1.
                        When the phrase leaks out, we prove the server broke the
                        rules and write a receipt in the public receipt book.
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={busyAction !== null}
                      onClick={() =>
                        void runAccountabilityAction(
                          "trigger-canary",
                          "sim-1",
                          "Practice leak drill on sim-1",
                          "We caught practice server sim-1 leaking the trap phrase and recorded the receipt.",
                        )
                      }
                      className="ep-btn text-xs self-start cursor-pointer"
                    >
                      {busyAction === "trigger-canary:sim-1"
                        ? "Running practice drill..."
                        : "Run leak drill"}
                    </button>
                  </div>

                  {/* Practice 2 */}
                  <div className="ep-card p-5 flex flex-col justify-between space-y-4 min-w-0">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <h3 className="font-serif text-base font-medium text-ink">
                          2. Catch a stolen server key (sim-2)
                        </h3>
                        <span className="ep-muted-chip">Practice</span>
                      </div>
                      <p className="text-sm text-ink-2 leading-relaxed">
                        Pretend someone stole the secret key from practice
                        server 2. We prove the key escaped and flag that server
                        in the public receipt book.
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={busyAction !== null}
                      onClick={() =>
                        void runAccountabilityAction(
                          "claim-key-bounty",
                          "sim-2",
                          "Practice stolen-key drill on sim-2",
                          "We proved the practice key escaped on sim-2 and recorded the receipt.",
                        )
                      }
                      className="ep-btn text-xs self-start cursor-pointer"
                    >
                      {busyAction === "claim-key-bounty:sim-2"
                        ? "Running practice drill..."
                        : "Run stolen-key drill"}
                    </button>
                  </div>

                  {/* Practice 3 */}
                  <div className="ep-card p-5 flex flex-col justify-between space-y-4 min-w-0">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <h3 className="font-serif text-base font-medium text-ink">
                          3. Catch a surprise reboot or twin server (sim-3)
                        </h3>
                        <span className="ep-muted-chip">Practice</span>
                      </div>
                      <p className="text-sm text-ink-2 leading-relaxed">
                        Test what happens if practice server 3 restarts without
                        warning or tries to run two copies of itself at once.
                        deRoute pauses its traffic right away.
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
                            "Practice surprise reboot on sim-3",
                            "We caught an unannounced reboot on practice server sim-3 and placed it on probation.",
                          )
                        }
                        className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                      >
                        {busyAction === "simulate-restart:sim-3"
                          ? "Running..."
                          : "Test surprise reboot"}
                      </button>
                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onClick={() =>
                          void runAccountabilityAction(
                            "simulate-clone",
                            "sim-3",
                            "Practice twin server check on sim-3",
                            "We caught a duplicate copy of practice server sim-3 and suspended it.",
                          )
                        }
                        className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                      >
                        {busyAction === "simulate-clone:sim-3"
                          ? "Running..."
                          : "Test twin server"}
                      </button>
                    </div>
                  </div>

                  {/* Practice 4 */}
                  <div className="ep-card p-5 flex flex-col justify-between space-y-4 min-w-0">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <h3 className="font-serif text-base font-medium text-ink">
                          4. Stamp the receipt book &amp; settle tokens
                        </h3>
                        <span className="ep-muted-chip">Practice</span>
                      </div>
                      <p className="text-sm text-ink-2 leading-relaxed">
                        Stamp the latest summary of server checks into the
                        public receipt book, or clear used anonymous tokens in a
                        single batch.
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onClick={() => void runAnchorTransparencyRoot()}
                        className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                      >
                        {busyAction === "anchor-root"
                          ? "Stamping..."
                          : "Stamp receipt book"}
                      </button>
                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onClick={() => void runRedeemCredits()}
                        className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                      >
                        {busyAction === "redeem-credits"
                          ? "Clearing..."
                          : "Clear used tokens"}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Plain action result banner */}
                {actionResult && (
                  <div className="ep-inset p-5 space-y-3 text-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-serif text-base font-medium text-ink">
                          {actionResult.title}
                        </span>
                        <span className="ep-muted-chip">Practice</span>
                        {actionResult.onChain && (
                          <span className="ep-pass">
                            Recorded in public receipt book
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => setActionResult(null)}
                        className="ep-link font-mono text-xs cursor-pointer"
                      >
                        Dismiss
                      </button>
                    </div>

                    <p className="text-ink-2">{actionResult.plainSummary}</p>

                    {actionResult.explorerUrl && (
                      <div>
                        <a
                          href={actionResult.explorerUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-btn text-xs py-2 px-3.5 inline-flex items-center gap-2"
                        >
                          <span>Open receipt in public receipt book</span>
                          <span aria-hidden="true">-&gt;</span>
                        </a>
                      </div>
                    )}

                    <TechDetails label="Show technical details">
                      <div className="space-y-2 pt-2 font-mono text-[11px] text-ink-2">
                        <div>{actionResult.verdictSummary}</div>
                        {actionResult.evidenceHash && (
                          <div className="break-all">
                            evidenceHash: {actionResult.evidenceHash}
                          </div>
                        )}
                        {actionResult.txHash && (
                          <div className="break-all">
                            txHash: {actionResult.txHash}
                          </div>
                        )}
                        <pre className="mt-2 ep-card p-3 max-h-60 overflow-auto text-[11px] text-ink-2">
                          {JSON.stringify(actionResult.payload, null, 2)}
                        </pre>
                      </div>
                    </TechDetails>
                  </div>
                )}

                {/* Deep technical details for transparency log, ramp states, quorum, credits, and frozen blobs */}
                <TechDetails label="Show technical details">
                  <div className="space-y-6 pt-2 text-xs">
                    {/* Transparency Log Root & Proofs */}
                    <div className="ep-card p-4 space-y-4">
                      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule pb-3">
                        <div>
                          <div className="ep-label">
                            RFC 6962 Merkle transparency log
                          </div>
                          <h3 className="font-serif text-base text-ink">
                            Signed tree head and Merkle inclusion proofs
                          </h3>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {sthVerification?.ok ? (
                            <span className="ep-pass">
                              STH Ed25519 verified
                            </span>
                          ) : (
                            <span className="ep-muted-chip">
                              Checking STH...
                            </span>
                          )}
                          {consistencyVerification?.ok && (
                            <span className="ep-pass">
                              Consistency proof verified
                            </span>
                          )}
                        </div>
                      </div>

                      {transparency ? (
                        <div className="space-y-4">
                          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 font-mono">
                            <div className="ep-inset p-3 space-y-1">
                              <div className="ep-label">
                                Verification log Merkle root (tree size{" "}
                                {transparency.signedTreeHead?.treeSize ??
                                  transparency.verificationLog?.treeSize ??
                                  transparency.log.entries.length}
                                )
                              </div>
                              <div className="text-ink break-all">
                                {transparency.signedTreeHead?.rootHash ??
                                  transparency.verificationLog?.root ??
                                  transparency.log.root}
                              </div>
                              <div className="text-ink-3 text-[11px]">
                                Operator key:{" "}
                                {shortHex(
                                  transparency.operatorPublicKey ?? "",
                                  14,
                                  10,
                                )}{" "}
                                | Persisted:{" "}
                                {transparency.persisted
                                  ? "MongoDB"
                                  : "In-memory"}
                              </div>
                            </div>

                            <div className="ep-inset p-3 space-y-1">
                              <div className="ep-label">
                                Release log Merkle root (
                                {transparency.log.entries.length} entries)
                              </div>
                              <div className="text-ink break-all">
                                {transparency.log.root}
                              </div>
                              <div className="text-ink-3 text-[11px]">
                                {sthVerification?.detail ??
                                  "RFC 6962 sha256(0x00 || leaf) and sha256(0x01 || L || R)"}
                              </div>
                            </div>
                          </div>

                          <div className="space-y-2">
                            <div className="ep-label">
                              Verification log leaves and RFC 6962 inclusion
                              proofs
                            </div>
                            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 font-mono">
                              {(
                                transparency.verificationLog?.events ?? []
                              ).map((ev, idx) => {
                                const proof =
                                  transparency.verificationLog
                                    ?.inclusionProofs?.[idx];
                                const verified = proof
                                  ? verifyInclusionProofClient(proof)
                                  : null;
                                return (
                                  <div
                                    key={ev.index}
                                    className="ep-inset p-2.5 space-y-1 text-[11px] text-ink-2"
                                  >
                                    <div className="flex items-center justify-between gap-1">
                                      <span className="text-ink font-medium">
                                        #{ev.index} {ev.nodeId} ({ev.kind})
                                      </span>
                                      <span
                                        className={
                                          verified?.ok
                                            ? "ep-pass"
                                            : "ep-muted-chip"
                                        }
                                      >
                                        {verified?.ok ? "Proof OK" : "Leaf"}
                                      </span>
                                    </div>
                                    <div className="break-all">
                                      Leaf: {shortHex(ev.leafHash, 12, 8)}
                                    </div>
                                    <div className="break-all">
                                      Evidence:{" "}
                                      {shortHex(ev.evidenceHash, 12, 8)}
                                    </div>
                                    <div>
                                      Audit path:{" "}
                                      {proof
                                        ? `${proof.auditPath.length} step(s)`
                                        : "n/a"}{" "}
                                      | Hour: {formatUnixSec(ev.epochHourSec)}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      ) : (
                        <p className="text-ink-3">
                          Loading transparency log root and inclusion proofs...
                        </p>
                      )}
                    </div>

                    {/* Node Ramp States */}
                    <div className="space-y-2">
                      <div className="ep-label">Node heartbeat ramp state</div>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
                        {Object.values(accountability?.rampStates ?? {}).map(
                          (r) => (
                            <div
                              key={r.nodeId}
                              className="ep-inset p-3 space-y-1"
                            >
                              <div className="flex items-center justify-between font-mono">
                                <span className="text-ink font-medium">
                                  {r.nodeId}
                                </span>
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
                          ),
                        )}
                      </div>
                    </div>

                    {/* Monitor Policy Table Check */}
                    <div className="space-y-1">
                      <div className="ep-label">
                        Monitor exit policy table (JavaScript state enumeration)
                      </div>
                      <p className="text-ink-2">
                        Checked{" "}
                        {monitorPolicyCheck.statesChecked.toLocaleString()}{" "}
                        combinations in browser memory:{" "}
                        {monitorPolicyCheck.allowedStates} allowed,{" "}
                        {monitorPolicyCheck.deniedStates.toLocaleString()}{" "}
                        denied.
                      </p>
                    </div>

                    {/* Blind Credits & Frozen Blobs */}
                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <div className="space-y-2">
                        <div className="ep-label">
                          Blind-signed credit counters
                        </div>
                        {credits ? (
                          <div className="ep-inset p-3 font-mono space-y-1 text-ink-2">
                            <div>
                              Modulus (n): {shortHex(credits.n, 16, 10)}
                            </div>
                            <div>
                              Spent nullifiers: {credits.stats.spentCount} |
                              Unredeemed: {credits.stats.unredeemedCount} |
                              Batches: {credits.stats.redeemedBatches}
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
                                  {b.byteLength} B ({formatUnixSec(b.createdAt)}
                                  )
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="ep-inset p-3 text-ink-3">
                            No frozen session blobs currently stored.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </TechDetails>
              </section>
            </InkReveal>
          </div>
        </AuthGate>
      </main>

      <SpecimenFooter />
    </div>
  );
}
