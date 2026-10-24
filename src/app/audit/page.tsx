"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
import {
  type AccountabilityResponse,
  type AuditorResponse,
  buildVerifiableClaims,
  type CanarySessionView,
  formatUnixSec,
  type RampEvaluationView,
  type RecordedClaimEventView,
  shortHex,
  type TransparencyResponse,
} from "@/components/audit/audit-helpers";
import {
  ExhibitSection,
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

      // Also append this verification event to the live transparency log
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
        title: "Transparency log root anchor (/api/anchor)",
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
        title: "Batch credit nullifier settlement (/api/credits/redeem)",
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
              Every live hardware, transparency, and registry claim below links
              to an exact external record you can verify yourself. Accountability
              fault actions record real evidence hashes on Circle Arc Testnet.
            </p>
          </header>

          {/* 1. External Claims You Can Verify Yourself */}
          <section
            aria-label="Claims you can verify yourself"
            className="space-y-4"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div className="space-y-1">
                <div className="ep-label">Independent verification</div>
                <h2 className="font-serif text-2xl text-ink">
                  Claims you can verify yourself
                </h2>
              </div>
              <span className="ep-muted-chip">
                {matrix
                  ? `Live attestation fetched (${matrix.routerHost})`
                  : "Loading live attestation records..."}
              </span>
            </div>

            <div className="ep-card divide-y divide-rule">
              {verifiableClaims.map((item) => (
                <div
                  key={item.id}
                  className="p-4 sm:p-5 flex flex-col gap-3 sm:flex-row sm:items-baseline sm:justify-between"
                >
                  <div className="space-y-1.5 max-w-[62ch] min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-serif text-base font-medium text-ink">
                        {item.title}
                      </h3>
                      <span className="ep-pass break-all">{item.liveRecordBadge}</span>
                    </div>
                    <p className="text-xs sm:text-sm text-ink-2 leading-relaxed break-words">
                      {item.claim}
                    </p>
                  </div>
                  <div className="flex flex-col sm:items-end gap-1.5 sm:shrink-0 min-w-0">
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noreferrer"
                      className="ep-link font-mono text-xs break-all"
                    >
                      {item.linkLabel} -&gt;
                    </a>
                    {item.secondaryHref && item.secondaryLabel && (
                      <a
                        href={item.secondaryHref}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link font-mono text-[11px] text-ink-3 break-all"
                      >
                        {item.secondaryLabel} -&gt;
                      </a>
                    )}
                  </div>
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

          {/* 2. Mystery-Shopper Statistical Model Auditor (/api/auditor) */}
          <section
            aria-label="Mystery-shopper model auditor"
            className="space-y-4"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div className="space-y-1">
                <div className="ep-label">Model integrity audit</div>
                <h2 className="font-serif text-2xl text-ink">
                  Latest mystery-shopper SPRT audit result
                </h2>
              </div>
              <div className="flex items-center gap-2">
                {auditor?.simulated === true ? (
                  <span className="ep-muted-chip">Simulated</span>
                ) : auditor?.hasRun ? (
                  <span
                    className={
                      auditor.latestRun?.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {auditor.latestRun?.verdict ?? "RECORDED"}
                  </span>
                ) : (
                  <span className="ep-muted-chip">Awaiting first run</span>
                )}
              </div>
            </div>

            <div className="ep-card p-4 sm:p-5 space-y-4">
              {auditor?.latestRun ? (
                <>
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-rule pb-3">
                    <div className="space-y-0.5">
                      <div className="font-serif text-base font-medium text-ink">
                        Model:{" "}
                        <span className="font-mono">
                          {auditor.latestRun.model}
                        </span>{" "}
                        via{" "}
                        <span className="font-mono">
                          {auditor.latestRun.enclaveHost}
                        </span>
                      </div>
                      <p className="text-xs text-ink-2">
                        {auditor.statusMessage}
                      </p>
                    </div>
                    <div className="font-mono text-xs text-ink-3 shrink-0">
                      Coarse hour:{" "}
                      {String(auditor.latestRun.at)
                        .replace("T", " ")
                        .slice(0, 19)}{" "}
                      UTC
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs font-mono">
                    <div className="ep-inset p-3 space-y-1">
                      <div className="ep-label">Canary probes passed</div>
                      <div className="text-sm text-ink font-medium">
                        {auditor.latestRun.passedCount} /{" "}
                        {auditor.latestRun.probesCount} (
                        {Math.round(auditor.latestRun.empiricalPassRate * 100)}
                        %)
                      </div>
                    </div>
                    <div className="ep-inset p-3 space-y-1">
                      <div className="ep-label">Cumulative SPRT LLR</div>
                      <div className="text-sm text-ink font-medium">
                        {auditor.latestRun.cumulativeSprtStatistic.toFixed(4)}
                      </div>
                    </div>
                    <div className="ep-inset p-3 space-y-1">
                      <div className="ep-label">Decision bounds [B, A]</div>
                      <div className="text-sm text-ink font-medium">
                        [{auditor.latestRun.lowerBoundB.toFixed(2)}, +
                        {auditor.latestRun.upperBoundA.toFixed(2)}]
                      </div>
                    </div>
                    <div className="ep-inset p-3 space-y-1">
                      <div className="ep-label">Mean enclave latency</div>
                      <div className="text-sm text-ink font-medium">
                        {auditor.latestRun.meanLatencyMs} ms
                      </div>
                    </div>
                  </div>

                  {auditor.parameters?.canaryCategories && (
                    <div className="text-xs text-ink-2 font-mono">
                      Canary battery:{" "}
                      {auditor.parameters.canaryCategories
                        .map((c) => `${c.probeId} (${c.category})`)
                        .join(" | ")}
                    </div>
                  )}
                </>
              ) : (
                <div className="space-y-2 text-xs text-ink-2">
                  <p className="text-ink font-medium">
                    {auditor?.statusMessage ??
                      "Loading mystery-shopper audit history from /api/auditor..."}
                  </p>
                  <p>
                    Protocol: {auditor?.protocol ?? "mystery-shopper-sprt-v1"}{" "}
                    (p0={auditor?.parameters?.baselinePassRateP0 ?? 0.9}, p1=
                    {auditor?.parameters?.substitutePassRateP1 ?? 0.45}, alpha=
                    {auditor?.parameters?.falsePositiveAlpha ?? 0.001}, beta=
                    {auditor?.parameters?.falseNegativeBeta ?? 0.01}).
                  </p>
                </div>
              )}
            </div>
          </section>

          {/* 3. Accountability and On-Chain Evidence Actions */}
          <section
            aria-label="Accountability actions"
            className="space-y-4"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div className="space-y-1">
                <div className="ep-label">Live endpoints &amp; Arc Testnet</div>
                <h2 className="font-serif text-2xl text-ink">
                  Accountability actions and on-chain evidence
                </h2>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {accountability?.onChain ? (
                  <span className="ep-pass">
                    Arc Testnet connected (min stake{" "}
                    {accountability.minStakeUsdc ?? "0.01"} USDC)
                  </span>
                ) : accountability?.simulated === true ? (
                  <span className="ep-muted-chip">Simulated</span>
                ) : (
                  <span className="ep-muted-chip">
                    Nodes: tinfoil-router, sim-1, sim-2, sim-3
                  </span>
                )}
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
              Each fault action below evaluates cryptographic proofs against the
              node&apos;s staked balance on{" "}
              <code className="font-mono text-xs">DRouterRegistry</code> and
              submits a real <code className="font-mono text-xs">recordVerification</code>{" "}
              or <code className="font-mono text-xs">anchorReceipt</code>{" "}
              transaction to Circle Arc Testnet.
            </p>

            {/* Latest On-Chain Transaction Banner */}
            {(accountability?.txHash || latestClaimWithTx?.txHash) && (
              <div className="ep-inset p-3.5 flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between text-xs font-mono">
                <div className="space-y-0.5">
                  <span className="ep-label">
                    Latest on-chain registry transaction
                  </span>
                  <div className="text-ink break-all">
                    txHash:{" "}
                    {accountability?.txHash ?? latestClaimWithTx?.txHash}
                  </div>
                </div>
                {(accountability?.explorerUrl ||
                  latestClaimWithTx?.explorerUrl) && (
                  <a
                    href={
                      (accountability?.explorerUrl ??
                        latestClaimWithTx?.explorerUrl) ||
                      "#"
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="ep-link shrink-0"
                  >
                    View on Circle Arc Explorer -&gt;
                  </a>
                )}
              </div>
            )}

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {/* Action 1: Canary Honeytoken */}
              <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4 min-w-0">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-serif text-base font-medium text-ink">
                      1. Canary honeytoken leak (sim-1)
                    </h3>
                    {accountability?.simulated === true ? (
                      <span className="ep-muted-chip">Simulated</span>
                    ) : (
                      <span className="ep-pass">On-chain evidence</span>
                    )}
                  </div>
                  <p className="text-xs text-ink-2 leading-relaxed break-words">
                    Reveals the pre-committed canary honeytoken and salt for{" "}
                    <code className="font-mono">sim-1</code>, verifies the
                    SHA-256 commitment against its{" "}
                    {accountability?.minStakeUsdc ?? "0.01"} USDC stake, and
                    records the evidence hash on Circle Arc Testnet.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() =>
                    void runAccountabilityAction(
                      "trigger-canary",
                      "sim-1",
                      "Canary honeytoken leak verification (sim-1)",
                    )
                  }
                  className="ep-btn text-xs self-start cursor-pointer"
                >
                  {busyAction === "trigger-canary:sim-1"
                    ? "Submitting to Arc..."
                    : "Verify canary leak & record on-chain"}
                </button>
              </div>

              {/* Action 2: Key-Compromise Bounty */}
              <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4 min-w-0">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-serif text-base font-medium text-ink">
                      2. Key-compromise proof (sim-2)
                    </h3>
                    {accountability?.simulated === true ? (
                      <span className="ep-muted-chip">Simulated</span>
                    ) : (
                      <span className="ep-pass">On-chain evidence</span>
                    )}
                  </div>
                  <p className="text-xs text-ink-2 leading-relaxed break-words">
                    Submits a P-384 signature over the forbidden prefix{" "}
                    <code className="font-mono">
                      {accountability?.forbiddenPrefix
                        ? shortHex(accountability.forbiddenPrefix, 10, 6)
                        : "F"}
                    </code>{" "}
                    on <code className="font-mono">sim-2</code> and records the
                    compromise evidence hash on Circle Arc Testnet.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() =>
                    void runAccountabilityAction(
                      "claim-key-bounty",
                      "sim-2",
                      "Key-compromise proof verification (sim-2)",
                    )
                  }
                  className="ep-btn text-xs self-start cursor-pointer"
                >
                  {busyAction === "claim-key-bounty:sim-2"
                    ? "Submitting to Arc..."
                    : "Submit key-compromise proof"}
                </button>
              </div>

              {/* Action 3: Restart or Clone */}
              <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4 min-w-0">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-serif text-base font-medium text-ink">
                      3. Unannounced restart or cloned key (sim-3)
                    </h3>
                    {accountability?.simulated === true ? (
                      <span className="ep-muted-chip">Simulated</span>
                    ) : (
                      <span className="ep-pass">On-chain evidence</span>
                    )}
                  </div>
                  <p className="text-xs text-ink-2 leading-relaxed break-words">
                    Places <code className="font-mono">sim-3</code> into
                    canary-only probation (0 bps routing weight) after an
                    unannounced reboot, or suspends it on duplicate key
                    heartbeats, and anchors the evidence hash on-chain.
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
                        "Unannounced restart evaluation (sim-3)",
                      )
                    }
                    className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                  >
                    {busyAction === "simulate-restart:sim-3"
                      ? "Submitting..."
                      : "Record restart probation"}
                  </button>
                  <button
                    type="button"
                    disabled={busyAction !== null}
                    onClick={() =>
                      void runAccountabilityAction(
                        "simulate-clone",
                        "sim-3",
                        "Cloned identity key detection (sim-3)",
                      )
                    }
                    className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                  >
                    {busyAction === "simulate-clone:sim-3"
                      ? "Submitting..."
                      : "Record clone suspension"}
                  </button>
                </div>
              </div>

              {/* Action 4: Anchor Transparency Merkle Root & Batch Redeem Credits */}
              <div className="ep-card p-4 sm:p-5 flex flex-col justify-between space-y-4 min-w-0">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-serif text-base font-medium text-ink">
                      4. Anchor Merkle root &amp; settle credits
                    </h3>
                    {credits?.simulated === true ? (
                      <span className="ep-muted-chip">Simulated</span>
                    ) : (
                      <span className="ep-pass">RFC 6962 + RSA-2048</span>
                    )}
                  </div>
                  <p className="text-xs text-ink-2 leading-relaxed break-words">
                    Anchors the current transparency log Merkle root via{" "}
                    <code className="font-mono">/api/anchor</code> on Circle Arc
                    Testnet, or flushes unredeemed blind-credit nullifiers via{" "}
                    <code className="font-mono">/api/credits/redeem</code>.
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
                      ? "Anchoring..."
                      : "Anchor log root (/api/anchor)"}
                  </button>
                  <button
                    type="button"
                    disabled={busyAction !== null}
                    onClick={() => void runRedeemCredits()}
                    className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
                  >
                    {busyAction === "redeem-credits"
                      ? "Settling..."
                      : "Batch-redeem credits"}
                  </button>
                </div>
              </div>
            </div>

            {/* Action Verdict & On-Chain Receipt Output */}
            {actionResult && (
              <div className="ep-inset p-4 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-serif text-sm font-medium text-ink">
                      {actionResult.title}
                    </span>
                    {actionResult.onChain && (
                      <span className="ep-pass">On-chain (Arc Testnet)</span>
                    )}
                    {actionResult.simulated && (
                      <span className="ep-muted-chip">Simulated</span>
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

                <p className="text-ink-2">{actionResult.verdictSummary}</p>

                {(actionResult.txHash ||
                  actionResult.explorerUrl ||
                  actionResult.evidenceHash) && (
                  <div className="ep-card p-3 font-mono text-[11px] space-y-1">
                    {actionResult.evidenceHash && (
                      <div className="text-ink-2 break-all">
                        <span className="text-ink font-medium">
                          evidenceHash:
                        </span>{" "}
                        {actionResult.evidenceHash}
                      </div>
                    )}
                    {actionResult.txHash && (
                      <div className="text-ink-2 break-all">
                        <span className="text-ink font-medium">txHash:</span>{" "}
                        {actionResult.txHash}
                      </div>
                    )}
                    {actionResult.explorerUrl && (
                      <div>
                        <a
                          href={actionResult.explorerUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-link"
                        >
                          {actionResult.explorerUrl} -&gt;
                        </a>
                      </div>
                    )}
                  </div>
                )}

                <details>
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show raw response JSON
                  </summary>
                  <pre className="mt-2 ep-card p-3 max-h-60 overflow-auto font-mono text-[11px] text-ink-2">
                    {JSON.stringify(actionResult.payload, null, 2)}
                  </pre>
                </details>
              </div>
            )}

            {/* 4. Transparency Log Root, Signed Tree Head, and Inclusion Proofs */}
            <div className="ep-card p-4 sm:p-5 space-y-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule pb-3">
                <div className="space-y-0.5">
                  <div className="ep-label">RFC 6962 Merkle transparency log</div>
                  <h3 className="font-serif text-lg text-ink">
                    Signed tree head and Merkle inclusion proofs
                  </h3>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {sthVerification?.ok ? (
                    <span className="ep-pass">STH Ed25519 verified</span>
                  ) : (
                    <span className="ep-muted-chip">Checking STH...</span>
                  )}
                  {consistencyVerification?.ok && (
                    <span className="ep-pass">Consistency proof verified</span>
                  )}
                </div>
              </div>

              {transparency ? (
                <div className="space-y-4 text-xs">
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
                        {shortHex(transparency.operatorPublicKey ?? "", 14, 10)}{" "}
                        | Persisted:{" "}
                        {transparency.persisted ? "MongoDB" : "In-memory"}
                      </div>
                      {transparency.signedTreeHead?.anchorTx && (
                        <div className="pt-1">
                          <a
                            href={
                              transparency.anchorExplorerUrl ??
                              `https://explorer.testnet.arc.io/tx/${transparency.signedTreeHead.anchorTx}`
                            }
                            target="_blank"
                            rel="noreferrer"
                            className="ep-link text-[11px]"
                          >
                            Anchored tx:{" "}
                            {shortHex(
                              transparency.signedTreeHead.anchorTx,
                              12,
                              8,
                            )}{" "}
                            -&gt;
                          </a>
                        </div>
                      )}
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

                  {/* Verification Log Events & Inclusion Proofs */}
                  <div className="space-y-2">
                    <div className="ep-label">
                      Verification log leaves and RFC 6962 inclusion proofs
                    </div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 font-mono">
                      {(transparency.verificationLog?.events ?? []).map(
                        (ev, idx) => {
                          const proof =
                            transparency.verificationLog?.inclusionProofs?.[
                              idx
                            ];
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
                                Evidence: {shortHex(ev.evidenceHash, 12, 8)}
                              </div>
                              <div>
                                Audit path:{" "}
                                {proof ? `${proof.auditPath.length} step(s)` : "n/a"}{" "}
                                | Hour: {formatUnixSec(ev.epochHourSec)}
                              </div>
                            </div>
                          );
                        },
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-ink-3">
                  Loading transparency log root and inclusion proofs...
                </p>
              )}
            </div>

            {/* Collapsible Node Ramp State, Quorum, Credits, Frozen Blobs */}
            <details className="ep-card p-4 sm:p-5">
              <summary className="cursor-pointer font-serif text-base font-medium text-ink select-none">
                Show node ramp state, recent on-chain claims, quorum tickets,
                credit counters, and frozen blobs
              </summary>

              <div className="mt-4 space-y-6 border-t border-rule pt-4 text-xs">
                {/* Recent Accountability Claims */}
                {accountability?.recentClaims &&
                  accountability.recentClaims.length > 0 && (
                    <div className="space-y-2">
                      <div className="ep-label">
                        Recent accountability claims and on-chain transactions
                      </div>
                      <div className="space-y-2 font-mono">
                        {accountability.recentClaims.map((claim) => (
                          <div
                            key={claim.id}
                            className="ep-inset p-3 space-y-1 text-ink-2"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-ink font-medium">
                                {claim.id} | {claim.kind} on {claim.nodeId}
                              </span>
                              <div className="flex items-center gap-2">
                                {claim.onChain && (
                                  <span className="ep-pass">On-chain</span>
                                )}
                                {claim.simulated === true && (
                                  <span className="ep-muted-chip">
                                    Simulated
                                  </span>
                                )}
                              </div>
                            </div>
                            <p className="font-sans text-xs text-ink-2">
                              {claim.summary}
                            </p>
                            {claim.evidenceHash && (
                              <div className="text-[11px] break-all">
                                evidenceHash: {claim.evidenceHash}
                              </div>
                            )}
                            {claim.txHash && (
                              <div className="text-[11px] break-all">
                                txHash: {claim.txHash}{" "}
                                {claim.explorerUrl && (
                                  <a
                                    href={claim.explorerUrl}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="ep-link ml-2"
                                  >
                                    Arc Explorer -&gt;
                                  </a>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Node Ramp States */}
                <div className="space-y-2">
                  <div className="ep-label">Node heartbeat ramp state</div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
                    {Object.values(accountability?.rampStates ?? {}).map(
                      (r) => (
                        <div key={r.nodeId} className="ep-inset p-3 space-y-1">
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

                {/* Release Transparency Entries & Quorum Tickets */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <div className="ep-label">
                      Release log entries and inclusion proofs
                    </div>
                    <div className="space-y-2">
                      {(transparency?.log?.entries ?? []).map((entry, idx) => {
                        const proof = transparency?.proofs?.[idx];
                        const proofCheck = proof
                          ? verifyInclusionProofClient(proof)
                          : null;
                        return (
                          <div
                            key={entry.index}
                            className="ep-inset p-2.5 font-mono space-y-1 text-ink-2"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-ink font-medium">
                                #{entry.index} {entry.imageId} ({entry.version})
                              </span>
                              {proofCheck?.ok && (
                                <span className="ep-pass">Merkle OK</span>
                              )}
                            </div>
                            <div>
                              Measurement: {shortHex(entry.measurement, 14, 8)}
                            </div>
                            {proof && (
                              <div className="text-[11px] text-ink-3">
                                Leaf: {shortHex(proof.leafHash, 12, 8)} (
                                {proof.auditPath.length} sibling hashes)
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="ep-label">5-of-7 quorum tickets</div>
                      {(transparency?.quorumSimulated ||
                        transparency?.verifierSet?.quorumSimulated) && (
                        <span className="ep-muted-chip">Simulated</span>
                      )}
                    </div>
                    <div className="space-y-2">
                      {Object.values(transparency?.tickets ?? {}).map(
                        (ticket) => (
                          <div
                            key={ticket.nodeId}
                            className="ep-inset p-2.5 font-mono space-y-1 text-ink-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-ink font-medium">
                                {ticket.nodeId}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span>
                                  {ticket.signatures.length}/7 sigs (
                                  {ticket.weight} bps)
                                </span>
                                {ticket.quorumSimulated && (
                                  <span className="ep-muted-chip">
                                    Simulated
                                  </span>
                                )}
                              </div>
                            </div>
                            <div>Chip ID: {shortHex(ticket.chipId, 12, 8)}</div>
                          </div>
                        ),
                      )}
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
                        {credits.issuerAddress && (
                          <div>
                            Arc USDC issuer:{" "}
                            {shortHex(credits.issuerAddress, 12, 8)} (
                            {credits.usdcPerCredit ?? "0.0001"} USDC/credit)
                          </div>
                        )}
                        <div>
                          Spent nullifiers: {credits.stats.spentCount} |
                          Unredeemed: {credits.stats.unredeemedCount} | Batches:{" "}
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

        {/* 5. What if someone cheats? */}
        <ExhibitSection
          tag="Threat matrix"
          title="What if someone cheats?"
          subtitle="Inspect seven real-world compromise scenarios and the repository tests that verify each defense."
        >
          <ThreatMatrix />
        </ExhibitSection>
      </main>

      <SpecimenFooter />
    </div>
  );
}
