"use client";

import React, { useEffect, useState } from "react";
import type { CheckResult, NodeRecord } from "@/lib/types";
import type {
  DeepAttestationBundle,
  ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import {
  buildAmdKdsVcekUrl,
  buildArcExplorerAddressUrl,
  buildArcExplorerTxUrl,
  buildGitHubDeploymentJsonUrl,
  buildGitHubHashAssetUrl,
  buildGitHubReleaseTagUrl,
  buildSigstoreSearchByHashUrl,
  extractAttestationRekorEntry,
  isDeepAttestationBundle,
  lookupRekorEntryByDigest,
  resolveActiveRegistryNode,
  resolveModelDeploymentProvenance,
  type DeploymentAssetLookup,
  type RawAttestationResponse,
  type RegistrySnapshot,
  type RekorLookupEntry,
  type TransparencySnapshot,
} from "@/components/inspector/live-records";

export type InspectorTabId =
  | "overview"
  | "silicon"
  | "gpu"
  | "provenance"
  | "onchain"
  | "privacy";

export interface RecordInspectorModalProps {
  open: boolean;
  initialTab?: InspectorTabId;
  onClose: () => void;
  node: NodeRecord | null;
  model: string;
  checks: CheckResult[];
  evidence: Record<string, string>;
  deepBundle?: DeepAttestationBundle | unknown;
  verifyAnchorUrl?: string | null;
  registryAddress?: string | null;
}

function displayValue(
  value: string | number | undefined | null,
  loading: boolean,
): string {
  if (value !== undefined && value !== null && String(value).trim() !== "") {
    return String(value);
  }
  return loading ? "Loading" : "Unavailable";
}

export function RecordInspectorModal({
  open,
  initialTab = "overview",
  onClose,
  node,
  model,
  checks,
  evidence,
  deepBundle,
  verifyAnchorUrl,
  registryAddress,
}: RecordInspectorModalProps) {
  const [activeTab, setActiveTab] = useState<InspectorTabId>(initialTab);
  const [selectedModelId, setSelectedModelId] = useState<string>(
    model && TINFOIL_MODELS.some((m) => m.id === model) ? model : "kimi-k3",
  );
  const [fetchedBundle, setFetchedBundle] =
    useState<DeepAttestationBundle | null>(null);
  const [loadingBundle, setLoadingBundle] = useState<boolean>(false);

  const [rawAttestation, setRawAttestation] =
    useState<RawAttestationResponse | null>(null);
  const [loadingAttestation, setLoadingAttestation] = useState<boolean>(false);

  const [transparency, setTransparency] =
    useState<TransparencySnapshot | null>(null);
  const [loadingTransparency, setLoadingTransparency] =
    useState<boolean>(false);

  const [registrySnapshot, setRegistrySnapshot] =
    useState<RegistrySnapshot | null>(null);
  const [loadingRegistry, setLoadingRegistry] = useState<boolean>(false);

  const [routerRekorEntry, setRouterRekorEntry] =
    useState<RekorLookupEntry | null>(null);
  const [modelProvenanceCache, setModelProvenanceCache] = useState<
    Record<string, DeploymentAssetLookup>
  >({});

  useEffect(() => {
    if (open && initialTab) {
      setActiveTab(initialTab);
    }
  }, [open, initialTab]);

  useEffect(() => {
    if (model && TINFOIL_MODELS.some((m) => m.id === model)) {
      setSelectedModelId(model);
    }
  }, [model]);

  useEffect(() => {
    if (!open) return;

    if (!isDeepAttestationBundle(deepBundle) && !fetchedBundle) {
      setLoadingBundle(true);
      fetch("/api/relay/enclave-matrix")
        .then(async (res) =>
          res.ok ? ((await res.json()) as DeepAttestationBundle) : null,
        )
        .then((data) => {
          if (data) setFetchedBundle(data);
        })
        .catch(() => {})
        .finally(() => setLoadingBundle(false));
    }

    if (!rawAttestation) {
      setLoadingAttestation(true);
      fetch("/api/relay/attestation")
        .then(async (res) =>
          res.ok ? ((await res.json()) as RawAttestationResponse) : null,
        )
        .then((data) => {
          if (data) setRawAttestation(data);
        })
        .catch(() => {})
        .finally(() => setLoadingAttestation(false));
    }

    if (!transparency) {
      setLoadingTransparency(true);
      fetch("/api/transparency")
        .then(async (res) =>
          res.ok ? ((await res.json()) as TransparencySnapshot) : null,
        )
        .then((data) => {
          if (data) setTransparency(data);
        })
        .catch(() => {})
        .finally(() => setLoadingTransparency(false));
    }

    if (!registrySnapshot) {
      setLoadingRegistry(true);
      fetch("/api/registry")
        .then(async (res) =>
          res.ok ? ((await res.json()) as RegistrySnapshot) : null,
        )
        .then((data) => {
          if (data) setRegistrySnapshot(data);
        })
        .catch(() => {})
        .finally(() => setLoadingRegistry(false));
    }
  }, [
    open,
    deepBundle,
    fetchedBundle,
    rawAttestation,
    transparency,
    registrySnapshot,
  ]);

  const bundle: DeepAttestationBundle | null = isDeepAttestationBundle(
    deepBundle,
  )
    ? deepBundle
    : fetchedBundle;

  const routerDigest = rawAttestation?.digest ?? bundle?.routerReleaseDigest;

  useEffect(() => {
    if (!open || !routerDigest || routerRekorEntry) return;
    let cancelled = false;
    void lookupRekorEntryByDigest(routerDigest).then((entry) => {
      if (!cancelled && entry) {
        setRouterRekorEntry(entry);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [open, routerDigest, routerRekorEntry]);

  const activeModelAttestation: ModelEnclaveAttestation | undefined =
    bundle?.models?.[selectedModelId];

  useEffect(() => {
    if (!open || !activeModelAttestation) return;
    const cacheKey = `${activeModelAttestation.repo}@${activeModelAttestation.tag}`;
    if (modelProvenanceCache[cacheKey]) return;
    let cancelled = false;
    void resolveModelDeploymentProvenance(activeModelAttestation).then(
      (prov) => {
        if (!cancelled) {
          setModelProvenanceCache((prev) => ({ ...prev, [cacheKey]: prov }));
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [open, activeModelAttestation, modelProvenanceCache]);

  if (!open) return null;

  const snp = bundle?.routerSnpReport;
  const activeNode = resolveActiveRegistryNode(node, registrySnapshot);
  const isSim = activeNode?.kind === "sim";
  const loadingAny = loadingBundle || loadingAttestation;

  const chipId = isSim
    ? displayValue(evidence["Chip ID"] ?? evidence.chipId, false)
    : displayValue(
        snp?.chipIdHex ?? evidence["Chip ID"] ?? evidence.chipId,
        loadingBundle,
      );

  const measurement = isSim
    ? displayValue(evidence.Measurement ?? activeNode?.measurement, false)
    : displayValue(
        snp?.measurementHex ??
          evidence["Enclave fingerprint"] ??
          evidence.Measurement,
        loadingBundle,
      );

  const reportData = isSim
    ? displayValue(evidence["Report data"], false)
    : displayValue(snp?.reportDataHex, loadingBundle);

  const tlsKeyFpFromReport = displayValue(
    snp?.tlsKeyFpFromReportDataHex,
    loadingBundle,
  );
  const hpkeKeyFromReport = displayValue(
    snp?.hpkeKeyFromReportDataHex ?? evidence["HPKE key"],
    loadingBundle,
  );

  const signatureR = displayValue(snp?.signatureRHex, loadingBundle);
  const signatureS = displayValue(snp?.signatureSHex, loadingBundle);

  const amdKdsUrl =
    buildAmdKdsVcekUrl(snp?.productName, snp?.chipIdHex, snp?.tcb) ??
    bundle?.amdKdsUrl ??
    null;

  const modelIds = bundle?.models
    ? Object.keys(bundle.models)
    : TINFOIL_MODELS.map((m) => m.id);

  const cpuTeeLabel = activeModelAttestation
    ? activeModelAttestation.hardwarePredicate.includes("sev-snp")
      ? "AMD SEV-SNP"
      : activeModelAttestation.hardwarePredicate.includes("tdx")
        ? "Intel TDX"
        : activeModelAttestation.hardwarePredicate
    : loadingBundle
      ? "Loading"
      : "Unavailable";

  const gpuDescription = activeModelAttestation
    ? `${activeModelAttestation.vmShape.gpus}x NVIDIA confidential-computing GPU${activeModelAttestation.vmShape.gpus === 1 ? "" : "s"}`
    : loadingBundle
      ? "Loading"
      : "Unavailable";

  const vmShapeDescription = activeModelAttestation
    ? `${activeModelAttestation.vmShape.cpus} vCPUs, ${Math.round(activeModelAttestation.vmShape.memoryMb / 1024)} GB RAM, ${activeModelAttestation.vmShape.gpus} confidential GPU${activeModelAttestation.vmShape.gpus === 1 ? "" : "s"}, ${activeModelAttestation.vmShape.disks} disks`
    : loadingBundle
      ? "Loading"
      : "Unavailable";

  const modelCacheKey = activeModelAttestation
    ? `${activeModelAttestation.repo}@${activeModelAttestation.tag}`
    : "";
  const activeModelProvenance = modelCacheKey
    ? modelProvenanceCache[modelCacheKey]
    : undefined;

  const modelDeploymentJsonUrl = activeModelAttestation
    ? buildGitHubDeploymentJsonUrl(
        activeModelAttestation.repo,
        activeModelAttestation.tag,
      )
    : null;
  const modelHashAssetUrl = activeModelAttestation
    ? buildGitHubHashAssetUrl(
        activeModelAttestation.repo,
        activeModelAttestation.tag,
      )
    : null;

  const routerRepo = bundle?.routerConfigRepo ?? evidence["Source repo"];
  const routerTag = bundle?.routerReleaseTag ?? evidence.Release;
  const routerReleaseUrl =
    bundle?.routerReleaseUrl ??
    (routerRepo && routerTag
      ? buildGitHubReleaseTagUrl(routerRepo, routerTag)
      : null);
  const routerDeploymentJsonUrl =
    routerRepo && routerTag
      ? buildGitHubDeploymentJsonUrl(routerRepo, routerTag)
      : null;
  const routerHashAssetUrl =
    routerRepo && routerTag
      ? buildGitHubHashAssetUrl(routerRepo, routerTag)
      : null;

  const attestationRekor = extractAttestationRekorEntry(rawAttestation);
  const routerSigstoreEntryUrl =
    attestationRekor?.searchUrl ??
    routerRekorEntry?.searchUrl ??
    (routerDigest ? buildSigstoreSearchByHashUrl(routerDigest) : null);
  const routerRekorApiUrl =
    routerRekorEntry?.apiUrl ?? attestationRekor?.apiUrl ?? null;

  const explorerBase = registrySnapshot?.explorer;
  const contractAddr = registryAddress || registrySnapshot?.address || null;
  const arcExplorerContractUrl = buildArcExplorerAddressUrl(
    explorerBase,
    contractAddr ?? undefined,
  );
  const operatorAddress = activeNode?.operator;
  const arcExplorerOperatorUrl = buildArcExplorerAddressUrl(
    explorerBase,
    operatorAddress,
  );
  const sessionTxUrl = buildArcExplorerTxUrl(explorerBase, verifyAnchorUrl);

  const nodeTicketKey =
    activeNode?.kind === "tinfoil"
      ? "tinfoil-router"
      : activeNode?.endpoint.split("/").filter(Boolean).pop() ||
        "tinfoil-router";
  const activeTicket = transparency?.tickets?.[nodeTicketKey];
  const logEntries = transparency?.log?.entries ?? [];

  const passedCount = checks.filter((c) => c.status === "pass").length;

  const tabs: Array<{ id: InspectorTabId; label: string }> = [
    {
      id: "overview",
      label: `1. Overview (${checks.length > 0 ? `${passedCount}/${checks.length}` : "C1-C7"})`,
    },
    { id: "silicon", label: "2. Router Silicon (SEV-SNP)" },
    { id: "gpu", label: "3. Model Enclave & Weights" },
    { id: "provenance", label: "4. Sigstore & Release" },
    { id: "onchain", label: "5. Arc Testnet & Quorum" },
    { id: "privacy", label: "6. Privacy & Limits" },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="record-inspector-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-2 sm:p-4"
    >
      <div className="ep-card flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden bg-paper text-ink">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-3 py-3 sm:px-5 sm:py-4">
          <div className="min-w-0">
            <div className="ep-label">Attestation &amp; Provenance</div>
            <h2
              id="record-inspector-title"
              className="ep-display mt-0.5 text-lg sm:text-2xl"
            >
              Raw Hardware &amp; Cryptographic Records
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="ep-btn-ghost shrink-0 px-3 py-1 text-xs"
          >
            Close
          </button>
        </div>

        <div className="flex gap-1 overflow-x-auto border-b border-rule bg-paper px-2 pt-2 sm:px-4">
          {tabs.map((t) => {
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={`whitespace-nowrap border-b-2 px-2.5 py-2 text-xs font-medium transition-colors sm:px-3 ${
                  active
                    ? "border-ink bg-paper-2 text-ink"
                    : "border-transparent text-ink-3 hover:text-ink"
                }`}
              >
                {t.label}
              </button>
            );
          })}
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto p-3 text-sm sm:p-5">
          {activeTab === "overview" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Before your browser sends a prompt, it runs 7 checks (C1 to C7) against the enclave hardware report, the Sigstore transparency log, the model enclave table, and the Circle Arc testnet registry.
              </p>

              {checks.length === 0 ? (
                <div className="ep-inset p-4 text-xs text-ink-2">
                  {loadingAny
                    ? "Loading verification checks..."
                    : "Unavailable. Connect to a node in the console to run checks C1 through C7."}
                </div>
              ) : (
                <div className="divide-y divide-rule border-t border-b border-rule">
                  {checks.map((check) => {
                    const jumpTab: InspectorTabId =
                      check.id === "C1" || check.id === "C3"
                        ? "silicon"
                        : check.id === "C2" || check.id === "C4"
                          ? "provenance"
                          : check.id === "C5" || check.id === "C7"
                            ? "gpu"
                            : "onchain";
                    return (
                      <div
                        key={check.id}
                        className="flex flex-col justify-between gap-3 py-3 sm:flex-row sm:items-center"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={
                                check.status === "pass"
                                  ? "ep-pass"
                                  : check.status === "fail"
                                    ? "ep-fail"
                                    : "ep-muted-chip"
                              }
                            >
                              {check.id} · {check.status}
                            </span>
                            <span className="font-medium text-ink">
                              {check.label}
                            </span>
                          </div>
                          <p className="ep-mono text-xs text-ink-2">
                            {check.detail}
                          </p>
                        </div>

                        <button
                          type="button"
                          onClick={() => setActiveTab(jumpTab)}
                          className="ep-btn-ghost shrink-0 self-start px-2.5 py-1 text-xs sm:self-center"
                        >
                          Inspect record
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === "silicon" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                The Tinfoil router enclave (
                {displayValue(
                  rawAttestation?.domain ?? bundle?.routerHost,
                  loadingAny,
                )}
                ) attests with AMD SEV-SNP. The AMD Secure Processor signs a 1,184-byte binary report committing to the boot measurement, guest policy flags, and the enclave&apos;s ephemeral key.
                {isSim &&
                  " Note: the currently selected node in the console is Simulated in software."}
              </p>

              <div className="flex flex-wrap gap-2">
                <a
                  href="https://atc.tinfoil.sh/attestation"
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open live router attestation (atc.tinfoil.sh/attestation)
                </a>
                {amdKdsUrl && (
                  <a
                    href={amdKdsUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open AMD KDS VCEK cert ({snp?.productName ?? "Genoa"} TCB)
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-3.5 sm:p-4 space-y-3 min-w-0">
                  <div className="ep-label">
                    AMD SEV-SNP Binary Registers (1,184 Bytes)
                  </div>
                  <div className="space-y-2.5 text-xs">
                    <div>
                      <div className="text-ink-3">
                        CHIP_ID (64 bytes · {displayValue(snp?.productName, loadingBundle)})
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {chipId}
                      </div>
                    </div>
                    <div>
                      <div className="text-ink-3">
                        MEASUREMENT (48-byte launch digest)
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {measurement}
                      </div>
                    </div>
                    <div>
                      <div className="text-ink-3">
                        REPORT_DATA (64 bytes binding TLS &amp; HPKE keys)
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {reportData}
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <div>
                        <div className="text-ink-3">
                          REPORT_DATA[0..32] (TLS key fp)
                        </div>
                        <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                          {tlsKeyFpFromReport}
                        </div>
                      </div>
                      <div>
                        <div className="text-ink-3">
                          REPORT_DATA[32..64] (HPKE key)
                        </div>
                        <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                          {hpkeKeyFromReport}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="ep-inset p-3.5 sm:p-4 space-y-3 min-w-0">
                  <div className="ep-label">
                    TCB Floor, Guest Policy &amp; VCEK Signature
                  </div>

                  {snp?.tcb ? (
                    <div className="grid grid-cols-3 gap-2 text-center sm:grid-cols-5">
                      {[
                        { label: "fmc", val: snp.tcb.fmc },
                        { label: "bootloader", val: snp.tcb.bootloader },
                        { label: "tee", val: snp.tcb.tee },
                        { label: "snp", val: snp.tcb.snp },
                        { label: "microcode", val: snp.tcb.microcode },
                      ].map((t) => (
                        <div
                          key={t.label}
                          className="rounded border border-rule bg-paper p-2"
                        >
                          <div className="font-mono text-[10px] uppercase text-ink-3">
                            {t.label}
                          </div>
                          <div className="mt-0.5 font-mono text-sm font-semibold text-ink">
                            {t.val}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded border border-rule bg-paper p-2 text-xs text-ink-2">
                      TCB: {displayValue(evidence.TCB, loadingBundle)}
                    </div>
                  )}

                  <div className="rounded border border-rule bg-paper p-2.5 font-mono text-xs text-ink break-words">
                    {snp
                      ? `Report v${snp.version} · Guest Policy (${snp.policyHex}): Debug=${snp.debugAllowed ? "on" : "off"} · Migration=${snp.migrationAllowed ? "on" : "off"} · SMT=${snp.smtAllowed ? "on" : "off"} · VMPL=${snp.vmpl}`
                      : `Guest Policy: ${displayValue(evidence["Guest policy"], loadingBundle)}`}
                  </div>

                  <div className="space-y-2 text-xs">
                    <div>
                      <div className="text-ink-3">
                        VCEK ECDSA P-384 Signature R
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {signatureR}
                      </div>
                    </div>
                    <div>
                      <div className="text-ink-3">
                        VCEK ECDSA P-384 Signature S
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {signatureS}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "gpu" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Tinfoil uses two-hop hardware attestation. The AMD SEV-SNP router enclave attests backend model enclaves and publishes the live routing table at{" "}
                <code className="font-mono text-ink break-all">
                  {displayValue(bundle?.proxyWellKnownUrl, loadingBundle)}
                </code>
                . For Kimi K3, the model enclave runs on Intel TDX with NVIDIA confidential-computing GPUs and a 262,144-token context limit.
              </p>

              <div className="flex flex-wrap items-center gap-2">
                <span className="ep-label mr-1">Model enclave:</span>
                {modelIds.map((id) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setSelectedModelId(id)}
                    className={
                      selectedModelId === id
                        ? "ep-btn px-2.5 py-1 font-mono text-xs"
                        : "ep-btn-ghost px-2.5 py-1 font-mono text-xs"
                    }
                  >
                    {id}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap gap-2">
                {bundle?.proxyWellKnownUrl && (
                  <a
                    href={bundle.proxyWellKnownUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open live proxy matrix (.well-known/tinfoil-proxy)
                  </a>
                )}
                {activeModelAttestation?.releaseUrl && (
                  <a
                    href={activeModelAttestation.releaseUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open release tag ({activeModelAttestation.repo}@{activeModelAttestation.tag})
                  </a>
                )}
                {modelDeploymentJsonUrl && (
                  <a
                    href={modelDeploymentJsonUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Download tinfoil-deployment.json
                  </a>
                )}
                {modelHashAssetUrl && (
                  <a
                    href={modelHashAssetUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Download tinfoil.hash
                  </a>
                )}
                {activeModelProvenance?.rekor && (
                  <a
                    href={activeModelProvenance.rekor.searchUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open Rekor entry (#{activeModelProvenance.rekor.logIndex ?? activeModelProvenance.rekor.uuid.slice(0, 12)})
                  </a>
                )}
                {activeModelAttestation?.huggingFaceUrl && (
                  <a
                    href={activeModelAttestation.huggingFaceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open pinned weights commit
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-3.5 sm:p-4 space-y-3 min-w-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-medium text-ink">{selectedModelId}</h3>
                    <span className="ep-pass">{cpuTeeLabel}</span>
                  </div>

                  <dl className="space-y-2 border-t border-rule pt-3 text-xs">
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">Deployment repo:</dt>
                      <dd className="font-mono text-ink break-all">
                        {activeModelAttestation
                          ? `${activeModelAttestation.repo} (${activeModelAttestation.tag})`
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">Host CPU TEE:</dt>
                      <dd className="font-mono text-ink">{cpuTeeLabel}</dd>
                    </div>
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">Confidential GPUs:</dt>
                      <dd className="font-mono text-ink">{gpuDescription}</dd>
                    </div>
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">VM shape:</dt>
                      <dd className="font-mono text-ink">
                        {vmShapeDescription}
                      </dd>
                    </div>
                    {selectedModelId === "kimi-k3" && (
                      <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                        <dt className="text-ink-3">Max context length:</dt>
                        <dd className="font-mono text-ink">
                          262,144 tokens (max-model-len)
                        </dd>
                      </div>
                    )}
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">Verified / configured hosts:</dt>
                      <dd className="font-mono text-ink">
                        {activeModelAttestation
                          ? `${activeModelAttestation.verifiedHosts} / ${activeModelAttestation.configuredHosts} (${activeModelAttestation.healthyHosts} healthy)`
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">CC GPU flags verified:</dt>
                      <dd className="font-mono text-ink">
                        {activeModelAttestation
                          ? activeModelAttestation.ccGpuFlagsVerified
                            ? "Yes"
                            : "No"
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                    <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                      <dt className="text-ink-3">Container image digest:</dt>
                      <dd className="ep-mono text-ink">
                        {displayValue(
                          activeModelAttestation?.containerImageDigest,
                          loadingBundle,
                        )}
                      </dd>
                    </div>
                  </dl>

                  {activeModelAttestation &&
                    activeModelAttestation.measurementRegisters.length > 0 && (
                      <div className="border-t border-rule pt-2.5 space-y-1.5 text-xs">
                        <div className="ep-label">
                          Hardware Measurement Registers ({activeModelAttestation.measurementRegisters.length})
                        </div>
                        {activeModelAttestation.measurementRegisters.map(
                          (reg, idx) => (
                            <div
                              key={idx}
                              className="rounded border border-rule bg-paper p-2 ep-mono text-[11px]"
                            >
                              RTMR[{idx}]: {reg}
                            </div>
                          ),
                        )}
                      </div>
                    )}
                </div>

                <div className="ep-inset p-3.5 sm:p-4 space-y-3 min-w-0">
                  <div className="ep-label">
                    Rootfs, Pinned Weights &amp; Enclave Hosts
                  </div>
                  <div className="space-y-2 text-xs">
                    <div className="rounded border border-rule bg-paper p-2">
                      <div className="text-ink-3">dm-verity rootfs hash</div>
                      <div className="ep-mono mt-0.5">
                        {displayValue(
                          activeModelAttestation?.dmVerityRootHash,
                          loadingBundle,
                        )}
                      </div>
                    </div>
                    <div className="rounded border border-rule bg-paper p-2">
                      <div className="text-ink-3">Kernel / initrd hashes</div>
                      <div className="ep-mono mt-0.5">
                        {activeModelAttestation
                          ? `${activeModelAttestation.kernelHash} / ${activeModelAttestation.initrdHash}`
                          : displayValue(null, loadingBundle)}
                      </div>
                    </div>
                    <div className="rounded border border-rule bg-paper p-2">
                      <div className="text-ink-3">Pinned weight package (MPK)</div>
                      <div className="ep-mono mt-0.5">
                        {displayValue(
                          activeModelAttestation?.weightMpkHash,
                          loadingBundle,
                        )}
                      </div>
                    </div>
                    <div className="rounded border border-rule bg-paper p-2">
                      <div className="text-ink-3">Weight repo &amp; commit</div>
                      <div className="ep-mono mt-0.5">
                        {displayValue(
                          activeModelAttestation?.weightRepoCommit,
                          loadingBundle,
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="border-t border-rule pt-2.5 space-y-2">
                    <div className="ep-label">Live Attested Enclave Hosts</div>
                    {!activeModelAttestation ? (
                      <div className="text-xs text-ink-2">
                        {displayValue(null, loadingBundle)}
                      </div>
                    ) : activeModelAttestation.enclaveHosts.length === 0 ? (
                      <div className="text-xs text-ink-2">Unavailable</div>
                    ) : (
                      activeModelAttestation.enclaveHosts.map((h) => (
                        <div
                          key={h.host}
                          className="rounded border border-rule bg-paper p-2 font-mono text-[11px] space-y-0.5"
                        >
                          <div className="font-semibold text-ink break-all">
                            {h.host}
                          </div>
                          <div className="text-ink-2 break-all">
                            HPKE key: {displayValue(h.hpkeKey, false)}
                          </div>
                          <div className="text-ink-3 break-all">
                            TLS key fp: {displayValue(h.tlsKeyFp, false)}
                          </div>
                          <div className="text-ink-3 break-all">
                            Predicate: {displayValue(h.predicate, false)}
                          </div>
                          {(h.codeTag || h.lastSuccess) && (
                            <div className="text-ink-3 break-all">
                              Tag: {h.codeTag ?? activeModelAttestation.tag}
                              {h.lastSuccess ? ` · Verified: ${h.lastSuccess}` : ""}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "provenance" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Hardware attestation proves which binary measurement is running in memory. Sigstore Rekor proves that binary measurement was built from public source code in GitHub Actions.
              </p>

              <div className="flex flex-wrap gap-2">
                {routerSigstoreEntryUrl && (
                  <a
                    href={routerSigstoreEntryUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open router Rekor entry (
                    {attestationRekor?.logIndex
                      ? `logIndex #${attestationRekor.logIndex}`
                      : "search.sigstore.dev"}
                    )
                  </a>
                )}
                {routerRekorApiUrl && (
                  <a
                    href={routerRekorApiUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open raw Rekor JSON (rekor.sigstore.dev)
                  </a>
                )}
                {routerReleaseUrl && (
                  <a
                    href={routerReleaseUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open router release tag ({routerTag ?? "GitHub"})
                  </a>
                )}
                {routerDeploymentJsonUrl && (
                  <a
                    href={routerDeploymentJsonUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Download router tinfoil-deployment.json
                  </a>
                )}
                {routerHashAssetUrl && (
                  <a
                    href={routerHashAssetUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Download router tinfoil.hash
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs min-w-0">
                  <div className="ep-label">Router Release Provenance</div>
                  <div>
                    <div className="text-ink-3">Source repository</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(routerRepo, loadingAny)}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Release tag</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(routerTag, loadingAny)}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">
                      Release digest (tinfoil-deployment.json SHA-256)
                    </div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(routerDigest, loadingAny)}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">
                      Sigstore Rekor transparency log entry
                    </div>
                    <div className="ep-mono mt-0.5">
                      {attestationRekor
                        ? `logIndex ${attestationRekor.logIndex} · treeSize ${attestationRekor.treeSize ?? "verified"} · root ${attestationRekor.rootHash ?? ""}`
                        : routerRekorEntry
                          ? `logIndex ${routerRekorEntry.logIndex ?? "verified"} · UUID ${routerRekorEntry.uuid}`
                          : displayValue(null, loadingAttestation)}
                    </div>
                  </div>
                </div>

                <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs min-w-0">
                  <div className="ep-label">
                    Signed DSSE Predicate Hashes (Router Image)
                  </div>
                  <div>
                    <div className="text-ink-3">Predicate version</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerHashes?.version,
                        loadingBundle,
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Root hash</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(bundle?.routerHashes?.root, loadingBundle)}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Kernel hash</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerHashes?.kernel,
                        loadingBundle,
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Initrd hash</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerHashes?.initrd,
                        loadingBundle,
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="ep-label">
                    Model Release Provenance ({selectedModelId})
                  </div>
                  {activeModelProvenance?.rekor && (
                    <div className="flex flex-wrap gap-2">
                      <a
                        href={activeModelProvenance.rekor.searchUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link text-xs"
                      >
                        Rekor logIndex #{activeModelProvenance.rekor.logIndex}
                      </a>
                      <a
                        href={activeModelProvenance.rekor.apiUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link text-xs"
                      >
                        Raw Rekor JSON
                      </a>
                    </div>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <div className="rounded border border-rule bg-paper p-2">
                    <div className="text-ink-3">Model release tag</div>
                    <div className="ep-mono mt-0.5">
                      {activeModelAttestation
                        ? `${activeModelAttestation.repo}@${activeModelAttestation.tag}`
                        : displayValue(null, loadingBundle)}
                    </div>
                  </div>
                  <div className="rounded border border-rule bg-paper p-2">
                    <div className="text-ink-3">
                      tinfoil-deployment.json SHA-256
                    </div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        activeModelProvenance?.sha256Digest,
                        loadingBundle || !activeModelProvenance,
                      )}
                    </div>
                  </div>
                  <div className="rounded border border-rule bg-paper p-2">
                    <div className="text-ink-3">Rekor entry UUID</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        activeModelProvenance?.rekor?.uuid,
                        loadingBundle || !activeModelProvenance,
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {logEntries.length > 0 && (
                <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs">
                  <div className="ep-label">
                    Local Merkle Transparency Log (Simulated Multi-Party Log · Root{" "}
                    {transparency?.log?.root.slice(0, 16)}…)
                  </div>
                  <div className="space-y-1.5">
                    {logEntries.map((entry) => (
                      <div
                        key={entry.index}
                        className="rounded border border-rule bg-paper p-2 ep-mono text-[11px]"
                      >
                        #{entry.index} {entry.imageId}@{entry.version} · measurement{" "}
                        {entry.measurement.slice(0, 24)}… ·{" "}
                        {entry.builderSignatures.length} builders,{" "}
                        {entry.reviewerSignatures.length} reviewers
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "onchain" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Nodes register on the Circle Arc testnet (chain{" "}
                {registrySnapshot?.chainId ?? 5042002}) at contract{" "}
                <code className="font-mono text-ink break-all">
                  {displayValue(contractAddr, loadingRegistry)}
                </code>
                . Note: Arc is a public testnet, and the 5-of-7 verifier quorum tickets in this demo are signed by the local transparency service.
              </p>

              <div className="flex flex-wrap gap-2">
                {arcExplorerContractUrl && (
                  <a
                    href={arcExplorerContractUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open registry contract on Arc explorer
                  </a>
                )}
                {arcExplorerOperatorUrl && (
                  <a
                    href={arcExplorerOperatorUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open operator address ({operatorAddress?.slice(0, 10)}…)
                  </a>
                )}
                {sessionTxUrl && (
                  <a
                    href={sessionTxUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open session verification tx
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs min-w-0">
                  <div className="ep-label">
                    Arc Testnet Registry (Chain{" "}
                    {registrySnapshot?.chainId ?? 5042002})
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Registry source:</span>
                    <span className="ep-mono">
                      {displayValue(registrySnapshot?.source, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Registry contract:</span>
                    <span className="ep-mono">
                      {displayValue(contractAddr, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Selected node:</span>
                    <span className="ep-mono">
                      {activeNode
                        ? `${activeNode.name} (${activeNode.kind === "sim" ? "Simulated" : "Real enclave"})`
                        : displayValue(null, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">On-chain node ID:</span>
                    <span className="ep-mono">
                      {displayValue(activeNode?.id, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Operator address:</span>
                    <span className="ep-mono">
                      {displayValue(activeNode?.operator, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 border-b border-rule pb-2 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Staked collateral:</span>
                    <span className="ep-mono">
                      {activeNode
                        ? `${activeNode.stake} USDC (testnet)`
                        : displayValue(null, loadingRegistry)}
                    </span>
                  </div>
                  <div className="flex flex-col justify-between gap-1 sm:flex-row sm:gap-2">
                    <span className="text-ink-3">Status / Region:</span>
                    <span className="ep-mono">
                      {activeNode
                        ? `${activeNode.status} (${activeNode.region})`
                        : displayValue(null, loadingRegistry)}
                    </span>
                  </div>
                </div>

                <div className="ep-inset p-3.5 sm:p-4 space-y-2.5 text-xs min-w-0">
                  <div className="ep-label">
                    Demo Verifier Quorum Ticket (Simulated Verifier Set)
                  </div>
                  {!activeTicket ? (
                    <div className="text-ink-2">
                      {displayValue(null, loadingTransparency)}
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <div className="text-ink-2">
                        Node <code className="font-mono">{activeTicket.nodeId}</code> ·{" "}
                        {activeTicket.signatures.length}/
                        {transparency?.verifierSet?.total ?? 7} signatures (threshold{" "}
                        {transparency?.verifierSet?.threshold ?? 5})
                      </div>
                      {activeTicket.signatures.map((sig) => (
                        <div
                          key={sig.verifierId}
                          className="flex items-center justify-between gap-2 rounded border border-rule bg-paper px-2.5 py-1.5 font-mono text-[11px]"
                        >
                          <span className="text-ink break-all">
                            {sig.verifierId} ({sig.signature.slice(0, 14)}...)
                          </span>
                          <span className="ep-pass shrink-0">Signed</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "privacy" && (
            <div className="space-y-4">
              <div className="ep-inset p-4">
                <div className="ep-label">What is protected</div>
                <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs text-ink-2">
                  <li>
                    <strong className="text-ink">Relay blindness:</strong> Your browser encrypts prompts with HPKE (RFC 9180) to the enclave&apos;s attested public key. The dRouter relay only forwards ciphertext.
                  </li>
                  <li>
                    <strong className="text-ink">Local PII scrubbing:</strong> Emails, phone numbers, API keys, IPv4 addresses, and hex addresses are replaced with placeholders in browser memory before encryption and restored locally when the stream returns.
                  </li>
                  <li>
                    <strong className="text-ink">Bucket padding &amp; cadence:</strong> Payloads are padded to power-of-two byte buckets and streamed on a 50 ms frame cadence.
                  </li>
                  <li>
                    <strong className="text-ink">Unlinkable blind credits:</strong> Prompts spend RSA blind-signed credits so payment issuance cannot be linked to individual prompts.
                  </li>
                </ul>
              </div>

              <div className="ep-inset p-4">
                <div className="ep-label">What this does not hide</div>
                <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs text-ink-2">
                  <li>
                    Tinfoil&apos;s safeguards classifier (gpt-oss-safeguard-120b with kimi-k3 review) sees prompts inside the enclave and reports policy violations to https://api.tinfoil.sh.
                  </li>
                  <li>
                    Tinfoil&apos;s usage reporter counts token usage inside the enclave.
                  </li>
                  <li>
                    Kimi K3 context here is 262,144 tokens (not 1M).
                  </li>
                  <li>
                    Nodes sim-1, sim-2, and sim-3 are simulated in software.
                  </li>
                  <li>
                    The Circle Arc registry (0xbc8085c2b6fe6e0db05f169925c0b841828f4481, chain 5042002) is a testnet.
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
