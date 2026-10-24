"use client";

import React, { useEffect, useState } from "react";
import type { CheckResult, NodeRecord, QuorumTicket } from "@/lib/types";
import type {
  DeepAttestationBundle,
  ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";

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

interface TransparencySnapshot {
  verifierSet?: {
    threshold: number;
    total: number;
    verifiers?: Array<{ id: string; publicKeyHex: string }>;
  };
  tickets?: Record<string, QuorumTicket>;
}

function isDeepAttestationBundle(val: unknown): val is DeepAttestationBundle {
  return Boolean(
    val &&
      typeof val === "object" &&
      "routerHost" in (val as Record<string, unknown>) &&
      "models" in (val as Record<string, unknown>),
  );
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
  const [transparency, setTransparency] =
    useState<TransparencySnapshot | null>(null);
  const [loadingTransparency, setLoadingTransparency] =
    useState<boolean>(false);

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
  }, [open, deepBundle, fetchedBundle, transparency]);

  if (!open) return null;

  const bundle: DeepAttestationBundle | null = isDeepAttestationBundle(
    deepBundle,
  )
    ? deepBundle
    : fetchedBundle;

  const snp = bundle?.routerSnpReport;
  const isSim = node?.kind === "sim";

  const chipId = isSim
    ? displayValue(evidence["Chip ID"] ?? evidence.chipId, false)
    : displayValue(
        snp?.chipIdHex ?? evidence["Chip ID"] ?? evidence.chipId,
        loadingBundle,
      );

  const measurement = isSim
    ? displayValue(evidence.Measurement ?? node?.measurement, false)
    : displayValue(
        snp?.measurementHex ??
          evidence["Enclave fingerprint"] ??
          evidence.Measurement,
        loadingBundle,
      );

  const reportData = isSim
    ? displayValue(evidence["Report data"], false)
    : displayValue(snp?.reportDataHex, loadingBundle);

  const signatureR = displayValue(snp?.signatureRHex, loadingBundle);
  const signatureS = displayValue(snp?.signatureSHex, loadingBundle);

  const modelIds = bundle?.models
    ? Object.keys(bundle.models)
    : TINFOIL_MODELS.map((m) => m.id);

  const activeModelAttestation: ModelEnclaveAttestation | undefined =
    bundle?.models?.[selectedModelId];

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

  const contractAddr =
    registryAddress || "0xbc8085c2b6fe6e0db05f169925c0b841828f4481";
  const arcExplorerContractUrl = `https://testnet.arcscan.app/address/${contractAddr}`;

  const nodeTicketKey =
    node?.kind === "tinfoil"
      ? "tinfoil-router"
      : node?.endpoint.split("/").filter(Boolean).pop() || "tinfoil-router";
  const activeTicket = transparency?.tickets?.[nodeTicketKey];

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
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-5 py-4">
          <div>
            <div className="ep-label">Attestation &amp; Provenance</div>
            <h2
              id="record-inspector-title"
              className="ep-display mt-0.5 text-xl sm:text-2xl"
            >
              Raw Hardware &amp; Cryptographic Records
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="ep-btn-ghost px-3 py-1 text-xs"
          >
            Close
          </button>
        </div>

        <div className="flex gap-1 overflow-x-auto border-b border-rule bg-paper px-4 pt-2">
          {tabs.map((t) => {
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={`whitespace-nowrap border-b-2 px-3 py-2 text-xs font-medium transition-colors ${
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

        <div className="flex-1 space-y-5 overflow-y-auto p-5 text-sm">
          {activeTab === "overview" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Before your browser sends a prompt, it runs 7 checks (C1 to C7) against the enclave hardware report, the Sigstore transparency log, the model enclave table, and the Circle Arc testnet registry.
              </p>

              {checks.length === 0 ? (
                <div className="ep-inset p-4 text-xs text-ink-2">
                  {loadingBundle
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
                        <div className="space-y-1">
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
                          className="ep-btn-ghost shrink-0 px-2.5 py-1 text-xs"
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
                The Tinfoil router enclave ({bundle?.routerHost ?? "router-0.tinfoil.sh"}) attests with AMD SEV-SNP. The AMD Secure Processor signs a 1,184-byte binary report committing to the boot measurement, guest policy flags, and the enclave&apos;s ephemeral key.
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
                <a
                  href={
                    bundle?.amdKdsUrl ??
                    "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open AMD KDS VCEK authority (kdsintf.amd.com)
                </a>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-4 space-y-3">
                  <div className="ep-label">
                    AMD SEV-SNP Binary Registers (1,184 Bytes)
                  </div>
                  <div className="space-y-2.5 text-xs">
                    <div>
                      <div className="text-ink-3">CHIP_ID (64 bytes)</div>
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
                        REPORT_DATA (64 bytes binding session key)
                      </div>
                      <div className="mt-1 rounded border border-rule bg-paper p-2 ep-mono">
                        {reportData}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="ep-inset p-4 space-y-3">
                  <div className="ep-label">
                    TCB Floor, Guest Policy &amp; VCEK Signature
                  </div>

                  {snp?.tcb ? (
                    <div className="grid grid-cols-5 gap-2 text-center">
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

                  <div className="rounded border border-rule bg-paper p-2.5 font-mono text-xs text-ink">
                    {snp
                      ? `Guest Policy (${snp.policyHex}): Debug=${snp.debugAllowed ? "on" : "off"} · Migration=${snp.migrationAllowed ? "on" : "off"} · SMT=${snp.smtAllowed ? "on" : "off"} · VMPL=${snp.vmpl}`
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
                <code className="font-mono text-ink">
                  https://inference.tinfoil.sh/.well-known/tinfoil-proxy
                </code>
                . For Kimi K3, the model enclave (
                <code className="font-mono text-ink">
                  kimi-k3-inf14.tinfoil.containers.tinfoil.dev
                </code>
                ) runs on Intel TDX with NVIDIA confidential-computing GPUs and a 262,144-token context limit.
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
                <a
                  href={
                    bundle?.proxyWellKnownUrl ??
                    "https://inference.tinfoil.sh/.well-known/tinfoil-proxy"
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open live proxy matrix (.well-known/tinfoil-proxy)
                </a>
                {activeModelAttestation?.releaseUrl && (
                  <a
                    href={activeModelAttestation.releaseUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open signed deployment release ({activeModelAttestation.repo}@{activeModelAttestation.tag})
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
                <div className="ep-inset p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-medium text-ink">{selectedModelId}</h3>
                    <span className="ep-pass">{cpuTeeLabel}</span>
                  </div>

                  <dl className="space-y-2 border-t border-rule pt-3 text-xs">
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">Deployment repo:</dt>
                      <dd className="font-mono text-ink">
                        {activeModelAttestation
                          ? `${activeModelAttestation.repo} (${activeModelAttestation.tag})`
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">Host CPU TEE:</dt>
                      <dd className="font-mono text-ink">{cpuTeeLabel}</dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">Confidential GPUs:</dt>
                      <dd className="font-mono text-ink">{gpuDescription}</dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">VM shape:</dt>
                      <dd className="font-mono text-ink">
                        {vmShapeDescription}
                      </dd>
                    </div>
                    {selectedModelId === "kimi-k3" && (
                      <div className="flex justify-between gap-2">
                        <dt className="text-ink-3">Max context length:</dt>
                        <dd className="font-mono text-ink">
                          262,144 tokens (max-model-len)
                        </dd>
                      </div>
                    )}
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">Verified / configured hosts:</dt>
                      <dd className="font-mono text-ink">
                        {activeModelAttestation
                          ? `${activeModelAttestation.verifiedHosts} / ${activeModelAttestation.configuredHosts} (${activeModelAttestation.healthyHosts} healthy)`
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-3">CC GPU flags verified:</dt>
                      <dd className="font-mono text-ink">
                        {activeModelAttestation
                          ? activeModelAttestation.ccGpuFlagsVerified
                            ? "Yes"
                            : "No"
                          : displayValue(null, loadingBundle)}
                      </dd>
                    </div>
                  </dl>
                </div>

                <div className="ep-inset p-4 space-y-3">
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
                          <div className="font-semibold text-ink">{h.host}</div>
                          <div className="text-ink-2 break-all">
                            HPKE key: {displayValue(h.hpkeKey, false)}
                          </div>
                          <div className="text-ink-3 break-all">
                            TLS key fp: {displayValue(h.tlsKeyFp, false)}
                          </div>
                          <div className="text-ink-3 break-all">
                            Predicate: {displayValue(h.predicate, false)}
                          </div>
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
                <a
                  href={
                    bundle?.routerSigstoreUrl ?? "https://search.sigstore.dev"
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open Sigstore Rekor log (search.sigstore.dev)
                </a>
                <a
                  href={
                    bundle?.routerReleaseUrl ??
                    "https://github.com/tinfoilsh/confidential-model-router/releases"
                  }
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open router release on GitHub
                </a>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-4 space-y-2.5 text-xs">
                  <div className="ep-label">Router Release Provenance</div>
                  <div>
                    <div className="text-ink-3">Source repository</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerConfigRepo ?? evidence["Source repo"],
                        loadingBundle,
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Release tag</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerReleaseTag ?? evidence.Release,
                        loadingBundle,
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-ink-3">Release digest</div>
                    <div className="ep-mono mt-0.5">
                      {displayValue(
                        bundle?.routerReleaseDigest,
                        loadingBundle,
                      )}
                    </div>
                  </div>
                </div>

                <div className="ep-inset p-4 space-y-2.5 text-xs">
                  <div className="ep-label">
                    Signed DSSE Predicate Hashes (Router Image)
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
            </div>
          )}

          {activeTab === "onchain" && (
            <div className="space-y-4">
              <p className="max-w-[70ch] text-sm text-ink-2">
                Nodes register on the Circle Arc testnet (chain 5042002) at contract{" "}
                <code className="font-mono text-ink">{contractAddr}</code>. Note: Arc is a public testnet, and the 5-of-7 verifier quorum tickets in this demo are signed by the local transparency service.
              </p>

              <div className="flex flex-wrap gap-2">
                <a
                  href={arcExplorerContractUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="ep-btn-ghost px-3 py-1.5 text-xs"
                >
                  Open contract on Arc testnet explorer
                </a>
                {verifyAnchorUrl && (
                  <a
                    href={verifyAnchorUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open session verification tx
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="ep-inset p-4 space-y-2.5 text-xs">
                  <div className="ep-label">Arc Testnet Registry (Chain 5042002)</div>
                  <div className="flex justify-between gap-2 border-b border-rule pb-2">
                    <span className="text-ink-3">Registry contract:</span>
                    <span className="ep-mono">{contractAddr}</span>
                  </div>
                  <div className="flex justify-between gap-2 border-b border-rule pb-2">
                    <span className="text-ink-3">Selected node:</span>
                    <span className="ep-mono">
                      {node ? `${node.name} (${node.kind === "sim" ? "Simulated" : "Real enclave"})` : "Unavailable"}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2 border-b border-rule pb-2">
                    <span className="text-ink-3">Staked collateral:</span>
                    <span className="ep-mono">
                      {node ? `${node.stake} USDC (testnet)` : "Unavailable"}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-ink-3">Status:</span>
                    <span className="ep-mono">
                      {node ? node.status : "Unavailable"}
                    </span>
                  </div>
                </div>

                <div className="ep-inset p-4 space-y-2.5 text-xs">
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
                          className="flex items-center justify-between rounded border border-rule bg-paper px-2.5 py-1.5 font-mono text-[11px]"
                        >
                          <span className="text-ink">
                            {sig.verifierId} ({sig.signature.slice(0, 14)}...)
                          </span>
                          <span className="ep-pass">Signed</span>
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
