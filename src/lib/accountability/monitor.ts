import { gunzipSync } from "node:zlib";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { keccak256, toHex } from "viem";
import {
  ARC_EXPLORER,
  explorerAddress,
  explorerTx,
  hashEvidenceObject,
  listNodes,
  nodeIdFor,
  nodeKeyFor,
  recordVerification,
} from "@/lib/arc/registry";
import { getAuditorRunsHistory, type AuditorRunRecord } from "@/lib/auditor";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import {
  decodeSnpReportBytes,
  parseDeploymentConfigYaml,
  verifyAmdSevSnpChainEndToEnd,
  verifyModelEnclaveStatus,
  verifyTdxQuoteEndToEnd,
  type ModelEnclaveAttestation,
  type RouterSnpHardwareReport,
  type SnpChainVerificationResult,
} from "@/lib/tinfoil/deep-inspect";
import { coarsenEpochSecToHour, type SignedTreeHead } from "@/lib/transparency/log";
import {
  appendVerificationEventToLog,
  getPersistedTransparencyLog,
} from "@/lib/transparency/store";
import type { Hex, NodeRecord } from "@/lib/types";
import {
  OPEN_MODEL_CATALOG,
  TINFOIL_PROXY_WELL_KNOWN_URL,
  verifyLiveModelWeightProvenance,
} from "@/lib/weights/open-shards";
import { measureRouterRtt, type RouterRttMeasurement } from "./latency";
import {
  getMonitorRunsHistory,
  saveMonitorRun,
  type MonitorAuditorSummary,
  type MonitoredEnclaveRecord,
  type MonitorRunRecord,
  type RealEnclaveRampState,
  type RecordedMonitorFailure,
  type ReleaseChangeEvaluation,
} from "./store";

export const ATC_ATTESTATION_URL = "https://atc.tinfoil.sh/attestation";
export const ROUTER_CONFIG_REPO = "tinfoilsh/confidential-model-router";
export const MAX_ARC_FAILURE_TX_PER_RUN = 3;

const globalForArcBudget = globalThis as unknown as {
  __drouterMonitorArcTxCount?: number;
};

export function getMonitorArcTxCount(): number {
  return globalForArcBudget.__drouterMonitorArcTxCount ?? 0;
}

export function resetMonitorArcTxCountForTests(): void {
  globalForArcBudget.__drouterMonitorArcTxCount = 0;
}

interface AtcAttestationResponse {
  domain?: string;
  digest?: string;
  releaseTag?: string;
  vcek?: string;
  enclaveCert?: string;
  enclaveAttestationReport?: {
    format?: string;
    body?: string;
  };
  sigstoreBundle?: {
    dsseEnvelope?: {
      payload?: string;
    };
  };
}

interface DssePredicatePayload {
  snp_measurement?: string;
  tdx_measurement?: {
    mrtd?: string;
    rtmr0?: string;
    rtmr1?: string;
    rtmr2?: string;
  };
  vm_shape?: {
    cpus?: number;
    memory_mb?: number;
    gpus?: number;
    disks?: number;
  };
  cmdline?: string;
  hashes?: {
    version?: string;
    root?: string;
    initrd?: string;
    kernel?: string;
    raw?: string;
  };
  config?: string;
}

interface ProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  };
  enclaves?: Record<
    string,
    {
      hpke_key?: string;
      predicate?: string;
      tls_key_fp?: string;
    }
  >;
  verification?: {
    configured?: number;
    verified?: number;
    healthy?: number;
    unverified?: number;
    hosts?: Record<
      string,
      {
        last_success?: string;
        expires_at?: string;
        code_tag?: string;
      }
    >;
  };
}

interface ProxyTableResponse {
  version?: string;
  models?: Record<string, ProxyModelEntry>;
}

const kdsCertChainCache = new Map<string, string>();

export function clearKdsCertChainCacheForTests(): void {
  kdsCertChainCache.clear();
}

function decodeBase64Bytes(b64: string): Uint8Array {
  const clean = b64.replace(/[\r\n\s]/g, "");
  return new Uint8Array(Buffer.from(clean, "base64"));
}

function decodeReportBodyBytes(bodyB64: string): Uint8Array {
  const raw = decodeBase64Bytes(bodyB64);
  if (raw.length >= 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
    return new Uint8Array(gunzipSync(raw));
  }
  return raw;
}

async function fetchJsonSafe<T>(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchTextSafe(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
      cache: "no-store",
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function getAmdKdsCertChain(
  productName: "Milan" | "Genoa" | "Turin",
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<string | null> {
  const useCache = fetchImpl === fetch;
  if (useCache) {
    const cached = kdsCertChainCache.get(productName);
    if (cached) return cached;
  }
  const pem = await fetchTextSafe(
    `https://kdsintf.amd.com/vcek/v1/${productName}/cert_chain`,
    fetchImpl,
    timeoutMs,
  );
  if (pem && pem.includes("-----BEGIN CERTIFICATE-----")) {
    if (useCache) {
      kdsCertChainCache.set(productName, pem);
    }
    return pem;
  }
  return null;
}

export function resolveRegistryNodeId(nodeId: string): Hex {
  const fromArc = nodeIdFor(nodeId);
  if (fromArc) return fromArc;
  if (/^0x[0-9a-fA-F]{64}$/.test(nodeId)) return nodeId as Hex;
  return keccak256(toHex(nodeId));
}

export function filterRealRegistryNodes(nodes: NodeRecord[]): NodeRecord[] {
  return nodes.filter(
    (n) =>
      n.kind === "tinfoil" &&
      !n.endpoint.startsWith("/api/sim") &&
      !n.name.toLowerCase().includes("simulated"),
  );
}

/**
 * Evaluates whether an enclave's release tag, measurement, dm-verity root, or host identity keys
 * changed since the previous monitor run (the real "unannounced restart or upgrade" detector).
 */
export function evaluateEnclaveReleaseChange(params: {
  nodeId: string;
  currentTag: string;
  currentMeasurement: string;
  currentDmVerityRoot: string;
  currentHosts: {
    host: string;
    hpkeKey: string;
    tlsKeyFp: string;
    codeTag: string;
  }[];
  previous?: MonitoredEnclaveRecord | null;
}): ReleaseChangeEvaluation {
  const {
    nodeId,
    currentTag,
    currentMeasurement,
    currentDmVerityRoot,
    currentHosts,
    previous,
  } = params;

  const hostCodeTags: Record<string, string> = {};
  for (const h of currentHosts) {
    hostCodeTags[h.host] = h.codeTag || currentTag;
  }
  const currentHostNames = currentHosts.map((h) => h.host);
  const previousHostNames = previous ? previous.enclaveHosts.map((h) => h.host) : [];

  const skewedHosts = currentHosts.filter(
    (h) => Boolean(h.codeTag) && Boolean(currentTag) && h.codeTag !== currentTag,
  );

  if (!previous) {
    if (skewedHosts.length > 0) {
      return {
        nodeId,
        changed: true,
        unannounced: false,
        kind: "rolling-release-skew",
        previousTag: null,
        currentTag,
        previousMeasurement: null,
        currentMeasurement,
        previousHosts: [],
        currentHosts: currentHostNames,
        hostCodeTags,
        detail: `Rolling release skew across hosts on ${nodeId}: ${skewedHosts.map((h) => `${h.host}=${h.codeTag}`).join(", ")} vs target ${currentTag}`,
      };
    }
    return {
      nodeId,
      changed: false,
      unannounced: false,
      kind: "initial",
      previousTag: null,
      currentTag,
      previousMeasurement: null,
      currentMeasurement,
      previousHosts: [],
      currentHosts: currentHostNames,
      hostCodeTags,
      detail: `Initial baseline recorded for ${nodeId} at release ${currentTag || "unknown"}`,
    };
  }

  const prevTag = previous.releaseTag;
  const prevMeasurement = previous.measurement;
  const prevRoot = previous.dmVerityRootHash;

  // 1. Release tag upgrade
  if (prevTag && currentTag && prevTag !== currentTag) {
    return {
      nodeId,
      changed: true,
      unannounced: false,
      kind: "release-upgrade",
      previousTag: prevTag,
      currentTag,
      previousMeasurement: prevMeasurement,
      currentMeasurement,
      previousHosts: previousHostNames,
      currentHosts: currentHostNames,
      hostCodeTags,
      detail: `Release upgrade detected on ${nodeId}: ${prevTag} -> ${currentTag}`,
    };
  }

  // 2. Unannounced measurement or dm-verity root change without a release tag change
  const measurementChanged =
    Boolean(prevMeasurement) &&
    Boolean(currentMeasurement) &&
    prevMeasurement.toLowerCase() !== currentMeasurement.toLowerCase();
  const rootChanged =
    Boolean(prevRoot) &&
    Boolean(currentDmVerityRoot) &&
    prevRoot.toLowerCase() !== currentDmVerityRoot.toLowerCase();

  if (measurementChanged || rootChanged) {
    return {
      nodeId,
      changed: true,
      unannounced: true,
      kind: "unannounced-measurement-change",
      previousTag: prevTag,
      currentTag,
      previousMeasurement: prevMeasurement,
      currentMeasurement,
      previousHosts: previousHostNames,
      currentHosts: currentHostNames,
      hostCodeTags,
      detail: `Unannounced measurement or dm-verity root change on ${nodeId} without release tag change (${currentTag}): ${prevMeasurement.slice(0, 16)}... -> ${currentMeasurement.slice(0, 16)}...`,
    };
  }

  // 3. Unannounced host restart / ephemeral HPKE or TLS key rotation under the same release tag
  if (previous.enclaveHosts.length > 0 && currentHosts.length > 0) {
    const prevByHost = new Map(previous.enclaveHosts.map((h) => [h.host, h]));
    const rotatedHosts: string[] = [];
    for (const curr of currentHosts) {
      const prev = prevByHost.get(curr.host);
      if (!prev) {
        rotatedHosts.push(curr.host);
      } else if (
        (prev.hpkeKey && curr.hpkeKey && prev.hpkeKey !== curr.hpkeKey) ||
        (prev.tlsKeyFp && curr.tlsKeyFp && prev.tlsKeyFp !== curr.tlsKeyFp)
      ) {
        rotatedHosts.push(curr.host);
      }
    }
    if (rotatedHosts.length > 0) {
      return {
        nodeId,
        changed: true,
        unannounced: true,
        kind: "unannounced-restart",
        previousTag: prevTag,
        currentTag,
        previousMeasurement: prevMeasurement,
        currentMeasurement,
        previousHosts: previousHostNames,
        currentHosts: currentHostNames,
        hostCodeTags,
        detail: `Unannounced enclave restart or HPKE/TLS key rotation detected on ${nodeId} (${rotatedHosts.join(", ")}) at release ${currentTag}`,
      };
    }
  }

  // 4. Rolling release code_tag skew across hosts
  if (skewedHosts.length > 0) {
    return {
      nodeId,
      changed: true,
      unannounced: false,
      kind: "rolling-release-skew",
      previousTag: prevTag,
      currentTag,
      previousMeasurement: prevMeasurement,
      currentMeasurement,
      previousHosts: previousHostNames,
      currentHosts: currentHostNames,
      hostCodeTags,
      detail: `Rolling release skew across hosts on ${nodeId}: ${skewedHosts.map((h) => `${h.host}=${h.codeTag}`).join(", ")} vs target ${currentTag}`,
    };
  }

  return {
    nodeId,
    changed: false,
    unannounced: false,
    kind: "unchanged",
    previousTag: prevTag,
    currentTag,
    previousMeasurement: prevMeasurement,
    currentMeasurement,
    previousHosts: previousHostNames,
    currentHosts: currentHostNames,
    hostCodeTags,
    detail: `Release ${currentTag} and hardware measurement unchanged since previous monitor run`,
  };
}

/**
 * Computes real enclave traffic ramp states from persisted `monitor_runs` history.
 */
export function computeRealRampStatesFromHistory(
  history: MonitorRunRecord[],
): Record<string, RealEnclaveRampState> {
  const latestRun = history[0];
  if (!latestRun) return {};

  const out: Record<string, RealEnclaveRampState> = {};
  for (const enclave of latestRun.enclaves) {
    let restartsIn30d = 0;
    for (const run of history) {
      const match = run.enclaves.find((e) => e.nodeId === enclave.nodeId);
      if (
        match &&
        match.releaseChange.changed &&
        match.releaseChange.kind !== "initial"
      ) {
        restartsIn30d += 1;
      }
    }

    if (!enclave.ok) {
      out[enclave.nodeId] = {
        nodeId: enclave.nodeId,
        status: "suspended",
        restartsIn30d,
        dualIdentityDetected:
          enclave.releaseChange.kind === "unannounced-measurement-change",
        weightBps: 0,
        phase: "suspended",
        releaseTag: enclave.releaseTag,
        lastChangeKind: enclave.releaseChange.kind,
        detail:
          enclave.failureReasons.join("; ") ||
          `Enclave ${enclave.nodeId} suspended due to verification failure`,
      };
      continue;
    }

    if (enclave.releaseChange.kind === "unannounced-restart") {
      out[enclave.nodeId] = {
        nodeId: enclave.nodeId,
        status: "ramp",
        restartsIn30d: Math.max(1, restartsIn30d),
        dualIdentityDetected: false,
        weightBps: 0,
        phase: "canary-only",
        releaseTag: enclave.releaseTag,
        lastChangeKind: enclave.releaseChange.kind,
        detail: enclave.releaseChange.detail,
      };
      continue;
    }

    if (
      enclave.releaseChange.kind === "release-upgrade" ||
      enclave.releaseChange.kind === "rolling-release-skew"
    ) {
      out[enclave.nodeId] = {
        nodeId: enclave.nodeId,
        status: "ramp",
        restartsIn30d: Math.max(1, restartsIn30d),
        dualIdentityDetected: false,
        weightBps: 5000,
        phase: "linear-ramp",
        releaseTag: enclave.releaseTag,
        lastChangeKind: enclave.releaseChange.kind,
        detail: enclave.releaseChange.detail,
      };
      continue;
    }

    out[enclave.nodeId] = {
      nodeId: enclave.nodeId,
      status: "full",
      restartsIn30d,
      dualIdentityDetected: false,
      weightBps: 10000,
      phase: "steady",
      releaseTag: enclave.releaseTag,
      lastChangeKind: enclave.releaseChange.kind,
      detail: `Verified ${enclave.repo}@${enclave.releaseTag} on ${enclave.enclaveHost} (${enclave.verifiedHosts}/${enclave.configuredHosts} hosts verified)`,
    };
  }

  return out;
}

function summarizeAuditor(latestRun: AuditorRunRecord | null): MonitorAuditorSummary {
  if (!latestRun) {
    return {
      hasRun: false,
      model: null,
      verdict: null,
      passed: null,
      probesCount: null,
      passedCount: null,
      empiricalPassRate: null,
      cumulativeSprtStatistic: null,
      enclaveHost: null,
      at: null,
    };
  }
  return {
    hasRun: true,
    model: latestRun.model,
    verdict: latestRun.verdict,
    passed: latestRun.passed,
    probesCount: latestRun.probesCount,
    passedCount: latestRun.passedCount,
    empiricalPassRate: latestRun.empiricalPassRate,
    cumulativeSprtStatistic: latestRun.cumulativeSprtStatistic,
    enclaveHost: latestRun.enclaveHost,
    at: latestRun.at instanceof Date ? latestRun.at.toISOString() : String(latestRun.at),
  };
}

export interface ExecuteMonitorOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  nowSec?: number;
  modelIds?: string[];
  maxArcFailureTx?: number;
  anchorTreeHead?: boolean;
  forceAnchor?: boolean;
  /** Optional raw binary TDX or SNP quote per modelId for direct hardware quote verification in tests or live probes. */
  directQuotes?: Record<
    string,
    { format: "tdx-guest" | "sev-snp-guest"; rawQuoteBytes: Uint8Array; vcek?: string; kdsChainPem?: string }
  >;
}

export interface ExecuteMonitorResult {
  run: MonitorRunRecord;
  storedInMongo: boolean;
  signedTreeHead: SignedTreeHead;
  rampStates: Record<string, RealEnclaveRampState>;
  routerLatency: RouterRttMeasurement | null;
  arcTransactionsUsed: number;
}

/**
 * Discovers the real enclave model IDs to monitor:
 * - All models in `TINFOIL_MODELS` (`kimi-k3`, `glm-5-3`, `deepseek-v4-1-flash`, `gpt-oss-120b`, `llama3-3-70b`)
 * - Plus any additional real `tinfoil` model enclaves registered in `src/lib/arc` that appear in the live Tinfoil proxy table.
 */
function discoverModelEnclaveIds(
  proxyTable: ProxyTableResponse | null,
  registryNodes: NodeRecord[],
  explicitModelIds?: string[],
): string[] {
  if (explicitModelIds && explicitModelIds.length > 0) {
    return [...explicitModelIds];
  }
  const ordered = new Set<string>(TINFOIL_MODELS.map((m) => m.id));
  for (const node of registryNodes) {
    if (node.kind !== "tinfoil") continue;
    const explicitModelId = (node as NodeRecord & { modelId?: string }).modelId;
    const rawKey = explicitModelId ?? nodeKeyFor(node.id);
    if (!rawKey || rawKey === "tinfoil-router" || rawKey.startsWith("sim-")) {
      continue;
    }
    const candidateId = proxyTable?.models?.[rawKey]
      ? rawKey
      : rawKey.replace(/^tinfoil-/, "");
    const proxyEntry = proxyTable?.models?.[candidateId];
    if (proxyEntry && proxyEntry.tag && (proxyEntry.verification?.configured ?? 0) > 0) {
      ordered.add(candidateId);
    }
  }
  return Array.from(ordered);
}

async function verifyRouterEnclave(params: {
  atc: AtcAttestationResponse | null;
  proxyTable: ProxyTableResponse | null;
  previousRecord: MonitoredEnclaveRecord | null;
  fetchImpl: typeof fetch;
  timeoutMs: number;
  epochHourSec: number;
}): Promise<
  Omit<
    MonitoredEnclaveRecord,
    | "evidenceHash"
    | "transparencyLeafHash"
    | "transparencyLeafIndex"
    | "arcFailureTxHash"
    | "arcExplorerUrl"
  >
> {
  const { atc, proxyTable, previousRecord, fetchImpl, timeoutMs, epochHourSec } = params;
  const nodeId = "tinfoil-router";
  const repo = ROUTER_CONFIG_REPO;

  let routerSnpReport: RouterSnpHardwareReport | undefined;
  let routerSnpChain: SnpChainVerificationResult | undefined;
  let predicate: DssePredicatePayload | undefined;
  let releaseTag = atc?.releaseTag || proxyTable?.version || "";
  const releaseDigest = (atc?.digest ?? "").trim().toLowerCase();
  const enclaveHost = atc?.domain || "router-0.tinfoil.sh";

  if (atc?.sigstoreBundle?.dsseEnvelope?.payload) {
    try {
      const dsseText = Buffer.from(
        atc.sigstoreBundle.dsseEnvelope.payload,
        "base64",
      ).toString("utf8");
      const parsedDsse = JSON.parse(dsseText) as { predicate?: DssePredicatePayload };
      predicate = parsedDsse.predicate;
      if (predicate?.config) {
        const routerYaml = Buffer.from(predicate.config, "base64").toString("utf8");
        const tagMatch = routerYaml.match(
          /confidential-model-router@sha256:[0-9a-f]+\s*["']?\s*#\s*(v[0-9.]+)/i,
        );
        if (tagMatch?.[1]) {
          releaseTag = tagMatch[1];
        }
      }
      if (!releaseTag && predicate?.hashes?.version) {
        releaseTag = predicate.hashes.version;
      }
    } catch {
      // Malformed DSSE payload
    }
  }

  if (atc?.enclaveAttestationReport?.body) {
    try {
      const rawBytes = decodeReportBodyBytes(atc.enclaveAttestationReport.body);
      routerSnpReport = decodeSnpReportBytes(rawBytes);
      if (atc.vcek) {
        const kdsChainPem = await getAmdKdsCertChain(
          routerSnpReport.productName,
          fetchImpl,
          timeoutMs,
        );
        if (kdsChainPem) {
          routerSnpChain = await verifyAmdSevSnpChainEndToEnd(
            rawBytes,
            atc.vcek,
            kdsChainPem,
          );
        } else {
          routerSnpChain = {
            verified: false,
            productName: routerSnpReport.productName,
            arkSubject: "",
            askSubject: "",
            vcekSubject: "",
            arkFingerprintSha256: "",
            askFingerprintSha256: "",
            vcekFingerprintSha256: "",
            arkSelfSigned: false,
            askSignedByArk: false,
            vcekSignedByAsk: false,
            vcekTcbMatched: false,
            vcekHwidMatched: false,
            reportSignatureVerified: false,
            kdsVcekUrl: "",
            kdsCertChainUrl: "",
            error: `AMD KDS certificate chain unreachable for ${routerSnpReport.productName}`,
          };
        }
      }
    } catch (err) {
      routerSnpChain = {
        verified: false,
        productName: "Genoa",
        arkSubject: "",
        askSubject: "",
        vcekSubject: "",
        arkFingerprintSha256: "",
        askFingerprintSha256: "",
        vcekFingerprintSha256: "",
        arkSelfSigned: false,
        askSignedByArk: false,
        vcekSignedByAsk: false,
        vcekTcbMatched: false,
        vcekHwidMatched: false,
        reportSignatureVerified: false,
        kdsVcekUrl: "",
        kdsCertChainUrl: "",
        error: err instanceof Error ? err.message : "Failed to decode router SEV-SNP report",
      };
    }
  }

  const attestationChainOk = Boolean(routerSnpChain?.verified);
  const attestationDetail = attestationChainOk
    ? `AMD SEV-SNP (${routerSnpChain!.productName}) VCEK -> ASK -> ARK chain and P-384 hardware report signature verified on ${enclaveHost}`
    : (routerSnpChain?.error ??
      "Router AMD SEV-SNP attestation report or VCEK certificate chain missing/invalid");

  const expectedSnpMeasurement = (predicate?.snp_measurement ?? "").toLowerCase();
  const actualSnpMeasurement = (routerSnpReport?.measurementHex ?? "").toLowerCase();
  const dmVerityRootHash = (predicate?.hashes?.root ?? "").toLowerCase();
  const hasValidDigest = /^[0-9a-f]{64}$/.test(releaseDigest);

  const measurementMatchesRelease =
    Boolean(actualSnpMeasurement) &&
    Boolean(expectedSnpMeasurement) &&
    actualSnpMeasurement === expectedSnpMeasurement &&
    hasValidDigest &&
    Boolean(dmVerityRootHash);

  const measurementDetail = measurementMatchesRelease
    ? `Router SEV-SNP LAUNCH_DIGEST (${actualSnpMeasurement.slice(0, 16)}...) matches Sigstore release ${releaseTag || releaseDigest.slice(0, 12)} (dm-verity root ${dmVerityRootHash.slice(0, 12)}...)`
    : !actualSnpMeasurement || !expectedSnpMeasurement
      ? "Missing router SEV-SNP measurement or Sigstore DSSE release predicate"
      : `Router SEV-SNP measurement mismatch: report ${actualSnpMeasurement.slice(0, 16)}... vs release ${expectedSnpMeasurement.slice(0, 16)}...`;

  const currentHosts = [
    {
      host: enclaveHost,
      hpkeKey: routerSnpReport?.hpkeKeyFromReportDataHex ?? "",
      tlsKeyFp: routerSnpReport?.tlsKeyFpFromReportDataHex ?? "",
      codeTag: releaseTag,
    },
  ];

  const releaseChange = evaluateEnclaveReleaseChange({
    nodeId,
    currentTag: releaseTag,
    currentMeasurement: actualSnpMeasurement,
    currentDmVerityRoot: dmVerityRootHash,
    currentHosts,
    previous: previousRecord,
  });

  const failureReasons: string[] = [];
  if (!attestationChainOk) failureReasons.push(attestationDetail);
  if (!measurementMatchesRelease) failureReasons.push(measurementDetail);
  if (releaseChange.kind === "unannounced-measurement-change") {
    failureReasons.push(releaseChange.detail);
  }

  const measurementRegisters = [
    actualSnpMeasurement || expectedSnpMeasurement,
    predicate?.tdx_measurement?.rtmr1 ?? "",
    predicate?.tdx_measurement?.rtmr2 ?? "",
  ].filter((r) => Boolean(r));

  return {
    nodeId,
    nodeKind: "tinfoil",
    role: "router",
    repo,
    releaseTag,
    releaseDigest,
    measurement: actualSnpMeasurement || expectedSnpMeasurement,
    measurementRegisters,
    dmVerityRootHash,
    enclaveHost,
    enclaveHosts: currentHosts,
    configuredHosts: 1,
    verifiedHosts: attestationChainOk && measurementMatchesRelease ? 1 : 0,
    healthyHosts: attestationChainOk ? 1 : 0,
    unverifiedHosts: attestationChainOk && measurementMatchesRelease ? 0 : 1,
    attestationChainOk,
    attestationDetail,
    measurementMatchesRelease,
    measurementDetail,
    modelProvenanceOk: true,
    modelProvenanceDetail: `Stateless HPKE TLS router (${repo}@${releaseTag}); model weights are hosted in downstream GPU enclaves`,
    auditorOk: true,
    auditorDetail: "Router forwards encrypted HPKE sessions to audited model enclaves",
    releaseChange,
    ok: failureReasons.length === 0,
    failureReasons,
    epochHourSec,
  };
}

async function verifyModelEnclave(params: {
  modelId: string;
  proxyEntry: ProxyModelEntry | undefined;
  previousRecord: MonitoredEnclaveRecord | null;
  auditorHistory: AuditorRunRecord[];
  latestAuditorRun: AuditorRunRecord | null;
  directQuote?: {
    format: "tdx-guest" | "sev-snp-guest";
    rawQuoteBytes: Uint8Array;
    vcek?: string;
    kdsChainPem?: string;
  };
  fetchImpl: typeof fetch;
  timeoutMs: number;
  epochHourSec: number;
}): Promise<
  Omit<
    MonitoredEnclaveRecord,
    | "evidenceHash"
    | "transparencyLeafHash"
    | "transparencyLeafIndex"
    | "arcFailureTxHash"
    | "arcExplorerUrl"
  >
> {
  const {
    modelId,
    proxyEntry,
    previousRecord,
    auditorHistory,
    latestAuditorRun,
    directQuote,
    fetchImpl,
    timeoutMs,
    epochHourSec,
  } = params;

  const hasCatalogProvenance = Boolean(OPEN_MODEL_CATALOG[modelId]?.tinfoilRepo);

  const provenance = hasCatalogProvenance
    ? await verifyLiveModelWeightProvenance(modelId, {
        fetchImpl,
        timeoutMs,
        bypassCache: true,
      })
    : null;

  const repo =
    proxyEntry?.repo ??
    provenance?.proxyTable.repo ??
    OPEN_MODEL_CATALOG[modelId]?.tinfoilRepo ??
    `tinfoilsh/confidential-${modelId}`;
  const releaseTag =
    proxyEntry?.tag ??
    provenance?.proxyTable.tag ??
    OPEN_MODEL_CATALOG[modelId]?.tinfoilTag ??
    "";
  const measurementRegisters =
    proxyEntry?.measurement?.registers ??
    provenance?.proxyTable.measurementRegisters ??
    [];
  const primaryMeasurement = measurementRegisters[0] ?? "";
  const dmVerityRootHash = provenance?.deploymentManifest.dmVerityHashesRoot ?? "";
  const releaseDigest =
    provenance?.deploymentManifest.computedConfigSha256 ||
    dmVerityRootHash ||
    bytesToHex(sha256(utf8ToBytes(`${repo}@${releaseTag}`)));

  const currentHosts: MonitoredEnclaveRecord["enclaveHosts"] = [];
  if (proxyEntry?.enclaves) {
    for (const [host, info] of Object.entries(proxyEntry.enclaves)) {
      const vHost = proxyEntry.verification?.hosts?.[host];
      currentHosts.push({
        host,
        hpkeKey: info.hpke_key ?? "",
        tlsKeyFp: info.tls_key_fp ?? "",
        codeTag: vHost?.code_tag ?? releaseTag,
      });
    }
  }
  const primaryHost =
    currentHosts[0]?.host ?? `${modelId}.tinfoil.containers.tinfoil.dev`;

  const configuredHosts =
    proxyEntry?.verification?.configured ??
    provenance?.proxyTable.configuredHosts ??
    currentHosts.length;
  const verifiedHosts =
    proxyEntry?.verification?.verified ??
    provenance?.proxyTable.verifiedHosts ??
    0;
  const healthyHosts =
    proxyEntry?.verification?.healthy ??
    provenance?.proxyTable.healthyHosts ??
    0;
  const unverifiedHosts =
    proxyEntry?.verification?.unverified ??
    provenance?.proxyTable.unverifiedHosts ??
    0;

  // Direct quote cryptographic verification via src/lib/tinfoil/deep-inspect (from options.directQuotes or live host .well-known/tinfoil-attestation)
  let directQuoteOk = true;
  let directQuoteNote = "";
  const targetHostEntry =
    currentHosts.find((h) => h.codeTag === releaseTag) ?? currentHosts[0];

  if (directQuote) {
    if (directQuote.format === "tdx-guest") {
      const tdxRes = await verifyTdxQuoteEndToEnd(directQuote.rawQuoteBytes, {
        rtmr1Hex: provenance?.deploymentManifest.tdxRtmr1 || measurementRegisters[1],
        rtmr2Hex: provenance?.deploymentManifest.tdxRtmr2 || measurementRegisters[2],
      });
      directQuoteOk = tdxRes.verified;
      directQuoteNote = tdxRes.verified
        ? `; direct TDX v4 quote verified (${tdxRes.rootCaSubject})`
        : `; direct TDX quote failed: ${tdxRes.error ?? "invalid quote"}`;
    } else if (directQuote.format === "sev-snp-guest" && directQuote.vcek && directQuote.kdsChainPem) {
      const snpRes = await verifyAmdSevSnpChainEndToEnd(
        directQuote.rawQuoteBytes,
        directQuote.vcek,
        directQuote.kdsChainPem,
      );
      directQuoteOk = snpRes.verified;
      directQuoteNote = snpRes.verified
        ? `; direct AMD SEV-SNP (${snpRes.productName}) quote verified`
        : `; direct SEV-SNP quote failed: ${snpRes.error ?? "invalid quote"}`;
    }
  } else if (targetHostEntry?.host) {
    const liveAtt = await fetchJsonSafe<{ format?: string; body?: string }>(
      `https://${targetHostEntry.host}/.well-known/tinfoil-attestation`,
      fetchImpl,
      Math.min(timeoutMs, 2500),
    );
    if (liveAtt?.format && liveAtt?.body) {
      try {
        const rawQuoteBytes = decodeReportBodyBytes(liveAtt.body);
        if (liveAtt.format.includes("tdx-guest")) {
          const tdxRes = await verifyTdxQuoteEndToEnd(rawQuoteBytes, {
            rtmr1Hex: provenance?.deploymentManifest.tdxRtmr1 || measurementRegisters[1],
            rtmr2Hex: provenance?.deploymentManifest.tdxRtmr2 || measurementRegisters[2],
          });
          directQuoteOk = tdxRes.verified;
          directQuoteNote = tdxRes.verified
            ? `; live TDX v4 quote verified on ${targetHostEntry.host}`
            : `; live TDX quote failed on ${targetHostEntry.host}: ${tdxRes.error ?? "invalid quote"}`;
        } else if (liveAtt.format.includes("sev-snp-guest")) {
          const decodedSnp = decodeSnpReportBytes(rawQuoteBytes);
          const expectedSnp = (
            provenance?.deploymentManifest.snpMeasurement ||
            measurementRegisters[0] ||
            ""
          ).toLowerCase();
          const snpMatch =
            !expectedSnp || decodedSnp.measurementHex.toLowerCase() === expectedSnp;
          directQuoteOk = snpMatch && !decodedSnp.debugAllowed && !decodedSnp.migrationAllowed;
          directQuoteNote = directQuoteOk
            ? `; live AMD SEV-SNP (${decodedSnp.productName}) report verified on ${targetHostEntry.host}`
            : `; live AMD SEV-SNP report failed on ${targetHostEntry.host}`;
        }
      } catch (err) {
        directQuoteOk = false;
        directQuoteNote = `; live quote parse error on ${targetHostEntry.host}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
  }

  let c5Pass = provenance?.enclaveStatus.c5Pass ?? false;
  let c5Detail = provenance?.enclaveStatus.c5Detail ?? "";
  let c7Pass = provenance?.enclaveStatus.c7Pass ?? false;
  let c7Detail = provenance?.enclaveStatus.c7Detail ?? "";

  if (!provenance && proxyEntry) {
    const githubDeploymentUrl = `https://github.com/${repo}/releases/download/${encodeURIComponent(releaseTag)}/tinfoil-deployment.json`;
    const depJson = await fetchJsonSafe<{
      snp_measurement?: string;
      tdx_measurement?: { rtmr1?: string; rtmr2?: string };
      vm_shape?: { cpus?: number; memory_mb?: number; gpus?: number; disks?: number };
      hashes?: { root?: string; kernel?: string; initrd?: string };
      config?: string;
    }>(githubDeploymentUrl, fetchImpl, timeoutMs);

    const decodedYaml = depJson?.config
      ? Buffer.from(depJson.config, "base64").toString("utf8")
      : "";
    const parsedYaml = parseDeploymentConfigYaml(decodedYaml);
    const modelAtt: ModelEnclaveAttestation = {
      modelId,
      repo,
      tag: releaseTag,
      hardwarePredicate: proxyEntry.measurement?.type ?? "",
      tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)",
      configuredHosts,
      verifiedHosts,
      healthyHosts,
      unverifiedHosts,
      enclaveHosts: currentHosts.map((h) => ({
        ...h,
        predicate: proxyEntry.measurement?.type ?? "",
      })),
      measurementRegisters,
      vmShape: {
        cpus: depJson?.vm_shape?.cpus ?? 16,
        memoryMb: depJson?.vm_shape?.memory_mb ?? 65536,
        gpus: depJson?.vm_shape?.gpus ?? 1,
        disks: depJson?.vm_shape?.disks ?? 4,
      },
      dmVerityRootHash: depJson?.hashes?.root ?? "",
      kernelHash: depJson?.hashes?.kernel ?? "",
      initrdHash: depJson?.hashes?.initrd ?? "",
      containerImageDigest: parsedYaml.containerImageDigest,
      weightRepoCommit: parsedYaml.weightRepoCommit,
      weightMpkHash: parsedYaml.weightMpkHash,
      ccGpuFlagsVerified: parsedYaml.ccGpuFlagsVerified,
      releaseUrl: `https://github.com/${repo}/releases/tag/${encodeURIComponent(releaseTag)}`,
      sigstoreSearchUrl: "",
    };
    const status = verifyModelEnclaveStatus(modelAtt);
    c5Pass = status.c5Pass;
    c5Detail = status.c5Detail;
    c7Pass = status.c7Pass;
    c7Detail = status.c7Detail;
  }

  const proxyPresent = Boolean(proxyEntry?.repo && proxyEntry?.tag);
  const attestationChainOk =
    proxyPresent &&
    verifiedHosts > 0 &&
    verifiedHosts === configuredHosts &&
    unverifiedHosts === 0 &&
    healthyHosts > 0 &&
    c5Pass &&
    directQuoteOk;

  const attestationDetail = attestationChainOk
    ? `${c5Detail}${directQuoteNote}`
    : !proxyPresent
      ? `Model "${modelId}" missing from live Tinfoil router proxy table`
      : !directQuoteOk
        ? `Direct hardware quote verification failed for ${modelId}${directQuoteNote}`
        : `Enclave pool verification failed for ${modelId}: ${verifiedHosts}/${configuredHosts} verified, ${unverifiedHosts} unverified, ${healthyHosts} healthy; ${c5Detail}`;

  const measurementMatchesRelease = provenance
    ? provenance.fetchedLive.githubDeploymentManifest &&
      provenance.comparisons.measurementRegistersMatchProxy &&
      provenance.comparisons.dmVerityRootMatchesAcrossSources &&
      provenance.comparisons.configSha256MatchesCmdline
    : Boolean(proxyPresent && measurementRegisters.length > 0 && c7Pass);

  const measurementDetail = measurementMatchesRelease
    ? `Measurement registers (${measurementRegisters.length}) and dm-verity root (${dmVerityRootHash.slice(0, 12)}...) match signed release ${repo}@${releaseTag}`
    : `Measurement register or dm-verity/config hash mismatch against signed release ${repo}@${releaseTag}`;

  const modelProvenanceOk = provenance
    ? provenance.comparisons.hfRepoCommitMatchesAcrossSources &&
      (provenance.fetchedLive.huggingFaceApi
        ? provenance.comparisons.hfCommitConfirmedViaPublicApi
        : true) &&
      provenance.comparisons.weightMpkHashMatchesAcrossSources &&
      provenance.comparisons.shardMerkleRootMatchesCommitted &&
      provenance.comparisons.dmVerityRootMatchesAcrossSources &&
      c7Pass
    : c7Pass;

  const modelProvenanceDetail = provenance
    ? modelProvenanceOk
      ? `${c7Detail}; Hugging Face commit ${provenance.huggingFace.expectedCommit.slice(0, 12)}... (${provenance.huggingFace.safetensorsShardCount} shards, Merkle root ${provenance.huggingFace.computedShardMerkleRoot.slice(0, 12)}...) verified`
      : `Model weight provenance mismatch for ${modelId}: HF commit=${provenance.comparisons.hfRepoCommitMatchesAcrossSources}, HF API=${provenance.comparisons.hfCommitConfirmedViaPublicApi}, MPK=${provenance.comparisons.weightMpkHashMatchesAcrossSources}, Merkle=${provenance.comparisons.shardMerkleRootMatchesCommitted}, dmVerity=${provenance.comparisons.dmVerityRootMatchesAcrossSources}`
    : c7Detail;

  // Check real SPRT mystery-shopper auditor result for this model
  const modelAuditorRun = auditorHistory.find((r) => r.model === modelId) ?? null;
  let auditorOk = true;
  let auditorDetail = "No SPRT mystery-shopper downgrade detected";

  if (modelAuditorRun) {
    auditorOk =
      modelAuditorRun.passed &&
      modelAuditorRun.verdict !== "SLASH_MODEL_DOWNGRADE_DETECTED";
    auditorDetail = `SPRT mystery-shopper audit on ${modelId}: ${modelAuditorRun.verdict} (${modelAuditorRun.passedCount}/${modelAuditorRun.probesCount} canary probes passed, LLR=${modelAuditorRun.cumulativeSprtStatistic.toFixed(3)})`;
  } else if (latestAuditorRun) {
    auditorDetail = `Latest SPRT audit ran on ${latestAuditorRun.model}: ${latestAuditorRun.verdict} (${latestAuditorRun.passedCount}/${latestAuditorRun.probesCount} probes passed)`;
  }

  const releaseChange = evaluateEnclaveReleaseChange({
    nodeId: modelId,
    currentTag: releaseTag,
    currentMeasurement: primaryMeasurement,
    currentDmVerityRoot: dmVerityRootHash,
    currentHosts,
    previous: previousRecord,
  });

  const failureReasons: string[] = [];
  if (!attestationChainOk) failureReasons.push(attestationDetail);
  if (!measurementMatchesRelease) failureReasons.push(measurementDetail);
  if (!modelProvenanceOk) failureReasons.push(modelProvenanceDetail);
  if (!auditorOk) failureReasons.push(auditorDetail);
  if (releaseChange.kind === "unannounced-measurement-change") {
    failureReasons.push(releaseChange.detail);
  }

  return {
    nodeId: modelId,
    nodeKind: "tinfoil",
    role: "model",
    repo,
    releaseTag,
    releaseDigest,
    measurement: primaryMeasurement,
    measurementRegisters,
    dmVerityRootHash,
    enclaveHost: primaryHost,
    enclaveHosts: currentHosts,
    configuredHosts,
    verifiedHosts,
    healthyHosts,
    unverifiedHosts,
    attestationChainOk,
    attestationDetail,
    measurementMatchesRelease,
    measurementDetail,
    modelProvenanceOk,
    modelProvenanceDetail,
    auditorOk,
    auditorDetail,
    releaseChange,
    ok: failureReasons.length === 0,
    failureReasons,
    epochHourSec,
  };
}

/**
 * Executes a full continuous monitoring run across all real Tinfoil enclaves:
 * 1. Verifies router + model enclave attestation chains (`src/lib/tinfoil`)
 * 2. Verifies hardware measurements vs signed releases (`src/lib/tinfoil`)
 * 3. Detects release changes / host key rotations since the last run ("unannounced restart or upgrade" detector)
 * 4. Verifies model weight provenance (`src/lib/weights`)
 * 5. Incorporates the latest real mystery-shopper auditor result (`src/lib/auditor`)
 * 6. Appends each enclave verification event to the transparency log (`src/lib/transparency`), anchoring at most hourly
 * 7. Records any verification failures on Circle Arc with evidence hashes (`src/lib/arc/registry`, capped at <= 3 tx)
 * 8. Stores aggregate results (no PII, coarse UTC hour) in MongoDB `monitor_runs`
 */
export async function executeContinuousMonitorRun(
  options?: ExecuteMonitorOptions,
): Promise<ExecuteMonitorResult> {
  const baseFetch = options?.fetchImpl ?? fetch;
  const timeoutMs = options?.timeoutMs ?? 6000;
  const nowSec = options?.nowSec ?? Math.floor(Date.now() / 1000);
  const epochHourSec = coarsenEpochSecToHour(nowSec);
  const maxArcFailureTx = Math.min(
    MAX_ARC_FAILURE_TX_PER_RUN,
    options?.maxArcFailureTx ?? MAX_ARC_FAILURE_TX_PER_RUN,
  );

  // Deduplicate proxy well-known fetches within a single monitor run
  let proxyWellKnownPromise: Promise<Response> | null = null;
  const runScopedFetch: typeof fetch = async (input, init) => {
    const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (
      urlStr === TINFOIL_PROXY_WELL_KNOWN_URL &&
      (!init?.method || init.method.toUpperCase() === "GET")
    ) {
      if (!proxyWellKnownPromise) {
        proxyWellKnownPromise = baseFetch(input, init);
      }
      const res = await proxyWellKnownPromise;
      return res.clone();
    }
    return baseFetch(input, init);
  };

  const [priorHistory, auditorState, registryState, atc, proxyTable, routerLatency] =
    await Promise.all([
      getMonitorRunsHistory(30),
      getAuditorRunsHistory(10),
      listNodes(),
      fetchJsonSafe<AtcAttestationResponse>(ATC_ATTESTATION_URL, runScopedFetch, timeoutMs),
      fetchJsonSafe<ProxyTableResponse>(TINFOIL_PROXY_WELL_KNOWN_URL, runScopedFetch, timeoutMs),
      measureRouterRtt("inference.tinfoil.sh", baseFetch),
    ]);

  const previousRun = priorHistory.latestRun;
  const previousByNode = new Map<string, MonitoredEnclaveRecord>(
    (previousRun?.enclaves ?? []).map((e) => [e.nodeId, e]),
  );

  const realRegistryNodes = filterRealRegistryNodes(registryState.nodes);
  const modelIds = discoverModelEnclaveIds(
    proxyTable,
    realRegistryNodes,
    options?.modelIds,
  );

  // Verify router enclave + all real model enclaves concurrently
  const [routerPartial, ...modelPartials] = await Promise.all([
    verifyRouterEnclave({
      atc,
      proxyTable,
      previousRecord: previousByNode.get("tinfoil-router") ?? null,
      fetchImpl: runScopedFetch,
      timeoutMs,
      epochHourSec,
    }),
    ...modelIds.map((modelId) =>
      verifyModelEnclave({
        modelId,
        proxyEntry: proxyTable?.models?.[modelId],
        previousRecord: previousByNode.get(modelId) ?? null,
        auditorHistory: auditorState.history,
        latestAuditorRun: auditorState.latestRun,
        directQuote: options?.directQuotes?.[modelId],
        fetchImpl: runScopedFetch,
        timeoutMs,
        epochHourSec,
      }),
    ),
  ]);

  const partials = [routerPartial, ...modelPartials];
  const enclaves: MonitoredEnclaveRecord[] = [];
  const failures: RecordedMonitorFailure[] = [];
  let arcTransactionsUsed = 0;
  let latestSth: SignedTreeHead | null = null;

  for (let i = 0; i < partials.length; i++) {
    const p = partials[i];
    const isLast = i === partials.length - 1;
    const evidencePayload = {
      domain: "drouter/monitor/v1",
      nodeId: p.nodeId,
      role: p.role,
      repo: p.repo,
      releaseTag: p.releaseTag,
      releaseDigest: p.releaseDigest,
      measurement: p.measurement,
      dmVerityRootHash: p.dmVerityRootHash,
      enclaveHost: p.enclaveHost,
      attestationChainOk: p.attestationChainOk,
      measurementMatchesRelease: p.measurementMatchesRelease,
      modelProvenanceOk: p.modelProvenanceOk,
      auditorOk: p.auditorOk,
      releaseChangeKind: p.releaseChange.kind,
      ok: p.ok,
      failureReasons: p.failureReasons,
      epochHourSec,
    };
    const evidenceHash = hashEvidenceObject(evidencePayload);

    let arcFailureTxHash: Hex | null = null;
    let arcExplorerUrl: string | null = null;

    if (!p.ok) {
      const totalUsedSoFar = getMonitorArcTxCount();
      if (
        arcTransactionsUsed < maxArcFailureTx &&
        totalUsedSoFar < MAX_ARC_FAILURE_TX_PER_RUN &&
        process.env.DROUTER_STUB_UPSTREAM !== "1"
      ) {
        const registryNodeId = resolveRegistryNodeId(p.nodeId);
        arcFailureTxHash = await recordVerification(
          registryNodeId,
          false,
          evidenceHash,
        );
        if (arcFailureTxHash) {
          arcTransactionsUsed += 1;
          globalForArcBudget.__drouterMonitorArcTxCount = totalUsedSoFar + 1;
          arcExplorerUrl = explorerTx(arcFailureTxHash);
        }
      }

      failures.push({
        id: `failure-${epochHourSec}-${p.nodeId}`,
        nodeId: p.nodeId,
        epochHourSec,
        reasons: p.failureReasons,
        measurement: p.measurement,
        releaseTag: p.releaseTag,
        evidenceHash,
        txHash: arcFailureTxHash,
        explorerUrl: arcExplorerUrl,
        onChain: Boolean(arcFailureTxHash),
      });
    }

    const shouldAnchorTreeHead =
      isLast &&
      options?.anchorTreeHead !== false &&
      getMonitorArcTxCount() < MAX_ARC_FAILURE_TX_PER_RUN;

    const appended = await appendVerificationEventToLog({
      kind: "verification_event",
      nodeId: p.nodeId,
      nodeKind: "tinfoil",
      ok: p.ok,
      measurement: p.measurement || p.releaseDigest || p.nodeId,
      evidenceHash,
      releaseDigest: p.releaseDigest || undefined,
      enclaveHost: p.enclaveHost || undefined,
      timestampSec: nowSec,
      anchorOnArc: shouldAnchorTreeHead,
      forceAnchor: isLast ? options?.forceAnchor : false,
    });

    latestSth = appended.signedTreeHead;

    enclaves.push({
      ...p,
      evidenceHash,
      transparencyLeafHash: appended.event.leafHash,
      transparencyLeafIndex: appended.event.index,
      arcFailureTxHash,
      arcExplorerUrl,
    });
  }

  if (!latestSth) {
    const persisted = await getPersistedTransparencyLog({ nowSec });
    latestSth = persisted.signedTreeHead;
  }

  const releaseChanges = enclaves.map((e) => e.releaseChange);
  const passedEnclaves = enclaves.filter((e) => e.ok).length;
  const failedEnclaves = enclaves.length - passedEnclaves;
  const releaseChangesCount = releaseChanges.filter((c) => c.changed).length;

  const runDigest = bytesToHex(
    sha256(
      utf8ToBytes(
        `${epochHourSec}|${latestSth.rootHash}|${enclaves.map((e) => `${e.nodeId}:${e.evidenceHash}`).join(",")}`,
      ),
    ),
  ).slice(0, 12);

  const runRecord: MonitorRunRecord = {
    runId: `monitor-${epochHourSec}-${runDigest}`,
    epochHourSec,
    at: new Date(epochHourSec * 1000),
    ok: failedEnclaves === 0,
    routerHost: routerPartial.enclaveHost,
    routerReleaseTag: routerPartial.releaseTag,
    routerReleaseDigest: routerPartial.releaseDigest,
    routerRttMs: routerLatency?.bestRttMs ?? null,
    totalEnclaves: enclaves.length,
    passedEnclaves,
    failedEnclaves,
    releaseChangesCount,
    enclaves,
    releaseChanges,
    failures,
    auditor: summarizeAuditor(auditorState.latestRun),
    transparencyRoot: latestSth.rootHash,
    transparencyTreeSize: latestSth.treeSize,
    anchorTx: latestSth.anchorTx ?? null,
    anchoredAtSec: latestSth.anchoredAtSec ?? null,
  };

  const saved = await saveMonitorRun(runRecord);
  const fullHistory = [saved.sanitized, ...priorHistory.history];
  const rampStates = computeRealRampStatesFromHistory(fullHistory);

  return {
    run: saved.sanitized,
    storedInMongo: saved.storedInMongo,
    signedTreeHead: latestSth,
    rampStates,
    routerLatency,
    arcTransactionsUsed,
  };
}

export { ARC_EXPLORER, explorerAddress, explorerTx };
