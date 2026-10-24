import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { TinfoilAI } from "tinfoil";
import type { CheckResult, NodeRecord, PopReceipt, QuorumTicket } from "@/lib/types";
import { padJsonPayloadToBucket } from "@/lib/relay";
import { toHex } from "@/lib/sim/bytes";
import {
  checksFromDocument,
  openTinfoilSession,
  type TinfoilEvidence,
  type TinfoilSession,
} from "@/lib/tinfoil/client";
import {
  verifyModelEnclaveStatus,
  type DeepAttestationBundle,
  type ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import { openSimSession } from "@/lib/sim/client";
import type { MessagePrivacyReport } from "@/components/console/send-pipeline";

export interface RegistryResponse {
  source: "arc" | "fallback";
  onChain?: boolean;
  address?: string;
  minStake?: string;
  error?: string;
  nodes: NodeRecord[];
  chainId: number;
  explorer: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  wireContent?: string;
  privacyReport?: MessagePrivacyReport;
}

export interface SendOptions {
  creditHeader?: string | null;
}

/** A verified session with one node, regardless of whether the node is real or simulated. */
export interface ActiveSession {
  node: NodeRecord;
  checks: CheckResult[];
  evidence: Record<string, string>;
  evidenceHash: string;
  deepBundle?: DeepAttestationBundle;
  send(
    history: ChatMessage[],
    model: string,
    opts?: SendOptions,
  ): AsyncIterable<string>;
  close?: () => Promise<PopReceipt>;
}

/** Weighted random choice by stake, using this browser's own randomness (operators can't steer it). */
export function pickNode(
  nodes: NodeRecord[],
  kind: NodeRecord["kind"],
): NodeRecord | null {
  const eligible = nodes.filter((n) => n.kind === kind && n.status === "active");
  if (eligible.length === 0) return null;
  const weights = eligible.map((n) => Math.max(Number(n.stake) || 0, 0.0001));
  const total = weights.reduce((a, b) => a + b, 0);
  const r = (crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * total;
  let acc = 0;
  for (let i = 0; i < eligible.length; i++) {
    acc += weights[i];
    if (r < acc) return eligible[i];
  }
  return eligible[eligible.length - 1];
}

export function hashHex(value: unknown): `0x${string}` {
  return `0x${bytesToHex(sha256(utf8ToBytes(JSON.stringify(value))))}`;
}

export function simIdFor(node: NodeRecord): string {
  if (node.kind === "tinfoil") return "tinfoil-router";
  return node.endpoint.split("/").filter(Boolean).pop() ?? "";
}

/** C6: checks both the on-chain Arc registry stake AND the verifier quorum ticket. */
export async function registryAndQuorumCheck(
  node: NodeRecord,
  registry: RegistryResponse,
): Promise<CheckResult> {
  const key = simIdFor(node);
  let quorumDetail = "";
  let quorumOk = false;
  let quorumLoaded = false;

  try {
    const res = await fetch("/api/transparency");
    if (res.ok) {
      const data = (await res.json()) as {
        verifierSet?: { threshold?: number; total?: number };
        tickets?: Record<string, QuorumTicket>;
      };
      const ticket = data.tickets?.[key];
      const threshold = data.verifierSet?.threshold;
      const total = data.verifierSet?.total;
      if (
        ticket &&
        typeof threshold === "number" &&
        typeof total === "number"
      ) {
        quorumLoaded = true;
        const sigs = Array.isArray(ticket.signatures)
          ? ticket.signatures.length
          : 0;
        quorumOk =
          sigs >= threshold &&
          ticket.status !== "suspended" &&
          ticket.weight > 0;
        quorumDetail = ` · simulated quorum: ${sigs}/${total} verifier signatures (threshold ${threshold}, all keys held by demo server, status ${ticket.status}, weight ${(ticket.weight / 100).toFixed(0)}%)`;
      } else {
        quorumDetail =
          " · quorum ticket unavailable (/api/transparency did not return verifierSet or ticket for this node)";
      }
    } else {
      quorumDetail = ` · quorum unavailable (/api/transparency returned HTTP ${res.status})`;
    }
  } catch {
    quorumDetail = " · quorum unavailable (/api/transparency unreachable)";
  }

  if (registry.source !== "arc") {
    const fallbackReason =
      registry.error || "On-chain Arc registry unreachable; using local fallback node list";
    return {
      id: "C6",
      label: "Registry admission",
      status: quorumLoaded && !quorumOk ? "fail" : "skip",
      detail: `Unavailable on-chain (${fallbackReason})${quorumDetail}`,
    };
  }

  const requiredStake =
    registry.minStake !== undefined && Number.isFinite(Number(registry.minStake))
      ? Number(registry.minStake)
      : 0.01;
  const arcOk = node.status === "active" && Number(node.stake) >= requiredStake;
  const ok = arcOk && (!quorumLoaded || quorumOk);
  return {
    id: "C6",
    label: "Registry admission",
    status: ok ? "pass" : "fail",
    detail: ok
      ? `Arc staked (${node.stake} USDC by ${node.operator.slice(0, 10)}...)${quorumDetail}`
      : `Node status ${node.status}, stake ${node.stake} USDC (minimum ${requiredStake} USDC)${quorumDetail}`,
  };
}

const VIRTUAL_HTTPS_RELAY = "https://local-relay.drouter.internal/api/relay";
let fetchInterceptorInstalled = false;
let localRelayOrigin = "";
let pendingCreditHeader: string | null = null;

function isInferenceTurnRequest(urlStr: string, method?: string): boolean {
  const upper = (method ?? "GET").toUpperCase();
  if (upper !== "POST") return false;
  return (
    urlStr.includes("/api/relay/") && urlStr.includes("/v1/")
  ) || (
    urlStr.includes("/api/sim/") && urlStr.endsWith("/turn")
  );
}

function ensureFetchInterceptorInstalled(origin: string): void {
  localRelayOrigin = origin;
  if (fetchInterceptorInstalled || typeof window === "undefined") return;
  fetchInterceptorInstalled = true;
  const origFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;

    const method =
      init?.method ?? (input instanceof Request ? input.method : "GET");

    let nextInput: RequestInfo | URL = input;
    let nextInit: RequestInit | undefined = init;

    if (localRelayOrigin && urlStr.startsWith(VIRTUAL_HTTPS_RELAY)) {
      const rewritten = urlStr.replace(
        VIRTUAL_HTTPS_RELAY,
        `${localRelayOrigin}/api/relay`,
      );
      nextInput = rewritten;
    }

    if (pendingCreditHeader && isInferenceTurnRequest(urlStr, method)) {
      const creditToAttach = pendingCreditHeader;
      pendingCreditHeader = null;
      const baseHeaders =
        nextInit?.headers ??
        (input instanceof Request ? input.headers : undefined);
      const mergedHeaders = new Headers(baseHeaders);
      if (!mergedHeaders.has("x-drouter-credit")) {
        mergedHeaders.set("x-drouter-credit", creditToAttach);
      }
      nextInit = { ...(nextInit ?? {}), headers: mergedHeaders };
    }

    return origFetch(nextInput, nextInit);
  };
}

/**
 * Fallback for plain HTTP localhost dev servers where the Tinfoil SDK rejects
 * non-HTTPS attestationBundleURL values. Routes attestation via local relay.
 */
async function openLocalHttpTinfoilSession(
  selectedModel = "kimi-k3",
): Promise<TinfoilSession> {
  const origin = window.location.origin;
  ensureFetchInterceptorInstalled(origin);

  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const userCacheSecret = toHex(secretBytes);

  const baseURL = `${origin}/api/relay/v1/`;

  const client = new TinfoilAI({
    bearerToken: "drouter-demo",
    baseURL,
    attestationBundleURL: VIRTUAL_HTTPS_RELAY,
    userCacheSecret,
  });

  const matrixPromise: Promise<DeepAttestationBundle | undefined> = fetch(
    `${origin}/api/relay/enclave-matrix`,
  )
    .then(async (res) =>
      res.ok ? ((await res.json()) as DeepAttestationBundle) : undefined,
    )
    .catch(() => undefined);

  const [, deepBundle] = await Promise.all([client.ready(), matrixPromise]);
  const doc = await client.getVerificationDocument();
  const selectedModelAttestation: ModelEnclaveAttestation | undefined =
    deepBundle?.models?.[selectedModel];

  const internalTransport = (
    client as unknown as {
      secureClient?: {
        _transport?: {
          fetch: (
            input: RequestInfo | URL,
            init?: RequestInit,
          ) => Promise<Response>;
        };
      };
    }
  ).secureClient?._transport;

  if (internalTransport && typeof internalTransport.fetch === "function") {
    const origTransportFetch = internalTransport.fetch.bind(internalTransport);
    internalTransport.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      let nextInit = init;
      if (pendingCreditHeader) {
        const creditToAttach = pendingCreditHeader;
        pendingCreditHeader = null;
        const mergedHeaders = new Headers(nextInit?.headers);
        if (!mergedHeaders.has("x-drouter-credit")) {
          mergedHeaders.set("x-drouter-credit", creditToAttach);
        }
        nextInit = { ...(nextInit ?? {}), headers: mergedHeaders };
      }
      if (nextInit && typeof nextInit.body === "string") {
        try {
          const parsed = JSON.parse(nextInit.body) as Record<string, unknown>;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            if (!parsed.user_cache_secret) {
              parsed.user_cache_secret = userCacheSecret;
            }
            const { paddedJson } = padJsonPayloadToBucket(
              JSON.stringify(parsed),
            );
            nextInit = { ...nextInit, body: paddedJson };
          }
        } catch {
          // Leave non-JSON body unchanged
        }
      }
      return origTransportFetch(input, nextInit);
    };
  }

  const snp = deepBundle?.routerSnpReport;
  const chipId = snp
    ? `${snp.chipIdHex.slice(0, 16)}...${snp.chipIdHex.slice(-8)}`
    : undefined;
  const tcb = snp
    ? `bl=${snp.tcb.bootloader} tee=${snp.tcb.tee} snp=${snp.tcb.snp} ucode=${snp.tcb.microcode} fmc=${snp.tcb.fmc}`
    : undefined;
  const guestPolicy = snp
    ? `${snp.policyHex} (debug=${snp.debugAllowed ? "on" : "off"}, smt=${snp.smtAllowed ? "on" : "off"}, migrate=${snp.migrationAllowed ? "on" : "off"})`
    : undefined;
  const primaryGpuHost = selectedModelAttestation?.enclaveHosts[0]?.host;
  const gpuEnclaveHost = selectedModelAttestation
    ? `${primaryGpuHost ?? selectedModelAttestation.repo} (${selectedModelAttestation.healthyHosts}/${selectedModelAttestation.configuredHosts} healthy)`
    : undefined;
  const gpuVmShape = selectedModelAttestation
    ? `${selectedModelAttestation.vmShape.gpus}x GPU · ${selectedModelAttestation.vmShape.cpus} vCPU · ${Math.round(selectedModelAttestation.vmShape.memoryMb / 1024)} GB RAM`
    : undefined;
  const pinnedWeights = selectedModelAttestation
    ? `${selectedModelAttestation.weightRepoCommit} (mpk-${selectedModelAttestation.weightMpkHash.replace(/^mpk-/, "").slice(0, 12)}...)`
    : undefined;
  const dmVerityRoot = selectedModelAttestation?.dmVerityRootHash;

  const evidence: TinfoilEvidence = {
    enclaveHost: doc.enclaveHost,
    releaseTag: doc.releaseTag,
    releaseDigest: doc.releaseDigest,
    codeFingerprint: doc.codeFingerprint,
    enclaveFingerprint: doc.enclaveFingerprint,
    measurementType: doc.enclaveMeasurement.measurement.type,
    hpkePublicKey: doc.hpkePublicKey,
    configRepo: doc.configRepo,
    verifiedAt: doc.verifiedAt,
    ...(chipId ? { chipId, "Chip ID": chipId } : {}),
    ...(tcb ? { tcb, TCB: tcb } : {}),
    ...(guestPolicy ? { guestPolicy, "Guest policy": guestPolicy } : {}),
    ...(gpuEnclaveHost
      ? { gpuEnclaveHost, "GPU enclave host": gpuEnclaveHost }
      : {}),
    ...(gpuVmShape ? { gpuVmShape, "GPU VM shape": gpuVmShape } : {}),
    ...(pinnedWeights
      ? { pinnedWeights, "Pinned weights": pinnedWeights }
      : {}),
    ...(dmVerityRoot ? { dmVerityRoot, "dm-verity root": dmVerityRoot } : {}),
  };

  return {
    checks: checksFromDocument(doc, selectedModelAttestation),
    evidence,
    relayHop: "/api/relay/v1",
    deepBundle,
    selectedModelAttestation,
    async *send(model, messages) {
      const reqHeaders: Record<string, string> = {
        "X-Tinfoil-Model": model,
        "X-DRouter-Cadence-Ms": "50",
      };
      if (pendingCreditHeader) {
        reqHeaders["x-drouter-credit"] = pendingCreditHeader;
        pendingCreditHeader = null;
      }
      const stream = await client.chat.completions.create(
        { model, messages, stream: true },
        { headers: reqHeaders },
      );
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta?.content;
        if (delta) yield delta;
      }
    },
  };
}

function buildHonestTinfoilEvidence(
  session: TinfoilSession,
  selectedModel: string,
): Record<string, string> {
  const snp = session.deepBundle?.routerSnpReport;
  const exactModelAttestation = session.deepBundle?.models?.[selectedModel];

  const chipId = snp
    ? `${snp.chipIdHex.slice(0, 16)}...${snp.chipIdHex.slice(-8)}`
    : (session.evidence["Chip ID"] ??
      session.evidence.chipId ??
      "Unavailable (SEV-SNP binary report not returned by enclave matrix)");

  const tcb = snp
    ? `bl=${snp.tcb.bootloader} tee=${snp.tcb.tee} snp=${snp.tcb.snp} ucode=${snp.tcb.microcode} fmc=${snp.tcb.fmc}`
    : (session.evidence.TCB ??
      session.evidence.tcb ??
      "Unavailable (SEV-SNP binary report not returned by enclave matrix)");

  const guestPolicy = snp
    ? `${snp.policyHex} (debug=${snp.debugAllowed ? "on" : "off"}, smt=${snp.smtAllowed ? "on" : "off"}, migrate=${snp.migrationAllowed ? "on" : "off"})`
    : (session.evidence["Guest policy"] ??
      session.evidence.guestPolicy ??
      "Unavailable (SEV-SNP binary report not returned by enclave matrix)");

  const primaryGpuHost = exactModelAttestation?.enclaveHosts[0]?.host;
  const gpuEnclaveHost = exactModelAttestation
    ? `${primaryGpuHost ?? exactModelAttestation.repo} (${exactModelAttestation.healthyHosts}/${exactModelAttestation.configuredHosts} healthy)`
    : `Unavailable (no enclave matrix entry for ${selectedModel})`;

  const gpuVmShape = exactModelAttestation
    ? `${exactModelAttestation.vmShape.gpus}x GPU · ${exactModelAttestation.vmShape.cpus} vCPU · ${Math.round(exactModelAttestation.vmShape.memoryMb / 1024)} GB RAM`
    : `Unavailable (no VM shape reported for ${selectedModel})`;

  const pinnedWeights = exactModelAttestation
    ? `${exactModelAttestation.weightRepoCommit} (mpk-${exactModelAttestation.weightMpkHash.replace(/^mpk-/, "").slice(0, 12)}...)`
    : `Unavailable (no weight manifest reported for ${selectedModel})`;

  const dmVerityRoot =
    exactModelAttestation?.dmVerityRootHash ||
    `Unavailable (no dm-verity root reported for ${selectedModel})`;

  return {
    "Enclave host":
      session.evidence.enclaveHost || "Unavailable (not reported by verifier)",
    "Measurement type":
      session.evidence.measurementType ||
      "Unavailable (not reported by verifier)",
    "Enclave fingerprint":
      session.evidence.enclaveFingerprint ||
      "Unavailable (not reported by verifier)",
    "Code fingerprint":
      session.evidence.codeFingerprint ||
      "Unavailable (not reported by verifier)",
    Release:
      session.evidence.releaseTag ??
      session.evidence.releaseDigest ??
      "Unavailable (not reported by verifier)",
    "Source repo":
      session.evidence.configRepo || "Unavailable (not reported by verifier)",
    "HPKE key":
      session.evidence.hpkePublicKey ||
      "Unavailable (not reported by verifier)",
    "Chip ID": chipId,
    chipId,
    TCB: tcb,
    "Guest policy": guestPolicy,
    "GPU enclave host": gpuEnclaveHost,
    "GPU VM shape": gpuVmShape,
    "Pinned weights": pinnedWeights,
    "dm-verity root": dmVerityRoot,
  };
}

function wrapSendWithCreditAndChecks(
  checks: CheckResult[],
  innerSend: (
    history: ChatMessage[],
    model: string,
  ) => AsyncIterable<string>,
): (
  history: ChatMessage[],
  model: string,
  opts?: SendOptions,
) => AsyncIterable<string> {
  return async function* (
    history: ChatMessage[],
    model: string,
    opts?: SendOptions,
  ) {
    const failed = checks.find((c) => c.status === "fail");
    if (failed) {
      throw new Error(
        `Not verified: ${failed.id} (${failed.label}) failed: ${failed.detail}`,
      );
    }
    if (typeof window !== "undefined") {
      ensureFetchInterceptorInstalled(window.location.origin);
    }
    pendingCreditHeader = opts?.creditHeader ?? null;
    try {
      for await (const chunk of innerSend(history, model)) {
        yield chunk;
      }
    } finally {
      pendingCreditHeader = null;
    }
  };
}

export async function openSession(
  node: NodeRecord,
  registry: RegistryResponse,
  onCheck: (c: CheckResult) => void,
  selectedModel = "kimi-k3",
): Promise<ActiveSession> {
  if (typeof window !== "undefined") {
    ensureFetchInterceptorInstalled(window.location.origin);
  }
  const c6 = await registryAndQuorumCheck(node, registry);

  if (node.kind === "tinfoil") {
    let session: TinfoilSession;
    try {
      session = await openTinfoilSession(selectedModel);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("attestationBundleURL must use HTTPS")) {
        session = await openLocalHttpTinfoilSession(selectedModel);
      } else {
        throw err;
      }
    }

    const exactModelAttestation = session.deepBundle?.models?.[selectedModel];
    const modelStatus = exactModelAttestation
      ? verifyModelEnclaveStatus(exactModelAttestation)
      : null;

    const checks = session.checks.map((c) => {
      if (c.id === "C6") return c6;
      if (c.id === "C5" && session.deepBundle && !exactModelAttestation) {
        return {
          ...c,
          status: "skip" as const,
          detail: `Unavailable: enclave matrix did not report confidential GPU pool status for ${selectedModel}`,
        };
      }
      if (c.id === "C5" && modelStatus) {
        return {
          ...c,
          status: modelStatus.c5Pass ? ("pass" as const) : ("fail" as const),
          detail: modelStatus.c5Detail,
        };
      }
      if (c.id === "C7" && modelStatus) {
        return {
          ...c,
          status: modelStatus.c7Pass ? ("pass" as const) : ("fail" as const),
          detail: modelStatus.c7Detail,
        };
      }
      return c;
    });

    checks.forEach(onCheck);
    const evidence = buildHonestTinfoilEvidence(session, selectedModel);

    const failed = checks.find((c) => c.status === "fail");
    if (failed) {
      throw Object.assign(
        new Error(
          `${failed.id} (${failed.label}): ${failed.detail}`,
        ),
        { checks, evidence, deepBundle: session.deepBundle },
      );
    }

    return {
      node,
      checks,
      evidence,
      evidenceHash: hashHex(session.evidence),
      deepBundle: session.deepBundle,
      send: wrapSendWithCreditAndChecks(checks, (history, model) =>
        session.send(
          model,
          history.map((m) => ({
            role: m.role,
            content: m.wireContent ?? m.content,
          })),
        ),
      ),
    };
  }

  const sim = await openSimSession(window.location.origin, simIdFor(node), {
    onCheck: (c) => onCheck(c.id === "C6" ? c6 : c),
  });
  const checks = sim.checks.map((c) => (c.id === "C6" ? c6 : c));
  onCheck(c6);

  const simChipId = sim.evidence.chipId
    ? `${sim.evidence.chipId} (simulated)`
    : "Unavailable (no simulated chip ID)";

  const evidence: Record<string, string> = {
    Mode: "Simulated in software (not real TEE hardware)",
    "Simulated node": sim.simId,
    Measurement: sim.evidence.measurement
      ? `${sim.evidence.measurement} (simulated)`
      : "Unavailable (no simulated measurement)",
    "Chip ID": simChipId,
    chipId: simChipId,
    TCB: sim.evidence.tcb
      ? `${typeof sim.evidence.tcb === "string" ? sim.evidence.tcb : JSON.stringify(sim.evidence.tcb)} (simulated)`
      : "Unavailable (no simulated TCB)",
    "GPUs attested":
      sim.evidence.gpuCount !== undefined
        ? `${sim.evidence.gpuCount} (simulated)`
        : "Unavailable (simulated node)",
    "Report data": sim.evidence.reportData
      ? `${sim.evidence.reportData} (simulated)`
      : "Unavailable (no simulated report data)",
    "Guest policy": sim.evidence.policy
      ? `${typeof sim.evidence.policy === "string" ? sim.evidence.policy : JSON.stringify(sim.evidence.policy)} (simulated)`
      : "Unavailable (no simulated guest policy)",
  };

  const failed = checks.find((c) => c.status === "fail");
  if (failed) {
    throw Object.assign(
      new Error(`${failed.id} (${failed.label}): ${failed.detail}`),
      { checks, evidence },
    );
  }

  return {
    node,
    checks,
    evidence,
    evidenceHash: hashHex(sim.evidence),
    send: wrapSendWithCreditAndChecks(checks, async function* (history) {
      const lastMsg = history[history.length - 1];
      const text = lastMsg ? (lastMsg.wireContent ?? lastMsg.content) : "";
      for await (const chunk of sim.send(text)) {
        yield chunk.replace(/\bSimulated enclave\b/g, "Practice server");
      }
    }),
    close: () => sim.close(),
  };
}

export async function postJson<T>(
  url: string,
  body: unknown,
): Promise<T | null> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return res.ok ? ((await res.json()) as T) : null;
  } catch {
    return null;
  }
}
