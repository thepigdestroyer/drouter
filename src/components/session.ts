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
import type {
  DeepAttestationBundle,
  ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import { openSimSession } from "@/lib/sim/client";

export interface RegistryResponse {
  source: "arc" | "fallback";
  address?: string;
  nodes: NodeRecord[];
  chainId: number;
  explorer: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** A verified session with one node, regardless of whether the node is real or simulated. */
export interface ActiveSession {
  node: NodeRecord;
  checks: CheckResult[];
  evidence: Record<string, string>;
  evidenceHash: string;
  deepBundle?: DeepAttestationBundle;
  send(history: ChatMessage[], model: string): AsyncIterable<string>;
  close?: () => Promise<PopReceipt>;
}

/** Weighted random choice by stake, using this browser's own randomness (operators can't steer it). */
export function pickNode(nodes: NodeRecord[], kind: NodeRecord["kind"]): NodeRecord | null {
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

/** C6: checks both the on-chain Arc registry stake AND the 5-of-7 verifier quorum ticket. */
export async function registryAndQuorumCheck(node: NodeRecord, registry: RegistryResponse): Promise<CheckResult> {
  const key = simIdFor(node);
  let quorumDetail = "";
  let quorumOk = true;
  try {
    const res = await fetch("/api/transparency");
    if (res.ok) {
      const data = (await res.json()) as {
        verifierSet?: { threshold: number; total: number };
        tickets?: Record<string, QuorumTicket>;
      };
      const ticket = data.tickets?.[key];
      const threshold = data.verifierSet?.threshold ?? 5;
      const total = data.verifierSet?.total ?? 7;
      if (ticket) {
        const sigs = ticket.signatures?.length ?? 0;
        quorumOk = sigs >= threshold && ticket.status !== "suspended" && ticket.weight > 0;
        quorumDetail = ` · simulated quorum: ${sigs}/${total} verifier signatures, all keys held by our demo server (${ticket.status}, weight ${(ticket.weight / 100).toFixed(0)}%)`;
      }
    }
  } catch {
    // Fallback to on-chain registry check only if transparency endpoint is unreachable.
  }

  if (registry.source !== "arc") {
    return {
      id: "C6",
      label: "Registry admission",
      status: quorumDetail && quorumOk ? "pass" : "skip",
      detail: `Built-in node list${quorumDetail}`,
    };
  }
  const arcOk = node.status === "active" && Number(node.stake) >= 0.01;
  const ok = arcOk && quorumOk;
  return {
    id: "C6",
    label: "Registry admission",
    status: ok ? "pass" : "fail",
    detail: ok
      ? `Arc staked (${node.stake} USDC by ${node.operator.slice(0, 10)}…)${quorumDetail}`
      : `Node status ${node.status}, stake ${node.stake} USDC${quorumDetail}`,
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
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const userCacheSecret = toHex(secretBytes);

  const baseURL = `${origin}/api/relay/v1/`;
  const virtualHttpsRelay = "https://local-relay.drouter.internal/api/relay";

  const origFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    if (urlStr.startsWith(virtualHttpsRelay)) {
      const rewritten = urlStr.replace(virtualHttpsRelay, `${origin}/api/relay`);
      return origFetch(rewritten, init);
    }
    return origFetch(input, init);
  };

  try {
    const client = new TinfoilAI({
      bearerToken: "drouter-demo",
      baseURL,
      attestationBundleURL: virtualHttpsRelay,
      userCacheSecret,
    });

    const matrixPromise: Promise<DeepAttestationBundle | undefined> = origFetch(
      `${origin}/api/relay/enclave-matrix`,
    )
      .then(async (res) =>
        res.ok ? ((await res.json()) as DeepAttestationBundle) : undefined,
      )
      .catch(() => undefined);

    const [, deepBundle] = await Promise.all([client.ready(), matrixPromise]);
    const doc = await client.getVerificationDocument();
    const selectedModelAttestation: ModelEnclaveAttestation | undefined =
      deepBundle?.models[selectedModel] ?? deepBundle?.models["kimi-k3"];

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
        if (init && typeof init.body === "string") {
          try {
            const parsed = JSON.parse(init.body) as Record<string, unknown>;
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              if (!parsed.user_cache_secret) {
                parsed.user_cache_secret = userCacheSecret;
              }
              const { paddedJson } = padJsonPayloadToBucket(
                JSON.stringify(parsed),
              );
              init = { ...init, body: paddedJson };
            }
          } catch {
            // Leave non-JSON body unchanged
          }
        }
        return origTransportFetch(input, init);
      };
    }

    const snp = deepBundle?.routerSnpReport;
    const chipId = snp
      ? `${snp.chipIdHex.slice(0, 16)}…${snp.chipIdHex.slice(-8)}`
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
      ? `${selectedModelAttestation.vmShape.gpus}× GPU · ${selectedModelAttestation.vmShape.cpus} vCPU · ${Math.round(selectedModelAttestation.vmShape.memoryMb / 1024)} GB RAM`
      : undefined;
    const pinnedWeights = selectedModelAttestation
      ? `${selectedModelAttestation.weightRepoCommit} (mpk-${selectedModelAttestation.weightMpkHash.replace(/^mpk-/, "").slice(0, 12)}…)`
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
      relayHop: "relay-a",
      deepBundle,
      selectedModelAttestation,
      async *send(model, messages) {
        const stream = await client.chat.completions.create(
          { model, messages, stream: true },
          { headers: { "X-Tinfoil-Model": model, "X-DRouter-Cadence-Ms": "50" } },
        );
        for await (const chunk of stream) {
          const delta = chunk.choices[0]?.delta?.content;
          if (delta) yield delta;
        }
      },
    };
  } finally {
    window.fetch = origFetch;
  }
}

export async function openSession(
  node: NodeRecord,
  registry: RegistryResponse,
  onCheck: (c: CheckResult) => void,
  selectedModel = "kimi-k3",
): Promise<ActiveSession> {
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
    const checks = session.checks.map((c) => (c.id === "C6" ? c6 : c));
    checks.forEach(onCheck);
    const evidence: Record<string, string> = {
      "Enclave host": session.evidence.enclaveHost,
      "Measurement type": session.evidence.measurementType,
      "Enclave fingerprint": session.evidence.enclaveFingerprint,
      "Code fingerprint": session.evidence.codeFingerprint,
      "Release": session.evidence.releaseTag ?? session.evidence.releaseDigest,
      "Source repo": session.evidence.configRepo,
      "HPKE key": session.evidence.hpkePublicKey,
      ...(session.evidence["Chip ID"] ? { "Chip ID": session.evidence["Chip ID"], chipId: session.evidence["Chip ID"] } : {}),
      ...(session.evidence.TCB ? { TCB: session.evidence.TCB } : {}),
      ...(session.evidence["Guest policy"] ? { "Guest policy": session.evidence["Guest policy"] } : {}),
      ...(session.evidence["GPU enclave host"] ? { "GPU enclave host": session.evidence["GPU enclave host"] } : {}),
      ...(session.evidence["GPU VM shape"] ? { "GPU VM shape": session.evidence["GPU VM shape"] } : {}),
      ...(session.evidence["Pinned weights"] ? { "Pinned weights": session.evidence["Pinned weights"] } : {}),
      ...(session.evidence["dm-verity root"] ? { "dm-verity root": session.evidence["dm-verity root"] } : {}),
    };
    return {
      node,
      checks,
      evidence,
      evidenceHash: hashHex(session.evidence),
      deepBundle: session.deepBundle,
      send: (history, model) => session.send(model, history),
    };
  }

  const sim = await openSimSession(window.location.origin, simIdFor(node), {
    onCheck: (c) => onCheck(c.id === "C6" ? c6 : c),
  });
  const checks = sim.checks.map((c) => (c.id === "C6" ? c6 : c));
  onCheck(c6);
  const evidence: Record<string, string> = {
    "Simulated node": sim.simId,
    "Measurement": String(sim.evidence.measurement),
    "Chip ID": String(sim.evidence.chipId),
    chipId: String(sim.evidence.chipId),
    "TCB": typeof sim.evidence.tcb === "string" ? sim.evidence.tcb : JSON.stringify(sim.evidence.tcb),
    "GPUs attested": String(sim.evidence.gpuCount),
    "Report data": String(sim.evidence.reportData),
    "Guest policy": String(sim.evidence.policy),
  };
  return {
    node,
    checks,
    evidence,
    evidenceHash: hashHex(sim.evidence),
    send: (history) => sim.send(history[history.length - 1]?.content ?? ""),
    close: () => sim.close(),
  };
}

export async function postJson<T>(url: string, body: unknown): Promise<T | null> {
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
