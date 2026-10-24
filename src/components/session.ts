import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import type { CheckResult, NodeRecord, PopReceipt } from "@/lib/types";
import { openTinfoilSession } from "@/lib/tinfoil/client";
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

/** C6: the node must be registered on Arc, active, and staked. */
export function registryCheck(node: NodeRecord, registry: RegistryResponse): CheckResult {
  if (registry.source !== "arc") {
    return {
      id: "C6",
      label: "Registry admission",
      status: "skip",
      detail: "Registry contract not deployed yet; using the built-in node list",
    };
  }
  const ok = node.status === "active" && Number(node.stake) >= 0.01;
  return {
    id: "C6",
    label: "Registry admission",
    status: ok ? "pass" : "fail",
    detail: ok
      ? `Registered on Arc with ${node.stake} USDC staked by ${node.operator.slice(0, 10)}…`
      : `Node is ${node.status} with ${node.stake} USDC staked`,
  };
}

export function simIdFor(node: NodeRecord): string {
  return node.endpoint.split("/").filter(Boolean).pop() ?? "";
}

export async function openSession(
  node: NodeRecord,
  registry: RegistryResponse,
  onCheck: (c: CheckResult) => void,
): Promise<ActiveSession> {
  const c6 = registryCheck(node, registry);

  if (node.kind === "tinfoil") {
    const session = await openTinfoilSession();
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
    };
    return {
      node,
      checks,
      evidence,
      evidenceHash: hashHex(session.evidence),
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
