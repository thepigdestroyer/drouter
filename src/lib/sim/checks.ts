import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { CheckResult } from "../types";
import { bytesEqual, concat, fromHex, toHex, u8 } from "./bytes";
import { GPUS_PER_NODE, type Tcb } from "./constants";
import { p384Verify } from "./ecdsa";
import { canonicalBytes, computeReportData } from "./protocol";
import { REPORT_SIZE, decodePolicy, parseReport, tcbFromU64, verifyReportSignature } from "./snp";
import type { EvidenceBundle, SimRoots } from "./types";

/** Client-side verification of a sim node's evidence bundle (checks C1-C7). */

export const CHECK_LABELS = {
  C1: "Hardware signature chain",
  C2: "Approved software",
  C3: "Fresh and bound to this session",
  C4: "Registered chip and manifest",
  C5: "GPUs in confidential mode",
  C6: "Registry admission",
  C7: "Committed model",
} as const;

export interface SimEvidenceSummary {
  simulated: true;
  measurement: string;
  chipId: string;
  tcb: Tcb;
  gpuCount: number;
  reportData: string;
  policy: { value: string; smt: boolean; migrationAgent: boolean; debug: boolean; abiMajor: number };
}

export interface CheckInput {
  roots: SimRoots;
  simId: string;
  modelId: string;
  clientNonce: Uint8Array;
  evidence: EvidenceBundle;
}

const hexEq = (a: string, b: string) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

function tcbMeets(actual: Tcb, minimum: Tcb): boolean {
  return (Object.keys(minimum) as Array<keyof Tcb>).every((k) => actual[k] >= minimum[k]);
}

function tcbText(t: Tcb): string {
  return `fmc ${t.fmc}, bootloader ${t.bootloader}, tee ${t.tee}, snp ${t.snp}, microcode ${t.microcode}`;
}

function parseEvidenceReport(evidence: EvidenceBundle) {
  return parseReport(fromHex(evidence.report, REPORT_SIZE));
}

function checkC1({ roots, evidence }: CheckInput): { detail: string; policy: SimEvidenceSummary["policy"]; tcb: Tcb } {
  const { statement, signature } = evidence.vcekCertificate;
  if (!p384Verify(fromHex(signature), canonicalBytes(statement), fromHex(roots.amdRoot))) {
    throw new Error("VCEK statement is not signed by the pinned simulated AMD root");
  }
  const reportBytes = fromHex(evidence.report, REPORT_SIZE);
  if (!verifyReportSignature(reportBytes, fromHex(statement.vcekPublicKey))) {
    throw new Error("attestation report signature does not verify under the simulated VCEK");
  }
  const report = parseReport(reportBytes);
  if (report.version !== 3) throw new Error(`unexpected report version ${report.version}`);
  if (!hexEq(statement.chipId, toHex(report.chipId))) throw new Error("VCEK chip id differs from the report");
  const tcb = tcbFromU64(report.reportedTcb);
  if (JSON.stringify(tcbFromU64(report.reportedTcb)) !== JSON.stringify(tcbFromU64(report.currentTcb))) {
    throw new Error("reported TCB differs from current TCB");
  }
  if (JSON.stringify(statement.tcb) !== JSON.stringify(tcb)) throw new Error("VCEK TCB differs from the report");
  if (!tcbMeets(tcb, roots.minTcb)) throw new Error(`TCB below minimum (${tcbText(tcb)})`);
  const policy = decodePolicy(report.policy);
  if (!policy.reservedOne) throw new Error("guest policy reserved bit 17 is not set");
  if (policy.debug) throw new Error("guest policy allows debug");
  if (policy.migrationAgent) throw new Error("guest policy allows a migration agent");
  if (policy.smt) throw new Error("guest policy allows SMT");
  return {
    detail: `Simulated report signed by simulated VCEK under simulated AMD root. TCB ${tcbText(tcb)}. Debug, migration and SMT off.`,
    policy: {
      value: `0x${report.policy.toString(16)}`,
      smt: policy.smt,
      migrationAgent: policy.migrationAgent,
      debug: policy.debug,
      abiMajor: policy.abiMajor,
    },
    tcb,
  };
}

function checkC2({ roots, evidence }: CheckInput): string {
  const report = parseEvidenceReport(evidence);
  if (!hexEq(toHex(report.measurement), roots.approvedMeasurement)) {
    throw new Error("launch measurement is not the approved image");
  }
  return `Simulated measurement ${toHex(report.measurement).slice(0, 16)}… matches the approved practice image.`;
}

function checkC3({ clientNonce, evidence }: CheckInput): string {
  const report = parseEvidenceReport(evidence);
  const expected = computeReportData({
    clientNonce,
    nodeIdentityPk: fromHex(evidence.identityPublicKey, 32),
    custodyX25519Pk: fromHex(evidence.custody.x25519PublicKey, 32),
    custodyMlkemPk: fromHex(evidence.custody.mlkemPublicKey),
    manifestHash: fromHex(evidence.manifestHash, 32),
    modelRoot: fromHex(evidence.modelRoot, 32),
  });
  if (!bytesEqual(expected, report.reportData)) {
    throw new Error("REPORT_DATA does not match this session's nonce and the presented keys");
  }
  return "REPORT_DATA recomputed from my nonce, the simulated node identity, custody keys, manifest and model root.";
}

function checkC4({ roots, simId, evidence }: CheckInput): string {
  const node = roots.nodes.find((n) => n.simId === simId);
  if (!node) throw new Error(`${simId} is not in the registered node list`);
  const report = parseEvidenceReport(evidence);
  if (!hexEq(toHex(report.chipId), node.chipId)) throw new Error("chip id is not the registered chip");
  if (!hexEq(evidence.manifestHash, node.manifestHash)) throw new Error("manifest hash is not the registered one");
  if (!hexEq(toHex(sha256(canonicalBytes(evidence.manifest))), evidence.manifestHash)) {
    throw new Error("manifest does not hash to the presented manifest hash");
  }
  if (!hexEq(evidence.manifest.chipId, node.chipId)) throw new Error("manifest chip id differs from registration");
  if (JSON.stringify(evidence.manifest.gpuIds) !== JSON.stringify(node.gpuIds)) {
    throw new Error("manifest GPU ids differ from registration");
  }
  if (!hexEq(evidence.identityPublicKey, node.identityPublicKey)) {
    throw new Error("node identity key is not the registered one");
  }
  return `Simulated synthetic chip ${node.chipId.slice(0, 16)}… and manifest ${node.manifestHash.slice(0, 16)}… match the registered practice node.`;
}

function checkC5({ roots, clientNonce, evidence }: CheckInput): string {
  if (evidence.gpus.length !== GPUS_PER_NODE) throw new Error(`expected ${GPUS_PER_NODE} GPUs, got ${evidence.gpus.length}`);
  evidence.gpus.forEach((gpu, i) => {
    const { statement, signature } = gpu.certificate;
    if (!ed25519.verify(fromHex(signature, 64), canonicalBytes(statement), fromHex(roots.nvidiaRoot, 32))) {
      throw new Error(`GPU ${i} certificate is not signed by the pinned simulated NVIDIA root`);
    }
    if (statement.gpuIndex !== i || gpu.report.gpuIndex !== i) throw new Error(`GPU ${i} index mismatch`);
    if (!ed25519.verify(fromHex(gpu.signature, 64), canonicalBytes(gpu.report), fromHex(statement.devicePublicKey, 32))) {
      throw new Error(`GPU ${i} report signature does not verify`);
    }
    if (gpu.report.ccMode !== true) throw new Error(`GPU ${i} is not in confidential-compute mode`);
    const nonce = sha256(concat(clientNonce, u8(i)));
    if (!hexEq(gpu.report.nonce, toHex(nonce))) throw new Error(`GPU ${i} nonce is not fresh for this session`);
    if (!hexEq(gpu.report.gpuId, statement.gpuId) || !hexEq(gpu.report.gpuId, evidence.manifest.gpuIds[i])) {
      throw new Error(`GPU ${i} id does not match the manifest`);
    }
  });
  return `All ${GPUS_PER_NODE} simulated GPUs: certificate chain valid, CC mode on, nonce fresh, ids match the manifest.`;
}

function checkC7({ roots, modelId, evidence }: CheckInput): string {
  if (evidence.modelId !== modelId || roots.model.id !== modelId) throw new Error("model id differs from the allowlist");
  if (!hexEq(evidence.modelRoot, roots.model.modelRoot)) throw new Error("model root is not the allowlisted weights");
  return `Simulated model ${modelId} root ${evidence.modelRoot.slice(0, 16)}… matches the allowlist.`;
}

export const REGISTRY_SKIP_DETAIL = "Registry ticket checked against Arc by the app";

/**
 * Runs C1-C7 in order, emitting each result as it completes. Stops and throws at the first failure
 * with an Error whose message names the check id.
 */
export function runChecks(
  input: CheckInput,
  onCheck?: (c: CheckResult) => void,
): { checks: CheckResult[]; summary: SimEvidenceSummary } {
  const checks: CheckResult[] = [];
  const emit = (result: CheckResult) => {
    checks.push(result);
    onCheck?.(result);
  };
  const run = <T>(id: keyof typeof CHECK_LABELS, fn: () => T, detailOf: (v: T) => string): T => {
    try {
      const value = fn();
      emit({ id, label: CHECK_LABELS[id], status: "pass", detail: detailOf(value) });
      return value;
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      emit({ id, label: CHECK_LABELS[id], status: "fail", detail: reason });
      throw new Error(`${id} failed (${CHECK_LABELS[id]}): ${reason}`);
    }
  };

  const c1 = run("C1", () => checkC1(input), (v) => v.detail);
  run("C2", () => checkC2(input), (v) => v);
  run("C3", () => checkC3(input), (v) => v);
  run("C4", () => checkC4(input), (v) => v);
  run("C5", () => checkC5(input), (v) => v);
  emit({ id: "C6", label: CHECK_LABELS.C6, status: "skip", detail: REGISTRY_SKIP_DETAIL });
  run("C7", () => checkC7(input), (v) => v);

  const report = parseEvidenceReport(input.evidence);
  return {
    checks,
    summary: {
      simulated: true,
      measurement: toHex(report.measurement),
      chipId: toHex(report.chipId),
      tcb: c1.tcb,
      gpuCount: input.evidence.gpus.length,
      reportData: toHex(report.reportData),
      policy: c1.policy,
    },
  };
}
