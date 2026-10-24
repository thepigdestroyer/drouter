import { ed25519 } from "@noble/curves/ed25519.js";
import { p384 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, fromHex, toHex, u8, utf8 } from "./bytes";
import { GPU_FIRMWARE_MEASUREMENT, GPUS_PER_NODE, SIM_TCB } from "./constants";
import { p384Sign } from "./ecdsa";
import { SimError } from "./errors";
import { canonicalBytes } from "./protocol";
import type { GpuCertStatement, GpuEvidence, GpuReportBody, SignedStatement, VcekStatement } from "./types";

/**
 * Simulated hardware roots. Every key is derived from SIM_HARDWARE_SEED with HKDF-SHA-256, so the
 * stateless serverless routes agree on the same "silicon" without storing anything.
 */

function seed(): Uint8Array {
  const raw = process.env.SIM_HARDWARE_SEED;
  if (!raw) throw new Error("SIM_HARDWARE_SEED is not set: the simulated hardware roots cannot be derived");
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error("SIM_HARDWARE_SEED must be 64 hex characters");
  return fromHex(raw);
}

function derive(info: string, length: number): Uint8Array {
  return hkdf(sha256, seed(), undefined, utf8(info), length);
}

function p384Key(info: string) {
  // 72 bytes of HKDF output gives an unbiased P-384 scalar.
  const secretKey = p384.utils.randomSecretKey(derive(info, 72));
  return { secretKey, publicKey: p384.getPublicKey(secretKey) };
}

function ed25519Key(info: string) {
  const secretKey = derive(info, 32);
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function assertSimId(simId: string): void {
  if (!/^sim-[1-9][0-9]*$/.test(simId)) throw new SimError(404, "unknown simulated node");
}

export function amdRoot() {
  return p384Key("sim/amd-root");
}

export function nvidiaRoot() {
  return ed25519Key("sim/nvidia-root");
}

export function vcek(simId: string) {
  return p384Key(`sim/vcek/${simId}`);
}

export function chipId(simId: string): Uint8Array {
  return derive(`sim/chip/${simId}`, 64);
}

export function ticketKey(simId: string): Uint8Array {
  return derive(`sim/ticket-key/${simId}`, 32);
}

/** Long-term node identity (Ed25519), used for report binding and pop receipts. */
export function identity(simId: string) {
  return ed25519Key(`sim/identity/${simId}`);
}

/**
 * The "VCEK certificate". Real AMD uses an X.509 chain (ARK -> ASK -> VCEK, RSA-PSS) with the chip id
 * and TCB in certificate extensions. The sim replaces it with a canonical-JSON statement
 * { chipId, tcb, vcekPublicKey } signed by the simulated AMD root using ECDSA P-384 / SHA-384.
 */
export function vcekCertificate(simId: string): SignedStatement<VcekStatement> {
  const statement: VcekStatement = {
    chipId: toHex(chipId(simId)),
    tcb: SIM_TCB,
    vcekPublicKey: toHex(vcek(simId).publicKey),
  };
  return { statement, signature: toHex(p384Sign(canonicalBytes(statement), amdRoot().secretKey)) };
}

function gpuKey(simId: string, index: number) {
  return ed25519Key(`sim/gpu/${simId}/${index}`);
}

export function gpuId(simId: string, index: number): Uint8Array {
  return sha256(gpuKey(simId, index).publicKey).slice(0, 16);
}

export function gpuIds(simId: string): string[] {
  return Array.from({ length: GPUS_PER_NODE }, (_, i) => toHex(gpuId(simId, i)));
}

export function gpuCertificate(simId: string, index: number): SignedStatement<GpuCertStatement> {
  const statement: GpuCertStatement = {
    gpuIndex: index,
    gpuId: toHex(gpuId(simId, index)),
    devicePublicKey: toHex(gpuKey(simId, index).publicKey),
  };
  return { statement, signature: toHex(ed25519.sign(canonicalBytes(statement), nvidiaRoot().secretKey)) };
}

/** GPU nonce = sha256(clientNonce ‖ u8 gpuIndex). */
export function gpuNonce(clientNonce: Uint8Array, index: number): Uint8Array {
  return sha256(concat(clientNonce, u8(index)));
}

export function gpuEvidence(simId: string, index: number, clientNonce: Uint8Array): GpuEvidence {
  const report: GpuReportBody = {
    gpuIndex: index,
    gpuId: toHex(gpuId(simId, index)),
    ccMode: true,
    nonce: toHex(gpuNonce(clientNonce, index)),
    firmwareMeasurement: toHex(GPU_FIRMWARE_MEASUREMENT),
  };
  return {
    certificate: gpuCertificate(simId, index),
    report,
    signature: toHex(ed25519.sign(canonicalBytes(report), gpuKey(simId, index).secretKey)),
  };
}
