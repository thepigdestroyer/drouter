import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { p384Verify } from "@/lib/sim/ecdsa";
import { fromHex, toHex } from "@/lib/sim/bytes";
import { APPROVED_MEASUREMENT } from "@/lib/sim/constants";
import {
  amdRoot,
  chipId,
  gpuEvidence,
  gpuIds,
  identity,
  nvidiaRoot,
  vcek,
  vcekCertificate,
} from "@/lib/sim/hardware";
import { canonicalBytes } from "@/lib/sim/protocol";

describe("simulated hardware", () => {
  it("fails clearly without a seed and rejects a malformed seed", () => {
    const seed = process.env.SIM_HARDWARE_SEED;
    try {
      delete process.env.SIM_HARDWARE_SEED;
      expect(() => amdRoot()).toThrow(/SIM_HARDWARE_SEED/);
      process.env.SIM_HARDWARE_SEED = "abc";
      expect(() => amdRoot()).toThrow(/64 hex/);
    } finally {
      process.env.SIM_HARDWARE_SEED = seed;
    }
  });

  it("derives deterministic, distinct keys per purpose and node", () => {
    expect(toHex(amdRoot().publicKey)).toBe(toHex(amdRoot().publicKey));
    expect(toHex(vcek("sim-1").publicKey)).not.toBe(toHex(vcek("sim-2").publicKey));
    expect(toHex(amdRoot().publicKey)).not.toBe(toHex(vcek("sim-1").publicKey));
    expect(chipId("sim-1")).toHaveLength(64);
    expect(toHex(chipId("sim-1"))).not.toBe(toHex(chipId("sim-2")));
    expect(toHex(identity("sim-1").publicKey)).not.toBe(toHex(identity("sim-2").publicKey));
    expect(APPROVED_MEASUREMENT).toHaveLength(48);
  });

  it("signs the VCEK statement with the AMD root", () => {
    const cert = vcekCertificate("sim-1");
    expect(p384Verify(fromHex(cert.signature), canonicalBytes(cert.statement), amdRoot().publicKey)).toBe(true);
    expect(cert.statement.vcekPublicKey).toBe(toHex(vcek("sim-1").publicKey));
    expect(cert.statement.chipId).toBe(toHex(chipId("sim-1")));
  });

  it("gives each node eight certified GPUs with nonce-bound reports", () => {
    expect(new Set(gpuIds("sim-1")).size).toBe(8);
    const nonce = new Uint8Array(32).fill(4);
    const gpu = gpuEvidence("sim-1", 5, nonce);
    const { statement, signature } = gpu.certificate;
    expect(statement.gpuId).toHaveLength(32);
    expect(ed25519.verify(fromHex(signature), canonicalBytes(statement), nvidiaRoot().publicKey)).toBe(true);
    expect(ed25519.verify(fromHex(gpu.signature), canonicalBytes(gpu.report), fromHex(statement.devicePublicKey))).toBe(true);
    expect(gpu.report.ccMode).toBe(true);
    expect(gpu.report.firmwareMeasurement).toHaveLength(96);
    expect(gpuEvidence("sim-1", 5, new Uint8Array(32)).report.nonce).not.toBe(gpu.report.nonce);
  });
});
