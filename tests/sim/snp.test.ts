import { p384 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";
import { openSimSession } from "@/lib/sim/client";
import { FORBIDDEN_REPORT_DATA_PREFIX, SIM_NODES, SIM_TCB } from "@/lib/sim/constants";
import { assertSimId, SYNTHETIC_CHIP_ID_HEX_PREFIX } from "@/lib/sim/hardware";
import { nodeClose, nodeHello, nodeKeyshare, nodeTurn } from "@/lib/sim/node";
import { simRoots } from "@/lib/sim/roots";
import {
  REPORT_SIZE,
  encodeReport,
  parseReport,
  signReport,
  tcbFromU64,
  tcbToU64,
  verifyReportSignature,
  type SnpReportFields,
} from "@/lib/sim/snp";

function fill(n: number, v: number): Uint8Array {
  return new Uint8Array(n).fill(v);
}

function sampleFields(overrides: Partial<SnpReportFields> = {}): SnpReportFields {
  return {
    version: 3,
    guestSvn: 7,
    policy: (BigInt(1) << BigInt(17)) | (BigInt(1) << BigInt(8)),
    familyId: fill(16, 1),
    imageId: fill(16, 2),
    vmpl: 0,
    signatureAlgo: 1,
    currentTcb: tcbToU64(SIM_TCB),
    platformInfo: BigInt(0),
    flags: 0,
    reportData: fill(64, 3),
    measurement: fill(48, 4),
    hostData: fill(32, 5),
    idKeyDigest: fill(48, 6),
    authorKeyDigest: fill(48, 7),
    reportId: fill(32, 8),
    reportIdMa: fill(32, 9),
    reportedTcb: tcbToU64(SIM_TCB),
    chipId: fill(64, 10),
    committedTcb: tcbToU64(SIM_TCB),
    launchTcb: tcbToU64(SIM_TCB),
    ...overrides,
  };
}

describe("SEV-SNP report", () => {
  it("round-trips fields through the 1184-byte layout", () => {
    const fields = sampleFields();
    const bytes = encodeReport(fields);
    expect(bytes.length).toBe(REPORT_SIZE);
    expect(REPORT_SIZE).toBe(0x4a0);
    const parsed = parseReport(bytes);
    expect(parsed.version).toBe(3);
    expect(parsed.guestSvn).toBe(7);
    expect(parsed.policy).toBe(fields.policy);
    expect(parsed.currentTcb).toBe(fields.currentTcb);
    expect(parsed.reportedTcb).toBe(fields.reportedTcb);
    expect(Array.from(parsed.reportData)).toEqual(Array.from(fields.reportData));
    expect(Array.from(parsed.measurement)).toEqual(Array.from(fields.measurement));
    expect(Array.from(parsed.chipId)).toEqual(Array.from(fields.chipId));
    expect(Array.from(parsed.reportId)).toEqual(Array.from(fields.reportId));
  });

  it("places fields at the documented offsets", () => {
    const bytes = encodeReport(sampleFields());
    const dv = new DataView(bytes.buffer);
    expect(dv.getUint32(0x00, true)).toBe(3);
    expect(dv.getUint32(0x04, true)).toBe(7);
    expect(dv.getBigUint64(0x08, true)).toBe((BigInt(1) << BigInt(17)) | (BigInt(1) << BigInt(8)));
    expect(dv.getUint32(0x34, true)).toBe(1);
    expect(bytes[0x50]).toBe(3);
    expect(bytes[0x90]).toBe(4);
    expect(bytes[0xc0]).toBe(5);
    expect(bytes[0x140]).toBe(8);
    expect(bytes[0x1a0]).toBe(10);
    expect(dv.getBigUint64(0x180, true)).toBe(tcbToU64(SIM_TCB));
  });

  it("packs the Turin TCB layout", () => {
    const u = tcbToU64(SIM_TCB);
    expect(Number(u & BigInt(0xff))).toBe(2);
    expect(Number((u >> BigInt(8)) & BigInt(0xff))).toBe(3);
    expect(Number((u >> BigInt(16)) & BigInt(0xff))).toBe(1);
    expect(Number((u >> BigInt(24)) & BigInt(0xff))).toBe(4);
    expect(Number((u >> BigInt(56)) & BigInt(0xff))).toBe(9);
    expect(tcbFromU64(u)).toEqual(SIM_TCB);
  });

  it("signs and verifies, and verification covers bytes 0x000-0x29f", () => {
    const key = p384.keygen();
    const report = signReport(sampleFields(), key.secretKey);
    expect(report.length).toBe(REPORT_SIZE);
    expect(verifyReportSignature(report, key.publicKey)).toBe(true);
    const other = p384.keygen();
    expect(verifyReportSignature(report, other.publicKey)).toBe(false);
  });

  it("rejects a tampered report body or signature", () => {
    const key = p384.keygen();
    const report = signReport(sampleFields(), key.secretKey);
    for (const offset of [0x00, 0x50, 0x90, 0x1a0, 0x29f, 0x2a0, 0x2e8]) {
      const tampered = report.slice();
      tampered[offset] ^= 0x01;
      expect(verifyReportSignature(tampered, key.publicKey), `offset ${offset}`).toBe(false);
    }
    expect(verifyReportSignature(report.slice(0, 100), key.publicKey)).toBe(false);
  });

  it("refuses to sign REPORT_DATA with the forbidden prefix", () => {
    const key = p384.keygen();
    const reportData = new Uint8Array(64);
    reportData.set(FORBIDDEN_REPORT_DATA_PREFIX, 0);
    expect(() => signReport(sampleFields({ reportData }), key.secretKey)).toThrow(/forbidden/i);
  });
});

describe("Simulated practice nodes removed from production", () => {
  it("exports an empty SIM_NODES list and empty simRoots()", () => {
    expect(SIM_NODES).toEqual([]);
    expect(simRoots().nodes).toEqual([]);
    expect(SYNTHETIC_CHIP_ID_HEX_PREFIX).toBe("73696d2d636869702d30303030303030");
  });

  it("rejects all simulated session and node operations", async () => {
    expect(() => assertSimId("sim-1")).toThrow(/removed/i);
    await expect(openSimSession("", "sim-1")).rejects.toThrow(/removed/i);
    expect(() => nodeHello("sim-1", { clientNonce: "00".repeat(32), modelId: "sim-echo-1" })).toThrow(
      /removed/i,
    );
    expect(() =>
      nodeKeyshare("sim-1", {
        ticket: "00",
        clientX25519Pk: "00",
        mlkemCt: "00",
        sealed: "00",
      }),
    ).toThrow(/removed/i);
    expect(() => nodeTurn("sim-1", { ticket: "00", turn: 1, ct: "00" })).toThrow(/removed/i);
    expect(() => nodeClose("sim-1", { ticket: "00" })).toThrow(/removed/i);
  });
});
