import { concat, startsWith } from "./bytes";
import { FORBIDDEN_REPORT_DATA_PREFIX, type Tcb } from "./constants";
import { p384Sign, p384Verify } from "./ecdsa";

/**
 * AMD SEV-SNP ATTESTATION_REPORT (version 3), 1184 bytes, little-endian, real field offsets.
 * The signature (ECDSA P-384 / SHA-384) covers bytes 0x000-0x29F; R and S are stored as
 * 72-byte little-endian integers at 0x2A0 and 0x2E8.
 */

export const REPORT_SIZE = 0x4a0;
export const SIGNED_SIZE = 0x2a0;
const SIG_R = 0x2a0;
const SIG_S = 0x2e8;
const SIG_FIELD = 72;
const SIG_ALGO_ECDSA_P384_SHA384 = 1;

export interface SnpReportFields {
  version: number;
  guestSvn: number;
  policy: bigint;
  familyId: Uint8Array; // 16
  imageId: Uint8Array; // 16
  vmpl: number;
  signatureAlgo: number;
  currentTcb: bigint;
  platformInfo: bigint;
  flags: number;
  reportData: Uint8Array; // 64
  measurement: Uint8Array; // 48
  hostData: Uint8Array; // 32
  idKeyDigest: Uint8Array; // 48
  authorKeyDigest: Uint8Array; // 48
  reportId: Uint8Array; // 32
  reportIdMa: Uint8Array; // 32
  reportedTcb: bigint;
  chipId: Uint8Array; // 64
  committedTcb: bigint;
  launchTcb: bigint;
}

export interface ParsedSnpReport extends SnpReportFields {
  /** Raw little-endian signature fields as stored in the report. */
  signatureR: Uint8Array;
  signatureS: Uint8Array;
}

const BYTE_FIELDS: Array<[keyof SnpReportFields, number, number]> = [
  ["familyId", 0x10, 16],
  ["imageId", 0x20, 16],
  ["reportData", 0x50, 64],
  ["measurement", 0x90, 48],
  ["hostData", 0xc0, 32],
  ["idKeyDigest", 0xe0, 48],
  ["authorKeyDigest", 0x110, 48],
  ["reportId", 0x140, 32],
  ["reportIdMa", 0x160, 32],
  ["chipId", 0x1a0, 64],
];

/** Encode a report with an all-zero signature region. */
export function encodeReport(fields: SnpReportFields): Uint8Array {
  const out = new Uint8Array(REPORT_SIZE);
  const dv = new DataView(out.buffer);
  dv.setUint32(0x00, fields.version, true);
  dv.setUint32(0x04, fields.guestSvn, true);
  dv.setBigUint64(0x08, fields.policy, true);
  dv.setUint32(0x30, fields.vmpl, true);
  dv.setUint32(0x34, fields.signatureAlgo, true);
  dv.setBigUint64(0x38, fields.currentTcb, true);
  dv.setBigUint64(0x40, fields.platformInfo, true);
  dv.setUint32(0x48, fields.flags, true);
  dv.setBigUint64(0x180, fields.reportedTcb, true);
  dv.setBigUint64(0x1e0, fields.committedTcb, true);
  dv.setBigUint64(0x1f0, fields.launchTcb, true);
  for (const [name, offset, length] of BYTE_FIELDS) {
    const value = fields[name] as Uint8Array;
    if (value.length !== length) throw new Error(`${name} must be ${length} bytes`);
    out.set(value, offset);
  }
  return out;
}

export function parseReport(bytes: Uint8Array): ParsedSnpReport {
  if (bytes.length !== REPORT_SIZE) throw new Error(`SNP report must be ${REPORT_SIZE} bytes`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const slice = (offset: number, length: number) => bytes.slice(offset, offset + length);
  const byteField = (name: keyof SnpReportFields) => {
    const [, offset, length] = BYTE_FIELDS.find(([n]) => n === name)!;
    return slice(offset, length);
  };
  return {
    version: dv.getUint32(0x00, true),
    guestSvn: dv.getUint32(0x04, true),
    policy: dv.getBigUint64(0x08, true),
    familyId: byteField("familyId"),
    imageId: byteField("imageId"),
    vmpl: dv.getUint32(0x30, true),
    signatureAlgo: dv.getUint32(0x34, true),
    currentTcb: dv.getBigUint64(0x38, true),
    platformInfo: dv.getBigUint64(0x40, true),
    flags: dv.getUint32(0x48, true),
    reportData: byteField("reportData"),
    measurement: byteField("measurement"),
    hostData: byteField("hostData"),
    idKeyDigest: byteField("idKeyDigest"),
    authorKeyDigest: byteField("authorKeyDigest"),
    reportId: byteField("reportId"),
    reportIdMa: byteField("reportIdMa"),
    reportedTcb: dv.getBigUint64(0x180, true),
    chipId: byteField("chipId"),
    committedTcb: dv.getBigUint64(0x1e0, true),
    launchTcb: dv.getBigUint64(0x1f0, true),
    signatureR: slice(SIG_R, SIG_FIELD),
    signatureS: slice(SIG_S, SIG_FIELD),
  };
}

/** Sign with the VCEK. Throws if REPORT_DATA starts with the forbidden prefix. */
export function signReport(fields: SnpReportFields, vcekSecretKey: Uint8Array): Uint8Array {
  if (startsWith(fields.reportData, FORBIDDEN_REPORT_DATA_PREFIX)) {
    throw new Error("refusing to sign forbidden REPORT_DATA prefix");
  }
  const report = encodeReport(fields);
  const sig = p384Sign(report.subarray(0, SIGNED_SIZE), vcekSecretKey); // r‖s big-endian
  report.set(toLittleEndian72(sig.subarray(0, 48)), SIG_R);
  report.set(toLittleEndian72(sig.subarray(48, 96)), SIG_S);
  return report;
}

export function verifyReportSignature(bytes: Uint8Array, vcekPublicKey: Uint8Array): boolean {
  if (bytes.length !== REPORT_SIZE) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint32(0x34, true) !== SIG_ALGO_ECDSA_P384_SHA384) return false;
  const r = fromLittleEndian72(bytes.subarray(SIG_R, SIG_R + SIG_FIELD));
  const s = fromLittleEndian72(bytes.subarray(SIG_S, SIG_S + SIG_FIELD));
  if (!r || !s) return false;
  return p384Verify(concat(r, s), bytes.subarray(0, SIGNED_SIZE), vcekPublicKey);
}

function toLittleEndian72(be48: Uint8Array): Uint8Array {
  const out = new Uint8Array(SIG_FIELD);
  for (let i = 0; i < 48; i++) out[i] = be48[47 - i];
  return out;
}

/** Returns the 48-byte big-endian value, or null if the high padding bytes are non-zero. */
function fromLittleEndian72(le72: Uint8Array): Uint8Array | null {
  for (let i = 48; i < SIG_FIELD; i++) if (le72[i] !== 0) return null;
  const out = new Uint8Array(48);
  for (let i = 0; i < 48; i++) out[i] = le72[47 - i];
  return out;
}

// BigInt() calls instead of literals: the repo tsconfig targets ES2017, which rejects `1n` syntax.
const bit = (n: number): bigint => BigInt(1) << BigInt(n);
const bitSet = (value: bigint, n: number): boolean => (value & bit(n)) !== BigInt(0);
const byteAt = (value: bigint, n: number): number => Number((value >> BigInt(n)) & BigInt(0xff));

/** Turin TCB u64: byte0 fmc, byte1 bootloader, byte2 tee, byte3 snp, byte7 microcode. */
export function tcbToU64(tcb: Tcb): bigint {
  const put = (v: number, shift: number) => BigInt(v) << BigInt(shift);
  return put(tcb.fmc, 0) | put(tcb.bootloader, 8) | put(tcb.tee, 16) | put(tcb.snp, 24) | put(tcb.microcode, 56);
}

export function tcbFromU64(value: bigint): Tcb {
  return {
    fmc: byteAt(value, 0),
    bootloader: byteAt(value, 8),
    tee: byteAt(value, 16),
    snp: byteAt(value, 24),
    microcode: byteAt(value, 56),
  };
}

/** Guest policy: bit 16 SMT, 17 reserved (must be 1), 18 migration agent, 19 debug; ABI major in bits 8-15. */
export function decodePolicy(policy: bigint) {
  return {
    abiMinor: byteAt(policy, 0),
    abiMajor: byteAt(policy, 8),
    smt: bitSet(policy, 16),
    reservedOne: bitSet(policy, 17),
    migrationAgent: bitSet(policy, 18),
    debug: bitSet(policy, 19),
  };
}

/** Sim guest policy: only the reserved bit 17, ABI major 1. SMT, migration and debug stay off. */
export const SIM_POLICY: bigint = bit(17) | bit(8);
