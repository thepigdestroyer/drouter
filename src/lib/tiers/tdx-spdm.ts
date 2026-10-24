import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Spec §3 E4: Platform Tiers
 * - Tier A: AMD SEV-SNP + NVIDIA H100/B200 CC (baseline default)
 * - Tier B: Intel TDX + H100/B200 CC (opt-in only; shown as lower assurance)
 * - Tier A+: AMD SEV-SNP / Intel TDX + SPDM 1.2 device measurement (8x GPU, NIC, NVMe)
 *            + PCIe TDISP / TEE-IO VM binding + riser-proof on-package/soldered memory CPU allowlist
 */

export const TDX_TEE_TYPE = 0x81 as const;

export const TIER_B_ASSURANCE_WARNING =
  "Tier B (Intel TDX): client opt-in required; displayed as lower assurance than Tier A (AMD SEV-SNP)." as const;

/**
 * Riser-proof CPU models with on-package HBM or soldered/integrated memory controller topologies
 * eligible for Tier A+ hardware physical-interposer hardening (Spec §3 Tier A+).
 */
export const RISER_PROOF_CPU_ALLOWLIST = [
  "AMD EPYC 9005 (Turin-X On-Package)",
  "NVIDIA Grace Hopper Superchip (GH200 Soldered LPDDR5X)",
  "NVIDIA Grace Blackwell Superchip (GB200 Soldered LPDDR5X)",
  "Intel Xeon Max 9480 (Sapphire Rapids HBM2e On-Package)",
] as const;

export interface TdxQuoteV4 {
  teeType: number; // 0x81 for Intel TDX Quote v4
  mrtd: string;
  rtmr0: string;
  reportData: string;
  tdAttributesDebug: boolean;
  tcbSvn: number;
  pckSignatureHex: string;
  pckPublicKeyHex: string;
}

export interface VerifyTdxTierBOptions {
  allowTierB: boolean;
  expectedReportData: string;
  expectedMrtd: string;
  minTcbSvn: number;
}

export interface VerifyTdxTierBResult {
  accepted: boolean;
  tier: "B";
  assuranceWarning: string;
  reason: string;
}

export type SpdmDeviceClass = "GPU" | "NIC" | "NVME";

export interface SpdmDeviceMeasurement {
  deviceId: string;
  deviceClass: SpdmDeviceClass;
  spdmVersion: "1.2";
  measurementDigestHex: string;
  expectedDigestHex: string;
  nonceHex: string;
  devicePublicKeyHex: string;
  signatureHex: string;
}

export interface TierAPlusEvidence {
  nodeId: string;
  cpuModel: string;
  teeIoBoundVmId: string;
  devices: SpdmDeviceMeasurement[];
}

export interface VerifyTierAPlusResult {
  accepted: boolean;
  tier: "A+" | "A";
  spdmVerifiedCount: number;
  teeIoBound: boolean;
  riserProofMemory: boolean;
  detail: string;
}

function canonicalTdxQuotePayload(quote: Omit<TdxQuoteV4, "pckSignatureHex" | "pckPublicKeyHex">): Uint8Array {
  const canonical = JSON.stringify({
    domain: "drouter-tdx-quote-v4",
    teeType: quote.teeType,
    mrtd: quote.mrtd.toLowerCase(),
    rtmr0: quote.rtmr0.toLowerCase(),
    reportData: quote.reportData.toLowerCase(),
    tdAttributesDebug: quote.tdAttributesDebug,
    tcbSvn: quote.tcbSvn,
  });
  return utf8ToBytes(canonical);
}

function canonicalSpdmPayload(
  device: Omit<SpdmDeviceMeasurement, "signatureHex" | "devicePublicKeyHex" | "expectedDigestHex">,
  teeIoBoundVmId: string,
): Uint8Array {
  const canonical = JSON.stringify({
    domain: "drouter-spdm-1.2-measurements",
    spdmVersion: device.spdmVersion,
    deviceId: device.deviceId,
    deviceClass: device.deviceClass,
    measurementDigestHex: device.measurementDigestHex.toLowerCase(),
    nonceHex: device.nonceHex.toLowerCase(),
    teeIoBoundVmId,
  });
  return utf8ToBytes(canonical);
}

export function p256SignHex(message: Uint8Array, secretKey: Uint8Array): string {
  const digest = sha256(message);
  return bytesToHex(p256.sign(digest, secretKey, { prehash: false }));
}

export function p256VerifyHex(signatureHex: string, message: Uint8Array, publicKeyHex: string): boolean {
  try {
    const sigBytes = hexToBytes(signatureHex);
    const pubBytes = hexToBytes(publicKeyHex);
    const digest = sha256(message);
    return p256.verify(sigBytes, digest, pubBytes, { prehash: false, lowS: false });
  } catch {
    return false;
  }
}

export function deriveDeterministicP256KeyPair(label: string): {
  secretKey: Uint8Array;
  publicKeyHex: string;
} {
  const seed = sha256(utf8ToBytes("drouter-tiers-demo-seed-v1"));
  const secretKey = hkdf(sha256, seed, undefined, utf8ToBytes(label), 32);
  const publicKeyHex = bytesToHex(p256.getPublicKey(secretKey, false));
  return { secretKey, publicKeyHex };
}

/**
 * Helper to create a signed Intel TDX Quote v4 for testing and simulation.
 */
export function createSignedTdxQuote(params?: Partial<{
  teeType: number;
  mrtd: string;
  rtmr0: string;
  reportData: string;
  tdAttributesDebug: boolean;
  tcbSvn: number;
  keyLabel: string;
}>): TdxQuoteV4 {
  const mrtd =
    params?.mrtd ??
    bytesToHex(sha384(utf8ToBytes("drouter-tdx-mrtd/v0.1.0")));
  const rtmr0 =
    params?.rtmr0 ??
    bytesToHex(sha384(utf8ToBytes("drouter-tdx-rtmr0/v0.1.0")));
  const reportData =
    params?.reportData ??
    bytesToHex(sha256(utf8ToBytes("drouter-session-binding-v1")));
  const teeType = params?.teeType ?? TDX_TEE_TYPE;
  const tdAttributesDebug = params?.tdAttributesDebug ?? false;
  const tcbSvn = params?.tcbSvn ?? 7;

  const { secretKey, publicKeyHex } = deriveDeterministicP256KeyPair(
    params?.keyLabel ?? "intel-sgx-pck-tdx-v4",
  );

  const payload = canonicalTdxQuotePayload({
    teeType,
    mrtd,
    rtmr0,
    reportData,
    tdAttributesDebug,
    tcbSvn,
  });

  const pckSignatureHex = p256SignHex(payload, secretKey);

  return {
    teeType,
    mrtd,
    rtmr0,
    reportData,
    tdAttributesDebug,
    tcbSvn,
    pckSignatureHex,
    pckPublicKeyHex: publicKeyHex,
  };
}

/**
 * Verifies an Intel TDX Quote v4 under Tier B policy (Spec §3 E4, Tier B).
 * - Rejects unless `opts.allowTierB === true` (clients must explicitly opt in).
 * - Rejects if `teeType !== 0x81`, `tdAttributesDebug === true`, `tcbSvn < minTcbSvn`,
 *   `mrtd !== expectedMrtd`, `reportData !== expectedReportData`, or P-256 PCK signature is invalid.
 */
export function verifyTdxTierBQuote(
  quote: TdxQuoteV4,
  opts: VerifyTdxTierBOptions,
): VerifyTdxTierBResult {
  if (!opts.allowTierB) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: "Tier B (Intel TDX) rejected: client did not opt in (allowTierB is false)",
    };
  }

  if (quote.teeType !== TDX_TEE_TYPE) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: `Invalid TDX quote header teeType: expected 0x81, got 0x${quote.teeType.toString(16)}`,
    };
  }

  if (quote.tdAttributesDebug) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: "TDX quote rejected: TD_ATTRIBUTES.DEBUG bit is set (debug TDs cannot serve production traffic)",
    };
  }

  if (quote.tcbSvn < opts.minTcbSvn) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: `TDX quote rejected: tcbSvn ${quote.tcbSvn} is below minimum required ${opts.minTcbSvn}`,
    };
  }

  if (quote.mrtd.toLowerCase() !== opts.expectedMrtd.toLowerCase()) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: "TDX quote rejected: MRTD measurement mismatch",
    };
  }

  if (quote.reportData.toLowerCase() !== opts.expectedReportData.toLowerCase()) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: "TDX quote rejected: REPORT_DATA session binding mismatch",
    };
  }

  const payload = canonicalTdxQuotePayload({
    teeType: quote.teeType,
    mrtd: quote.mrtd,
    rtmr0: quote.rtmr0,
    reportData: quote.reportData,
    tdAttributesDebug: quote.tdAttributesDebug,
    tcbSvn: quote.tcbSvn,
  });

  if (!p256VerifyHex(quote.pckSignatureHex, payload, quote.pckPublicKeyHex)) {
    return {
      accepted: false,
      tier: "B",
      assuranceWarning: TIER_B_ASSURANCE_WARNING,
      reason: "TDX quote rejected: invalid PCK P-256 ECDSA signature",
    };
  }

  return {
    accepted: true,
    tier: "B",
    assuranceWarning: TIER_B_ASSURANCE_WARNING,
    reason: "Intel TDX Quote v4 verified (Tier B opt-in active)",
  };
}

/**
 * Helper to create a complete 10-device (8 GPUs + 1 NIC + 1 NVMe) SPDM 1.2 + TEE-IO evidence bundle.
 */
export function createSampleTierAPlusEvidence(params?: {
  nodeId?: string;
  cpuModel?: string;
  teeIoBoundVmId?: string;
  signedVmId?: string;
}): TierAPlusEvidence {
  const nodeId = params?.nodeId ?? "tier-aplus-node-1";
  const cpuModel = params?.cpuModel ?? RISER_PROOF_CPU_ALLOWLIST[1];
  const teeIoBoundVmId = params?.teeIoBoundVmId ?? "cvm-snp-vm-001";
  const signedVmId = params?.signedVmId ?? teeIoBoundVmId;

  const specs: { deviceId: string; deviceClass: SpdmDeviceClass }[] = [
    { deviceId: "gpu-0", deviceClass: "GPU" },
    { deviceId: "gpu-1", deviceClass: "GPU" },
    { deviceId: "gpu-2", deviceClass: "GPU" },
    { deviceId: "gpu-3", deviceClass: "GPU" },
    { deviceId: "gpu-4", deviceClass: "GPU" },
    { deviceId: "gpu-5", deviceClass: "GPU" },
    { deviceId: "gpu-6", deviceClass: "GPU" },
    { deviceId: "gpu-7", deviceClass: "GPU" },
    { deviceId: "nic-0", deviceClass: "NIC" },
    { deviceId: "nvme-0", deviceClass: "NVME" },
  ];

  const devices: SpdmDeviceMeasurement[] = specs.map((spec) => {
    const digest = bytesToHex(
      sha384(utf8ToBytes(`spdm-fw-measurement/${spec.deviceClass}/${spec.deviceId}/v1`)),
    );
    const nonceHex = bytesToHex(
      sha256(utf8ToBytes(`spdm-nonce/${nodeId}/${spec.deviceId}`)),
    );
    const { secretKey, publicKeyHex } = deriveDeterministicP256KeyPair(
      `spdm-device-key/${nodeId}/${spec.deviceId}`,
    );
    const payload = canonicalSpdmPayload(
      {
        deviceId: spec.deviceId,
        deviceClass: spec.deviceClass,
        spdmVersion: "1.2",
        measurementDigestHex: digest,
        nonceHex,
      },
      signedVmId,
    );
    const signatureHex = p256SignHex(payload, secretKey);

    return {
      deviceId: spec.deviceId,
      deviceClass: spec.deviceClass,
      spdmVersion: "1.2",
      measurementDigestHex: digest,
      expectedDigestHex: digest,
      nonceHex,
      devicePublicKeyHex: publicKeyHex,
      signatureHex,
    };
  });

  return {
    nodeId,
    cpuModel,
    teeIoBoundVmId,
    devices,
  };
}

/**
 * Verifies Tier A+ evidence (Spec §3 Tier A+):
 * 1. Verifies SPDM 1.2 cryptographic device measurement responses from 8 GPUs, 1 NIC, and 1 NVMe (10 devices).
 * 2. Verifies PCIe TDISP / TEE-IO binding (`teeIoBoundVmId === expectedVmId`) to close the GPU attestation relay gap.
 * 3. Verifies CPU model is in the riser-proof on-package/soldered memory allowlist.
 * Upgrades node to `"A+"` only when all checks pass; otherwise remains at `"A"`.
 */
export function verifyTierAPlusEvidence(
  evidence: TierAPlusEvidence,
  expectedVmId: string,
): VerifyTierAPlusResult {
  const teeIoBound =
    typeof evidence.teeIoBoundVmId === "string" &&
    evidence.teeIoBoundVmId.length > 0 &&
    evidence.teeIoBoundVmId === expectedVmId;

  const riserProofMemory = (RISER_PROOF_CPU_ALLOWLIST as readonly string[]).includes(
    evidence.cpuModel,
  );

  let gpuCount = 0;
  let nicCount = 0;
  let nvmeCount = 0;
  let spdmVerifiedCount = 0;

  for (const dev of evidence.devices) {
    if (dev.spdmVersion !== "1.2") {
      continue;
    }
    if (dev.measurementDigestHex.toLowerCase() !== dev.expectedDigestHex.toLowerCase()) {
      continue;
    }
    const payload = canonicalSpdmPayload(
      {
        deviceId: dev.deviceId,
        deviceClass: dev.deviceClass,
        spdmVersion: dev.spdmVersion,
        measurementDigestHex: dev.measurementDigestHex,
        nonceHex: dev.nonceHex,
      },
      expectedVmId,
    );
    if (!p256VerifyHex(dev.signatureHex, payload, dev.devicePublicKeyHex)) {
      continue;
    }

    spdmVerifiedCount += 1;
    if (dev.deviceClass === "GPU") gpuCount += 1;
    if (dev.deviceClass === "NIC") nicCount += 1;
    if (dev.deviceClass === "NVME") nvmeCount += 1;
  }

  const allDevicesVerified =
    gpuCount === 8 &&
    nicCount >= 1 &&
    nvmeCount >= 1 &&
    spdmVerifiedCount === evidence.devices.length;

  const accepted = allDevicesVerified && teeIoBound && riserProofMemory;

  const reasons: string[] = [];
  if (!allDevicesVerified) {
    reasons.push(
      `SPDM 1.2 device verification incomplete (verified ${spdmVerifiedCount}/${evidence.devices.length}; GPUs=${gpuCount}/8, NIC=${nicCount}/1, NVMe=${nvmeCount}/1)`,
    );
  }
  if (!teeIoBound) {
    reasons.push(
      `TEE-IO binding mismatch (evidence teeIoBoundVmId="${evidence.teeIoBoundVmId}" !== expected "${expectedVmId}")`,
    );
  }
  if (!riserProofMemory) {
    reasons.push(
      `CPU model "${evidence.cpuModel}" is not in the riser-proof on-package/soldered memory allowlist`,
    );
  }

  return {
    accepted,
    tier: accepted ? "A+" : "A",
    spdmVerifiedCount,
    teeIoBound,
    riserProofMemory,
    detail: accepted
      ? `Upgraded to Tier A+: ${spdmVerifiedCount}/10 SPDM 1.2 devices (8x GPU, NIC, NVMe) bound via TEE-IO to ${expectedVmId} on ${evidence.cpuModel}`
      : `Remains Tier A: ${reasons.join("; ")}`,
  };
}
