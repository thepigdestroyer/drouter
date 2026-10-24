import { gunzipSync } from "node:zlib";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  decodeSnpReportBytes,
  decodeTdxQuoteBytes,
  verifyAmdSevSnpChainEndToEnd,
  verifyTdxQuoteEndToEnd,
  type RouterSnpHardwareReport,
  type SnpChainVerificationResult,
  type TdxQuoteParsed,
  type TdxQuoteVerificationResult,
} from "@/lib/tinfoil/deep-inspect";

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

export function canonicalTdxQuotePayload(
  quote: Omit<TdxQuoteV4, "pckSignatureHex" | "pckPublicKeyHex">,
): Uint8Array {
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

export function canonicalSpdmPayload(
  device: Omit<
    SpdmDeviceMeasurement,
    "signatureHex" | "devicePublicKeyHex" | "expectedDigestHex"
  >,
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

export function p256VerifyHex(
  signatureHex: string,
  message: Uint8Array,
  publicKeyHex: string,
): boolean {
  try {
    const sigBytes = hexToBytes(signatureHex);
    const pubBytes = hexToBytes(publicKeyHex);
    const digest = sha256(message);
    return p256.verify(sigBytes, digest, pubBytes, { prehash: false, lowS: false });
  } catch {
    return false;
  }
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
      reason:
        "TDX quote rejected: TD_ATTRIBUTES.DEBUG bit is set (debug TDs cannot serve production traffic)",
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

export interface LiveQuoteVerificationMeasurements {
  tierASevSnpRouter: {
    host: string;
    report: RouterSnpHardwareReport | null;
    verification: SnpChainVerificationResult | null;
    measuredVerifyLatencyMs: number | null;
  };
  tierAPlusTurinEnclave: {
    modelId: string;
    host: string;
    report: RouterSnpHardwareReport | null;
    verification: SnpChainVerificationResult | null;
    measuredVerifyLatencyMs: number | null;
  };
  tierBTdxEnclave: {
    modelId: string;
    host: string;
    parsedQuote: TdxQuoteParsed | null;
    verification: TdxQuoteVerificationResult | null;
    measuredVerifyLatencyMs: number | null;
  };
}

interface RawLiveQuoteCache {
  fetchedAt: number;
  routerHost: string;
  routerRawBytes: Uint8Array | null;
  routerVcek: string | null;
  genoaChainPem: string | null;
  turinModelId: string;
  turinHost: string;
  turinRawBytes: Uint8Array | null;
  turinVcekDer: Uint8Array | null;
  turinChainPem: string | null;
  tdxModelId: string;
  tdxHost: string;
  tdxRawBytes: Uint8Array | null;
  tdxRtmr1Hex?: string;
  tdxRtmr2Hex?: string;
}

const LIVE_QUOTE_CACHE_TTL_MS = 60_000;
let cachedRawLiveQuotes: RawLiveQuoteCache | null = null;

async function fetchJsonWithTimeout<T>(url: string, timeoutMs = 4500): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
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

async function fetchTextWithTimeout(url: string, timeoutMs = 4500): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
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

async function fetchBytesWithTimeout(url: string, timeoutMs = 4500): Promise<Uint8Array | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      cache: "no-store",
    });
    if (!res.ok) return null;
    return new Uint8Array(await res.arrayBuffer());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function getOrFetchRawLiveQuotes(): Promise<RawLiveQuoteCache> {
  const now = Date.now();
  if (cachedRawLiveQuotes && now - cachedRawLiveQuotes.fetchedAt < LIVE_QUOTE_CACHE_TTL_MS) {
    return cachedRawLiveQuotes;
  }

  const [atc, proxy, genoaChainPem, turinChainPem] = await Promise.all([
    fetchJsonWithTimeout<{
      domain?: string;
      vcek?: string;
      enclaveAttestationReport?: { body?: string };
    }>("https://atc.tinfoil.sh/attestation", 4500),
    fetchJsonWithTimeout<{
      models?: Record<
        string,
        {
          tag?: string;
          measurement?: { registers?: string[] };
          enclaves?: Record<string, { predicate?: string }>;
          verification?: { hosts?: Record<string, { code_tag?: string }> };
        }
      >;
    }>("https://inference.tinfoil.sh/.well-known/tinfoil-proxy", 4500),
    fetchTextWithTimeout("https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain", 4000),
    fetchTextWithTimeout("https://kdsintf.amd.com/vcek/v1/Turin/cert_chain", 4000),
  ]);

  let routerRawBytes: Uint8Array | null = null;
  if (atc?.enclaveAttestationReport?.body) {
    try {
      routerRawBytes = new Uint8Array(
        gunzipSync(Buffer.from(atc.enclaveAttestationReport.body, "base64")),
      );
    } catch {
      routerRawBytes = null;
    }
  }

  // Pick live AMD Turin SEV-SNP model enclave (glm-5-3) and live Intel TDX v4 model enclave (deepseek-v4-1-flash)
  const glmEntry = proxy?.models?.["glm-5-3"];
  const glmHost = glmEntry?.enclaves ? Object.keys(glmEntry.enclaves)[0] ?? "" : "";

  const dsEntry = proxy?.models?.["deepseek-v4-1-flash"];
  const dsHost = dsEntry?.enclaves
    ? (Object.keys(dsEntry.enclaves).find(
        (h) => dsEntry.verification?.hosts?.[h]?.code_tag === dsEntry.tag,
      ) ??
        Object.keys(dsEntry.enclaves)[0] ??
        "")
    : "";

  const [glmAtt, dsAtt] = await Promise.all([
    glmHost
      ? fetchJsonWithTimeout<{ format?: string; body?: string }>(
          `https://${glmHost}/.well-known/tinfoil-attestation`,
          3500,
        )
      : Promise.resolve(null),
    dsHost
      ? fetchJsonWithTimeout<{ format?: string; body?: string }>(
          `https://${dsHost}/.well-known/tinfoil-attestation`,
          3500,
        )
      : Promise.resolve(null),
  ]);

  let turinRawBytes: Uint8Array | null = null;
  let turinVcekDer: Uint8Array | null = null;
  if (glmAtt?.body) {
    try {
      turinRawBytes = new Uint8Array(gunzipSync(Buffer.from(glmAtt.body, "base64")));
      const decoded = decodeSnpReportBytes(turinRawBytes);
      const chipIdShort =
        decoded.productName === "Turin" ? decoded.chipIdHex.slice(0, 16) : decoded.chipIdHex;
      const fmcParam = decoded.productName === "Turin" ? `&fmcSPL=${decoded.tcb.fmc}` : "";
      const vcekUrl = `https://kdsintf.amd.com/vcek/v1/${decoded.productName}/${chipIdShort}?blSPL=${decoded.tcb.bootloader}&teeSPL=${decoded.tcb.tee}&snpSPL=${decoded.tcb.snp}&ucodeSPL=${decoded.tcb.microcode}${fmcParam}`;
      turinVcekDer = await fetchBytesWithTimeout(vcekUrl, 3500);
    } catch {
      turinRawBytes = null;
    }
  }

  let tdxRawBytes: Uint8Array | null = null;
  if (dsAtt?.body) {
    try {
      tdxRawBytes = new Uint8Array(gunzipSync(Buffer.from(dsAtt.body, "base64")));
    } catch {
      tdxRawBytes = null;
    }
  }

  const entry: RawLiveQuoteCache = {
    fetchedAt: Date.now(),
    routerHost: atc?.domain ?? "router-0.tinfoil.sh",
    routerRawBytes,
    routerVcek: atc?.vcek ?? null,
    genoaChainPem,
    turinModelId: "glm-5-3",
    turinHost: glmHost,
    turinRawBytes,
    turinVcekDer,
    turinChainPem,
    tdxModelId: "deepseek-v4-1-flash",
    tdxHost: dsHost,
    tdxRawBytes,
    tdxRtmr1Hex: dsEntry?.measurement?.registers?.[1],
    tdxRtmr2Hex: dsEntry?.measurement?.registers?.[2],
  };

  if (routerRawBytes || turinRawBytes || tdxRawBytes) {
    cachedRawLiveQuotes = entry;
  }
  return entry;
}

/**
 * Measures real cryptographic hardware quote verification time on live quotes fetched from Tinfoil:
 * 1. Tier A: Live AMD SEV-SNP (Genoa) 1,184-byte report + VCEK/ASK/ARK chain on `router-0.tinfoil.sh`
 * 2. Tier A+: Live AMD EPYC 9005 (Turin) SEV-SNP 1,184-byte report + VCEK/ASK/ARK chain on `glm-5-3` enclave
 * 3. Tier B: Live Intel TDX Quote v4 + PCK chain + QE report + RTMR1/RTMR2 on `deepseek-v4-1-flash` enclave
 */
export async function measureLiveTinfoilQuoteVerifications(): Promise<LiveQuoteVerificationMeasurements> {
  const raw = await getOrFetchRawLiveQuotes();

  // 1. Measure live Tier A AMD SEV-SNP Genoa router verification
  let routerReport: RouterSnpHardwareReport | null = null;
  let routerVerification: SnpChainVerificationResult | null = null;
  let routerVerifyMs: number | null = null;
  if (raw.routerRawBytes && raw.routerVcek && raw.genoaChainPem) {
    const t0 = performance.now();
    routerReport = decodeSnpReportBytes(raw.routerRawBytes);
    routerVerification = await verifyAmdSevSnpChainEndToEnd(
      raw.routerRawBytes,
      raw.routerVcek,
      raw.genoaChainPem,
    );
    routerVerifyMs = Number(Math.max(0.01, performance.now() - t0).toFixed(3));
  }

  // 2. Measure live Tier A+ AMD EPYC 9005 Turin SEV-SNP model enclave verification
  let turinReport: RouterSnpHardwareReport | null = null;
  let turinVerification: SnpChainVerificationResult | null = null;
  let turinVerifyMs: number | null = null;
  if (raw.turinRawBytes && raw.turinVcekDer && raw.turinChainPem) {
    const t0 = performance.now();
    turinReport = decodeSnpReportBytes(raw.turinRawBytes);
    turinVerification = await verifyAmdSevSnpChainEndToEnd(
      raw.turinRawBytes,
      raw.turinVcekDer,
      raw.turinChainPem,
    );
    turinVerifyMs = Number(Math.max(0.01, performance.now() - t0).toFixed(3));
  }

  // 3. Measure live Tier B Intel TDX Quote v4 model enclave verification
  let tdxParsed: TdxQuoteParsed | null = null;
  let tdxVerification: TdxQuoteVerificationResult | null = null;
  let tdxVerifyMs: number | null = null;
  if (raw.tdxRawBytes) {
    const t0 = performance.now();
    tdxParsed = decodeTdxQuoteBytes(raw.tdxRawBytes);
    tdxVerification = await verifyTdxQuoteEndToEnd(raw.tdxRawBytes, {
      rtmr1Hex: raw.tdxRtmr1Hex,
      rtmr2Hex: raw.tdxRtmr2Hex,
    });
    tdxVerifyMs = Number(Math.max(0.01, performance.now() - t0).toFixed(3));
  }

  return {
    tierASevSnpRouter: {
      host: raw.routerHost,
      report: routerReport,
      verification: routerVerification,
      measuredVerifyLatencyMs: routerVerifyMs,
    },
    tierAPlusTurinEnclave: {
      modelId: raw.turinModelId,
      host: raw.turinHost,
      report: turinReport,
      verification: turinVerification,
      measuredVerifyLatencyMs: turinVerifyMs,
    },
    tierBTdxEnclave: {
      modelId: raw.tdxModelId,
      host: raw.tdxHost,
      parsedQuote: tdxParsed,
      verification: tdxVerification,
      measuredVerifyLatencyMs: tdxVerifyMs,
    },
  };
}
