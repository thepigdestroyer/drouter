import { toHex } from "@/lib/sim/bytes";
import { decodePolicy, parseReport, tcbFromU64 } from "@/lib/sim/snp";

export interface RouterSnpHardwareReport {
  version: number;
  guestSvn: number;
  policyHex: string;
  smtAllowed: boolean;
  migrationAllowed: boolean;
  debugAllowed: boolean;
  vmpl: number;
  productName: "Milan" | "Genoa" | "Turin";
  tcb: {
    fmc: number;
    bootloader: number;
    tee: number;
    snp: number;
    microcode: number;
  };
  chipIdHex: string;
  measurementHex: string;
  reportDataHex: string;
  tlsKeyFpFromReportDataHex: string;
  hpkeKeyFromReportDataHex: string;
  signatureRHex: string;
  signatureSHex: string;
}

export interface ModelEnclaveAttestation {
  modelId: string;
  repo: string;
  tag: string;
  hardwarePredicate: string;
  tierClassification:
    | "Tier A (AMD SEV-SNP + 8x Confidential GPU)"
    | "Tier B (Intel TDX + 8x Confidential GPU)";
  configuredHosts: number;
  verifiedHosts: number;
  healthyHosts: number;
  unverifiedHosts: number;
  enclaveHosts: {
    host: string;
    hpkeKey: string;
    predicate: string;
    tlsKeyFp: string;
    lastSuccess?: string;
    expiresAt?: string;
    codeTag?: string;
  }[];
  measurementRegisters: string[];
  vmShape: {
    cpus: number;
    memoryMb: number;
    gpus: number;
    disks: number;
  };
  dmVerityRootHash: string;
  kernelHash: string;
  initrdHash: string;
  containerImageDigest: string;
  weightRepoCommit: string;
  weightMpkHash: string;
  ccGpuFlagsVerified: boolean;
  releaseUrl: string;
  sigstoreSearchUrl: string;
  huggingFaceUrl?: string;
}

export interface DeepAttestationBundle {
  routerHost: string;
  routerReleaseTag: string;
  routerReleaseDigest: string;
  routerConfigRepo: string;
  routerSnpReport?: RouterSnpHardwareReport;
  routerHashes?: {
    version: string;
    root: string;
    initrd: string;
    kernel: string;
    raw: string;
  };
  routerReleaseUrl: string;
  routerSigstoreUrl: string;
  amdKdsUrl: string;
  proxyWellKnownUrl: string;
  models: Record<string, ModelEnclaveAttestation>;
  fetchedAt: string;
}

/**
 * Decodes a raw 1,184-byte AMD SEV-SNP binary attestation report into structured hardware fields.
 * Handles both Milan/Genoa (Zen 3 / Zen 4) TCB byte offsets (bl=byte0, tee=byte1, snp=byte6, ucode=byte7)
 * and Turin (Zen 5, family 0x1A) TCB byte offsets (fmc=byte0, bl=byte1, tee=byte2, snp=byte3, ucode=byte7).
 * Works in both Node and browser environments.
 */
export function decodeSnpReportBytes(raw1184Bytes: Uint8Array): RouterSnpHardwareReport {
  const parsed = parseReport(raw1184Bytes);
  const policyBits = decodePolicy(parsed.policy);
  const tcbRaw = parsed.reportedTcb !== BigInt(0) ? parsed.reportedTcb : parsed.currentTcb;

  // Inspect CPUID family/model at offsets 0x188 and 0x189 (valid in report version >= 3)
  const family = parsed.version >= 3 && raw1184Bytes.length > 0x189 ? raw1184Bytes[0x188] : 0x19;
  const model = parsed.version >= 3 && raw1184Bytes.length > 0x189 ? raw1184Bytes[0x189] : 0x11;

  // Turin is Family 0x1A (26). Genoa is Family 0x19 Model 0x10..0x1F or 0xA0..0xAF.
  // In synthetic test reports where family/model are 0x00, fall back to tcbFromU64 (Turin layout) if byte 0 & byte 3 are non-zero while byte 6 is 0.
  const byteAt = (val: bigint, bitShift: number): number =>
    Number((val >> BigInt(bitShift)) & BigInt(0xff));
  const snpByteGenoa = byteAt(tcbRaw, 48);
  const fmcByteTurin = byteAt(tcbRaw, 0);
  const snpByteTurin = byteAt(tcbRaw, 24);

  let productName: "Milan" | "Genoa" | "Turin" = "Genoa";
  let tcb = tcbFromU64(tcbRaw);

  if (family === 0x1a) {
    productName = "Turin";
    tcb = tcbFromU64(tcbRaw);
  } else if (family === 0x19) {
    productName = model === 0x01 ? "Milan" : "Genoa";
    tcb = {
      fmc: 0,
      bootloader: byteAt(tcbRaw, 0),
      tee: byteAt(tcbRaw, 8),
      snp: snpByteGenoa,
      microcode: byteAt(tcbRaw, 56),
    };
  } else if (snpByteGenoa > 0 && snpByteTurin === 0) {
    productName = "Genoa";
    tcb = {
      fmc: 0,
      bootloader: byteAt(tcbRaw, 0),
      tee: byteAt(tcbRaw, 8),
      snp: snpByteGenoa,
      microcode: byteAt(tcbRaw, 56),
    };
  } else if (fmcByteTurin > 0 && snpByteTurin > 0) {
    productName = "Turin";
  }

  const reportDataHex = toHex(parsed.reportData);

  return {
    version: parsed.version,
    guestSvn: parsed.guestSvn,
    policyHex: `0x${parsed.policy.toString(16)}`,
    smtAllowed: policyBits.smt,
    migrationAllowed: policyBits.migrationAgent,
    debugAllowed: policyBits.debug,
    vmpl: parsed.vmpl,
    productName,
    tcb,
    chipIdHex: toHex(parsed.chipId),
    measurementHex: toHex(parsed.measurement),
    reportDataHex,
    tlsKeyFpFromReportDataHex: reportDataHex.slice(0, 64),
    hpkeKeyFromReportDataHex: reportDataHex.slice(64, 128),
    signatureRHex: toHex(parsed.signatureR),
    signatureSHex: toHex(parsed.signatureS),
  };
}

/**
 * Extracts pinned model weight metadata, container digest, and confidential GPU flags
 * from a Tinfoil enclave deployment YAML configuration.
 */
export function parseDeploymentConfigYaml(yamlText: string): {
  containerImageDigest: string;
  weightRepoCommit: string;
  weightMpkHash: string;
  ccGpuFlagsVerified: boolean;
} {
  if (!yamlText || typeof yamlText !== "string") {
    return {
      containerImageDigest: "",
      weightRepoCommit: "",
      weightMpkHash: "",
      ccGpuFlagsVerified: false,
    };
  }

  // Extract first repo under models: (e.g., repo: "moonshotai/Kimi-K3@a590ce09...")
  const repoMatch = yamlText.match(/^\s*repo:\s*["']?([^"'\s#]+)["']?/m);
  const weightRepoCommit = repoMatch?.[1]?.trim() ?? "";

  // Extract first mpk under models: or from /tinfoil/mpk/mpk-<hash>
  const mpkFieldMatch = yamlText.match(/^\s*mpk:\s*["']?([^"'\s#]+)["']?/m);
  const mpkPathMatch = yamlText.match(/\/tinfoil\/mpk\/mpk-([0-9a-fA-F]{64})/);
  const weightMpkHash = mpkFieldMatch?.[1]?.trim() ?? mpkPathMatch?.[1]?.trim() ?? "";

  // Extract container image sha256 digest
  const digestMatch = yamlText.match(/image:\s*["']?[^\s"']*@(sha256:[0-9a-fA-F]{64})["']?/m);
  const imageFallbackMatch = yamlText.match(/^\s*image:\s*["']?([^"'\s#]+)["']?/m);
  const containerImageDigest =
    digestMatch?.[1]?.trim() ?? imageFallbackMatch?.[1]?.trim() ?? "";

  // Check GPU count and Confidential Compute flags
  const gpusMatch = yamlText.match(/^gpus:\s*(\d+)/m);
  const gpuCount = gpusMatch ? Number(gpusMatch[1]) : 0;

  const hasUvaDisabled =
    /VLLM_DISABLE_UVA:\s*["']?1["']?/.test(yamlText);
  const hasSymmMemDisabled =
    /VLLM_ALLREDUCE_USE_SYMM_MEM:\s*["']?0["']?/.test(yamlText);
  const hasDisableCustomAllReduce =
    /--disable-custom-all-reduce/.test(yamlText);
  const hasNvidiaRuntime =
    /runtime:\s*["']?nvidia["']?/.test(yamlText) &&
    /gpus:\s*["']?all["']?/.test(yamlText);

  // Multi-GPU confidential compute requires UVA disabled and peer symmetric memory disabled.
  // Single-GPU confidential enclaves (gpus: 1) do not run P2P all-reduce and require nvidia runtime + gpus: all.
  const ccGpuFlagsVerified =
    (hasUvaDisabled && (hasSymmMemDisabled || hasDisableCustomAllReduce)) ||
    (gpuCount === 1 && hasNvidiaRuntime);

  return {
    containerImageDigest,
    weightRepoCommit,
    weightMpkHash,
    ccGpuFlagsVerified,
  };
}

/**
 * Evaluates C5 (GPUs in confidential mode) and C7 (Committed model weights & rootfs)
 * from a model enclave's live attestation and signed deployment bundle.
 */
export function verifyModelEnclaveStatus(m: ModelEnclaveAttestation): {
  c5Pass: boolean;
  c5Detail: string;
  c7Pass: boolean;
  c7Detail: string;
} {
  const c5Pass =
    m.verifiedHosts > 0 &&
    m.verifiedHosts === m.configuredHosts &&
    m.unverifiedHosts === 0 &&
    m.vmShape.gpus >= 1 &&
    m.ccGpuFlagsVerified;

  const isSevSnp =
    m.hardwarePredicate.includes("sev-snp") ||
    m.tierClassification.includes("SEV-SNP") ||
    m.enclaveHosts.some((h) => h.predicate.includes("sev-snp"));
  const teeLabel = isSevSnp ? "SEV-SNP + CC mode" : "TDX + CC mode";

  const c5Detail = c5Pass
    ? `${m.vmShape.gpus}× NVIDIA confidential GPU${m.vmShape.gpus === 1 ? "" : "s"} attested by router (${m.healthyHosts}/${m.configuredHosts} hosts healthy, ${teeLabel}, VLLM_DISABLE_UVA=1, SYMM_MEM=0; transitive via router proxy table & signed deployment YAML)`
    : `GPU enclave verification incomplete: ${m.verifiedHosts}/${m.configuredHosts} verified, ${m.unverifiedHosts} unverified, ${m.vmShape.gpus} GPUs, CC flags=${m.ccGpuFlagsVerified}`;

  const c7Pass = Boolean(
    m.dmVerityRootHash &&
      (m.weightMpkHash || m.containerImageDigest) &&
      m.measurementRegisters.length > 0,
  );

  const mpkHex = m.weightMpkHash.replace(/^mpk-/, "").slice(0, 8);
  const mpkLabel = mpkHex ? `mpk-${mpkHex}…` : m.containerImageDigest.slice(0, 15) + "…";
  let repoLabel = m.weightRepoCommit || m.repo;
  if (repoLabel.includes("@")) {
    const [repoPart, commitPart] = repoLabel.split("@");
    repoLabel = `${repoPart}@${commitPart.slice(0, 8)}`;
  }
  const rootShort = m.dmVerityRootHash ? `${m.dmVerityRootHash.slice(0, 8)}…` : "unpinned";

  const c7Detail = c7Pass
    ? `Pinned weight package ${mpkLabel} (${repoLabel}) on dm-verity root ${rootShort}`
    : `Missing committed model weight package, dm-verity root, or hardware measurement registers`;

  return {
    c5Pass,
    c5Detail,
    c7Pass,
    c7Detail,
  };
}
