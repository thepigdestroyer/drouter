import { ASN1Obj, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { X509Certificate } from "@freedomofpress/sigstore-browser";
import { fromHex, toHex } from "@/lib/sim/bytes";
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

export interface SnpChainVerificationResult {
  verified: boolean;
  productName: "Milan" | "Genoa" | "Turin";
  arkSubject: string;
  askSubject: string;
  vcekSubject: string;
  arkFingerprintSha256: string;
  askFingerprintSha256: string;
  vcekFingerprintSha256: string;
  arkSelfSigned: boolean;
  askSignedByArk: boolean;
  vcekSignedByAsk: boolean;
  vcekTcbMatched: boolean;
  vcekHwidMatched: boolean;
  reportSignatureVerified: boolean;
  kdsVcekUrl: string;
  kdsCertChainUrl: string;
  error?: string;
}

export interface TdxQuoteParsed {
  version: number;
  attKeyType: number;
  teeType: number;
  teeTcbSvnHex: string;
  mrSeamHex: string;
  mrSignerSeamHex: string;
  mrTdHex: string;
  rtmr0Hex: string;
  rtmr1Hex: string;
  rtmr2Hex: string;
  rtmr3Hex: string;
  reportDataHex: string;
  tlsKeyFpHex: string;
  hpkeKeyHex: string;
  ecdsaSigHex: string;
  ecdsaAttKeyHex: string;
  qeReportHex: string;
  qeReportDataHex: string;
  qeReportSigHex: string;
  qeAuthDataHex: string;
  pckCertChainPems: string[];
}

export interface TdxQuoteVerificationResult {
  verified: boolean;
  version: number;
  teeType: number;
  mrTdHex: string;
  rtmr0Hex: string;
  rtmr1Hex: string;
  rtmr2Hex: string;
  rtmr3Hex: string;
  reportDataHex: string;
  tlsKeyFpHex: string;
  hpkeKeyHex: string;
  pckLeafSubject: string;
  pckCaSubject: string;
  rootCaSubject: string;
  pckChainVerified: boolean;
  qeReportSignatureVerified: boolean;
  attKeyBindingVerified: boolean;
  quoteBodySignatureVerified: boolean;
  rtmr1Matched: boolean;
  rtmr2Matched: boolean;
  error?: string;
}

export interface NvidiaEatVerificationResult {
  verified: boolean;
  kid?: string;
  alg?: string;
  issuer?: string;
  overallAttResult?: boolean;
  secboot?: boolean;
  dbgstat?: string;
  error?: string;
}

export interface ModelEnclaveAttestation {
  modelId: string;
  status?: "verified" | "router-attested" | "unavailable";
  unavailableReason?: string;
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
  sigstoreVerified?: boolean;
  sigstoreReleaseDigest?: string;
  registersMatchSigstore?: boolean;
  directQuoteVerified?: boolean;
  directQuoteFormat?: string;
  directQuoteHost?: string;
  directQuoteCertVerified?: boolean;
  directQuoteError?: string;
  snpChainVerification?: SnpChainVerificationResult;
  tdxQuoteVerification?: TdxQuoteVerificationResult;
  nvidiaEatExposed?: boolean;
  nvidiaEatVerified?: boolean;
  nvidiaJwksReachable?: boolean;
  verificationBreakdown?: {
    cryptographicallyVerified: string[];
    trustedFromRouter: string[];
  };
}

export interface DeepAttestationBundle {
  status?: "verified" | "partial" | "unavailable";
  unavailable?: boolean;
  unavailableReason?: string;
  routerHost: string;
  routerReleaseTag: string;
  routerReleaseDigest: string;
  routerConfigRepo: string;
  routerSnpReport?: RouterSnpHardwareReport;
  routerSnpChain?: SnpChainVerificationResult;
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

const SNP_OID = {
  BL_SPL: "1.3.6.1.4.1.3704.1.3.1",
  TEE_SPL: "1.3.6.1.4.1.3704.1.3.2",
  SNP_SPL: "1.3.6.1.4.1.3704.1.3.3",
  UCODE: "1.3.6.1.4.1.3704.1.3.8",
  HWID: "1.3.6.1.4.1.3704.1.4",
  CSP_ID: "1.3.6.1.4.1.3704.1.5",
} as const;

function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[\r\n\s]/g, "");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return base64ToBytes(b64 + pad);
}

function pemToDerBytes(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/[\r\n\s]/g, "");
  return base64ToBytes(body);
}

async function sha256HexBytes(data: Uint8Array): Promise<string> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return toHex(new Uint8Array(digest));
}

function formatDn(dn: Map<string, string>): string {
  const parts: string[] = [];
  for (const key of ["CN", "OU", "O", "L", "ST", "C"]) {
    const val = dn.get(key);
    if (val) parts.push(`${key}=${val}`);
  }
  return parts.join(", ");
}

function decodeAsn1Integer(value: Uint8Array): number {
  const asn1 = ASN1Obj.parseBuffer(value);
  return Number(asn1.toInteger());
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
 * Cryptographically verifies an AMD SEV-SNP hardware report and its X.509 certificate chain
 * end-to-end: ARK (self-signed AMD root) -> ASK (AMD SEV intermediate) -> VCEK (chip-unique leaf),
 * VCEK X.509 OID extensions (BL_SPL, TEE_SPL, SNP_SPL, UCODE, HWID), and the ECDSA P-384 / SHA-384
 * signature over bytes 0x000..0x29F of the 1,184-byte binary report.
 * Supports Genoa, Turin, and Milan processor families.
 */
export async function verifyAmdSevSnpChainEndToEnd(
  raw1184Bytes: Uint8Array,
  vcekDerOrBase64: Uint8Array | string,
  askArkPemChain: string,
): Promise<SnpChainVerificationResult> {
  const decoded = decodeSnpReportBytes(raw1184Bytes);
  const chipIdForKds =
    decoded.productName === "Turin" ? decoded.chipIdHex.slice(0, 16) : decoded.chipIdHex;
  const fmcParam = decoded.productName === "Turin" ? `&fmcSPL=${decoded.tcb.fmc}` : "";
  const kdsVcekUrl = `https://kdsintf.amd.com/vcek/v1/${decoded.productName}/${chipIdForKds}?blSPL=${decoded.tcb.bootloader}&teeSPL=${decoded.tcb.tee}&snpSPL=${decoded.tcb.snp}&ucodeSPL=${decoded.tcb.microcode}${fmcParam}`;
  const kdsCertChainUrl = `https://kdsintf.amd.com/vcek/v1/${decoded.productName}/cert_chain`;

  try {
    const vcekDer =
      typeof vcekDerOrBase64 === "string" ? base64ToBytes(vcekDerOrBase64) : vcekDerOrBase64;
    const pems =
      askArkPemChain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
    const askPem = pems[0];
    const arkPem = pems[1];
    if (!askPem || !arkPem) {
      throw new Error("AMD KDS cert_chain must contain ASK and ARK PEM certificates");
    }

    const askDer = pemToDerBytes(askPem);
    const arkDer = pemToDerBytes(arkPem);
    const vcek = X509Certificate.parse(vcekDer);
    const ask = X509Certificate.parse(askPem);
    const ark = X509Certificate.parse(arkPem);

    const [arkFp, askFp, vcekFp] = await Promise.all([
      sha256HexBytes(arkDer),
      sha256HexBytes(askDer),
      sha256HexBytes(vcekDer),
    ]);

    const now = new Date();
    if (!ark.validForDate(now)) {
      throw new Error("AMD Root Key (ARK) certificate is outside its validity window");
    }
    if (!ask.validForDate(now)) {
      throw new Error("AMD SEV Key (ASK) certificate is outside its validity window");
    }
    if (!vcek.validForDate(now)) {
      throw new Error("AMD VCEK leaf certificate is outside its validity window");
    }

    const expectedArkCn = `ARK-${decoded.productName}`;
    const expectedAskCn = `SEV-${decoded.productName}`;
    const arkCn = ark.subjectDN.get("CN") ?? "";
    const askCn = ask.subjectDN.get("CN") ?? "";
    const vcekCn = vcek.subjectDN.get("CN") ?? "";

    if (arkCn !== expectedArkCn) {
      throw new Error(`ARK common name mismatch: expected ${expectedArkCn}, got ${arkCn}`);
    }
    if (askCn !== expectedAskCn) {
      throw new Error(`ASK common name mismatch: expected ${expectedAskCn}, got ${askCn}`);
    }
    if (vcekCn !== "SEV-VCEK") {
      throw new Error(`VCEK common name mismatch: expected SEV-VCEK, got ${vcekCn}`);
    }
    if (vcek.extension(SNP_OID.CSP_ID)) {
      throw new Error("Certificate contains CSP_ID extension (VLEK not allowed for VCEK report)");
    }

    const arkSelfSigned = await ark.verify();
    const askSignedByArk = await ask.verify(ark);
    const vcekSignedByAsk = await vcek.verify(ask);

    // Check VCEK OID extensions against report TCB
    const blExt = vcek.extension(SNP_OID.BL_SPL);
    const teeExt = vcek.extension(SNP_OID.TEE_SPL);
    const snpExt = vcek.extension(SNP_OID.SNP_SPL);
    const ucodeExt = vcek.extension(SNP_OID.UCODE);
    const vcekTcbMatched = Boolean(
      blExt &&
        teeExt &&
        snpExt &&
        ucodeExt &&
        decodeAsn1Integer(blExt.value) === decoded.tcb.bootloader &&
        decodeAsn1Integer(teeExt.value) === decoded.tcb.tee &&
        decodeAsn1Integer(snpExt.value) === decoded.tcb.snp &&
        decodeAsn1Integer(ucodeExt.value) === decoded.tcb.microcode,
    );

    // Check HWID extension (64 bytes on Milan/Genoa, 8 bytes on Turin)
    const hwidExt = vcek.extension(SNP_OID.HWID);
    const rawChipId = fromHex(decoded.chipIdHex);
    const signerInfo = new DataView(
      raw1184Bytes.buffer,
      raw1184Bytes.byteOffset,
      raw1184Bytes.byteLength,
    ).getUint32(0x48, true);
    const maskChipKey = Boolean(signerInfo & 2);
    let vcekHwidMatched = false;
    if (maskChipKey) {
      vcekHwidMatched = rawChipId.every((b) => b === 0);
    } else if (hwidExt) {
      if (hwidExt.value.length === 64) {
        vcekHwidMatched = uint8ArrayEqual(hwidExt.value, rawChipId);
      } else if (hwidExt.value.length === 8) {
        vcekHwidMatched = uint8ArrayEqual(hwidExt.value, rawChipId.subarray(0, 8));
      }
    }

    // Verify ECDSA P-384 / SHA-384 signature over bytes 0x000..0x29F
    const rLE = raw1184Bytes.subarray(0x2a0, 0x2a0 + 48);
    const sLE = raw1184Bytes.subarray(0x2e8, 0x2e8 + 48);
    const rawSig96 = new Uint8Array(96);
    for (let i = 0; i < 48; i++) {
      rawSig96[i] = rLE[47 - i];
      rawSig96[48 + i] = sLE[47 - i];
    }
    const signedData = new Uint8Array(0x2a0);
    signedData.set(raw1184Bytes.subarray(0, 0x2a0));
    const vcekPublicKey = await vcek.publicKeyObj;
    const reportSignatureVerified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      vcekPublicKey,
      rawSig96.buffer,
      signedData.buffer,
    );

    const verified =
      arkSelfSigned &&
      askSignedByArk &&
      vcekSignedByAsk &&
      vcekTcbMatched &&
      vcekHwidMatched &&
      reportSignatureVerified &&
      !decoded.debugAllowed &&
      !decoded.migrationAllowed;

    return {
      verified,
      productName: decoded.productName,
      arkSubject: formatDn(ark.subjectDN),
      askSubject: formatDn(ask.subjectDN),
      vcekSubject: formatDn(vcek.subjectDN),
      arkFingerprintSha256: arkFp,
      askFingerprintSha256: askFp,
      vcekFingerprintSha256: vcekFp,
      arkSelfSigned,
      askSignedByArk,
      vcekSignedByAsk,
      vcekTcbMatched,
      vcekHwidMatched,
      reportSignatureVerified,
      kdsVcekUrl,
      kdsCertChainUrl,
      ...(verified
        ? {}
        : {
            error: "One or more AMD SEV-SNP certificate chain or signature checks failed",
          }),
    };
  } catch (err) {
    return {
      verified: false,
      productName: decoded.productName,
      arkSubject: "",
      askSubject: "",
      vcekSubject: "",
      arkFingerprintSha256: "",
      askFingerprintSha256: "",
      vcekFingerprintSha256: "",
      arkSelfSigned: false,
      askSignedByArk: false,
      vcekSignedByAsk: false,
      vcekTcbMatched: false,
      vcekHwidMatched: false,
      reportSignatureVerified: false,
      kdsVcekUrl,
      kdsCertChainUrl,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Parses a raw binary Intel TDX v4 Quote (header + 584-byte TD Quote Body + ECDSA-P256 QE certification data).
 */
export function decodeTdxQuoteBytes(rawQuoteBytes: Uint8Array): TdxQuoteParsed {
  if (rawQuoteBytes.byteLength < 1226) {
    throw new Error(`TDX quote too short: ${rawQuoteBytes.byteLength} bytes`);
  }
  const dv = new DataView(
    rawQuoteBytes.buffer,
    rawQuoteBytes.byteOffset,
    rawQuoteBytes.byteLength,
  );
  const version = dv.getUint16(0, true);
  const attKeyType = dv.getUint16(2, true);
  const teeType = dv.getUint32(4, true);
  if (version !== 4 || teeType !== 0x81) {
    throw new Error(
      `Unsupported TDX quote header: version=${version} (expected 4), teeType=0x${teeType.toString(16)} (expected 0x81)`,
    );
  }

  const bodySlice = (off: number, len: number) =>
    toHex(rawQuoteBytes.subarray(48 + off, 48 + off + len));
  const reportDataHex = bodySlice(520, 64);

  const ecdsaSigHex = toHex(rawQuoteBytes.subarray(636, 700));
  const ecdsaAttKeyHex = toHex(rawQuoteBytes.subarray(700, 764));
  const qeCertType = dv.getUint16(764, true);
  if (qeCertType !== 6) {
    throw new Error(`Unsupported TDX QE certification data type: ${qeCertType} (expected 6)`);
  }
  const qeReportHex = toHex(rawQuoteBytes.subarray(770, 1154));
  const qeReportDataHex = toHex(rawQuoteBytes.subarray(770 + 320, 770 + 352));
  const qeReportSigHex = toHex(rawQuoteBytes.subarray(1154, 1218));
  const authDataSize = dv.getUint16(1218, true);
  const qeAuthDataHex = toHex(rawQuoteBytes.subarray(1220, 1220 + authDataSize));

  const innerCertOff = 1220 + authDataSize;
  const innerCertSize = dv.getUint32(innerCertOff + 2, true);
  const pemChainText = new TextDecoder().decode(
    rawQuoteBytes.subarray(innerCertOff + 6, innerCertOff + 6 + innerCertSize),
  );
  const pckCertChainPems =
    pemChainText.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];

  return {
    version,
    attKeyType,
    teeType,
    teeTcbSvnHex: bodySlice(0, 16),
    mrSeamHex: bodySlice(16, 48),
    mrSignerSeamHex: bodySlice(64, 48),
    mrTdHex: bodySlice(136, 48),
    rtmr0Hex: bodySlice(328, 48),
    rtmr1Hex: bodySlice(376, 48),
    rtmr2Hex: bodySlice(424, 48),
    rtmr3Hex: bodySlice(472, 48),
    reportDataHex,
    tlsKeyFpHex: reportDataHex.slice(0, 64),
    hpkeKeyHex: reportDataHex.slice(64, 128),
    ecdsaSigHex,
    ecdsaAttKeyHex,
    qeReportHex,
    qeReportDataHex,
    qeReportSigHex,
    qeAuthDataHex,
    pckCertChainPems,
  };
}

/**
 * Cryptographically verifies an Intel TDX v4 Quote end-to-end:
 * 1. Embedded Intel SGX/TDX PCK X.509 certificate chain (PCK Leaf -> PCK CA -> Intel SGX Root CA)
 * 2. ECDSA P-256 signature over the 384-byte Quoting Enclave (QE) report using the PCK Leaf certificate
 * 3. QE Report REPORT_DATA[0..32] == SHA-256(ecdsa_att_key || qe_auth_data)
 * 4. ECDSA P-256 signature over the 632-byte TD Quote Header+Body using ecdsa_att_key
 * 5. Measurement register comparison (RTMR1 and RTMR2 against expected Sigstore release values)
 */
export async function verifyTdxQuoteEndToEnd(
  rawQuoteBytes: Uint8Array,
  expected?: { rtmr1Hex?: string; rtmr2Hex?: string },
): Promise<TdxQuoteVerificationResult> {
  try {
    const parsed = decodeTdxQuoteBytes(rawQuoteBytes);
    if (parsed.pckCertChainPems.length < 3) {
      throw new Error(
        `TDX quote PCK certificate chain has ${parsed.pckCertChainPems.length} certs (expected 3)`,
      );
    }

    const [pckLeaf, pckCa, sgxRoot] = parsed.pckCertChainPems.map((pem) =>
      X509Certificate.parse(pem),
    );
    const now = new Date();
    if (!pckLeaf.validForDate(now) || !pckCa.validForDate(now) || !sgxRoot.validForDate(now)) {
      throw new Error("One or more Intel SGX/TDX PCK certificates have expired");
    }

    const rootCn = sgxRoot.subjectDN.get("CN") ?? "";
    const rootOrg = sgxRoot.subjectDN.get("O") ?? "";
    const pckByCa = await pckLeaf.verify(pckCa);
    const caByRoot = await pckCa.verify(sgxRoot);
    const rootSelf = await sgxRoot.verify();
    const pckChainVerified =
      pckByCa &&
      caByRoot &&
      rootSelf &&
      rootCn === "Intel SGX Root CA" &&
      rootOrg === "Intel Corporation";

    // Verify QE report ECDSA P-256 signature by PCK Leaf
    const pckLeafKey = await pckLeaf.publicKeyObj;
    const qeReportBytes = fromHex(parsed.qeReportHex);
    const qeReportSigBytes = fromHex(parsed.qeReportSigHex);
    const qeReportSignatureVerified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pckLeafKey,
      qeReportSigBytes.buffer as ArrayBuffer,
      qeReportBytes.buffer as ArrayBuffer,
    );

    // Verify QE report_data[0..32] == SHA256(attKey || qeAuthData)
    const attKeyBytes = fromHex(parsed.ecdsaAttKeyHex);
    const authDataBytes = fromHex(parsed.qeAuthDataHex);
    const combinedAttAuth = new Uint8Array(attKeyBytes.length + authDataBytes.length);
    combinedAttAuth.set(attKeyBytes, 0);
    combinedAttAuth.set(authDataBytes, attKeyBytes.length);
    const expectedQeDataHex = await sha256HexBytes(combinedAttAuth);
    const attKeyBindingVerified =
      parsed.qeReportDataHex.toLowerCase() === expectedQeDataHex.toLowerCase();

    // Verify TD Quote Header+Body (0..632) ECDSA P-256 signature using ecdsaAttKey
    const uncompressedAttKey = new Uint8Array(65);
    uncompressedAttKey[0] = 0x04;
    uncompressedAttKey.set(attKeyBytes, 1);
    const attCryptoKey = await crypto.subtle.importKey(
      "raw",
      uncompressedAttKey.buffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const quoteSignedBytes = new Uint8Array(632);
    quoteSignedBytes.set(rawQuoteBytes.subarray(0, 632));
    const ecdsaSigBytes = fromHex(parsed.ecdsaSigHex);
    const quoteBodySignatureVerified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      attCryptoKey,
      ecdsaSigBytes.buffer as ArrayBuffer,
      quoteSignedBytes.buffer,
    );

    const rtmr1Matched = expected?.rtmr1Hex
      ? parsed.rtmr1Hex.toLowerCase() === expected.rtmr1Hex.toLowerCase()
      : true;
    const rtmr2Matched = expected?.rtmr2Hex
      ? parsed.rtmr2Hex.toLowerCase() === expected.rtmr2Hex.toLowerCase()
      : true;

    const verified =
      pckChainVerified &&
      qeReportSignatureVerified &&
      attKeyBindingVerified &&
      quoteBodySignatureVerified &&
      rtmr1Matched &&
      rtmr2Matched;

    return {
      verified,
      version: parsed.version,
      teeType: parsed.teeType,
      mrTdHex: parsed.mrTdHex,
      rtmr0Hex: parsed.rtmr0Hex,
      rtmr1Hex: parsed.rtmr1Hex,
      rtmr2Hex: parsed.rtmr2Hex,
      rtmr3Hex: parsed.rtmr3Hex,
      reportDataHex: parsed.reportDataHex,
      tlsKeyFpHex: parsed.tlsKeyFpHex,
      hpkeKeyHex: parsed.hpkeKeyHex,
      pckLeafSubject: formatDn(pckLeaf.subjectDN),
      pckCaSubject: formatDn(pckCa.subjectDN),
      rootCaSubject: formatDn(sgxRoot.subjectDN),
      pckChainVerified,
      qeReportSignatureVerified,
      attKeyBindingVerified,
      quoteBodySignatureVerified,
      rtmr1Matched,
      rtmr2Matched,
      ...(verified
        ? {}
        : {
            error: "One or more Intel TDX quote cryptographic or RTMR checks failed",
          }),
    };
  } catch (err) {
    return {
      verified: false,
      version: 0,
      teeType: 0,
      mrTdHex: "",
      rtmr0Hex: "",
      rtmr1Hex: "",
      rtmr2Hex: "",
      rtmr3Hex: "",
      reportDataHex: "",
      tlsKeyFpHex: "",
      hpkeKeyHex: "",
      pckLeafSubject: "",
      pckCaSubject: "",
      rootCaSubject: "",
      pckChainVerified: false,
      qeReportSignatureVerified: false,
      attKeyBindingVerified: false,
      quoteBodySignatureVerified: false,
      rtmr1Matched: false,
      rtmr2Matched: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Verifies an NVIDIA NRAS EAT/JWT token (ES384) against NVIDIA's published JWKS
 * (`https://nras.attestation.nvidia.com/.well-known/jwks.json`).
 */
export async function verifyNvidiaEatJwtAgainstJwks(
  eatJwt: string,
  jwks: { keys?: Array<Record<string, unknown>> },
): Promise<NvidiaEatVerificationResult> {
  try {
    const parts = eatJwt.trim().split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format: expected 3 dot-separated segments");
    }
    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(headerB64)),
    ) as Record<string, unknown>;
    const payload = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(payloadB64)),
    ) as Record<string, unknown>;

    const alg = typeof header.alg === "string" ? header.alg : "";
    const kid = typeof header.kid === "string" ? header.kid : "";
    if (alg !== "ES384") {
      throw new Error(`Unsupported NVIDIA EAT JWT alg "${alg}" (expected ES384)`);
    }

    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const matchingKey =
      (kid ? keys.find((k) => k.kid === kid) : undefined) ?? keys[0];
    if (!matchingKey) {
      throw new Error(`No matching JWK found in NVIDIA JWKS for kid="${kid}"`);
    }

    let cryptoKey: CryptoKey;
    if (typeof matchingKey.x === "string" && typeof matchingKey.y === "string") {
      cryptoKey = await crypto.subtle.importKey(
        "jwk",
        {
          kty: "EC",
          crv: "P-384",
          x: matchingKey.x,
          y: matchingKey.y,
        },
        { name: "ECDSA", namedCurve: "P-384" },
        false,
        ["verify"],
      );
    } else if (Array.isArray(matchingKey.x5c) && typeof matchingKey.x5c[0] === "string") {
      const certDer = base64ToBytes(matchingKey.x5c[0]);
      const cert = X509Certificate.parse(certDer);
      cryptoKey = await cert.publicKeyObj;
    } else {
      throw new Error("Matching NVIDIA JWK has neither EC (x,y) coordinates nor x5c certificate");
    }

    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sigBytes = base64UrlToBytes(sigB64);
    const sigOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      cryptoKey,
      sigBytes.buffer as ArrayBuffer,
      signingInput.buffer as ArrayBuffer,
    );

    const overallAttResult =
      payload["x-nvidia-overall-att-result"] === true ||
      payload.measres === "success";
    const secboot = typeof payload.secboot === "boolean" ? payload.secboot : undefined;
    const dbgstat = typeof payload.dbgstat === "string" ? payload.dbgstat : undefined;
    const issuer = typeof payload.iss === "string" ? payload.iss : undefined;

    return {
      verified: sigOk && overallAttResult && dbgstat !== "enabled",
      kid,
      alg,
      issuer,
      overallAttResult,
      secboot,
      dbgstat,
      ...(sigOk ? {} : { error: "NVIDIA EAT JWT ES384 signature verification failed" }),
    };
  } catch (err) {
    return {
      verified: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
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
 * Evaluates C5 (Router-attested confidential GPU pool) and C7 (Manifest-pinned model & dm-verity root)
 * from a model enclave's live attestation and signed deployment bundle.
 * Reports precisely which parts are verified cryptographically vs trusted from the router.
 */
export function verifyModelEnclaveStatus(m: ModelEnclaveAttestation): {
  c5Pass: boolean;
  c5Detail: string;
  c7Pass: boolean;
  c7Detail: string;
} {
  if (m.status === "unavailable") {
    const reason = m.unavailableReason || "Upstream attestation or release manifest unreachable";
    return {
      c5Pass: false,
      c5Detail: `Unavailable: ${reason}`,
      c7Pass: false,
      c7Detail: `Unavailable: ${reason}`,
    };
  }

  const sigstoreOk = m.sigstoreVerified !== false && m.registersMatchSigstore !== false;

  const c5Pass =
    sigstoreOk &&
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

  const provenanceSuffix =
    m.directQuoteVerified === true
      ? `cryptographically verified: live ${m.directQuoteFormat ?? teeLabel} quote on ${m.directQuoteHost} + Sigstore DSSE release ${m.tag}; trusted from router: pool health & in-CVM NVIDIA GPU CC state (no external GPU EAT endpoint exposed)`
      : m.sigstoreVerified === true
        ? `cryptographically verified: Sigstore DSSE release ${m.tag} & measurement registers; trusted from router: per-host quote [${m.directQuoteError ?? "transitive via router proxy table"}] & in-CVM NVIDIA GPU CC state`
        : "transitive via router proxy table & signed deployment YAML";

  const c5Detail = c5Pass
    ? `${m.vmShape.gpus}× NVIDIA confidential GPU${m.vmShape.gpus === 1 ? "" : "s"} attested by router (${m.healthyHosts}/${m.configuredHosts} hosts healthy, ${teeLabel}, VLLM_DISABLE_UVA=1, SYMM_MEM=0; ${provenanceSuffix})`
    : `GPU enclave verification incomplete: ${m.verifiedHosts}/${m.configuredHosts} verified, ${m.unverifiedHosts} unverified, ${m.vmShape.gpus} GPUs, CC flags=${m.ccGpuFlagsVerified}, Sigstore=${sigstoreOk}`;

  const c7Pass = Boolean(
    sigstoreOk &&
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

  const c7CryptographicNote =
    m.directQuoteVerified === true
      ? ` (cryptographically verified: Sigstore DSSE release ${m.tag} + live ${m.directQuoteHost} hardware quote measurement matched)`
      : m.sigstoreVerified === true
        ? ` (cryptographically verified: Sigstore DSSE release ${m.tag} + measurement registers matched; live host quote trusted from router)`
        : "";

  const c7Detail = c7Pass
    ? `Pinned weight package ${mpkLabel} (${repoLabel}) on dm-verity root ${rootShort}${c7CryptographicNote}`
    : `Missing or unverified committed model weight package, dm-verity root, or hardware measurement registers`;

  return {
    c5Pass,
    c5Detail,
    c7Pass,
    c7Detail,
  };
}
