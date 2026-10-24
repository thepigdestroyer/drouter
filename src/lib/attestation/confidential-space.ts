/**
 * Google Cloud Confidential Space PKI Attestation Verifier (G4).
 *
 * Browser- and Node-safe module using only `@peculiar/x509@2.2.0` and WebCrypto (`globalThis.crypto.subtle`).
 * Performs zero randomness or network calls at import time.
 *
 * Official documentation references:
 * - PKI token verification: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#pki_attestation_tokens
 * - Token claims: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims
 * - Launch policies: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies
 */

import {
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256,
} from "./google-cs-root";
import * as x509 from "@peculiar/x509";

export {
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256,
};

export const EXPECTED_CONFIDENTIAL_SPACE_ISSUER =
  "https://confidentialcomputing.googleapis.com" as const;

export const DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE =
  "https://drouter-demo.vercel.app/deroute-core" as const;

export const ALLOWED_CONFIDENTIAL_SPACE_HWMODELS = [
  "GCP_AMD_SEV",
  "GCP_AMD_SEV_ES",
  "GCP_INTEL_TDX",
] as const;

export type AllowedConfidentialSpaceHwModel =
  (typeof ALLOWED_CONFIDENTIAL_SPACE_HWMODELS)[number];

export const DEFAULT_ALLOWED_ENV_OVERRIDES = [
  "CORE_KEY_SOURCE",
  "CORE_PUBLIC_ORIGIN",
] as const;

export const CLOCK_SKEW_SECONDS = 60;

export interface ConfidentialSpaceAttestedKeys {
  egress: string;
  tree: string;
}

export interface ConfidentialSpaceCheck {
  id: string;
  passed: boolean;
  plain: string;
  technical: string;
}

export interface ConfidentialSpaceVerificationOptions {
  /** The compact-serialized JWS PKI token returned by `/attestation`. */
  token: string;
  /** The workload's Ed25519 public keys (`{ egress, tree }` in 64-char hex). */
  keys: ConfidentialSpaceAttestedKeys;
  /**
   * Either the TLS server certificate (PEM/DER/base64) or its precomputed
   * SubjectPublicKeyInfo SHA-256 hex digest (e.g. when verifying in the browser).
   */
  tlsCertificatePemOrDer?: string | ArrayBuffer | Uint8Array;
  /**
   * Lowercase 64-char hex SHA-256 of the TLS certificate's SubjectPublicKeyInfo DER.
   * If `tlsCertificatePemOrDer` is provided, the verifier recomputes the SPKI SHA-256
   * directly from the certificate and cross-checks `tlsSpkiSha256` if both are present.
   */
  tlsSpkiSha256?: string;
  /** Expected `aud` claim. Defaults to `https://drouter-demo.vercel.app/deroute-core`. */
  expectedAudience?: string;
  /** Expected `submods.container.image_digest` allowlist (`sha256:...`). */
  expectedImageDigests: readonly string[];
  /** Allowed `submods.container.env_override` variable names. */
  allowedEnvOverrides?: readonly string[];
  /** Optional override for current Unix time in seconds (for deterministic tests). */
  nowSec?: number;
  /** Optional root CA PEM override for negative unit tests. Defaults to pinned Google CS Root CA. */
  pinnedRootCaPem?: string;
}

export interface ConfidentialSpaceVerificationResult {
  ok: boolean;
  checks: ConfidentialSpaceCheck[];
  hwmodel: AllowedConfidentialSpaceHwModel | string | null;
  imageDigest: string | null;
  expiresAtSec: number | null;
  keys: ConfidentialSpaceAttestedKeys | null;
  keysDigest: string | null;
  tlsSpkiDigest: string | null;
}

function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new Error("WebCrypto API (globalThis.crypto.subtle) is required");
}

function bytesToHexLower(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < view.length; i++) {
    out += view[i].toString(16).padStart(2, "0");
  }
  return out;
}

function bytesToHexUpper(bytes: ArrayBuffer | Uint8Array): string {
  return bytesToHexLower(bytes).toUpperCase();
}

function base64UrlToBytes(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  if (typeof globalThis.atob === "function") {
    const bin = globalThis.atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }
  throw new Error("base64 decoder (atob) is unavailable in this environment");
}

function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function equalBytes(a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): boolean {
  const va = a instanceof Uint8Array ? a : new Uint8Array(a);
  const vb = b instanceof Uint8Array ? b : new Uint8Array(b);
  if (va.byteLength !== vb.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < va.byteLength; i++) {
    diff |= va[i] ^ vb[i];
  }
  return diff === 0;
}

/**
 * Deterministic canonical JSON serializer (sorted keys, no whitespace) used for `keysDigest`.
 */
export function canonicalJsonForAttestation(value: unknown): string {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonicalJsonForAttestation cannot encode non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value
          .map((item) => canonicalJsonForAttestation(item === undefined ? null : item))
          .join(",")}]`;
      }
      const rec = value as Record<string, unknown>;
      const keys = Object.keys(rec)
        .filter((k) => rec[k] !== undefined)
        .sort();
      const pairs = keys.map(
        (k) => `${JSON.stringify(k)}:${canonicalJsonForAttestation(rec[k])}`,
      );
      return `{${pairs.join(",")}}`;
    }
    default:
      throw new Error(`canonicalJsonForAttestation cannot encode ${typeof value}`);
  }
}

export async function sha256HexLower(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const cryptoApi = getWebCrypto();
  const bytes =
    typeof data === "string"
      ? utf8ToBytes(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);
  const buf = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const digest = await cryptoApi.subtle.digest("SHA-256", buf);
  return bytesToHexLower(digest);
}

/**
 * Recomputes `keysDigest` = lowercase hex SHA-256 of
 * `canonicalJson({ egress: <raw ed25519 pub hex>, tree: <raw ed25519 pub hex> })`.
 */
export async function computeAttestedKeysDigest(
  keys: ConfidentialSpaceAttestedKeys,
): Promise<string> {
  const egress = String(keys?.egress ?? "").trim().replace(/^0x/i, "").toLowerCase();
  const tree = String(keys?.tree ?? "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(egress) || !/^[0-9a-f]{64}$/.test(tree)) {
    throw new Error("Attested Ed25519 keys (egress, tree) must be 64-character hex strings");
  }
  const canonical = canonicalJsonForAttestation({ egress, tree });
  return sha256HexLower(canonical);
}

/**
 * Recomputes `tlsSpkiDigest` = lowercase hex SHA-256 of the X.509 certificate's
 * SubjectPublicKeyInfo DER bytes using `@peculiar/x509` and WebCrypto.
 */
export async function computeTlsCertSpkiSha256(
  certPemOrDer: string | ArrayBuffer | Uint8Array,
): Promise<string> {
  const rawInput: x509.AsnEncodedType =
    certPemOrDer instanceof Uint8Array
      ? (certPemOrDer.buffer.slice(
          certPemOrDer.byteOffset,
          certPemOrDer.byteOffset + certPemOrDer.byteLength,
        ) as ArrayBuffer)
      : certPemOrDer;
  const cert = new x509.X509Certificate(rawInput);
  return sha256HexLower(cert.publicKey.rawData);
}

/**
 * Computes the uppercase SHA-256 and SHA-1 fingerprints of the embedded
 * Google Confidential Space Root CA PEM certificate.
 */
export async function getEmbeddedRootCaFingerprints(): Promise<{
  sha256: string;
  sha1: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}> {
  const cryptoApi = getWebCrypto();
  const cert = new x509.X509Certificate(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM);
  const sha256Buf = await cryptoApi.subtle.digest("SHA-256", cert.rawData);
  const sha1Buf = await cryptoApi.subtle.digest("SHA-1", cert.rawData);
  return {
    sha256: bytesToHexUpper(sha256Buf),
    sha1: bytesToHexUpper(sha1Buf),
    subject: cert.subject,
    issuer: cert.issuer,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
  };
}

/**
 * Verifies a Google Cloud Confidential Space PKI attestation JWT across all G4 checks.
 */
export async function verifyConfidentialSpaceAttestation(
  options: ConfidentialSpaceVerificationOptions,
): Promise<ConfidentialSpaceVerificationResult> {
  const cryptoApi = getWebCrypto();
  const checks: ConfidentialSpaceCheck[] = [];
  const expectedAudience = options.expectedAudience ?? DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE;
  const allowedEnvOverrides = new Set(
    options.allowedEnvOverrides ?? DEFAULT_ALLOWED_ENV_OVERRIDES,
  );
  const expectedDigests = new Set(
    (options.expectedImageDigests ?? []).map((d) => d.trim()).filter(Boolean),
  );
  const nowSec =
    options.nowSec !== undefined ? Math.floor(options.nowSec) : Math.floor(Date.now() / 1000);
  const checkDate = new Date(nowSec * 1000);

  // Step 1: Parse JWT parts, header alg === RS256, and x5c length === 3
  let headerObj: Record<string, unknown> | null = null;
  let payloadObj: Record<string, unknown> | null = null;
  let signingInputBytes: Uint8Array | null = null;
  let signatureBytes: Uint8Array | null = null;
  let x5cList: string[] = [];

  const rawToken = typeof options.token === "string" ? options.token.trim() : "";
  const parts = rawToken.split(".");

  if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
    try {
      const headerJson = bytesToUtf8(base64UrlToBytes(parts[0]));
      const payloadJson = bytesToUtf8(base64UrlToBytes(parts[1]));
      headerObj = JSON.parse(headerJson) as Record<string, unknown>;
      payloadObj = JSON.parse(payloadJson) as Record<string, unknown>;
      signingInputBytes = utf8ToBytes(`${parts[0]}.${parts[1]}`);
      signatureBytes = base64UrlToBytes(parts[2]);
      if (Array.isArray(headerObj?.x5c) && headerObj.x5c.every((c) => typeof c === "string")) {
        x5cList = headerObj.x5c as string[];
      }
    } catch {
      headerObj = null;
      payloadObj = null;
    }
  }

  const alg = headerObj?.alg;
  const headerCheckPassed =
    headerObj !== null &&
    payloadObj !== null &&
    alg === "RS256" &&
    x5cList.length === 3;

  checks.push({
    id: "jwt_header_and_x5c",
    passed: headerCheckPassed,
    plain: headerCheckPassed
      ? "The attestation token uses a standard RSA signature and includes a three-certificate Google chain."
      : "The attestation token header is malformed or does not use a valid RSA certificate chain.",
    technical: headerCheckPassed
      ? `JWT header alg=RS256 and x5c contains 3 certificates (leaf, intermediate, root).`
      : `Expected JWT with alg="RS256" and x5c.length=3; got alg=${JSON.stringify(alg)}, x5c.length=${x5cList.length}.`,
  });

  // Step 2: Parse certificates and verify root DER equals pinned Google Confidential Space Root CA
  let leafCert: x509.X509Certificate | null = null;
  let intermediateCert: x509.X509Certificate | null = null;
  let rootCert: x509.X509Certificate | null = null;
  let pinnedRootCert: x509.X509Certificate | null = null;

  if (x5cList.length === 3) {
    try {
      leafCert = new x509.X509Certificate(x5cList[0]);
      intermediateCert = new x509.X509Certificate(x5cList[1]);
      rootCert = new x509.X509Certificate(x5cList[2]);
      pinnedRootCert = new x509.X509Certificate(
        options.pinnedRootCaPem ?? GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
      );
    } catch {
      leafCert = null;
      intermediateCert = null;
      rootCert = null;
    }
  }

  let rootDerMatches = false;
  let rootSha256Hex = "";
  if (rootCert && pinnedRootCert) {
    const rootDigest = await cryptoApi.subtle.digest("SHA-256", rootCert.rawData);
    rootSha256Hex = bytesToHexUpper(rootDigest);
    const expectedRootDigest = await cryptoApi.subtle.digest("SHA-256", pinnedRootCert.rawData);
    const expectedRootHex = bytesToHexUpper(expectedRootDigest);
    rootDerMatches =
      equalBytes(rootCert.rawData, pinnedRootCert.rawData) &&
      rootSha256Hex === expectedRootHex;
  }

  checks.push({
    id: "pinned_root_ca",
    passed: rootDerMatches,
    plain: rootDerMatches
      ? "The certificate chain is anchored to Google's official Confidential Space Root CA."
      : "The root certificate does not match Google's pinned Confidential Space Root CA.",
    technical: rootDerMatches
      ? `x5c[2] DER matches pinned Google Confidential Space Root CA (SHA-256 ${rootSha256Hex}).`
      : `x5c[2] DER mismatch against pinned Root CA (got SHA-256 ${rootSha256Hex || "unparseable"}).`,
  });

  // Step 3: Verify certificate chain signatures and validity windows at check time
  let chainSignaturesPassed = false;
  let chainValidityPassed = false;
  let chainDetail = "";

  if (leafCert && intermediateCert && rootCert) {
    const checkMs = checkDate.getTime();
    const leafTimeOk =
      checkMs >= leafCert.notBefore.getTime() && checkMs <= leafCert.notAfter.getTime();
    const interTimeOk =
      checkMs >= intermediateCert.notBefore.getTime() &&
      checkMs <= intermediateCert.notAfter.getTime();
    const rootTimeOk =
      checkMs >= rootCert.notBefore.getTime() && checkMs <= rootCert.notAfter.getTime();
    chainValidityPassed = leafTimeOk && interTimeOk && rootTimeOk;

    try {
      const interCaExt = intermediateCert.getExtension(x509.BasicConstraintsExtension);
      const rootCaExt = rootCert.getExtension(x509.BasicConstraintsExtension);
      const caConstraintsOk =
        (interCaExt ? interCaExt.ca : true) && (rootCaExt ? rootCaExt.ca : true);

      const issuerMatchOk =
        leafCert.issuer === intermediateCert.subject &&
        intermediateCert.issuer === rootCert.subject &&
        rootCert.issuer === rootCert.subject;

      const leafSignedByInter = await leafCert.verify(
        { publicKey: intermediateCert.publicKey, signatureOnly: true },
        cryptoApi,
      );
      const interSignedByRoot = await intermediateCert.verify(
        { publicKey: rootCert.publicKey, signatureOnly: true },
        cryptoApi,
      );
      const rootSelfSigned = await rootCert.verify(
        { publicKey: rootCert.publicKey, signatureOnly: true },
        cryptoApi,
      );

      chainSignaturesPassed =
        caConstraintsOk &&
        issuerMatchOk &&
        leafSignedByInter &&
        interSignedByRoot &&
        rootSelfSigned;
      chainDetail = `leafSignedByInter=${leafSignedByInter}, interSignedByRoot=${interSignedByRoot}, rootSelfSigned=${rootSelfSigned}, leafTimeOk=${leafTimeOk}, interTimeOk=${interTimeOk}, rootTimeOk=${rootTimeOk}`;
    } catch (err) {
      chainSignaturesPassed = false;
      chainDetail = `chain verification error: ${err instanceof Error ? err.message : String(err)}`;
    }
  } else {
    chainDetail = "x5c certificates could not be parsed";
  }

  const chainOverallPassed = chainSignaturesPassed && chainValidityPassed;
  checks.push({
    id: "x5c_chain_and_validity",
    passed: chainOverallPassed,
    plain: chainOverallPassed
      ? "Every certificate in the Google signing chain is valid and unbroken."
      : "The Google certificate chain is broken or contains an expired certificate.",
    technical: chainDetail,
  });

  // Step 4: Verify RS256 JWS signature over `header.payload` using leaf public key
  let jwtSignaturePassed = false;
  let jwtSignatureDetail = "";

  if (
    headerCheckPassed &&
    leafCert &&
    signingInputBytes !== null &&
    signatureBytes !== null
  ) {
    try {
      const leafCryptoKey = await leafCert.publicKey.export(
        { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
        ["verify"],
        cryptoApi,
      );
      const sigBuf = signatureBytes.buffer.slice(
        signatureBytes.byteOffset,
        signatureBytes.byteOffset + signatureBytes.byteLength,
      ) as ArrayBuffer;
      const dataBuf = signingInputBytes.buffer.slice(
        signingInputBytes.byteOffset,
        signingInputBytes.byteOffset + signingInputBytes.byteLength,
      ) as ArrayBuffer;
      jwtSignaturePassed = await cryptoApi.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        leafCryptoKey,
        sigBuf,
        dataBuf,
      );
      jwtSignatureDetail = jwtSignaturePassed
        ? "RSASSA-PKCS1-v1_5 SHA-256 signature over header.payload verified with leaf SPKI."
        : "RSASSA-PKCS1-v1_5 SHA-256 signature verification returned false.";
    } catch (err) {
      jwtSignaturePassed = false;
      jwtSignatureDetail = `WebCrypto signature verification failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  } else {
    jwtSignatureDetail = "Skipped or failed due to invalid JWT header or missing leaf certificate.";
  }

  checks.push({
    id: "jwt_rs256_signature",
    passed: jwtSignaturePassed,
    plain: jwtSignaturePassed
      ? "Google's cryptographic signature on this attestation report is authentic."
      : "The cryptographic signature on the attestation report failed verification.",
    technical: jwtSignatureDetail,
  });

  // Step 5a: Issuer and audience claims
  const iss = payloadObj?.iss;
  const aud = payloadObj?.aud;
  const issAudPassed =
    iss === EXPECTED_CONFIDENTIAL_SPACE_ISSUER && aud === expectedAudience;

  checks.push({
    id: "issuer_and_audience",
    passed: issAudPassed,
    plain: issAudPassed
      ? "The attestation token was issued by Google Cloud specifically for deRoute core."
      : "The token issuer or target audience does not match deRoute core.",
    technical: `iss=${JSON.stringify(iss)} (expected "${EXPECTED_CONFIDENTIAL_SPACE_ISSUER}"), aud=${JSON.stringify(aud)} (expected "${expectedAudience}").`,
  });

  // Step 5b: Token lifetime (nbf, iat, exp with 60 s clock skew)
  const nbf = typeof payloadObj?.nbf === "number" ? payloadObj.nbf : null;
  const iat = typeof payloadObj?.iat === "number" ? payloadObj.iat : null;
  const exp = typeof payloadObj?.exp === "number" ? payloadObj.exp : null;
  const timeClaimsPassed =
    nbf !== null &&
    iat !== null &&
    exp !== null &&
    Number.isFinite(nbf) &&
    Number.isFinite(iat) &&
    Number.isFinite(exp) &&
    nowSec + CLOCK_SKEW_SECONDS >= nbf &&
    nowSec + CLOCK_SKEW_SECONDS >= iat &&
    nowSec - CLOCK_SKEW_SECONDS < exp;

  checks.push({
    id: "token_lifetime",
    passed: timeClaimsPassed,
    plain: timeClaimsPassed
      ? "This attestation report is fresh and has not expired."
      : "This attestation report has expired or has invalid timestamps.",
    technical: `now=${nowSec}, nbf=${nbf}, iat=${iat}, exp=${exp} (±${CLOCK_SKEW_SECONDS}s skew).`,
  });

  // Step 5c: Confidential Space platform posture (swname, dbgstat, secboot, STABLE)
  const swname = payloadObj?.swname;
  const dbgstat = payloadObj?.dbgstat;
  const secboot = payloadObj?.secboot;
  const submods =
    payloadObj?.submods && typeof payloadObj.submods === "object"
      ? (payloadObj.submods as Record<string, unknown>)
      : null;
  const csSubmod =
    submods?.confidential_space && typeof submods.confidential_space === "object"
      ? (submods.confidential_space as Record<string, unknown>)
      : null;
  const supportAttributes = Array.isArray(csSubmod?.support_attributes)
    ? (csSubmod.support_attributes as unknown[]).filter((x): x is string => typeof x === "string")
    : [];

  const posturePassed =
    swname === "CONFIDENTIAL_SPACE" &&
    dbgstat === "disabled-since-boot" &&
    secboot === true &&
    supportAttributes.includes("STABLE");

  checks.push({
    id: "confidential_space_posture",
    passed: posturePassed,
    plain: posturePassed
      ? "The machine booted Google's hardened production Confidential Space OS with debugging disabled."
      : "The machine is running a debug image, lacks Secure Boot, or is not a STABLE Confidential Space release.",
    technical: `swname=${JSON.stringify(swname)}, dbgstat=${JSON.stringify(dbgstat)}, secboot=${JSON.stringify(secboot)}, support_attributes=${JSON.stringify(supportAttributes)}.`,
  });

  // Step 5d: Hardware model (`hwmodel`)
  const hwmodelRaw = typeof payloadObj?.hwmodel === "string" ? payloadObj.hwmodel : null;
  const hwmodelPassed =
    hwmodelRaw !== null &&
    (ALLOWED_CONFIDENTIAL_SPACE_HWMODELS as readonly string[]).includes(hwmodelRaw);

  checks.push({
    id: "hardware_tee_model",
    passed: hwmodelPassed,
    plain: hwmodelPassed
      ? `The workload is isolated inside hardware-encrypted memory (${hwmodelRaw}).`
      : "The hardware isolation model is missing or not an approved Confidential VM CPU.",
    technical: `hwmodel=${JSON.stringify(hwmodelRaw)} (allowed: ${ALLOWED_CONFIDENTIAL_SPACE_HWMODELS.join(", ")}).`,
  });

  // Step 5e: Container image digest (`submods.container.image_digest`)
  const containerSubmod =
    submods?.container && typeof submods.container === "object"
      ? (submods.container as Record<string, unknown>)
      : null;
  const imageDigest =
    typeof containerSubmod?.image_digest === "string" ? containerSubmod.image_digest : null;
  const imageDigestPassed =
    imageDigest !== null &&
    /^sha256:[0-9a-f]{64}$/.test(imageDigest) &&
    expectedDigests.size > 0 &&
    expectedDigests.has(imageDigest);

  checks.push({
    id: "container_image_digest",
    passed: imageDigestPassed,
    plain: imageDigestPassed
      ? "Google confirmed this is a sealed computer running the published deRoute code."
      : "The container image digest running inside the VM does not match the published deRoute release.",
    technical: `image_digest=${JSON.stringify(imageDigest)}, expected=${JSON.stringify([...expectedDigests])}.`,
  });

  // Step 5f: Environment variable overrides (`submods.container.env_override`)
  const envOverrideObj =
    containerSubmod?.env_override !== undefined &&
    containerSubmod?.env_override !== null &&
    typeof containerSubmod.env_override === "object" &&
    !Array.isArray(containerSubmod.env_override)
      ? (containerSubmod.env_override as Record<string, unknown>)
      : containerSubmod?.env_override === undefined
        ? {}
        : null;

  const overrideKeys = envOverrideObj ? Object.keys(envOverrideObj) : [];
  const disallowedKeys = overrideKeys.filter((k) => !allowedEnvOverrides.has(k));
  const envOverridePassed = envOverrideObj !== null && disallowedKeys.length === 0;

  checks.push({
    id: "container_env_override",
    passed: envOverridePassed,
    plain: envOverridePassed
      ? "No unauthorized environment overrides were injected by the cloud operator."
      : "The cloud operator passed unauthorized environment variable overrides to the container.",
    technical:
      envOverrideObj === null
        ? "submods.container.env_override is not a plain object."
        : `env_override keys=${JSON.stringify(overrideKeys)} (allowed: ${JSON.stringify([...allowedEnvOverrides])}).`,
  });

  // Step 5g: `eat_nonce` binding to recomputed `keysDigest` and `tlsSpkiDigest`
  let recomputedKeysDigest: string | null = null;
  let recomputedTlsSpkiDigest: string | null = null;
  let nonceError = "";

  try {
    recomputedKeysDigest = await computeAttestedKeysDigest(options.keys);
  } catch (err) {
    nonceError = err instanceof Error ? err.message : String(err);
  }

  try {
    if (options.tlsCertificatePemOrDer !== undefined) {
      const fromCert = await computeTlsCertSpkiSha256(options.tlsCertificatePemOrDer);
      if (
        options.tlsSpkiSha256 !== undefined &&
        options.tlsSpkiSha256.trim().toLowerCase() !== fromCert
      ) {
        nonceError = `Provided tlsSpkiSha256 (${options.tlsSpkiSha256}) does not match certificate SPKI SHA-256 (${fromCert}).`;
      } else {
        recomputedTlsSpkiDigest = fromCert;
      }
    } else if (typeof options.tlsSpkiSha256 === "string") {
      const cleanTls = options.tlsSpkiSha256.trim().replace(/^0x/i, "").toLowerCase();
      if (/^[0-9a-f]{64}$/.test(cleanTls)) {
        recomputedTlsSpkiDigest = cleanTls;
      } else {
        nonceError = "tlsSpkiSha256 must be a 64-character hex SHA-256 digest.";
      }
    } else {
      nonceError = "Missing TLS certificate or tlsSpkiSha256 for nonce verification.";
    }
  } catch (err) {
    nonceError = err instanceof Error ? err.message : String(err);
  }

  const rawEatNonce = payloadObj?.eat_nonce;
  const eatNonceList: string[] =
    typeof rawEatNonce === "string"
      ? [rawEatNonce]
      : Array.isArray(rawEatNonce) && rawEatNonce.every((n) => typeof n === "string")
        ? (rawEatNonce as string[])
        : [];

  const noncePassed =
    !nonceError &&
    recomputedKeysDigest !== null &&
    recomputedTlsSpkiDigest !== null &&
    eatNonceList.includes(recomputedKeysDigest) &&
    eatNonceList.includes(recomputedTlsSpkiDigest);

  checks.push({
    id: "eat_nonce_binding",
    passed: noncePassed,
    plain: noncePassed
      ? "The workload's signing keys and TLS certificate are cryptographically bound to this hardware attestation."
      : "The attestation nonces do not match the workload's signing keys or TLS certificate.",
    technical: nonceError
      ? `Nonce recomputation failed: ${nonceError}`
      : `eat_nonce=${JSON.stringify(eatNonceList)}, expected keysDigest=${recomputedKeysDigest} and tlsSpkiDigest=${recomputedTlsSpkiDigest}.`,
  });

  const allPassed = checks.every((c) => c.passed);

  return {
    ok: allPassed,
    checks,
    hwmodel: hwmodelPassed ? (hwmodelRaw as AllowedConfidentialSpaceHwModel) : hwmodelRaw,
    imageDigest,
    expiresAtSec: exp,
    keys: allPassed
      ? {
          egress: options.keys.egress.trim().replace(/^0x/i, "").toLowerCase(),
          tree: options.keys.tree.trim().replace(/^0x/i, "").toLowerCase(),
        }
      : null,
    keysDigest: recomputedKeysDigest,
    tlsSpkiDigest: recomputedTlsSpkiDigest,
  };
}
