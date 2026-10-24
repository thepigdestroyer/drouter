import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { CheckResult, NodeKind, PopReceipt } from "@/lib/types";

export const FORENSIC_PROOF_SCHEMA = "drouter.forensic-proof.v1" as const;

export const REQUIRED_CHECK_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"] as const;

export interface ForensicProofBundle {
  schema: "drouter.forensic-proof.v1";
  createdAt: number;
  nodeId: string;
  nodeName: string;
  nodeKind: NodeKind;
  modelId: string;
  checks: CheckResult[];
  evidence: Record<string, string>;
  popReceipt?: PopReceipt | null;
  arcAnchorTx?: string | null;
  bundleDigestHex: string;
  clientSignatureHex: string;
  clientPublicKeyHex: string;
  cliVerifyOneLiner: string;
}

export interface CreateForensicProofBundleInput {
  createdAt?: number;
  nodeId: string;
  nodeName: string;
  nodeKind: NodeKind;
  modelId: string;
  checks: CheckResult[];
  evidence: Record<string, string>;
  popReceipt?: PopReceipt | null;
  arcAnchorTx?: string | null;
  /** Optional 32-byte Ed25519 secret key (Uint8Array or hex). If omitted, an ephemeral keypair is generated. */
  clientSecretKey?: Uint8Array | string;
}

export interface VerifyForensicProofOptions {
  /** Pinned/expected 32-byte Ed25519 client public key (hex). Required to prove origin rather than mere self-signed integrity. */
  expectedClientPublicKeyHex?: string;
  /** Pinned/expected 32-byte Ed25519 enclave signer public key for the embedded PopReceipt (hex). */
  expectedPopSignerPublicKeyHex?: string;
  /** When true, `valid` is false unless `expectedClientPublicKeyHex` is provided and matches. */
  requirePinnedOrigin?: boolean;
}

export interface ForensicProofVerificationResult {
  valid: boolean;
  digestMatches: boolean;
  clientSignatureValid: boolean;
  popReceiptSignatureValid: boolean | null;
  allChecksPassed: boolean;
  /** True only when `expectedClientPublicKeyHex` was supplied and matched `bundle.clientPublicKeyHex`. */
  originVerified: boolean;
  /** True only when `expectedPopSignerPublicKeyHex` was supplied and matched `bundle.popReceipt.signerPublicKey` (null if no popReceipt). */
  popOriginVerified: boolean | null;
  reasons: string[];
}

function normalizeHex(hex: string): string {
  const trimmed = hex.trim();
  return trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  const cleanA = normalizeHex(a).toLowerCase();
  const cleanB = normalizeHex(b).toLowerCase();
  const maxLen = Math.max(cleanA.length, cleanB.length);
  let diff = cleanA.length ^ cleanB.length;
  for (let i = 0; i < maxLen; i++) {
    const codeA = i < cleanA.length ? cleanA.charCodeAt(i) : 0;
    const codeB = i < cleanB.length ? cleanB.charCodeAt(i) : 0;
    diff |= codeA ^ codeB;
  }
  return diff === 0;
}

/**
 * Deterministic RFC-8785-style canonical JSON serializer (sorted object keys, no whitespace).
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  if (value instanceof Uint8Array) {
    return JSON.stringify(bytesToHex(value));
  }
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("Canonical JSON cannot encode non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalizeJson(item === undefined ? null : item)).join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      const entries = Object.keys(record)
        .filter((key) => record[key] !== undefined)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`);
      return `{${entries.join(",")}}`;
    }
    default:
      throw new Error(`Canonical JSON cannot encode ${typeof value}`);
  }
}

/**
 * Canonical payload covered by `bundleDigestHex`.
 */
export function computeForensicBundleDigestHex(payload: {
  schema: string;
  createdAt: number;
  nodeId: string;
  modelId: string;
  checks: CheckResult[];
  evidence: Record<string, string>;
  popReceipt?: PopReceipt | null;
  arcAnchorTx?: string | null;
}): string {
  const canonicalPayload = {
    schema: payload.schema,
    createdAt: payload.createdAt,
    nodeId: payload.nodeId,
    modelId: payload.modelId,
    checks: payload.checks,
    evidence: payload.evidence,
    popReceipt: payload.popReceipt ?? null,
    arcAnchorTx: payload.arcAnchorTx ?? null,
  };
  const bytes = utf8ToBytes(canonicalizeJson(canonicalPayload));
  return bytesToHex(sha256(bytes));
}

function buildPopCanonicalMessageBytes(receipt: {
  nodeId: string;
  sessionIdHash: string;
  time: number;
  measurement: string;
}): Uint8Array {
  return utf8ToBytes(
    canonicalizeJson({
      type: "pop",
      nodeId: receipt.nodeId,
      sessionIdHash: receipt.sessionIdHash,
      time: receipt.time,
      measurement: receipt.measurement,
    })
  );
}

/**
 * Helper to sign a PopReceipt with an Ed25519 enclave identity secret key.
 */
export function signForensicPopReceipt(
  fields: {
    nodeId: string;
    sessionIdHash: string;
    time: number;
    measurement: string;
  },
  signerSecretKey: Uint8Array | string
): PopReceipt {
  const skBytes =
    typeof signerSecretKey === "string"
      ? hexToBytes(normalizeHex(signerSecretKey))
      : signerSecretKey;
  const pkBytes = ed25519.getPublicKey(skBytes);
  const msgBytes = buildPopCanonicalMessageBytes(fields);
  const sigBytes = ed25519.sign(msgBytes, skBytes);
  return {
    nodeId: fields.nodeId,
    sessionIdHash: fields.sessionIdHash,
    time: fields.time,
    measurement: fields.measurement,
    signature: bytesToHex(sigBytes),
    signerPublicKey: bytesToHex(pkBytes),
    verified: true,
  };
}

/**
 * Verify a PopReceipt's Ed25519 signature offline against its canonical fields.
 * If `expectedSignerPublicKeyHex` is provided, also enforces that `receipt.signerPublicKey` matches the pinned enclave key.
 */
export function verifyPopReceiptSignatureOffline(
  receipt: PopReceipt,
  expectedSignerPublicKeyHex?: string
): boolean {
  try {
    if (!receipt || typeof receipt !== "object") return false;
    if (receipt.verified !== true) return false;
    if (
      typeof receipt.nodeId !== "string" ||
      !receipt.nodeId ||
      typeof receipt.sessionIdHash !== "string" ||
      !receipt.sessionIdHash ||
      typeof receipt.measurement !== "string" ||
      !receipt.measurement ||
      typeof receipt.signature !== "string" ||
      !receipt.signature ||
      typeof receipt.signerPublicKey !== "string" ||
      !receipt.signerPublicKey ||
      typeof receipt.time !== "number" ||
      !Number.isFinite(receipt.time)
    ) {
      return false;
    }

    if (
      expectedSignerPublicKeyHex !== undefined &&
      !constantTimeEqualHex(receipt.signerPublicKey, expectedSignerPublicKeyHex)
    ) {
      return false;
    }

    const sigBytes = hexToBytes(normalizeHex(receipt.signature));
    const pkBytes = hexToBytes(normalizeHex(receipt.signerPublicKey));
    if (sigBytes.byteLength !== 64 || pkBytes.byteLength !== 32) {
      return false;
    }

    const msgBytes = buildPopCanonicalMessageBytes(receipt);
    return ed25519.verify(sigBytes, msgBytes, pkBytes);
  } catch {
    return false;
  }
}

/**
 * Builds a ready-to-run standalone `node -e '...'` command that recomputes the canonical
 * SHA-256 digest and verifies the Ed25519 signature offline using only Node.js built-ins.
 */
export function buildCliVerifyOneLiner(filename = "session.drouter-proof.json"): string {
  const script = [
    `const fs=require("fs"),crypto=require("crypto");`,
    `const b=JSON.parse(fs.readFileSync(process.argv[1]||${JSON.stringify(filename)},"utf8"));`,
    `const canon=(v)=>v===null||v===undefined?"null":Array.isArray(v)?"["+v.map(x=>canon(x===undefined?null:x)).join(",")+"]":typeof v==="object"?"{"+Object.keys(v).filter(k=>v[k]!==undefined).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}":JSON.stringify(v);`,
    `const digest=crypto.createHash("sha256").update(canon({schema:b.schema,createdAt:b.createdAt,nodeId:b.nodeId,modelId:b.modelId,checks:b.checks,evidence:b.evidence,popReceipt:b.popReceipt??null,arcAnchorTx:b.arcAnchorTx??null})).digest("hex");`,
    `const spki=Buffer.concat([Buffer.from("302a300506032b6570032100","hex"),Buffer.from(b.clientPublicKeyHex,"hex")]);`,
    `const sigOk=crypto.verify(null,Buffer.from(b.bundleDigestHex,"utf8"),crypto.createPublicKey({key:spki,format:"der",type:"spki"}),Buffer.from(b.clientSignatureHex,"hex"));`,
    `if(digest!==b.bundleDigestHex||!sigOk){console.error("INVALID PROOF",{digestMatches:digest===b.bundleDigestHex,sigOk});process.exit(1);}`,
    `console.log("VALID DROUTER FORENSIC PROOF:",b.bundleDigestHex);`,
  ].join("");
  return `node -e '${script}' ${filename}`;
}

/**
 * Packages all cryptographic evidence of a session into a downloadable, self-contained
 * `.drouter-proof.json` bundle (`ForensicProofBundle`) signed with an Ed25519 client key.
 */
export function createForensicProofBundle(
  input: CreateForensicProofBundleInput
): ForensicProofBundle {
  const createdAt = input.createdAt ?? Date.now();
  const checks: CheckResult[] = input.checks.map((c) => ({
    id: c.id,
    label: c.label,
    status: c.status,
    detail: c.detail,
  }));
  const evidence: Record<string, string> = { ...input.evidence };
  const popReceipt: PopReceipt | null = input.popReceipt
    ? {
        nodeId: input.popReceipt.nodeId,
        sessionIdHash: input.popReceipt.sessionIdHash,
        time: input.popReceipt.time,
        measurement: input.popReceipt.measurement,
        signature: input.popReceipt.signature,
        signerPublicKey: input.popReceipt.signerPublicKey,
        verified: input.popReceipt.verified,
      }
    : null;
  const arcAnchorTx: string | null = input.arcAnchorTx ?? null;

  const secretKeyBytes =
    input.clientSecretKey !== undefined
      ? typeof input.clientSecretKey === "string"
        ? hexToBytes(normalizeHex(input.clientSecretKey))
        : input.clientSecretKey
      : ed25519.utils.randomSecretKey();

  const clientPublicKeyBytes = ed25519.getPublicKey(secretKeyBytes);
  const clientPublicKeyHex = bytesToHex(clientPublicKeyBytes);

  const bundleDigestHex = computeForensicBundleDigestHex({
    schema: FORENSIC_PROOF_SCHEMA,
    createdAt,
    nodeId: input.nodeId,
    modelId: input.modelId,
    checks,
    evidence,
    popReceipt,
    arcAnchorTx,
  });

  const clientSignatureBytes = ed25519.sign(utf8ToBytes(bundleDigestHex), secretKeyBytes);
  const clientSignatureHex = bytesToHex(clientSignatureBytes);

  return {
    schema: FORENSIC_PROOF_SCHEMA,
    createdAt,
    nodeId: input.nodeId,
    nodeName: input.nodeName,
    nodeKind: input.nodeKind,
    modelId: input.modelId,
    checks,
    evidence,
    popReceipt,
    arcAnchorTx,
    bundleDigestHex,
    clientSignatureHex,
    clientPublicKeyHex,
    cliVerifyOneLiner: buildCliVerifyOneLiner(),
  };
}

/**
 * Standalone offline verifier for `.drouter-proof.json` bundles.
 * Recomputes the canonical SHA-256 digest, verifies the client's Ed25519 signature,
 * verifies the embedded PopReceipt Ed25519 signature (if present), and checks C1-C7.
 *
 * Security note: Because a bundle carries its own `clientPublicKeyHex` and `popReceipt.signerPublicKey`,
 * signature verification without pinned keys proves only self-consistency, not origin (`originVerified: false`).
 * Pass `options.expectedClientPublicKeyHex` (and `options.expectedPopSignerPublicKeyHex`) to verify origin.
 */
export function verifyForensicProofBundleOffline(
  bundle: ForensicProofBundle,
  options?: VerifyForensicProofOptions | string
): ForensicProofVerificationResult {
  const reasons: string[] = [];
  const opts: VerifyForensicProofOptions =
    typeof options === "string"
      ? { expectedClientPublicKeyHex: options }
      : (options ?? {});

  if (!bundle || typeof bundle !== "object") {
    return {
      valid: false,
      digestMatches: false,
      clientSignatureValid: false,
      popReceiptSignatureValid: null,
      allChecksPassed: false,
      originVerified: false,
      popOriginVerified: null,
      reasons: ["Bundle is not a valid object"],
    };
  }

  const schemaValid = bundle.schema === FORENSIC_PROOF_SCHEMA;
  if (!schemaValid) {
    reasons.push(`Unsupported schema: ${String(bundle.schema)}`);
  }

  if (
    !bundle.evidence ||
    typeof bundle.evidence !== "object" ||
    Object.keys(bundle.evidence).length === 0
  ) {
    reasons.push("Evidence register map is empty or missing");
  }

  // 1. Recompute canonical SHA-256 digest
  let digestMatches = false;
  try {
    const recomputedDigestHex = computeForensicBundleDigestHex({
      schema: bundle.schema,
      createdAt: bundle.createdAt,
      nodeId: bundle.nodeId,
      modelId: bundle.modelId,
      checks: bundle.checks,
      evidence: bundle.evidence,
      popReceipt: bundle.popReceipt ?? null,
      arcAnchorTx: bundle.arcAnchorTx ?? null,
    });
    digestMatches =
      typeof bundle.bundleDigestHex === "string" &&
      recomputedDigestHex.length === 64 &&
      constantTimeEqualHex(recomputedDigestHex, bundle.bundleDigestHex);
  } catch {
    digestMatches = false;
  }

  if (!digestMatches) {
    reasons.push(
      "Bundle SHA-256 digest mismatch: one or more registers in evidence, checks, popReceipt, or metadata were tampered with"
    );
  }

  // 2. Verify client Ed25519 signature over bundleDigestHex
  let clientSignatureValid = false;
  try {
    const sigBytes = hexToBytes(normalizeHex(bundle.clientSignatureHex));
    const pkBytes = hexToBytes(normalizeHex(bundle.clientPublicKeyHex));
    const digestBytes = utf8ToBytes(normalizeHex(bundle.bundleDigestHex).toLowerCase());
    if (sigBytes.byteLength === 64 && pkBytes.byteLength === 32) {
      clientSignatureValid = ed25519.verify(sigBytes, digestBytes, pkBytes);
    }
  } catch {
    clientSignatureValid = false;
  }

  if (!clientSignatureValid) {
    reasons.push("Client Ed25519 signature verification failed");
  }

  // 2b. Check pinned client public key for origin authentication
  let originVerified = false;
  if (typeof opts.expectedClientPublicKeyHex === "string" && opts.expectedClientPublicKeyHex.trim()) {
    const keyMatches =
      typeof bundle.clientPublicKeyHex === "string" &&
      constantTimeEqualHex(bundle.clientPublicKeyHex, opts.expectedClientPublicKeyHex);
    if (!keyMatches) {
      reasons.push("Client public key does not match pinned expectedClientPublicKeyHex");
    } else if (clientSignatureValid) {
      originVerified = true;
    }
  } else if (opts.requirePinnedOrigin) {
    reasons.push("Origin not verified: expectedClientPublicKeyHex is required when requirePinnedOrigin is true");
  }

  // 3. Verify all C1-C7 checks are present and passed
  let allChecksPassed = false;
  if (Array.isArray(bundle.checks) && bundle.checks.length >= REQUIRED_CHECK_IDS.length) {
    const checkMap = new Map<string, CheckResult>();
    for (const c of bundle.checks) {
      if (c && typeof c.id === "string") {
        checkMap.set(c.id, c);
      }
    }
    const missingOrFailed: string[] = [];
    for (const reqId of REQUIRED_CHECK_IDS) {
      const found = checkMap.get(reqId);
      if (!found || found.status !== "pass") {
        missingOrFailed.push(reqId);
      }
    }
    const anyExtraFailed = bundle.checks.some((c) => !c || c.status !== "pass");
    if (missingOrFailed.length === 0 && !anyExtraFailed) {
      allChecksPassed = true;
    } else {
      reasons.push(
        `Verification checks did not all pass (failed or missing: ${missingOrFailed.join(", ") || "extra check"})`
      );
    }
  } else {
    reasons.push("Verification checklist is incomplete (requires C1-C7)");
  }

  // 4. Verify optional PopReceipt Ed25519 signature and nodeId binding
  let popReceiptSignatureValid: boolean | null = null;
  let popOriginVerified: boolean | null = null;
  if (bundle.popReceipt !== undefined && bundle.popReceipt !== null) {
    const nodeIdMatches = bundle.popReceipt.nodeId === bundle.nodeId;
    popReceiptSignatureValid =
      nodeIdMatches && verifyPopReceiptSignatureOffline(bundle.popReceipt);
    if (!nodeIdMatches) {
      reasons.push("Embedded PopReceipt nodeId does not match bundle.nodeId");
    } else if (!popReceiptSignatureValid) {
      reasons.push("Embedded PopReceipt Ed25519 signature verification failed");
    }

    popOriginVerified = false;
    if (
      typeof opts.expectedPopSignerPublicKeyHex === "string" &&
      opts.expectedPopSignerPublicKeyHex.trim()
    ) {
      const popKeyMatches =
        typeof bundle.popReceipt.signerPublicKey === "string" &&
        constantTimeEqualHex(
          bundle.popReceipt.signerPublicKey,
          opts.expectedPopSignerPublicKeyHex
        );
      if (!popKeyMatches) {
        reasons.push("PopReceipt signerPublicKey does not match pinned expectedPopSignerPublicKeyHex");
      } else if (popReceiptSignatureValid) {
        popOriginVerified = true;
      }
    }
  }

  const valid =
    schemaValid &&
    digestMatches &&
    clientSignatureValid &&
    allChecksPassed &&
    (popReceiptSignatureValid === null || popReceiptSignatureValid === true) &&
    reasons.length === 0;

  return {
    valid,
    digestMatches,
    clientSignatureValid,
    popReceiptSignatureValid,
    allChecksPassed,
    originVerified,
    popOriginVerified,
    reasons,
  };
}
