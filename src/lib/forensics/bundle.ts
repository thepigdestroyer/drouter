import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { getCurrentVaultSession } from "@/lib/auth/vault";
import type { CheckResult, NodeKind, NodeRecord, PopReceipt } from "@/lib/types";

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
  /** Optional 32-byte Ed25519 secret key (Uint8Array or hex). If omitted, uses the unlocked Vault Ed25519 key or generates an ephemeral keypair. */
  clientSecretKey?: Uint8Array | string;
}

/**
 * Input shape accepted by `buildProofBundle(...)` and `downloadForensicProofBundle(...)`
 * directly from the live Console (`src/components/console.tsx`).
 */
export interface BuildSessionProofBundleInput {
  session?: {
    node: NodeRecord;
    checks: CheckResult[];
    evidence: Record<string, string>;
    evidenceHash?: string;
    deepBundle?: unknown;
  } | null;
  node?: NodeRecord | null;
  model?: string;
  checks?: CheckResult[];
  evidence?: Record<string, string>;
  receipt?: PopReceipt | null;
  verifyAnchorUrl?: string | null;
  receiptAnchorUrl?: string | null;
  arcAnchorTx?: string | null;
  createdAt?: number;
  clientSecretKey?: Uint8Array | string;
}

export interface VerifyForensicProofOptions {
  /** Pinned/expected 32-byte Ed25519 client public key (hex). Required to prove origin rather than mere self-signed integrity. */
  expectedClientPublicKeyHex?: string;
  /** Pinned/expected 32-byte Ed25519 enclave signer public key for the embedded PopReceipt (hex). */
  expectedPopSignerPublicKeyHex?: string;
  /** Map of `nodeId -> ed25519PublicKeyHex` for pinned enclave PopReceipt signers (e.g. from `/api/sim/roots`). */
  pinnedNodePublicKeys?: Record<string, string>;
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
  /** True only when `expectedPopSignerPublicKeyHex` or `pinnedNodePublicKeys[nodeId]` matched `bundle.popReceipt.signerPublicKey` (null if no popReceipt). */
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

function resolveClientSigningSecretKey(explicitKey?: Uint8Array | string): Uint8Array {
  if (explicitKey !== undefined) {
    return typeof explicitKey === "string"
      ? hexToBytes(normalizeHex(explicitKey))
      : explicitKey;
  }
  const activeVault = getCurrentVaultSession();
  if (
    activeVault &&
    typeof activeVault.ed25519PrivateKeyHex === "string" &&
    /^[0-9a-fA-F]{64}$/.test(activeVault.ed25519PrivateKeyHex) &&
    activeVault.ed25519PrivateKeyHex !== "0".repeat(64)
  ) {
    return hexToBytes(activeVault.ed25519PrivateKeyHex);
  }
  return ed25519.utils.randomSecretKey();
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

  const secretKeyBytes = resolveClientSigningSecretKey(input.clientSecretKey);
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

function extractTxHashFromUrlOrHex(urlOrTx?: string | null): string | null {
  if (!urlOrTx || typeof urlOrTx !== "string") return null;
  const trimmed = urlOrTx.trim();
  if (!trimmed) return null;
  const txMatch = /0x[0-9a-fA-F]{64}/.exec(trimmed);
  if (txMatch) return txMatch[0];
  return trimmed;
}

/**
 * Builds a `ForensicProofBundle` directly from real Console session state (`ActiveSession`, `NodeRecord`,
 * `CheckResult[]`, `evidence`, `PopReceipt`, and optional Arc anchor URL/tx).
 * If the user's Passphrase Vault is unlocked in browser memory, automatically signs the proof bundle
 * with the user's deterministic Ed25519 identity key (`session.ed25519PrivateKeyHex`) and records
 * `Vault ID` in the evidence map so `verifyForensicProofBundleOffline` can verify pinned origin.
 */
export function buildProofBundle(input: BuildSessionProofBundleInput): ForensicProofBundle {
  const activeNode = input.session?.node ?? input.node;
  if (!activeNode) {
    throw new Error("Cannot build forensic proof bundle: no attested node or active session");
  }

  const rawChecks =
    input.checks && input.checks.length > 0
      ? input.checks
      : (input.session?.checks ?? []);
  if (rawChecks.length === 0) {
    throw new Error("Cannot build forensic proof bundle: verification checks C1-C7 have not completed");
  }

  const rawEvidence: Record<string, string> = {
    ...(input.session?.evidence ?? {}),
    ...(input.evidence ?? {}),
  };

  // Enrich evidence with deepBundle registers if available and not already populated
  const deep = input.session?.deepBundle as
    | {
        routerHost?: string;
        routerReleaseDigest?: string;
        routerSnpReport?: {
          chipIdHex?: string;
          measurementHex?: string;
          reportDataHex?: string;
          policyHex?: string;
        };
      }
    | undefined;

  if (deep?.routerHost && !rawEvidence["Enclave host"]) {
    rawEvidence["Enclave host"] = deep.routerHost;
  }
  if (deep?.routerSnpReport?.chipIdHex && !rawEvidence["Chip ID"]) {
    rawEvidence["Chip ID"] = deep.routerSnpReport.chipIdHex;
  }
  if (deep?.routerSnpReport?.measurementHex && !rawEvidence["Enclave fingerprint"] && !rawEvidence["Measurement"]) {
    rawEvidence["Enclave fingerprint"] = deep.routerSnpReport.measurementHex;
  }
  if (deep?.routerSnpReport?.reportDataHex && !rawEvidence["Report data"]) {
    rawEvidence["Report data"] = deep.routerSnpReport.reportDataHex;
  }
  if (input.session?.evidenceHash && !rawEvidence["Evidence hash"]) {
    rawEvidence["Evidence hash"] = input.session.evidenceHash;
  }

  const vaultSession = getCurrentVaultSession();
  if (vaultSession?.vaultId && !rawEvidence["Client vault ID"]) {
    rawEvidence["Client vault ID"] = vaultSession.vaultId;
  }

  if (Object.keys(rawEvidence).length === 0) {
    rawEvidence["Node endpoint"] = activeNode.endpoint;
    rawEvidence["Measurement"] = activeNode.measurement;
  }

  const modelId = input.model ?? "kimi-k3";

  // Ensure PopReceipt.nodeId aligns with bundle.nodeId when sim close receipt uses "sim-1" while registry node.id is "0x..."
  let normalizedPopReceipt: PopReceipt | null = null;
  if (input.receipt) {
    normalizedPopReceipt = {
      ...input.receipt,
    };
    if (normalizedPopReceipt.nodeId !== activeNode.id) {
      rawEvidence["PopReceipt nodeId"] = normalizedPopReceipt.nodeId;
    }
  }

  const arcAnchorTx =
    extractTxHashFromUrlOrHex(input.arcAnchorTx) ??
    extractTxHashFromUrlOrHex(input.receiptAnchorUrl) ??
    extractTxHashFromUrlOrHex(input.verifyAnchorUrl);

  return createForensicProofBundle({
    createdAt: input.createdAt ?? Date.now(),
    nodeId: normalizedPopReceipt ? normalizedPopReceipt.nodeId : activeNode.id,
    nodeName: activeNode.name,
    nodeKind: activeNode.kind,
    modelId,
    checks: rawChecks,
    evidence: rawEvidence,
    popReceipt: normalizedPopReceipt,
    arcAnchorTx,
    clientSecretKey: input.clientSecretKey,
  });
}

/**
 * Convenience helper for the Console UI button: builds a `ForensicProofBundle` from the current
 * session state, triggers a browser file download (`<nodeId>-<timestamp>.drouter-proof.json`),
 * and returns the bundle alongside its offline verification result.
 */
export function downloadForensicProofBundle(
  input: BuildSessionProofBundleInput
): {
  bundle: ForensicProofBundle;
  verification: ForensicProofVerificationResult;
  filename: string;
} {
  const bundle = buildProofBundle(input);
  const vaultSession = getCurrentVaultSession();
  const verification = verifyForensicProofBundleOffline(bundle, {
    expectedClientPublicKeyHex: vaultSession?.ed25519PublicKeyHex,
    expectedPopSignerPublicKeyHex: bundle.popReceipt?.signerPublicKey,
  });

  const safeNodeSlug = bundle.nodeId.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 16) || "session";
  const filename = `drouter-proof-${safeNodeSlug}-${bundle.createdAt}.drouter-proof.json`;

  if (typeof window !== "undefined" && typeof document !== "undefined") {
    try {
      const jsonText = JSON.stringify(bundle, null, 2);
      const blob = new Blob([jsonText], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    } catch {
      // Non-fatal in headless/SSR environments
    }
  }

  return { bundle, verification, filename };
}

/**
 * Standalone offline verifier for `.drouter-proof.json` bundles.
 * Recomputes the canonical SHA-256 digest, verifies the client's Ed25519 signature,
 * verifies the embedded PopReceipt Ed25519 signature (if present), and checks C1-C7.
 *
 * Security note: Because a bundle carries its own `clientPublicKeyHex` and `popReceipt.signerPublicKey`,
 * signature verification without pinned keys proves only self-consistency, not origin (`originVerified: false`).
 * Pass `options.expectedClientPublicKeyHex` (and `options.expectedPopSignerPublicKeyHex` or `options.pinnedNodePublicKeys`) to verify origin.
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

  // 3. Verify all C1-C7 checks are present and passed (or C5/C6 skipped only when explicitly allowed, but forensic proof requires pass)
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
    const pinnedPopKey =
      opts.expectedPopSignerPublicKeyHex ??
      opts.pinnedNodePublicKeys?.[bundle.popReceipt.nodeId] ??
      opts.pinnedNodePublicKeys?.[bundle.nodeId];

    if (typeof pinnedPopKey === "string" && pinnedPopKey.trim()) {
      const popKeyMatches =
        typeof bundle.popReceipt.signerPublicKey === "string" &&
        constantTimeEqualHex(bundle.popReceipt.signerPublicKey, pinnedPopKey);
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
