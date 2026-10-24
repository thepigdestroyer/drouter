import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Legacy type kept only until UI components (`src/app/network/page.tsx`) finish cleanup.
 * Simulated builder/reviewer release entries are removed from all production APIs.
 */
export interface BuilderSignature {
  builderId: string;
  publicKey: string;
  signature: string;
}

export interface ReviewerSignature {
  reviewerId: string;
  publicKey: string;
  signature: string;
}

export interface TransparencyEntry {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays: number;
  emergency: boolean;
  builderSignatures: BuilderSignature[];
  reviewerSignatures: ReviewerSignature[];
}

/**
 * Append-only verification event leaf stored in the `transparency_log` MongoDB collection.
 * Privacy invariant: no PII, prompts, completions, IP addresses, or exact timestamps.
 * All timestamps are coarsened to the start of the UTC hour (divisible by 3600).
 */
export interface VerificationLogEvent {
  index: number;
  kind: "verification_event" | "release_approval" | "independent_verification";
  nodeId: string;
  nodeKind: "tinfoil";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  verifierFingerprint?: string;
  /** Coarsened UTC hour timestamp in seconds (divisible by 3600). */
  epochHourSec: number;
  leafHash: string;
}

export const VERIFIER_CHECK_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"] as const;
export type VerifierCheckId = (typeof VERIFIER_CHECK_IDS)[number];

export interface VerifierCheckStatus {
  id: VerifierCheckId;
  status: "pass" | "fail" | "skip";
}

export interface VerifierModelClaim {
  id: string;
  repo: string;
  tag: string;
  measurement: string;
  dmVerityRootHash?: string;
  weightRepoCommit?: string;
  ok: boolean;
}

export interface VerifierRouterClaim {
  nodeId: string;
  enclaveHost: string;
  configRepo: string;
  releaseDigest: string;
  measurement: string;
}

export const VERIFICATION_CLAIM_DOMAIN = "drouter/transparency/verification-claim/v1" as const;

export interface VerifierSubmissionClaim {
  domain: typeof VERIFICATION_CLAIM_DOMAIN;
  /** Coarsened UTC hour timestamp in seconds (divisible by 3600). */
  epochHourSec: number;
  router: VerifierRouterClaim;
  models: VerifierModelClaim[];
  checks: VerifierCheckStatus[];
  overallOk: boolean;
}

/**
 * Privacy-preserving record stored in MongoDB `verifier_submissions`.
 * Contains only the verifier key fingerprint, verification result, and coarse UTC hour (never IP or sub-hour timestamp).
 */
export interface VerifierSubmissionRecord {
  verifierFingerprint: string;
  epochHourSec: number;
  overallOk: boolean;
  checks: VerifierCheckStatus[];
  router: VerifierRouterClaim;
  models: VerifierModelClaim[];
  evidenceHash: string;
  leafIndex: number;
  leafHash: string;
}

export interface SignedTreeHead {
  treeSize: number;
  rootHash: string;
  /** Coarsened UTC hour timestamp in seconds (divisible by 3600). */
  timestampSec: number;
  operatorPublicKey: string;
  signature: string;
  anchorTx?: string | null;
  anchoredAtSec?: number | null;
}

export interface AuditStep {
  side: "left" | "right";
  hash: string;
}

export interface InclusionProof {
  leafHash: string;
  root: string;
  auditPath: AuditStep[];
  leafIndex?: number;
  treeSize?: number;
}

export interface ConsistencyProof {
  firstTreeSize: number;
  secondTreeSize: number;
  firstRoot: string;
  secondRoot: string;
  consistencyPath: string[];
}

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue | undefined };

function canonicalize(value: JsonValue | undefined): string {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonicalJson cannot encode non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(",")}]`;
      }
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
      return `{${pairs.join(",")}}`;
    }
    default:
      throw new Error(`canonicalJson cannot encode ${typeof value}`);
  }
}

export function canonicalJson(value: unknown): string {
  return canonicalize(value as JsonValue);
}

export function getSeedBytes(): Uint8Array {
  const raw = process.env.SIM_HARDWARE_SEED;
  if (raw && /^[0-9a-fA-F]{64}$/.test(raw)) return hexToBytes(raw);
  // Tests may run without secrets; production must never sign with a public seed.
  if (process.env.VITEST) return hexToBytes("03".repeat(32));
  throw new Error("SIM_HARDWARE_SEED must be set to 64 hex characters");
}

export function deriveEd25519Key(info: string): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const secretKey = hkdf(sha256, getSeedBytes(), undefined, utf8ToBytes(info), 32);
  const publicKey = ed25519.getPublicKey(secretKey);
  return {
    secretKey,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
  };
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** RFC 6962 raw byte leaf hash: sha256(0x00 || rawLeafBytes) */
export function computeRawLeafHash(rawLeafBytes: Uint8Array): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(0x00), rawLeafBytes));
}

/** RFC 6962 leaf hash: sha256(0x00 || utf8ToBytes(canonicalJson(entry))) */
export function computeLeafHash(entry: unknown): Uint8Array {
  if (entry instanceof Uint8Array) {
    return computeRawLeafHash(entry);
  }
  const payload = utf8ToBytes(canonicalJson(entry));
  return computeRawLeafHash(payload);
}

/** RFC 6962 internal node hash: sha256(0x01 || left || right) */
export function computeNodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(0x01), left, right));
}

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

export function computeMerkleRootFromLeaves(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    return sha256(new Uint8Array(0));
  }
  if (leaves.length === 1) {
    return leaves[0];
  }
  const k = largestPowerOfTwoLessThan(leaves.length);
  const left = computeMerkleRootFromLeaves(leaves.slice(0, k));
  const right = computeMerkleRootFromLeaves(leaves.slice(k));
  return computeNodeHash(left, right);
}

export function computeAuditPathFromLeaves(leaves: Uint8Array[], index: number): AuditStep[] {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`Transparency log index out of range: ${index}`);
  }
  if (leaves.length <= 1) {
    return [];
  }
  const k = largestPowerOfTwoLessThan(leaves.length);
  if (index < k) {
    const subPath = computeAuditPathFromLeaves(leaves.slice(0, k), index);
    const rightRoot = computeMerkleRootFromLeaves(leaves.slice(k));
    return [...subPath, { side: "right", hash: bytesToHex(rightRoot) }];
  } else {
    const subPath = computeAuditPathFromLeaves(leaves.slice(k), index - k);
    const leftRoot = computeMerkleRootFromLeaves(leaves.slice(0, k));
    return [...subPath, { side: "left", hash: bytesToHex(leftRoot) }];
  }
}

/**
 * RFC 6962 Section 2.1.2 SUBPROOF(m, D[n], b)
 * Computes the consistency proof hashes showing that the first `m` leaves of `leaves` (length `n`)
 * form a prefix tree of the full tree of size `n`.
 */
function computeSubproofFromLeaves(leaves: Uint8Array[], m: number, isCompleteSubtree: boolean): Uint8Array[] {
  const n = leaves.length;
  if (m === n) {
    if (isCompleteSubtree) {
      return [];
    }
    return [computeMerkleRootFromLeaves(leaves)];
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    const sub = computeSubproofFromLeaves(leaves.slice(0, k), m, isCompleteSubtree);
    const rightRoot = computeMerkleRootFromLeaves(leaves.slice(k));
    return [...sub, rightRoot];
  } else {
    const sub = computeSubproofFromLeaves(leaves.slice(k), m - k, false);
    const leftRoot = computeMerkleRootFromLeaves(leaves.slice(0, k));
    return [...sub, leftRoot];
  }
}

/**
 * RFC 6962 Section 2.1.2 PROOF(m, D[n])
 * Returns the consistency path (hex hashes) between tree size `firstSize` (m) and `secondSize` (n).
 */
export function computeConsistencyPathFromLeaves(
  leaves: Uint8Array[],
  firstSize: number,
  secondSize: number = leaves.length,
): string[] {
  if (
    !Number.isInteger(firstSize) ||
    !Number.isInteger(secondSize) ||
    firstSize < 0 ||
    secondSize < firstSize ||
    secondSize > leaves.length
  ) {
    throw new Error(`Invalid consistency proof sizes: first=${firstSize}, second=${secondSize}, total=${leaves.length}`);
  }
  if (firstSize === 0 || firstSize === secondSize) {
    return [];
  }
  const subset = leaves.slice(0, secondSize);
  return computeSubproofFromLeaves(subset, firstSize, true).map(bytesToHex);
}

export function proveConsistencyFromLeaves(
  leaves: Uint8Array[],
  firstSize: number,
  secondSize: number = leaves.length,
): ConsistencyProof {
  if (
    !Number.isInteger(firstSize) ||
    !Number.isInteger(secondSize) ||
    firstSize < 0 ||
    secondSize < firstSize ||
    secondSize > leaves.length
  ) {
    throw new Error(`Invalid consistency proof sizes: first=${firstSize}, second=${secondSize}, total=${leaves.length}`);
  }
  const firstRoot = bytesToHex(computeMerkleRootFromLeaves(leaves.slice(0, firstSize)));
  const secondRoot = bytesToHex(computeMerkleRootFromLeaves(leaves.slice(0, secondSize)));
  const consistencyPath = computeConsistencyPathFromLeaves(leaves, firstSize, secondSize);
  return {
    firstTreeSize: firstSize,
    secondTreeSize: secondSize,
    firstRoot,
    secondRoot,
    consistencyPath,
  };
}

/**
 * Pure client-side verifier for RFC 6962 Merkle inclusion proofs.
 * Verifies both the auditPath Step direction ("left"/"right") AND optionally the RFC 6962 index/treeSize bit decomposition.
 */
export function verifyInclusionProofClient(proof: InclusionProof): {
  ok: boolean;
  computedRoot: string;
  detail: string;
} {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(proof.leafHash) || !/^[0-9a-fA-F]{64}$/.test(proof.root)) {
      return { ok: false, computedRoot: "", detail: "Invalid leafHash or root hex format" };
    }

    if (proof.leafIndex !== undefined && proof.treeSize !== undefined) {
      let fn = proof.leafIndex;
      let sn = proof.treeSize - 1;
      if (proof.leafIndex < 0 || proof.treeSize <= 0 || proof.leafIndex >= proof.treeSize) {
        return { ok: false, computedRoot: "", detail: "Invalid leafIndex or treeSize bounds" };
      }
      let r: Uint8Array = hexToBytes(proof.leafHash);
      for (const step of proof.auditPath) {
        if (!/^[0-9a-fA-F]{64}$/.test(step.hash)) {
          return { ok: false, computedRoot: "", detail: "Invalid audit step hash hex" };
        }
        if (sn === 0) {
          return { ok: false, computedRoot: "", detail: "Audit path too long for treeSize" };
        }
        const c = hexToBytes(step.hash);
        if ((fn & 1) === 1 || fn === sn) {
          if (step.side !== "left") {
            return { ok: false, computedRoot: "", detail: "Audit step side mismatch against RFC 6962 index parity" };
          }
          r = computeNodeHash(c, r);
          while ((fn & 1) === 0 && fn !== 0) {
            fn >>= 1;
            sn >>= 1;
          }
        } else {
          if (step.side !== "right") {
            return { ok: false, computedRoot: "", detail: "Audit step side mismatch against RFC 6962 index parity" };
          }
          r = computeNodeHash(r, c);
        }
        fn >>= 1;
        sn >>= 1;
      }
      if (sn !== 0) {
        return { ok: false, computedRoot: "", detail: "Audit path too short for treeSize" };
      }
      const computedRoot = bytesToHex(r);
      const ok = computedRoot.toLowerCase() === proof.root.toLowerCase();
      return {
        ok,
        computedRoot,
        detail: ok
          ? `RFC 6962 inclusion proof verified for leaf #${proof.leafIndex} in tree of size ${proof.treeSize}.`
          : "Computed root does not match expected tree root",
      };
    }

    let current: Uint8Array = hexToBytes(proof.leafHash);
    for (const step of proof.auditPath) {
      if (!/^[0-9a-fA-F]{64}$/.test(step.hash)) {
        return { ok: false, computedRoot: "", detail: "Invalid audit step hash hex" };
      }
      const sibling = hexToBytes(step.hash);
      if (step.side === "left") {
        current = computeNodeHash(sibling, current);
      } else if (step.side === "right") {
        current = computeNodeHash(current, sibling);
      } else {
        return { ok: false, computedRoot: "", detail: "Invalid audit step side" };
      }
    }
    const computedRoot = bytesToHex(current);
    const ok = computedRoot.toLowerCase() === proof.root.toLowerCase();
    return {
      ok,
      computedRoot,
      detail: ok ? `RFC 6962 inclusion proof verified under root ${computedRoot.slice(0, 16)}...` : "Root hash mismatch",
    };
  } catch {
    return { ok: false, computedRoot: "", detail: "Failed to verify inclusion proof" };
  }
}

/**
 * Pure client-side verifier for RFC 6962 Section 2.1.2 Merkle consistency proofs.
 */
export function verifyConsistencyProofClient(proof: ConsistencyProof): {
  ok: boolean;
  detail: string;
} {
  try {
    const { firstTreeSize: first, secondTreeSize: second, firstRoot, secondRoot, consistencyPath } = proof;
    if (
      !Number.isInteger(first) ||
      !Number.isInteger(second) ||
      first < 0 ||
      second < first ||
      !/^[0-9a-fA-F]{64}$/.test(firstRoot) ||
      !/^[0-9a-fA-F]{64}$/.test(secondRoot)
    ) {
      return { ok: false, detail: "Invalid consistency proof parameters" };
    }
    if (first === 0) {
      const emptyHash = bytesToHex(sha256(new Uint8Array(0)));
      const ok = firstRoot.toLowerCase() === emptyHash && consistencyPath.length === 0;
      return { ok, detail: ok ? "Trivial consistency from empty tree verified." : "Invalid empty tree consistency proof" };
    }
    if (first === second) {
      const ok = firstRoot.toLowerCase() === secondRoot.toLowerCase() && consistencyPath.length === 0;
      return {
        ok,
        detail: ok ? `Identical tree size (${first}) root match verified.` : "Mismatch on equal-size consistency proof",
      };
    }
    if (consistencyPath.length === 0) {
      return { ok: false, detail: "Empty consistency path for distinct non-empty trees" };
    }
    for (const h of consistencyPath) {
      if (!/^[0-9a-fA-F]{64}$/.test(h)) {
        return { ok: false, detail: "Invalid hex hash in consistencyPath" };
      }
    }

    const pathBytes: Uint8Array[] = isPowerOfTwo(first)
      ? [hexToBytes(firstRoot), ...consistencyPath.map(hexToBytes)]
      : consistencyPath.map(hexToBytes);

    let fn = first - 1;
    let sn = second - 1;
    while ((fn & 1) === 1) {
      fn >>= 1;
      sn >>= 1;
    }

    let fr: Uint8Array = pathBytes[0];
    let sr: Uint8Array = pathBytes[0];

    for (let i = 1; i < pathBytes.length; i++) {
      const c = pathBytes[i];
      if (sn === 0) {
        return { ok: false, detail: "Consistency path too long for tree sizes" };
      }
      if ((fn & 1) === 1 || fn === sn) {
        fr = computeNodeHash(c, fr);
        sr = computeNodeHash(c, sr);
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      } else {
        sr = computeNodeHash(sr, c);
      }
      fn >>= 1;
      sn >>= 1;
    }

    if (sn !== 0) {
      return { ok: false, detail: "Consistency path too short for tree sizes" };
    }

    const frHex = bytesToHex(fr).toLowerCase();
    const srHex = bytesToHex(sr).toLowerCase();
    const ok = frHex === firstRoot.toLowerCase() && srHex === secondRoot.toLowerCase();
    return {
      ok,
      detail: ok
        ? `RFC 6962 consistency proof verified from tree size ${first} to ${second}.`
        : "Reconstructed roots do not match firstRoot and secondRoot",
    };
  } catch {
    return { ok: false, detail: "Consistency proof verification threw an error" };
  }
}

/**
 * Operator Ed25519 key derived from server secret (SIM_HARDWARE_SEED).
 */
export function getOperatorKey(): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  return deriveEd25519Key("transparency/operator-tree-head-v1");
}

export function getOperatorPublicKey(): string {
  return getOperatorKey().publicKeyHex;
}

export function treeHeadSigningPayload(
  sth: Pick<SignedTreeHead, "treeSize" | "rootHash" | "timestampSec">,
): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      domain: "drouter/transparency/sth/v1",
      rootHash: sth.rootHash.toLowerCase(),
      timestampSec: sth.timestampSec,
      treeSize: sth.treeSize,
    }),
  );
}

/** Coarsens a Unix timestamp in seconds down to the start of the UTC hour (divisible by 3600). */
export function coarsenEpochSecToHour(sec: number = Math.floor(Date.now() / 1000)): number {
  return Math.floor(sec / 3600) * 3600;
}

export function signTreeHead(params: {
  treeSize: number;
  rootHash: string;
  timestampSec?: number;
  anchorTx?: string | null;
  anchoredAtSec?: number | null;
}): SignedTreeHead {
  const timestampSec = coarsenEpochSecToHour(params.timestampSec ?? Math.floor(Date.now() / 1000));
  const key = getOperatorKey();
  const payload = treeHeadSigningPayload({
    treeSize: params.treeSize,
    rootHash: params.rootHash,
    timestampSec,
  });
  const signature = bytesToHex(ed25519.sign(payload, key.secretKey));
  return {
    treeSize: params.treeSize,
    rootHash: params.rootHash.toLowerCase(),
    timestampSec,
    operatorPublicKey: key.publicKeyHex,
    signature,
    anchorTx: params.anchorTx ?? null,
    anchoredAtSec: params.anchoredAtSec ?? null,
  };
}

/**
 * Pure client-side verifier for operator-signed tree heads (STH).
 */
export function verifySignedTreeHeadClient(
  sth: SignedTreeHead,
  expectedOperatorPublicKey?: string,
): { ok: boolean; detail: string } {
  try {
    const pubHex = (expectedOperatorPublicKey ?? sth.operatorPublicKey).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubHex) || sth.operatorPublicKey.toLowerCase() !== pubHex) {
      return { ok: false, detail: "Operator public key mismatch or invalid format" };
    }
    if (!/^[0-9a-fA-F]{64}$/.test(sth.rootHash) || !/^[0-9a-fA-F]{128}$/.test(sth.signature)) {
      return { ok: false, detail: "Invalid rootHash or Ed25519 signature hex" };
    }
    if (!Number.isInteger(sth.treeSize) || sth.treeSize < 0) {
      return { ok: false, detail: "Invalid treeSize" };
    }
    if (!Number.isInteger(sth.timestampSec) || sth.timestampSec % 3600 !== 0) {
      return { ok: false, detail: "STH timestampSec must be coarsened to the UTC hour" };
    }
    const payload = treeHeadSigningPayload(sth);
    const verified = ed25519.verify(hexToBytes(sth.signature), payload, hexToBytes(pubHex));
    return {
      ok: verified,
      detail: verified
        ? `Operator Ed25519 signature verified on tree head (size=${sth.treeSize}, root=${sth.rootHash.slice(0, 16)}...).`
        : "Ed25519 signature verification failed on signed tree head",
    };
  } catch {
    return { ok: false, detail: "Failed to verify signed tree head" };
  }
}

/**
 * Pure client-side combined verifier for an inclusion proof, consistency proof, and signed tree head.
 */
export function verifyTransparencyProofBundleClient(params: {
  sth: SignedTreeHead;
  expectedOperatorPublicKey?: string;
  inclusionProof?: InclusionProof;
  consistencyProof?: ConsistencyProof;
}): {
  ok: boolean;
  sthVerified: boolean;
  inclusionVerified: boolean;
  consistencyVerified: boolean;
  detail: string;
} {
  const sthRes = verifySignedTreeHeadClient(params.sth, params.expectedOperatorPublicKey);
  let inclusionVerified = true;
  let consistencyVerified = true;
  const reasons: string[] = [];
  if (!sthRes.ok) reasons.push(sthRes.detail);

  if (params.inclusionProof) {
    const incRes = verifyInclusionProofClient(params.inclusionProof);
    const rootMatchesSth = params.inclusionProof.root.toLowerCase() === params.sth.rootHash.toLowerCase();
    inclusionVerified = incRes.ok && rootMatchesSth;
    if (!incRes.ok) reasons.push(incRes.detail);
    else if (!rootMatchesSth) reasons.push("Inclusion proof root does not match signed tree head rootHash");
  }

  if (params.consistencyProof) {
    const conRes = verifyConsistencyProofClient(params.consistencyProof);
    const secondMatchesSth =
      params.consistencyProof.secondRoot.toLowerCase() === params.sth.rootHash.toLowerCase() &&
      params.consistencyProof.secondTreeSize === params.sth.treeSize;
    consistencyVerified = conRes.ok && secondMatchesSth;
    if (!conRes.ok) reasons.push(conRes.detail);
    else if (!secondMatchesSth) reasons.push("Consistency proof secondRoot/secondTreeSize does not match STH");
  }

  const ok = sthRes.ok && inclusionVerified && consistencyVerified;
  return {
    ok,
    sthVerified: sthRes.ok,
    inclusionVerified,
    consistencyVerified,
    detail: ok ? "All transparency proofs and operator STH verified." : reasons.join("; "),
  };
}

export function createVerificationLogEvent(params: {
  index: number;
  kind?: "verification_event" | "release_approval" | "independent_verification";
  nodeId: string;
  nodeKind?: "tinfoil";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  verifierFingerprint?: string;
  timestampSec?: number;
}): VerificationLogEvent {
  const epochHourSec = coarsenEpochSecToHour(params.timestampSec ?? Math.floor(Date.now() / 1000));
  const core = {
    index: params.index,
    kind: params.kind ?? "verification_event",
    nodeId: String(params.nodeId).slice(0, 80),
    nodeKind: "tinfoil" as const,
    ok: Boolean(params.ok),
    measurement: String(params.measurement).slice(0, 256),
    evidenceHash: String(params.evidenceHash).slice(0, 128),
    ...(params.releaseDigest ? { releaseDigest: String(params.releaseDigest).slice(0, 128) } : {}),
    ...(params.enclaveHost ? { enclaveHost: String(params.enclaveHost).slice(0, 128) } : {}),
    ...(params.verifierFingerprint ? { verifierFingerprint: String(params.verifierFingerprint).slice(0, 64) } : {}),
    epochHourSec,
  };
  const leafHash = bytesToHex(computeLeafHash(core));
  return {
    ...core,
    leafHash,
  };
}

/**
 * Computes the SHA-256 fingerprint (64 lowercase hex chars) of an Ed25519 public key.
 */
export function computeVerifierFingerprint(publicKeyHexOrBytes: string | Uint8Array): string {
  const pubBytes =
    typeof publicKeyHexOrBytes === "string"
      ? hexToBytes(publicKeyHexOrBytes.replace(/^0x/i, ""))
      : publicKeyHexOrBytes;
  if (pubBytes.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  return bytesToHex(sha256(pubBytes)).toLowerCase();
}

/**
 * Canonicalizes a `VerifierSubmissionClaim` so models are sorted by ID, checks are ordered C1..C7,
 * hex digests are lowercased, and `epochHourSec` is coarsened to the UTC hour.
 */
export function normalizeVerificationClaim(claim: VerifierSubmissionClaim): VerifierSubmissionClaim {
  const checkMap = new Map<string, "pass" | "fail" | "skip">();
  if (Array.isArray(claim.checks)) {
    for (const c of claim.checks) {
      if (c && typeof c.id === "string" && (c.status === "pass" || c.status === "fail" || c.status === "skip")) {
        checkMap.set(c.id, c.status);
      }
    }
  }
  const checks: VerifierCheckStatus[] = VERIFIER_CHECK_IDS.map((id) => ({
    id,
    status: checkMap.get(id) ?? "skip",
  }));

  const models: VerifierModelClaim[] = Array.isArray(claim.models)
    ? [...claim.models]
        .map((m) => ({
          id: String(m.id ?? "").trim(),
          repo: String(m.repo ?? "").trim(),
          tag: String(m.tag ?? "").trim(),
          measurement: String(m.measurement ?? "").trim().toLowerCase(),
          ...(m.dmVerityRootHash ? { dmVerityRootHash: String(m.dmVerityRootHash).trim().toLowerCase() } : {}),
          ...(m.weightRepoCommit ? { weightRepoCommit: String(m.weightRepoCommit).trim() } : {}),
          ok: Boolean(m.ok),
        }))
        .sort((a, b) => a.id.localeCompare(b.id))
    : [];

  return {
    domain: VERIFICATION_CLAIM_DOMAIN,
    epochHourSec: coarsenEpochSecToHour(claim.epochHourSec),
    router: {
      nodeId: String(claim.router?.nodeId ?? "tinfoil-router").trim(),
      enclaveHost: String(claim.router?.enclaveHost ?? "").trim().toLowerCase(),
      configRepo: String(claim.router?.configRepo ?? "").trim(),
      releaseDigest: String(claim.router?.releaseDigest ?? "").trim().toLowerCase(),
      measurement: String(claim.router?.measurement ?? "").trim().toLowerCase(),
    },
    models,
    checks,
    overallOk: Boolean(claim.overallOk),
  };
}

export function verificationClaimSigningPayload(claim: VerifierSubmissionClaim): Uint8Array {
  return utf8ToBytes(canonicalJson(normalizeVerificationClaim(claim)));
}

export function computeVerificationClaimEvidenceHash(claim: VerifierSubmissionClaim): string {
  return bytesToHex(sha256(verificationClaimSigningPayload(claim))).toLowerCase();
}

export function signVerificationClaim(
  claim: VerifierSubmissionClaim,
  secretKeyHexOrBytes: string | Uint8Array,
): {
  publicKey: string;
  verifierFingerprint: string;
  signature: string;
  claim: VerifierSubmissionClaim;
  evidenceHash: string;
} {
  const secretKey =
    typeof secretKeyHexOrBytes === "string"
      ? hexToBytes(secretKeyHexOrBytes.replace(/^0x/i, ""))
      : secretKeyHexOrBytes;
  if (secretKey.length !== 32) {
    throw new Error("Ed25519 secret key must be 32 bytes");
  }
  const normalized = normalizeVerificationClaim(claim);
  const publicKeyBytes = ed25519.getPublicKey(secretKey);
  const publicKey = bytesToHex(publicKeyBytes).toLowerCase();
  const verifierFingerprint = computeVerifierFingerprint(publicKeyBytes);
  const payload = verificationClaimSigningPayload(normalized);
  const signature = bytesToHex(ed25519.sign(payload, secretKey)).toLowerCase();
  const evidenceHash = bytesToHex(sha256(payload)).toLowerCase();
  return {
    publicKey,
    verifierFingerprint,
    signature,
    claim: normalized,
    evidenceHash,
  };
}

export function verifyVerificationClaimSignature(params: {
  publicKey: string;
  signature: string;
  claim: VerifierSubmissionClaim;
}): {
  ok: boolean;
  verifierFingerprint: string;
  evidenceHash: string;
  normalizedClaim?: VerifierSubmissionClaim;
  detail: string;
} {
  try {
    const cleanPub = String(params.publicKey ?? "").replace(/^0x/i, "").toLowerCase();
    const cleanSig = String(params.signature ?? "").replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(cleanPub)) {
      return { ok: false, verifierFingerprint: "", evidenceHash: "", detail: "Invalid Ed25519 publicKey hex (expected 64 hex chars)" };
    }
    if (!/^[0-9a-f]{128}$/.test(cleanSig)) {
      return { ok: false, verifierFingerprint: "", evidenceHash: "", detail: "Invalid Ed25519 signature hex (expected 128 hex chars)" };
    }
    if (!params.claim || typeof params.claim !== "object" || params.claim.domain !== VERIFICATION_CLAIM_DOMAIN) {
      return { ok: false, verifierFingerprint: "", evidenceHash: "", detail: `Invalid claim domain (expected ${VERIFICATION_CLAIM_DOMAIN})` };
    }
    if (!Number.isInteger(params.claim.epochHourSec) || params.claim.epochHourSec <= 0 || params.claim.epochHourSec % 3600 !== 0) {
      return { ok: false, verifierFingerprint: "", evidenceHash: "", detail: "claim.epochHourSec must be a positive integer divisible by 3600" };
    }
    if (!Array.isArray(params.claim.checks) || params.claim.checks.length !== VERIFIER_CHECK_IDS.length) {
      return { ok: false, verifierFingerprint: "", evidenceHash: "", detail: "claim.checks must contain C1 through C7" };
    }
    for (let i = 0; i < VERIFIER_CHECK_IDS.length; i++) {
      const c = params.claim.checks[i];
      if (!c || c.id !== VERIFIER_CHECK_IDS[i] || (c.status !== "pass" && c.status !== "fail" && c.status !== "skip")) {
        return {
          ok: false,
          verifierFingerprint: "",
          evidenceHash: "",
          detail: `claim.checks[${i}] must be ${VERIFIER_CHECK_IDS[i]} with status pass, fail, or skip`,
        };
      }
    }

    const normalized = normalizeVerificationClaim(params.claim);
    const payload = verificationClaimSigningPayload(normalized);
    const pubBytes = hexToBytes(cleanPub);
    const sigBytes = hexToBytes(cleanSig);
    const verified = ed25519.verify(sigBytes, payload, pubBytes);
    if (!verified) {
      return {
        ok: false,
        verifierFingerprint: computeVerifierFingerprint(pubBytes),
        evidenceHash: bytesToHex(sha256(payload)).toLowerCase(),
        detail: "Ed25519 signature verification failed over canonical verification claim",
      };
    }

    return {
      ok: true,
      verifierFingerprint: computeVerifierFingerprint(pubBytes),
      evidenceHash: bytesToHex(sha256(payload)).toLowerCase(),
      normalizedClaim: normalized,
      detail: "Ed25519 signature verified over canonical C1-C7 verification claim",
    };
  } catch {
    return {
      ok: false,
      verifierFingerprint: "",
      evidenceHash: "",
      detail: "Failed to verify verification claim signature",
    };
  }
}
