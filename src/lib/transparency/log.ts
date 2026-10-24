import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

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
  kind: "verification_event" | "release_approval";
  nodeId: string;
  nodeKind: "tinfoil" | "sim";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  /** Coarsened UTC hour timestamp in seconds (divisible by 3600). */
  epochHourSec: number;
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

export const BUILDER_IDS = ["builder-ethz", "builder-stanford", "builder-tinfoil"] as const;
export const REVIEWER_IDS = [
  "reviewer-1",
  "reviewer-2",
  "reviewer-3",
  "reviewer-4",
  "reviewer-5",
  "reviewer-6",
  "reviewer-7",
] as const;

const NORMAL_REVIEW_WINDOW_DAYS = 14;
const EMERGENCY_REVIEW_WINDOW_DAYS = 2; // 48 hours
const SECONDS_PER_DAY = 86400;

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
  const raw = process.env.SIM_HARDWARE_SEED || "03".repeat(32);
  const validHex = /^[0-9a-fA-F]{64}$/.test(raw) ? raw : "03".repeat(32);
  return hexToBytes(validHex);
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

function builderKey(builderId: string) {
  return deriveEd25519Key(`transparency/builder/${builderId}`);
}

function reviewerKey(reviewerId: string) {
  return deriveEd25519Key(`transparency/reviewer/${reviewerId}`);
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

export function entrySigningPayload(
  entry: Pick<
    TransparencyEntry,
    "index" | "imageId" | "version" | "measurement" | "approvedAt" | "reviewWindowDays" | "emergency"
  >,
): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      approvedAt: entry.approvedAt,
      emergency: entry.emergency,
      imageId: entry.imageId,
      index: entry.index,
      measurement: entry.measurement,
      reviewWindowDays: entry.reviewWindowDays,
      version: entry.version,
    }),
  );
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

    // If leafIndex and treeSize are provided, also verify RFC 6962 Section 2.1.1 index/treeSize structure
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
  kind?: "verification_event" | "release_approval";
  nodeId: string;
  nodeKind: "tinfoil" | "sim";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  timestampSec?: number;
}): VerificationLogEvent {
  const epochHourSec = coarsenEpochSecToHour(params.timestampSec ?? Math.floor(Date.now() / 1000));
  const core = {
    index: params.index,
    kind: params.kind ?? "verification_event",
    nodeId: String(params.nodeId).slice(0, 80),
    nodeKind: params.nodeKind === "tinfoil" ? ("tinfoil" as const) : ("sim" as const),
    ok: Boolean(params.ok),
    measurement: String(params.measurement).slice(0, 256),
    evidenceHash: String(params.evidenceHash).slice(0, 128),
    ...(params.releaseDigest ? { releaseDigest: String(params.releaseDigest).slice(0, 128) } : {}),
    ...(params.enclaveHost ? { enclaveHost: String(params.enclaveHost).slice(0, 128) } : {}),
    epochHourSec,
  };
  const leafHash = bytesToHex(computeLeafHash(core));
  return {
    ...core,
    leafHash,
  };
}

export function createSignedTransparencyEntry(params: {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays?: number;
  emergency?: boolean;
  builderCount?: number;
  reviewerCount?: number;
}): TransparencyEntry {
  const emergency = params.emergency ?? false;
  const reviewWindowDays =
    params.reviewWindowDays ?? (emergency ? EMERGENCY_REVIEW_WINDOW_DAYS : NORMAL_REVIEW_WINDOW_DAYS);
  const builderCount = Math.min(Math.max(params.builderCount ?? 3, 0), BUILDER_IDS.length);
  const defaultReviewers = emergency ? 7 : 5;
  const reviewerCount = Math.min(Math.max(params.reviewerCount ?? defaultReviewers, 0), REVIEWER_IDS.length);

  const core = {
    index: params.index,
    imageId: params.imageId,
    version: params.version,
    measurement: params.measurement,
    approvedAt: params.approvedAt,
    reviewWindowDays,
    emergency,
  };
  const payload = entrySigningPayload(core);

  const builderSignatures: BuilderSignature[] = BUILDER_IDS.slice(0, builderCount).map((builderId) => {
    const key = builderKey(builderId);
    return {
      builderId,
      publicKey: key.publicKeyHex,
      signature: bytesToHex(ed25519.sign(payload, key.secretKey)),
    };
  });

  const reviewerSignatures: ReviewerSignature[] = REVIEWER_IDS.slice(0, reviewerCount).map((reviewerId) => {
    const key = reviewerKey(reviewerId);
    return {
      reviewerId,
      publicKey: key.publicKeyHex,
      signature: bytesToHex(ed25519.sign(payload, key.secretKey)),
    };
  });

  return {
    ...core,
    builderSignatures,
    reviewerSignatures,
  };
}

function buildEntries(): TransparencyEntry[] {
  // Approved dates in early 2025 so the 14-day / 48-hour review windows have elapsed.
  return [
    createSignedTransparencyEntry({
      index: 0,
      imageId: "tinfoilsh/confidential-model-router",
      version: "v0.0.167",
      measurement: bytesToHex(sha384(utf8ToBytes("tinfoilsh/confidential-model-router@v0.0.167"))),
      approvedAt: 1735689600, // 2025-01-01T00:00:00Z
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 3,
      reviewerCount: 5,
    }),
    createSignedTransparencyEntry({
      index: 1,
      imageId: "drouter-sim-node-image/v0.1.0",
      version: "v0.1.0",
      measurement: bytesToHex(sha384(utf8ToBytes("drouter-sim-node-image/v0.1.0"))),
      approvedAt: 1738368000, // 2025-02-01T00:00:00Z
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 3,
      reviewerCount: 5,
    }),
    createSignedTransparencyEntry({
      index: 2,
      imageId: "drouter-monitor-svsm/v0.1.0",
      version: "v0.1.0",
      measurement: bytesToHex(sha384(utf8ToBytes("drouter-monitor-svsm/v0.1.0"))),
      approvedAt: 1740787200, // 2025-03-01T00:00:00Z
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 3,
      reviewerCount: 5,
    }),
  ];
}

export function getTransparencyLog(): { root: string; entries: TransparencyEntry[] } {
  const entries = buildEntries();
  const leaves = entries.map(computeLeafHash);
  const root = bytesToHex(computeMerkleRootFromLeaves(leaves));
  return { root, entries };
}

export function proveInclusion(index: number): InclusionProof {
  const entries = buildEntries();
  if (index < 0 || index >= entries.length) {
    throw new Error(`Transparency log index out of range: ${index}`);
  }
  const leaves = entries.map(computeLeafHash);
  const root = bytesToHex(computeMerkleRootFromLeaves(leaves));
  const auditPath = computeAuditPathFromLeaves(leaves, index);
  return {
    leafHash: bytesToHex(leaves[index]),
    root,
    auditPath,
    leafIndex: index,
    treeSize: entries.length,
  };
}

export function proveConsistency(firstSize: number, secondSize?: number): ConsistencyProof {
  const entries = buildEntries();
  const leaves = entries.map(computeLeafHash);
  return proveConsistencyFromLeaves(leaves, firstSize, secondSize ?? leaves.length);
}

export function verifyInclusion(
  entry: TransparencyEntry,
  proof: { root: string; auditPath: { side: "left" | "right"; hash: string }[] },
  nowSec?: number,
): {
  ok: boolean;
  builderCount: number;
  reviewerCount: number;
  reviewWindowPassed: boolean;
  detail: string;
} {
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  const payload = entrySigningPayload(entry);

  // 1. Verify builder signatures (need >= 3 reproducible builders, no invalid/duplicate signatures)
  const validBuilders = new Set<string>();
  let allBuilderSigsValid = true;
  for (const sig of entry.builderSignatures) {
    if (!BUILDER_IDS.includes(sig.builderId as (typeof BUILDER_IDS)[number]) || validBuilders.has(sig.builderId)) {
      allBuilderSigsValid = false;
      continue;
    }
    try {
      const expected = builderKey(sig.builderId);
      if (sig.publicKey.toLowerCase() !== expected.publicKeyHex.toLowerCase()) {
        allBuilderSigsValid = false;
        continue;
      }
      const sigBytes = hexToBytes(sig.signature);
      if (ed25519.verify(sigBytes, payload, expected.publicKey)) {
        validBuilders.add(sig.builderId);
      } else {
        allBuilderSigsValid = false;
      }
    } catch {
      allBuilderSigsValid = false;
    }
  }
  const builderCount = validBuilders.size;

  // 2. Verify reviewer signatures (need >= 4 of 7 for normal, or 7 of 7 for emergency)
  const validReviewers = new Set<string>();
  let allReviewerSigsValid = true;
  for (const sig of entry.reviewerSignatures) {
    if (!REVIEWER_IDS.includes(sig.reviewerId as (typeof REVIEWER_IDS)[number]) || validReviewers.has(sig.reviewerId)) {
      allReviewerSigsValid = false;
      continue;
    }
    try {
      const expected = reviewerKey(sig.reviewerId);
      if (sig.publicKey.toLowerCase() !== expected.publicKeyHex.toLowerCase()) {
        allReviewerSigsValid = false;
        continue;
      }
      const sigBytes = hexToBytes(sig.signature);
      if (ed25519.verify(sigBytes, payload, expected.publicKey)) {
        validReviewers.add(sig.reviewerId);
      } else {
        allReviewerSigsValid = false;
      }
    } catch {
      allReviewerSigsValid = false;
    }
  }
  const reviewerCount = validReviewers.size;
  const requiredReviewers = entry.emergency ? 7 : 4;

  // 3. Verify review window elapsed (14 days normal, 48h emergency)
  const minWindowDays = entry.emergency ? EMERGENCY_REVIEW_WINDOW_DAYS : NORMAL_REVIEW_WINDOW_DAYS;
  const effectiveWindowDays = Math.max(entry.reviewWindowDays, minWindowDays);
  const reviewWindowPassed =
    entry.reviewWindowDays >= minWindowDays && now - entry.approvedAt >= effectiveWindowDays * SECONDS_PER_DAY;

  // 4. Verify RFC 6962 Merkle path from leaf hash to proof.root
  let merkleOk = false;
  try {
    let current = computeLeafHash(entry);
    let pathValid = true;
    for (const step of proof.auditPath) {
      if (!/^[0-9a-fA-F]{64}$/.test(step.hash)) {
        pathValid = false;
        break;
      }
      const sibling = hexToBytes(step.hash);
      if (step.side === "left") {
        current = computeNodeHash(sibling, current);
      } else if (step.side === "right") {
        current = computeNodeHash(current, sibling);
      } else {
        pathValid = false;
        break;
      }
    }
    merkleOk = pathValid && bytesToHex(current).toLowerCase() === proof.root.toLowerCase();
  } catch {
    merkleOk = false;
  }

  const reasons: string[] = [];
  if (!merkleOk) {
    reasons.push("Merkle inclusion proof does not match transparency log root");
  }
  if (!allBuilderSigsValid || builderCount < 3) {
    reasons.push(`requires 3 valid builder signatures (got ${builderCount})`);
  }
  if (!allReviewerSigsValid || reviewerCount < requiredReviewers) {
    reasons.push(`requires ${requiredReviewers} valid reviewer signatures (got ${reviewerCount})`);
  }
  if (!reviewWindowPassed) {
    reasons.push(`review window (${minWindowDays}d minimum) has not elapsed`);
  }

  const ok = reasons.length === 0;
  return {
    ok,
    builderCount,
    reviewerCount,
    reviewWindowPassed,
    detail: ok
      ? `Merkle inclusion verified under root ${proof.root.slice(0, 16)}…; ${builderCount}/3 builders, ${reviewerCount}/7 reviewers, ${entry.reviewWindowDays}d review window passed.`
      : reasons.join("; "),
  };
}
