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

export interface AuditStep {
  side: "left" | "right";
  hash: string;
}

export interface InclusionProof {
  leafHash: string;
  root: string;
  auditPath: AuditStep[];
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

/** RFC 6962 leaf hash: sha256(0x00 || utf8ToBytes(canonicalJson(entry))) */
export function computeLeafHash(entry: TransparencyEntry): Uint8Array {
  const payload = utf8ToBytes(canonicalJson(entry));
  return sha256(concatBytes(Uint8Array.of(0x00), payload));
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
  };
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
