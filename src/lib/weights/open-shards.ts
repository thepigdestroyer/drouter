import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export interface OpenModelSpec {
  modelId: string;
  kind: "open";
  totalParams: string;
  activeParams: string;
  quantization: string;
  shardCount: number;
  tokenizerHash: string;
  shardHashes: string[];
  merkleRoot: string;
}

export interface ClosedModelSpec {
  modelId: string;
  kind: "closed";
  totalParams: string;
  activeParams: string;
  quantization: string;
  shardCount: number;
  tokenizerHash: string;
  weightKeyCommitment: string;
}

export interface ModelRegistryEntry {
  modelId: string;
  kind: "open" | "closed";
  totalParams: string;
  activeParams: string;
  shardCount: number;
  tokenizerHash: string;
  weightRootOrCommitment: string;
}

export interface MerkleProofStep {
  side: "left" | "right";
  hash: string;
}

export interface ShardMembershipProof {
  shardHash: string;
  root: string;
  proof: MerkleProofStep[];
}

function hashPairHex(leftHex: string, rightHex: string): string {
  const leftBytes = hexToBytes(leftHex.toLowerCase());
  const rightBytes = hexToBytes(rightHex.toLowerCase());
  const combined = new Uint8Array(1 + leftBytes.length + rightBytes.length);
  combined[0] = 0x01; // internal node domain separator
  combined.set(leftBytes, 1);
  combined.set(rightBytes, 1 + leftBytes.length);
  return bytesToHex(sha256(combined));
}

function deriveDeterministicShardHashes(modelId: string, shardCount: number, quantization: string): string[] {
  const hashes: string[] = [];
  for (let i = 0; i < shardCount; i++) {
    const label = `drouter:open-shard:v1:${modelId}:${quantization}:shard-${String(i).padStart(4, "0")}`;
    hashes.push(bytesToHex(sha256(utf8ToBytes(label))));
  }
  return hashes;
}

function deriveTokenizerHash(modelId: string): string {
  return bytesToHex(sha256(utf8ToBytes(`drouter:tokenizer:v1:${modelId}:tiktoken-bpe`)));
}

/**
 * Computes the binary Merkle root over per-shard SHA-256 hex digests.
 * Odd levels duplicate the trailing node before pairing.
 */
export function computeShardMerkleRoot(shardHashesHex: string[]): string {
  if (!Array.isArray(shardHashesHex) || shardHashesHex.length === 0) {
    throw new Error("shardHashesHex must be a non-empty array of SHA-256 hex strings");
  }

  let level = shardHashesHex.map((h) => h.toLowerCase());
  while (level.length > 1) {
    const working = level.length % 2 === 1 ? [...level, level[level.length - 1]] : level;
    const nextLevel: string[] = [];
    for (let i = 0; i < working.length; i += 2) {
      nextLevel.push(hashPairHex(working[i], working[i + 1]));
    }
    level = nextLevel;
  }

  return level[0];
}

/**
 * Generates a Merkle inclusion proof for a shard at `shardIndex`.
 */
export function proveShardMembership(
  shardHashesHex: string[],
  shardIndex: number
): ShardMembershipProof {
  if (!Array.isArray(shardHashesHex) || shardHashesHex.length === 0) {
    throw new Error("shardHashesHex must be a non-empty array");
  }
  if (!Number.isInteger(shardIndex) || shardIndex < 0 || shardIndex >= shardHashesHex.length) {
    throw new Error(`shardIndex ${shardIndex} out of bounds for ${shardHashesHex.length} shards`);
  }

  let level = shardHashesHex.map((h) => h.toLowerCase());
  const shardHash = level[shardIndex];
  const proof: MerkleProofStep[] = [];
  let idx = shardIndex;

  while (level.length > 1) {
    const working = level.length % 2 === 1 ? [...level, level[level.length - 1]] : level;
    const isRightNode = idx % 2 === 1;
    const siblingIdx = isRightNode ? idx - 1 : idx + 1;
    proof.push({
      side: isRightNode ? "left" : "right",
      hash: working[siblingIdx],
    });

    const nextLevel: string[] = [];
    for (let i = 0; i < working.length; i += 2) {
      nextLevel.push(hashPairHex(working[i], working[i + 1]));
    }
    level = nextLevel;
    idx = Math.floor(idx / 2);
  }

  return {
    shardHash,
    root: level[0],
    proof,
  };
}

/**
 * Verifies a shard's SHA-256 digest against its Merkle inclusion proof and the registry's committed Merkle root
 * before the inference engine loads the shard into GPU memory.
 */
export function verifyShardBeforeLoad(
  shardHashHex: string,
  proof: { root: string; proof: { side: "left" | "right"; hash: string }[] },
  committedRootHex: string
): boolean {
  try {
    if (!shardHashHex || !committedRootHex || !proof || !Array.isArray(proof.proof)) {
      return false;
    }
    const normalizedCommitted = committedRootHex.toLowerCase();
    const normalizedProofRoot = proof.root.toLowerCase();
    if (normalizedProofRoot !== normalizedCommitted) {
      return false;
    }

    let current = shardHashHex.toLowerCase();
    if (current.length !== 64) {
      return false;
    }
    // Validate hex format
    hexToBytes(current);

    for (const step of proof.proof) {
      if (!step || (step.side !== "left" && step.side !== "right") || typeof step.hash !== "string" || step.hash.length !== 64) {
        return false;
      }
      if (step.side === "left") {
        current = hashPairHex(step.hash, current);
      } else {
        current = hashPairHex(current, step.hash);
      }
    }

    return current === normalizedCommitted;
  } catch {
    return false;
  }
}

function createOpenModelSpec(params: {
  modelId: string;
  totalParams: string;
  activeParams: string;
  quantization: string;
  shardCount: number;
}): OpenModelSpec {
  const shardHashes = deriveDeterministicShardHashes(params.modelId, params.shardCount, params.quantization);
  return {
    modelId: params.modelId,
    kind: "open",
    totalParams: params.totalParams,
    activeParams: params.activeParams,
    quantization: params.quantization,
    shardCount: params.shardCount,
    tokenizerHash: deriveTokenizerHash(params.modelId),
    shardHashes,
    merkleRoot: computeShardMerkleRoot(shardHashes),
  };
}

export const OPEN_MODEL_CATALOG: Record<string, OpenModelSpec> = {
  "kimi-k3": createOpenModelSpec({
    modelId: "kimi-k3",
    totalParams: "2.8T",
    activeParams: "88B",
    quantization: "MXFP4",
    shardCount: 64,
  }),
  "kimi-linear-48b": createOpenModelSpec({
    modelId: "kimi-linear-48b",
    totalParams: "48B",
    activeParams: "8B",
    quantization: "FP8",
    shardCount: 8,
  }),
  "glm-5-3": createOpenModelSpec({
    modelId: "glm-5-3",
    totalParams: "350B",
    activeParams: "32B",
    quantization: "FP8",
    shardCount: 16,
  }),
  "llama3-3-70b": createOpenModelSpec({
    modelId: "llama3-3-70b",
    totalParams: "70B",
    activeParams: "70B",
    quantization: "BF16",
    shardCount: 8,
  }),
  "sim-echo-1": createOpenModelSpec({
    modelId: "sim-echo-1",
    totalParams: "1B",
    activeParams: "1B",
    quantization: "INT8",
    shardCount: 1,
  }),
};

export const CLOSED_MODEL_CATALOG: Record<string, ClosedModelSpec> = {
  "frontier-closed-x1": {
    modelId: "frontier-closed-x1",
    kind: "closed",
    totalParams: "1.8T",
    activeParams: "110B",
    quantization: "MXFP4-AES256GCM",
    shardCount: 32,
    tokenizerHash: deriveTokenizerHash("frontier-closed-x1"),
    weightKeyCommitment: bytesToHex(
      sha256(utf8ToBytes("drouter:closed-weight-key-commitment:v1:frontier-closed-x1"))
    ),
  },
};

export function listModelRegistry(): ModelRegistryEntry[] {
  const openEntries: ModelRegistryEntry[] = Object.values(OPEN_MODEL_CATALOG).map((m) => ({
    modelId: m.modelId,
    kind: "open",
    totalParams: m.totalParams,
    activeParams: m.activeParams,
    shardCount: m.shardCount,
    tokenizerHash: m.tokenizerHash,
    weightRootOrCommitment: m.merkleRoot,
  }));

  const closedEntries: ModelRegistryEntry[] = Object.values(CLOSED_MODEL_CATALOG).map((m) => ({
    modelId: m.modelId,
    kind: "closed",
    totalParams: m.totalParams,
    activeParams: m.activeParams,
    shardCount: m.shardCount,
    tokenizerHash: m.tokenizerHash,
    weightRootOrCommitment: m.weightKeyCommitment,
  }));

  return [...openEntries, ...closedEntries];
}
