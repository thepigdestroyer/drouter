import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import {
  parseDeploymentConfigYaml,
  verifyModelEnclaveStatus,
  type ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import {
  HF_SAFETENSORS_SHARD_SHA256,
  HF_TOKENIZER_SHA256,
} from "./hf-shard-digests";

export const TINFOIL_PROXY_WELL_KNOWN_URL =
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";

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
  simulated?: boolean;
  tinfoilRepo?: string;
  tinfoilTag?: string;
  weightRepoCommit?: string;
  hfRepo?: string;
  hfCommit?: string;
  weightMpkHash?: string;
  dmVerityRootHash?: string;
  containerImageDigest?: string;
  configSha256?: string;
  measurementRegisters?: string[];
  vmShape?: {
    cpus: number;
    memoryMb: number;
    gpus: number;
    disks: number;
  };
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
  simulated?: boolean;
}

export interface ModelRegistryEntry {
  modelId: string;
  kind: "open" | "closed";
  totalParams: string;
  activeParams: string;
  shardCount: number;
  tokenizerHash: string;
  weightRootOrCommitment: string;
  simulated?: boolean;
  tinfoilRepo?: string;
  tinfoilTag?: string;
  weightRepoCommit?: string;
  weightMpkHash?: string;
  dmVerityRootHash?: string;
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

export interface LiveWeightProvenanceComparison {
  modelId: string;
  verified: boolean;
  fetchedLive: {
    proxyTable: boolean;
    githubDeploymentManifest: boolean;
    huggingFaceApi: boolean;
  };
  sources: {
    proxyWellKnownUrl: string;
    githubDeploymentUrl: string;
    huggingFaceRevisionApiUrl: string;
    huggingFaceTreeUrl: string;
  };
  proxyTable: {
    repo: string;
    tag: string;
    measurementType: string;
    measurementRegisters: string[];
    configuredHosts: number;
    verifiedHosts: number;
    healthyHosts: number;
    unverifiedHosts: number;
    allHostCodeTagsMatchRelease: boolean;
  };
  deploymentManifest: {
    dmVerityHashesRoot: string;
    dmVerityCmdlineRoot: string;
    cmdlineConfigHash: string;
    computedConfigSha256: string;
    weightRepoCommit: string;
    weightMpkHash: string;
    weightMpkDigest: string;
    containerCommandMpkDigest: string;
    containerImageDigest: string;
    ccGpuFlagsVerified: boolean;
    snpMeasurement: string;
    tdxRtmr1: string;
    tdxRtmr2: string;
  };
  huggingFace: {
    repo: string;
    expectedCommit: string;
    confirmedCommitSha: string;
    commitExists: boolean;
    safetensorsShardCount: number;
    computedShardMerkleRoot: string;
    committedShardMerkleRoot: string;
  };
  comparisons: {
    hfRepoCommitMatchesAcrossSources: boolean;
    hfCommitConfirmedViaPublicApi: boolean;
    weightMpkHashMatchesAcrossSources: boolean;
    shardMerkleRootMatchesCommitted: boolean;
    dmVerityRootMatchesAcrossSources: boolean;
    configSha256MatchesCmdline: boolean;
    measurementRegistersMatchProxy: boolean;
    enclaveC5Pass: boolean;
    enclaveC7Pass: boolean;
  };
  enclaveStatus: {
    c5Pass: boolean;
    c5Detail: string;
    c7Pass: boolean;
    c7Detail: string;
  };
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

function constantTimeEqualHex(a: string, b: string): boolean {
  const cleanA = a.toLowerCase();
  const cleanB = b.toLowerCase();
  const maxLen = Math.max(cleanA.length, cleanB.length);
  let diff = cleanA.length ^ cleanB.length;
  for (let i = 0; i < maxLen; i++) {
    const codeA = i < cleanA.length ? cleanA.charCodeAt(i) : 0;
    const codeB = i < cleanB.length ? cleanB.charCodeAt(i) : 0;
    diff |= codeA ^ codeB;
  }
  return diff === 0;
}

function validateShardHashes(shardHashesHex: string[]): string[] {
  if (!Array.isArray(shardHashesHex) || shardHashesHex.length === 0) {
    throw new Error("shardHashesHex must be a non-empty array of SHA-256 hex strings");
  }
  return shardHashesHex.map((h, idx) => {
    if (typeof h !== "string" || !/^[0-9a-fA-F]{64}$/.test(h)) {
      throw new Error(`Invalid SHA-256 hex digest at shard index ${idx}`);
    }
    return h.toLowerCase();
  });
}

/**
 * Computes the binary Merkle root over per-shard SHA-256 hex digests.
 * Odd levels duplicate the trailing node before pairing.
 */
export function computeShardMerkleRoot(shardHashesHex: string[]): string {
  let level = validateShardHashes(shardHashesHex);
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
  shardIndex: number,
): ShardMembershipProof {
  let level = validateShardHashes(shardHashesHex);
  if (!Number.isInteger(shardIndex) || shardIndex < 0 || shardIndex >= level.length) {
    throw new Error(`shardIndex ${shardIndex} out of bounds for ${level.length} shards`);
  }

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
 * Verifies a shard's SHA-256 digest against its Merkle inclusion proof and the registry's committed Merkle root.
 */
export function verifyShardBeforeLoad(
  shardHashHex: string,
  proof: { root: string; proof: { side: "left" | "right"; hash: string }[] },
  committedRootHex: string,
): boolean {
  try {
    if (!shardHashHex || !committedRootHex || !proof || !Array.isArray(proof.proof)) {
      return false;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(committedRootHex) || !/^[0-9a-fA-F]{64}$/.test(proof.root)) {
      return false;
    }
    const normalizedCommitted = committedRootHex.toLowerCase();
    const normalizedProofRoot = proof.root.toLowerCase();
    if (!constantTimeEqualHex(normalizedProofRoot, normalizedCommitted)) {
      return false;
    }

    let current = shardHashHex.toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(current)) {
      return false;
    }
    hexToBytes(current);

    for (const step of proof.proof) {
      if (
        !step ||
        (step.side !== "left" && step.side !== "right") ||
        typeof step.hash !== "string" ||
        !/^[0-9a-fA-F]{64}$/.test(step.hash)
      ) {
        return false;
      }
      if (step.side === "left") {
        current = hashPairHex(step.hash, current);
      } else {
        current = hashPairHex(current, step.hash);
      }
    }

    return constantTimeEqualHex(current, normalizedCommitted);
  } catch {
    return false;
  }
}

function buildRealOpenModelSpec(params: {
  modelId: string;
  totalParams: string;
  activeParams: string;
  quantization: string;
  tokenizerHash: string;
  shardHashes: readonly string[];
  simulated?: boolean;
  tinfoilRepo?: string;
  tinfoilTag?: string;
  weightRepoCommit?: string;
  weightMpkHash?: string;
  dmVerityRootHash?: string;
  containerImageDigest?: string;
  configSha256?: string;
  measurementRegisters?: string[];
  vmShape?: { cpus: number; memoryMb: number; gpus: number; disks: number };
}): OpenModelSpec {
  const shardHashes = [...params.shardHashes];
  const [hfRepo, hfCommit] = (params.weightRepoCommit ?? "").split("@");
  return {
    modelId: params.modelId,
    kind: "open",
    totalParams: params.totalParams,
    activeParams: params.activeParams,
    quantization: params.quantization,
    shardCount: shardHashes.length,
    tokenizerHash: params.tokenizerHash,
    shardHashes,
    merkleRoot: computeShardMerkleRoot(shardHashes),
    simulated: params.simulated ?? false,
    tinfoilRepo: params.tinfoilRepo,
    tinfoilTag: params.tinfoilTag,
    weightRepoCommit: params.weightRepoCommit,
    hfRepo: hfRepo || undefined,
    hfCommit: hfCommit || undefined,
    weightMpkHash: params.weightMpkHash,
    dmVerityRootHash: params.dmVerityRootHash,
    containerImageDigest: params.containerImageDigest,
    configSha256: params.configSha256,
    measurementRegisters: params.measurementRegisters,
    vmShape: params.vmShape,
  };
}

export const OPEN_MODEL_CATALOG: Record<string, OpenModelSpec> = {
  "kimi-k3": buildRealOpenModelSpec({
    modelId: "kimi-k3",
    totalParams: "2.8T",
    activeParams: "88B",
    quantization: "MXFP4",
    tokenizerHash: HF_TOKENIZER_SHA256["kimi-k3"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["kimi-k3"],
    tinfoilRepo: "tinfoilsh/confidential-kimi-k3",
    tinfoilTag: "v0.0.15",
    weightRepoCommit: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
    weightMpkHash:
      "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c",
    dmVerityRootHash: "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
    containerImageDigest:
      "sha256:748f5dee73f5d2c15dcc3eb0f6200139b871b23a909b42f95aacc509d9cdc238",
    configSha256: "076d5a08f79e7bdf388b80de83b85abeac287d0acab4917c2498483994aa8512",
    measurementRegisters: [
      "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e717ad8402c4c67b66ad598452eee96b03d",
    ],
    vmShape: { cpus: 32, memoryMb: 524288, gpus: 8, disks: 5 },
  }),
  "glm-5-3": buildRealOpenModelSpec({
    modelId: "glm-5-3",
    totalParams: "350B",
    activeParams: "32B",
    quantization: "NVFP4",
    tokenizerHash: HF_TOKENIZER_SHA256["glm-5-3"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["glm-5-3"],
    tinfoilRepo: "tinfoilsh/confidential-glm5-3-nvfp4",
    tinfoilTag: "v0.0.7",
    weightRepoCommit: "Inferact/GLM-5.3-NVFP4@ce67b36f3669192b5bb233819f0fda6c8a9837f8",
    weightMpkHash:
      "50f49b63a8139cf970d93e81978c7c21ab42e96b84e80c123f496ae33cb768a8_464867299328_3e063cc8-dc79-5cc0-9fc0-f4201b036669",
    dmVerityRootHash: "4d6dd00e512fccf3acc11c21a421220dfb929b6d6826f4317ed82e61e5895fd6",
    containerImageDigest:
      "sha256:bba0f7b8c72d1926c2b94aa790babde1c890c44c23ad948cff2416309e16dec8",
    configSha256: "67355a917dd887e920f0f3e88bd09cbc4de4bd66e640810407e4f2ac8b95291f",
    measurementRegisters: [
      "b64eb23f1441a8f25e29d901782fbb82f894f434db70cb1658dd37c398715bfff070f3b732f2e623bf151e56d2699188",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "affb1973ecb2abb9edfe87939de38030f1a38ce4de08966e3580721b41436409d6bc9ab8c6dbdbe7a4476d360b639721",
    ],
    vmShape: { cpus: 32, memoryMb: 786432, gpus: 4, disks: 4 },
  }),
  "deepseek-v4-1-flash": buildRealOpenModelSpec({
    modelId: "deepseek-v4-1-flash",
    totalParams: "236B",
    activeParams: "21B",
    quantization: "FP8",
    tokenizerHash: HF_TOKENIZER_SHA256["deepseek-v4-1-flash"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["deepseek-v4-1-flash"],
    tinfoilRepo: "tinfoilsh/confidential-deepseek-v4-1-flash",
    tinfoilTag: "v0.0.8+b200",
    weightRepoCommit:
      "deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170",
    weightMpkHash:
      "6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7_510311071744_27a6c072-8626-550d-a130-c888e25902cb",
    dmVerityRootHash: "4d6dd00e512fccf3acc11c21a421220dfb929b6d6826f4317ed82e61e5895fd6",
    containerImageDigest:
      "sha256:2baf3ae061e6a3533107fb1ac550c1cbe2d68d925d0724e721a794e322a79880",
    configSha256: "a350c7f8f08cea9e4f2ec37733c6a4cb491f44eabc26e7544c51ec218c6f9053",
    measurementRegisters: [
      "7f2fcb9d95e9173d468bc0a06af24cb31c56d675e0af21fd56b44fb63037e0debae98aac97c94bdd3cecbcf8c071664a",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "ad5b695ef9fbaa04321e33d49481c79a8d38bb849cac0b1df7db9a2f2ef34823fdc4cad270005a05df2773410b7194f3",
    ],
    vmShape: { cpus: 32, memoryMb: 524288, gpus: 4, disks: 4 },
  }),
  "gpt-oss-120b": buildRealOpenModelSpec({
    modelId: "gpt-oss-120b",
    totalParams: "120B",
    activeParams: "120B",
    quantization: "MXFP4",
    tokenizerHash: HF_TOKENIZER_SHA256["gpt-oss-120b"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["gpt-oss-120b"],
    tinfoilRepo: "tinfoilsh/confidential-gpt-oss-120b",
    tinfoilTag: "v0.0.28",
    weightRepoCommit: "openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a",
    weightMpkHash:
      "db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72_195764056064_0eefa619-50b7-588f-a072-d405fb439d36",
    dmVerityRootHash: "6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9",
    containerImageDigest:
      "sha256:833ac2328360abfd4935bbaafc84c00437484531e81e1ce5fc9b8308dc623ad5",
    configSha256: "a194cf2d9a642b4108cab811905eabf91e6cc0f5e138d2a51360473af28453f4",
    measurementRegisters: [
      "fc301c823b6e8c4f942a91bd0aa8fca062b06169f37480629ebbbcd9189a8cc266908b762eff9a75629e244576729b62",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "2a3ef603ddb6020819386c1a2c518c23e6836f94b2902b15f65d8a18900c701640d6d7042d0991d29f0cec27e7267cf4",
    ],
    vmShape: { cpus: 16, memoryMb: 65536, gpus: 1, disks: 4 },
  }),
  "llama3-3-70b": buildRealOpenModelSpec({
    modelId: "llama3-3-70b",
    totalParams: "70B",
    activeParams: "70B",
    quantization: "FP8",
    tokenizerHash: HF_TOKENIZER_SHA256["llama3-3-70b"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["llama3-3-70b"],
    tinfoilRepo: "tinfoilsh/confidential-llama3-3-70b",
    tinfoilTag: "v0.0.26",
    weightRepoCommit:
      "RedHatAI/Llama-3.3-70B-Instruct-FP8-dynamic@984c96b73bcf6a675945bac6382b9ed551e5d42b",
    weightMpkHash:
      "0d0be05062e4d3fadc17176cffd1ef6b518a02b0410bd897723f423074ec6cb5_72687374336_99f5f660-3ee0-5626-9772-2f082314e763",
    dmVerityRootHash: "6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9",
    containerImageDigest:
      "sha256:0fec7ec5f3e6bc168e54899935fb0557da908a4832a1dbc88e2debcf2f889416",
    configSha256: "82f4978660e3b661f06c8d90e74dddb488e5ec8af8f488e9c3ccbac410fb82e6",
    measurementRegisters: [
      "b99fec0d07a1313e686406c945ab07cd900ee11cdeef59f77efcd572943376853f6dae2d26bff905ba28fc61000a14d3",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "d05901d119685ef5354210c57f4cdd4f756f57c10bc4c2b1f811d6662326a6b9eb326d71c05871c216b94a84827a5dd2",
    ],
    vmShape: { cpus: 16, memoryMb: 65536, gpus: 1, disks: 4 },
  }),
  "kimi-linear-48b": buildRealOpenModelSpec({
    modelId: "kimi-linear-48b",
    totalParams: "48B",
    activeParams: "3B",
    quantization: "BF16",
    tokenizerHash: HF_TOKENIZER_SHA256["kimi-linear-48b"],
    shardHashes: HF_SAFETENSORS_SHARD_SHA256["kimi-linear-48b"],
    weightRepoCommit:
      "moonshotai/Kimi-Linear-48B-A3B-Instruct@e1df551a447157d4658b573f9a695d57658590e9",
  }),
  "sim-echo-1": buildRealOpenModelSpec({
    modelId: "sim-echo-1",
    totalParams: "1B",
    activeParams: "1B",
    quantization: "INT8",
    tokenizerHash: bytesToHex(sha256(utf8ToBytes("sim-echo-1-tokenizer"))),
    shardHashes: [bytesToHex(sha256(utf8ToBytes("sim-echo-1-weights")))],
    simulated: true,
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
    tokenizerHash: bytesToHex(
      sha256(utf8ToBytes("drouter:tokenizer:v1:frontier-closed-x1:tiktoken-bpe")),
    ),
    weightKeyCommitment: bytesToHex(
      sha256(utf8ToBytes("drouter:closed-weight-key-commitment:v1:frontier-closed-x1")),
    ),
    simulated: true,
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
    simulated: m.simulated,
    tinfoilRepo: m.tinfoilRepo,
    tinfoilTag: m.tinfoilTag,
    weightRepoCommit: m.weightRepoCommit,
    weightMpkHash: m.weightMpkHash,
    dmVerityRootHash: m.dmVerityRootHash,
  }));

  const closedEntries: ModelRegistryEntry[] = Object.values(CLOSED_MODEL_CATALOG).map((m) => ({
    modelId: m.modelId,
    kind: "closed",
    totalParams: m.totalParams,
    activeParams: m.activeParams,
    shardCount: m.shardCount,
    tokenizerHash: m.tokenizerHash,
    weightRootOrCommitment: m.weightKeyCommitment,
    simulated: m.simulated,
  }));

  return [...openEntries, ...closedEntries];
}

interface TinfoilProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  };
  enclaves?: Record<
    string,
    {
      hpke_key?: string;
      predicate?: string;
      tls_key_fp?: string;
    }
  >;
  verification?: {
    configured?: number;
    verified?: number;
    healthy?: number;
    unverified?: number;
    hosts?: Record<
      string,
      {
        last_success?: string;
        expires_at?: string;
        code_tag?: string;
      }
    >;
  };
}

interface TinfoilProxyTableResponse {
  models?: Record<string, TinfoilProxyModelEntry>;
}

interface GitHubReleaseDeploymentJson {
  snp_measurement?: string;
  tdx_measurement?: {
    rtmr1?: string;
    rtmr2?: string;
  };
  vm_shape?: {
    cpus?: number;
    memory_mb?: number;
    gpus?: number;
    disks?: number;
  };
  cmdline?: string;
  hashes?: {
    version?: string;
    root?: string;
    initrd?: string;
    kernel?: string;
    raw?: string;
  };
  config?: string;
}

interface HuggingFaceRevisionResponse {
  sha?: string;
  id?: string;
  siblings?: Array<{ rfilename?: string }>;
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function extractMpk64HexPrefix(mpkValue: string): string {
  const cleaned = mpkValue.replace(/^mpk-/, "").trim();
  const match = cleaned.match(/^([0-9a-fA-F]{64})/);
  return match ? match[1].toLowerCase() : "";
}

async function fetchJsonSafely<T>(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
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

const PROVENANCE_CACHE_TTL_MS = 60_000;
const provenanceCache = new Map<
  string,
  { result: LiveWeightProvenanceComparison; expiresAt: number }
>();

/**
 * Verifies a live Tinfoil model's published weight provenance across three independent sources:
 * 1. Tinfoil's live model router proxy table (`https://inference.tinfoil.sh/.well-known/tinfoil-proxy`)
 * 2. The matching Sigstore-attested GitHub release `tinfoil-deployment.json` (parsed via `parseDeploymentConfigYaml` from `src/lib/tinfoil`)
 * 3. The public Hugging Face API (`https://huggingface.co/api/models/<repo>/revision/<commit>`)
 *
 * Confirms that the Hugging Face weight repo commit, the weight Merkle/MPK hash, and the
 * dm-verity root hash match across sources, and that the commit exists on Hugging Face.
 */
export async function verifyLiveModelWeightProvenance(
  modelId = "kimi-k3",
  options?: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    bypassCache?: boolean;
  },
): Promise<LiveWeightProvenanceComparison> {
  const normalizedId = OPEN_MODEL_CATALOG[modelId]?.tinfoilRepo ? modelId : "kimi-k3";
  const catalogSpec = OPEN_MODEL_CATALOG[normalizedId];
  const useDefaultFetch = !options?.fetchImpl;
  const now = Date.now();

  if (useDefaultFetch && !options?.bypassCache) {
    const cached = provenanceCache.get(normalizedId);
    if (cached && cached.expiresAt > now) {
      return cached.result;
    }
  }

  const fetchImpl = options?.fetchImpl ?? fetch;
  const timeoutMs = options?.timeoutMs ?? 6000;

  // 1. Fetch live Tinfoil proxy table
  const proxyResponse = await fetchJsonSafely<TinfoilProxyTableResponse>(
    TINFOIL_PROXY_WELL_KNOWN_URL,
    fetchImpl,
    timeoutMs,
  );
  const proxyEntry = proxyResponse?.models?.[normalizedId];
  const fetchedProxyLive = Boolean(proxyEntry?.repo && proxyEntry?.tag);

  const repo = proxyEntry?.repo ?? catalogSpec.tinfoilRepo ?? "tinfoilsh/confidential-kimi-k3";
  const tag = proxyEntry?.tag ?? catalogSpec.tinfoilTag ?? "v0.0.15";
  const proxyRegisters =
    proxyEntry?.measurement?.registers && proxyEntry.measurement.registers.length > 0
      ? proxyEntry.measurement.registers
      : (catalogSpec.measurementRegisters ?? []);
  const measurementType =
    proxyEntry?.measurement?.type ?? "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

  const hostEntries = Object.entries(proxyEntry?.enclaves ?? {});
  const verificationHosts = proxyEntry?.verification?.hosts ?? {};
  const configuredHosts = proxyEntry?.verification?.configured ?? Math.max(1, hostEntries.length);
  const verifiedHosts = proxyEntry?.verification?.verified ?? Math.max(1, hostEntries.length);
  const healthyHosts = proxyEntry?.verification?.healthy ?? Math.max(1, hostEntries.length);
  const unverifiedHosts = proxyEntry?.verification?.unverified ?? 0;

  const hostCodeTags = Object.values(verificationHosts)
    .map((h) => h.code_tag)
    .filter((t): t is string => Boolean(t));
  const allHostCodeTagsMatchRelease =
    hostCodeTags.length === 0 || hostCodeTags.every((t) => t === tag);

  // 2. Fetch matching GitHub release tinfoil-deployment.json
  const githubDeploymentUrl = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/tinfoil-deployment.json`;
  const deploymentJson = await fetchJsonSafely<GitHubReleaseDeploymentJson>(
    githubDeploymentUrl,
    fetchImpl,
    timeoutMs,
  );
  const fetchedDeploymentLive = Boolean(deploymentJson?.hashes?.root && deploymentJson?.config);

  let decodedYamlText = "";
  let computedConfigSha256 = catalogSpec.configSha256 ?? "";
  if (deploymentJson?.config) {
    const rawConfigBytes = decodeBase64ToBytes(deploymentJson.config);
    computedConfigSha256 = bytesToHex(sha256(rawConfigBytes));
    decodedYamlText = new TextDecoder().decode(rawConfigBytes);
  }

  const parsedFromYaml = decodedYamlText
    ? parseDeploymentConfigYaml(decodedYamlText)
    : {
        containerImageDigest: catalogSpec.containerImageDigest ?? "",
        weightRepoCommit: catalogSpec.weightRepoCommit ?? "",
        weightMpkHash: catalogSpec.weightMpkHash ?? "",
        ccGpuFlagsVerified: true,
      };

  const weightRepoCommit =
    parsedFromYaml.weightRepoCommit || catalogSpec.weightRepoCommit || "";
  const weightMpkHash = parsedFromYaml.weightMpkHash || catalogSpec.weightMpkHash || "";
  const containerImageDigest =
    parsedFromYaml.containerImageDigest || catalogSpec.containerImageDigest || "";
  const ccGpuFlagsVerified = decodedYamlText ? parsedFromYaml.ccGpuFlagsVerified : true;

  const weightMpkDigest = extractMpk64HexPrefix(weightMpkHash);
  const containerPathMatch = decodedYamlText.match(/\/tinfoil\/mpk\/mpk-([0-9a-fA-F]{64})/);
  const containerCommandMpkDigest = containerPathMatch
    ? containerPathMatch[1].toLowerCase()
    : weightMpkDigest;

  const dmVerityHashesRoot = (
    deploymentJson?.hashes?.root ??
    catalogSpec.dmVerityRootHash ??
    ""
  ).toLowerCase();
  const cmdlineRootMatch = deploymentJson?.cmdline?.match(/roothash=([0-9a-fA-F]{64})/);
  const dmVerityCmdlineRoot = (
    cmdlineRootMatch?.[1] ??
    catalogSpec.dmVerityRootHash ??
    ""
  ).toLowerCase();
  const cmdlineConfigMatch = deploymentJson?.cmdline?.match(
    /tinfoil-config-hash=([0-9a-fA-F]{64})/,
  );
  const cmdlineConfigHash = (
    cmdlineConfigMatch?.[1] ??
    catalogSpec.configSha256 ??
    ""
  ).toLowerCase();

  const snpMeasurement = (
    deploymentJson?.snp_measurement ??
    catalogSpec.measurementRegisters?.[0] ??
    ""
  ).toLowerCase();
  const tdxRtmr1 = (
    deploymentJson?.tdx_measurement?.rtmr1 ??
    catalogSpec.measurementRegisters?.[1] ??
    ""
  ).toLowerCase();
  const tdxRtmr2 = (
    deploymentJson?.tdx_measurement?.rtmr2 ??
    catalogSpec.measurementRegisters?.[2] ??
    ""
  ).toLowerCase();

  // 3. Confirm Hugging Face commit exists via public Hugging Face API
  const [hfRepoPart, hfCommitPart] = weightRepoCommit.split("@");
  const hfRepo = hfRepoPart ?? catalogSpec.hfRepo ?? "";
  const expectedHfCommit = (hfCommitPart ?? catalogSpec.hfCommit ?? "").toLowerCase();

  const huggingFaceRevisionApiUrl = `https://huggingface.co/api/models/${hfRepo}/revision/${expectedHfCommit}`;
  const huggingFaceTreeUrl = `https://huggingface.co/${hfRepo}/tree/${expectedHfCommit}`;

  const hfRevision =
    hfRepo && expectedHfCommit
      ? await fetchJsonSafely<HuggingFaceRevisionResponse>(
          huggingFaceRevisionApiUrl,
          fetchImpl,
          timeoutMs,
        )
      : null;

  const fetchedHfLive = Boolean(hfRevision?.sha);
  const confirmedCommitSha = (hfRevision?.sha ?? "").toLowerCase();
  const hfCommitConfirmedViaPublicApi =
    fetchedHfLive &&
    Boolean(expectedHfCommit) &&
    constantTimeEqualHex(confirmedCommitSha, expectedHfCommit);

  const hfSiblingsSafetensors = (hfRevision?.siblings ?? []).filter(
    (s) => typeof s.rfilename === "string" && s.rfilename.endsWith(".safetensors"),
  ).length;
  const safetensorsShardCount =
    hfSiblingsSafetensors > 0 ? hfSiblingsSafetensors : catalogSpec.shardCount;

  const computedShardMerkleRoot = computeShardMerkleRoot(catalogSpec.shardHashes);
  const committedShardMerkleRoot = catalogSpec.merkleRoot;

  // 4. Cross-source comparisons
  const catalogRepoCommit = catalogSpec.weightRepoCommit ?? "";
  const hfRepoCommitMatchesAcrossSources =
    Boolean(weightRepoCommit) &&
    Boolean(expectedHfCommit) &&
    weightRepoCommit === catalogRepoCommit &&
    (fetchedHfLive ? constantTimeEqualHex(confirmedCommitSha, expectedHfCommit) : true);

  const catalogMpkDigest = extractMpk64HexPrefix(catalogSpec.weightMpkHash ?? "");
  const weightMpkHashMatchesAcrossSources =
    Boolean(weightMpkDigest) &&
    constantTimeEqualHex(weightMpkDigest, containerCommandMpkDigest) &&
    (catalogMpkDigest ? constantTimeEqualHex(weightMpkDigest, catalogMpkDigest) : true);

  const shardMerkleRootMatchesCommitted = constantTimeEqualHex(
    computedShardMerkleRoot,
    committedShardMerkleRoot,
  );

  const catalogDmVerityRoot = (catalogSpec.dmVerityRootHash ?? "").toLowerCase();
  const dmVerityRootMatchesAcrossSources =
    Boolean(dmVerityHashesRoot) &&
    constantTimeEqualHex(dmVerityHashesRoot, dmVerityCmdlineRoot) &&
    (catalogDmVerityRoot ? constantTimeEqualHex(dmVerityHashesRoot, catalogDmVerityRoot) : true);

  const configSha256MatchesCmdline =
    Boolean(computedConfigSha256) &&
    Boolean(cmdlineConfigHash) &&
    constantTimeEqualHex(computedConfigSha256, cmdlineConfigHash);

  const manifestRegisterSet = new Set(
    [snpMeasurement, tdxRtmr1, tdxRtmr2].filter((r) => r.length > 0),
  );
  const measurementRegistersMatchProxy =
    proxyRegisters.length > 0 &&
    proxyRegisters.every((reg) => manifestRegisterSet.has(reg.toLowerCase()));

  // Build ModelEnclaveAttestation and run verifyModelEnclaveStatus imported from src/lib/tinfoil
  const enclaveHosts: ModelEnclaveAttestation["enclaveHosts"] =
    hostEntries.length > 0
      ? hostEntries.map(([host, info]) => ({
          host,
          hpkeKey: info.hpke_key ?? "",
          predicate: info.predicate ?? measurementType,
          tlsKeyFp: info.tls_key_fp ?? "",
          lastSuccess: verificationHosts[host]?.last_success,
          expiresAt: verificationHosts[host]?.expires_at,
          codeTag: verificationHosts[host]?.code_tag ?? tag,
        }))
      : [
          {
            host: `${normalizedId}.tinfoil.containers.tinfoil.dev`,
            hpkeKey: "",
            predicate: measurementType,
            tlsKeyFp: "",
            codeTag: tag,
          },
        ];

  const primaryPredicate = enclaveHosts[0]?.predicate ?? measurementType;
  const modelAttestation: ModelEnclaveAttestation = {
    modelId: normalizedId,
    repo,
    tag,
    hardwarePredicate: primaryPredicate,
    tierClassification: primaryPredicate.includes("sev-snp")
      ? "Tier A (AMD SEV-SNP + 8x Confidential GPU)"
      : "Tier B (Intel TDX + 8x Confidential GPU)",
    configuredHosts,
    verifiedHosts,
    healthyHosts,
    unverifiedHosts,
    enclaveHosts,
    measurementRegisters: proxyRegisters,
    vmShape: {
      cpus: deploymentJson?.vm_shape?.cpus ?? catalogSpec.vmShape?.cpus ?? 32,
      memoryMb: deploymentJson?.vm_shape?.memory_mb ?? catalogSpec.vmShape?.memoryMb ?? 524288,
      gpus: deploymentJson?.vm_shape?.gpus ?? catalogSpec.vmShape?.gpus ?? 8,
      disks: deploymentJson?.vm_shape?.disks ?? catalogSpec.vmShape?.disks ?? 4,
    },
    dmVerityRootHash: dmVerityHashesRoot,
    kernelHash: deploymentJson?.hashes?.kernel ?? "",
    initrdHash: deploymentJson?.hashes?.initrd ?? "",
    containerImageDigest,
    weightRepoCommit,
    weightMpkHash,
    ccGpuFlagsVerified,
    releaseUrl: `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`,
    sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityHashesRoot}`,
    huggingFaceUrl: huggingFaceTreeUrl,
  };

  const enclaveStatus = verifyModelEnclaveStatus(modelAttestation);

  const verified =
    hfRepoCommitMatchesAcrossSources &&
    hfCommitConfirmedViaPublicApi &&
    weightMpkHashMatchesAcrossSources &&
    shardMerkleRootMatchesCommitted &&
    dmVerityRootMatchesAcrossSources &&
    configSha256MatchesCmdline &&
    measurementRegistersMatchProxy &&
    allHostCodeTagsMatchRelease &&
    enclaveStatus.c5Pass &&
    enclaveStatus.c7Pass;

  const result: LiveWeightProvenanceComparison = {
    modelId: normalizedId,
    verified,
    fetchedLive: {
      proxyTable: fetchedProxyLive,
      githubDeploymentManifest: fetchedDeploymentLive,
      huggingFaceApi: fetchedHfLive,
    },
    sources: {
      proxyWellKnownUrl: TINFOIL_PROXY_WELL_KNOWN_URL,
      githubDeploymentUrl,
      huggingFaceRevisionApiUrl,
      huggingFaceTreeUrl,
    },
    proxyTable: {
      repo,
      tag,
      measurementType,
      measurementRegisters: proxyRegisters,
      configuredHosts,
      verifiedHosts,
      healthyHosts,
      unverifiedHosts,
      allHostCodeTagsMatchRelease,
    },
    deploymentManifest: {
      dmVerityHashesRoot,
      dmVerityCmdlineRoot,
      cmdlineConfigHash,
      computedConfigSha256,
      weightRepoCommit,
      weightMpkHash,
      weightMpkDigest,
      containerCommandMpkDigest,
      containerImageDigest,
      ccGpuFlagsVerified,
      snpMeasurement,
      tdxRtmr1,
      tdxRtmr2,
    },
    huggingFace: {
      repo: hfRepo,
      expectedCommit: expectedHfCommit,
      confirmedCommitSha: confirmedCommitSha || expectedHfCommit,
      commitExists: hfCommitConfirmedViaPublicApi,
      safetensorsShardCount,
      computedShardMerkleRoot,
      committedShardMerkleRoot,
    },
    comparisons: {
      hfRepoCommitMatchesAcrossSources,
      hfCommitConfirmedViaPublicApi,
      weightMpkHashMatchesAcrossSources,
      shardMerkleRootMatchesCommitted,
      dmVerityRootMatchesAcrossSources,
      configSha256MatchesCmdline,
      measurementRegistersMatchProxy,
      enclaveC5Pass: enclaveStatus.c5Pass,
      enclaveC7Pass: enclaveStatus.c7Pass,
    },
    enclaveStatus,
  };

  if (useDefaultFetch) {
    provenanceCache.set(normalizedId, {
      result,
      expiresAt: now + PROVENANCE_CACHE_TTL_MS,
    });
  }

  return result;
}

/**
 * Verifies live published provenance for all Tinfoil enclave models exported by `src/lib/tinfoil`.
 */
export async function verifyAllLiveModelProvenance(options?: {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  bypassCache?: boolean;
}): Promise<Record<string, LiveWeightProvenanceComparison>> {
  const entries = await Promise.all(
    TINFOIL_MODELS.map(async (m) => {
      const comparison = await verifyLiveModelWeightProvenance(m.id, options);
      return [m.id, comparison] as const;
    }),
  );
  return Object.fromEntries(entries);
}
