export const EMBEDDING_DIMENSIONS = 128 as const;
export const LOCAL_STANDIN_EMBEDDING_MODEL = "local-hashed-128 (stand-in)" as const;

export interface EmbeddingResult {
  vector: number[];
  model: string;
  dimensions: 128;
  isLiveModel: boolean;
}

/**
 * 64 curated semantic concept clusters for confidential AI, hardware TEEs,
 * side-channel advisories, and cryptographic protocols.
 * Dimensions 0..63 encode explicit domain concept activations;
 * Dimensions 64..127 encode signed character trigram & token hash projections.
 */
const SEMANTIC_CONCEPT_CLUSTERS: ReadonlyArray<{
  dim: number;
  weight: number;
  terms: readonly string[];
}> = [
  // Hardware Attacks & Memory Bus Probes (Dims 0..11)
  {
    dim: 0,
    weight: 3.2,
    terms: ["tee.fail", "teefail", "interposer", "riser", "passive probe", "logic analyzer", "tux-penguin", "tux penguin"],
  },
  {
    dim: 1,
    weight: 3.0,
    terms: ["ddr5", "memory bus", "dimm", "dram bus", "memory probe", "bus probe", "ddr5 riser", "physical bus"],
  },
  {
    dim: 2,
    weight: 2.8,
    terms: ["aes-xts", "static iv", "deterministic tweak", "ciphertext block", "16-byte block", "block repetition", "ecb pattern"],
  },
  {
    dim: 3,
    weight: 3.2,
    terms: ["ddrop", "active memory", "fault injection", "memory replay", "bus splice", "rowhammer", "bit flip", "replay attack"],
  },
  {
    dim: 4,
    weight: 3.2,
    terms: ["cipherleaks", "ciphertext side-channel", "cache line", "sev-snp side-channel", "deterministic ciphertext"],
  },
  {
    dim: 5,
    weight: 3.2,
    terms: ["voltpillager", "voltage glitching", "svi2", "pmbus", "voltage regulator", "hardware glitch", "undervolting", "fault attack"],
  },
  {
    dim: 6,
    weight: 2.5,
    terms: ["advisory", "vulnerability", "exploit", "mitigation", "cve", "attack vector", "threat model", "side-channel"],
  },
  {
    dim: 7,
    weight: 2.6,
    terms: ["riser-proof", "bga", "soldered memory", "allowlist", "spdm 1.2", "tdisp", "tee-io", "sev-tio", "cxl 3.0", "ide"],
  },
  {
    dim: 8,
    weight: 2.8,
    terms: ["monotonic nonce", "aes-256-gcm", "gcm counter", "shannon entropy", "offload encryption", "kv-cache offload"],
  },
  {
    dim: 9,
    weight: 2.8,
    terms: ["pop()", "zeroization", "crypto-shredding", "hbm wipe", "memory scrub", "zero-retention", "post-turn wipe", "zeroize"],
  },
  {
    dim: 10,
    weight: 2.7,
    terms: ["custody", "two-hop gpu custody", "custodyctrdrbg", "drbg", "prefix cache", "session isolation", "hmac-sha256"],
  },
  {
    dim: 11,
    weight: 2.7,
    terms: ["vmpl0", "svsm", "inner monitor", "egress policy", "secret scrubber", "token framing", "privilege ring"],
  },

  // CPU & GPU TEE Silicon Roots of Trust (Dims 12..21)
  {
    dim: 12,
    weight: 2.6,
    terms: ["amd sev-snp", "sev-snp", "vcek", "milan", "genoa", "turin", "amd psp", "asp", "rmp"],
  },
  {
    dim: 13,
    weight: 2.6,
    terms: ["intel tdx", "tdx", "dcap", "mrtd", "rtmr", "tcb svn", "quote v4", "cvm", "trust domain"],
  },
  {
    dim: 14,
    weight: 2.8,
    terms: ["8x", "8x gpu", "b200", "h200", "h100", "blackwell", "hopper", "nvidia cc", "confidential computing", "gpu tee", "hbm3e"],
  },
  {
    dim: 15,
    weight: 2.6,
    terms: ["nvlink", "pcie", "bounce buffer", "local verifier", "rim", "gpu attestation", "spdm"],
  },
  {
    dim: 16,
    weight: 2.6,
    terms: ["hpke", "rfc 9180", "ehbp", "encrypted http body", "client-to-enclave", "e2ee", "end-to-end encrypted"],
  },
  {
    dim: 17,
    weight: 2.5,
    terms: ["ml-kem-768", "pqc", "post-quantum", "x25519", "hybrid kem", "quantum resistant"],
  },
  {
    dim: 18,
    weight: 2.6,
    terms: ["sigstore", "rekor", "transparency log", "inclusion proof", "reproducible build", "5-of-7 quorum", "manifest"],
  },
  {
    dim: 19,
    weight: 2.4,
    terms: ["dm-verity", "rootfs", "initramfs", "container measurement", "firecracker", "microvm", "sandbox"],
  },
  {
    dim: 20,
    weight: 2.5,
    terms: ["two-hop", "2-hop", "router enclave", "worker enclave", "mutual tls", "attested tls"],
  },
  {
    dim: 21,
    weight: 2.4,
    terms: ["gateway-tee-only", "terminated tls", "proxy termination", "plaintext gateway"],
  },

  // Frontier Models (Dims 22..29)
  {
    dim: 22,
    weight: 3.2,
    terms: ["kimi k3", "kimi k2.5", "kimi", "moonshot", "2.8t moe", "2.8t"],
  },
  {
    dim: 23,
    weight: 3.0,
    terms: ["glm-5.3", "glm-5", "glm", "zhipu"],
  },
  {
    dim: 24,
    weight: 3.0,
    terms: ["deepseek", "deepseek v4.1", "deepseek r1", "deepseek v3", "671b"],
  },
  {
    dim: 25,
    weight: 2.6,
    terms: ["qwen", "qwen 3.5", "qwen 3", "235b", "72b"],
  },
  {
    dim: 26,
    weight: 2.5,
    terms: ["llama 3.3", "llama", "70b", "meta llama"],
  },
  {
    dim: 27,
    weight: 2.6,
    terms: ["gemma 4", "gemma 3", "gemma", "31b", "27b"],
  },
  {
    dim: 28,
    weight: 2.6,
    terms: ["gpt-oss", "120b", "nemotron", "253b", "mistral large"],
  },
  {
    dim: 29,
    weight: 2.2,
    terms: ["frontier model", "inference", "llm", "token streaming", "autoregressive"],
  },

  // Confidential Inference Providers (Dims 30..39)
  {
    dim: 30,
    weight: 3.2,
    terms: ["tinfoil", "tinfoil.sh", "live-integrated", "primary provider", "17 models"],
  },
  {
    dim: 31,
    weight: 3.0,
    terms: ["phala", "redpill", "phala cloud", "openrouter confidential", "aci receipt"],
  },
  {
    dim: 32,
    weight: 3.0,
    terms: ["near ai", "near cloud", "cloud.near.ai", "13 frontier models"],
  },
  {
    dim: 33,
    weight: 3.0,
    terms: ["venice", "venice.ai", "venice e2ee", "browser encryption"],
  },
  {
    dim: 34,
    weight: 3.0,
    terms: ["prem ai", "premai", "sovereign tdx", "caller nonce"],
  },
  {
    dim: 35,
    weight: 3.0,
    terms: ["ppq.ai", "ppq", "pay-per-query", "lightning", "anonymous settlement"],
  },
  {
    dim: 36,
    weight: 3.0,
    terms: ["confidential ai", "confidential.ai", "c8s", "sha-384 transcript"],
  },
  {
    dim: 37,
    weight: 3.0,
    terms: ["chutes", "bittensor", "miner node", "spot pricing", "subnet"],
  },
  {
    dim: 38,
    weight: 3.0,
    terms: ["privatemode", "cosmian", "contrast", "eu-hosted", "kubernetes coordinator"],
  },
  {
    dim: 39,
    weight: 3.0,
    terms: ["nanogpt", "nano-gpt", "ecdsa response signature", "24 models"],
  },

  // Cryptographic Settlement, Privacy & dRouter Architecture (Dims 40..63)
  {
    dim: 40,
    weight: 2.7,
    terms: ["circle arc", "arc blockchain", "on-chain attestation", "usdc", "settlement contract", "anchor"],
  },
  {
    dim: 41,
    weight: 2.7,
    terms: ["rsa blind", "blind signature", "credit nullifier", "nullifier", "anonymous credit", "double-spend"],
  },
  {
    dim: 42,
    weight: 2.7,
    terms: ["shamir", "threshold", "3-of-5", "secret sharing", "key share", "lagrange"],
  },
  {
    dim: 43,
    weight: 2.7,
    terms: ["k_freeze", "frozen blob", "session freeze", "state migration", "failover", "webcrypto"],
  },
  {
    dim: 44,
    weight: 2.6,
    terms: ["ohttp", "rfc 9458", "oblivious http", "metadata privacy", "ip stripping", "relay"],
  },
  {
    dim: 45,
    weight: 2.5,
    terms: ["chaff", "decoy traffic", "packet padding", "traffic analysis", "timing correlation"],
  },
  {
    dim: 46,
    weight: 2.5,
    terms: ["canary trap", "honeypot", "bounty", "slashing", "stake", "operator cap"],
  },
  {
    dim: 47,
    weight: 2.5,
    terms: ["sprt", "wald sequential", "latency audit", "statistical auditor", "ashi"],
  },
  {
    dim: 48,
    weight: 2.5,
    terms: ["stylometry", "author anonymization", "pii scrubber", "compartment splitter"],
  },
  {
    dim: 49,
    weight: 2.5,
    terms: ["mongodb atlas", "vector search", "hybrid search", "reciprocal rank fusion", "rrf", "stream processing"],
  },
  {
    dim: 50,
    weight: 2.5,
    terms: ["voyage ai", "voyage-3", "nomic-embed-text", "automated embedding", "cosine similarity", "128-dim"],
  },
  {
    dim: 51,
    weight: 2.4,
    terms: ["tier a", "tier a+", "tier b", "hardware tier", "security tier"],
  },
  {
    dim: 52,
    weight: 2.4,
    terms: ["ecdsa", "p-384", "secp256k1", "signature verification", "receipt hash"],
  },
  {
    dim: 53,
    weight: 2.4,
    terms: ["kv-cache", "kv cache", "attention cache", "context window", "prefix block"],
  },
  {
    dim: 54,
    weight: 2.3,
    terms: ["enclave", "tee", "trusted execution environment", "confidential enclave", "hardware isolation"],
  },
  {
    dim: 55,
    weight: 2.3,
    terms: ["attestation", "quote", "evidence", "verification", "remote attestation", "measurement"],
  },
  {
    dim: 56,
    weight: 2.2,
    terms: ["architecture", "specification", "protocol", "design", "subsystem"],
  },
  {
    dim: 57,
    weight: 2.2,
    terms: ["provider", "catalog", "marketplace", "endpoint", "pricing"],
  },
  {
    dim: 58,
    weight: 2.3,
    terms: ["encryption", "cipher", "authenticated encryption", "aead", "key derivation", "hkdf"],
  },
  {
    dim: 59,
    weight: 2.3,
    terms: ["memory protection", "dram encryption", "bus encryption", "physical attacker", "interposer defense"],
  },
  {
    dim: 60,
    weight: 2.3,
    terms: ["zero knowledge", "halo2", "plonky3", "fhe", "mpc", "3pc", "speculative split"],
  },
  {
    dim: 61,
    weight: 2.2,
    terms: ["open weights", "closed weights", "merkle shard", "weight release", "model custody"],
  },
  {
    dim: 62,
    weight: 2.2,
    terms: ["forensics", "incident bundle", "audit log", "tamper-evident"],
  },
  {
    dim: 63,
    weight: 2.2,
    terms: ["streaming", "real-time", "telemetry", "anomaly detection", "aggregation pipeline"],
  },
];

/**
 * Deterministic 32-bit FNV-1a hash helper (ES2017 safe, no BigInt needed).
 */
function fnv1a32(str: string, seed = 0x811c9dc5): number {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/**
 * Normalizes any numeric vector to unit L2 length (norm === 1.0).
 */
export function normalizeVectorL2(vec: number[]): number[] {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i++) {
    sumSq += vec[i] * vec[i];
  }
  if (sumSq <= 1e-12) {
    const out = new Array<number>(vec.length).fill(0);
    if (out.length > 0) out[0] = 1;
    return out;
  }
  const invNorm = 1 / Math.sqrt(sumSq);
  return vec.map((v) => Number((v * invNorm).toFixed(8)));
}

/**
 * Local 128-d Feature-Hash Stand-In Embedding:
 * Note: Atlas Automated Embedding (`type: "autoEmbed"` with Voyage AI models) requires
 * MongoDB 8.2+ and an Atlas Model API key (plus M10+ dedicated storage auto-scaling).
 * The live dRouter Atlas M0 cluster runs MongoDB 8.0.34, where `autoEmbed` indexes remain PENDING.
 * When `VOYAGE_API_KEY` is not set, this function computes a deterministic 128-dimensional
 * feature-hash vector (`local-hashed-128 (stand-in)`) so native Atlas `$vectorSearch`
 * (`drouter_vector_index`, 128-d cosine) and native `$rankFusion` execute on the live cluster.
 */
export function embedDocumentText(text: string): EmbeddingResult {
  const normalized = (text || "").toLowerCase().trim();
  const raw = new Array<number>(EMBEDDING_DIMENSIONS).fill(0);

  // 1. Activate curated semantic concept clusters (Dims 0..63)
  for (const cluster of SEMANTIC_CONCEPT_CLUSTERS) {
    let matches = 0;
    for (const term of cluster.terms) {
      if (normalized.includes(term)) {
        matches += 1;
      }
    }
    if (matches > 0) {
      // Sublinear saturation so multiple matching synonyms reinforce the concept cleanly
      raw[cluster.dim] += cluster.weight * (1 + Math.log1p(matches));
    }
  }

  // Cross-concept semantic coupling (e.g., DDR5 / interposer / riser queries co-activate memory bus defense dims)
  if (raw[0] > 0 || raw[1] > 0) {
    const boost = Math.max(raw[0], raw[1]) * 0.65;
    raw[0] += boost;
    raw[1] += boost;
    raw[2] += boost * 0.5;
    raw[6] += boost * 0.5;
    raw[59] += boost * 0.7;
  }
  if (raw[3] > 0) {
    raw[1] += raw[3] * 0.5;
    raw[6] += raw[3] * 0.5;
    raw[59] += raw[3] * 0.5;
  }
  if (raw[22] > 0 && (raw[14] > 0 || raw[54] > 0)) {
    // Kimi K3 + 8x GPU / enclave strongly couples with Tinfoil & PPQ.AI 2-hop providers
    raw[30] += 1.8;
    raw[35] += 1.2;
  }

  // 2. Signed token & character 3-gram hash projections (Dims 64..127)
  const tokens = normalized
    .replace(/[^a-z0-9.+_-]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2);

  for (const token of tokens) {
    const h1 = fnv1a32(token, 0x811c9dc5);
    const dim1 = 64 + (h1 % 64);
    const sign1 = (h1 & 0x100) === 0 ? 1 : -1;
    raw[dim1] += sign1 * 0.45;

    // Character 3-grams for subword resilience
    const padded = `^${token}$`;
    for (let i = 0; i <= padded.length - 3; i++) {
      const trigram = padded.slice(i, i + 3);
      const h2 = fnv1a32(trigram, 0x9e3779b9);
      const dim2 = 64 + (h2 % 64);
      const sign2 = (h2 & 0x200) === 0 ? 1 : -1;
      raw[dim2] += sign2 * 0.12;
    }
  }

  // Re-normalize to exact unit L2 norm
  let sumSq = 0;
  for (let i = 0; i < EMBEDDING_DIMENSIONS; i++) {
    sumSq += raw[i] * raw[i];
  }
  const norm = sumSq > 1e-12 ? Math.sqrt(sumSq) : 1;
  const vector = raw.map((v, idx) => (sumSq > 1e-12 ? v / norm : idx === 0 ? 1 : 0));

  return {
    vector,
    model: LOCAL_STANDIN_EMBEDDING_MODEL,
    dimensions: EMBEDDING_DIMENSIONS,
    isLiveModel: false,
  };
}

/**
 * Live Voyage AI (`VOYAGE_API_KEY`) embedding call when configured, with deterministic
 * fallback to `embedDocumentText` (`local-hashed-128 (stand-in)`).
 */
export async function embedDocumentTextWithProvider(text: string): Promise<EmbeddingResult> {
  const deterministic = embedDocumentText(text);
  const voyageKey = process.env.VOYAGE_API_KEY?.trim();

  if (voyageKey) {
    try {
      const voyageModel = process.env.VOYAGE_MODEL?.trim() || "voyage-3-lite";
      const res = await fetch("https://api.voyageai.com/v1/embeddings", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${voyageKey}`,
        },
        body: JSON.stringify({
          input: [text],
          model: voyageModel,
        }),
        signal: AbortSignal.timeout(3500),
      });
      if (res.ok) {
        const data = (await res.json()) as {
          data?: Array<{ embedding?: number[] }>;
          model?: string;
        };
        const remoteVec = data.data?.[0]?.embedding;
        if (Array.isArray(remoteVec) && remoteVec.length >= EMBEDDING_DIMENSIONS) {
          const sliced = remoteVec.slice(0, EMBEDDING_DIMENSIONS);
          return {
            vector: normalizeVectorL2(sliced),
            model: `${data.model || voyageModel} (live Voyage AI)`,
            dimensions: EMBEDDING_DIMENSIONS,
            isLiveModel: true,
          };
        }
      }
    } catch {
      // Fallback to deterministic 128-d stand-in embedding
    }
  }

  return deterministic;
}

/**
 * Computes cosine similarity between two equal-length vectors in [-1, 1].
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  const len = Math.min(a.length, b.length);
  if (len === 0) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (denom <= 1e-12) return 0;
  return dot / denom;
}
