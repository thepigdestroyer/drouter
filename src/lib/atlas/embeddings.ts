
export const EMBEDDING_DIMENSIONS = 768 as const;
export const TINFOIL_EMBEDDING_MODEL_ID = "nomic-embed-text" as const;
export const TINFOIL_ATTESTED_EMBEDDING_MODEL =
  "nomic-embed-text (Tinfoil attested enclave)" as const;
export const LOCAL_STANDIN_EMBEDDING_MODEL =
  "local-hashed-768 (fallback: Tinfoil unreachable)" as const;

export interface EmbeddingResult {
  vector: number[];
  model: string;
  dimensions: number;
  isLiveModel: boolean;
  attestedEnclave?: boolean;
  enclaveHost?: string;
}

export type TinfoilEmbeddingTestHandler = (texts: string[]) => Promise<{
  vectors: number[][];
  model?: string;
  enclaveHost?: string;
}>;

interface VerifiedTinfoilEmbeddingClient {
  client: {
    embeddings: {
      create(params: { model: string; input: string[] }): Promise<{
        data: Array<{ embedding: number[]; index?: number }>;
        model?: string;
      }>;
    };
  };
  enclaveHost: string;
  securityVerified: boolean;
}

const globalForEmbeddings = globalThis as unknown as {
  __drouterTinfoilEmbedClient?: Promise<VerifiedTinfoilEmbeddingClient>;
  __drouterLiveEmbeddingCache?: Map<string, EmbeddingResult>;
  __drouterTestEmbeddingHandler?: TinfoilEmbeddingTestHandler | null;
};

function getLiveEmbeddingCache(): Map<string, EmbeddingResult> {
  if (!globalForEmbeddings.__drouterLiveEmbeddingCache) {
    globalForEmbeddings.__drouterLiveEmbeddingCache = new Map<string, EmbeddingResult>();
  }
  return globalForEmbeddings.__drouterLiveEmbeddingCache;
}

export function setTinfoilEmbeddingHandlerForTests(
  handler: TinfoilEmbeddingTestHandler | null,
): void {
  globalForEmbeddings.__drouterTestEmbeddingHandler = handler;
}

export function clearEmbeddingCacheForTests(): void {
  globalForEmbeddings.__drouterLiveEmbeddingCache?.clear();
}

export function seedLiveEmbeddingCache(text: string, result: EmbeddingResult): void {
  const key = (text || "").trim();
  if (key && result.isLiveModel && result.vector.length === EMBEDDING_DIMENSIONS) {
    getLiveEmbeddingCache().set(key, result);
  }
}

export function resolveTinfoilApiKey(): string | null {
  // Next.js and `node --env-file=.env.local` load env vars; never read secret files from disk here.
  return process.env.TINFOIL_API_KEY?.trim() || null;
}

/**
 * 64 curated semantic concept clusters for confidential AI, hardware TEEs,
 * side-channel advisories, and cryptographic protocols.
 * Used only by the labelled fallback (`local-hashed-768 (fallback: Tinfoil unreachable)`)
 * when Tinfoil's attested `nomic-embed-text` enclave cannot be reached.
 * Dimensions 0..63 encode explicit domain concept activations;
 * Dimensions 64..767 encode signed token, token-bigram, and character trigram hash projections.
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
    terms: ["aes-xts", "aes-xex", "static iv", "deterministic tweak", "ciphertext block", "16-byte block", "block repetition", "ecb pattern"],
  },
  {
    dim: 3,
    weight: 3.2,
    terms: ["ddrop", "active memory", "fault injection", "memory replay", "dropped write", "parity error", "sept", "replay attack"],
  },
  {
    dim: 4,
    weight: 3.2,
    terms: ["cipherleaks", "badram", "ciphertext side-channel", "cache line", "sev-snp side-channel", "deterministic ciphertext", "vmsa", "spd"],
  },
  {
    dim: 5,
    weight: 3.2,
    terms: ["voltpillager", "voltage glitching", "svid", "plundervolt", "voltage regulator", "hardware glitch", "undervolting", "fault attack"],
  },
  {
    dim: 6,
    weight: 2.5,
    terms: ["advisory", "vulnerability", "exploit", "mitigation", "cve", "attack vector", "threat model", "side-channel"],
  },
  {
    dim: 7,
    weight: 2.6,
    terms: ["riser-proof", "bga", "soldered memory", "allowlist", "spdm", "tdisp", "tee-io", "sev-tio", "cxl 3.0", "ide"],
  },
  {
    dim: 8,
    weight: 2.8,
    terms: ["monotonic nonce", "aes-256-gcm", "gcm counter", "shannon entropy", "offload encryption", "freshness"],
  },
  {
    dim: 9,
    weight: 2.8,
    terms: ["zeroization", "crypto-shredding", "hbm wipe", "memory scrub", "zero-retention", "stateless", "ramdisk"],
  },
  {
    dim: 10,
    weight: 2.7,
    terms: ["custody", "two-hop", "prefix cache", "session isolation", "hmac-sha256", "nvattest"],
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
    terms: ["ml-kem-768", "x25519mlkem768", "pqc", "post-quantum", "x25519", "hybrid kem", "quantum resistant"],
  },
  {
    dim: 18,
    weight: 2.6,
    terms: ["sigstore", "rekor", "transparency log", "inclusion proof", "reproducible build", "quorum", "manifest"],
  },
  {
    dim: 19,
    weight: 2.4,
    terms: ["dm-verity", "modelwrap", "rootfs", "initramfs", "container measurement", "ovmf", "sandbox"],
  },
  {
    dim: 20,
    weight: 2.5,
    terms: ["two-hop", "2-hop", "router enclave", "worker enclave", "mutual tls", "attested tls", "router-0.tinfoil.sh"],
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
    terms: ["kimi k3", "kimi k2.6", "kimi k2.5", "kimi", "moonshot", "2.8t moe", "2.8t"],
  },
  {
    dim: 23,
    weight: 3.0,
    terms: ["glm-5.3", "glm-5", "glm", "zhipu"],
  },
  {
    dim: 24,
    weight: 3.0,
    terms: ["deepseek", "deepseek v4.1", "deepseek v4", "deepseek r1", "deepseek v3", "671b"],
  },
  {
    dim: 25,
    weight: 2.6,
    terms: ["qwen", "qwen 3.8", "qwen 3.5", "qwen 3", "235b", "72b", "27b"],
  },
  {
    dim: 26,
    weight: 2.5,
    terms: ["llama 3.3", "llama", "70b", "meta llama"],
  },
  {
    dim: 27,
    weight: 2.6,
    terms: ["gemma 4", "gemma 3", "gemma", "31b", "27b", "26b"],
  },
  {
    dim: 28,
    weight: 2.6,
    terms: ["gpt-oss", "120b", "nemotron", "550b", "253b", "mistral", "voxtral"],
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
    terms: ["tinfoil", "tinfoil.sh", "live-integrated", "primary provider", "kimi-k3-inf14"],
  },
  {
    dim: 31,
    weight: 3.0,
    terms: ["phala", "redpill", "phala cloud", "dstack", "redpill.ai"],
  },
  {
    dim: 32,
    weight: 3.0,
    terms: ["near ai", "near cloud", "cloud.near.ai", "13 confidential models"],
  },
  {
    dim: 33,
    weight: 3.0,
    terms: ["venice", "venice.ai", "venice e2ee", "e2ee-"],
  },
  {
    dim: 34,
    weight: 3.0,
    terms: ["prem ai", "premai", "prem.io", "reticle", "xwing"],
  },
  {
    dim: 35,
    weight: 3.0,
    terms: ["ppq.ai", "ppq", "pay-per-query", "private/"],
  },
  {
    dim: 36,
    weight: 3.0,
    terms: ["confidential ai", "confidential.ai", "c8s", "inexorable"],
  },
  {
    dim: 37,
    weight: 3.0,
    terms: ["chutes", "bittensor", "miner", "chutes.ai"],
  },
  {
    dim: 38,
    weight: 3.0,
    terms: ["privatemode", "cosmian", "edgeless", "eu-hosted", "privatemode.ai"],
  },
  {
    dim: 39,
    weight: 3.0,
    terms: ["nanogpt", "nano-gpt", "ecdsa", "24 tee"],
  },

  // Cryptographic Settlement, Privacy & dRouter Architecture (Dims 40..63)
  {
    dim: 40,
    weight: 2.7,
    terms: ["circle arc", "arc blockchain", "on-chain attestation", "usdc", "settlement", "anchor", "5042002"],
  },
  {
    dim: 41,
    weight: 3.2,
    terms: ["chaumian", "rsa blind", "blind signature", "rsabssa", "rfc 9474", "credit nullifier", "nullifier", "anonymous credit", "double-spend", "x-drouter-credit"],
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
    terms: ["chaff", "decoy traffic", "packet padding", "rfc 8259", "byte bucket", "timing correlation"],
  },
  {
    dim: 46,
    weight: 2.5,
    terms: ["canary trap", "honeypot", "bounty", "slashing", "stake", "operator"],
  },
  {
    dim: 47,
    weight: 2.5,
    terms: ["sprt", "wald sequential", "latency audit", "statistical auditor"],
  },
  {
    dim: 48,
    weight: 2.5,
    terms: ["stylometry", "author anonymization", "pii scrubber", "custom terms", "vault"],
  },
  {
    dim: 49,
    weight: 2.5,
    terms: ["mongodb atlas", "vector search", "hybrid search", "reciprocal rank fusion", "rrf", "$rankfusion"],
  },
  {
    dim: 50,
    weight: 2.5,
    terms: ["nomic-embed-text", "embedding", "cosine similarity", "768-dim"],
  },
  {
    dim: 51,
    weight: 2.4,
    terms: ["tier a", "tier a+", "tier b", "hardware tier", "security tier"],
  },
  {
    dim: 52,
    weight: 2.4,
    terms: ["ecdsa", "p-384", "secp256k1", "ed25519", "signature verification", "receipt hash"],
  },
  {
    dim: 53,
    weight: 2.4,
    terms: ["kv-cache", "kv cache", "attention cache", "context window", "262,144"],
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
    terms: ["zero knowledge", "fhe", "mpc", "3pc", "speculative split"],
  },
  {
    dim: 61,
    weight: 2.2,
    terms: ["open weights", "closed weights", "merkle", "weight release", "model custody"],
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
 * Deterministic 768-dimensional local feature-hash fallback embedding.
 * Used only when Tinfoil's attested `nomic-embed-text` enclave cannot be reached
 * or when synchronous offline embedding is requested.
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
      raw[cluster.dim] += cluster.weight * (1 + Math.log1p(matches));
    }
  }

  // Cross-concept semantic coupling for memory-bus interposer & two-hop queries
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
    raw[30] += 1.8;
    raw[35] += 1.2;
  }

  // 2. Signed token & character 3-gram hash projections across Dims 64..767 (704 buckets)
  const hashBuckets = EMBEDDING_DIMENSIONS - 64;
  const tokens = normalized
    .replace(/[^a-z0-9.+_-]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2);

  for (let tIdx = 0; tIdx < tokens.length; tIdx++) {
    const token = tokens[tIdx];
    const h1 = fnv1a32(token, 0x811c9dc5);
    const dim1 = 64 + (h1 % hashBuckets);
    const sign1 = (h1 & 0x100) === 0 ? 1 : -1;
    raw[dim1] += sign1 * 0.45;

    if (tIdx + 1 < tokens.length) {
      const bigram = `${token}_${tokens[tIdx + 1]}`;
      const hb = fnv1a32(bigram, 0x85ebca6b);
      const dimB = 64 + (hb % hashBuckets);
      const signB = (hb & 0x100) === 0 ? 1 : -1;
      raw[dimB] += signB * 0.25;
    }

    const padded = `^${token}$`;
    for (let i = 0; i <= padded.length - 3; i++) {
      const trigram = padded.slice(i, i + 3);
      const h2 = fnv1a32(trigram, 0x9e3779b9);
      const dim2 = 64 + (h2 % hashBuckets);
      const sign2 = (h2 & 0x200) === 0 ? 1 : -1;
      raw[dim2] += sign2 * 0.12;
    }
  }

  return {
    vector: normalizeVectorL2(raw),
    model: LOCAL_STANDIN_EMBEDDING_MODEL,
    dimensions: EMBEDDING_DIMENSIONS,
    isLiveModel: false,
    attestedEnclave: false,
  };
}

async function getVerifiedTinfoilEmbeddingClient(
  apiKey: string,
): Promise<VerifiedTinfoilEmbeddingClient> {
  if (!globalForEmbeddings.__drouterTinfoilEmbedClient) {
    globalForEmbeddings.__drouterTinfoilEmbedClient = (async () => {
      const { TinfoilAI } = await import("tinfoil");
      const client = new TinfoilAI({ apiKey });
      await client.ready();
      const doc = await client.getVerificationDocument();
      if (!doc.securityVerified) {
        throw new Error("Tinfoil enclave attestation verification failed");
      }
      return {
        client: client as unknown as VerifiedTinfoilEmbeddingClient["client"],
        enclaveHost: doc.enclaveHost || "inference.tinfoil.sh",
        securityVerified: Boolean(doc.securityVerified),
      };
    })().catch((err) => {
      globalForEmbeddings.__drouterTinfoilEmbedClient = undefined;
      throw err;
    });
  }
  return globalForEmbeddings.__drouterTinfoilEmbedClient;
}

/**
 * Batches one or more texts through Tinfoil's attested `nomic-embed-text` enclave
 * (`nomic-embed-text.small-inf12.tinfoil.containers.tinfoil.dev` via `router-0.tinfoil.sh`,
 * 768 dimensions, EHBP/HPKE encrypted body). Falls back to `embedDocumentText`
 * (`local-hashed-768 (fallback: Tinfoil unreachable)`) only when Tinfoil is unreachable.
 */
export async function embedBatchWithProvider(texts: string[]): Promise<EmbeddingResult[]> {
  if (texts.length === 0) return [];

  const cache = getLiveEmbeddingCache();
  const results = new Array<EmbeddingResult | null>(texts.length).fill(null);
  const missingIndices: number[] = [];
  const missingInputs: string[] = [];

  for (let i = 0; i < texts.length; i++) {
    const clean = (texts[i] || "").trim() || "confidential enclave";
    const cached = cache.get(clean);
    if (cached && cached.vector.length === EMBEDDING_DIMENSIONS) {
      results[i] = cached;
    } else {
      missingIndices.push(i);
      missingInputs.push(clean);
    }
  }

  if (missingInputs.length === 0) {
    return results as EmbeddingResult[];
  }

  // 1. Test hook for deterministic unit tests without unmocked network calls
  if (globalForEmbeddings.__drouterTestEmbeddingHandler) {
    try {
      const mocked = await globalForEmbeddings.__drouterTestEmbeddingHandler(missingInputs);
      if (Array.isArray(mocked.vectors) && mocked.vectors.length === missingInputs.length) {
        for (let m = 0; m < missingInputs.length; m++) {
          const vec = mocked.vectors[m];
          if (Array.isArray(vec) && vec.length === EMBEDDING_DIMENSIONS) {
            const entry: EmbeddingResult = {
              vector: normalizeVectorL2(vec),
              model: mocked.model || TINFOIL_ATTESTED_EMBEDDING_MODEL,
              dimensions: EMBEDDING_DIMENSIONS,
              isLiveModel: true,
              attestedEnclave: true,
              enclaveHost: mocked.enclaveHost || "inference.tinfoil.sh",
            };
            cache.set(missingInputs[m], entry);
            results[missingIndices[m]] = entry;
          }
        }
      }
    } catch {
      // Fall through to fallback
    }
  } else {
    // 2. Live attested Tinfoil `nomic-embed-text` enclave call
    const tinfoilKey = resolveTinfoilApiKey();
    if (tinfoilKey) {
      try {
        const verified = await getVerifiedTinfoilEmbeddingClient(tinfoilKey);
        const res = await verified.client.embeddings.create({
          model: TINFOIL_EMBEDDING_MODEL_ID,
          input: missingInputs,
        });
        if (Array.isArray(res.data) && res.data.length === missingInputs.length) {
          for (let m = 0; m < missingInputs.length; m++) {
            const item = res.data[m];
            const remoteVec = item?.embedding;
            if (Array.isArray(remoteVec) && remoteVec.length === EMBEDDING_DIMENSIONS) {
              const entry: EmbeddingResult = {
                vector: normalizeVectorL2(remoteVec),
                model: TINFOIL_ATTESTED_EMBEDDING_MODEL,
                dimensions: EMBEDDING_DIMENSIONS,
                isLiveModel: true,
                attestedEnclave: true,
                enclaveHost: verified.enclaveHost,
              };
              cache.set(missingInputs[m], entry);
              results[missingIndices[m]] = entry;
            }
          }
        }
      } catch {
        // Fallback to labelled local-hashed-768 when Tinfoil is unreachable
      }
    }
  }

  for (let i = 0; i < texts.length; i++) {
    if (!results[i]) {
      results[i] = embedDocumentText(texts[i]);
    }
  }

  return results as EmbeddingResult[];
}

/**
 * Embeds a single document or query through Tinfoil's attested `nomic-embed-text`
 * enclave (768 dims), falling back to `embedDocumentText` (`local-hashed-768 (fallback: Tinfoil unreachable)`)
 * when Tinfoil cannot be reached.
 */
export async function embedDocumentTextWithProvider(text: string): Promise<EmbeddingResult> {
  const [res] = await embedBatchWithProvider([text]);
  return res ?? embedDocumentText(text);
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
