import { MongoClient } from "mongodb";
import { canonicalJson, sha256Hex } from "./canonical.js";

export const ATLAS_DATABASE_NAME = "drouter";
export const ATLAS_COLLECTION_NAME = "enclave_intelligence";
export const CORPUS_RETRIEVED_AT_UTC = "2026-10-24";
export const EMBEDDING_DIMENSIONS = 768;
export const LOCAL_STANDIN_EMBEDDING_MODEL =
  "local-hashed-768 (fallback: Tinfoil unreachable)";

const SEMANTIC_CONCEPT_CLUSTERS = [
  { dim: 0, weight: 3.2, terms: ["tee.fail", "teefail", "interposer", "riser", "passive probe", "logic analyzer", "tux-penguin", "tux penguin"] },
  { dim: 1, weight: 3.0, terms: ["ddr5", "memory bus", "dimm", "dram bus", "memory probe", "bus probe", "ddr5 riser", "physical bus"] },
  { dim: 2, weight: 2.8, terms: ["aes-xts", "aes-xex", "static iv", "deterministic tweak", "ciphertext block", "16-byte block", "block repetition", "ecb pattern"] },
  { dim: 3, weight: 3.2, terms: ["ddrop", "active memory", "fault injection", "memory replay", "dropped write", "parity error", "sept", "replay attack"] },
  { dim: 4, weight: 3.2, terms: ["cipherleaks", "badram", "ciphertext side-channel", "cache line", "sev-snp side-channel", "deterministic ciphertext", "vmsa", "spd"] },
  { dim: 5, weight: 3.2, terms: ["voltpillager", "voltage glitching", "svid", "plundervolt", "voltage regulator", "hardware glitch", "undervolting", "fault attack"] },
  { dim: 6, weight: 2.5, terms: ["advisory", "vulnerability", "exploit", "mitigation", "cve", "attack vector", "threat model", "side-channel"] },
  { dim: 7, weight: 2.6, terms: ["riser-proof", "bga", "soldered memory", "allowlist", "spdm", "tdisp", "tee-io", "sev-tio", "cxl 3.0", "ide"] },
  { dim: 8, weight: 2.8, terms: ["monotonic nonce", "aes-256-gcm", "gcm counter", "shannon entropy", "offload encryption", "freshness"] },
  { dim: 9, weight: 2.8, terms: ["zeroization", "crypto-shredding", "hbm wipe", "memory scrub", "zero-retention", "stateless", "ramdisk"] },
  { dim: 10, weight: 2.7, terms: ["custody", "two-hop", "prefix cache", "session isolation", "hmac-sha256", "nvattest"] },
  { dim: 11, weight: 2.7, terms: ["vmpl0", "svsm", "inner monitor", "egress policy", "secret scrubber", "token framing", "privilege ring"] },
  { dim: 12, weight: 2.6, terms: ["amd sev-snp", "sev-snp", "vcek", "milan", "genoa", "turin", "amd psp", "asp", "rmp"] },
  { dim: 13, weight: 2.6, terms: ["intel tdx", "tdx", "dcap", "mrtd", "rtmr", "tcb svn", "quote v4", "cvm", "trust domain"] },
  { dim: 14, weight: 2.8, terms: ["8x", "8x gpu", "b200", "h200", "h100", "blackwell", "hopper", "nvidia cc", "confidential computing", "gpu tee", "hbm3e"] },
  { dim: 15, weight: 2.6, terms: ["nvlink", "pcie", "bounce buffer", "local verifier", "rim", "gpu attestation", "spdm"] },
  { dim: 16, weight: 2.6, terms: ["hpke", "rfc 9180", "ehbp", "encrypted http body", "client-to-enclave", "e2ee", "end-to-end encrypted"] },
  { dim: 17, weight: 2.5, terms: ["ml-kem-768", "x25519mlkem768", "pqc", "post-quantum", "x25519", "hybrid kem", "quantum resistant"] },
  { dim: 18, weight: 2.6, terms: ["sigstore", "rekor", "transparency log", "inclusion proof", "reproducible build", "quorum", "manifest"] },
  { dim: 19, weight: 2.4, terms: ["dm-verity", "modelwrap", "rootfs", "initramfs", "container measurement", "ovmf", "sandbox"] },
  { dim: 20, weight: 2.5, terms: ["two-hop", "2-hop", "router enclave", "worker enclave", "mutual tls", "attested tls", "router-0.tinfoil.sh"] },
  { dim: 21, weight: 2.4, terms: ["gateway-tee-only", "terminated tls", "proxy termination", "plaintext gateway"] },
  { dim: 22, weight: 3.2, terms: ["kimi k3", "kimi k2.6", "kimi k2.5", "kimi", "moonshot", "2.8t moe", "2.8t"] },
  { dim: 23, weight: 3.0, terms: ["glm-5.3", "glm-5", "glm", "zhipu"] },
  { dim: 24, weight: 3.0, terms: ["deepseek", "deepseek v4.1", "deepseek v4", "deepseek r1", "deepseek v3", "671b"] },
  { dim: 25, weight: 2.6, terms: ["qwen", "qwen 3.8", "qwen 3.5", "qwen 3", "235b", "72b", "27b"] },
  { dim: 26, weight: 2.5, terms: ["llama 3.3", "llama", "70b", "meta llama"] },
  { dim: 27, weight: 2.6, terms: ["gemma 4", "gemma 3", "gemma", "31b", "27b", "26b"] },
  { dim: 28, weight: 2.6, terms: ["gpt-oss", "120b", "nemotron", "550b", "253b", "mistral", "voxtral"] },
  { dim: 29, weight: 2.2, terms: ["frontier model", "inference", "llm", "token streaming", "autoregressive"] },
  { dim: 30, weight: 3.2, terms: ["tinfoil", "tinfoil.sh", "live-integrated", "primary provider", "kimi-k3-inf14"] },
  { dim: 31, weight: 3.0, terms: ["phala", "redpill", "phala cloud", "dstack", "redpill.ai"] },
  { dim: 32, weight: 3.0, terms: ["near ai", "near cloud", "cloud.near.ai", "13 confidential models"] },
  { dim: 33, weight: 3.0, terms: ["venice", "venice.ai", "venice e2ee", "e2ee-"] },
  { dim: 34, weight: 3.0, terms: ["prem ai", "premai", "prem.io", "reticle", "xwing"] },
  { dim: 35, weight: 3.0, terms: ["ppq.ai", "ppq", "pay-per-query", "private/"] },
  { dim: 36, weight: 3.0, terms: ["confidential ai", "confidential.ai", "c8s", "inexorable"] },
  { dim: 37, weight: 3.0, terms: ["chutes", "bittensor", "miner", "chutes.ai"] },
  { dim: 38, weight: 3.0, terms: ["privatemode", "cosmian", "edgeless", "eu-hosted", "privatemode.ai"] },
  { dim: 39, weight: 3.0, terms: ["nanogpt", "nano-gpt", "ecdsa", "24 tee"] },
  { dim: 40, weight: 2.7, terms: ["circle arc", "arc blockchain", "on-chain attestation", "usdc", "settlement", "anchor", "5042002"] },
  { dim: 41, weight: 3.2, terms: ["chaumian", "rsa blind", "blind signature", "rsabssa", "rfc 9474", "credit nullifier", "nullifier", "anonymous credit", "double-spend", "x-drouter-credit"] },
  { dim: 42, weight: 2.7, terms: ["shamir", "threshold", "3-of-5", "secret sharing", "key share", "lagrange"] },
  { dim: 43, weight: 2.7, terms: ["k_freeze", "frozen blob", "session freeze", "state migration", "failover", "webcrypto"] },
  { dim: 44, weight: 2.6, terms: ["ohttp", "rfc 9458", "oblivious http", "metadata privacy", "ip stripping", "relay"] },
  { dim: 45, weight: 2.5, terms: ["chaff", "decoy traffic", "packet padding", "rfc 8259", "byte bucket", "timing correlation"] },
  { dim: 46, weight: 2.5, terms: ["canary trap", "honeypot", "bounty", "slashing", "stake", "operator"] },
  { dim: 47, weight: 2.5, terms: ["sprt", "wald sequential", "latency audit", "statistical auditor"] },
  { dim: 48, weight: 2.5, terms: ["stylometry", "author anonymization", "pii scrubber", "custom terms", "vault"] },
  { dim: 49, weight: 2.5, terms: ["mongodb atlas", "vector search", "hybrid search", "reciprocal rank fusion", "rrf", "$rankfusion"] },
  { dim: 50, weight: 2.5, terms: ["nomic-embed-text", "embedding", "cosine similarity", "768-dim"] },
  { dim: 51, weight: 2.4, terms: ["tier a", "tier a+", "tier b", "hardware tier", "security tier"] },
  { dim: 52, weight: 2.4, terms: ["ecdsa", "p-384", "secp256k1", "ed25519", "signature verification", "receipt hash"] },
  { dim: 53, weight: 2.4, terms: ["kv-cache", "kv cache", "attention cache", "context window", "262,144"] },
  { dim: 54, weight: 2.3, terms: ["enclave", "tee", "trusted execution environment", "confidential enclave", "hardware isolation"] },
  { dim: 55, weight: 2.3, terms: ["attestation", "quote", "evidence", "verification", "remote attestation", "measurement"] },
  { dim: 56, weight: 2.2, terms: ["architecture", "specification", "protocol", "design", "subsystem"] },
  { dim: 57, weight: 2.2, terms: ["provider", "catalog", "marketplace", "endpoint", "pricing"] },
  { dim: 58, weight: 2.3, terms: ["encryption", "cipher", "authenticated encryption", "aead", "key derivation", "hkdf"] },
  { dim: 59, weight: 2.3, terms: ["memory protection", "dram encryption", "bus encryption", "physical attacker", "interposer defense"] },
  { dim: 60, weight: 2.3, terms: ["zero knowledge", "fhe", "mpc", "3pc", "speculative split"] },
  { dim: 61, weight: 2.2, terms: ["open weights", "closed weights", "merkle", "weight release", "model custody"] },
  { dim: 62, weight: 2.2, terms: ["forensics", "incident bundle", "audit log", "tamper-evident"] },
  { dim: 63, weight: 2.2, terms: ["streaming", "real-time", "telemetry", "anomaly detection", "aggregation pipeline"] },
];

function fnv1a32(str, seed = 0x811c9dc5) {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

export function normalizeVectorL2(vec) {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i++) {
    sumSq += vec[i] * vec[i];
  }
  if (sumSq <= 1e-12) {
    const out = new Array(vec.length).fill(0);
    if (out.length > 0) out[0] = 1;
    return out;
  }
  const invNorm = 1 / Math.sqrt(sumSq);
  return vec.map((v) => Number((v * invNorm).toFixed(8)));
}

export function embedDocumentTextDeterministic(text) {
  const normalized = String(text || "").toLowerCase().trim();
  const raw = new Array(EMBEDDING_DIMENSIONS).fill(0);

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

  return normalizeVectorL2(raw);
}

/**
 * Curated 16-document public knowledge base (10 confidential providers, 4 hardware TEE advisories,
 * 2 cryptographic architecture specifications), ported from `src/lib/atlas/knowledge-base.ts`.
 */
export const RAW_CORPUS_SEED_DOCS = [
  {
    docId: "provider-tinfoil",
    title: "Tinfoil - Confidential Inference Enclave (AMD SEV-SNP (router) + Intel TDX (model enclave) + 8x NVIDIA H100 / H200 / B200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/tinfoil",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Tinfoil (live-integrated) runs confidential inference on AMD SEV-SNP (router) + Intel TDX (model enclave) and 8x NVIDIA H100 / H200 / B200 CC with HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS. Frontier models: Kimi K3 (256K ctx), GLM-5.3, DeepSeek V4.1 Flash, GPT-OSS 120B, Llama 3.3 70B, Gemma 4 31B, Voxtral Small 24B. Attestation verdict: Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix. Verification summary: Verified router quote (AMD SEV-SNP) + Intel TDX and NVIDIA CC model enclave quotes; hybrid X25519MLKEM768 TLS observed. Pricing: $0.02+/M. Source: https://confidentialinference.net/providers/tinfoil.",
    tags: ["tinfoil", "live-integrated", "amd sev-snp", "intel tdx", "8x nvidia h100 / h200 / b200 cc", "pqc-hybrid-ml-kem-768", "kimi k3 (256k ctx)", "glm-5.3", "deepseek v4.1 flash", "gpt-oss 120b", "llama 3.3 70b", "gemma 4 31b"],
  },
  {
    docId: "provider-phala-redpill",
    title: "Phala Cloud / Redpill - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/redpill",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Phala Cloud / Redpill (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Qwen 3.8 27B (phala/qwen3.8-27b-uncensored), Gemma 4 26B A4B (phala/gemma-4-26b-a4b-uncensored), DeepSeek V3.2 (deepseek/deepseek-v3.2), GLM-5.3 Flash (z-ai/glm-5.3-flash). Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Pricing: $0.15+/M. Source: https://confidentialinference.net/providers/redpill.",
    tags: ["phala-redpill", "phala cloud / redpill", "compatible-openai-e2ee", "intel tdx", "nvidia h100 / h200 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-near-ai-cloud",
    title: "NEAR AI Cloud - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/near",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "NEAR AI Cloud (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Kimi K3 (moonshotai/kimi-k3), Kimi K2.6 (moonshotai/kimi-k2.6), DeepSeek V3.2 (deepseek/deepseek-v3.2), GLM-5.3 (z-ai/glm-5.3), GLM-5.3 Flash (z-ai/glm-5.3-flash), Qwen 3.5 397B A17B, Qwen 3.8 27B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Pricing: $0.01+/M. Source: https://confidentialinference.net/providers/near.",
    tags: ["near-ai-cloud", "near ai cloud", "compatible-openai-e2ee", "intel tdx", "nvidia h100 / h200 cc", "classical-ecdh"],
  },
  {
    docId: "provider-venice-ai",
    title: "Venice.ai (E2EE Mode) - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/venice",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Venice.ai (E2EE Mode) (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Kimi K3 (e2ee-kimi-k3-p), Kimi K2.6 (e2ee-kimi-k2-6), DeepSeek V4 Flash (e2ee-deepseek-v4-flash), GLM-5.3 (e2ee-glm-5-3-p), GPT-OSS 120B (e2ee-gpt-oss-120b-p), Qwen 3.8 27B, Gemma 4 26B A4B. Pricing: $0.05+/M. Source: https://confidentialinference.net/providers/venice.",
    tags: ["venice-ai", "venice.ai (e2ee mode)", "compatible-openai-e2ee", "intel tdx", "nvidia h100 / h200 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-prem-ai",
    title: "Prem AI - Confidential Inference Enclave (Intel TDX / AMD SEV-SNP + NVIDIA H100 / Blackwell CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/prem",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Prem AI (compatible-openai-e2ee) runs confidential inference on Intel TDX / AMD SEV-SNP and NVIDIA H100 / Blackwell CC with Attested E2EE. Frontier models: DeepSeek V4.1 Flash 1017, Nemotron 3 Ultra 550B A55B, Qwen 3.8 27B, Qwen 3.6 27B, DeepGram General Nova 3. Attestation verdict: Per-Workload TDX Transcript Binding. Pricing: $0.30+/M. Source: https://confidentialinference.net/providers/prem.",
    tags: ["prem-ai", "prem ai", "compatible-openai-e2ee", "intel tdx / amd sev-snp", "nvidia h100 / blackwell cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-ppq-ai",
    title: "PPQ.AI - Confidential Inference Enclave (AMD SEV-SNP (router) + Intel TDX / SEV-SNP (Tinfoil backend) + NVIDIA H100 / H200 / B200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/ppq",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "PPQ.AI (compatible-openai-e2ee) runs confidential inference on AMD SEV-SNP (router) + Intel TDX / SEV-SNP (Tinfoil backend) and NVIDIA H100 / H200 / B200 CC with Attested E2EE. Frontier models: Kimi K3 (private/kimi-k3), DeepSeek V4.1 Flash (private/deepseek-v4-1-flash), GLM-5.3 (private/glm-5-3), GPT-OSS 120B (private/gpt-oss-120b), Llama 3.3 70B, Gemma 4 31B. Pricing: $0.16+/M. Source: https://confidentialinference.net/providers/ppq.",
    tags: ["ppq-ai", "ppq.ai", "compatible-openai-e2ee", "amd sev-snp", "intel tdx", "nvidia h100 / h200 / b200 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-confidential-ai",
    title: "Confidential AI - Confidential Inference Enclave (Intel TDX + NVIDIA B300 / B200 / H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/confidentialai",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Confidential AI (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA B300 / B200 / H100 CC with TEE-Terminated TLS. Frontier models: DeepSeek V4 Flash (deepseek-ai/DeepSeek-V4-Flash-0731), Qwen 3.8 27B, GLM 5.3, Kimi K3. Attestation verdict: Per-Workload TDX Transcript Binding. Pricing: $0.20+/M. Source: https://confidentialinference.net/providers/confidentialai.",
    tags: ["confidential-ai", "confidential ai", "compatible-openai-e2ee", "intel tdx", "nvidia b300 / b200 / h100 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-chutes-bittensor",
    title: "Chutes (Bittensor TEE) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 / H200 CC (Miner Dependent))",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/chutes",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Chutes (Bittensor TEE) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 / H200 CC with TEE-Only Gateway. Frontier models: Kimi K3 (moonshotai/Kimi-K3-TEE), Kimi K2.6, DeepSeek V4 Flash 0731, DeepSeek V3.2, GLM-5.2, Qwen 3.5 397B A17B, Gemma 4 31B Turbo. Attestation verdict: Gateway Attestation Only. Pricing: $0.02+/M. Source: https://confidentialinference.net/providers/chutes.",
    tags: ["chutes-bittensor", "chutes (bittensor tee)", "gateway-tee-only", "amd sev-snp + intel tdx", "classical-ecdh"],
  },
  {
    docId: "provider-privatemode-cosmian",
    title: "Privatemode (Edgeless / Cosmian) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/privatemode",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Privatemode (Edgeless / Cosmian) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 CC with TEE-Only Gateway. Frontier models: GLM-5.3, GLM-5.3 Flash, GPT-OSS 120B, DeepSeek OCR 2, Qwen 3 Embedding 4B, Voxtral Mini 3B, Whisper Large v3. Attestation verdict: Gateway Attestation Only. Pricing: $0.15+/M. Source: https://confidentialinference.net/providers/privatemode.",
    tags: ["privatemode-cosmian", "privatemode (edgeless / cosmian)", "gateway-tee-only", "amd sev-snp + intel tdx", "nvidia h100 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "provider-nanogpt",
    title: "NanoGPT - Confidential Inference Enclave (Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/nanogpt",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "NanoGPT (gateway-tee-only) runs confidential inference on Intel TDX and NVIDIA H100 CC with TEE-Only Gateway. Frontier models: Kimi K3 (TEE/kimi-k3), Kimi K2.6 (TEE/kimi-k2.6), DeepSeek V4.1 Flash (TEE/deepseek-v4.1-flash), DeepSeek V3.2, GLM-5.3, Qwen 3.8 27B, Llama 3.3 70B. Attestation verdict: Gateway Attestation Only. Pricing: $0.15+/M. Source: https://confidentialinference.net/providers/nanogpt.",
    tags: ["nanogpt", "gateway-tee-only", "intel tdx", "nvidia h100 cc", "pqc-hybrid-ml-kem-768"],
  },
  {
    docId: "advisory-tee-fail-ddr5",
    title: "TEE.fail: Breaking Trusted Execution Environments via DDR5 Memory Bus Interposition",
    category: "advisory",
    sourceUrl: "https://tee.fail/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published by researchers at Georgia Institute of Technology and Purdue University (Chuang, Seto, Berrios, van Schaik, Garman, Genkin), TEE.fail demonstrates a passive DDR5 DRAM bus interposer and riser probe built from off-the-shelf equipment under $1,000. Because Intel TDX, Intel SGX, and AMD SEV-SNP (even with Zen 5 Ciphertext Hiding enabled) use deterministic physical-address memory encryption (AES-XTS and AES-XEX) without per-write freshness, identical 16-byte plaintext blocks at the same physical address produce identical ciphertext blocks (the Tux-penguin pattern). The paper extracts OpenSSL constant-time ECDSA signing keys from AMD SEV-SNP guests, extracts Intel Provisioning Certification Enclave (PCE) keys to forge DCAP UpToDate TDX quotes, and relays borrowed NVIDIA Confidential Computing GPU attestation reports that are not bound to a specific host CPU. Tracked in vendor bulletins INTEL-SA-2025-10-28-001 and AMD-SB-3040.",
    tags: ["tee.fail", "ddr5", "memory bus", "interposer", "riser probe", "tux-penguin", "aes-xts", "amd-sb-3040", "intel-sa-2025-10-28-001"],
  },
  {
    docId: "advisory-ddrop",
    title: "DDRop: Active Memory Interposer Attacks on Confidential VMs by Dropping DDR5 Writes (ACM CCS 2026)",
    category: "advisory",
    sourceUrl: "https://ddropattack.eu/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published at ACM CCS 2026 by researchers from KU Leuven, ETH Zurich, Durham University, and Google (De Meulemeester, Gloor, Jattke, Moghimi, Oswald, Thompson, Razavi, Verbauwhede, Van Bulck), DDRop introduces a $159 active analog-switch DDR5 interposer operating at native DDR5 speed. By injecting a command-bus parity error and suppressing the alert signal, the DIMM silently discards targeted memory writes while the processor believes the write succeeded. Because scalable memory encryption in Intel TDX, Intel Scalable SGX, and AMD SEV-SNP lacks cryptographic freshness trees, stale ciphertext remains valid. On Intel TDX, dropping zero-initialization writes during Secure Extended Page Table allocation (TDH.MEM.SEPT.ADD) lets an attacker remap guest physical pages, toggle the TD debug flag, or overwrite MRTD launch measurements in the TD control structure to forge TDX attestation reports. Tracked under INTEL-SA-2026-08-11-001 and AMD-SB-3048.",
    tags: ["ddrop", "ddr5", "memory bus", "replay attack", "fault injection", "dropped write", "sept", "intel tdx", "amd sev-snp", "amd-sb-3048"],
  },
  {
    docId: "advisory-cipherleaks",
    title: "CIPHERLEAKS & BadRAM: AMD SEV-SNP Ciphertext Side-Channel and Memory Aliasing Advisories (CVE-2020-12966, CVE-2024-21944)",
    category: "advisory",
    sourceUrl: "https://cipherleaks.com/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "CIPHERLEAKS (USENIX Security 2021, Li et al., CVE-2020-12966 / AMD-SB-1013) demonstrated that deterministic XOR-Encrypt-XOR (AES-XEX) physical-address memory encryption in AMD SEV and SEV-SNP lets an untrusted hypervisor monitor ciphertext transitions in the encrypted VM Save Area (VMSA) to recover constant-time OpenSSL RSA and ECDSA keys. AMD issued firmware mitigations in AMD-SB-1013 and added Zen 5 Ciphertext Hiding. Separately, BadRAM (IEEE S&P 2025, De Meulemeester et al., CVE-2024-21944 / AMD-SB-3015, https://badram.eu/) showed that reprogramming an unlocked DIMM Serial Presence Detect (SPD) chip creates ghost physical address aliases that bypass AMD SEV-SNP Reverse Map Table (RMP) checks and replay attestation measurements; AMD issued boot-time SPD alias validation firmware updates in AMD-SB-3015.",
    tags: ["cipherleaks", "badram", "amd sev-snp", "ciphertext side-channel", "cve-2020-12966", "cve-2024-21944", "amd-sb-1013", "amd-sb-3015", "vmsa", "rmp"],
  },
  {
    docId: "advisory-voltpillager",
    title: "VoltPillager: Hardware-Based SVID Voltage Fault Injection Against TEEs (USENIX Security 2021, CVE-2019-11157)",
    category: "advisory",
    sourceUrl: "https://www.usenix.org/conference/usenixsecurity21/presentation/chen-zitai",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published at USENIX Security 2021 by University of Birmingham researchers (Chen, Vasilakis, Murdock, Dean, Oswald, Garcia), VoltPillager demonstrates hardware-based voltage glitching against x86 server processors by injecting Serial Voltage Identification (SVID) bus frames between the CPU and the motherboard voltage regulator. Unlike software-only undervolting (Plundervolt, CVE-2019-11157), physical SVID bus injection bypasses microcode undervolting locks on patched processors to corrupt cryptographic calculations and delay memory writes inside enclaves. Because physical voltage fault injection is outside single-host CPU threat models, confidential routing systems combine independent Sigstore Rekor transparency verification, client-side HPKE encryption, and on-chain receipt verification.",
    tags: ["voltpillager", "voltage glitching", "svid", "cve-2019-11157", "plundervolt", "hardware fault", "usenix-security-2021", "fault injection"],
  },
  {
    docId: "arch-vmpl0-inner-monitor",
    title: "Chaumian RSA Blind Signature Credits (RFC 9474 RSABSSA), Client PII Scrubbing & Circle Arc Receipts",
    category: "architecture",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9474.html",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "dRouter decouples credit issuance from inference requests using Chaumian RSA Blind Signatures (RFC 9474 RSABSSA). The browser generates a random credit secret, blinds it with a random factor coprime to the issuer RSA modulus, obtains a blind signature from the credit issuer, and unblinds it locally. When sending an HPKE-encrypted prompt through the relay via the x-drouter-credit header, the relay verifies the RSA signature and records a SHA-256 nullifier in MongoDB Atlas credit_nullifiers to prevent double-spending without linking the token to issuance. Before encryption, client-side PII scrubbing, stylometry normalization, and power-of-two RFC 8259 JSON byte-bucket padding strip identifying metadata, while verification receipts are anchored on the Circle Arc testnet registry (0xbc8085c2b6fe6e0db05f169925c0b841828f4481, chain 5042002) with timestamps coarsened to the UTC hour.",
    tags: ["chaumian", "rsa blind signature", "blind signature", "credits", "rfc 9474", "rsabssa", "credit nullifier", "nullifier", "double-spend", "x-drouter-credit", "circle arc", "pii scrubber", "packet padding", "architecture"],
  },
  {
    docId: "arch-two-hop-gpu-custody",
    title: "Tinfoil Chained Two-Hop Enclave Attestation, NVIDIA Confidential Computing & RFC 9180 HPKE (EHBP)",
    category: "architecture",
    sourceUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Tinfoil chains hardware attestation across two enclave hops and verifies supply-chain provenance via Sigstore Rekor. Hop 1 is the open-source confidential model router (tinfoilsh/confidential-model-router on router-0.tinfoil.sh, AMD SEV-SNP predicate v2), which verifies each Hop 2 model enclave (Intel TDX or AMD SEV-SNP CVM paired with 8x NVIDIA Hopper H100/H200 or Blackwell B200 Confidential Computing GPUs verified at boot via NVIDIA nvattest, plus read-only modelwrap weight volumes checked by Linux kernel dm-verity). Clients verify the hardware certificate chain and Sigstore bundle before encrypting HTTP request and response bodies end-to-end to the enclave's attested HPKE public key via the Encrypted HTTP Body Protocol (EHBP, RFC 9180) so intermediate relays never see plaintext prompts or completions.",
    tags: ["two-hop", "tinfoil", "amd sev-snp", "intel tdx", "nvidia cc", "nvattest", "dm-verity", "modelwrap", "sigstore", "rekor", "hpke", "rfc 9180", "ehbp", "8x gpu", "b200", "h200", "h100", "architecture"],
  },
];

function stripEmDashes(str) {
  return String(str ?? "").replace(/[\u2013\u2014]/g, "-");
}

export function normalizeCorpusDoc(raw) {
  const docId = stripEmDashes(raw.docId || raw.title || "doc").trim();
  const title = stripEmDashes(raw.title || docId).trim();
  const category = stripEmDashes(raw.category || "advisory").trim();
  const summary = stripEmDashes(raw.summary || "").trim();
  const sourceUrl =
    typeof raw.sourceUrl === "string" && raw.sourceUrl.trim().startsWith("https://")
      ? raw.sourceUrl.trim()
      : "https://docs.tinfoil.sh/verification/attestation-architecture";
  const retrievedAt =
    typeof raw.retrievedAt === "string" && raw.retrievedAt.trim().length > 0
      ? stripEmDashes(raw.retrievedAt.trim())
      : CORPUS_RETRIEVED_AT_UTC;
  const tags = Array.isArray(raw.tags)
    ? raw.tags.map((t) => stripEmDashes(String(t)).trim()).filter(Boolean)
    : [];

  const hasValidEmbedding =
    Array.isArray(raw.embedding) &&
    raw.embedding.length === EMBEDDING_DIMENSIONS &&
    raw.embedding.every((n) => typeof n === "number" && Number.isFinite(n));

  const compositeText = `${title} ${category} ${summary} ${sourceUrl} ${tags.join(" ")}`;
  const embedding = hasValidEmbedding
    ? raw.embedding.map((n) => Number(n))
    : embedDocumentTextDeterministic(compositeText);
  const embeddingModel =
    hasValidEmbedding && typeof raw.embeddingModel === "string" && raw.embeddingModel.trim()
      ? stripEmDashes(raw.embeddingModel.trim())
      : LOCAL_STANDIN_EMBEDDING_MODEL;

  return {
    docId,
    title,
    category,
    summary,
    tags,
    sourceUrl,
    retrievedAt,
    embedding,
    embeddingModel,
    embeddingDimensions: EMBEDDING_DIMENSIONS,
  };
}

export const SEED_CORPUS_DOCS = Object.freeze(
  RAW_CORPUS_SEED_DOCS.map((d) => Object.freeze(normalizeCorpusDoc(d))).sort((a, b) =>
    a.docId.localeCompare(b.docId),
  ),
);

let mongoClientPromise = null;
let testDbOverride;

export function setCorpusDbForTests(db) {
  testDbOverride = db;
}

async function getMongoDb() {
  if (testDbOverride !== undefined) {
    return testDbOverride;
  }
  const uri = typeof process.env.MONGODB_URI === "string" ? process.env.MONGODB_URI.trim() : "";
  if (!uri) return null;
  try {
    if (!mongoClientPromise) {
      const client = new MongoClient(uri, {
        appName: "deroute-core-enclave",
        maxPoolSize: 4,
        serverSelectionTimeoutMS: 4500,
      });
      mongoClientPromise = client.connect();
    }
    const connected = await mongoClientPromise;
    return connected.db(process.env.MONGODB_DB || ATLAS_DATABASE_NAME);
  } catch {
    mongoClientPromise = null;
    return null;
  }
}

/**
 * Returns the entire public knowledge base (`drouter.enclave_intelligence`),
 * identical for every caller, sorted deterministically by `docId`, with `contentSha256`.
 * Accepts zero query parameters so MongoDB learns nothing about any user's interest (Wave 6 A1).
 */
export async function getWholeKnowledgeCorpus({ db } = {}) {
  const database = db !== undefined ? db : await getMongoDb();
  const byId = new Map();
  for (const seedDoc of SEED_CORPUS_DOCS) {
    byId.set(seedDoc.docId, seedDoc);
  }

  let source = "seed-corpus";
  if (database) {
    try {
      const col = database.collection(ATLAS_COLLECTION_NAME);
      const mongoDocs = await col
        .find(
          {},
          {
            projection: {
              _id: 0,
              docId: 1,
              title: 1,
              category: 1,
              summary: 1,
              tags: 1,
              sourceUrl: 1,
              retrievedAt: 1,
              embedding: 1,
              embeddingModel: 1,
              embeddingDimensions: 1,
            },
          },
        )
        .toArray();
      if (Array.isArray(mongoDocs) && mongoDocs.length > 0) {
        source = "mongodb-atlas";
        for (const rawDoc of mongoDocs) {
          if (rawDoc && (rawDoc.docId || rawDoc.title)) {
            const normalized = normalizeCorpusDoc(rawDoc);
            byId.set(normalized.docId, normalized);
          }
        }
      }
    } catch {
      source = "seed-corpus";
    }
  }

  const documents = Array.from(byId.values()).sort((a, b) => a.docId.localeCompare(b.docId));
  const contentSha256 = `0x${sha256Hex(canonicalJson(documents))}`;

  return {
    ok: true,
    database: ATLAS_DATABASE_NAME,
    collection: ATLAS_COLLECTION_NAME,
    source,
    totalDocs: documents.length,
    contentSha256,
    documents,
  };
}
