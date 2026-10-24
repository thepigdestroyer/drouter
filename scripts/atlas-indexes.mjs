#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MongoClient } from "mongodb";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENV_PATH = join(ROOT, ".env.local");
const EMBEDDING_DIMENSIONS = 128;
const COLLECTION_NAME = "enclave_intelligence";
const TEXT_INDEX_NAME = "drouter_text_search";
const VECTOR_INDEX_NAME = "drouter_vector_index";

function loadMongoUri() {
  if (process.env.MONGODB_URI) return process.env.MONGODB_URI;
  if (!existsSync(ENV_PATH)) return null;
  const text = readFileSync(ENV_PATH, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("MONGODB_URI=")) {
      let val = line.slice("MONGODB_URI=".length).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      return val;
    }
  }
  return null;
}

const SEMANTIC_CONCEPT_CLUSTERS = [
  { dim: 0, weight: 3.2, terms: ["tee.fail", "teefail", "interposer", "riser", "passive probe", "logic analyzer", "tux-penguin", "tux penguin"] },
  { dim: 1, weight: 3.0, terms: ["ddr5", "memory bus", "dimm", "dram bus", "memory probe", "bus probe", "ddr5 riser", "physical bus"] },
  { dim: 2, weight: 2.8, terms: ["aes-xts", "static iv", "deterministic tweak", "ciphertext block", "16-byte block", "block repetition", "ecb pattern"] },
  { dim: 3, weight: 3.2, terms: ["ddrop", "active memory", "fault injection", "memory replay", "bus splice", "rowhammer", "bit flip", "replay attack"] },
  { dim: 4, weight: 3.2, terms: ["cipherleaks", "ciphertext side-channel", "cache line", "sev-snp side-channel", "deterministic ciphertext"] },
  { dim: 5, weight: 3.2, terms: ["voltpillager", "voltage glitching", "svi2", "pmbus", "voltage regulator", "hardware glitch", "undervolting", "fault attack"] },
  { dim: 6, weight: 2.5, terms: ["advisory", "vulnerability", "exploit", "mitigation", "cve", "attack vector", "threat model", "side-channel"] },
  { dim: 7, weight: 2.6, terms: ["riser-proof", "bga", "soldered memory", "allowlist", "spdm 1.2", "tdisp", "tee-io", "sev-tio", "cxl 3.0", "ide"] },
  { dim: 8, weight: 2.8, terms: ["monotonic nonce", "aes-256-gcm", "gcm counter", "shannon entropy", "offload encryption", "kv-cache offload"] },
  { dim: 9, weight: 2.8, terms: ["pop()", "zeroization", "crypto-shredding", "hbm wipe", "memory scrub", "zero-retention", "post-turn wipe", "zeroize"] },
  { dim: 10, weight: 2.7, terms: ["custody", "two-hop gpu custody", "custodyctrdrbg", "drbg", "prefix cache", "session isolation", "hmac-sha256"] },
  { dim: 11, weight: 2.7, terms: ["vmpl0", "svsm", "inner monitor", "egress policy", "secret scrubber", "token framing", "privilege ring"] },
  { dim: 12, weight: 2.6, terms: ["amd sev-snp", "sev-snp", "vcek", "milan", "genoa", "turin", "amd psp", "asp", "rmp"] },
  { dim: 13, weight: 2.6, terms: ["intel tdx", "tdx", "dcap", "mrtd", "rtmr", "tcb svn", "quote v4", "cvm", "trust domain"] },
  { dim: 14, weight: 2.8, terms: ["8x", "8x gpu", "b200", "h200", "h100", "blackwell", "hopper", "nvidia cc", "confidential computing", "gpu tee", "hbm3e"] },
  { dim: 15, weight: 2.6, terms: ["nvlink", "pcie", "bounce buffer", "local verifier", "rim", "gpu attestation", "spdm"] },
  { dim: 16, weight: 2.6, terms: ["hpke", "rfc 9180", "ehbp", "encrypted http body", "client-to-enclave", "e2ee", "end-to-end encrypted"] },
  { dim: 17, weight: 2.5, terms: ["ml-kem-768", "pqc", "post-quantum", "x25519", "hybrid kem", "quantum resistant"] },
  { dim: 18, weight: 2.6, terms: ["sigstore", "rekor", "transparency log", "inclusion proof", "reproducible build", "5-of-7 quorum", "manifest"] },
  { dim: 19, weight: 2.4, terms: ["dm-verity", "rootfs", "initramfs", "container measurement", "firecracker", "microvm", "sandbox"] },
  { dim: 20, weight: 2.5, terms: ["two-hop", "2-hop", "router enclave", "worker enclave", "mutual tls", "attested tls"] },
  { dim: 21, weight: 2.4, terms: ["gateway-tee-only", "terminated tls", "proxy termination", "plaintext gateway"] },
  { dim: 22, weight: 3.2, terms: ["kimi k3", "kimi k2.5", "kimi", "moonshot", "2.8t moe", "2.8t"] },
  { dim: 23, weight: 3.0, terms: ["glm-5.3", "glm-5", "glm", "zhipu"] },
  { dim: 24, weight: 3.0, terms: ["deepseek", "deepseek v4.1", "deepseek r1", "deepseek v3", "671b"] },
  { dim: 25, weight: 2.6, terms: ["qwen", "qwen 3.5", "qwen 3", "235b", "72b"] },
  { dim: 26, weight: 2.5, terms: ["llama 3.3", "llama", "70b", "meta llama"] },
  { dim: 27, weight: 2.6, terms: ["gemma 4", "gemma 3", "gemma", "31b", "27b"] },
  { dim: 28, weight: 2.6, terms: ["gpt-oss", "120b", "nemotron", "253b", "mistral large"] },
  { dim: 29, weight: 2.2, terms: ["frontier model", "inference", "llm", "token streaming", "autoregressive"] },
  { dim: 30, weight: 3.2, terms: ["tinfoil", "tinfoil.sh", "live-integrated", "primary provider", "17 models"] },
  { dim: 31, weight: 3.0, terms: ["phala", "redpill", "phala cloud", "openrouter confidential", "aci receipt"] },
  { dim: 32, weight: 3.0, terms: ["near ai", "near cloud", "cloud.near.ai", "13 frontier models"] },
  { dim: 33, weight: 3.0, terms: ["venice", "venice.ai", "venice e2ee", "browser encryption"] },
  { dim: 34, weight: 3.0, terms: ["prem ai", "premai", "sovereign tdx", "caller nonce"] },
  { dim: 35, weight: 3.0, terms: ["ppq.ai", "ppq", "pay-per-query", "lightning", "anonymous settlement"] },
  { dim: 36, weight: 3.0, terms: ["confidential ai", "confidential.ai", "c8s", "sha-384 transcript"] },
  { dim: 37, weight: 3.0, terms: ["chutes", "bittensor", "miner node", "spot pricing", "subnet"] },
  { dim: 38, weight: 3.0, terms: ["privatemode", "cosmian", "contrast", "eu-hosted", "kubernetes coordinator"] },
  { dim: 39, weight: 3.0, terms: ["nanogpt", "nano-gpt", "ecdsa response signature", "24 models"] },
  { dim: 40, weight: 2.7, terms: ["circle arc", "arc blockchain", "on-chain attestation", "usdc", "settlement contract", "anchor"] },
  { dim: 41, weight: 2.7, terms: ["rsa blind", "blind signature", "credit nullifier", "nullifier", "anonymous credit", "double-spend"] },
  { dim: 42, weight: 2.7, terms: ["shamir", "threshold", "3-of-5", "secret sharing", "key share", "lagrange"] },
  { dim: 43, weight: 2.7, terms: ["k_freeze", "frozen blob", "session freeze", "state migration", "failover", "webcrypto"] },
  { dim: 44, weight: 2.6, terms: ["ohttp", "rfc 9458", "oblivious http", "metadata privacy", "ip stripping", "relay"] },
  { dim: 45, weight: 2.5, terms: ["chaff", "decoy traffic", "packet padding", "traffic analysis", "timing correlation"] },
  { dim: 46, weight: 2.5, terms: ["canary trap", "honeypot", "bounty", "slashing", "stake", "operator cap"] },
  { dim: 47, weight: 2.5, terms: ["sprt", "wald sequential", "latency audit", "statistical auditor", "ashi"] },
  { dim: 48, weight: 2.5, terms: ["stylometry", "author anonymization", "pii scrubber", "compartment splitter"] },
  { dim: 49, weight: 2.5, terms: ["mongodb atlas", "vector search", "hybrid search", "reciprocal rank fusion", "rrf", "stream processing"] },
  { dim: 50, weight: 2.5, terms: ["voyage ai", "voyage-3", "nomic-embed-text", "automated embedding", "cosine similarity", "128-dim"] },
  { dim: 51, weight: 2.4, terms: ["tier a", "tier a+", "tier b", "hardware tier", "security tier"] },
  { dim: 52, weight: 2.4, terms: ["ecdsa", "p-384", "secp256k1", "signature verification", "receipt hash"] },
  { dim: 53, weight: 2.4, terms: ["kv-cache", "kv cache", "attention cache", "context window", "prefix block"] },
  { dim: 54, weight: 2.3, terms: ["enclave", "tee", "trusted execution environment", "confidential enclave", "hardware isolation"] },
  { dim: 55, weight: 2.3, terms: ["attestation", "quote", "evidence", "verification", "remote attestation", "measurement"] },
  { dim: 56, weight: 2.2, terms: ["architecture", "specification", "protocol", "design", "subsystem"] },
  { dim: 57, weight: 2.2, terms: ["provider", "catalog", "marketplace", "endpoint", "pricing"] },
  { dim: 58, weight: 2.3, terms: ["encryption", "cipher", "authenticated encryption", "aead", "key derivation", "hkdf"] },
  { dim: 59, weight: 2.3, terms: ["memory protection", "dram encryption", "bus encryption", "physical attacker", "interposer defense"] },
  { dim: 60, weight: 2.3, terms: ["zero knowledge", "halo2", "plonky3", "fhe", "mpc", "3pc", "speculative split"] },
  { dim: 61, weight: 2.2, terms: ["open weights", "closed weights", "merkle shard", "weight release", "model custody"] },
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

function embedDocumentText(text) {
  const normalized = (text || "").toLowerCase().trim();
  const raw = new Array(EMBEDDING_DIMENSIONS).fill(0);

  for (const cluster of SEMANTIC_CONCEPT_CLUSTERS) {
    let matches = 0;
    for (const term of cluster.terms) {
      if (normalized.includes(term)) matches += 1;
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

  const tokens = normalized
    .replace(/[^a-z0-9.+_-]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2);

  for (const token of tokens) {
    const h1 = fnv1a32(token, 0x811c9dc5);
    const dim1 = 64 + (h1 % 64);
    const sign1 = (h1 & 0x100) === 0 ? 1 : -1;
    raw[dim1] += sign1 * 0.45;

    const padded = `^${token}$`;
    for (let i = 0; i <= padded.length - 3; i++) {
      const trigram = padded.slice(i, i + 3);
      const h2 = fnv1a32(trigram, 0x9e3779b9);
      const dim2 = 64 + (h2 % 64);
      const sign2 = (h2 & 0x200) === 0 ? 1 : -1;
      raw[dim2] += sign2 * 0.12;
    }
  }

  let sumSq = 0;
  for (let i = 0; i < EMBEDDING_DIMENSIONS; i++) sumSq += raw[i] * raw[i];
  const norm = sumSq > 1e-12 ? Math.sqrt(sumSq) : 1;
  const vector = raw.map((v, idx) => (sumSq > 1e-12 ? v / norm : idx === 0 ? 1 : 0));

  return {
    vector,
    model: "local-hashed-128 (stand-in)",
    dimensions: EMBEDDING_DIMENSIONS,
  };
}

const RAW_SEED_DOCS = [
  {
    docId: "provider-tinfoil",
    title: "Tinfoil - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + 8x NVIDIA B200 / H200 / H100 CC)",
    category: "provider",
    summary:
      "Tinfoil (live-integrated) runs confidential inference on AMD SEV-SNP (router-0.tinfoil.sh) + Intel TDX and 8x NVIDIA Confidential Computing GPUs (kimi-k3-inf14.tinfoil.containers.tinfoil.dev, max-model-len 262,144 tokens) with HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS. Frontier models: Kimi K3 (2.8T MoE), GLM-5.3, DeepSeek V4.1 Flash, GPT-OSS 120B, Llama 3.3 70B, Gemma 4 31B, Qwen 3.5 72B. Attestation verdict: Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix. Pricing: $0.02+/M. Live primary provider in dRouter.",
    tags: ["tinfoil", "live-integrated", "amd sev-snp", "intel tdx", "8x nvidia b200 / h200 / h100 cc", "pqc-hybrid-ml-kem-768", "kimi k3 (2.8t moe)", "glm-5.3", "deepseek v4.1 flash", "gpt-oss 120b", "llama 3.3 70b", "gemma 4 31b", "qwen 3.5 72b"],
    metadata: { providerId: "tinfoil", statusInDrouter: "live-integrated", cpuTee: "AMD SEV-SNP + Intel TDX", gpuTee: "8x NVIDIA B200 / H200 / H100 CC", pqcHybrid: true },
  },
  {
    docId: "provider-phala-redpill",
    title: "Phala Cloud / Redpill - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    summary:
      "Phala Cloud / Redpill (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: DeepSeek V3, DeepSeek R1, Qwen 3 235B, Llama 3.3 70B, Gemma 3 27B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Pricing: $0.04+/M. Backs OpenRouter's enterprise confidential tier via Redpill and Phala Cloud CVM workers.",
    tags: ["phala-redpill", "phala cloud / redpill", "compatible-openai-e2ee", "intel tdx", "nvidia h100 / h200 cc", "pqc-hybrid-ml-kem-768", "deepseek v3", "deepseek r1", "qwen 3 235b", "llama 3.3 70b", "gemma 3 27b"],
    metadata: { providerId: "phala-redpill", statusInDrouter: "compatible-openai-e2ee", cpuTee: "Intel TDX", gpuTee: "NVIDIA H100 / H200 CC", pqcHybrid: true },
  },
  {
    docId: "provider-near-ai-cloud",
    title: "NEAR AI Cloud - Confidential Inference Enclave (Intel TDX + NVIDIA H200 CC)",
    category: "provider",
    summary:
      "NEAR AI Cloud (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H200 CC with Attested E2EE. Frontier models: DeepSeek R1, DeepSeek V3, Moonshot Kimi K2.5, GLM-5, Qwen 3, GPT-OSS 120B, Llama 3.3 70B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Pricing: $0.01+/M.",
    tags: ["near-ai-cloud", "near ai cloud", "compatible-openai-e2ee", "intel tdx", "nvidia h200 cc", "classical-ecdh", "deepseek r1", "deepseek v3", "moonshot kimi k2.5", "glm-5", "qwen 3", "gpt-oss 120b", "llama 3.3 70b"],
    metadata: { providerId: "near-ai-cloud", statusInDrouter: "compatible-openai-e2ee", cpuTee: "Intel TDX", gpuTee: "NVIDIA H200 CC", pqcHybrid: false },
  },
  {
    docId: "provider-venice-ai",
    title: "Venice.ai (E2EE Mode) - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    summary:
      "Venice.ai (E2EE Mode) (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Moonshot Kimi K2.5, GLM-5, DeepSeek R1 671B, Qwen 3 235B, Gemma 3 27B, Llama 3.3 70B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Pricing: $0.05+/M.",
    tags: ["venice-ai", "venice.ai (e2ee mode)", "compatible-openai-e2ee", "intel tdx", "nvidia h100 / h200 cc", "classical-ecdh", "moonshot kimi k2.5", "glm-5", "deepseek r1 671b", "qwen 3 235b", "gemma 3 27b", "llama 3.3 70b"],
    metadata: { providerId: "venice-ai", statusInDrouter: "compatible-openai-e2ee", cpuTee: "Intel TDX", gpuTee: "NVIDIA H100 / H200 CC", pqcHybrid: false },
  },
  {
    docId: "provider-prem-ai",
    title: "Prem AI - Confidential Inference Enclave (Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    summary:
      "Prem AI (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 CC with Attested E2EE. Frontier models: DeepSeek R1, Qwen 3 72B, NVIDIA Nemotron Ultra 253B, Llama 3.3 70B, Mistral Large 2. Attestation verdict: Per-Workload TDX Transcript Binding. Pricing: $0.30+/M.",
    tags: ["prem-ai", "prem ai", "compatible-openai-e2ee", "intel tdx", "nvidia h100 cc", "classical-ecdh", "deepseek r1", "qwen 3 72b", "nvidia nemotron ultra 253b", "llama 3.3 70b", "mistral large 2"],
    metadata: { providerId: "prem-ai", statusInDrouter: "compatible-openai-e2ee", cpuTee: "Intel TDX", gpuTee: "NVIDIA H100 CC", pqcHybrid: false },
  },
  {
    docId: "provider-ppq-ai",
    title: "PPQ.AI - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    summary:
      "PPQ.AI (compatible-openai-e2ee) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Moonshot Kimi K3, DeepSeek V4.1, GLM-5.3, Llama 3.3 70B, Qwen 3 72B, Gemma 4 31B. Attestation verdict: Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix. Pricing: $0.16+/M.",
    tags: ["ppq-ai", "ppq.ai", "compatible-openai-e2ee", "amd sev-snp + intel tdx", "nvidia h100 / h200 cc", "pqc-hybrid-ml-kem-768", "moonshot kimi k3", "deepseek v4.1", "glm-5.3", "llama 3.3 70b", "qwen 3 72b", "gemma 4 31b"],
    metadata: { providerId: "ppq-ai", statusInDrouter: "compatible-openai-e2ee", cpuTee: "AMD SEV-SNP + Intel TDX", gpuTee: "NVIDIA H100 / H200 CC", pqcHybrid: true },
  },
  {
    docId: "provider-confidential-ai",
    title: "Confidential AI - Confidential Inference Enclave (Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    summary:
      "Confidential AI (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 CC with Attested E2EE. Frontier models: DeepSeek R1 671B, DeepSeek V3, Llama 3.3 70B. Attestation verdict: Per-Workload TDX Transcript Binding. Pricing: $0.12+/M.",
    tags: ["confidential-ai", "confidential ai", "compatible-openai-e2ee", "intel tdx", "nvidia h100 cc", "pqc-hybrid-ml-kem-768", "deepseek r1 671b", "deepseek v3", "llama 3.3 70b"],
    metadata: { providerId: "confidential-ai", statusInDrouter: "compatible-openai-e2ee", cpuTee: "Intel TDX", gpuTee: "NVIDIA H100 CC", pqcHybrid: true },
  },
  {
    docId: "provider-chutes-bittensor",
    title: "Chutes (Bittensor TEE) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    summary:
      "Chutes (Bittensor TEE) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 / H200 CC (Miner Dependent) with TEE-Terminated TLS. Frontier models: DeepSeek R1, DeepSeek V3, Moonshot Kimi K2.5, GLM-5, Qwen 3 235B, Mistral Large 2, Llama 3.3 70B. Attestation verdict: Gateway Attestation Only. Pricing: $0.02+/M.",
    tags: ["chutes-bittensor", "chutes (bittensor tee)", "gateway-tee-only", "amd sev-snp + intel tdx", "nvidia h100 / h200 cc (miner dependent)", "classical-ecdh", "deepseek r1", "deepseek v3", "moonshot kimi k2.5", "glm-5", "qwen 3 235b", "mistral large 2", "llama 3.3 70b"],
    metadata: { providerId: "chutes-bittensor", statusInDrouter: "gateway-tee-only", cpuTee: "AMD SEV-SNP + Intel TDX", gpuTee: "NVIDIA H100 / H200 CC (Miner Dependent)", pqcHybrid: false },
  },
  {
    docId: "provider-privatemode-cosmian",
    title: "Privatemode (Cosmian / Contrast) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    summary:
      "Privatemode (Cosmian / Contrast) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 CC with TEE-Terminated TLS. Frontier models: DeepSeek R1, GLM-5, GPT-OSS 120B, Qwen 3 72B, Mistral Large 2, Llama 3.3 70B, Gemma 3 27B. Attestation verdict: Gateway Attestation Only. Pricing: $0.15+/M.",
    tags: ["privatemode-cosmian", "privatemode (cosmian / contrast)", "gateway-tee-only", "amd sev-snp + intel tdx", "nvidia h100 cc", "classical-ecdh", "deepseek r1", "glm-5", "gpt-oss 120b", "qwen 3 72b", "mistral large 2", "llama 3.3 70b", "gemma 3 27b"],
    metadata: { providerId: "privatemode-cosmian", statusInDrouter: "gateway-tee-only", cpuTee: "AMD SEV-SNP + Intel TDX", gpuTee: "NVIDIA H100 CC", pqcHybrid: false },
  },
  {
    docId: "provider-nanogpt",
    title: "NanoGPT - Confidential Inference Enclave (Host CPU + NVIDIA CC Driver + NVIDIA H100 CC)",
    category: "provider",
    summary:
      "NanoGPT (gateway-tee-only) runs confidential inference on Host CPU + NVIDIA CC Driver and NVIDIA H100 CC with TEE-Only Gateway. Frontier models: Qwen 3 235B, DeepSeek R1, Moonshot Kimi K2.5, GLM-5, Llama 3.3 70B. Attestation verdict: Gateway Attestation Only. Pricing: $0.03+/M.",
    tags: ["nanogpt", "gateway-tee-only", "host cpu + nvidia cc driver", "nvidia h100 cc", "classical-ecdh", "qwen 3 235b", "deepseek r1", "moonshot kimi k2.5", "glm-5", "llama 3.3 70b"],
    metadata: { providerId: "nanogpt", statusInDrouter: "gateway-tee-only", cpuTee: "Host CPU + NVIDIA CC Driver", gpuTee: "NVIDIA H100 CC", pqcHybrid: false },
  },
  {
    docId: "advisory-tee-fail-ddr5",
    title: "TEE.fail DDR5 Interposer & Riser Attack Advisory",
    category: "advisory",
    summary:
      "TEE.fail (Georgia Tech / Purdue) demonstrates a passive DDR5 memory bus interposer and riser probe capable of inspecting encrypted CPU DRAM bus traffic at line rate. Static-IV or deterministic physical-address AES-XTS memory encryption exposes repeated 16-byte ciphertext blocks (the Tux-penguin pattern) across identical prompts. dRouter mitigates TEE.fail via Two-Hop GPU Custody monotonic AES-256-GCM counters (zero repeated 16-byte blocks across turns, Shannon entropy > 7.99 bits/byte), SPDM 1.2 / PCIe TDISP link binding, and riser-proof BGA/soldered CPU allowlists.",
    tags: ["tee.fail", "ddr5", "memory bus", "interposer", "riser probe", "tux-penguin", "aes-xts", "aes-256-gcm", "monotonic nonce", "tier-a-plus"],
    metadata: { advisoryId: "DROUTER-ADV-2026-001", severity: "CRITICAL", attackClass: "Passive DDR5 Memory Bus Interposer Probe" },
  },
  {
    docId: "advisory-ddrop",
    title: "DDRop Active DDR5 Memory Bus Fault & Replay Advisory",
    category: "advisory",
    summary:
      "DDRop targets confidential virtual machines (AMD SEV-SNP and Intel TDX) by actively splicing and replaying encrypted DDR5 DIMM cache lines on the physical memory bus when cryptographic integrity trees (MKTME / RMP) lack freshness counters. dRouter neutralizes DDRop on offloaded KV-cache and PCIe bounce buffers by binding every 4 KB offload frame to an authenticated AES-256-GCM tag with session-scoped AAD (`sessionId:turn:kv-offload-page`) and a strictly monotonic 32-bit hardware DRBG counter.",
    tags: ["ddrop", "ddr5", "memory bus", "replay attack", "fault injection", "kv-cache offload", "aes-256-gcm", "authenticated encryption"],
    metadata: { advisoryId: "DROUTER-ADV-2026-002", severity: "HIGH", attackClass: "Active DDR5 Bus Replay & Fault Injection" },
  },
  {
    docId: "advisory-cipherleaks",
    title: "Cipherleaks AMD SEV-SNP Ciphertext Side-Channel Advisory",
    category: "advisory",
    summary:
      "Cipherleaks exploits deterministic physical-address memory encryption in AMD SEV-SNP where an untrusted hypervisor monitors ciphertext changes on identical guest physical cache lines during secret-dependent branches or modular arithmetic. dRouter eliminates Cipherleaks exposure by running constant-time @noble cryptographic primitives, confining session keys inside the VMPL0 SVSM inner monitor ring, and keeping decrypted model weights and KV activations inside NVIDIA B200/H200 HBM3e confidential memory rather than host DRAM.",
    tags: ["cipherleaks", "amd sev-snp", "ciphertext side-channel", "cache line", "constant-time", "vmpl0", "hbm3e"],
    metadata: { advisoryId: "DROUTER-ADV-2026-003", severity: "HIGH", attackClass: "Hypervisor Ciphertext Observation Side-Channel" },
  },
  {
    docId: "advisory-voltpillager",
    title: "VoltPillager SVI2 Hardware Voltage Glitching Advisory",
    category: "advisory",
    summary:
      "VoltPillager uses a physical PMBus/SVI2 interposer on the server motherboard voltage regulator to inject sub-microsecond undervolting faults into the AMD Secure Processor (ASP/PSP) during attestation quote signing or key derivation. Because physical voltage glitching can compromise a single rogue operator's socket, dRouter enforces a 5-of-7 independent transparency verifier quorum, 3-of-5 Shamir threshold key custody, 3% cryptographic canary traps, and slashable Circle Arc USDC operator stakes ($50,000+ leak deterrence).",
    tags: ["voltpillager", "voltage glitching", "svi2", "pmbus", "hardware fault", "amd psp", "canary trap", "circle arc", "shamir threshold"],
    metadata: { advisoryId: "DROUTER-ADV-2026-004", severity: "HIGH", attackClass: "Physical SVI2 Voltage Fault Injection" },
  },
  {
    docId: "arch-vmpl0-inner-monitor",
    title: "VMPL0 Inner Monitor & Egress Policy Engine (Spec §2.2)",
    category: "architecture",
    summary:
      "The dRouter VMPL0 Inner Monitor executes inside AMD SEV-SNP Virtual Machine Privilege Level 0 (SVSM ring), isolated from the VMPL1/VMPL2 Linux guest OS and inference runtime. Every outbound token stream and tool call must pass through the VMPL0 egress ring, which enforces fixed-size packet framing, runs deterministic regex + Shannon entropy secret scrubbing, blocks unattested network sockets, and signs the turn receipt only after verifying zero policy violations.",
    tags: ["vmpl0", "svsm", "inner monitor", "amd sev-snp", "egress policy", "secret scrubber", "zero-retention", "architecture"],
    metadata: { specSection: "§2.2", privilegeRing: "AMD SEV-SNP VMPL0 (SVSM)" },
  },
  {
    docId: "arch-two-hop-gpu-custody",
    title: "Two-Hop GPU Custody & Deterministic pop() Zeroization (Spec §2.3-2.4)",
    category: "architecture",
    summary:
      "dRouter's Two-Hop GPU Custody architecture pairs an AMD SEV-SNP ingress router enclave (Hop 1) with an 8x NVIDIA B200/H200/H100 Confidential Computing worker enclave (Hop 2) over attested mutual TLS and RFC 9180 HPKE Encrypted HTTP Body (EHBP). Inside Hop 2, `CustodyCtrDrbg` derives isolated per-session keys (`sessionTrafficKey`, `sessionOffloadKey`, `sessionPrefixKey`), partitions the 512-token prefix cache via HMAC-SHA256 so cross-session cache hits are mathematically zero, and executes `pop()` on session close to cryptographically zeroize all HBM staging pages and DRBG state.",
    tags: ["two-hop gpu custody", "custodyctrdrbg", "pop()", "zeroization", "crypto-shredding", "prefix cache", "8x gpu", "b200", "h200", "hpke", "rfc 9180", "architecture"],
    metadata: { specSection: "§2.3-2.4", hop1: "AMD SEV-SNP Ingress Router Enclave", hop2: "8x NVIDIA B200/H200 CC Worker Enclave" },
  },
];

async function main() {
  const uri = loadMongoUri();
  if (!uri) {
    console.log("[atlas-indexes] No MONGODB_URI found in environment or .env.local; skipping live cluster sync.");
    return;
  }

  const client = new MongoClient(uri, {
    appName: "drouter-atlas-indexer",
    serverSelectionTimeoutMS: 8000,
  });

  try {
    await client.connect();
    const dbName = process.env.MONGODB_DB || "drouter";
    const db = client.db(dbName);
    const col = db.collection(COLLECTION_NAME);

    // 1. Embed and upsert all 16 seed documents
    const embeddedDocs = RAW_SEED_DOCS.map((doc) => {
      const composite = [
        doc.title,
        doc.category,
        doc.summary,
        doc.tags.join(" "),
        JSON.stringify(doc.metadata),
      ].join(" ");
      const emb = embedDocumentText(composite);
      return {
        ...doc,
        embedding: emb.vector,
        embeddingModel: emb.model,
        embeddingDimensions: emb.dimensions,
        updatedAt: new Date().toISOString(),
      };
    });

    await col.createIndex({ docId: 1 }, { unique: true });
    await col.createIndex({ category: 1 });

    const receiptsCol = db.collection("agent_verification_receipts");
    await receiptsCol.createIndex({ receiptId: 1 }, { unique: true });
    await receiptsCol.createIndex({ coarsenedAt: -1 });

    const bulkOps = embeddedDocs.map((doc) => ({
      updateOne: {
        filter: { docId: doc.docId },
        update: { $set: doc },
        upsert: true,
      },
    }));
    const bulkResult = await col.bulkWrite(bulkOps, { ordered: false });
    const totalCount = await col.countDocuments();

    console.log(
      `[atlas-indexes] Seeded ${embeddedDocs.length} embedded docs (128-d unit vectors) into ${dbName}.${COLLECTION_NAME} (upserted: ${bulkResult.upsertedCount}, modified: ${bulkResult.modifiedCount}, total in collection: ${totalCount}).`
    );

    // 2. Ensure Atlas Search full-text index (`drouter_text_search`)
    try {
      const textIdx = await col.createSearchIndex({
        name: TEXT_INDEX_NAME,
        type: "search",
        definition: {
          mappings: {
            dynamic: true,
            fields: {
              title: { type: "string", analyzer: "lucene.standard" },
              summary: { type: "string", analyzer: "lucene.standard" },
              category: { type: "string", analyzer: "lucene.keyword" },
              tags: { type: "string", analyzer: "lucene.standard" },
            },
          },
        },
      });
      console.log(`[atlas-indexes] Created Atlas Search index: ${textIdx}`);
    } catch (err) {
      console.log(`[atlas-indexes] Atlas Search index (${TEXT_INDEX_NAME}) status: ${err.message || "already exists"}`);
    }

    // 3. Ensure Atlas Vector Search index (`drouter_vector_index`, 128 dims, cosine)
    try {
      const vecIdx = await col.createSearchIndex({
        name: VECTOR_INDEX_NAME,
        type: "vectorSearch",
        definition: {
          fields: [
            {
              type: "vector",
              path: "embedding",
              numDimensions: EMBEDDING_DIMENSIONS,
              similarity: "cosine",
            },
            {
              type: "filter",
              path: "category",
            },
          ],
        },
      });
      console.log(`[atlas-indexes] Created Atlas Vector Search index: ${vecIdx}`);
    } catch (err) {
      console.log(`[atlas-indexes] Atlas Vector Search index (${VECTOR_INDEX_NAME}) status: ${err.message || "already exists"}`);
    }

    // 4. List live search indexes
    const indexes = await col.listSearchIndexes().toArray().catch(() => []);
    console.log(
      `[atlas-indexes] Live search indexes (${indexes.length}):`,
      indexes.map((i) => ({ name: i.name, type: i.type, status: i.status }))
    );
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error("[atlas-indexes] Error:", err.message || err);
  process.exitCode = 1;
});
