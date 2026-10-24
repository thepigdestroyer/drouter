#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MongoClient } from "mongodb";
import { TinfoilAI } from "tinfoil";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENV_PATH = join(ROOT, ".env.local");
const EMBEDDING_DIMENSIONS = 768;
const TINFOIL_EMBEDDING_MODEL_ID = "nomic-embed-text";
const TINFOIL_ATTESTED_EMBEDDING_MODEL = "nomic-embed-text (Tinfoil attested enclave)";
const LOCAL_STANDIN_EMBEDDING_MODEL = "local-hashed-768 (fallback: Tinfoil unreachable)";
const CORPUS_RETRIEVED_AT_UTC = "2026-10-24";
const COLLECTION_NAME = "enclave_intelligence";
const RECEIPTS_COLLECTION_NAME = "agent_verification_receipts";
const TEXT_INDEX_NAME = "drouter_text_search";
const VECTOR_INDEX_NAME = "drouter_vector_index";

function loadEnvVar(key) {
  if (process.env[key] && process.env[key].trim()) return process.env[key].trim();
  if (!existsSync(ENV_PATH)) return null;
  const text = readFileSync(ENV_PATH, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith(`${key}=`)) {
      let val = line.slice(`${key}=`.length).trim();
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      ) {
        val = val.slice(1, -1);
      }
      if (val) return val;
    }
  }
  return null;
}

function coarsenIsoToUtcHour(input) {
  const dt = input instanceof Date ? input : input ? new Date(input) : new Date();
  const ms = Number.isFinite(dt.getTime()) ? dt.getTime() : Date.now();
  return new Date(ms - (ms % 3_600_000)).toISOString();
}

function normalizeVectorL2(vec) {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i++) sumSq += vec[i] * vec[i];
  if (sumSq <= 1e-12) {
    const out = new Array(vec.length).fill(0);
    if (out.length > 0) out[0] = 1;
    return out;
  }
  const invNorm = 1 / Math.sqrt(sumSq);
  return vec.map((v) => Number((v * invNorm).toFixed(8)));
}

function fnv1a32(str, seed = 0x811c9dc5) {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function embedFallback768(text) {
  const normalized = (text || "").toLowerCase().trim();
  const raw = new Array(EMBEDDING_DIMENSIONS).fill(0);
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
  };
}

async function embedTextsBatch(texts) {
  const apiKey = loadEnvVar("TINFOIL_API_KEY");
  if (apiKey) {
    try {
      const client = new TinfoilAI({ apiKey });
      await client.ready();
      const doc = await client.getVerificationDocument();
      if (!doc.securityVerified) {
        throw new Error("Tinfoil enclave attestation verification did not pass");
      }
      const res = await client.embeddings.create({
        model: TINFOIL_EMBEDDING_MODEL_ID,
        input: texts,
      });
      if (Array.isArray(res.data) && res.data.length === texts.length) {
        console.log(
          `[atlas-indexes] Embedded ${texts.length} texts in 1 batched request via Tinfoil attested enclave (${doc.enclaveHost}, model=${res.model || TINFOIL_EMBEDDING_MODEL_ID}, dims=${res.data[0]?.embedding?.length}).`,
        );
        return res.data.map((item) => ({
          vector: normalizeVectorL2(item.embedding),
          model: TINFOIL_ATTESTED_EMBEDDING_MODEL,
          dimensions: EMBEDDING_DIMENSIONS,
        }));
      }
    } catch (err) {
      console.warn(
        `[atlas-indexes] Tinfoil attested embedding unreachable (${err.message || err}); using labelled 768-d fallback.`,
      );
    }
  }
  return texts.map((t) => embedFallback768(t));
}

const RAW_SEED_DOCS = [
  {
    docId: "provider-tinfoil",
    title:
      "Tinfoil - Confidential Inference Enclave (AMD SEV-SNP (router) + Intel TDX (model enclave) + 8x NVIDIA H100 / H200 / B200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/tinfoil",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Tinfoil (live-integrated) runs confidential inference on AMD SEV-SNP (router) + Intel TDX (model enclave) and 8x NVIDIA H100 / H200 / B200 CC with HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS. Frontier models: Kimi K3 (256K ctx), GLM-5.3, DeepSeek V4.1 Flash, GPT-OSS 120B, Llama 3.3 70B, Gemma 4 31B, Voxtral Small 24B. Attestation verdict: Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix. Verification summary: Verified router quote (AMD SEV-SNP) + Intel TDX and NVIDIA CC model enclave quotes; hybrid X25519MLKEM768 TLS observed. Pricing: $0.02+/M. Live primary confidential enclave in dRouter. Router router-0.tinfoil.sh attests with AMD SEV-SNP; the Kimi K3 8x GPU confidential enclave (kimi-k3-inf14.tinfoil.containers.tinfoil.dev) runs on Intel TDX plus NVIDIA confidential-computing GPUs with max-model-len 262,144 tokens. Tinfoil's router also runs a safeguards acceptable-use classifier sidecar (gpt-oss-safeguard-120b with kimi-k3 review) that reports violations to api.tinfoil.sh, plus a usage reporter. Source: https://confidentialinference.net/providers/tinfoil.",
    tags: [
      "tinfoil",
      "live-integrated",
      "amd sev-snp (router) + intel tdx (model enclave)",
      "8x nvidia h100 / h200 / b200 cc",
      "pqc-hybrid-ml-kem-768",
      "kimi k3 (256k ctx)",
      "glm-5.3",
      "deepseek v4.1 flash",
      "gpt-oss 120b",
      "llama 3.3 70b",
      "gemma 4 31b",
      "voxtral small 24b",
    ],
    metadata: {
      providerId: "tinfoil",
      url: "https://tinfoil.sh",
      docsUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
      sourceUrl: "https://confidentialinference.net/providers/tinfoil",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: true,
      verificationSummary:
        "Verified router quote (AMD SEV-SNP) + Intel TDX and NVIDIA CC model enclave quotes; hybrid X25519MLKEM768 TLS observed.",
      statusInDrouter: "live-integrated",
      cpuTee: "AMD SEV-SNP (router) + Intel TDX (model enclave)",
      gpuTee: "8x NVIDIA H100 / H200 / B200 CC",
      channelSecurity: "HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS",
      pqcHybrid: true,
      frontierModels: [
        "Kimi K3 (256K ctx)",
        "GLM-5.3",
        "DeepSeek V4.1 Flash",
        "GPT-OSS 120B",
        "Llama 3.3 70B",
        "Gemma 4 31B",
        "Voxtral Small 24B",
      ],
      inputUsdPerM: "$0.02+/M",
      attestationVerdict: "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix",
    },
  },
  {
    docId: "provider-phala-redpill",
    title:
      "Phala Cloud / Redpill - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/redpill",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Phala Cloud / Redpill (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Qwen 3.8 27B (TEE), Gemma 4 26B A4B (TEE), DeepSeek V3.2 (dstack), GLM-5.3 Flash (dstack). Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Verification summary: Unverified route binding: Intel TDX + H100 CC quotes published, but storefront routing to backend dstack or Chutes workers is marked incomplete. Pricing: $0.15+/M. OpenAI-compatible confidential storefront and router over Phala Cloud dstack CVMs and Chutes workers. Only 2 Redpill catalog models (Qwen 3.8 27B and Gemma 4 26B A4B) expose direct confidential checks on confidentialinference.net (62 non-TEE catalog models excluded). Hybrid X25519MLKEM768 TLS is observed, but per-request backend route binding remains incomplete. Source: https://confidentialinference.net/providers/redpill.",
    tags: [
      "phala-redpill",
      "phala cloud / redpill",
      "compatible-openai-e2ee",
      "intel tdx",
      "nvidia h100 / h200 cc",
      "pqc-hybrid-ml-kem-768",
      "qwen 3.8 27b (tee)",
      "gemma 4 26b a4b (tee)",
      "deepseek v3.2 (dstack)",
      "glm-5.3 flash (dstack)",
    ],
    metadata: {
      providerId: "phala-redpill",
      url: "https://www.redpill.ai",
      docsUrl: "https://docs.phala.com/phala-cloud/attestation/overview",
      sourceUrl: "https://confidentialinference.net/providers/redpill",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified route binding: Intel TDX + H100 CC quotes published, but storefront routing to backend dstack or Chutes workers is marked incomplete.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "Intel TDX",
      gpuTee: "NVIDIA H100 / H200 CC",
      channelSecurity: "Attested E2EE",
      pqcHybrid: true,
      frontierModels: [
        "Qwen 3.8 27B (TEE)",
        "Gemma 4 26B A4B (TEE)",
        "DeepSeek V3.2 (dstack)",
        "GLM-5.3 Flash (dstack)",
      ],
      inputUsdPerM: "$0.15+/M",
      attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    },
  },
  {
    docId: "provider-near-ai-cloud",
    title:
      "NEAR AI Cloud - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/near",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "NEAR AI Cloud (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Kimi K3, Kimi K2.6, DeepSeek V3.2, GLM-5.3, GLM-5.3 Flash, Qwen 3.5 397B A17B, Qwen 3.8 27B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Verification summary: Unverified: 9 models have incomplete route provenance (delegated to Chutes or Phala/dstack) and GLM-5.3 failed verifier policy on confidentialinference.net. Pricing: $0.01+/M. Advertises 13 confidential models on Intel TDX + NVIDIA H100/H200 TEEs with X25519-XChaCha20-Poly1305 E2EE. Independent checks on confidentialinference.net show workloads routed via Chutes and Phala/dstack without cryptographic route binding, 1 explicit policy failure (GLM-5.3), and classical TLS without hybrid post-quantum key exchange. Source: https://confidentialinference.net/providers/near.",
    tags: [
      "near-ai-cloud",
      "near ai cloud",
      "compatible-openai-e2ee",
      "intel tdx",
      "nvidia h100 / h200 cc",
      "classical-ecdh",
      "kimi k3",
      "kimi k2.6",
      "deepseek v3.2",
      "glm-5.3",
      "glm-5.3 flash",
      "qwen 3.5 397b a17b",
      "qwen 3.8 27b",
    ],
    metadata: {
      providerId: "near-ai-cloud",
      url: "https://cloud.near.ai",
      docsUrl: "https://docs.near.ai",
      sourceUrl: "https://confidentialinference.net/providers/near",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified: 9 models have incomplete route provenance (delegated to Chutes or Phala/dstack) and GLM-5.3 failed verifier policy on confidentialinference.net.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "Intel TDX",
      gpuTee: "NVIDIA H100 / H200 CC",
      channelSecurity: "Attested E2EE",
      pqcHybrid: false,
      frontierModels: [
        "Kimi K3",
        "Kimi K2.6",
        "DeepSeek V3.2",
        "GLM-5.3",
        "GLM-5.3 Flash",
        "Qwen 3.5 397B A17B",
        "Qwen 3.8 27B",
      ],
      inputUsdPerM: "$0.01+/M",
      attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    },
  },
  {
    docId: "provider-venice-ai",
    title:
      "Venice.ai (E2EE Mode) - Confidential Inference Enclave (Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/venice",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Venice.ai (E2EE Mode) (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Kimi K3, Kimi K2.6, DeepSeek V4 Flash, GLM-5.3, GPT-OSS 120B, Qwen 3.8 27B, Gemma 4 26B A4B. Attestation verdict: On-Chain Attestation (Intel DCAP + NVIDIA CC). Verification summary: Unverified: 10 models show incomplete source provenance and route binding (Phala/dstack backends), and 2 Kimi endpoints were unreachable. Pricing: $0.05+/M. Offers 12 E2EE models (prefixed e2ee-*) with ECDH client encryption and observed X25519MLKEM768 hybrid TLS, while 128 standard Venice catalog models are non-TEE. Independent checks report incomplete hardware and route provenance across the 10 reachable E2EE models. Source: https://confidentialinference.net/providers/venice.",
    tags: [
      "venice-ai",
      "venice.ai (e2ee mode)",
      "compatible-openai-e2ee",
      "intel tdx",
      "nvidia h100 / h200 cc",
      "pqc-hybrid-ml-kem-768",
      "kimi k3",
      "kimi k2.6",
      "deepseek v4 flash",
      "glm-5.3",
      "gpt-oss 120b",
      "qwen 3.8 27b",
      "gemma 4 26b a4b",
    ],
    metadata: {
      providerId: "venice-ai",
      url: "https://venice.ai",
      docsUrl: "https://docs.venice.ai",
      sourceUrl: "https://confidentialinference.net/providers/venice",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified: 10 models show incomplete source provenance and route binding (Phala/dstack backends), and 2 Kimi endpoints were unreachable.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "Intel TDX",
      gpuTee: "NVIDIA H100 / H200 CC",
      channelSecurity: "Attested E2EE",
      pqcHybrid: true,
      frontierModels: [
        "Kimi K3",
        "Kimi K2.6",
        "DeepSeek V4 Flash",
        "GLM-5.3",
        "GPT-OSS 120B",
        "Qwen 3.8 27B",
        "Gemma 4 26B A4B",
      ],
      inputUsdPerM: "$0.05+/M",
      attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    },
  },
  {
    docId: "provider-prem-ai",
    title:
      "Prem AI - Confidential Inference Enclave (Intel TDX / AMD SEV-SNP + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/prem",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Prem AI (compatible-openai-e2ee) runs confidential inference on Intel TDX / AMD SEV-SNP and NVIDIA H100 CC with Attested E2EE. Frontier models: DeepSeek V4.1 Flash, Nemotron 3 Ultra 550B, Qwen 3.8 27B, Qwen 3.6 27B, DeepGram Nova 3. Attestation verdict: Per-Workload TDX Transcript Binding. Verification summary: Unverified baseline: Intel TDX + GPU EAT quotes use 64-byte nonce freshness, but measurements are compared against an unpinned baseline. Pricing: $0.30+/M. Serves 5 confidential models at gateway.prem.io using XWing post-quantum hybrid key encapsulation + XChaCha20-Poly1305 and client-side Reticle verification. Independent audit notes that reference measurements are compared against an unpinned baseline and 3 of 5 model attestation endpoints had availability issues. Source: https://confidentialinference.net/providers/prem.",
    tags: [
      "prem-ai",
      "prem ai",
      "compatible-openai-e2ee",
      "intel tdx / amd sev-snp",
      "nvidia h100 cc",
      "pqc-hybrid-ml-kem-768",
      "deepseek v4.1 flash",
      "nemotron 3 ultra 550b",
      "qwen 3.8 27b",
      "qwen 3.6 27b",
      "deepgram nova 3",
    ],
    metadata: {
      providerId: "prem-ai",
      url: "https://www.premai.io",
      docsUrl: "https://docs.prem.io",
      sourceUrl: "https://confidentialinference.net/providers/prem",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified baseline: Intel TDX + GPU EAT quotes use 64-byte nonce freshness, but measurements are compared against an unpinned baseline.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "Intel TDX / AMD SEV-SNP",
      gpuTee: "NVIDIA H100 CC",
      channelSecurity: "Attested E2EE",
      pqcHybrid: true,
      frontierModels: [
        "DeepSeek V4.1 Flash",
        "Nemotron 3 Ultra 550B",
        "Qwen 3.8 27B",
        "Qwen 3.6 27B",
        "DeepGram Nova 3",
      ],
      inputUsdPerM: "$0.30+/M",
      attestationVerdict: "Per-Workload TDX Transcript Binding",
    },
  },
  {
    docId: "provider-ppq-ai",
    title:
      "PPQ.AI - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 / H200 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/ppq",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "PPQ.AI (compatible-openai-e2ee) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 / H200 CC with Attested E2EE. Frontier models: Kimi K3, DeepSeek V4.1 Flash, GLM-5.3, GPT-OSS 120B, Llama 3.3 70B, Gemma 4 31B. Attestation verdict: Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix. Verification summary: Partial verification: AMD SEV-SNP hardware, TCB policy, and channel binding pass 6/6, but freshness and Tinfoil backend route binding are incomplete. Pricing: $0.16+/M. Pay-per-query aggregator offering 6 private/* models (387 non-TEE models excluded) backed by an AMD SEV-SNP router and downstream Tinfoil model enclaves with HPKE and hybrid X25519MLKEM768 TLS. Hardware, TCB, and channel binding pass, while per-request freshness and route binding remain incomplete. Source: https://confidentialinference.net/providers/ppq.",
    tags: [
      "ppq-ai",
      "ppq.ai",
      "compatible-openai-e2ee",
      "amd sev-snp + intel tdx",
      "nvidia h100 / h200 cc",
      "pqc-hybrid-ml-kem-768",
      "kimi k3",
      "deepseek v4.1 flash",
      "glm-5.3",
      "gpt-oss 120b",
      "llama 3.3 70b",
      "gemma 4 31b",
    ],
    metadata: {
      providerId: "ppq-ai",
      url: "https://ppq.ai",
      docsUrl: "https://ppq.ai/api-docs",
      sourceUrl: "https://confidentialinference.net/providers/ppq",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Partial verification: AMD SEV-SNP hardware, TCB policy, and channel binding pass 6/6, but freshness and Tinfoil backend route binding are incomplete.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "AMD SEV-SNP + Intel TDX",
      gpuTee: "NVIDIA H100 / H200 CC",
      channelSecurity: "Attested E2EE",
      pqcHybrid: true,
      frontierModels: [
        "Kimi K3",
        "DeepSeek V4.1 Flash",
        "GLM-5.3",
        "GPT-OSS 120B",
        "Llama 3.3 70B",
        "Gemma 4 31B",
      ],
      inputUsdPerM: "$0.16+/M",
      attestationVerdict: "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix",
    },
  },
  {
    docId: "provider-confidential-ai",
    title:
      "Confidential AI - Confidential Inference Enclave (Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/confidentialai",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Confidential AI (compatible-openai-e2ee) runs confidential inference on Intel TDX and NVIDIA H100 CC with TEE-Terminated TLS. Frontier models: DeepSeek V4 Flash, DeepSeek R1 (c8s enterprise), Llama 3.3 70B (c8s enterprise). Attestation verdict: Per-Workload TDX Transcript Binding. Verification summary: Unverified: publishes c8s Intel TDX + H100 CC cluster bundles and hybrid ML-KEM-768 TLS, but per-model evidence gates are incomplete. Pricing: $0.20+/M. Operates the open-source c8s platform on Intel TDX + NVIDIA H100 CC with an ML-KEM-768 + X25519 tunnel terminating inside the TEE. Currently exposes 1 public catalog model (DeepSeek V4 Flash at $0.20/M input) and a cluster-wide c8s attestation bundle whose individual model evidence is marked incomplete. Source: https://confidentialinference.net/providers/confidentialai.",
    tags: [
      "confidential-ai",
      "confidential ai",
      "compatible-openai-e2ee",
      "intel tdx",
      "nvidia h100 cc",
      "pqc-hybrid-ml-kem-768",
      "deepseek v4 flash",
      "deepseek r1 (c8s enterprise)",
      "llama 3.3 70b (c8s enterprise)",
    ],
    metadata: {
      providerId: "confidential-ai",
      url: "https://confidential.ai",
      docsUrl: "https://confidential.ai/docs/inference-api/get-started",
      sourceUrl: "https://confidentialinference.net/providers/confidentialai",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified: publishes c8s Intel TDX + H100 CC cluster bundles and hybrid ML-KEM-768 TLS, but per-model evidence gates are incomplete.",
      statusInDrouter: "compatible-openai-e2ee",
      cpuTee: "Intel TDX",
      gpuTee: "NVIDIA H100 CC",
      channelSecurity: "TEE-Terminated TLS",
      pqcHybrid: true,
      frontierModels: [
        "DeepSeek V4 Flash",
        "DeepSeek R1 (c8s enterprise)",
        "Llama 3.3 70B (c8s enterprise)",
      ],
      inputUsdPerM: "$0.20+/M",
      attestationVerdict: "Per-Workload TDX Transcript Binding",
    },
  },
  {
    docId: "provider-chutes-bittensor",
    title:
      "Chutes (Bittensor TEE) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 / H200 CC (Miner Dependent))",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/chutes",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Chutes (Bittensor TEE) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 / H200 CC (Miner Dependent) with TEE-Only Gateway. Frontier models: Kimi K3, Kimi K2.6, DeepSeek V4 Flash, DeepSeek V3.2, GLM-5.2, Qwen 3.5 397B A17B, Gemma 4 31B Turbo. Attestation verdict: Gateway Attestation Only. Verification summary: Unverified gateway route: 13 of 14 TEE models return Intel TDX / SEV-SNP miner quotes, but workload identity and request routing are not bound. Pricing: $0.02+/M. Decentralized Bittensor marketplace serving 14 -TEE models across community AMD SEV-SNP and Intel TDX miners. While miner hardware quotes are corroborated on 13 models, TLS terminates at the gateway without hybrid PQC or cryptographic proof binding a caller's request to a specific attested miner. Source: https://confidentialinference.net/providers/chutes.",
    tags: [
      "chutes-bittensor",
      "chutes (bittensor tee)",
      "gateway-tee-only",
      "amd sev-snp + intel tdx",
      "nvidia h100 / h200 cc (miner dependent)",
      "classical-ecdh",
      "kimi k3",
      "kimi k2.6",
      "deepseek v4 flash",
      "deepseek v3.2",
      "glm-5.2",
      "qwen 3.5 397b a17b",
      "gemma 4 31b turbo",
    ],
    metadata: {
      providerId: "chutes-bittensor",
      url: "https://chutes.ai",
      docsUrl: "https://chutes.ai/docs",
      sourceUrl: "https://confidentialinference.net/providers/chutes",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Unverified gateway route: 13 of 14 TEE models return Intel TDX / SEV-SNP miner quotes, but workload identity and request routing are not bound.",
      statusInDrouter: "gateway-tee-only",
      cpuTee: "AMD SEV-SNP + Intel TDX",
      gpuTee: "NVIDIA H100 / H200 CC (Miner Dependent)",
      channelSecurity: "TEE-Only Gateway",
      pqcHybrid: false,
      frontierModels: [
        "Kimi K3",
        "Kimi K2.6",
        "DeepSeek V4 Flash",
        "DeepSeek V3.2",
        "GLM-5.2",
        "Qwen 3.5 397B A17B",
        "Gemma 4 31B Turbo",
      ],
      inputUsdPerM: "$0.02+/M",
      attestationVerdict: "Gateway Attestation Only",
    },
  },
  {
    docId: "provider-privatemode-cosmian",
    title:
      "Privatemode (Edgeless / Cosmian) - Confidential Inference Enclave (AMD SEV-SNP + Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/privatemode",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Privatemode (Edgeless / Cosmian) (gateway-tee-only) runs confidential inference on AMD SEV-SNP + Intel TDX and NVIDIA H100 CC with TEE-Only Gateway. Frontier models: GLM-5.3, GLM-5.3 Flash, GPT-OSS 120B, DeepSeek OCR 2, Qwen 3 Embedding 4B, Voxtral Mini 3B, Whisper Large v3. Attestation verdict: Gateway Attestation Only. Verification summary: Partial verification: Hardware, TCB, freshness, channel binding, and workload identity pass 13/13; source provenance and request route are unverified. Pricing: $0.15+/M. EU-hosted confidential service built by Edgeless Systems (Contrast / Cosmian VM) on AMD SEV-SNP and Intel TDX with observed X25519MLKEM768 hybrid TLS across 7 models. Passes hardware, TCB, freshness, channel binding, and workload identity checks, but requires the Privatemode SDK/proxy for end-to-end encryption and lacks public source-provenance binding. Source: https://confidentialinference.net/providers/privatemode.",
    tags: [
      "privatemode-cosmian",
      "privatemode (edgeless / cosmian)",
      "gateway-tee-only",
      "amd sev-snp + intel tdx",
      "nvidia h100 cc",
      "pqc-hybrid-ml-kem-768",
      "glm-5.3",
      "glm-5.3 flash",
      "gpt-oss 120b",
      "deepseek ocr 2",
      "qwen 3 embedding 4b",
      "voxtral mini 3b",
      "whisper large v3",
    ],
    metadata: {
      providerId: "privatemode-cosmian",
      url: "https://privatemode.ai",
      docsUrl: "https://docs.privatemode.ai/security/attestation/overview",
      sourceUrl: "https://confidentialinference.net/providers/privatemode",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Partial verification: Hardware, TCB, freshness, channel binding, and workload identity pass 13/13; source provenance and request route are unverified.",
      statusInDrouter: "gateway-tee-only",
      cpuTee: "AMD SEV-SNP + Intel TDX",
      gpuTee: "NVIDIA H100 CC",
      channelSecurity: "TEE-Only Gateway",
      pqcHybrid: true,
      frontierModels: [
        "GLM-5.3",
        "GLM-5.3 Flash",
        "GPT-OSS 120B",
        "DeepSeek OCR 2",
        "Qwen 3 Embedding 4B",
        "Voxtral Mini 3B",
        "Whisper Large v3",
      ],
      inputUsdPerM: "$0.15+/M",
      attestationVerdict: "Gateway Attestation Only",
    },
  },
  {
    docId: "provider-nanogpt",
    title:
      "NanoGPT - Confidential Inference Enclave (Intel TDX + NVIDIA H100 CC)",
    category: "provider",
    sourceUrl: "https://confidentialinference.net/providers/nanogpt",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "NanoGPT (gateway-tee-only) runs confidential inference on Intel TDX and NVIDIA H100 CC with TEE-Only Gateway. Frontier models: Kimi K3, Kimi K2.6, DeepSeek V4.1 Flash, DeepSeek V3.2, GLM-5.3, Qwen 3.8 27B, Llama 3.3 70B. Attestation verdict: Gateway Attestation Only. Verification summary: Failed / Unverified: 6 of 24 TEE models failed hardware and TCB policy checks on confidentialinference.net; gateway terminates TLS outside the enclave. Pricing: $0.15+/M. Pay-per-prompt storefront offering 24 TEE-prefixed models (654 non-TEE models excluded) with Intel TDX + H100 CC quotes and per-request ECDSA signatures. Independent testing on confidentialinference.net recorded 6 explicit hardware/TCB failures (including Kimi K3 and Qwen 3.5/3.6), 14 incomplete checks, and gateway-terminated TLS where the NanoGPT proxy sees plaintext. Source: https://confidentialinference.net/providers/nanogpt.",
    tags: [
      "nanogpt",
      "gateway-tee-only",
      "intel tdx",
      "nvidia h100 cc",
      "pqc-hybrid-ml-kem-768",
      "kimi k3",
      "kimi k2.6",
      "deepseek v4.1 flash",
      "deepseek v3.2",
      "glm-5.3",
      "qwen 3.8 27b",
      "llama 3.3 70b",
    ],
    metadata: {
      providerId: "nanogpt",
      url: "https://nano-gpt.com",
      docsUrl: "https://docs.nano-gpt.com/api-reference/tee-verification",
      sourceUrl: "https://confidentialinference.net/providers/nanogpt",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      verified: false,
      verificationSummary:
        "Failed / Unverified: 6 of 24 TEE models failed hardware and TCB policy checks on confidentialinference.net; gateway terminates TLS outside the enclave.",
      statusInDrouter: "gateway-tee-only",
      cpuTee: "Intel TDX",
      gpuTee: "NVIDIA H100 CC",
      channelSecurity: "TEE-Only Gateway",
      pqcHybrid: true,
      frontierModels: [
        "Kimi K3",
        "Kimi K2.6",
        "DeepSeek V4.1 Flash",
        "DeepSeek V3.2",
        "GLM-5.3",
        "Qwen 3.8 27B",
        "Llama 3.3 70B",
      ],
      inputUsdPerM: "$0.15+/M",
      attestationVerdict: "Gateway Attestation Only",
    },
  },
  {
    docId: "advisory-tee-fail-ddr5",
    title: "TEE.fail: Breaking Trusted Execution Environments via DDR5 Memory Bus Interposition",
    category: "advisory",
    sourceUrl: "https://tee.fail/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published by researchers at Georgia Institute of Technology and Purdue University (Chuang, Seto, Berrios, van Schaik, Garman, Genkin), TEE.fail demonstrates a passive DDR5 DRAM bus interposer and riser probe built from off-the-shelf equipment under $1,000. Because Intel TDX, Intel SGX, and AMD SEV-SNP (even with Zen 5 Ciphertext Hiding enabled) use deterministic physical-address memory encryption (AES-XTS and AES-XEX) without per-write freshness, identical 16-byte plaintext blocks at the same physical address produce identical ciphertext blocks (the Tux-penguin pattern). The paper extracts OpenSSL constant-time ECDSA signing keys from AMD SEV-SNP guests, extracts Intel Provisioning Certification Enclave (PCE) keys to forge DCAP UpToDate TDX quotes, and relays borrowed NVIDIA Confidential Computing GPU attestation reports that are not bound to a specific host CPU. Tracked in vendor bulletins INTEL-SA-2025-10-28-001 and AMD-SB-3040.",
    tags: [
      "tee.fail",
      "ddr5",
      "memory bus",
      "interposer",
      "riser probe",
      "tux-penguin",
      "aes-xts",
      "amd-sb-3040",
      "intel-sa-2025-10-28-001",
    ],
    metadata: {
      sourceUrl: "https://tee.fail/",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      vendorBulletins: [
        "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3040.html",
        "https://intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html",
      ],
      authors:
        "Jalen Chuang, Alex Seto, Nicolas Berrios, Stephan van Schaik, Christina Garman, Daniel Genkin (Georgia Tech & Purdue University)",
      attackClass: "Passive DDR5 DRAM Bus Interposer & Deterministic Ciphertext Side-Channel",
      affectedPlatforms: [
        "Intel TDX (4th/5th Gen Xeon Scalable DDR5)",
        "AMD SEV-SNP (EPYC Zen 4 / Zen 5 DDR5)",
        "NVIDIA GPU Confidential Computing (unbound quote relay)",
      ],
    },
  },
  {
    docId: "advisory-ddrop",
    title: "DDRop: Active Memory Interposer Attacks on Confidential VMs by Dropping DDR5 Writes (ACM CCS 2026)",
    category: "advisory",
    sourceUrl: "https://ddropattack.eu/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published at ACM CCS 2026 by researchers from KU Leuven, ETH Zurich, Durham University, and Google (De Meulemeester, Gloor, Jattke, Moghimi, Oswald, Thompson, Razavi, Verbauwhede, Van Bulck), DDRop introduces a $159 active analog-switch DDR5 interposer operating at native DDR5 speed. By injecting a command-bus parity error and suppressing the alert signal, the DIMM silently discards targeted memory writes while the processor believes the write succeeded. Because scalable memory encryption in Intel TDX, Intel Scalable SGX, and AMD SEV-SNP lacks cryptographic freshness trees, stale ciphertext remains valid. On Intel TDX, dropping zero-initialization writes during Secure Extended Page Table allocation (TDH.MEM.SEPT.ADD) lets an attacker remap guest physical pages, toggle the TD debug flag, or overwrite MRTD launch measurements in the TD control structure to forge TDX attestation reports. Tracked under INTEL-SA-2026-08-11-001 and AMD-SB-3048.",
    tags: [
      "ddrop",
      "ddr5",
      "memory bus",
      "replay attack",
      "fault injection",
      "dropped write",
      "sept",
      "intel tdx",
      "amd sev-snp",
      "amd-sb-3048",
    ],
    metadata: {
      sourceUrl: "https://ddropattack.eu/",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      venue: "ACM CCS 2026",
      vendorBulletins: [
        "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3048.html",
        "https://intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2026-08-11-001.html",
      ],
      authors:
        "Jesse De Meulemeester, Stefan Gloor, Patrick Jattke, Daniel Moghimi, David Oswald, Martin Thompson, Kaveh Razavi, Ingrid Verbauwhede, Jo Van Bulck",
      attackClass: "Active DDR5 Bus Write-Drop & Stale Ciphertext Replay",
      affectedPlatforms: [
        "Intel TDX (5th Gen Xeon Scalable)",
        "Intel Scalable SGX",
        "AMD SEV-SNP (EPYC Turin)",
      ],
    },
  },
  {
    docId: "advisory-cipherleaks",
    title: "CIPHERLEAKS & BadRAM: AMD SEV-SNP Ciphertext Side-Channel and Memory Aliasing Advisories (CVE-2020-12966, CVE-2024-21944)",
    category: "advisory",
    sourceUrl: "https://cipherleaks.com/",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "CIPHERLEAKS (USENIX Security 2021, Li et al., CVE-2020-12966 / AMD-SB-1013) demonstrated that deterministic XOR-Encrypt-XOR (AES-XEX) physical-address memory encryption in AMD SEV and SEV-SNP lets an untrusted hypervisor monitor ciphertext transitions in the encrypted VM Save Area (VMSA) to recover constant-time OpenSSL RSA and ECDSA keys. AMD issued firmware mitigations in AMD-SB-1013 and added Zen 5 Ciphertext Hiding. Separately, BadRAM (IEEE S&P 2025, De Meulemeester et al., CVE-2024-21944 / AMD-SB-3015, https://badram.eu/) showed that reprogramming an unlocked DIMM Serial Presence Detect (SPD) chip creates ghost physical address aliases that bypass AMD SEV-SNP Reverse Map Table (RMP) checks and replay attestation measurements; AMD issued boot-time SPD alias validation firmware updates in AMD-SB-3015.",
    tags: [
      "cipherleaks",
      "badram",
      "amd sev-snp",
      "ciphertext side-channel",
      "cve-2020-12966",
      "cve-2024-21944",
      "amd-sb-1013",
      "amd-sb-3015",
      "vmsa",
      "rmp",
    ],
    metadata: {
      sourceUrl: "https://cipherleaks.com/",
      secondarySourceUrl: "https://badram.eu/",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      cves: ["CVE-2020-12966", "CVE-2024-21944"],
      vendorBulletins: ["AMD-SB-1013", "AMD-SB-3015"],
      venues: ["USENIX Security 2021", "IEEE Symposium on Security and Privacy (S&P) 2025"],
      attackClass: "Hypervisor VMSA Ciphertext Side-Channel & SPD Memory Aliasing",
      affectedPlatforms: ["AMD EPYC SEV / SEV-ES / SEV-SNP"],
    },
  },
  {
    docId: "advisory-voltpillager",
    title: "VoltPillager: Hardware-Based SVID Voltage Fault Injection Against TEEs (USENIX Security 2021, CVE-2019-11157)",
    category: "advisory",
    sourceUrl: "https://www.usenix.org/conference/usenixsecurity21/presentation/chen-zitai",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Published at USENIX Security 2021 by University of Birmingham researchers (Chen, Vasilakis, Murdock, Dean, Oswald, Garcia), VoltPillager demonstrates hardware-based voltage glitching against x86 server processors by injecting Serial Voltage Identification (SVID) bus frames between the CPU and the motherboard voltage regulator. Unlike software-only undervolting (Plundervolt, CVE-2019-11157), physical SVID bus injection bypasses microcode undervolting locks on patched processors to corrupt cryptographic calculations and delay memory writes inside enclaves. Because physical voltage fault injection is outside single-host CPU threat models, confidential routing systems combine independent Sigstore Rekor transparency verification, client-side HPKE encryption, and on-chain receipt verification.",
    tags: [
      "voltpillager",
      "voltage glitching",
      "svid",
      "cve-2019-11157",
      "plundervolt",
      "hardware fault",
      "usenix-security-2021",
      "fault injection",
    ],
    metadata: {
      sourceUrl: "https://www.usenix.org/conference/usenixsecurity21/presentation/chen-zitai",
      pdfUrl: "https://www.usenix.org/system/files/sec21-chen-zitai.pdf",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      cves: ["CVE-2019-11157"],
      venue: "30th USENIX Security Symposium (USENIX Security 2021)",
      authors:
        "Zitai Chen, Georgios Vasilakis, Kit Murdock, Edward Dean, David Oswald, Flavio D. Garcia (University of Birmingham)",
      attackClass: "Physical SVID Bus Voltage Glitching & Fault Injection",
      affectedPlatforms: ["Intel SGX / x86 Server Motherboards with Accessible SVID Bus"],
    },
  },
  {
    docId: "arch-vmpl0-inner-monitor",
    title: "Chaumian RSA Blind Signature Credits (RFC 9474 RSABSSA), Client PII Scrubbing & Circle Arc Receipts",
    category: "architecture",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9474.html",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "dRouter decouples credit issuance from inference requests using Chaumian RSA Blind Signatures (RFC 9474 RSABSSA). The browser generates a random credit secret, blinds it with a random factor coprime to the issuer RSA modulus, obtains a blind signature from the credit issuer, and unblinds it locally. When sending an HPKE-encrypted prompt through the relay via the x-drouter-credit header, the relay verifies the RSA signature and records a SHA-256 nullifier in MongoDB Atlas credit_nullifiers to prevent double-spending without linking the token to issuance. Before encryption, client-side PII scrubbing, stylometry normalization, and power-of-two RFC 8259 JSON byte-bucket padding strip identifying metadata, while verification receipts are anchored on the Circle Arc testnet registry (0xbc8085c2b6fe6e0db05f169925c0b841828f4481, chain 5042002) with timestamps coarsened to the UTC hour.",
    tags: [
      "chaumian",
      "rsa blind signature",
      "blind signature",
      "credits",
      "rfc 9474",
      "rsabssa",
      "credit nullifier",
      "nullifier",
      "double-spend",
      "x-drouter-credit",
      "circle arc",
      "pii scrubber",
      "packet padding",
      "architecture",
    ],
    metadata: {
      sourceUrl: "https://www.rfc-editor.org/rfc/rfc9474.html",
      hpkeRfcUrl: "https://www.rfc-editor.org/rfc/rfc9180.html",
      arcExplorerUrl:
        "https://testnet.arcscan.app/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      protocol:
        "RFC 9474 RSABSSA + SHA-256 Nullifier Store + Circle Arc Testnet Registry (Chain 5042002)",
    },
  },
  {
    docId: "arch-two-hop-gpu-custody",
    title: "Tinfoil Chained Two-Hop Enclave Attestation, NVIDIA Confidential Computing & RFC 9180 HPKE (EHBP)",
    category: "architecture",
    sourceUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    summary:
      "Tinfoil chains hardware attestation across two enclave hops and verifies supply-chain provenance via Sigstore Rekor. Hop 1 is the open-source confidential model router (tinfoilsh/confidential-model-router on router-0.tinfoil.sh, AMD SEV-SNP predicate v2), which verifies each Hop 2 model enclave (Intel TDX or AMD SEV-SNP CVM paired with 8x NVIDIA Hopper H100/H200 or Blackwell B200 Confidential Computing GPUs verified at boot via NVIDIA nvattest, plus read-only modelwrap weight volumes checked by Linux kernel dm-verity). Clients verify the hardware certificate chain and Sigstore bundle before encrypting HTTP request and response bodies end-to-end to the enclave's attested HPKE public key via the Encrypted HTTP Body Protocol (EHBP, RFC 9180) so intermediate relays never see plaintext prompts or completions.",
    tags: [
      "two-hop",
      "tinfoil",
      "amd sev-snp",
      "intel tdx",
      "nvidia cc",
      "nvattest",
      "dm-verity",
      "modelwrap",
      "sigstore",
      "rekor",
      "hpke",
      "rfc 9180",
      "ehbp",
      "8x gpu",
      "b200",
      "h200",
      "h100",
      "architecture",
    ],
    metadata: {
      sourceUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
      rfcUrl: "https://www.rfc-editor.org/rfc/rfc9180.html",
      nvidiaCcUrl: "https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/",
      proxyManifestUrl: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      hop1: "tinfoilsh/confidential-model-router (router-0.tinfoil.sh, AMD SEV-SNP)",
      hop2: "Intel TDX / AMD SEV-SNP CVM + 8x NVIDIA H100/H200/B200 Confidential Computing GPUs (nvattest + dm-verity)",
    },
  },
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function ensureVectorIndexAtDimension(col, numDimensions) {
  const vectorDef = {
    fields: [
      {
        type: "vector",
        path: "embedding",
        numDimensions,
        similarity: "cosine",
      },
      {
        type: "filter",
        path: "category",
      },
    ],
  };

  const existing = await col.listSearchIndexes(VECTOR_INDEX_NAME).toArray().catch(() => []);
  if (existing.length > 0) {
    const currentDims = existing[0]?.latestDefinition?.fields?.[0]?.numDimensions;
    if (currentDims === numDimensions && existing[0]?.status === "READY") {
      console.log(
        `[atlas-indexes] Vector Search index (${VECTOR_INDEX_NAME}) already READY at ${numDimensions} dimensions.`,
      );
      return;
    }

    console.log(
      `[atlas-indexes] Recreating/updating ${VECTOR_INDEX_NAME} from ${currentDims} -> ${numDimensions} dimensions...`,
    );
    try {
      await col.updateSearchIndex(VECTOR_INDEX_NAME, vectorDef);
      console.log(`[atlas-indexes] Issued updateSearchIndex(${VECTOR_INDEX_NAME}) to ${numDimensions} dims.`);
    } catch {
      try {
        await col.dropSearchIndex(VECTOR_INDEX_NAME);
        for (let i = 0; i < 30; i++) {
          await sleep(2000);
          const check = await col.listSearchIndexes(VECTOR_INDEX_NAME).toArray().catch(() => []);
          if (check.length === 0) break;
        }
        await col.createSearchIndex({
          name: VECTOR_INDEX_NAME,
          type: "vectorSearch",
          definition: vectorDef,
        });
        console.log(`[atlas-indexes] Recreated ${VECTOR_INDEX_NAME} at ${numDimensions} dims.`);
      } catch (recreateErr) {
        console.warn(`[atlas-indexes] Vector index recreate warning: ${recreateErr.message}`);
      }
    }
  } else {
    const created = await col.createSearchIndex({
      name: VECTOR_INDEX_NAME,
      type: "vectorSearch",
      definition: vectorDef,
    });
    console.log(`[atlas-indexes] Created Atlas Vector Search index: ${created} (${numDimensions} dims).`);
  }
}

async function main() {
  const uri = loadEnvVar("MONGODB_URI");
  if (!uri) {
    console.log(
      "[atlas-indexes] No MONGODB_URI found in environment or .env.local; skipping live cluster sync.",
    );
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
    const receiptsCol = db.collection(RECEIPTS_COLLECTION_NAME);

    // 1. Read any existing receipts so we can batch-embed seed docs + receipts in a single Tinfoil request
    const existingReceipts = await receiptsCol.find({}).toArray().catch(() => []);
    const seedComposites = RAW_SEED_DOCS.map((doc) =>
      [
        doc.title,
        doc.category,
        doc.summary,
        doc.sourceUrl,
        doc.tags.join(" "),
        JSON.stringify(doc.metadata),
      ].join(" "),
    );
    const receiptSummaries = existingReceipts.map(
      (r) => r.summary || `Agent verification receipt ${r.receiptId}`,
    );

    const allTexts = [...seedComposites, ...receiptSummaries];
    const allEmbeddings = await embedTextsBatch(allTexts);

    const coarsenedUpdatedAt = coarsenIsoToUtcHour();
    const embeddedDocs = RAW_SEED_DOCS.map((doc, idx) => {
      const emb = allEmbeddings[idx];
      return {
        ...doc,
        embedding: emb.vector,
        embeddingModel: emb.model,
        embeddingDimensions: emb.dimensions,
        updatedAt: coarsenedUpdatedAt,
      };
    });

    await col.createIndex({ docId: 1 }, { unique: true });
    await col.createIndex({ category: 1 });
    await receiptsCol.createIndex({ receiptId: 1 }, { unique: true });
    await receiptsCol.createIndex({ coarsenedAt: -1 });

    // Remove any legacy docs not in our sourced corpus
    const seedIds = RAW_SEED_DOCS.map((d) => d.docId);
    await col.deleteMany({ docId: { $nin: seedIds } }).catch(() => {});

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
      `[atlas-indexes] Seeded ${embeddedDocs.length} sourced docs (${EMBEDDING_DIMENSIONS}-d vectors, model="${embeddedDocs[0]?.embeddingModel}") into ${dbName}.${COLLECTION_NAME} (upserted: ${bulkResult.upsertedCount}, modified: ${bulkResult.modifiedCount}, total in collection: ${totalCount}).`,
    );

    // Update existing receipts with 768-d embeddings from the same batch
    if (existingReceipts.length > 0) {
      const receiptOps = existingReceipts.map((r, idx) => {
        const emb = allEmbeddings[RAW_SEED_DOCS.length + idx];
        return {
          updateOne: {
            filter: { receiptId: r.receiptId },
            update: {
              $set: {
                embedding: emb.vector,
                embeddingModel: emb.model,
                embeddingDimensions: emb.dimensions,
                coarsenedAt: coarsenIsoToUtcHour(r.coarsenedAt),
              },
            },
          },
        };
      });
      await receiptsCol.bulkWrite(receiptOps, { ordered: false });
      console.log(
        `[atlas-indexes] Updated ${existingReceipts.length} existing receipt(s) in ${dbName}.${RECEIPTS_COLLECTION_NAME} with ${EMBEDDING_DIMENSIONS}-d vectors.`,
      );
    }

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
      console.log(
        `[atlas-indexes] Atlas Search index (${TEXT_INDEX_NAME}) status: ${err.message || "already exists"}`,
      );
    }

    // 3. Ensure Atlas Vector Search index (`drouter_vector_index`, 768 dims, cosine)
    await ensureVectorIndexAtDimension(col, EMBEDDING_DIMENSIONS);

    // 4. Poll until both indexes are READY at 768 dims
    let finalIndexes = [];
    for (let attempt = 0; attempt < 30; attempt++) {
      finalIndexes = await col.listSearchIndexes().toArray().catch(() => []);
      const vecIdx = finalIndexes.find((i) => i.name === VECTOR_INDEX_NAME);
      const txtIdx = finalIndexes.find((i) => i.name === TEXT_INDEX_NAME);
      const vecDims = vecIdx?.latestDefinition?.fields?.[0]?.numDimensions;
      const vecMainDims = vecIdx?.statusDetail?.[0]?.mainIndex?.definition?.fields?.[0]?.numDimensions;
      if (
        txtIdx?.status === "READY" &&
        vecIdx?.status === "READY" &&
        vecDims === EMBEDDING_DIMENSIONS &&
        (vecMainDims === undefined || vecMainDims === EMBEDDING_DIMENSIONS)
      ) {
        break;
      }
      await sleep(2000);
    }

    console.log(
      `[atlas-indexes] Live search indexes (${finalIndexes.length}):`,
      finalIndexes.map((i) => ({
        name: i.name,
        type: i.type,
        status: i.status,
        numDimensions: i.latestDefinition?.fields?.[0]?.numDimensions,
      })),
    );
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error("[atlas-indexes] Error:", err.message || err);
  process.exitCode = 1;
});
