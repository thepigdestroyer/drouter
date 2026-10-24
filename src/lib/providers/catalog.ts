export type DrouterIntegrationStatus =
  | "live-integrated"
  | "compatible-openai-e2ee"
  | "gateway-tee-only";

export type ChannelSecurityKind =
  | "HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS"
  | "Attested E2EE"
  | "TEE-Terminated TLS"
  | "TEE-Only Gateway";

export type AttestationVerdictKind =
  | "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix"
  | "On-Chain Attestation (Intel DCAP + NVIDIA CC)"
  | "Per-Workload TDX Transcript Binding"
  | "Gateway Attestation Only";

export interface ConfidentialProvider {
  id: string;
  name: string;
  url: string;
  docsUrl: string;
  sourceUrl: string;
  verified: boolean;
  verificationSummary: string;
  statusInDrouter: DrouterIntegrationStatus;
  cpuTee: string;
  gpuTee: string;
  channelSecurity: ChannelSecurityKind;
  pqcHybrid: boolean;
  frontierModels: string[];
  inputUsdPerM: string;
  attestationVerdict: AttestationVerdictKind;
  trustNotes: string;
}

export interface ProviderFilterOptions {
  modelQuery?: string;
  requireE2ee?: boolean;
  requirePqc?: boolean;
}

export interface SpecV2RoadmapItem {
  id: string;
  number: string;
  title: string;
  tierTarget: string;
  bottleneckSolved: string;
  mechanism: string;
  verificationArtifact: string;
}

export const CONFIDENTIAL_PROVIDERS: readonly ConfidentialProvider[] = [
  {
    id: "tinfoil",
    name: "Tinfoil",
    url: "https://tinfoil.sh",
    docsUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
    sourceUrl: "https://confidentialinference.net/providers/tinfoil",
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
    trustNotes:
      "Live primary confidential enclave in dRouter. Router router-0.tinfoil.sh attests with AMD SEV-SNP; the Kimi K3 8x GPU confidential enclave (kimi-k3-inf14.tinfoil.containers.tinfoil.dev) runs on Intel TDX plus NVIDIA confidential-computing GPUs with max-model-len 262,144 tokens. Tinfoil's router also runs a safeguards acceptable-use classifier sidecar (gpt-oss-safeguard-120b with kimi-k3 review) that reports violations to api.tinfoil.sh, plus a usage reporter.",
  },
  {
    id: "phala-redpill",
    name: "Phala Cloud / Redpill",
    url: "https://www.redpill.ai",
    docsUrl: "https://docs.phala.com/phala-cloud/attestation/overview",
    sourceUrl: "https://confidentialinference.net/providers/redpill",
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
    trustNotes:
      "OpenAI-compatible confidential storefront and router over Phala Cloud dstack CVMs and Chutes workers. Only 2 Redpill catalog models (Qwen 3.8 27B and Gemma 4 26B A4B) expose direct confidential checks on confidentialinference.net (62 non-TEE catalog models excluded). Hybrid X25519MLKEM768 TLS is observed, but per-request backend route binding remains incomplete.",
  },
  {
    id: "near-ai-cloud",
    name: "NEAR AI Cloud",
    url: "https://cloud.near.ai",
    docsUrl: "https://docs.near.ai",
    sourceUrl: "https://confidentialinference.net/providers/near",
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
    trustNotes:
      "Advertises 13 confidential models on Intel TDX + NVIDIA H100/H200 TEEs with X25519-XChaCha20-Poly1305 E2EE. Independent checks on confidentialinference.net show workloads routed via Chutes and Phala/dstack without cryptographic route binding, 1 explicit policy failure (GLM-5.3), and classical TLS without hybrid post-quantum key exchange.",
  },
  {
    id: "venice-ai",
    name: "Venice.ai (E2EE Mode)",
    url: "https://venice.ai",
    docsUrl: "https://docs.venice.ai",
    sourceUrl: "https://confidentialinference.net/providers/venice",
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
    trustNotes:
      "Offers 12 E2EE models (prefixed e2ee-*) with ECDH client encryption and observed X25519MLKEM768 hybrid TLS, while 128 standard Venice catalog models are non-TEE. Independent checks report incomplete hardware and route provenance across the 10 reachable E2EE models.",
  },
  {
    id: "prem-ai",
    name: "Prem AI",
    url: "https://www.premai.io",
    docsUrl: "https://docs.prem.io",
    sourceUrl: "https://confidentialinference.net/providers/prem",
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
    trustNotes:
      "Serves 5 confidential models at gateway.prem.io using XWing post-quantum hybrid key encapsulation + XChaCha20-Poly1305 and client-side Reticle verification. Independent audit notes that reference measurements are compared against an unpinned baseline and 3 of 5 model attestation endpoints had availability issues.",
  },
  {
    id: "ppq-ai",
    name: "PPQ.AI",
    url: "https://ppq.ai",
    docsUrl: "https://ppq.ai/api-docs",
    sourceUrl: "https://confidentialinference.net/providers/ppq",
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
    trustNotes:
      "Pay-per-query aggregator offering 6 private/* models (387 non-TEE models excluded) backed by an AMD SEV-SNP router and downstream Tinfoil model enclaves with HPKE and hybrid X25519MLKEM768 TLS. Hardware, TCB, and channel binding pass, while per-request freshness and route binding remain incomplete.",
  },
  {
    id: "confidential-ai",
    name: "Confidential AI",
    url: "https://confidential.ai",
    docsUrl: "https://confidential.ai/docs/inference-api/get-started",
    sourceUrl: "https://confidentialinference.net/providers/confidentialai",
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
    trustNotes:
      "Operates the open-source c8s platform on Intel TDX + NVIDIA H100 CC with an ML-KEM-768 + X25519 tunnel terminating inside the TEE. Currently exposes 1 public catalog model (DeepSeek V4 Flash at $0.20/M input) and a cluster-wide c8s attestation bundle whose individual model evidence is marked incomplete.",
  },
  {
    id: "chutes-bittensor",
    name: "Chutes (Bittensor TEE)",
    url: "https://chutes.ai",
    docsUrl: "https://chutes.ai/docs",
    sourceUrl: "https://confidentialinference.net/providers/chutes",
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
    trustNotes:
      "Decentralized Bittensor marketplace serving 14 -TEE models across community AMD SEV-SNP and Intel TDX miners. While miner hardware quotes are corroborated on 13 models, TLS terminates at the gateway without hybrid PQC or cryptographic proof binding a caller's request to a specific attested miner.",
  },
  {
    id: "privatemode-cosmian",
    name: "Privatemode (Edgeless / Cosmian)",
    url: "https://privatemode.ai",
    docsUrl: "https://docs.privatemode.ai/security/attestation/overview",
    sourceUrl: "https://confidentialinference.net/providers/privatemode",
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
    trustNotes:
      "EU-hosted confidential service built by Edgeless Systems (Contrast / Cosmian VM) on AMD SEV-SNP and Intel TDX with observed X25519MLKEM768 hybrid TLS across 7 models. Passes hardware, TCB, freshness, channel binding, and workload identity checks, but requires the Privatemode SDK/proxy for end-to-end encryption and lacks public source-provenance binding.",
  },
  {
    id: "nanogpt",
    name: "NanoGPT",
    url: "https://nano-gpt.com",
    docsUrl: "https://docs.nano-gpt.com/api-reference/tee-verification",
    sourceUrl: "https://confidentialinference.net/providers/nanogpt",
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
    trustNotes:
      "Pay-per-prompt storefront offering 24 TEE-prefixed models (654 non-TEE models excluded) with Intel TDX + H100 CC quotes and per-request ECDSA signatures. Independent testing on confidentialinference.net recorded 6 explicit hardware/TCB failures (including Kimi K3 and Qwen 3.5/3.6), 14 incomplete checks, and gateway-terminated TLS where the NanoGPT proxy sees plaintext.",
  },
] as const;

export function filterProviders(opts?: ProviderFilterOptions): ConfidentialProvider[] {
  if (!opts) {
    return [...CONFIDENTIAL_PROVIDERS];
  }

  const query = opts.modelQuery?.trim().toLowerCase() ?? "";
  const requireE2ee = Boolean(opts.requireE2ee);
  const requirePqc = Boolean(opts.requirePqc);

  return CONFIDENTIAL_PROVIDERS.filter((provider) => {
    if (requireE2ee) {
      const isE2ee =
        provider.statusInDrouter === "live-integrated" ||
        provider.statusInDrouter === "compatible-openai-e2ee";
      if (!isE2ee) {
        return false;
      }
    }

    if (requirePqc && !provider.pqcHybrid) {
      return false;
    }

    if (query.length > 0) {
      const matchesName = provider.name.toLowerCase().includes(query);
      const matchesModel = provider.frontierModels.some((m) =>
        m.toLowerCase().includes(query),
      );
      const matchesHardware =
        provider.cpuTee.toLowerCase().includes(query) ||
        provider.gpuTee.toLowerCase().includes(query);
      if (!matchesName && !matchesModel && !matchesHardware) {
        return false;
      }
    }

    return true;
  });
}

export const SPEC_V2_ROADMAP: readonly SpecV2RoadmapItem[] = [
  {
    id: "speculative-split-execution",
    number: "01",
    title: "Speculative Split-Execution (Draft in Enclave, Verify in 3PC/FHE)",
    tierTarget: "Research Tier (FHE / 3PC Bridge)",
    bottleneckSolved:
      "Pure FHE and 3-party MPC cannot reach usable interactive speeds on frontier MoE models because non-linear softmax and normalization layers require billions of cryptographic operations per token.",
    mechanism:
      "Run fast token drafting inside the hardware-attested GPU TEE while asynchronously checking sensitive policy commitments inside a 3-party secret-sharing ring.",
    verificationArtifact:
      "Dual-signed receipt pairing the enclave's per-token ECDSA signature with a delayed threshold MAC over the verification transcript.",
  },
  {
    id: "attested-tool-sandboxes",
    number: "02",
    title: "Attested Tool Sandboxes (Enclave-to-Enclave Agent Loops)",
    tierTarget: "Multi-Hop Agentic Extension",
    bottleneckSolved:
      "Confidential inference loses its privacy guarantee if a model emits a tool call (code execution, SQL query, or web search) that exits the enclave into an unverified host runner.",
    mechanism:
      "Extend the 2-hop HPKE session so the model enclave delegates code execution and retrieval to ephemeral Intel TDX micro-sandboxes bound to the same session key.",
    verificationArtifact:
      "Chained Merkle transcript binding the model measurement, tool sandbox registers, and zeroized ephemeral filesystem hashes into one turn receipt.",
  },
  {
    id: "universal-multi-provider-failover",
    number: "03",
    title: "Cross-Provider Session Migration via Client K_freeze",
    tierTarget: "Cross-Provider Portability",
    bottleneckSolved:
      "If a provider enclave goes offline or fails re-attestation mid-conversation, encrypted conversation state is normally stranded with that provider.",
    mechanism:
      "Use the browser-held AES-256-GCM K_freeze key to re-encrypt a frozen session bundle and resume on another attested provider without exposing plaintext history.",
    verificationArtifact:
      "Resumption receipt proving the replacement enclave decrypted the prior state root inside TEE memory only after passing client-side quote verification.",
  },
  {
    id: "zk-memory-zeroization-arc-batching",
    number: "04",
    title: "Batched Nullifiers and Receipt Anchoring on Circle Arc",
    tierTarget: "Settlement Scalability",
    bottleneckSolved:
      "Individual on-chain nullifier checks and per-session receipt transactions add latency and gas cost on Circle Arc at high concurrency.",
    mechanism:
      "Batch anonymous blind-credit nullifiers and session pop receipts into periodic Merkle root transitions anchored on the Arc testnet registry contract.",
    verificationArtifact:
      "On-chain Arc state root transition verifying zero double-spends and anchoring session pop receipt digests.",
  },
  {
    id: "cxl3-sev-tio-gpu-custody",
    number: "05",
    title: "CXL 3.0 / SEV-TIO Hardware-Bound GPU Link Encryption",
    tierTarget: "Next-Gen Silicon Custody",
    bottleneckSolved:
      "Current Hopper and Blackwell Confidential Computing relies on software-managed SPDM session encryption over PCIe between the CPU enclave and the GPU.",
    mechanism:
      "Adopt AMD SEV-TIO and Intel TDX Connect with PCIe IDE link encryption so GPU HBM regions are bound directly into the CPU hardware root of trust at boot.",
    verificationArtifact:
      "Hardware-rooted PCIe IDE stream integrity counters embedded directly inside the CPU and GPU attestation report bundle.",
  },
] as const;
