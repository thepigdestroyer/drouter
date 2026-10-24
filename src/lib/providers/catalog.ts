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
    docsUrl: "https://docs.tinfoil.sh/attestation/overview",
    statusInDrouter: "live-integrated",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "8x NVIDIA B200 / H200 / H100 CC",
    channelSecurity: "HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS",
    pqcHybrid: true,
    frontierModels: [
      "Kimi K3 (2.8T MoE)",
      "GLM-5.3",
      "DeepSeek V4.1 Flash",
      "GPT-OSS 120B",
      "Llama 3.3 70B",
      "Gemma 4 31B",
      "Qwen 3.5 72B",
    ],
    inputUsdPerM: "$0.02+/M",
    attestationVerdict: "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix",
    trustNotes:
      "Live primary provider in dRouter. End-to-end RFC 9180 HPKE Encrypted HTTP Body (EHBP) terminates inside an AMD SEV-SNP router enclave and forwards over attested mutual TLS to 8x B200/H200/H100 Confidential Computing model enclaves (17 models total). Both hops publish reproducible measurements in Sigstore Rekor. Remaining gap: PCIe/NVLink link encryption relies on NVIDIA CC session keys rather than CXL 3.0 SEV-TIO.",
  },
  {
    id: "phala-redpill",
    name: "Phala Cloud / Redpill",
    url: "https://phala.com",
    docsUrl: "https://docs.phala.com/phala-cloud/attestation/overview",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "DeepSeek V3",
      "DeepSeek R1",
      "Qwen 3 235B",
      "Llama 3.3 70B",
      "Gemma 3 27B",
    ],
    inputUsdPerM: "$0.04+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "Backs OpenRouter's enterprise confidential tier via Redpill and Phala Cloud CVM workers. Provides Intel TDX DCAP quotes paired with NVIDIA Local Verifier GPU CC tokens and on-chain ACI receipts. Remaining gap: OpenRouter aggregator routing headers stay visible unless wrapped in client-side E2EE before dispatch.",
  },
  {
    id: "near-ai-cloud",
    name: "NEAR AI Cloud",
    url: "https://cloud.near.ai",
    docsUrl: "https://docs.near.ai/cloud/confidential-inference",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: false,
    frontierModels: [
      "DeepSeek R1",
      "DeepSeek V3",
      "Moonshot Kimi K2.5",
      "GLM-5",
      "Qwen 3",
      "GPT-OSS 120B",
      "Llama 3.3 70B",
    ],
    inputUsdPerM: "$0.01+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "Serves 13 frontier models across Intel TDX host CVMs coupled with NVIDIA H200 TEE accelerators and NEAR on-chain attestation registry contracts. Remaining gap: session keys are negotiated over TLS or X25519 ECDH without default ML-KEM-768 hybrid post-quantum key encapsulation.",
  },
  {
    id: "venice-ai",
    name: "Venice.ai (E2EE Mode)",
    url: "https://venice.ai",
    docsUrl: "https://docs.venice.ai/overview/privacy",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: false,
    frontierModels: [
      "Moonshot Kimi K2.5",
      "GLM-5",
      "DeepSeek R1 671B",
      "Qwen 3 235B",
      "Gemma 3 27B",
      "Llama 3.3 70B",
    ],
    inputUsdPerM: "$0.05+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "Serves 12 models with optional browser and SDK client-side encryption directly to Intel TDX + H100/H200 CC enclaves operated over Phala and NEAR infrastructure. Remaining gap: E2EE mode must be explicitly enabled by the client; standard API calls terminate at the Venice API proxy.",
  },
  {
    id: "prem-ai",
    name: "Prem AI",
    url: "https://premai.io",
    docsUrl: "https://docs.premai.io/security/confidential-ai",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: false,
    frontierModels: [
      "DeepSeek R1",
      "Qwen 3 72B",
      "NVIDIA Nemotron Ultra 253B",
      "Llama 3.3 70B",
      "Mistral Large 2",
    ],
    inputUsdPerM: "$0.30+/M",
    attestationVerdict: "Per-Workload TDX Transcript Binding",
    trustNotes:
      "Serves 5 enterprise models inside Sovereign Intel TDX + GPU TEE pods with 64-byte caller nonce freshness verified per session. Remaining gap: container rootfs measurement manifests are signed by Prem release keys rather than an independent 5-of-7 public verifier quorum.",
  },
  {
    id: "ppq-ai",
    name: "PPQ.AI",
    url: "https://ppq.ai",
    docsUrl: "https://ppq.ai/docs/attestation",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "Moonshot Kimi K3",
      "DeepSeek V4.1",
      "GLM-5.3",
      "Llama 3.3 70B",
      "Qwen 3 72B",
      "Gemma 4 31B",
    ],
    inputUsdPerM: "$0.16+/M",
    attestationVerdict: "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix",
    trustNotes:
      "Privacy-first pay-per-query gateway running an AMD SEV-SNP router that maps and pins downstream Tinfoil model backend attestation reports across 6 models. Supports anonymous lightning and blind-token settlement. Remaining gap: adds an outer routing hop when compared against direct enclave peering.",
  },
  {
    id: "confidential-ai",
    name: "Confidential AI",
    url: "https://confidential.ai",
    docsUrl: "https://confidential.ai/docs/c8s-attestation",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "DeepSeek R1 671B",
      "DeepSeek V3",
      "Llama 3.3 70B",
    ],
    inputUsdPerM: "$0.12+/M",
    attestationVerdict: "Per-Workload TDX Transcript Binding",
    trustNotes:
      "Runs DeepSeek and Llama workloads on Intel TDX + NVIDIA H100 CC clusters using c8s attestation bundles that bind a SHA-384 transcript over caller nonce and ephemeral session keys. Remaining gap: narrower frontier catalog focused primarily on DeepSeek reasoning deployments.",
  },
  {
    id: "chutes-bittensor",
    name: "Chutes (Bittensor TEE)",
    url: "https://chutes.ai",
    docsUrl: "https://chutes.ai/docs/tee-verification",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC (Miner Dependent)",
    channelSecurity: "TEE-Terminated TLS",
    pqcHybrid: false,
    frontierModels: [
      "DeepSeek R1",
      "DeepSeek V3",
      "Moonshot Kimi K2.5",
      "GLM-5",
      "Qwen 3 235B",
      "Mistral Large 2",
      "Llama 3.3 70B",
    ],
    inputUsdPerM: "$0.02+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "Decentralized Bittensor subnet serving 14 models across AMD SEV-SNP and Intel TDX miner nodes at aggressive spot pricing. Remaining gap: TLS terminates at the gateway unless the caller pins individual miner quotes, and miner GPU CC enforcement varies by chute deployment.",
  },
  {
    id: "privatemode-cosmian",
    name: "Privatemode (Cosmian / Contrast)",
    url: "https://privatemode.ai",
    docsUrl: "https://docs.privatemode.ai/architecture/confidential-computing",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "TEE-Terminated TLS",
    pqcHybrid: false,
    frontierModels: [
      "DeepSeek R1",
      "GLM-5",
      "GPT-OSS 120B",
      "Qwen 3 72B",
      "Mistral Large 2",
      "Llama 3.3 70B",
      "Gemma 3 27B",
    ],
    inputUsdPerM: "$0.15+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "EU-hosted confidential workspace built on Contrast and Cosmian Kubernetes coordinator manifests over AMD SEV-SNP and Intel TDX nodes (7 models). Remaining gap: optimized for enterprise proxy deployment where the Contrast coordinator terminates TLS inside the cluster perimeter.",
  },
  {
    id: "nanogpt",
    name: "NanoGPT",
    url: "https://nano-gpt.com",
    docsUrl: "https://nano-gpt.com/confidential-compute",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "Host CPU + NVIDIA CC Driver",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "TEE-Only Gateway",
    pqcHybrid: false,
    frontierModels: [
      "Qwen 3 235B",
      "DeepSeek R1",
      "Moonshot Kimi K2.5",
      "GLM-5",
      "Llama 3.3 70B",
    ],
    inputUsdPerM: "$0.03+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "Catalog of 24 models featuring NVIDIA H100 Confidential Computing verification and per-request ECDSA response signatures. Remaining gap: the NanoGPT API gateway sees plaintext prompts before forwarding to backend TEE workers, so there is no end-to-end client-to-enclave HPKE wrapper.",
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
    tierTarget: "Hybrid Tier B / Tier C Bridge",
    bottleneckSolved:
      "Pure 3PC/MPC and FHE cannot sustain interactive token streaming on 2.8T MoE models due to 2.3 billion non-linear softmax exponentials per token at 1M context.",
    mechanism:
      "Run fast autoregressive token drafting inside the 8x B200/H200 GPU TEE bubble while asynchronously batch-verifying sensitive logit commitment checkpoints and policy classifier layers inside a 3-party secret-sharing ring.",
    verificationArtifact:
      "Dual-signed PoP receipt pairing the enclave's per-token ECDSA stream signature with a delayed threshold MAC over the speculative verification transcript.",
  },
  {
    id: "attested-tool-sandboxes",
    number: "02",
    title: "Attested Tool Sandboxes (Enclave-to-Enclave Agent Loops)",
    tierTarget: "Spec §3.4 Multi-Hop Agentic Extension",
    bottleneckSolved:
      "Confidential LLM inference loses its privacy guarantee the moment a model emits a tool call (code execution, SQL query, or web search) that exits the enclave into an unverified host runner.",
    mechanism:
      "Extend the 2-hop HPKE EHBP session into an N-hop enclave mesh where the LLM worker enclave delegates code execution and retrieval to ephemeral Intel TDX micro-sandboxes bound to the same session key and VMPL0 egress policy.",
    verificationArtifact:
      "Chained Merkle transcript binding the model measurement, tool sandbox RTMRs, and zeroized ephemeral filesystem hashes into a single verifiable turn receipt.",
  },
  {
    id: "universal-multi-provider-failover",
    number: "03",
    title: "Universal Multi-Provider Failover via K_freeze State Migration",
    tierTarget: "Spec §6 Cross-Provider Portability",
    bottleneckSolved:
      "If a live provider enclave (such as Tinfoil) suffers a hardware fault or fails a 5-of-7 quorum re-attestation mid-conversation, encrypted KV-cache and conversation history are normally stranded.",
    mechanism:
      "Standardize the AES-256-GCM K_freeze envelope so a browser holding its local WebCrypto key can re-encapsulate a frozen session blob and resume seamlessly on Phala, NEAR AI Cloud, or Prem AI without re-uploading plaintext history.",
    verificationArtifact:
      "Cross-provider resumption receipt proving the successor enclave decrypted the prior state root inside TEE memory only after passing client-side quote verification.",
  },
  {
    id: "zk-memory-zeroization-arc-batching",
    number: "04",
    title: "Zero-Knowledge Proof of Memory Zeroization & Nullifier Batching on Arc",
    tierTarget: "Spec §7 & §8 Settlement Scalability",
    bottleneckSolved:
      "Individual on-chain nullifier checks and per-session memory scrub attestations create gas and latency overhead on Circle Arc when scaling beyond 10,000 concurrent anonymous sessions.",
    mechanism:
      "Aggregate 1,024 RSA blind credit nullifiers and VMPL0 deterministic HBM wipe transitions into a single succinct Halo2/Plonky3 proof posted to the Arc settlement contract every epoch.",
    verificationArtifact:
      "On-chain Arc state root transition verifying zero double-spends and cryptographic confirmation of post-turn GPU HBM arena zeroization.",
  },
  {
    id: "cxl3-sev-tio-gpu-custody",
    number: "05",
    title: "CXL 3.0 / SEV-TIO Hardware-Bound GPU Custody (Tier A++)",
    tierTarget: "Spec §2.1 Next-Gen Silicon Custody",
    bottleneckSolved:
      "Current Hopper and Blackwell Confidential Computing relies on software-managed SPDM session establishment over PCIe between the host CVM and the 8x GPU baseboard.",
    mechanism:
      "Adopt AMD SEV-TIO and Intel TDX Connect with PCIe IDE (Integrity and Data Encryption) and CXL 3.0 fabric keys so GPU HBM regions are bound directly into the CPU root of trust at silicon boot without host bounce buffers.",
    verificationArtifact:
      "Hardware-rooted IDE stream integrity counters embedded directly inside the AMD PSP and NVIDIA Rim attestation report bundle.",
  },
] as const;
