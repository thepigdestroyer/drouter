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

export type ClaimVerificationState = "verified" | "unverified";

export interface SourcedClaim {
  claim: string;
  sourceUrl: string;
  verifiedOn: string;
  status: ClaimVerificationState;
  note?: string;
}

export interface ProviderPublicEndpoints {
  attestationUrl: string | null;
  modelsUrl: string | null;
  requiresAuthForAttestation: boolean;
  requiresAuthForModels: boolean;
}

export interface ConfidentialProvider {
  id: string;
  name: string;
  url: string;
  docsUrl: string;
  sourceUrl: string;
  verifiedOn: string;
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
  publicEndpoints: ProviderPublicEndpoints;
  claims: {
    hardware: SourcedClaim;
    models: SourcedClaim;
    channelSecurity: SourcedClaim;
    pricing: SourcedClaim;
  };
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

export const CATALOG_VERIFIED_ON = "2026-10-24" as const;

export const CONFIDENTIAL_PROVIDERS: readonly ConfidentialProvider[] = [
  {
    id: "tinfoil",
    name: "Tinfoil",
    url: "https://tinfoil.sh",
    docsUrl: "https://docs.tinfoil.sh/verification/attestation-architecture",
    sourceUrl: "https://confidentialinference.net/providers/tinfoil",
    verifiedOn: CATALOG_VERIFIED_ON,
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
    publicEndpoints: {
      attestationUrl: "https://atc.tinfoil.sh/attestation",
      modelsUrl: "https://api.tinfoil.sh/api/config/models",
      requiresAuthForAttestation: false,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Router router-0.tinfoil.sh attests with AMD SEV-SNP (Genoa VCEK); model enclaves attest with Intel TDX or AMD SEV-SNP and NVIDIA H100/B200 CC GPUs.",
        sourceUrl: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      models: {
        claim:
          "18 live enclave models in api.tinfoil.sh/api/config/models including kimi-k3 (262,144 max context), glm-5-3, deepseek-v4-1-flash, gemma4-31b, llama3-3-70b, gpt-oss-120b, and voxtral-small-24b.",
        sourceUrl: "https://api.tinfoil.sh/api/config/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "HPKE Encrypted HTTP Body (EHBP, RFC 9180) to enclave HPKE public key over attested TLS with observed X25519MLKEM768 post-quantum key exchange.",
        sourceUrl: "https://confidentialinference.net/providers/tinfoil",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      pricing: {
        claim:
          "Decision Small $0.02/M in, GPT-OSS 120B $0.15/M in, Gemma 4 31B $0.40/M in, DeepSeek V4.1 Flash $0.65/M in, Llama 3.3 70B $1.75/M in, GLM-5.3 $1.80/M in, Kimi K3 $4.00/M in ($20.00/M out).",
        sourceUrl: "https://api.tinfoil.sh/api/config/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "phala-redpill",
    name: "Phala Cloud / Redpill",
    url: "https://www.redpill.ai",
    docsUrl: "https://docs.redpill.ai/confidential-ai/attestation-report",
    sourceUrl: "https://confidentialinference.net/providers/redpill",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified route binding: gateway TDX quote at tee.redpill.ai/v1/attestation/report responds, but per-request backend route binding to Phala dstack or Chutes workers is marked incomplete.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "Qwen 3.8 27B (phala/qwen3.8-27b-uncensored)",
      "Gemma 4 26B A4B (phala/gemma-4-26b-a4b-uncensored)",
      "DeepSeek V3.2 (deepseek/deepseek-v3.2)",
      "GLM-5.3 Flash (z-ai/glm-5.3-flash)",
    ],
    inputUsdPerM: "$0.15+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "OpenAI-compatible confidential storefront and router over Phala Cloud dstack CVMs and Chutes workers. Public endpoint tee.redpill.ai/v1/attestation/report returns an Intel TDX quote and dstack KMS E2EE keys, while api.redpill.ai/v1/models lists 23 is_tee=true models. Only 2 models (phala/qwen3.8-27b-uncensored at $0.30/M and phala/gemma-4-26b-a4b-uncensored at $0.15/M) have direct confidential checks on confidentialinference.net, and backend route binding remains unverified.",
    publicEndpoints: {
      attestationUrl: "https://tee.redpill.ai/v1/attestation/report",
      modelsUrl: "https://api.redpill.ai/v1/models",
      requiresAuthForAttestation: false,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Gateway publishes an Intel TDX quote (tee_type=tdx) from Dstack-TEE/private-ai-gateway; individual model worker GPU TEE evidence is unverified per request.",
        sourceUrl: "https://tee.redpill.ai/v1/attestation/report",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
        note: "Gateway TDX quote is live, but confidentialinference.net marks per-model hardware/TCB and backend route binding incomplete.",
      },
      models: {
        claim:
          "23 models marked is_tee=true in api.redpill.ai/v1/models; 2 Phala TEE models (phala/qwen3.8-27b-uncensored and phala/gemma-4-26b-a4b-uncensored) tracked on confidentialinference.net.",
        sourceUrl: "https://api.redpill.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Declares Attested E2EE (X25519 / secp256k1 AES-256-GCM in workload_keyset) and observed X25519MLKEM768 TLS, but end-to-end channel binding to downstream workers is unverified.",
        sourceUrl: "https://confidentialinference.net/providers/redpill",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.15/M input tokens (phala/gemma-4-26b-a4b-uncensored $0.15/M in, $0.70/M out; phala/qwen3.8-27b-uncensored $0.30/M in, $1.50/M out).",
        sourceUrl: "https://api.redpill.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "near-ai-cloud",
    name: "NEAR AI Cloud",
    url: "https://cloud.near.ai",
    docsUrl: "https://docs.near.ai/cloud/verification",
    sourceUrl: "https://confidentialinference.net/providers/near",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified: 9 models have incomplete route provenance (delegated to Chutes or Phala/dstack) and z-ai/glm-5.3 failed verifier policy on confidentialinference.net.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: false,
    frontierModels: [
      "Kimi K3 (moonshotai/kimi-k3)",
      "Kimi K2.6 (moonshotai/kimi-k2.6)",
      "DeepSeek V3.2 (deepseek/deepseek-v3.2)",
      "GLM-5.3 (z-ai/glm-5.3)",
      "GLM-5.3 Flash (z-ai/glm-5.3-flash)",
      "Qwen 3.5 397B A17B (qwen/qwen3.5-397b-a17b)",
      "Qwen 3.8 27B (Qwen/Qwen3.8-27B)",
    ],
    inputUsdPerM: "$0.01+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "Publishes 61 total models on cloud-api.near.ai/v1/models, of which 13 are in the confidential/TEE class on confidentialinference.net. Gateway attestation at cloud-api.near.ai/v1/attestation/report requires a Bearer API key (HTTP 401 without auth). Independent checks on confidentialinference.net show workloads routed via Chutes and Phala/dstack without cryptographic route binding, 1 explicit policy failure (z-ai/glm-5.3), and classical TLS without hybrid post-quantum key exchange.",
    publicEndpoints: {
      attestationUrl: "https://cloud-api.near.ai/v1/attestation/report",
      modelsUrl: "https://cloud-api.near.ai/v1/models",
      requiresAuthForAttestation: true,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Declares Intel TDX + NVIDIA H200 TEEs, but confidentialinference.net reports 1 explicit policy failure (z-ai/glm-5.3) and 9 models delegated to Chutes or Phala/dstack without route provenance.",
        sourceUrl: "https://confidentialinference.net/providers/near",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "13 confidential catalog models verified in cloud-api.near.ai/v1/models including moonshotai/kimi-k3, moonshotai/kimi-k2.6, deepseek/deepseek-v3.2, z-ai/glm-5.3, z-ai/glm-5.3-flash, qwen/qwen3.5-397b-a17b, and Qwen/Qwen3.8-27B.",
        sourceUrl: "https://cloud-api.near.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Declares X25519-XChaCha20-Poly1305 Attested E2EE; classical TLS only (no hybrid PQC observed in PQC run #39) and backend request route is unverified.",
        sourceUrl: "https://confidentialinference.net/providers/near",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.01/M input tokens (openai/privacy-filter $0.01/M, Qwen/Qwen3.8-27B $0.04/M in, z-ai/glm-5.3-flash $0.08/M in, qwen/qwen3.5-397b-a17b $0.50/M in, moonshotai/kimi-k2.6 $0.81/M in, deepseek/deepseek-v3.2 $1.10/M in, z-ai/glm-5.3 $1.80/M in, moonshotai/kimi-k3 $3.30/M in).",
        sourceUrl: "https://cloud-api.near.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "venice-ai",
    name: "Venice.ai (E2EE Mode)",
    url: "https://venice.ai",
    docsUrl: "https://docs.venice.ai",
    sourceUrl: "https://confidentialinference.net/providers/venice",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified: 10 E2EE models show incomplete source provenance and route binding (Phala/dstack backends), and 2 Kimi endpoints (e2ee-kimi-k3-p, e2ee-kimi-k2-6) were unreachable.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "Kimi K3 (e2ee-kimi-k3-p)",
      "Kimi K2.6 (e2ee-kimi-k2-6)",
      "DeepSeek V4 Flash (e2ee-deepseek-v4-flash)",
      "GLM-5.3 (e2ee-glm-5-3-p)",
      "GPT-OSS 120B (e2ee-gpt-oss-120b-p)",
      "Qwen 3.8 27B (e2ee-qwen3-8-27b)",
      "Gemma 4 26B A4B (e2ee-gemma-4-26b-a4b-uncensored-p)",
    ],
    inputUsdPerM: "$0.05+/M",
    attestationVerdict: "On-Chain Attestation (Intel DCAP + NVIDIA CC)",
    trustNotes:
      "Exposes 12 E2EE models (prefixed e2ee-* with supportsE2EE=true and supportsTeeAttestation=true in api.venice.ai/api/v1/models) alongside 128 standard non-TEE models. Observed X25519MLKEM768 hybrid TLS, but confidentialinference.net reports incomplete hardware/TCB evaluation on 6 models, incomplete route/source provenance across all 10 reachable E2EE models, and 2 unreachable Kimi endpoints.",
    publicEndpoints: {
      attestationUrl: null,
      modelsUrl: "https://api.venice.ai/api/v1/models",
      requiresAuthForAttestation: true,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Declares Intel TDX + NVIDIA GPU TEEs (Phala/dstack backends), but 6 of 12 E2EE models lack evaluated hardware/TCB evidence and 2 Kimi endpoints were unreachable on confidentialinference.net.",
        sourceUrl: "https://confidentialinference.net/providers/venice",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "12 E2EE models live in api.venice.ai/api/v1/models: e2ee-qwen-2-5-7b-p, e2ee-gpt-oss-120b-p, e2ee-glm-5-3-flash, e2ee-deepseek-v4-flash, e2ee-qwen3-6-35b-a3b, e2ee-gemma-4-26b-a4b-uncensored-p, e2ee-qwen3-vl-30b-a3b-p, e2ee-qwen3-8-27b, e2ee-kimi-k2-6, e2ee-glm-5-2-p, e2ee-glm-5-3-p, and e2ee-kimi-k3-p.",
        sourceUrl: "https://api.venice.ai/api/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Declares ECDH Attested E2EE with observed X25519MLKEM768 hybrid TLS, but source provenance and backend route binding are unverified across all 12 E2EE models.",
        sourceUrl: "https://confidentialinference.net/providers/venice",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.05/M input tokens (e2ee-qwen-2-5-7b-p $0.05/M in, e2ee-gpt-oss-120b-p $0.13/M in, e2ee-glm-5-3-flash $0.16/M in, e2ee-deepseek-v4-flash $0.182/M in, e2ee-gemma-4-26b-a4b-uncensored-p $0.19/M in, e2ee-qwen3-8-27b $0.47/M in, e2ee-kimi-k2-6 $0.87/M in, e2ee-glm-5-3-p $1.75/M in, e2ee-kimi-k3-p $3.75/M in).",
        sourceUrl: "https://api.venice.ai/api/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "prem-ai",
    name: "Prem AI",
    url: "https://www.premai.io",
    docsUrl: "https://docs.prem.io/attestation.md",
    sourceUrl: "https://confidentialinference.net/providers/prem",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified baseline: Intel TDX / SEV-SNP + GPU EAT quotes use nonce freshness, but OPA golden policy leaves image measurements unpinned by default and 3 of 5 endpoints were unreachable.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX / AMD SEV-SNP",
    gpuTee: "NVIDIA H100 / Blackwell CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "DeepSeek V4.1 Flash 1017 (deepseek-v4.1-flash-1017)",
      "Nemotron 3 Ultra 550B A55B (nvidia/nemotron-3-ultra-550b-a55b)",
      "Qwen 3.8 27B (qwen38-27b)",
      "Qwen 3.6 27B (qwen36-27b)",
      "DeepGram General Nova 3 (deepgram/general-nova-3)",
    ],
    inputUsdPerM: "$0.30+/M",
    attestationVerdict: "Per-Workload TDX Transcript Binding",
    trustNotes:
      "Serves 5 confidential models at gateway.prem.io/rvenc/models (requires PREM_API_KEY; returns HTTP 401 without auth) using XWing (ML-KEM-768 + X25519) + XChaCha20-Poly1305 client encryption and the open-source @premai/reticle verifier. Prem's own attestation docs state that the shipped OPA golden policy leaves reference image measurements unpinned by default and does not prove which GPU behind the load balancer served a request.",
    publicEndpoints: {
      attestationUrl: null,
      modelsUrl: "https://gateway.prem.io/rvenc/models",
      requiresAuthForAttestation: true,
      requiresAuthForModels: true,
    },
    claims: {
      hardware: {
        claim:
          "Declares Intel TDX / AMD SEV-SNP CVMs and NVIDIA GPU EAT tokens verified via @premai/reticle, but shipped OPA golden policy leaves reference image measurements unpinned by default and 3 of 5 model attestation targets were unreachable.",
        sourceUrl: "https://docs.prem.io/attestation.md",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "5 confidential models tracked on confidentialinference.net (deepseek-v4.1-flash-1017, qwen38-27b, nvidia/nemotron-3-ultra-550b-a55b, qwen36-27b, deepgram/general-nova-3); docs.prem.io/models-and-pricing.md lists qwen38-27b, deepseek-v4.1-flash, and deepgram/general-nova-3.",
        sourceUrl: "https://confidentialinference.net/providers/prem",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Declares XWing-XChaCha20-Poly1305 client encryption and observed X25519MLKEM768 TLS, but confidentialinference.net marks channel binding, workload identity, and request route unproven.",
        sourceUrl: "https://confidentialinference.net/providers/prem",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.30/M input tokens (qwen38-27b $0.30/M in, $2.40/M out; qwen36-27b $0.30/M in, $2.40/M out; deepseek-v4.1-flash-1017 $0.35/M in, $1.40/M out; nvidia/nemotron-3-ultra-550b-a55b $0.625/M in, $3.125/M out; deepgram/general-nova-3 $0.05/audio-min).",
        sourceUrl: "https://docs.prem.io/models-and-pricing.md",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "ppq-ai",
    name: "PPQ.AI",
    url: "https://ppq.ai",
    docsUrl: "https://ppq.ai/api-docs",
    sourceUrl: "https://confidentialinference.net/providers/ppq",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Partial verification: AMD SEV-SNP hardware, TCB policy, and channel binding pass 6/6 on confidentialinference.net, but freshness, workload identity, and Tinfoil backend route binding are incomplete.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "AMD SEV-SNP (router) + Intel TDX / SEV-SNP (Tinfoil backend)",
    gpuTee: "NVIDIA H100 / H200 / B200 CC",
    channelSecurity: "Attested E2EE",
    pqcHybrid: true,
    frontierModels: [
      "Kimi K3 (private/kimi-k3)",
      "DeepSeek V4.1 Flash (private/deepseek-v4-1-flash)",
      "GLM-5.3 (private/glm-5-3)",
      "GPT-OSS 120B (private/gpt-oss-120b)",
      "Llama 3.3 70B (private/llama3-3-70b)",
      "Gemma 4 31B (private/gemma4-31b)",
    ],
    inputUsdPerM: "$0.16+/M",
    attestationVerdict: "Full 2-Hop Hardware + Sigstore Rekor + GPU Matrix",
    trustNotes:
      "Pay-per-query aggregator offering 6 private/* models (with privacyLevel='e2e' in api.ppq.ai/v1/models; 387 non-TEE models excluded) backed by Tinfoil enclaves with HPKE and hybrid X25519MLKEM768 TLS. When calling api.ppq.ai directly, PPQ's Enclave Router decrypts and re-encrypts unless the user runs the local ppq-private-mode proxy. Hardware, TCB, and channel binding pass 6/6, while freshness, source provenance, and route binding remain incomplete.",
    publicEndpoints: {
      attestationUrl: null,
      modelsUrl: "https://api.ppq.ai/v1/models",
      requiresAuthForAttestation: false,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Hardware and TCB policy pass 6/6 for AMD SEV-SNP router + Tinfoil enclaves, but freshness, workload identity, source provenance, and route binding are marked incomplete on confidentialinference.net.",
        sourceUrl: "https://confidentialinference.net/providers/ppq",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "6 private/* models with privacyLevel='e2e' verified in api.ppq.ai/v1/models: private/gpt-oss-120b, private/llama3-3-70b, private/glm-5-3, private/gemma4-31b, private/kimi-k3, and private/deepseek-v4-1-flash.",
        sourceUrl: "https://api.ppq.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Channel binding and X25519MLKEM768 hybrid TLS pass 6/6; true client-to-enclave HPKE requires running the local ppq-private-mode verifier proxy rather than posting plaintext to api.ppq.ai.",
        sourceUrl: "https://ppq.ai/api-docs",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.16/M input tokens (private/gpt-oss-120b $0.15825/M in, private/gemma4-31b $0.422/M in, private/deepseek-v4-1-flash $0.68575/M in, private/llama3-3-70b $1.84625/M in, private/glm-5-3 $1.899/M in, private/kimi-k3 $4.22/M in).",
        sourceUrl: "https://api.ppq.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "confidential-ai",
    name: "Confidential AI",
    url: "https://confidential.ai",
    docsUrl: "https://confidential.ai/docs/inference-api/attestation",
    sourceUrl: "https://confidentialinference.net/providers/confidentialai",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified: public api.confidential.ai/attestation returns c8s allowlist and Intel TDX cluster bundles with X25519MLKEM768 TLS, but GPU evidence is raw/unverified and per-model checks are incomplete.",
    statusInDrouter: "compatible-openai-e2ee",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA B300 / B200 / H100 CC",
    channelSecurity: "TEE-Terminated TLS",
    pqcHybrid: true,
    frontierModels: [
      "DeepSeek V4 Flash (deepseek-ai/DeepSeek-V4-Flash-0731)",
      "Qwen 3.8 27B (request capacity)",
      "GLM 5.3 (request capacity)",
      "Kimi K3 (request capacity)",
    ],
    inputUsdPerM: "$0.20+/M",
    attestationVerdict: "Per-Workload TDX Transcript Binding",
    trustNotes:
      "Operates the open-source c8s platform on Intel TDX + NVIDIA GPUs with an ML-KEM-768 + X25519 tunnel terminating inside the TEE. Keyless GET api.confidential.ai/v1/models currently lists 1 live public model (deepseek-ai/DeepSeek-V4-Flash-0731 at $0.20/M input, $0.40/M output), while Qwen 3.8 27B ($0.30/M), GLM 5.3 ($1.40/M), and Kimi K3 ($3.00/M) are listed on confidential.ai/pricing as request-capacity tiers. Confidential AI's own attestation docs note that NVIDIA evidence in /attestation is currently raw and unverified.",
    publicEndpoints: {
      attestationUrl: "https://api.confidential.ai/attestation",
      modelsUrl: "https://api.confidential.ai/v1/models",
      requiresAuthForAttestation: false,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Publishes Intel TDX + c8s cluster bundle at api.confidential.ai/attestation, but confidential.ai docs state NVIDIA GPU evidence is currently raw/unverified and confidentialinference.net marks hardware/TCB evaluation incomplete.",
        sourceUrl: "https://confidential.ai/docs/inference-api/attestation",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "1 live model in api.confidential.ai/v1/models (deepseek-ai/DeepSeek-V4-Flash-0731); Qwen 3.8 27B, GLM 5.3, and Kimi K3 listed on confidential.ai/pricing as request-capacity.",
        sourceUrl: "https://api.confidential.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Declares TEE-Terminated TLS with TEErminator client verification and observed X25519MLKEM768 hybrid PQC, but confidentialinference.net marks freshness and channel binding unproven.",
        sourceUrl: "https://confidentialinference.net/providers/confidentialai",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "Declared pricing on confidential.ai/pricing (as of 20 Oct 2026): DeepSeek V4 Flash $0.20/M in ($0.018/M cached, $0.40/M out); request-capacity Qwen 3.8 27B $0.30/M in, GLM 5.3 $1.40/M in, Kimi K3 $3.00/M in.",
        sourceUrl: "https://confidential.ai/pricing",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "chutes-bittensor",
    name: "Chutes (Bittensor TEE)",
    url: "https://chutes.ai",
    docsUrl: "https://chutes.ai/docs",
    sourceUrl: "https://confidentialinference.net/providers/chutes",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Unverified gateway route: 13 of 14 TEE models return Intel TDX / SEV-SNP miner quotes, but workload identity, source provenance, and request routing are not bound.",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "NVIDIA H100 / H200 CC (Miner Dependent)",
    channelSecurity: "TEE-Only Gateway",
    pqcHybrid: false,
    frontierModels: [
      "Kimi K3 (moonshotai/Kimi-K3-TEE)",
      "Kimi K2.6 (moonshotai/Kimi-K2.6-TEE)",
      "DeepSeek V4 Flash 0731 (deepseek-ai/DeepSeek-V4-Flash-0731-TEE)",
      "DeepSeek V3.2 (deepseek-ai/DeepSeek-V3.2-TEE)",
      "GLM-5.2 (zai-org/GLM-5.2-TEE)",
      "Qwen 3.5 397B A17B (Qwen/Qwen3.5-397B-A17B-TEE)",
      "Gemma 4 31B Turbo (google/gemma-4-31B-turbo-TEE)",
    ],
    inputUsdPerM: "$0.02+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "Decentralized Bittensor marketplace serving 14 confidential_compute=true (-TEE) models in llm.chutes.ai/v1/models across community AMD SEV-SNP and Intel TDX miners. While miner hardware quotes are corroborated on 13 of 14 models (1 unreachable: Qwen3-235B-A22B-Thinking-2507-TEE), TLS terminates at the gateway without hybrid PQC or cryptographic proof binding a caller's request to a specific attested miner.",
    publicEndpoints: {
      attestationUrl: null,
      modelsUrl: "https://llm.chutes.ai/v1/models",
      requiresAuthForAttestation: true,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Miner Intel TDX / AMD SEV-SNP quotes corroborated on 13 of 14 -TEE models (1 unreachable), but workload identity and source provenance are unproven across all 14 models.",
        sourceUrl: "https://confidentialinference.net/providers/chutes",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "14 confidential_compute=true models verified in llm.chutes.ai/v1/models including moonshotai/Kimi-K3-TEE, moonshotai/Kimi-K2.6-TEE, deepseek-ai/DeepSeek-V4-Flash-0731-TEE, deepseek-ai/DeepSeek-V3.2-TEE, zai-org/GLM-5.2-TEE, Qwen/Qwen3.5-397B-A17B-TEE, and google/gemma-4-31B-turbo-TEE.",
        sourceUrl: "https://llm.chutes.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Advertised TEE-only Gateway with classical TLS (no hybrid PQC observed in PQC run #39) and no cryptographic route binding between gateway requests and miner enclaves.",
        sourceUrl: "https://confidentialinference.net/providers/chutes",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "From $0.0245/M input tokens (Mistral-Nemo-Instruct-2407-TEE & Nemotron-3-Nano-Omni-30B-TEE $0.0245/M in, Qwen3.8-27B-TEE $0.039/M in, gemma-4-31B-turbo-TEE $0.12/M in, Kimi-K2.6-TEE $0.45/M in, DeepSeek-V3.2-TEE $1.00/M in, GLM-5.2-TEE $1.25/M in, Kimi-K3-TEE $1.85/M in).",
        sourceUrl: "https://llm.chutes.ai/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "privatemode-cosmian",
    name: "Privatemode (Edgeless / Cosmian)",
    url: "https://privatemode.ai",
    docsUrl: "https://docs.privatemode.ai/security/attestation/overview",
    sourceUrl: "https://confidentialinference.net/providers/privatemode",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Partial verification: Hardware, TCB, freshness, channel binding, and workload identity pass 13/13; source provenance and request route are unverified.",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "AMD SEV-SNP + Intel TDX",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "TEE-Only Gateway",
    pqcHybrid: true,
    frontierModels: [
      "GLM-5.3 (glm-5.3)",
      "GLM-5.3 Flash (glm-5.3-flash)",
      "GPT-OSS 120B (gpt-oss-120b)",
      "DeepSeek OCR 2 (deepseek-ocr-2)",
      "Qwen 3 Embedding 4B (qwen3-embedding-4b)",
      "Voxtral Mini 3B (voxtral-mini-3b)",
      "Whisper Large v3 (whisper-large-v3)",
    ],
    inputUsdPerM: "$0.15+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "EU-hosted confidential service built by Edgeless Systems (Contrast / Cosmian VM) on AMD SEV-SNP and Intel TDX with observed X25519MLKEM768 hybrid TLS across 7 models. Publishes its Contrast deployment manifest and allowed chip IDs at cdn.confidential.cloud/privatemode/v2/manifest.json. Passes hardware, TCB, freshness, channel binding, and workload identity 13/13 on confidentialinference.net, but requires the Privatemode SDK/proxy for end-to-end encryption and lacks public source-provenance and request-route binding.",
    publicEndpoints: {
      attestationUrl: "https://cdn.confidential.cloud/privatemode/v2/manifest.json",
      modelsUrl: null,
      requiresAuthForAttestation: false,
      requiresAuthForModels: true,
    },
    claims: {
      hardware: {
        claim:
          "Hardware, TCB policy, freshness, and workload identity pass 13/13 on AMD SEV-SNP (Genoa) and Intel TDX with pinned AllowedChipIDs/AllowedPIIDs in cdn.confidential.cloud/privatemode/v2/manifest.json.",
        sourceUrl: "https://cdn.confidential.cloud/privatemode/v2/manifest.json",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      models: {
        claim:
          "7 models verified on privatemode.ai/pricing and manifest workloads: glm-5.3, glm-5.3-flash, gpt-oss-120b, deepseek-ocr-2, qwen3-embedding-4b, voxtral-mini-3b, and whisper-large-v3.",
        sourceUrl: "https://www.privatemode.ai/pricing",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "Channel binding and X25519MLKEM768 hybrid TLS pass 13/13, but direct API is TEE-only Gateway unless using the Privatemode proxy/SDK, and request route / source provenance are marked unverified.",
        sourceUrl: "https://confidentialinference.net/providers/privatemode",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "Published in EUR on privatemode.ai/pricing (~$0.15+/M USD at 1.1193 EUR/USD): Qwen3-Embedding 4B EUR 0.13/M ($0.1455/M), GLM-5.3-Flash & gpt-oss-120b EUR 0.20/M in / EUR 0.65/M out ($0.2239/M in), DeepSeek-OCR-2 EUR 0.77/M in ($0.8619/M in), GLM-5.3 EUR 1.55/M in / EUR 5.74/M out ($1.7349/M in).",
        sourceUrl: "https://www.privatemode.ai/pricing",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
    },
  },
  {
    id: "nanogpt",
    name: "NanoGPT",
    url: "https://nano-gpt.com",
    docsUrl: "https://docs.nano-gpt.com/api-reference/tee-verification",
    sourceUrl: "https://confidentialinference.net/providers/nanogpt",
    verifiedOn: CATALOG_VERIFIED_ON,
    verified: false,
    verificationSummary:
      "Failed / Unverified: 6 of 24 TEE models failed hardware and TCB policy checks on confidentialinference.net; gateway terminates TLS outside the enclave and 10 of 24 TEE models have undisclosed custom pricing.",
    statusInDrouter: "gateway-tee-only",
    cpuTee: "Intel TDX",
    gpuTee: "NVIDIA H100 CC",
    channelSecurity: "TEE-Only Gateway",
    pqcHybrid: true,
    frontierModels: [
      "Kimi K3 (TEE/kimi-k3)",
      "Kimi K2.6 (TEE/kimi-k2.6)",
      "DeepSeek V4.1 Flash (TEE/deepseek-v4.1-flash)",
      "DeepSeek V3.2 (TEE/deepseek-v3.2)",
      "GLM-5.3 (TEE/glm-5.3)",
      "Qwen 3.8 27B (TEE/qwen3.8-27b)",
      "Llama 3.3 70B (TEE/llama3-3-70b)",
    ],
    inputUsdPerM: "$0.15+/M",
    attestationVerdict: "Gateway Attestation Only",
    trustNotes:
      "Pay-per-prompt storefront offering 24 TEE/* models in nano-gpt.com/api/v1/models (654 non-TEE models excluded). Attestation endpoint api.nano-gpt.com/api/v1/tee/attestation requires an API key. NanoGPT's own docs state that 'plaintext may still exist at gateway/proxy layers outside the enclave', and confidentialinference.net recorded 6 explicit hardware/TCB failures (TEE/kimi-k3, TEE/qwen3.6-27b, TEE/qwen3.5-27b, TEE/qwen3.5-397b-a17b, TEE/glm-5.1, TEE/glm-5.1-thinking), 14 incomplete checks, 4 unreachable endpoints, and 10 models with undisclosed pricing.",
    publicEndpoints: {
      attestationUrl: "https://api.nano-gpt.com/api/v1/tee/attestation",
      modelsUrl: "https://nano-gpt.com/api/v1/models",
      requiresAuthForAttestation: true,
      requiresAuthForModels: false,
    },
    claims: {
      hardware: {
        claim:
          "Declares Intel TDX + NVIDIA H100 CC quotes, but 6 of 24 TEE/* models explicitly failed hardware and TCB policy checks on confidentialinference.net and 4 were unreachable.",
        sourceUrl: "https://confidentialinference.net/providers/nanogpt",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      models: {
        claim:
          "24 TEE/* models verified in nano-gpt.com/api/v1/models including TEE/kimi-k3, TEE/kimi-k2.6, TEE/deepseek-v4.1-flash, TEE/deepseek-v3.2, TEE/glm-5.3, TEE/qwen3.8-27b, TEE/gemma-4-31b-it, and TEE/llama3-3-70b.",
        sourceUrl: "https://nano-gpt.com/api/v1/models",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "verified",
      },
      channelSecurity: {
        claim:
          "TEE-Only Gateway: docs.nano-gpt.com explicitly states plaintext may exist at gateway/proxy layers outside the enclave; X25519MLKEM768 hybrid TLS observed to gateway only.",
        sourceUrl: "https://docs.nano-gpt.com/api-reference/tee-verification",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
      pricing: {
        claim:
          "Unverified / partial: 14 TEE models have declared rates from $0.15/M (TEE/gemma-4-31b-it $0.15/M, TEE/deepseek-v3.2 $0.50/M, TEE/kimi-k2.6 $1.50/M, TEE/llama3-3-70b $2.00/M), while 10 TEE models (including TEE/kimi-k3, TEE/glm-5.3, TEE/deepseek-v4.1-flash, TEE/qwen3.8-27b) have undisclosed custom pricing.",
        sourceUrl: "https://confidentialinference.net/providers/nanogpt",
        verifiedOn: CATALOG_VERIFIED_ON,
        status: "unverified",
      },
    },
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
