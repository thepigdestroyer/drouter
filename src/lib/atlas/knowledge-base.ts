import { CONFIDENTIAL_PROVIDERS } from "@/lib/providers/catalog";
import {
  embedBatchWithProvider,
  embedDocumentText,
  embedDocumentTextWithProvider,
  type EmbeddingResult,
} from "./embeddings";

export type AtlasDocCategory = "provider" | "advisory" | "architecture" | string;

export const CORPUS_RETRIEVED_AT_UTC = "2026-10-24" as const;

export interface EnclaveIntelligenceDoc {
  docId: string;
  title: string;
  category: AtlasDocCategory;
  summary: string;
  sourceUrl: string;
  retrievedAt: string;
  tags: string[];
  metadata: Record<string, unknown>;
  embedding: number[];
  embeddingModel: string;
  embeddingDimensions: number;
  updatedAt: string;
}

export interface RawEnclaveSeedInput {
  docId: string;
  title: string;
  category: AtlasDocCategory;
  summary: string;
  sourceUrl?: string;
  retrievedAt?: string;
  tags: string[];
  metadata: Record<string, unknown>;
}

function resolveDocSourceUrl(input: RawEnclaveSeedInput): string {
  if (typeof input.sourceUrl === "string" && input.sourceUrl.trim().length > 0) {
    return input.sourceUrl.trim();
  }
  const metaSource =
    (typeof input.metadata?.sourceUrl === "string" && input.metadata.sourceUrl.trim()) ||
    (typeof input.metadata?.docsUrl === "string" && input.metadata.docsUrl.trim()) ||
    (typeof input.metadata?.url === "string" && input.metadata.url.trim()) ||
    "https://docs.tinfoil.sh/verification/attestation-architecture";
  return metaSource;
}

export function composeIntelligenceDocText(input: {
  title: string;
  category: string;
  summary: string;
  sourceUrl?: string;
  tags: string[];
  metadata: Record<string, unknown>;
}): string {
  return [
    input.title,
    input.category,
    input.summary,
    input.sourceUrl ?? "",
    input.tags.join(" "),
    JSON.stringify(input.metadata),
  ]
    .filter(Boolean)
    .join(" ");
}

/**
 * Builds an embedded `EnclaveIntelligenceDoc` synchronously using `embedDocumentText`
 * (768-dim fallback vector). For live attested Tinfoil `nomic-embed-text` embeddings,
 * use `buildEmbeddedIntelligenceDocWithProvider` or `embedSeedCorpusWithProvider`.
 */
export function buildEmbeddedIntelligenceDoc(input: RawEnclaveSeedInput): EnclaveIntelligenceDoc {
  const sourceUrl = resolveDocSourceUrl(input);
  const retrievedAt = input.retrievedAt?.trim() || CORPUS_RETRIEVED_AT_UTC;
  const metadata = {
    ...input.metadata,
    sourceUrl,
    retrievedAt,
  };
  const compositeText = composeIntelligenceDocText({
    title: input.title,
    category: input.category,
    summary: input.summary,
    sourceUrl,
    tags: input.tags,
    metadata,
  });
  const embedded: EmbeddingResult = embedDocumentText(compositeText);
  return {
    docId: input.docId,
    title: input.title,
    category: input.category,
    summary: input.summary,
    sourceUrl,
    retrievedAt,
    tags: input.tags,
    metadata,
    embedding: embedded.vector,
    embeddingModel: embedded.model,
    embeddingDimensions: embedded.dimensions,
    updatedAt: `${retrievedAt}T00:00:00.000Z`,
  };
}

/**
 * Builds an embedded `EnclaveIntelligenceDoc` using Tinfoil's attested
 * `nomic-embed-text` enclave (768 dims) with fallback when unreachable.
 */
export async function buildEmbeddedIntelligenceDocWithProvider(
  input: RawEnclaveSeedInput,
): Promise<EnclaveIntelligenceDoc> {
  const sourceUrl = resolveDocSourceUrl(input);
  const retrievedAt = input.retrievedAt?.trim() || CORPUS_RETRIEVED_AT_UTC;
  const metadata = {
    ...input.metadata,
    sourceUrl,
    retrievedAt,
  };
  const compositeText = composeIntelligenceDocText({
    title: input.title,
    category: input.category,
    summary: input.summary,
    sourceUrl,
    tags: input.tags,
    metadata,
  });
  const embedded = await embedDocumentTextWithProvider(compositeText);
  return {
    docId: input.docId,
    title: input.title,
    category: input.category,
    summary: input.summary,
    sourceUrl,
    retrievedAt,
    tags: input.tags,
    metadata,
    embedding: embedded.vector,
    embeddingModel: embedded.model,
    embeddingDimensions: embedded.dimensions,
    updatedAt: `${retrievedAt}T00:00:00.000Z`,
  };
}

const PROVIDER_SEED_INPUTS: RawEnclaveSeedInput[] = CONFIDENTIAL_PROVIDERS.map((p) => ({
  docId: `provider-${p.id}`,
  title: `${p.name} - Confidential Inference Enclave (${p.cpuTee} + ${p.gpuTee})`,
  category: "provider",
  sourceUrl: p.sourceUrl,
  retrievedAt: CORPUS_RETRIEVED_AT_UTC,
  summary: `${p.name} (${p.statusInDrouter}) runs confidential inference on ${p.cpuTee} and ${p.gpuTee} with ${p.channelSecurity}. Frontier models: ${p.frontierModels.join(", ")}. Attestation verdict: ${p.attestationVerdict}. Verification summary: ${p.verificationSummary.replace(/[\u2013\u2014]/g, "-")} Pricing: ${p.inputUsdPerM}. ${p.trustNotes.replace(/[\u2013\u2014]/g, "-")} Source: ${p.sourceUrl}.`,
  tags: [
    p.id,
    p.name.toLowerCase(),
    p.statusInDrouter,
    p.cpuTee.toLowerCase(),
    p.gpuTee.toLowerCase(),
    p.pqcHybrid ? "pqc-hybrid-ml-kem-768" : "classical-ecdh",
    ...p.frontierModels.map((m) => m.toLowerCase()),
  ],
  metadata: {
    providerId: p.id,
    url: p.url,
    docsUrl: p.docsUrl,
    sourceUrl: p.sourceUrl,
    retrievedAt: CORPUS_RETRIEVED_AT_UTC,
    verified: p.verified,
    verificationSummary: p.verificationSummary.replace(/[\u2013\u2014]/g, "-"),
    statusInDrouter: p.statusInDrouter,
    cpuTee: p.cpuTee,
    gpuTee: p.gpuTee,
    channelSecurity: p.channelSecurity,
    pqcHybrid: p.pqcHybrid,
    frontierModels: [...p.frontierModels],
    inputUsdPerM: p.inputUsdPerM,
    attestationVerdict: p.attestationVerdict,
  },
}));

const ADVISORY_SEED_INPUTS: RawEnclaveSeedInput[] = [
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
];

const ARCHITECTURE_SEED_INPUTS: RawEnclaveSeedInput[] = [
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
      arcExplorerUrl: "https://testnet.arcscan.app/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
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

export const RAW_ATLAS_SEED_INPUTS: readonly RawEnclaveSeedInput[] = [
  ...PROVIDER_SEED_INPUTS,
  ...ADVISORY_SEED_INPUTS,
  ...ARCHITECTURE_SEED_INPUTS,
];

/**
 * Batches all seed inputs in a single request through Tinfoil's attested
 * `nomic-embed-text` enclave (768 dims), falling back to `embedDocumentText`
 * if Tinfoil is unreachable.
 */
export async function embedSeedCorpusWithProvider(
  inputs: readonly RawEnclaveSeedInput[] = RAW_ATLAS_SEED_INPUTS,
): Promise<EnclaveIntelligenceDoc[]> {
  const prepared = inputs.map((input) => {
    const sourceUrl = resolveDocSourceUrl(input);
    const retrievedAt = input.retrievedAt?.trim() || CORPUS_RETRIEVED_AT_UTC;
    const metadata = {
      ...input.metadata,
      sourceUrl,
      retrievedAt,
    };
    const compositeText = composeIntelligenceDocText({
      title: input.title,
      category: input.category,
      summary: input.summary,
      sourceUrl,
      tags: input.tags,
      metadata,
    });
    return { input, sourceUrl, retrievedAt, metadata, compositeText };
  });

  const embeddings = await embedBatchWithProvider(prepared.map((p) => p.compositeText));

  return prepared.map((p, idx) => {
    const emb = embeddings[idx] ?? embedDocumentText(p.compositeText);
    return {
      docId: p.input.docId,
      title: p.input.title,
      category: p.input.category,
      summary: p.input.summary,
      sourceUrl: p.sourceUrl,
      retrievedAt: p.retrievedAt,
      tags: p.input.tags,
      metadata: p.metadata,
      embedding: emb.vector,
      embeddingModel: emb.model,
      embeddingDimensions: emb.dimensions,
      updatedAt: `${p.retrievedAt}T00:00:00.000Z`,
    };
  });
}

/**
 * Curated seed corpus of 16 real, sourced documents (10 Confidential Inference Providers,
 * 4 Published Hardware TEE Attack Advisories, and 2 Cryptographic Architecture Specs).
 * Each document carries a verified `sourceUrl` and `retrievedAt` UTC date.
 */
export const ATLAS_SEED_DOCS: readonly EnclaveIntelligenceDoc[] =
  RAW_ATLAS_SEED_INPUTS.map(buildEmbeddedIntelligenceDoc);
