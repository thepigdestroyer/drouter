import { CONFIDENTIAL_PROVIDERS } from "@/lib/providers/catalog";
import { embedDocumentText, type EmbeddingResult } from "./embeddings";

export type AtlasDocCategory = "provider" | "advisory" | "architecture" | string;

export interface EnclaveIntelligenceDoc {
  docId: string;
  title: string;
  category: AtlasDocCategory;
  summary: string;
  tags: string[];
  metadata: Record<string, unknown>;
  embedding: number[];
  embeddingModel: string;
  embeddingDimensions: 128;
  updatedAt: string;
}

export interface RawEnclaveSeedInput {
  docId: string;
  title: string;
  category: AtlasDocCategory;
  summary: string;
  tags: string[];
  metadata: Record<string, unknown>;
}

/**
 * Automatically builds an embedded `EnclaveIntelligenceDoc` from raw fields
 * using the 128-dim Automated Embedding Pipeline (`embedDocumentText`).
 */
export function buildEmbeddedIntelligenceDoc(input: RawEnclaveSeedInput): EnclaveIntelligenceDoc {
  const compositeText = [
    input.title,
    input.category,
    input.summary,
    input.tags.join(" "),
    JSON.stringify(input.metadata),
  ].join(" ");
  const embedded: EmbeddingResult = embedDocumentText(compositeText);
  return {
    docId: input.docId,
    title: input.title,
    category: input.category,
    summary: input.summary,
    tags: input.tags,
    metadata: input.metadata,
    embedding: embedded.vector,
    embeddingModel: embedded.model,
    embeddingDimensions: embedded.dimensions,
    updatedAt: "2026-10-24T00:00:00.000Z",
  };
}

const PROVIDER_SEED_INPUTS: RawEnclaveSeedInput[] = CONFIDENTIAL_PROVIDERS.map((p) => ({
  docId: `provider-${p.id}`,
  title: `${p.name} — Confidential Inference Enclave (${p.cpuTee} + ${p.gpuTee})`,
  category: "provider",
  summary: `${p.name} (${p.statusInDrouter}) runs confidential inference on ${p.cpuTee} and ${p.gpuTee} with ${p.channelSecurity}. Frontier models: ${p.frontierModels.join(", ")}. Attestation verdict: ${p.attestationVerdict}. Pricing: ${p.inputUsdPerM}. ${p.trustNotes}`,
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
    title: "TEE.fail DDR5 Interposer & Riser Attack Advisory",
    category: "advisory",
    summary:
      "TEE.fail (Georgia Tech / Purdue) demonstrates a passive DDR5 memory bus interposer and riser probe capable of inspecting encrypted CPU DRAM bus traffic at line rate. Static-IV or deterministic physical-address AES-XTS memory encryption exposes repeated 16-byte ciphertext blocks (the Tux-penguin pattern) across identical prompts. dRouter mitigates TEE.fail via Two-Hop GPU Custody monotonic AES-256-GCM counters (zero repeated 16-byte blocks across turns, Shannon entropy > 7.99 bits/byte), SPDM 1.2 / PCIe TDISP link binding, and riser-proof BGA/soldered CPU allowlists.",
    tags: [
      "tee.fail",
      "ddr5",
      "memory bus",
      "interposer",
      "riser probe",
      "tux-penguin",
      "aes-xts",
      "aes-256-gcm",
      "monotonic nonce",
      "tier-a-plus",
    ],
    metadata: {
      advisoryId: "DROUTER-ADV-2026-001",
      attackClass: "Passive DDR5 Memory Bus Interposer Probe",
      severity: "CRITICAL",
      affectedPlatforms: ["DDR5 RDIMM Server Sockets without Fresh Re-Keying"],
      drouterMitigation: "Spec §2.3 Monotonic AES-256-GCM Custody + Tier A+ Riser-Proof Allowlist (V1 Audit)",
      verificationTest: "runMemoryBusAndPopAudit() -> repeated16ByteBlocks === 0",
    },
  },
  {
    docId: "advisory-ddrop",
    title: "DDRop Active DDR5 Memory Bus Fault & Replay Advisory",
    category: "advisory",
    summary:
      "DDRop targets confidential virtual machines (AMD SEV-SNP and Intel TDX) by actively splicing and replaying encrypted DDR5 DIMM cache lines on the physical memory bus when cryptographic integrity trees (MKTME / RMP) lack freshness counters. dRouter neutralizes DDRop on offloaded KV-cache and PCIe bounce buffers by binding every 4 KB offload frame to an authenticated AES-256-GCM tag with session-scoped AAD (`sessionId:turn:kv-offload-page`) and a strictly monotonic 32-bit hardware DRBG counter.",
    tags: [
      "ddrop",
      "ddr5",
      "memory bus",
      "replay attack",
      "fault injection",
      "kv-cache offload",
      "aes-256-gcm",
      "authenticated encryption",
    ],
    metadata: {
      advisoryId: "DROUTER-ADV-2026-002",
      attackClass: "Active DDR5 Bus Replay & Fault Injection",
      severity: "HIGH",
      affectedPlatforms: ["AMD SEV-SNP", "Intel TDX Host DRAM Offload Tiers"],
      drouterMitigation: "Spec §2.3 Per-Turn Monotonic GCM Tag + AAD Transcript Binding",
      verificationTest: "postPopOffloadDecryptFailed === true",
    },
  },
  {
    docId: "advisory-cipherleaks",
    title: "Cipherleaks AMD SEV-SNP Ciphertext Side-Channel Advisory",
    category: "advisory",
    summary:
      "Cipherleaks exploits deterministic physical-address memory encryption in AMD SEV-SNP where an untrusted hypervisor monitors ciphertext changes on identical guest physical cache lines during secret-dependent branches or modular arithmetic. dRouter eliminates Cipherleaks exposure by running constant-time @noble cryptographic primitives, confining session keys inside the VMPL0 SVSM inner monitor ring, and keeping decrypted model weights and KV activations inside NVIDIA B200/H200 HBM3e confidential memory rather than host DRAM.",
    tags: [
      "cipherleaks",
      "amd sev-snp",
      "ciphertext side-channel",
      "cache line",
      "constant-time",
      "vmpl0",
      "hbm3e",
    ],
    metadata: {
      advisoryId: "DROUTER-ADV-2026-003",
      attackClass: "Hypervisor Ciphertext Observation Side-Channel",
      severity: "HIGH",
      affectedPlatforms: ["AMD EPYC Milan / Genoa SEV-SNP Guests"],
      drouterMitigation: "Constant-Time Crypto + VMPL0 Isolation + GPU HBM3e Residency",
      verificationTest: "VMPL0 Egress Policy & Constant-Time ECDSA/HPKE Suite",
    },
  },
  {
    docId: "advisory-voltpillager",
    title: "VoltPillager SVI2 Hardware Voltage Glitching Advisory",
    category: "advisory",
    summary:
      "VoltPillager uses a physical PMBus/SVI2 interposer on the server motherboard voltage regulator to inject sub-microsecond undervolting faults into the AMD Secure Processor (ASP/PSP) during attestation quote signing or key derivation. Because physical voltage glitching can compromise a single rogue operator's socket, dRouter enforces a 5-of-7 independent transparency verifier quorum, 3-of-5 Shamir threshold key custody, 3% cryptographic canary traps, and slashable Circle Arc USDC operator stakes ($50,000+ leak deterrence).",
    tags: [
      "voltpillager",
      "voltage glitching",
      "svi2",
      "pmbus",
      "hardware fault",
      "amd psp",
      "canary trap",
      "circle arc",
      "shamir threshold",
    ],
    metadata: {
      advisoryId: "DROUTER-ADV-2026-004",
      attackClass: "Physical SVI2 Voltage Fault Injection",
      severity: "HIGH",
      affectedPlatforms: ["Physical Host Motherboards with Exposed SVI2/PMBus Headers"],
      drouterMitigation: "Spec §5 & §8 5-of-7 Quorum + 3-of-5 Shamir Custody + Circle Arc Slashing",
      verificationTest: "requiredNodeStakeUsdc() + Canary Trap Bounty Verification",
    },
  },
];

const ARCHITECTURE_SEED_INPUTS: RawEnclaveSeedInput[] = [
  {
    docId: "arch-vmpl0-inner-monitor",
    title: "VMPL0 Inner Monitor & Egress Policy Engine (Spec §2.2)",
    category: "architecture",
    summary:
      "The dRouter VMPL0 Inner Monitor executes inside AMD SEV-SNP Virtual Machine Privilege Level 0 (SVSM ring), isolated from the VMPL1/VMPL2 Linux guest OS and inference runtime. Every outbound token stream and tool call must pass through the VMPL0 egress ring, which enforces fixed-size packet framing, runs deterministic regex + Shannon entropy secret scrubbing, blocks unattested network sockets, and signs the turn receipt only after verifying zero policy violations.",
    tags: [
      "vmpl0",
      "svsm",
      "inner monitor",
      "amd sev-snp",
      "egress policy",
      "secret scrubber",
      "zero-retention",
      "architecture",
    ],
    metadata: {
      specSection: "§2.2",
      privilegeRing: "AMD SEV-SNP VMPL0 (SVSM)",
      enforcedInvariants: [
        "No direct guest OS network egress",
        "Deterministic secret & PII scrubbing",
        "Fixed-cadence token framing against timing side-channels",
      ],
    },
  },
  {
    docId: "arch-two-hop-gpu-custody",
    title: "Two-Hop GPU Custody & Deterministic pop() Zeroization (Spec §2.3–2.4)",
    category: "architecture",
    summary:
      "dRouter's Two-Hop GPU Custody architecture pairs an AMD SEV-SNP ingress router enclave (Hop 1) with an 8x NVIDIA B200/H200/H100 Confidential Computing worker enclave (Hop 2) over attested mutual TLS and RFC 9180 HPKE Encrypted HTTP Body (EHBP). Inside Hop 2, `CustodyCtrDrbg` derives isolated per-session keys (`sessionTrafficKey`, `sessionOffloadKey`, `sessionPrefixKey`), partitions the 512-token prefix cache via HMAC-SHA256 so cross-session cache hits are mathematically zero, and executes `pop()` on session close to cryptographically zeroize all HBM staging pages and DRBG state.",
    tags: [
      "two-hop gpu custody",
      "custodyctrdrbg",
      "pop()",
      "zeroization",
      "crypto-shredding",
      "prefix cache",
      "8x gpu",
      "b200",
      "h200",
      "hpke",
      "rfc 9180",
      "architecture",
    ],
    metadata: {
      specSection: "§2.3–2.4",
      hop1: "AMD SEV-SNP Ingress Router Enclave",
      hop2: "8x NVIDIA B200/H200 CC Worker Enclave",
      blockSizeTokens: 512,
      auditRefs: ["V1 Memory-Bus Probe Audit", "V6 pop() Zeroization Audit"],
    },
  },
];

/**
 * Curated seed corpus of 16 documents (10 Confidential Inference Providers,
 * 4 Hardware Attack Advisories, and 2 dRouter Architecture Specs), each
 * automatically embedded into a 128-dim unit vector on ingest.
 */
export const ATLAS_SEED_DOCS: readonly EnclaveIntelligenceDoc[] = [
  ...PROVIDER_SEED_INPUTS,
  ...ADVISORY_SEED_INPUTS,
  ...ARCHITECTURE_SEED_INPUTS,
].map(buildEmbeddedIntelligenceDoc);
