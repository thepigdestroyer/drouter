import { NextRequest, NextResponse, connection } from "next/server";
import { evaluateAshiTierC } from "@/lib/ashi/model";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const ashiLimiter = createTokenBucketLimiter({
  name: "ashi-get",
  capacity: 120,
  refillPerSec: 4,
});

export interface PlatformTierComparisonEntry {
  tier: "Tier A" | "Tier A+" | "Tier B" | "Tier C";
  name: string;
  architecture: string;
  trustBoundary: string;
  physicalInterposerResistant: boolean;
  routingPrivacy: string;
  throughputTokPerSec: number;
  usdPerMillionOutputTokens: number;
  maxContextTokens: number;
  sessionStateFootprint: string;
}

export async function GET(request: NextRequest) {
  await connection();
  if (request) {
    const limited = ashiLimiter.check(request);
    if (limited) return limited;
  }

  const alphaParam = request.nextUrl.searchParams.get("alpha");
  const parsedAlpha = alphaParam !== null ? Number(alphaParam) : 0.95;
  const alpha =
    Number.isFinite(parsedAlpha) && parsedAlpha > 0 && parsedAlpha < 1
      ? parsedAlpha
      : 0.95;

  const evaluation = evaluateAshiTierC({ alpha });
  const floorProfile =
    evaluation.profiles.find((p) => p.name.includes("floor")) ??
    evaluation.profiles[1];
  const asicProfile =
    evaluation.profiles.find((p) => p.name.includes("ASIC")) ??
    evaluation.profiles[2];

  const tierComparison: PlatformTierComparisonEntry[] = [
    {
      tier: "Tier A",
      name: "Nested Enclave (Default Confidential Tier)",
      architecture: "Outer CVM + Nested Attested Enclave + Blinded I/O",
      trustBoundary: "CPU + GPU TEE silicon & attested firmware",
      physicalInterposerResistant: false,
      routingPrivacy: "Protected inside enclave; bus exposed to physical interposer",
      throughputTokPerSec: 85,
      usdPerMillionOutputTokens: 18,
      maxContextTokens: 1_000_000,
      sessionStateFootprint: "~288 GB plaintext KV cache @ 1M tokens",
    },
    {
      tier: "Tier A+",
      name: "TEE-IO + Soldered RAM (Hardware-Hardened Confidential Tier)",
      architecture: "PCIe IDE/TDISP TEE-IO + On-package HBM3e / Soldered LPDDR5X",
      trustBoundary: "Die-to-die encrypted link + potted/soldered memory package",
      physicalInterposerResistant: true,
      routingPrivacy: "Protected against passive bus interposers inside TEE boundary",
      throughputTokPerSec: 82,
      usdPerMillionOutputTokens: 24,
      maxContextTokens: 1_000_000,
      sessionStateFootprint: "~288 GB encrypted-in-package KV cache @ 1M tokens",
    },
    {
      tier: "Tier B",
      name: "Intel TDX Opt-In (Standard CVM Tier)",
      architecture: "Single-layer Intel TDX + NVIDIA H100/B200 CC Mode",
      trustBoundary: "Host VMM excluded; standard DIMM/PCIe topology",
      physicalInterposerResistant: false,
      routingPrivacy: "Standard TEE memory encryption; vulnerable to physical DIMM probing",
      throughputTokPerSec: 95,
      usdPerMillionOutputTokens: 14,
      maxContextTokens: 1_000_000,
      sessionStateFootprint: "~288 GB CVM KV cache @ 1M tokens",
    },
    {
      tier: "Tier C",
      name: "ASHI Cryptographic FHE Tier (Zero Silicon Trust)",
      architecture:
        "Pipelined Speculative Homomorphic Verification (PSHV) + CSEM + LT-MoE + RRC (CKKS N=2^17)",
      trustBoundary: "Client holds secret key; zero server hardware or enclave trust",
      physicalInterposerResistant: true,
      routingPrivacy:
        "Information-theoretic / RLWE 128-bit oblivious all-expert evaluation",
      throughputTokPerSec: floorProfile.committedTokPerSec,
      usdPerMillionOutputTokens: floorProfile.usdPerMillionOutputTokens,
      maxContextTokens: 1_000_000,
      sessionStateFootprint: `${evaluation.stateGb} GB constant encrypted state (vs ${evaluation.fullKvCacheTbAt1M} TB full KV @ 1M, ASIC $${asicProfile.usdPerMillionOutputTokens}/1M tok @ ${asicProfile.committedTokPerSec} tok/s)`,
    },
  ];

  return NextResponse.json({
    alpha,
    ...evaluation,
    tierComparison,
  });
}
