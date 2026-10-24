import { connection } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import {
  buildMeasuredTiersCatalog,
  GEMINI_4_ARGON_MAX_CONTEXT_TOKENS,
  KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
} from "@/lib/tiers/catalog";
import {
  applyOperatorShareCaps,
  evaluateCanaryRealismAuc,
  evaluateTimingSignal,
  OPERATOR_UNBONDING_PERIOD_DAYS,
  requiredNodeStakeUsdc,
  UNVERIFIED_OPERATOR_CAP_BPS,
  UNVERIFIED_OPERATOR_CAP_PCT,
  VERIFIED_OPERATOR_CAP_BPS,
  VERIFIED_OPERATOR_CAP_PCT,
} from "@/lib/tiers/economics";
import {
  createSampleTierAPlusEvidence,
  createSignedTdxQuote,
  RISER_PROOF_CPU_ALLOWLIST,
  verifyTdxTierBQuote,
  verifyTierAPlusEvidence,
} from "@/lib/tiers/tdx-spdm";

const tiersLimiter = createTokenBucketLimiter({
  name: "tiers-get",
  capacity: 120,
  refillPerSec: 4,
});

export async function GET(request?: Request) {
  try {
    await connection();
  } catch {
    // Allow direct handler invocation in unit tests outside Next.js request AsyncLocalStorage
  }
  if (request) {
    const limited = tiersLimiter.check(request);
    if (limited) return limited;
  }

  // 1. Tier A baseline summary (sourced from Tinfoil live router + Kimi K3 enclave manifest)
  const tierA = {
    tier: "A" as const,
    platform: "AMD SEV-SNP + NVIDIA H100/B200 CC",
    defaultEnabled: true,
    accepted: true,
    maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
    maxContextSource:
      "tinfoilsh/confidential-kimi-k3@v0.0.15 vLLM max-model-len=262,144 (Gemini 4 Argon outer orchestrator has 1,000,000 tokens)",
    detail:
      "Baseline hardware root of trust: AMD SEV-SNP VCEK (router-0.tinfoil.sh) + NVIDIA GPU CC attestation.",
  };

  // 2. Tier B (Intel TDX Quote v4) evaluation with measured P-256 verification latency
  const tdxQuote = createSignedTdxQuote();
  const tierBDefaultRejected = verifyTdxTierBQuote(tdxQuote, {
    allowTierB: false,
    expectedMrtd: tdxQuote.mrtd,
    expectedReportData: tdxQuote.reportData,
    minTcbSvn: 5,
  });

  const tTdx0 = performance.now();
  const tierBOptInAccepted = verifyTdxTierBQuote(tdxQuote, {
    allowTierB: true,
    expectedMrtd: tdxQuote.mrtd,
    expectedReportData: tdxQuote.reportData,
    minTcbSvn: 5,
  });
  const tierBTdxQuoteVerifyMs = Number(
    Math.max(0.01, performance.now() - tTdx0).toFixed(3),
  );

  // 3. Tier A+ (SPDM 1.2 + PCIe TDISP / TEE-IO + riser-proof memory allowlist) with measured 10-device P-256 verification latency
  const expectedVmId = "cvm-snp-vm-001";
  const tierAPlusEvidence = createSampleTierAPlusEvidence({
    nodeId: "tier-aplus-node-1",
    cpuModel: RISER_PROOF_CPU_ALLOWLIST[1],
    teeIoBoundVmId: expectedVmId,
  });
  const tSpdm0 = performance.now();
  const tierAPlusEvaluation = verifyTierAPlusEvidence(
    tierAPlusEvidence,
    expectedVmId,
  );
  const tierAPlusSpdmVerifyMs = Number(
    Math.max(0.01, performance.now() - tSpdm0).toFixed(3),
  );

  const relayGapEvidence = createSampleTierAPlusEvidence({
    nodeId: "tier-a-relay-attempt",
    cpuModel: RISER_PROOF_CPU_ALLOWLIST[1],
    teeIoBoundVmId: "foreign-vm-999",
  });
  const tierAPlusRelayGapDowngrade = verifyTierAPlusEvidence(
    relayGapEvidence,
    expectedVmId,
  );

  // 4. Build sourced & measured Tiers Catalog (including live Tier C node-seal CKKS linear classifier round trip)
  const catalog = await buildMeasuredTiersCatalog({
    cryptoVerifyLatencyMs: {
      tierBTdxQuoteVerifyMs,
      tierAPlusSpdmVerifyMs,
    },
  });

  // 5. Operator share-cap scaling (2.0% verified cap, 0.5% unverified cap)
  const rawNetworkNodes = [
    {
      nodeId: "whale-verified-1",
      operatorId: "op-whale-verified",
      operatorVerified: true,
      rawWeight: 2500,
    },
    {
      nodeId: "whale-verified-2",
      operatorId: "op-whale-verified",
      operatorVerified: true,
      rawWeight: 2500,
    },
    {
      nodeId: "sybil-unverified-1",
      operatorId: "op-unverified-alpha",
      operatorVerified: false,
      rawWeight: 1500,
    },
    ...Array.from({ length: 50 }, (_, idx) => ({
      nodeId: `fleet-node-${idx + 1}`,
      operatorId: `op-verified-${idx + 1}`,
      operatorVerified: true,
      rawWeight: 100,
    })),
  ];
  const shareCapResults = applyOperatorShareCaps(rawNetworkNodes);

  // 6. Economic stake sizing ($50,000 leak value @ 3% canary rate)
  const stakeSingleSession = requiredNodeStakeUsdc({
    estimatedLeakGainUsdc: 50_000,
    canaryRate: 0.03,
    sessionsBeforeMisuseUse: 1,
  });
  const stakeTenSessions = requiredNodeStakeUsdc({
    estimatedLeakGainUsdc: 50_000,
    canaryRate: 0.03,
    sessionsBeforeMisuseUse: 10,
  });

  // 7. Weak-signal confidential-mode timing check (Spec §8.7)
  const timingNormalCc = evaluateTimingSignal(19.2, 18.0); // +6.67% overhead
  const timingSuspiciousBypass = evaluateTimingSignal(18.2, 18.0); // +1.11% overhead (< 3%)

  // 8. V8 Canary-realism classifier AUC (<= 0.6)
  const canaryRealismSamples = [
    { isCanary: true, suspicionScore: 0.42 },
    { isCanary: false, suspicionScore: 0.45 },
    { isCanary: true, suspicionScore: 0.51 },
    { isCanary: false, suspicionScore: 0.49 },
    { isCanary: true, suspicionScore: 0.38 },
    { isCanary: false, suspicionScore: 0.41 },
    { isCanary: true, suspicionScore: 0.56 },
    { isCanary: false, suspicionScore: 0.54 },
    { isCanary: true, suspicionScore: 0.47 },
    { isCanary: false, suspicionScore: 0.52 },
  ];
  const canaryRealism = evaluateCanaryRealismAuc(canaryRealismSamples);

  return Response.json({
    parameters: {
      verifiedOperatorCapPct: VERIFIED_OPERATOR_CAP_PCT,
      verifiedOperatorCapBps: VERIFIED_OPERATOR_CAP_BPS,
      unverifiedOperatorCapPct: UNVERIFIED_OPERATOR_CAP_PCT,
      unverifiedOperatorCapBps: UNVERIFIED_OPERATOR_CAP_BPS,
      unbondingPeriodDays: OPERATOR_UNBONDING_PERIOD_DAYS,
      riserProofCpuAllowlist: RISER_PROOF_CPU_ALLOWLIST,
      kimiK3MaxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
      gemini4ArgonMaxContextTokens: GEMINI_4_ARGON_MAX_CONTEXT_TOKENS,
    },
    tiers: {
      tierA,
      tierB: {
        quote: tdxQuote,
        defaultOptOut: tierBDefaultRejected,
        optInVerified: tierBOptInAccepted,
        measuredVerifyLatencyMs: tierBTdxQuoteVerifyMs,
        maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
      },
      tierAPlus: {
        upgradedNode: tierAPlusEvaluation,
        relayGapDowngradedNode: tierAPlusRelayGapDowngrade,
        measuredVerifyLatencyMs: tierAPlusSpdmVerifyMs,
        maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
      },
      tierC: {
        scopeDisclosure: catalog.fheScopeDisclosure,
        liveFheMeasurement: catalog.liveFheMeasurement,
      },
    },
    catalog: catalog.entries,
    operatorShareCaps: {
      highlightNodes: shareCapResults.slice(0, 5),
      totalNodesEvaluated: shareCapResults.length,
    },
    economics: {
      leakValueUsdc: 50_000,
      canaryRate: 0.03,
      singleSession: stakeSingleSession,
      tenSessions: stakeTenSessions,
    },
    weakSignals: {
      normalCcMode: timingNormalCc,
      suspiciousLowOverhead: timingSuspiciousBypass,
    },
    canaryRealismV8: canaryRealism,
  });
}
