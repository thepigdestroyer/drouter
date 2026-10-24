import { connection } from "next/server";
import { listNodes } from "@/lib/arc/registry";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import {
  buildMeasuredTiersCatalog,
  GEMINI_4_ARGON_MAX_CONTEXT_TOKENS,
  KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
} from "@/lib/tiers/catalog";
import {
  applyOperatorShareCaps,
  evaluateTimingSignal,
  OPERATOR_UNBONDING_PERIOD_DAYS,
  requiredNodeStakeUsdc,
  UNVERIFIED_OPERATOR_CAP_BPS,
  UNVERIFIED_OPERATOR_CAP_PCT,
  VERIFIED_OPERATOR_CAP_BPS,
  VERIFIED_OPERATOR_CAP_PCT,
} from "@/lib/tiers/economics";
import {
  measureLiveTinfoilQuoteVerifications,
  RISER_PROOF_CPU_ALLOWLIST,
  TIER_B_ASSURANCE_WARNING,
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

  // 1. Measure real hardware quote verification times on live Tinfoil enclave quotes
  const [liveQuotes, registryResult] = await Promise.all([
    measureLiveTinfoilQuoteVerifications(),
    listNodes().catch(() => null),
  ]);

  const tierASevSnpVerifyMs = liveQuotes.tierASevSnpRouter.measuredVerifyLatencyMs;
  const tierAPlusTurinVerifyMs = liveQuotes.tierAPlusTurinEnclave.measuredVerifyLatencyMs;
  const tierBTdxQuoteVerifyMs = liveQuotes.tierBTdxEnclave.measuredVerifyLatencyMs;

  // 2. Build sourced & measured Tiers Catalog (including live Tier C node-seal CKKS linear classifier round trip)
  const catalog = await buildMeasuredTiersCatalog({
    liveQuoteMeasurements: liveQuotes,
    cryptoVerifyLatencyMs: {
      tierASevSnpVerifyMs,
      tierBTdxQuoteVerifyMs,
      tierAPlusSpdmVerifyMs: tierAPlusTurinVerifyMs,
    },
  });

  // 3. Tier A baseline summary (sourced from live Tinfoil router AMD SEV-SNP Genoa quote)
  const tierA = {
    tier: "A" as const,
    platform: "AMD SEV-SNP + NVIDIA H100/B200 CC",
    defaultEnabled: true,
    accepted: Boolean(liveQuotes.tierASevSnpRouter.verification?.verified),
    host: liveQuotes.tierASevSnpRouter.host,
    measuredVerifyLatencyMs: tierASevSnpVerifyMs,
    snpChainVerification: liveQuotes.tierASevSnpRouter.verification,
    maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
    maxContextSource:
      "tinfoilsh/confidential-kimi-k3@v0.0.15 vLLM max-model-len=262,144 (Gemini 4 Argon outer orchestrator has 1,000,000 tokens)",
    detail:
      "Baseline hardware root of trust: live AMD SEV-SNP VCEK (router-0.tinfoil.sh) + NVIDIA GPU CC attestation.",
  };

  // 4. Operator share-cap scaling over real registered network nodes
  const realNodes = (registryResult?.nodes ?? []).filter((n) => n.kind === "tinfoil");
  const shareCapInputs = realNodes.map((n) => ({
    nodeId: n.id,
    operatorId: n.operator,
    operatorVerified: n.status === "active" && n.lastVerifiedOk,
    rawWeight: Math.max(1, Number(n.stake) || 100),
  }));
  const shareCapResults = applyOperatorShareCaps(shareCapInputs);

  // 5. Economic stake sizing ($50,000 leak value @ 3% canary rate)
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

  // 6. Weak-signal confidential-mode timing check (Spec §8.7)
  const timingNormalCc = evaluateTimingSignal(19.2, 18.0); // +6.67% overhead
  const timingSuspiciousBypass = evaluateTimingSignal(18.2, 18.0); // +1.11% overhead (< 3%)

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
        modelId: liveQuotes.tierBTdxEnclave.modelId,
        host: liveQuotes.tierBTdxEnclave.host,
        assuranceWarning: TIER_B_ASSURANCE_WARNING,
        liveQuoteVerification: liveQuotes.tierBTdxEnclave.verification,
        measuredVerifyLatencyMs: tierBTdxQuoteVerifyMs,
        maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
      },
      tierAPlus: {
        modelId: liveQuotes.tierAPlusTurinEnclave.modelId,
        host: liveQuotes.tierAPlusTurinEnclave.host,
        liveTurinSnpVerification: liveQuotes.tierAPlusTurinEnclave.verification,
        measuredVerifyLatencyMs: tierAPlusTurinVerifyMs,
        maxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
      },
      tierC: {
        scopeDisclosure: catalog.fheScopeDisclosure,
        liveFheMeasurement: catalog.liveFheMeasurement,
      },
    },
    catalog: catalog.entries,
    operatorShareCaps: {
      highlightNodes: shareCapResults.slice(0, 10),
      totalNodesEvaluated: shareCapResults.length,
      registrySource: registryResult?.source ?? "unavailable",
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
  });
}
