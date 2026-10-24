import { NextResponse, connection } from "next/server";
import {
  CANARY_BATTERY,
  MAX_CALLS_PER_AUDIT,
  getAuditorRunsHistory,
} from "@/lib/auditor";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const auditorLimiter = createTokenBucketLimiter({
  name: "auditor-get",
  capacity: 120,
  refillPerSec: 4,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = auditorLimiter.check(request);
    if (limited) return limited;
  }

  const state = await getAuditorRunsHistory(25);

  return NextResponse.json({
    protocol: "mystery-shopper-sprt-v1",
    parameters: {
      frontierModel: "kimi-k3",
      baselinePassRateP0: 0.9,
      substitutePassRateP1: 0.45,
      falsePositiveAlpha: 0.001,
      falseNegativeBeta: 0.01,
      maxCallsPerAudit: MAX_CALLS_PER_AUDIT,
      canaryCategories: CANARY_BATTERY.map((c) => ({
        probeId: c.probeId,
        category: c.category,
      })),
    },
    mongoConfigured: state.mongoConfigured,
    hasRun: state.hasRun,
    statusMessage: state.statusMessage,
    latestRun: state.latestRun,
    history: state.history,
  });
}
