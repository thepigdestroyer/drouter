import { NextResponse, connection } from "next/server";
import {
  generateMysteryShopperProbes,
  runSprtModelAudit,
} from "@/lib/auditor/sprt";
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

  const honestProbes = generateMysteryShopperProbes("honest-kimi-k3", 15);
  const cheatingProbes = generateMysteryShopperProbes("cheating-8b-swap", 15);

  const honestAudit = runSprtModelAudit(honestProbes);
  const cheatingAudit = runSprtModelAudit(cheatingProbes);

  return NextResponse.json({
    protocol: "mystery-shopper-sprt-v1",
    parameters: {
      frontierModel: "kimi-k3",
      baselinePassRateP0: 0.9,
      substitutePassRateP1: 0.45,
      falsePositiveAlpha: 0.001,
      falseNegativeBeta: 0.01,
    },
    comparison: {
      honestProvider: {
        mode: "honest-kimi-k3",
        audit: honestAudit,
        probes: honestProbes,
      },
      cheatingProvider: {
        mode: "cheating-8b-swap",
        audit: cheatingAudit,
        probes: cheatingProbes,
      },
    },
  });
}
