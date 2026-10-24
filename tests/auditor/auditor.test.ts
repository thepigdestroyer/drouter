import { describe, expect, it } from "vitest";
import {
  generateMysteryShopperProbes,
  runSprtModelAudit,
} from "@/lib/auditor/sprt";

describe("Mystery-Shopper Statistical Model Auditor (SPRT)", () => {
  it("certifies an honest kimi-k3 probe stream as PASS_GENUINE_FRONTIER_MODEL", () => {
    const probes = generateMysteryShopperProbes("honest-kimi-k3", 15);
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("PASS_GENUINE_FRONTIER_MODEL");
    expect(result.logLikelihoodRatio).toBeLessThanOrEqual(result.lowerBoundB);
    expect(result.probesEvaluated).toBeGreaterThan(0);
    expect(result.probesEvaluated).toBeLessThanOrEqual(15);
    expect(result.empiricalPassRate).toBeGreaterThanOrEqual(0.85);
  });

  it("detects a cheating 8B-swap provider with SLASH_MODEL_DOWNGRADE_DETECTED within 15 probes", () => {
    const probes = generateMysteryShopperProbes("cheating-8b-swap", 15);
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("SLASH_MODEL_DOWNGRADE_DETECTED");
    expect(result.logLikelihoodRatio).toBeGreaterThanOrEqual(result.upperBoundA);
    expect(result.probesEvaluated).toBeLessThanOrEqual(15);
    expect(result.empiricalPassRate).toBeLessThan(0.5);
  });

  it("returns CONTINUE_SAMPLING when probe count is insufficient to cross either threshold", () => {
    const probes = [
      { probeId: "probe-1", passed: true, latencyMs: 600 },
      { probeId: "probe-2", passed: false, latencyMs: 610 },
      { probeId: "probe-3", passed: true, latencyMs: 590 },
    ];
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("CONTINUE_SAMPLING");
    expect(result.probesEvaluated).toBe(3);
    expect(result.logLikelihoodRatio).toBeGreaterThan(result.lowerBoundB);
    expect(result.logLikelihoodRatio).toBeLessThan(result.upperBoundA);
  });
});
