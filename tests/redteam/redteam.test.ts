import { describe, expect, it } from "vitest";
import {
  computeMannWhitneyAuc,
  generateNaiveCanaryCorpus,
  generateRealisticSessionCorpus,
  runRedTeamClassifierV8,
} from "@/lib/redteam/v8-canary-realism";

describe("Spec §Testing V8 — Canary Realism Generator & Red-Team Classifier", () => {
  it("generates a balanced realistic corpus with valid 2^j * 1024 token buckets and matched densities", () => {
    const corpus = generateRealisticSessionCorpus(120);
    expect(corpus.length).toBe(120);

    const canaries = corpus.filter((s) => s.isCanary);
    const reals = corpus.filter((s) => !s.isCanary);
    expect(canaries.length).toBe(60);
    expect(reals.length).toBe(60);

    const validBuckets = new Set([1024, 2048, 4096, 8192, 16384]);
    for (const sample of corpus) {
      expect(validBuckets.has(sample.tokenBucket)).toBe(true);
      expect(sample.turns).toBeGreaterThanOrEqual(1);
      expect(sample.interTurnIntervalSec).toBeGreaterThan(0);
      expect(sample.textPreview.length).toBeGreaterThan(10);
    }

    const canaryCodeRate = canaries.filter((s) => s.hasCodeBlocks).length / canaries.length;
    const realCodeRate = reals.filter((s) => s.hasCodeBlocks).length / reals.length;
    expect(Math.abs(canaryCodeRate - realCodeRate)).toBeLessThanOrEqual(0.05);

    const canaryCredRate =
      canaries.filter((s) => s.hasCredentialPattern).length / canaries.length;
    const realCredRate = reals.filter((s) => s.hasCredentialPattern).length / reals.length;
    expect(Math.abs(canaryCredRate - realCredRate)).toBeLessThanOrEqual(0.05);
  });

  it("passes V8 when evaluating high-realism canary corpus (AUC <= 0.6, v8Passed === true)", () => {
    const corpus = generateRealisticSessionCorpus(160);
    const result = runRedTeamClassifierV8(corpus);

    expect(result.threshold).toBe(0.6);
    expect(result.sampleSize).toBe(160);
    expect(result.auc).toBeLessThanOrEqual(0.6);
    expect(result.v8Passed).toBe(true);
    expect(Object.keys(result.featureImportances)).toEqual([
      "turns",
      "tokenBucket",
      "hasCodeBlocks",
      "hasCredentialPattern",
      "interTurnIntervalSec",
    ]);
  });

  it("catches naive poorly disguised canary corpus with AUC > 0.85 (v8Passed === false)", () => {
    const naiveCorpus = generateNaiveCanaryCorpus(160);
    const result = runRedTeamClassifierV8(naiveCorpus);

    expect(result.threshold).toBe(0.6);
    expect(result.sampleSize).toBe(160);
    expect(result.auc).toBeGreaterThan(0.85);
    expect(result.v8Passed).toBe(false);
  });

  it("computes exact Mann-Whitney U / ROC-AUC for known score rankings", () => {
    expect(computeMannWhitneyAuc([0.9, 0.8, 0.2, 0.1], [true, true, false, false])).toBe(1.0);
    expect(computeMannWhitneyAuc([0.1, 0.2, 0.8, 0.9], [true, true, false, false])).toBe(0.0);
    expect(computeMannWhitneyAuc([0.5, 0.5, 0.5, 0.5], [true, false, true, false])).toBe(0.5);
  });

  it("handles edge-case corpus sizes (0, 1, 3, 500 samples) without NaN or division by zero", () => {
    expect(runRedTeamClassifierV8([]).auc).toBe(0.5);
    expect(runRedTeamClassifierV8(generateRealisticSessionCorpus(2).slice(0, 1)).auc).toBe(0.5);

    const largeRealistic = generateRealisticSessionCorpus(500);
    const largeRes = runRedTeamClassifierV8(largeRealistic);
    expect(Number.isFinite(largeRes.auc)).toBe(true);
    expect(largeRes.v8Passed).toBe(true);
  });
});
