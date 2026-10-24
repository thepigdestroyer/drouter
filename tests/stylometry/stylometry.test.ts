import { describe, expect, it } from "vitest";
import {
  analyzeStylometricFingerprint,
  normalizeStylometry,
} from "@/lib/stylometry/normalizer";

describe("Stylometric De-Identification & Writing-Fingerprint Normalizer", () => {
  it("detects high uniqueness risk for UK spellings, curly punctuation, double spaces, and sign-offs", () => {
    const sample =
      "Hi team,\n\nWe need to analyse the colour behaviour and optimise the centre defence catalogue for our programme.  It’s “critical” — please prioritise this!\n\nCheers,\nBest regards,\nSent from my iPhone";

    const analysis = analyzeStylometricFingerprint(sample);

    expect(analysis.features.ukSpellingCount).toBeGreaterThanOrEqual(8);
    expect(analysis.features.typographicPunctuationCount).toBeGreaterThanOrEqual(4);
    expect(analysis.features.doubleSpaceCount).toBeGreaterThanOrEqual(1);
    expect(analysis.features.greetingSignoffDetected).toBe(true);
    expect(analysis.features.avgWordsPerSentence).toBeGreaterThan(0);
    expect(analysis.features.lexicalTypeTokenRatio).toBeGreaterThan(0);
    expect(analysis.features.lexicalTypeTokenRatio).toBeLessThanOrEqual(1);
    expect(analysis.uniquenessRiskScore).toBeGreaterThanOrEqual(70);
  });

  it("normalizes UK/Commonwealth spellings, collapses double spaces, replaces curly quotes/dashes, strips sign-offs, and lowers riskAfter below riskBefore", () => {
    const sample =
      "Please analyse the colour and behaviour in our centre defence catalogue for the new programme.  We must optimise the “layout” — it’s essential.\n\nCheers,\nBest regards,\nSent from my iPhone";

    const result = normalizeStylometry(sample);

    // Core UK -> US spelling conversions
    expect(result.normalized).toContain("analyze");
    expect(result.normalized).toContain("color");
    expect(result.normalized).toContain("behavior");
    expect(result.normalized).toContain("center");
    expect(result.normalized).toContain("defense");
    expect(result.normalized).toContain("catalog");
    expect(result.normalized).toContain("program");
    expect(result.normalized).toContain("optimize");

    // Ensure original UK words are removed
    expect(result.normalized).not.toMatch(
      /\b(analyse|colour|behaviour|centre|defence|catalogue|programme|optimise)\b/i
    );

    // Curly quotes and em-dashes replaced with ASCII equivalents
    expect(result.normalized).toContain('"layout"');
    expect(result.normalized).toContain("it's");
    expect(result.normalized).not.toMatch(/[“”‘’—–]/);

    // Double spaces collapsed
    expect(result.normalized).not.toMatch(/ {2,}/);

    // Sign-offs stripped
    expect(result.normalized).not.toMatch(/Cheers,/i);
    expect(result.normalized).not.toMatch(/Best regards/i);
    expect(result.normalized).not.toMatch(/Sent from my iPhone/i);

    // Risk score reduction & recorded changes
    expect(result.riskBefore).toBeGreaterThanOrEqual(70);
    expect(result.riskAfter).toBeLessThan(result.riskBefore);
    expect(result.riskAfter).toBe(0);
    expect(result.changesApplied.length).toBeGreaterThan(0);

    // Re-analysis of normalized text confirms zero remaining markers
    const postAnalysis = analyzeStylometricFingerprint(result.normalized);
    expect(postAnalysis.features.ukSpellingCount).toBe(0);
    expect(postAnalysis.features.typographicPunctuationCount).toBe(0);
    expect(postAnalysis.features.doubleSpaceCount).toBe(0);
    expect(postAnalysis.features.greetingSignoffDetected).toBe(false);
  });

  it("preserves capitalization when normalizing UK spellings and expands idiosyncratic contractions", () => {
    const sample =
      "Colour and Behaviour must be Optimised!  We shan’t ignore COLOUR differences.";
    const result = normalizeStylometry(sample);

    expect(result.normalized).toBe(
      "Color and Behavior must be Optimized! We shall not ignore COLOR differences."
    );
    expect(result.riskAfter).toBeLessThan(result.riskBefore);
  });

  it("handles empty or already-neutral US English text gracefully", () => {
    expect(analyzeStylometricFingerprint("").uniquenessRiskScore).toBe(0);
    expect(normalizeStylometry("").riskAfter).toBe(0);

    const neutral = "Evaluate the system performance and return a summary table.";
    const result = normalizeStylometry(neutral);
    expect(result.normalized).toBe(neutral);
    expect(result.riskBefore).toBe(0);
    expect(result.riskAfter).toBe(0);
    expect(result.changesApplied).toEqual([]);
  });

  it("strips zero-width characters and handles CRLF line endings when normalizing stylometric tells across 200 fuzz iterations", () => {
    const crlfWithZeroWidth =
      "Dear Alice,\r\n\r\nWe must opti\u200Bmise the col\u200Cour and beha\u200Dviour of the system.  It\u2019s ready.\r\n\r\nBest regards,\r\nDana\r\nSent from my iPhone";
    const res = normalizeStylometry(crlfWithZeroWidth);
    expect(res.normalized).toContain("optimize");
    expect(res.normalized).toContain("color");
    expect(res.normalized).toContain("behavior");
    expect(res.normalized).not.toMatch(/Best regards|Sent from my iPhone|Dear Alice/i);
    expect(res.riskAfter).toBe(0);

    for (let i = 0; i < 200; i++) {
      const input = `Hi there,\n\nTrial ${i}: Please analyse the colour and optimise the programme.  We shan’t delay!\n\nCheers,\nSent from my iPad`;
      const norm = normalizeStylometry(input);
      expect(norm.riskAfter).toBeLessThan(norm.riskBefore);
      expect(norm.riskAfter).toBe(0);
    }
  });
});
