import { describe, expect, it } from "vitest";
import {
  DEFAULT_ASHI_CRYPTO,
  DEFAULT_ASHI_MODEL,
  FHE_ASIC,
  GPU_FLOOR,
  GPU_TODAY,
  evaluateAshiTierC,
  passLatency,
  simulatePshv,
} from "@/lib/ashi/model";

describe("ASHI Tier C Cryptographic FHE Engine", () => {
  it("maintains ~2.4 GB constant encrypted state vs ~2.7 TB full 1M encrypted KV cache (>1,000x reduction)", () => {
    const result = evaluateAshiTierC({ alpha: 0.95 });

    expect(result.stateGb).toBeCloseTo(2.42, 1);
    expect(result.fullKvCacheTbAt1M).toBeCloseTo(2.65, 1);

    const ratio = (result.fullKvCacheTbAt1M * 1000) / result.stateGb;
    expect(ratio).toBeGreaterThan(1000);
  });

  it("computes refresh cadence as 16 bootstraps per 96-layer pass (every 6 layers)", () => {
    const result = evaluateAshiTierC({ alpha: 0.95 });

    expect(DEFAULT_ASHI_MODEL.layers).toBe(96);
    expect(DEFAULT_ASHI_MODEL.levelsPerLayer).toBe(5);
    expect(DEFAULT_ASHI_CRYPTO.levelsPerBts).toBe(30);
    expect(result.bootstrapsPerPass).toBe(16);
    expect(DEFAULT_ASHI_MODEL.layers / result.bootstrapsPerPass).toBe(6);
  });

  it("exceeds 50 tok/s committed decode throughput on both GPU_FLOOR and FHE_ASIC at alpha = 0.95", () => {
    const result = evaluateAshiTierC({ alpha: 0.95 });

    const gpuFloor = result.profiles.find((p) => p.name === GPU_FLOOR.name);
    const fheAsic = result.profiles.find((p) => p.name === FHE_ASIC.name);
    const gpuToday = result.profiles.find((p) => p.name === GPU_TODAY.name);

    expect(gpuFloor).toBeDefined();
    expect(fheAsic).toBeDefined();
    expect(gpuToday).toBeDefined();

    expect(gpuFloor!.committedTokPerSec).toBeGreaterThan(50);
    expect(fheAsic!.committedTokPerSec).toBeGreaterThan(50);
  });

  it("increases committed tok/s and lowers usdPerMillionOutputTokens as draft acceptance alpha rises", () => {
    const lowAlpha = evaluateAshiTierC({ alpha: 0.8 });
    const midAlpha = evaluateAshiTierC({ alpha: 0.9 });
    const highAlpha = evaluateAshiTierC({ alpha: 0.95 });

    for (let i = 0; i < lowAlpha.profiles.length; i++) {
      expect(midAlpha.profiles[i].committedTokPerSec).toBeGreaterThan(
        lowAlpha.profiles[i].committedTokPerSec
      );
      expect(highAlpha.profiles[i].committedTokPerSec).toBeGreaterThan(
        midAlpha.profiles[i].committedTokPerSec
      );

      expect(midAlpha.profiles[i].usdPerMillionOutputTokens).toBeLessThan(
        lowAlpha.profiles[i].usdPerMillionOutputTokens
      );
      expect(highAlpha.profiles[i].usdPerMillionOutputTokens).toBeLessThan(
        midAlpha.profiles[i].usdPerMillionOutputTokens
      );
    }

    const tPassFloor = passLatency(
      DEFAULT_ASHI_MODEL,
      DEFAULT_ASHI_CRYPTO,
      GPU_FLOOR
    );
    const pshv80 = simulatePshv(0.8, tPassFloor, 8, 4, 0.04, GPU_FLOOR);
    const pshv95 = simulatePshv(0.95, tPassFloor, 8, 4, 0.04, GPU_FLOOR);

    expect(pshv95.committedTokPerSec).toBeGreaterThan(pshv80.committedTokPerSec);
    expect(pshv95.usdPerMillionOutputTokens).toBeLessThan(
      pshv80.usdPerMillionOutputTokens
    );
    expect(pshv95.prefillCost.lazy150K.usd).toBeLessThan(
      pshv95.prefillCost.full1M.usd
    );
  });
});
