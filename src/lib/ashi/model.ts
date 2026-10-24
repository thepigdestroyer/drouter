export interface AshiModelParams {
  layers: number;
  d: number;
  dPad: number;
  pTotal: number;
  pActive: number;
  statePerLayer: number;
  levelsPerLayer: number;
}

export interface AshiCryptoParams {
  N: number;
  slots: number;
  limbsLin: number;
  slices: number;
  slicesPrefill: number;
  levelsPerBts: number;
}

export interface AshiHardwareProfile {
  id: "GPU_TODAY" | "GPU_FLOOR" | "FHE_ASIC";
  name: string;
  int8: number;
  usdHr: number;
  eff: number;
  tKs: number;
  tBts: number;
  latBts: number;
  latKs: number;
  latLayerExtra: number;
  slices: number;
  slicesPrefill: number;
}

export const DEFAULT_ASHI_MODEL: AshiModelParams = {
  layers: 96,
  d: 7168,
  dPad: 8192,
  pTotal: 3.0e12,
  pActive: 1.1e11,
  statePerLayer: 32 * 128 * 128,
  levelsPerLayer: 5,
};

export const DEFAULT_ASHI_CRYPTO: AshiCryptoParams = {
  N: 131072, // 2^17
  slots: 65536, // 2^16 (8 tokens/ciphertext at dPad=8192)
  limbsLin: 3,
  slices: 9,
  slicesPrefill: 4,
  levelsPerBts: 30,
};

export const GPU_TODAY: AshiHardwareProfile = {
  id: "GPU_TODAY",
  name: "8xB200, 2026 kernels",
  int8: 4.5e15,
  usdHr: 6.82,
  eff: 0.4,
  tKs: 4e-6,
  tBts: 0.032,
  latBts: 0.016,
  latKs: 60e-6,
  latLayerExtra: 150e-6,
  slices: 9,
  slicesPrefill: 4,
};

export const GPU_FLOOR: AshiHardwareProfile = {
  id: "GPU_FLOOR",
  name: "8xB200, floor kernels",
  int8: 4.5e15,
  usdHr: 6.82,
  eff: 0.6,
  tKs: 1.5e-6,
  tBts: 0.018,
  latBts: 0.008,
  latKs: 25e-6,
  latLayerExtra: 60e-6,
  slices: 9,
  slicesPrefill: 4,
};

export const FHE_ASIC: AshiHardwareProfile = {
  id: "FHE_ASIC",
  name: "FHE ASIC, projected",
  int8: 2.5e14,
  usdHr: 3.0,
  eff: 0.6,
  tKs: 0.15e-6,
  tBts: 0.002,
  latBts: 0.0015,
  latKs: 4e-6,
  latLayerExtra: 20e-6,
  slices: 1,
  slicesPrefill: 1,
};

export const ASHI_HARDWARE_PROFILES: readonly AshiHardwareProfile[] = [
  GPU_TODAY,
  GPU_FLOOR,
  FHE_ASIC,
];

export interface DecodePerTokenBreakdown {
  ks: number;
  gemm: number;
  bts: number;
  state: number;
  total: number;
}

export function decodePerToken(
  m: AshiModelParams = DEFAULT_ASHI_MODEL,
  c: AshiCryptoParams = DEFAULT_ASHI_CRYPTO,
  h: AshiHardwareProfile = GPU_FLOOR,
  kS: number = Math.floor(c.slots / m.dPad)
): { parts: DecodePerTokenBreakdown; nBts: number } {
  const outCts = (width: number) => Math.ceil((width * kS) / c.slots);
  const pLayer = m.pTotal / m.layers;
  const upW = pLayer / 3 / m.d;
  const nUp = 2 * outCts(upW);
  const b = Math.sqrt(3 * nUp * m.dPad);
  const ksUp = b / 3 + (nUp * m.dPad) / b;
  const nDn = outCts(upW);
  const b2 = nDn ? Math.sqrt((3 * m.dPad) / nDn) : 1;
  const ksDn = (nDn * b2) / 3 + m.dPad / b2;
  const ksAttn = 4 * 2 * Math.sqrt(3 * m.dPad);
  const ksState = (2 * 2 * 128) / 3 + 2 * 128;
  const ksLayer = (ksUp + ksDn + ksAttn + ksState) / kS;
  const tKs = ksLayer * m.layers * h.tKs;

  const gemmOps = 2 * m.pTotal * 2 * c.limbsLin * h.slices;
  const tGemm = gemmOps / (h.int8 * h.eff);

  const nBts = Math.ceil((m.layers * m.levelsPerLayer) / c.levelsPerBts);
  const tBts = (nBts * h.tBts) / kS;

  const tState = (m.layers * m.statePerLayer * 12 * 6) / (h.int8 * 0.05);
  const total = tKs + tGemm + tBts + tState;

  return {
    parts: { ks: tKs, gemm: tGemm, bts: tBts, state: tState, total },
    nBts,
  };
}

export function passLatency(
  m: AshiModelParams = DEFAULT_ASHI_MODEL,
  c: AshiCryptoParams = DEFAULT_ASHI_CRYPTO,
  h: AshiHardwareProfile = GPU_FLOOR
): number {
  const nBts = Math.ceil((m.layers * m.levelsPerLayer) / c.levelsPerBts);
  const seqKsPerLayer = 6;
  return (
    nBts * h.latBts +
    m.layers * (seqKsPerLayer * h.latKs + h.latLayerExtra)
  );
}

export function prefillPerToken(
  m: AshiModelParams = DEFAULT_ASHI_MODEL,
  c: AshiCryptoParams = DEFAULT_ASHI_CRYPTO,
  h: AshiHardwareProfile = GPU_FLOOR
): { gemm: number; bts: number; state: number; total: number } {
  const gemm =
    (2 * m.pTotal * 2 * c.limbsLin * h.slicesPrefill) / (h.int8 * h.eff);
  const nBts = Math.ceil((m.layers * m.levelsPerLayer) / c.levelsPerBts);
  const bts = (nBts * h.tBts * m.d) / c.slots;
  const state =
    ((m.layers * m.statePerLayer * Math.log2(c.slots)) / (c.slots / 2)) * h.tKs;
  return {
    gemm,
    bts,
    state,
    total: gemm + bts + state,
  };
}

export interface PshvSimulationResult {
  committedTokPerSec: number;
  wasteMultiplier: number;
  pipelineDepth: number;
  deviceSecondsPerToken: number;
  usdPerMillionOutputTokens: number;
  devicesPerStream: number;
  prefillCost: {
    full1M: {
      deviceHours: number;
      usd: number;
      minutesOn1024Devices: number;
    };
    lazy150K: {
      deviceHours: number;
      usd: number;
      minutesOn1024Devices: number;
    };
  };
  constantStateGb: number;
  fullKvCacheTbAt1M: number;
}

/**
 * Exact renewal-process expectation of the Pipelined Speculative Homomorphic Verification
 * (PSHV) simulator from `fhe-frontier/proto/sim_spec.py`.
 */
export function simulatePshvCore(
  alpha: number,
  tPass: number,
  k: number = 8,
  m: number = 4,
  rtt: number = 0.04,
  rDraft: number = 150.0
): { committedTokPerSec: number; wasteMultiplier: number } {
  const clampedAlpha = Math.max(0.01, Math.min(0.9999, alpha));
  const span = m * k;

  const doneTimes: number[] = [];
  for (let p = 0; p < m; p++) {
    const ready = ((p + 1) * k) / rDraft;
    const send = Math.max(ready, p * (tPass / m));
    const done = send + rtt + tPass;
    doneTimes.push(done);
  }

  let expectedCommitted = 0;
  let expectedTime = 0;

  for (let nOk = 0; nOk < span; nOk++) {
    const prob = Math.pow(clampedAlpha, nOk) * (1 - clampedAlpha);
    const pRej = Math.floor(nOk / k);
    expectedCommitted += prob * (nOk + 1);
    expectedTime += prob * doneTimes[pRej];
  }

  const probAllAccepted = Math.pow(clampedAlpha, span);
  expectedCommitted += probAllAccepted * span;
  expectedTime += probAllAccepted * doneTimes[m - 1];

  const expectedVerified = span;
  const committedTokPerSec = expectedCommitted / expectedTime;
  const wasteMultiplier = expectedVerified / expectedCommitted;

  return { committedTokPerSec, wasteMultiplier };
}

export function simulatePshv(
  alpha: number,
  tPass: number,
  k: number = 8,
  m: number = 4,
  rtt: number = 0.04,
  hardware: AshiHardwareProfile = GPU_FLOOR,
  model: AshiModelParams = DEFAULT_ASHI_MODEL,
  crypto: AshiCryptoParams = DEFAULT_ASHI_CRYPTO
): PshvSimulationResult {
  const { committedTokPerSec, wasteMultiplier } = simulatePshvCore(
    alpha,
    tPass,
    k,
    m,
    rtt
  );
  const kS = Math.floor(crypto.slots / model.dPad);
  const { parts } = decodePerToken(model, crypto, hardware, kS);
  const perVerified = parts.total;
  const deviceSecondsPerToken = perVerified * wasteMultiplier;
  const usdPerMillionOutputTokens =
    ((deviceSecondsPerToken * hardware.usdHr) / 3600) * 1e6;
  const devicesPerStream = Math.round(
    deviceSecondsPerToken * Math.min(committedTokPerSec, 50)
  );

  const pf = prefillPerToken(model, crypto, hardware);
  const full1MSeconds = pf.total * 1_000_000;
  const lazy150KSeconds = pf.total * 150_000;

  const constantStateGb =
    (model.layers * model.statePerLayer * 16 * 3) / 1e9;
  const fullKvCacheTbAt1M = (1e6 * model.layers * 576 * 48) / 1e12;

  return {
    committedTokPerSec,
    wasteMultiplier,
    pipelineDepth: m,
    deviceSecondsPerToken,
    usdPerMillionOutputTokens,
    devicesPerStream,
    prefillCost: {
      full1M: {
        deviceHours: full1MSeconds / 3600,
        usd: (full1MSeconds * hardware.usdHr) / 3600,
        minutesOn1024Devices: full1MSeconds / 1024 / 60,
      },
      lazy150K: {
        deviceHours: lazy150KSeconds / 3600,
        usd: (lazy150KSeconds * hardware.usdHr) / 3600,
        minutesOn1024Devices: lazy150KSeconds / 1024 / 60,
      },
    },
    constantStateGb,
    fullKvCacheTbAt1M,
  };
}

export interface AshiProfileEvaluation {
  name: string;
  passLatencyMs: number;
  decodeVerifiedMs: {
    ks: number;
    gemm: number;
    bts: number;
    state: number;
    total: number;
  };
  committedTokPerSec: number;
  wasteMultiplier: number;
  usdPerMillionOutputTokens: number;
  devicesPerStream: number;
  prefillLazy150kUsd: number;
  prefillLazy150kMinutesOn1024: number;
}

export interface AshiTierCEvaluation {
  stateGb: number;
  fullKvCacheTbAt1M: number;
  lazyMoeKeySwitchReduction: string;
  bootstrapsPerPass: number;
  profiles: AshiProfileEvaluation[];
}

export function evaluateAshiTierC(
  overrides?: Partial<{ alpha: number; contextTokens: number }>
): AshiTierCEvaluation {
  const alpha = overrides?.alpha ?? 0.95;
  const contextTokens = overrides?.contextTokens ?? 1_000_000;
  const model = DEFAULT_ASHI_MODEL;
  const crypto = DEFAULT_ASHI_CRYPTO;
  const kS = Math.floor(crypto.slots / model.dPad);

  const stateGb = Number(
    ((model.layers * model.statePerLayer * 16 * 3) / 1e9).toFixed(2)
  );
  const fullKvCacheTbAt1M = Number(
    ((contextTokens * model.layers * 576 * 48) / 1e12).toFixed(2)
  );
  const bootstrapsPerPass = Math.ceil(
    (model.layers * model.levelsPerLayer) / crypto.levelsPerBts
  );

  const profiles: AshiProfileEvaluation[] = ASHI_HARDWARE_PROFILES.map((h) => {
    const { parts } = decodePerToken(model, crypto, h, kS);
    const tPass = passLatency(model, crypto, h);

    const pshv = simulatePshv(
      alpha,
      tPass,
      8,
      4,
      0.04,
      h,
      model,
      crypto
    );

    return {
      name: h.name,
      passLatencyMs: Number((tPass * 1e3).toFixed(1)),
      decodeVerifiedMs: {
        ks: Number((parts.ks * 1e3).toFixed(1)),
        gemm: Number((parts.gemm * 1e3).toFixed(1)),
        bts: Number((parts.bts * 1e3).toFixed(1)),
        state: Number((parts.state * 1e3).toFixed(1)),
        total: Number((parts.total * 1e3).toFixed(1)),
      },
      committedTokPerSec: Number(pshv.committedTokPerSec.toFixed(1)),
      wasteMultiplier: Number(pshv.wasteMultiplier.toFixed(2)),
      usdPerMillionOutputTokens: Number(
        pshv.usdPerMillionOutputTokens.toFixed(0)
      ),
      devicesPerStream: pshv.devicesPerStream,
      prefillLazy150kUsd: Number(
        pshv.prefillCost.lazy150K.usd.toFixed(1)
      ),
      prefillLazy150kMinutesOn1024: Number(
        pshv.prefillCost.lazy150K.minutesOn1024Devices.toFixed(2)
      ),
    };
  });

  return {
    stateGb,
    fullKvCacheTbAt1M,
    lazyMoeKeySwitchReduction: "~200x fewer key switches (1.45M wide intermediate -> d=7168 narrow relinearization)",
    bootstrapsPerPass,
    profiles,
  };
}
