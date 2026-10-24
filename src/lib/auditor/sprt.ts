export type SprtVerdict =
  | "PASS_GENUINE_FRONTIER_MODEL"
  | "SLASH_MODEL_DOWNGRADE_DETECTED"
  | "CONTINUE_SAMPLING";

export interface AuditProbeInput {
  probeId: string;
  passed: boolean;
  latencyMs: number;
}

export interface MysteryShopperProbe extends AuditProbeInput {
  category: string;
}

export interface SprtAuditOptions {
  /** Baseline pass rate of the genuine frontier model (kimi-k3 2.8T MoE). Default: 0.90 */
  p0?: number;
  /** Degraded pass rate of a cheaper substitute/distill model (e.g. 8B/70B). Default: 0.45 */
  p1?: number;
  /** False-positive slash rate (Type I error). Default: 0.001 */
  alpha?: number;
  /** False-negative miss rate (Type II error). Default: 0.01 */
  beta?: number;
}

export interface SprtAuditResult {
  verdict: SprtVerdict;
  logLikelihoodRatio: number;
  upperBoundA: number;
  lowerBoundB: number;
  probesEvaluated: number;
  empiricalPassRate: number;
}

const CALIBRATION_CATEGORIES = [
  "multi-hop-formal-logic",
  "cryptographic-invariant-synthesis",
  "long-horizon-code-verification",
  "symbolic-tensor-calculus",
  "adversarial-constraint-satisfaction",
] as const;

/**
 * Runs Wald's Sequential Probability Ratio Test (SPRT) over a stream of
 * anonymous mystery-shopper calibration probes.
 *
 * H0 (honest frontier model): pass probability = p0 (default 0.90)
 * H1 (cheating substitute model): pass probability = p1 (default 0.45)
 */
export function runSprtModelAudit(
  probes: { probeId: string; passed: boolean; latencyMs: number }[],
  opts?: SprtAuditOptions,
): SprtAuditResult {
  const p0 = opts?.p0 ?? 0.9;
  const p1 = opts?.p1 ?? 0.45;
  const alpha = opts?.alpha ?? 0.001;
  const beta = opts?.beta ?? 0.01;

  if (p0 <= 0 || p0 >= 1 || p1 <= 0 || p1 >= 1) {
    throw new Error("SPRT pass probabilities p0 and p1 must be in (0, 1)");
  }
  if (alpha <= 0 || alpha >= 1 || beta <= 0 || beta >= 1) {
    throw new Error("SPRT error bounds alpha and beta must be in (0, 1)");
  }

  const upperBoundA = Math.log((1 - beta) / alpha);
  const lowerBoundB = Math.log(beta / (1 - alpha));

  const logPassRatio = Math.log(p1 / p0);
  const logFailRatio = Math.log((1 - p1) / (1 - p0));

  let llr = 0;
  let probesEvaluated = 0;
  let passedCount = 0;
  let verdict: SprtVerdict = "CONTINUE_SAMPLING";

  for (const probe of probes) {
    probesEvaluated += 1;
    if (probe.passed) {
      passedCount += 1;
      llr += logPassRatio;
    } else {
      llr += logFailRatio;
    }

    if (llr >= upperBoundA) {
      verdict = "SLASH_MODEL_DOWNGRADE_DETECTED";
      break;
    }
    if (llr <= lowerBoundB) {
      verdict = "PASS_GENUINE_FRONTIER_MODEL";
      break;
    }
  }

  const empiricalPassRate =
    probesEvaluated > 0 ? passedCount / probesEvaluated : 0;

  return {
    verdict,
    logLikelihoodRatio: llr,
    upperBoundA,
    lowerBoundB,
    probesEvaluated,
    empiricalPassRate,
  };
}

/**
 * Generates deterministic, realistic mystery-shopper calibration probe streams
 * for either an honest `kimi-k3` (2.8T MoE, ~90% pass rate) provider or a
 * cheating provider that swapped in an 8B model (~35-45% pass rate on hard
 * calibration prompts).
 */
export function generateMysteryShopperProbes(
  mode: "honest-kimi-k3" | "cheating-8b-swap",
  count = 15,
): MysteryShopperProbe[] {
  // Deterministic pass patterns reflecting p0 ≈ 0.90 vs p1 ≤ 0.45
  const honestPattern = [
    true,
    true,
    true,
    true,
    true,
    false,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
  ];

  const cheatingPattern = [
    false,
    true,
    false,
    false,
    false,
    true,
    false,
    false,
    false,
    true,
    false,
    false,
    true,
    false,
    false,
  ];

  const pattern = mode === "honest-kimi-k3" ? honestPattern : cheatingPattern;
  const probes: MysteryShopperProbe[] = [];

  for (let i = 0; i < count; i++) {
    const passed = pattern[i % pattern.length];
    const category = CALIBRATION_CATEGORIES[i % CALIBRATION_CATEGORIES.length];
    const baseLatency = mode === "honest-kimi-k3" ? 640 : 185;
    const jitter = ((i * 37) % 55) - 25;

    probes.push({
      probeId: `probe-${mode}-${String(i + 1).padStart(3, "0")}`,
      category,
      passed,
      latencyMs: baseLatency + jitter,
    });
  }

  return probes;
}
