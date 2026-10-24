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
  /** Initial cumulative log-likelihood ratio from prior sequential observations. Default: 0 */
  initialLlr?: number;
}

export interface SprtAuditResult {
  verdict: SprtVerdict;
  logLikelihoodRatio: number;
  upperBoundA: number;
  lowerBoundB: number;
  probesEvaluated: number;
  empiricalPassRate: number;
}

/**
 * Runs Wald's Sequential Probability Ratio Test (SPRT) over a stream of
 * mystery-shopper calibration probes.
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
  const initialLlr = opts?.initialLlr ?? 0;

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

  let llr = Number.isFinite(initialLlr) ? initialLlr : 0;
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
