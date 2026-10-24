/**
 * Spec §4 Parameters, §5 Session open step 2, §8.6 Economics, §8.7 Weak signals, §V8 Canary realism
 */

export const UNVERIFIED_OPERATOR_CAP_PCT = 0.5; // 50 bps
export const VERIFIED_OPERATOR_CAP_PCT = 2.0; // 200 bps
export const UNVERIFIED_OPERATOR_CAP_BPS = 50;
export const VERIFIED_OPERATOR_CAP_BPS = 200;
export const OPERATOR_UNBONDING_PERIOD_DAYS = 180;
export const MIN_CC_OVERHEAD_PCT = 3.0;

export interface OperatorNodeInput {
  nodeId: string;
  operatorId: string;
  operatorVerified: boolean;
  rawWeight: number;
}

export interface OperatorNodeShareResult {
  nodeId: string;
  operatorId: string;
  effectiveSharePct: number;
  capped: boolean;
}

/**
 * Spec §4 & §5: Operator share-cap scaler.
 * - Unverified operators are capped at 0.5% (50 bps) of total network capacity weight.
 * - Remote-verified operators are capped at 2.0% (200 bps) of total network capacity weight.
 * - Iteratively caps any operator whose combined node share exceeds its cap and redistributes
 *   excess share across remaining uncapped operators up to their respective caps.
 */
export function applyOperatorShareCaps(
  nodes: OperatorNodeInput[],
): OperatorNodeShareResult[] {
  if (nodes.length === 0) {
    return [];
  }

  const totalRaw = nodes.reduce((sum, n) => sum + Math.max(0, n.rawWeight), 0);
  if (totalRaw <= 0) {
    return nodes.map((n) => ({
      nodeId: n.nodeId,
      operatorId: n.operatorId,
      effectiveSharePct: 0,
      capped: false,
    }));
  }

  interface OperatorGroup {
    operatorId: string;
    verified: boolean;
    capPct: number;
    rawWeight: number;
    sharePct: number;
    capped: boolean;
  }

  const operators = new Map<string, OperatorGroup>();
  for (const node of nodes) {
    const w = Math.max(0, node.rawWeight);
    const existing = operators.get(node.operatorId);
    if (existing) {
      existing.rawWeight += w;
      existing.verified = existing.verified && node.operatorVerified;
      existing.capPct = existing.verified
        ? VERIFIED_OPERATOR_CAP_PCT
        : UNVERIFIED_OPERATOR_CAP_PCT;
    } else {
      const verified = node.operatorVerified;
      operators.set(node.operatorId, {
        operatorId: node.operatorId,
        verified,
        capPct: verified ? VERIFIED_OPERATOR_CAP_PCT : UNVERIFIED_OPERATOR_CAP_PCT,
        rawWeight: w,
        sharePct: 0,
        capped: false,
      });
    }
  }

  // Initial raw percentage share across operators
  for (const op of operators.values()) {
    op.sharePct = (op.rawWeight / totalRaw) * 100;
  }

  const EPSILON = 1e-9;

  // Iterative water-filling / share capping
  while (true) {
    let excessPct = 0;
    let newlyCapped = false;

    for (const op of operators.values()) {
      if (!op.capped && op.sharePct > op.capPct + EPSILON) {
        excessPct += op.sharePct - op.capPct;
        op.sharePct = op.capPct;
        op.capped = true;
        newlyCapped = true;
      }
    }

    if (!newlyCapped || excessPct <= EPSILON) {
      break;
    }

    const uncappedOps = Array.from(operators.values()).filter(
      (op) => !op.capped && op.rawWeight > 0,
    );
    const uncappedRawSum = uncappedOps.reduce((sum, op) => sum + op.rawWeight, 0);

    if (uncappedRawSum <= 0) {
      break;
    }

    for (const op of uncappedOps) {
      op.sharePct += excessPct * (op.rawWeight / uncappedRawSum);
    }
  }

  // Split each operator's effective share across its constituent nodes proportionally
  const nodeCountByOperator = new Map<string, number>();
  for (const node of nodes) {
    nodeCountByOperator.set(
      node.operatorId,
      (nodeCountByOperator.get(node.operatorId) ?? 0) + 1,
    );
  }

  return nodes.map((node) => {
    const op = operators.get(node.operatorId)!;
    const w = Math.max(0, node.rawWeight);
    const nodeFraction =
      op.rawWeight > 0
        ? w / op.rawWeight
        : 1 / (nodeCountByOperator.get(node.operatorId) ?? 1);
    const effectiveSharePct = Number((op.sharePct * nodeFraction).toFixed(6));

    return {
      nodeId: node.nodeId,
      operatorId: node.operatorId,
      effectiveSharePct,
      capped: op.capped,
    };
  });
}

export interface StakeSizingParams {
  estimatedLeakGainUsdc: number;
  canaryRate: number;
  sessionsBeforeMisuseUse: number;
}

export interface StakeSizingResult {
  minStakeUsdc: number;
  detectionProbability: number;
}

/**
 * Spec §8.6: Minimum economic stake sizing formula.
 * detectionProbability = 1 - (1 - canaryRate)^sessionsBeforeMisuseUse
 * minStakeUsdc = ceil(estimatedLeakGainUsdc / detectionProbability)
 */
export function requiredNodeStakeUsdc(params: StakeSizingParams): StakeSizingResult {
  const { estimatedLeakGainUsdc, canaryRate, sessionsBeforeMisuseUse } = params;
  const clampedRate = Math.min(1, Math.max(0, canaryRate));
  const sessions = Math.max(1, sessionsBeforeMisuseUse);
  const detectionProbability = 1 - Math.pow(1 - clampedRate, sessions);

  if (detectionProbability <= 0) {
    return {
      minStakeUsdc: Number.POSITIVE_INFINITY,
      detectionProbability: 0,
    };
  }

  const minStakeUsdc = Math.ceil(estimatedLeakGainUsdc / detectionProbability);
  return {
    minStakeUsdc,
    detectionProbability,
  };
}

export interface TimingSignalEvaluation {
  flaggedForVerifierReview: boolean;
  autoSlash: false;
  observedOverheadPct: number;
  detail: string;
}

/**
 * Spec §8.7: Weak-signal confidential-mode timing check.
 * Flags a node for human/verifier review if observed PCIe bounce-buffer encryption
 * overhead is suspiciously low (< 3%), while NEVER auto-slashing (`autoSlash: false`).
 */
export function evaluateTimingSignal(
  measuredMsPerToken: number,
  baselinePlaintextMsPerToken: number,
): TimingSignalEvaluation {
  if (baselinePlaintextMsPerToken <= 0) {
    return {
      flaggedForVerifierReview: true,
      autoSlash: false,
      observedOverheadPct: 0,
      detail: "Invalid baseline plaintext latency (<= 0 ms/token); queued for verifier review (no auto-slash).",
    };
  }

  const rawOverheadPct =
    ((measuredMsPerToken - baselinePlaintextMsPerToken) /
      baselinePlaintextMsPerToken) *
    100;
  const observedOverheadPct = Number(rawOverheadPct.toFixed(2));
  const flaggedForVerifierReview = rawOverheadPct < MIN_CC_OVERHEAD_PCT;

  return {
    flaggedForVerifierReview,
    autoSlash: false,
    observedOverheadPct,
    detail: flaggedForVerifierReview
      ? `Observed latency overhead ${observedOverheadPct}% is below expected >= ${MIN_CC_OVERHEAD_PCT}% CC PCIe encryption overhead; flagged for verifier review (autoSlash=false per Spec §8.7).`
      : `Observed latency overhead ${observedOverheadPct}% is consistent with active GPU Confidential Computing mode (>= ${MIN_CC_OVERHEAD_PCT}%).`,
  };
}

export interface CanaryScoreSample {
  isCanary: boolean;
  suspicionScore: number;
}

export interface CanaryRealismEvaluation {
  auc: number;
  v8Passed: boolean;
}

/**
 * Spec §Testing V8: Canary realism classifier ROC AUC evaluator.
 * Computes Mann-Whitney U ROC AUC over canary vs. organic traffic suspicion scores.
 * Passes V8 if |auc - 0.5| <= 0.1 (i.e. 0.4 <= auc <= 0.6).
 */
export function evaluateCanaryRealismAuc(
  scores: CanaryScoreSample[],
): CanaryRealismEvaluation {
  const canaries = scores.filter((s) => s.isCanary);
  const organics = scores.filter((s) => !s.isCanary);

  if (canaries.length === 0 || organics.length === 0) {
    return {
      auc: 0.5,
      v8Passed: true,
    };
  }

  let concordant = 0;
  for (const c of canaries) {
    for (const o of organics) {
      if (c.suspicionScore > o.suspicionScore) {
        concordant += 1;
      } else if (c.suspicionScore === o.suspicionScore) {
        concordant += 0.5;
      }
    }
  }

  const auc = Number((concordant / (canaries.length * organics.length)).toFixed(4));
  const v8Passed = Math.abs(auc - 0.5) <= 0.1;

  return {
    auc,
    v8Passed,
  };
}
