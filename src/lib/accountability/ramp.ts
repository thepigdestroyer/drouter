export const HEARTBEAT_INTERVAL_SEC = 10;
export const RESTART_GAP_SEC = 60;
export const CANARY_ONLY_MIN_HOURS = 24;
export const CANARY_ONLY_MAX_HOURS = 96;
export const LINEAR_RAMP_HOURS = 72;

const DUAL_IDENTITY_WINDOW_SEC = 15;
const THIRTY_DAYS_SEC = 30 * 24 * 3600;

export interface HeartbeatEvent {
  nodeIdentityPk: string;
  timestamp: number;
}

export interface HeartbeatEvaluation {
  status: "full" | "ramp" | "suspended";
  restartsIn30d: number;
  dualIdentityDetected: boolean;
  weightBps: number;
  phase: "canary-only" | "linear-ramp" | "steady" | "suspended";
  detail: string;
}

export function evaluateHeartbeatWindow(
  events: { nodeIdentityPk: string; timestamp: number }[],
  nowSec: number,
  canaryOnlyHours: number = CANARY_ONLY_MIN_HOURS,
): HeartbeatEvaluation {
  if (events.length === 0) {
    return {
      status: "suspended",
      restartsIn30d: 0,
      dualIdentityDetected: false,
      weightBps: 0,
      phase: "suspended",
      detail: "No heartbeat events received; node is suspended (0 bps)",
    };
  }

  const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

  // Detect simultaneous dual identity keys within 15s of each other (Spec §8.2)
  let dualIdentityDetected = false;
  for (let i = 0; i < sorted.length; i++) {
    for (let j = i + 1; j < sorted.length; j++) {
      if (sorted[j].timestamp - sorted[i].timestamp > DUAL_IDENTITY_WINDOW_SEC) {
        break;
      }
      if (sorted[i].nodeIdentityPk !== sorted[j].nodeIdentityPk) {
        dualIdentityDetected = true;
        break;
      }
    }
    if (dualIdentityDetected) break;
  }

  // Detect restart transitions (any gap > 60s or change in nodeIdentityPk)
  const restartTimestamps: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const curr = sorted[i];
    const gap = curr.timestamp - prev.timestamp;
    const pkChanged = curr.nodeIdentityPk !== prev.nodeIdentityPk;
    if (gap > RESTART_GAP_SEC || pkChanged) {
      restartTimestamps.push(curr.timestamp);
    }
  }

  const windowStartSec = nowSec - THIRTY_DAYS_SEC;
  const recentRestarts = restartTimestamps.filter(
    (ts) => ts >= windowStartSec && ts <= nowSec,
  );
  const restartsIn30d = recentRestarts.length;

  if (dualIdentityDetected) {
    return {
      status: "suspended",
      restartsIn30d,
      dualIdentityDetected: true,
      weightBps: 0,
      phase: "suspended",
      detail:
        "Cloned key / impossible behavior: two distinct nodeIdentityPk values observed within 15s",
    };
  }

  if (restartsIn30d === 0) {
    return {
      status: "full",
      restartsIn30d: 0,
      dualIdentityDetected: false,
      weightBps: 10000,
      phase: "steady",
      detail: "Continuous heartbeat stream with 0 restarts in 30d; full weight (10000 bps)",
    };
  }

  const clampedCanaryHours = Math.min(
    CANARY_ONLY_MAX_HOURS,
    Math.max(CANARY_ONLY_MIN_HOURS, canaryOnlyHours),
  );
  const latestRestartTs = recentRestarts[recentRestarts.length - 1];
  const elapsedSec = Math.max(0, nowSec - latestRestartTs);
  const elapsedHours = elapsedSec / 3600;

  if (elapsedHours < clampedCanaryHours) {
    return {
      status: "ramp",
      restartsIn30d,
      dualIdentityDetected: false,
      weightBps: 0,
      phase: "canary-only",
      detail: `Canary-only phase (${elapsedHours.toFixed(1)}h / ${clampedCanaryHours}h after restart); 0 bps real user traffic (100% canary probes)`,
    };
  }

  const rampElapsedHours = elapsedHours - clampedCanaryHours;
  if (rampElapsedHours < LINEAR_RAMP_HOURS) {
    const rawWeight = Math.round((rampElapsedHours / LINEAR_RAMP_HOURS) * 10000);
    const weightBps = restartsIn30d > 2 ? Math.round(rawWeight / 2) : rawWeight;
    return {
      status: "ramp",
      restartsIn30d,
      dualIdentityDetected: false,
      weightBps,
      phase: "linear-ramp",
      detail: `Linear ramp (${rampElapsedHours.toFixed(1)}h / ${LINEAR_RAMP_HOURS}h, ${restartsIn30d} restart(s) in 30d${restartsIn30d > 2 ? ", halved for >2 restarts" : ""}): ${weightBps} bps`,
    };
  }

  const steadyWeight = restartsIn30d > 2 ? 5000 : 10000;
  return {
    status: restartsIn30d > 2 ? "ramp" : "full",
    restartsIn30d,
    dualIdentityDetected: false,
    weightBps: steadyWeight,
    phase: "steady",
    detail:
      restartsIn30d > 2
        ? `Post-ramp steady phase with ${restartsIn30d} restarts in 30d (>2 threshold): weight halved to ${steadyWeight} bps`
        : `Post-ramp steady state (${restartsIn30d} restart(s) in 30d): full weight (${steadyWeight} bps)`,
  };
}
