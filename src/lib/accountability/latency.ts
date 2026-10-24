export const VANTAGE_POINTS = ["eu-west", "us-east", "ap-south"] as const;
export type VantageRegion = (typeof VANTAGE_POINTS)[number];

/** Round-trip fiber propagation speed (~200 km/ms round-trip limit, Spec §8.6 / §5). */
export const FIBER_KM_PER_MS_RTT = 200;

/** Processing + serialization margin (ms) allowed above pure speed-of-light in fiber. */
export const ATTESTATION_PROCESSING_OVERHEAD_MS = 18;

/** Maximum allowed RTT (ms) from a co-located regional vantage point before relay suspicion. */
export const MAX_LOCAL_VANTAGE_RTT_MS = 25;

/** Approximate great-circle fiber distances (km) between the 3 verifier vantage regions. */
const INTER_REGION_DISTANCE_KM: Record<VantageRegion, Record<VantageRegion, number>> = {
  "eu-west": {
    "eu-west": 350,
    "us-east": 6200,
    "ap-south": 7400,
  },
  "us-east": {
    "eu-west": 6200,
    "us-east": 400,
    "ap-south": 13500,
  },
  "ap-south": {
    "eu-west": 7400,
    "us-east": 13500,
    "ap-south": 450,
  },
};

export interface VantageMeasurement {
  vantageRegion: VantageRegion;
  rttMs: number;
  distanceKm?: number;
}

export interface LatencyTriangulationResult {
  nodeId: string;
  declaredRegion: string;
  consistent: boolean;
  relayedSuspected: boolean;
  localRttMs: number | null;
  measurements: {
    vantageRegion: VantageRegion;
    distanceKm: number;
    measuredRttMs: number;
    minPhysicalRttMs: number;
    maxExpectedRttMs: number;
    status: "ok" | "too-fast-impossible" | "relay-delay";
  }[];
  reasons: string[];
  /** True for practice-network nodes whose RTTs are illustrative, not measured. */
  simulated?: boolean;
}

function normalizeRegion(region: string): VantageRegion {
  if (region === "eu-west") return "eu-west";
  if (region === "ap-south") return "ap-south";
  return "us-east";
}

export function evaluateLatencyTriangulation(input: {
  nodeId: string;
  declaredRegion: string;
  measurements: VantageMeasurement[];
}): LatencyTriangulationResult {
  const declared = normalizeRegion(input.declaredRegion);
  const reasons: string[] = [];
  let relayedSuspected = false;
  let localRttMs: number | null = null;

  const evaluated = input.measurements.map((m) => {
    const distanceKm =
      m.distanceKm ?? INTER_REGION_DISTANCE_KM[declared][m.vantageRegion];
    // Speed-of-light lower bound (~200 km/ms round-trip)
    const minPhysicalRttMs = Number(
      Math.max(1, distanceKm / FIBER_KM_PER_MS_RTT).toFixed(2),
    );
    // Upper bound accounts for routing detour factor (2.2x) + attestation signing overhead
    const maxExpectedRttMs =
      m.vantageRegion === declared
        ? MAX_LOCAL_VANTAGE_RTT_MS
        : Number((minPhysicalRttMs * 2.2 + ATTESTATION_PROCESSING_OVERHEAD_MS).toFixed(2));

    if (m.vantageRegion === declared) {
      localRttMs = m.rttMs;
    }

    let status: "ok" | "too-fast-impossible" | "relay-delay" = "ok";
    if (m.rttMs < minPhysicalRttMs * 0.8) {
      status = "too-fast-impossible";
      reasons.push(
        `Vantage ${m.vantageRegion}: measured RTT (${m.rttMs} ms) violates fiber speed-of-light lower bound (${minPhysicalRttMs} ms for ${distanceKm} km)`,
      );
    } else if (m.rttMs > maxExpectedRttMs) {
      status = "relay-delay";
      relayedSuspected = true;
      reasons.push(
        `Vantage ${m.vantageRegion}: measured RTT (${m.rttMs} ms) exceeds physical bound (${maxExpectedRttMs} ms for ${distanceKm} km); possible relayed attestation`,
      );
    }

    return {
      vantageRegion: m.vantageRegion,
      distanceKm,
      measuredRttMs: m.rttMs,
      minPhysicalRttMs,
      maxExpectedRttMs,
      status,
    };
  });

  return {
    nodeId: input.nodeId,
    declaredRegion: input.declaredRegion,
    consistent: reasons.length === 0,
    relayedSuspected,
    localRttMs,
    measurements: evaluated,
    reasons,
  };
}

/**
 * Practice-network triangulations. The round-trip times are illustrative, not measured,
 * so every result is marked `simulated: true`. The real router is measured separately
 * by `measureRouterRtt`.
 */
export function defaultLatencyTriangulations(): LatencyTriangulationResult[] {
  return ([
    evaluateLatencyTriangulation({
      nodeId: "sim-1",
      declaredRegion: "eu-west",
      measurements: [
        { vantageRegion: "eu-west", rttMs: 5.8 },
        { vantageRegion: "us-east", rttMs: 67.4 },
        { vantageRegion: "ap-south", rttMs: 81.0 },
      ],
    }),
    evaluateLatencyTriangulation({
      nodeId: "sim-2",
      declaredRegion: "us-east",
      measurements: [
        { vantageRegion: "us-east", rttMs: 7.1 },
        { vantageRegion: "eu-west", rttMs: 69.0 },
        { vantageRegion: "ap-south", rttMs: 144.2 },
      ],
    }),
    evaluateLatencyTriangulation({
      nodeId: "sim-3",
      declaredRegion: "ap-south",
      measurements: [
        { vantageRegion: "ap-south", rttMs: 6.9 },
        { vantageRegion: "eu-west", rttMs: 82.3 },
        { vantageRegion: "us-east", rttMs: 145.1 },
      ],
    }),
  ] as LatencyTriangulationResult[]).map((r) => ({ ...r, simulated: true }));
}

export interface RouterRttMeasurement {
  host: string;
  /** Vercel region the measurement ran from, or "local" outside Vercel. */
  vantage: string;
  bestRttMs: number;
  samplesMs: number[];
}

let cachedRouterRtt: { atMs: number; value: RouterRttMeasurement | null } | null = null;
const ROUTER_RTT_CACHE_MS = 10 * 60_000;

/**
 * Measures real round trips from this server to the Tinfoil router (best of 3 HEAD
 * requests on a kept-alive connection). This is a plain measurement with no
 * triangulation verdict: the router runs in a region outside the triangulation model.
 */
export async function measureRouterRtt(host = "inference.tinfoil.sh"): Promise<RouterRttMeasurement | null> {
  const now = Date.now();
  if (cachedRouterRtt && now - cachedRouterRtt.atMs < ROUTER_RTT_CACHE_MS) return cachedRouterRtt.value;
  const samplesMs: number[] = [];
  try {
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const res = await fetch(`https://${host}/.well-known/tinfoil-proxy`, {
        method: "HEAD",
        cache: "no-store",
        signal: AbortSignal.timeout(5_000),
      });
      await res.arrayBuffer().catch(() => undefined);
      samplesMs.push(Math.round((performance.now() - t0) * 10) / 10);
    }
  } catch {
    cachedRouterRtt = { atMs: now, value: null };
    return null;
  }
  const value: RouterRttMeasurement = {
    host,
    vantage: process.env.VERCEL_REGION ?? "local",
    bestRttMs: Math.min(...samplesMs),
    samplesMs,
  };
  cachedRouterRtt = { atMs: now, value };
  return value;
}
