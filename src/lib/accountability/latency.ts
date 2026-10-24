export interface RouterRttMeasurement {
  host: string;
  /** Vercel region the measurement ran from, or "local" outside Vercel. */
  vantage: string;
  bestRttMs: number;
  samplesMs: number[];
}

let cachedRouterRtt: { atMs: number; value: RouterRttMeasurement | null } | null = null;
const ROUTER_RTT_CACHE_MS = 10 * 60_000;

export function resetRouterRttCacheForTests(): void {
  cachedRouterRtt = null;
}

/**
 * Measures real round trips from this server to the Tinfoil router (best of 3 HEAD
 * requests on a kept-alive connection).
 */
export async function measureRouterRtt(
  host = "inference.tinfoil.sh",
  fetchImpl: typeof fetch = fetch,
): Promise<RouterRttMeasurement | null> {
  const useDefaultFetch = fetchImpl === fetch;
  const now = Date.now();
  if (useDefaultFetch && cachedRouterRtt && now - cachedRouterRtt.atMs < ROUTER_RTT_CACHE_MS) {
    return cachedRouterRtt.value;
  }
  const samplesMs: number[] = [];
  try {
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const res = await fetchImpl(`https://${host}/.well-known/tinfoil-proxy`, {
        method: "HEAD",
        cache: "no-store",
        signal: AbortSignal.timeout(5_000),
      });
      await res.arrayBuffer().catch(() => undefined);
      samplesMs.push(Math.round((performance.now() - t0) * 10) / 10);
    }
  } catch {
    if (useDefaultFetch) {
      cachedRouterRtt = { atMs: now, value: null };
    }
    return null;
  }
  const value: RouterRttMeasurement = {
    host,
    vantage: process.env.VERCEL_REGION ?? "local",
    bestRttMs: Math.min(...samplesMs),
    samplesMs,
  };
  if (useDefaultFetch) {
    cachedRouterRtt = { atMs: now, value };
  }
  return value;
}
