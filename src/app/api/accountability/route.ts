import { connection } from "next/server";
import {
  computeRealRampStatesFromHistory,
  filterRealRegistryNodes,
  getMonitorRunsHistory,
  measureRouterRtt,
  type RecordedMonitorFailure,
  type ReleaseChangeEvaluation,
} from "@/lib/accountability";
import {
  ARC_EXPLORER,
  explorerAddress,
  explorerTx,
  listNodes,
} from "@/lib/arc/registry";
import { getAuditorRunsHistory } from "@/lib/auditor";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import { getPersistedTransparencyLog } from "@/lib/transparency/store";

const DEFAULT_MIN_STAKE_USDC = "0.01";

const getLimiter = createTokenBucketLimiter({
  name: "accountability-get",
  capacity: 60,
  refillPerSec: 2,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }

  let limit = 25;
  if (request) {
    try {
      const url = new URL(request.url, "http://localhost");
      const rawLimit = url.searchParams.get("limit");
      if (rawLimit) {
        const parsed = Number(rawLimit);
        if (Number.isInteger(parsed) && parsed > 0) {
          limit = Math.min(100, parsed);
        }
      }
    } catch {
      // Ignore malformed query string
    }
  }

  const [monitorHistory, auditorState, transparencyState, registry, routerLatency] =
    await Promise.all([
      getMonitorRunsHistory(limit),
      getAuditorRunsHistory(10),
      getPersistedTransparencyLog(),
      listNodes(),
      measureRouterRtt(),
    ]);

  const realRegistryNodes = filterRealRegistryNodes(registry.nodes);
  const rampStates = computeRealRampStatesFromHistory(monitorHistory.history);

  const failures: RecordedMonitorFailure[] = [];
  const releaseChanges: Array<ReleaseChangeEvaluation & { epochHourSec: number }> = [];

  for (const run of monitorHistory.history) {
    for (const f of run.failures) {
      if (failures.length < 50) {
        failures.push(f);
      }
    }
    for (const rc of run.releaseChanges) {
      if (rc.changed && releaseChanges.length < 50) {
        releaseChanges.push({
          ...rc,
          epochHourSec: run.epochHourSec,
        });
      }
    }
  }

  const latestFailureTx = failures.find((f) => Boolean(f.txHash))?.txHash ?? null;
  const latestTx =
    latestFailureTx ??
    monitorHistory.latestRun?.anchorTx ??
    transparencyState.signedTreeHead.anchorTx ??
    null;

  const explorerUrl = latestTx
    ? explorerTx(latestTx)
    : registry.address
      ? explorerAddress(registry.address)
      : ARC_EXPLORER;

  return Response.json({
    mongoConfigured: monitorHistory.mongoConfigured,
    hasRun: monitorHistory.hasRun,
    statusMessage: monitorHistory.statusMessage,
    latestRun: monitorHistory.latestRun,
    history: monitorHistory.history,
    enclaves: monitorHistory.latestRun?.enclaves ?? [],
    releaseChanges,
    failures,
    auditor: {
      hasRun: auditorState.hasRun,
      statusMessage: auditorState.statusMessage,
      latestRun: auditorState.latestRun,
    },
    signedTreeHead: transparencyState.signedTreeHead,
    rampStates,
    routerLatency,
    registrySource: registry.source,
    registryNodes: realRegistryNodes,
    minStakeUsdc: registry.minStake ?? DEFAULT_MIN_STAKE_USDC,
    txHash: latestTx,
    explorerUrl,
    onChain: registry.onChain,
  });
}
