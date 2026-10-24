import { MongoClient, type Db } from "mongodb";
import { coarsenToHour } from "@/lib/db";
import type { AuditorRunRecord } from "./canary";

const globalForAuditor = globalThis as unknown as {
  __drouterAuditorRuns?: AuditorRunRecord[];
  __drouterAuditorMongo?: Promise<MongoClient>;
};

function memoryRuns(): AuditorRunRecord[] {
  globalForAuditor.__drouterAuditorRuns ??= [];
  return globalForAuditor.__drouterAuditorRuns;
}

async function getAuditorDb(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  try {
    globalForAuditor.__drouterAuditorMongo ??= new MongoClient(uri, {
      appName: "drouter-demo-auditor",
      maxPoolSize: 5,
      serverSelectionTimeoutMS: 3000,
    }).connect();
    const client = await globalForAuditor.__drouterAuditorMongo;
    return client.db(process.env.MONGODB_DB ?? "drouter");
  } catch {
    return null;
  }
}

/**
 * Sanitizes and stores an aggregate auditor run record in `auditor_runs`.
 * Guarantees that only coarse UTC hours and aggregate statistics are persisted.
 */
export async function saveAuditorRun(record: AuditorRunRecord): Promise<{
  storedInMongo: boolean;
  sanitized: AuditorRunRecord;
}> {
  const sanitized: AuditorRunRecord = {
    model: String(record.model).slice(0, 80),
    passed: Boolean(record.passed),
    verdict: record.verdict,
    sprtStatistic: Number(record.sprtStatistic),
    cumulativeSprtStatistic: Number(record.cumulativeSprtStatistic),
    upperBoundA: Number(record.upperBoundA),
    lowerBoundB: Number(record.lowerBoundB),
    probesCount: Number(record.probesCount),
    passedCount: Number(record.passedCount),
    empiricalPassRate: Number(record.empiricalPassRate),
    meanLatencyMs: Number(record.meanLatencyMs),
    enclaveHost: String(record.enclaveHost).slice(0, 120),
    at: coarsenToHour(record.at instanceof Date ? record.at : new Date(record.at)),
  };

  const mem = memoryRuns();
  mem.unshift(sanitized);
  if (mem.length > 100) {
    mem.length = 100;
  }

  let storedInMongo = false;
  const db = await getAuditorDb();
  if (db) {
    try {
      await db.collection<AuditorRunRecord>("auditor_runs").insertOne({ ...sanitized });
      storedInMongo = true;
    } catch {
      // Best-effort MongoDB persistence
    }
  }

  return { storedInMongo, sanitized };
}

/**
 * Fetches recent real auditor runs from `auditor_runs` (or in-memory store when Mongo is unavailable).
 * Never returns fabricated runs. If no runs exist yet, returns `hasRun: false`, `latestRun: null`, `history: []`.
 */
export async function getAuditorRunsHistory(limit = 25): Promise<{
  mongoConfigured: boolean;
  hasRun: boolean;
  statusMessage: string;
  latestRun: AuditorRunRecord | null;
  history: AuditorRunRecord[];
}> {
  const cappedLimit = Math.min(100, Math.max(1, limit));
  const db = await getAuditorDb();
  let runs: AuditorRunRecord[] = [];

  if (db) {
    try {
      const docs = await db
        .collection<AuditorRunRecord>("auditor_runs")
        .find({}, { projection: { _id: 0 } })
        .sort({ at: -1 })
        .limit(cappedLimit)
        .toArray();
      runs = docs.map((d) => ({
        ...d,
        at: coarsenToHour(d.at instanceof Date ? d.at : new Date(d.at)),
      }));
    } catch {
      runs = memoryRuns().slice(0, cappedLimit);
    }
  } else {
    runs = memoryRuns().slice(0, cappedLimit);
  }

  const latestRun = runs[0] ?? null;
  const hasRun = runs.length > 0;
  const statusMessage = hasRun
    ? `Latest real SPRT audit on ${latestRun.model}: ${latestRun.verdict} (${latestRun.passedCount}/${latestRun.probesCount} canary probes passed, cumulative LLR ${latestRun.cumulativeSprtStatistic.toFixed(3)}).`
    : "No real mystery-shopper audit run has been recorded yet. Trigger GET /api/cron/auditor with Authorization: Bearer <CRON_SECRET> to execute a live enclave audit.";

  return {
    mongoConfigured: Boolean(process.env.MONGODB_URI),
    hasRun,
    statusMessage,
    latestRun,
    history: runs,
  };
}

/**
 * Clears in-memory auditor runs (used by unit tests).
 */
export function clearMemoryAuditorRuns(): void {
  memoryRuns().length = 0;
}
