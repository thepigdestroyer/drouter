import { MongoClient, type Collection, type Db } from "mongodb";
import { coarsenToHour, EPHEMERAL_LOG_TTL_SECONDS } from "@/lib/db";
import { resolveDbName } from "@/lib/mongo/db-name";
import { coarsenEpochSecToHour } from "@/lib/transparency/log";
import type { Hex } from "@/lib/types";

export const MONITOR_RUNS_COLLECTION = "monitor_runs";

export type ReleaseChangeKind =
  | "initial"
  | "unchanged"
  | "release-upgrade"
  | "unannounced-restart"
  | "rolling-release-skew"
  | "unannounced-measurement-change";

export interface ReleaseChangeEvaluation {
  nodeId: string;
  changed: boolean;
  unannounced: boolean;
  kind: ReleaseChangeKind;
  previousTag: string | null;
  currentTag: string;
  previousMeasurement: string | null;
  currentMeasurement: string;
  previousHosts: string[];
  currentHosts: string[];
  hostCodeTags: Record<string, string>;
  detail: string;
}

export interface MonitoredEnclaveRecord {
  nodeId: string;
  nodeKind: "tinfoil";
  role: "router" | "model";
  repo: string;
  releaseTag: string;
  releaseDigest: string;
  measurement: string;
  measurementRegisters: string[];
  dmVerityRootHash: string;
  enclaveHost: string;
  enclaveHosts: {
    host: string;
    hpkeKey: string;
    tlsKeyFp: string;
    codeTag: string;
  }[];
  configuredHosts: number;
  verifiedHosts: number;
  healthyHosts: number;
  unverifiedHosts: number;
  attestationChainOk: boolean;
  attestationDetail: string;
  measurementMatchesRelease: boolean;
  measurementDetail: string;
  modelProvenanceOk: boolean;
  modelProvenanceDetail: string;
  auditorOk: boolean;
  auditorDetail: string;
  releaseChange: ReleaseChangeEvaluation;
  ok: boolean;
  failureReasons: string[];
  evidenceHash: Hex;
  transparencyLeafHash: string;
  transparencyLeafIndex: number;
  arcFailureTxHash: Hex | null;
  arcExplorerUrl: string | null;
  epochHourSec: number;
}

export interface RecordedMonitorFailure {
  id: string;
  nodeId: string;
  epochHourSec: number;
  reasons: string[];
  measurement: string;
  releaseTag: string;
  evidenceHash: Hex;
  txHash: Hex | null;
  explorerUrl: string | null;
  onChain: boolean;
}

export interface MonitorAuditorSummary {
  hasRun: boolean;
  model: string | null;
  verdict: string | null;
  passed: boolean | null;
  probesCount: number | null;
  passedCount: number | null;
  empiricalPassRate: number | null;
  cumulativeSprtStatistic: number | null;
  enclaveHost: string | null;
  at: string | null;
}

export interface MonitorRunRecord {
  runId: string;
  epochHourSec: number;
  at: Date;
  ok: boolean;
  routerHost: string;
  routerReleaseTag: string;
  routerReleaseDigest: string;
  routerRttMs: number | null;
  totalEnclaves: number;
  passedEnclaves: number;
  failedEnclaves: number;
  releaseChangesCount: number;
  enclaves: MonitoredEnclaveRecord[];
  releaseChanges: ReleaseChangeEvaluation[];
  failures: RecordedMonitorFailure[];
  auditor: MonitorAuditorSummary;
  transparencyRoot: string;
  transparencyTreeSize: number;
  anchorTx: string | null;
  anchoredAtSec: number | null;
}

export interface RealEnclaveRampState {
  nodeId: string;
  status: "full" | "ramp" | "suspended";
  restartsIn30d: number;
  dualIdentityDetected: boolean;
  weightBps: number;
  phase: "canary-only" | "linear-ramp" | "steady" | "suspended";
  releaseTag: string;
  lastChangeKind: ReleaseChangeKind;
  detail: string;
}

export interface MonitorCollectionLike {
  find(
    filter: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): {
    sort(spec: Record<string, 1 | -1>): {
      limit(n: number): { toArray(): Promise<Record<string, unknown>[]> };
      toArray(): Promise<Record<string, unknown>[]>;
    };
    toArray(): Promise<Record<string, unknown>[]>;
  };
  insertOne(doc: Record<string, unknown>): Promise<unknown>;
}

const FORBIDDEN_MONITOR_KEYS = new Set([
  "prompt",
  "prompts",
  "completion",
  "completions",
  "messages",
  "message",
  "ip",
  "clientip",
  "useragent",
  "user_agent",
  "email",
  "headers",
  "authorization",
]);

function stripForbiddenFieldsDeep(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (value instanceof Date) return coarsenToHour(value);
  if (Array.isArray(value)) {
    return value.map((item) => stripForbiddenFieldsDeep(item));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_MONITOR_KEYS.has(k.toLowerCase())) continue;
      out[k] = stripForbiddenFieldsDeep(v);
    }
    return out;
  }
  return value;
}

const globalForMonitor = globalThis as unknown as {
  __drouterMonitorRuns?: MonitorRunRecord[];
  __drouterMonitorMongo?: Promise<MongoClient>;
  __drouterMonitorTtlIndexed?: Promise<void>;
  __drouterMonitorCollectionOverride?: MonitorCollectionLike | null;
};

function memoryMonitorRuns(): MonitorRunRecord[] {
  globalForMonitor.__drouterMonitorRuns ??= [];
  return globalForMonitor.__drouterMonitorRuns;
}

export function clearMemoryMonitorRuns(): void {
  memoryMonitorRuns().length = 0;
}

export function setMonitorCollectionOverride(col: MonitorCollectionLike | null | undefined): void {
  globalForMonitor.__drouterMonitorCollectionOverride = col === undefined ? undefined : col;
}

async function getMonitorCollection(): Promise<MonitorCollectionLike | null> {
  if (globalForMonitor.__drouterMonitorCollectionOverride !== undefined) {
    return globalForMonitor.__drouterMonitorCollectionOverride;
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  try {
    globalForMonitor.__drouterMonitorMongo ??= new MongoClient(uri, {
      appName: "drouter-demo-monitor",
      maxPoolSize: 5,
      serverSelectionTimeoutMS: 4000,
    }).connect();
    const client = await globalForMonitor.__drouterMonitorMongo;
    const db: Db = client.db(resolveDbName());
    globalForMonitor.__drouterMonitorTtlIndexed ??= db
      .collection(MONITOR_RUNS_COLLECTION)
      .createIndex(
        { at: 1 },
        { expireAfterSeconds: EPHEMERAL_LOG_TTL_SECONDS, name: "at_ttl_30d" },
      )
      .then(() => undefined)
      .catch(() => undefined);
    await globalForMonitor.__drouterMonitorTtlIndexed;
    const col: Collection = db.collection(MONITOR_RUNS_COLLECTION);
    return col as unknown as MonitorCollectionLike;
  } catch {
    return null;
  }
}

export function sanitizeMonitorRunRecord(record: MonitorRunRecord): MonitorRunRecord {
  const rawDate = record.at instanceof Date ? record.at : new Date(record.at);
  const coarseDate = coarsenToHour(
    Number.isFinite(rawDate.getTime()) ? rawDate : new Date(record.epochHourSec * 1000),
  );
  const epochHourSec = coarsenEpochSecToHour(
    record.epochHourSec || Math.floor(coarseDate.getTime() / 1000),
  );

  const enclaves: MonitoredEnclaveRecord[] = (record.enclaves ?? []).map((e) => ({
    ...e,
    nodeKind: "tinfoil",
    epochHourSec,
  }));

  const failures: RecordedMonitorFailure[] = (record.failures ?? []).map((f) => ({
    ...f,
    epochHourSec,
  }));

  const cleaned: MonitorRunRecord = {
    runId: String(record.runId).slice(0, 80),
    epochHourSec,
    at: coarseDate,
    ok: Boolean(record.ok),
    routerHost: String(record.routerHost ?? "").slice(0, 120),
    routerReleaseTag: String(record.routerReleaseTag ?? "").slice(0, 64),
    routerReleaseDigest: String(record.routerReleaseDigest ?? "").slice(0, 128),
    routerRttMs:
      typeof record.routerRttMs === "number" && Number.isFinite(record.routerRttMs)
        ? Number(record.routerRttMs.toFixed(1))
        : null,
    totalEnclaves: Number(record.totalEnclaves ?? enclaves.length),
    passedEnclaves: Number(
      record.passedEnclaves ?? enclaves.filter((e) => e.ok).length,
    ),
    failedEnclaves: Number(
      record.failedEnclaves ?? enclaves.filter((e) => !e.ok).length,
    ),
    releaseChangesCount: Number(
      record.releaseChangesCount ?? (record.releaseChanges ?? []).filter((c) => c.changed).length,
    ),
    enclaves,
    releaseChanges: [...(record.releaseChanges ?? [])],
    failures,
    auditor: {
      hasRun: Boolean(record.auditor?.hasRun),
      model: record.auditor?.model ? String(record.auditor.model).slice(0, 80) : null,
      verdict: record.auditor?.verdict ? String(record.auditor.verdict).slice(0, 80) : null,
      passed: typeof record.auditor?.passed === "boolean" ? record.auditor.passed : null,
      probesCount:
        typeof record.auditor?.probesCount === "number" ? record.auditor.probesCount : null,
      passedCount:
        typeof record.auditor?.passedCount === "number" ? record.auditor.passedCount : null,
      empiricalPassRate:
        typeof record.auditor?.empiricalPassRate === "number"
          ? record.auditor.empiricalPassRate
          : null,
      cumulativeSprtStatistic:
        typeof record.auditor?.cumulativeSprtStatistic === "number"
          ? record.auditor.cumulativeSprtStatistic
          : null,
      enclaveHost: record.auditor?.enclaveHost
        ? String(record.auditor.enclaveHost).slice(0, 120)
        : null,
      at: record.auditor?.at
        ? coarsenToHour(new Date(record.auditor.at)).toISOString()
        : null,
    },
    transparencyRoot: String(record.transparencyRoot ?? "").slice(0, 128),
    transparencyTreeSize: Number(record.transparencyTreeSize ?? 0),
    anchorTx: record.anchorTx ? String(record.anchorTx).slice(0, 128) : null,
    anchoredAtSec:
      typeof record.anchoredAtSec === "number" && Number.isFinite(record.anchoredAtSec)
        ? coarsenEpochSecToHour(record.anchoredAtSec)
        : null,
  };

  return stripForbiddenFieldsDeep(cleaned) as MonitorRunRecord;
}

/**
 * Persists an aggregate continuous monitor run in `monitor_runs` (with coarse UTC hour timestamps and no PII).
 */
export async function saveMonitorRun(record: MonitorRunRecord): Promise<{
  storedInMongo: boolean;
  sanitized: MonitorRunRecord;
}> {
  const sanitized = sanitizeMonitorRunRecord(record);
  const mem = memoryMonitorRuns();
  mem.unshift(sanitized);
  if (mem.length > 100) {
    mem.length = 100;
  }

  let storedInMongo = false;
  const col = await getMonitorCollection();
  if (col) {
    try {
      await col.insertOne({ ...(sanitized as unknown as Record<string, unknown>) });
      storedInMongo = true;
    } catch {
      // Best-effort MongoDB persistence
    }
  }

  return { storedInMongo, sanitized };
}

/**
 * Reads recent continuous monitor runs from `monitor_runs` (or in-memory store when Mongo is unavailable).
 * Never fabricates runs.
 */
export async function getMonitorRunsHistory(limit = 25): Promise<{
  mongoConfigured: boolean;
  hasRun: boolean;
  statusMessage: string;
  latestRun: MonitorRunRecord | null;
  history: MonitorRunRecord[];
}> {
  const cappedLimit = Math.min(100, Math.max(1, limit));
  const col = await getMonitorCollection();
  let runs: MonitorRunRecord[] = [];

  if (col) {
    try {
      const docs = await col
        .find({}, { projection: { _id: 0 } })
        .sort({ epochHourSec: -1, at: -1 })
        .limit(cappedLimit)
        .toArray();
      runs = docs.map((d) => sanitizeMonitorRunRecord(d as unknown as MonitorRunRecord));
    } catch {
      runs = memoryMonitorRuns().slice(0, cappedLimit);
    }
  } else {
    runs = memoryMonitorRuns().slice(0, cappedLimit);
  }

  const latestRun = runs[0] ?? null;
  const hasRun = runs.length > 0;
  const statusMessage = hasRun
    ? `Latest continuous monitor run (${latestRun.runId}): ${latestRun.passedEnclaves}/${latestRun.totalEnclaves} enclaves verified, ${latestRun.releaseChangesCount} release/host change(s), ${latestRun.failures.length} failure(s).`
    : "No continuous monitor run has been recorded yet. Trigger GET /api/cron/monitor with Authorization: Bearer <CRON_SECRET> to verify all live enclaves.";

  return {
    mongoConfigured: Boolean(
      process.env.MONGODB_URI || globalForMonitor.__drouterMonitorCollectionOverride,
    ),
    hasRun,
    statusMessage,
    latestRun,
    history: runs,
  };
}
