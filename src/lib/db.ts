import { MongoClient, type Db } from "mongodb";
import { resolveDbName } from "@/lib/mongo/db-name";

/**
 * Public transparency log. It stores only non-sensitive facts: which node was verified, the
 * outcome of each check, measurements, receipt hashes and aggregate relay byte counts.
 *
 * Privacy hardening:
 * - Prompts and outputs are end-to-end encrypted and never reach this server in plaintext.
 * - Verification and receipt timestamps are coarsened to the UTC hour boundary so log entries
 *   cannot be correlated with individual network requests.
 * - Relay traffic is accumulated into a single aggregate counter document (`$inc`) rather than
 *   per-request rows, eliminating per-turn timing and size correlation in the database.
 * - Ephemeral transparency collections enforce TTL indexes (`verifications`, `receipts`,
 *   `relay_events` expire after 30 days; `relay_totals` expires after 90 days of inactivity).
 */

const globalForMongo = globalThis as unknown as {
  __drouterMongo?: Promise<MongoClient>;
  __drouterTtlIndexed?: Promise<void>;
};

export const EPHEMERAL_LOG_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
export const RELAY_TOTALS_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days

export function mongoConfigured(): boolean {
  return Boolean(process.env.MONGODB_URI);
}

/** Rounds a timestamp down to the start of its UTC hour to defeat timing correlation. */
export function coarsenToHour(date: Date = new Date()): Date {
  const ms = date.getTime();
  return new Date(ms - (ms % 3_600_000));
}

async function ensureTtlIndexes(database: Db): Promise<void> {
  try {
    await Promise.all([
      database
        .collection("verifications")
        .createIndex(
          { at: 1 },
          { expireAfterSeconds: EPHEMERAL_LOG_TTL_SECONDS, name: "at_ttl_30d" },
        ),
      database
        .collection("receipts")
        .createIndex(
          { at: 1 },
          { expireAfterSeconds: EPHEMERAL_LOG_TTL_SECONDS, name: "at_ttl_30d" },
        ),
      database
        .collection("relay_events")
        .createIndex(
          { at: 1 },
          { expireAfterSeconds: EPHEMERAL_LOG_TTL_SECONDS, name: "at_ttl_30d" },
        ),
      database
        .collection("relay_totals")
        .createIndex(
          { lastEpochHour: 1 },
          { expireAfterSeconds: RELAY_TOTALS_TTL_SECONDS, name: "lastEpochHour_ttl_90d" },
        ),
    ]);
  } catch {
    // Index creation is best-effort and idempotent
  }
}

async function db(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  globalForMongo.__drouterMongo ??= new MongoClient(uri, {
    appName: "drouter-demo",
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
  }).connect();
  const client = await globalForMongo.__drouterMongo;
  const database = client.db(resolveDbName());
  globalForMongo.__drouterTtlIndexed ??= ensureTtlIndexes(database);
  await globalForMongo.__drouterTtlIndexed;
  return database;
}

export interface VerificationEvent {
  nodeId: string;
  nodeName: string;
  kind: "tinfoil" | "sim";
  ok: boolean;
  checks: { id: string; status: "pass" | "fail" | "skip" }[];
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  at: Date;
}

export interface ReceiptEvent {
  nodeId: string;
  receiptHash: string;
  signatureVerified: boolean;
  anchorTx?: string | null;
  at: Date;
}

export interface RelayEvent {
  enclaveHost: string;
  bytesUp: number;
  bytesDown: number;
  status: number;
  at: Date;
}

const FORBIDDEN_DOC_KEYS = new Set([
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

function stripForbiddenFields(doc: Record<string, unknown>): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc)) {
    if (FORBIDDEN_DOC_KEYS.has(k.toLowerCase())) continue;
    cleaned[k] = v;
  }
  return cleaned;
}

async function insert(collection: string, doc: { at: Date } & Record<string, unknown>): Promise<boolean> {
  try {
    const database = await db();
    if (!database) return false;
    const safeDoc = stripForbiddenFields(doc);
    await database.collection(collection).insertOne({ ...safeDoc, at: coarsenToHour(doc.at) });
    return true;
  } catch {
    return false;
  }
}

export const logVerification = (e: VerificationEvent) => insert("verifications", { ...e });
export const logReceipt = (e: ReceiptEvent) => insert("receipts", { ...e });

/** Updates only aggregate counters without storing per-request timestamps. */
export async function logRelay(e: RelayEvent): Promise<boolean> {
  try {
    const database = await db();
    if (!database) return false;
    await database.collection("relay_totals").updateOne(
      { _id: "global" as unknown as never },
      {
        $inc: {
          requests: 1,
          bytesUp: e.bytesUp,
          bytesDown: e.bytesDown,
        },
        $set: {
          lastEpochHour: coarsenToHour(e.at),
        },
      },
      { upsert: true },
    );
    return true;
  } catch {
    return false;
  }
}

export async function recentActivity(limit = 25) {
  try {
    const database = await db();
    if (!database) return { configured: false, verifications: [], receipts: [], relay: null };
    const project = { projection: { _id: 0 } };
    const [rawVerifications, rawReceipts, relayTotals, legacyRelayAgg] = await Promise.all([
      database.collection("verifications").find({}, project).sort({ at: -1 }).limit(limit).toArray(),
      database.collection("receipts").find({}, project).sort({ at: -1 }).limit(limit).toArray(),
      database.collection("relay_totals").findOne({ _id: "global" as unknown as never }),
      database
        .collection("relay_events")
        .aggregate([
          {
            $group: {
              _id: null,
              requests: { $sum: 1 },
              bytesUp: { $sum: "$bytesUp" },
              bytesDown: { $sum: "$bytesDown" },
            },
          },
        ])
        .toArray(),
    ]);
    const verifications: Record<string, unknown>[] = rawVerifications.map((v) => ({
      ...v,
      at: v.at instanceof Date ? coarsenToHour(v.at) : coarsenToHour(new Date(String(v.at))),
    }));
    const receipts: Record<string, unknown>[] = rawReceipts.map((r) => ({
      ...r,
      at: r.at instanceof Date ? coarsenToHour(r.at) : coarsenToHour(new Date(String(r.at))),
    }));
    const legacy = legacyRelayAgg[0] ?? { requests: 0, bytesUp: 0, bytesDown: 0 };
    const relay = {
      requests: Number(relayTotals?.requests ?? 0) + Number(legacy.requests ?? 0),
      bytesUp: Number(relayTotals?.bytesUp ?? 0) + Number(legacy.bytesUp ?? 0),
      bytesDown: Number(relayTotals?.bytesDown ?? 0) + Number(legacy.bytesDown ?? 0),
    };
    return { configured: true, verifications, receipts, relay };
  } catch {
    return { configured: true, error: "read failed", verifications: [], receipts: [], relay: null };
  }
}
