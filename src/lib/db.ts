import { MongoClient, type Db } from "mongodb";

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
 */

const globalForMongo = globalThis as unknown as { __drouterMongo?: Promise<MongoClient> };

export function mongoConfigured(): boolean {
  return Boolean(process.env.MONGODB_URI);
}

/** Rounds a timestamp down to the start of its UTC hour to defeat timing correlation. */
export function coarsenToHour(date: Date = new Date()): Date {
  const ms = date.getTime();
  return new Date(ms - (ms % 3_600_000));
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
  return client.db(process.env.MONGODB_DB ?? "drouter");
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

async function insert(collection: string, doc: { at: Date } & Record<string, unknown>): Promise<boolean> {
  try {
    const database = await db();
    if (!database) return false;
    await database.collection(collection).insertOne({ ...doc, at: coarsenToHour(doc.at) });
    return true;
  } catch (error) {
    console.error(`mongo insert into ${collection} failed`, error);
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
  } catch (error) {
    console.error("mongo relay counter update failed", error);
    return false;
  }
}

export async function recentActivity(limit = 25) {
  try {
    const database = await db();
    if (!database) return { configured: false, verifications: [], receipts: [], relay: null };
    const project = { projection: { _id: 0 } };
    const [verifications, receipts, relayTotals, legacyRelayAgg] = await Promise.all([
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
    const legacy = legacyRelayAgg[0] ?? { requests: 0, bytesUp: 0, bytesDown: 0 };
    const relay = {
      requests: Number(relayTotals?.requests ?? 0) + Number(legacy.requests ?? 0),
      bytesUp: Number(relayTotals?.bytesUp ?? 0) + Number(legacy.bytesUp ?? 0),
      bytesDown: Number(relayTotals?.bytesDown ?? 0) + Number(legacy.bytesDown ?? 0),
    };
    return { configured: true, verifications, receipts, relay };
  } catch (error) {
    console.error("mongo read failed", error);
    return { configured: true, error: "read failed", verifications: [], receipts: [], relay: null };
  }
}
