import { MongoClient, type Db } from "mongodb";

/**
 * Public transparency log. It stores only non-sensitive facts: which node was verified, the
 * outcome of each check, measurements, receipt hashes and relay byte counts. Prompts and outputs
 * are end-to-end encrypted and never reach this server in readable form, so they cannot be stored.
 */

const globalForMongo = globalThis as unknown as { __drouterMongo?: Promise<MongoClient> };

export function mongoConfigured(): boolean {
  return Boolean(process.env.MONGODB_URI);
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

async function insert(collection: string, doc: object): Promise<boolean> {
  try {
    const database = await db();
    if (!database) return false;
    await database.collection(collection).insertOne({ ...doc });
    return true;
  } catch (error) {
    console.error(`mongo insert into ${collection} failed`, error);
    return false;
  }
}

export const logVerification = (e: VerificationEvent) => insert("verifications", e);
export const logReceipt = (e: ReceiptEvent) => insert("receipts", e);
export const logRelay = (e: RelayEvent) => insert("relay_events", e);

export async function recentActivity(limit = 25) {
  try {
    const database = await db();
    if (!database) return { configured: false, verifications: [], receipts: [], relay: null };
    const project = { projection: { _id: 0 } };
    const [verifications, receipts, relayAgg] = await Promise.all([
      database.collection("verifications").find({}, project).sort({ at: -1 }).limit(limit).toArray(),
      database.collection("receipts").find({}, project).sort({ at: -1 }).limit(limit).toArray(),
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
    const relay = relayAgg[0] ? { requests: relayAgg[0].requests, bytesUp: relayAgg[0].bytesUp, bytesDown: relayAgg[0].bytesDown } : { requests: 0, bytesUp: 0, bytesDown: 0 };
    return { configured: true, verifications, receipts, relay };
  } catch (error) {
    console.error("mongo read failed", error);
    return { configured: true, error: "read failed", verifications: [], receipts: [], relay: null };
  }
}
