import { MongoClient, type Db } from "mongodb";

export interface StoredFrozenBlob {
  blobId: string;
  sessionIdHex: string;
  nonceHex: string;
  aadHex: string;
  ciphertextHex: string;
  byteLength: number;
  modelId: string;
  createdAt: number;
  expiresAt: number;
}

export interface FrozenBlobSummary {
  blobId: string;
  sessionIdHex: string;
  byteLength: number;
  modelId: string;
  createdAt: number;
  expiresAt: number;
}

export interface SaveFrozenBlobInput {
  blobId: string;
  sessionIdHex: string;
  nonceHex: string;
  aadHex: string;
  ciphertextHex: string;
  modelId?: string;
  createdAt?: number;
  expiresAt?: number;
  [key: string]: unknown;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const HEX_RE = /^[0-9a-fA-F]+$/;

const globalForFreeze = globalThis as unknown as {
  __drouterFreezeStore?: Map<string, StoredFrozenBlob>;
  __drouterFreezeMongo?: Promise<MongoClient>;
};

function memoryStore(): Map<string, StoredFrozenBlob> {
  globalForFreeze.__drouterFreezeStore ??= new Map<string, StoredFrozenBlob>();
  return globalForFreeze.__drouterFreezeStore;
}

async function getMongoDb(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  try {
    globalForFreeze.__drouterFreezeMongo ??= new MongoClient(uri, {
      appName: "drouter-demo-freeze",
      maxPoolSize: 5,
      serverSelectionTimeoutMS: 3000,
    }).connect();
    const client = await globalForFreeze.__drouterFreezeMongo;
    return client.db(process.env.MONGODB_DB ?? "drouter");
  } catch {
    return null;
  }
}

function cleanHex(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`Invalid or missing ${fieldName}`);
  }
  const stripped = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  if (stripped.length === 0 || stripped.length % 2 !== 0 || !HEX_RE.test(stripped)) {
    throw new Error(`Field ${fieldName} must be even-length hex`);
  }
  return stripped.toLowerCase();
}

/**
 * Validates and stores an encrypted session blob.
 * Defense-in-depth: refuses any payload that includes `freezeSecretHex` or `messages`.
 */
export async function saveFrozenBlob(input: SaveFrozenBlobInput): Promise<StoredFrozenBlob> {
  if (!input || typeof input !== "object") {
    throw new Error("Invalid freeze blob payload");
  }

  const raw = input as Record<string, unknown>;
  if ("freezeSecretHex" in raw || "messages" in raw) {
    throw new Error(
      "Defense-in-depth rejection: server store refuses freezeSecretHex or plaintext messages",
    );
  }

  const blobId = cleanHex(raw.blobId, "blobId");
  const sessionIdHex = cleanHex(raw.sessionIdHex, "sessionIdHex");
  const nonceHex = cleanHex(raw.nonceHex, "nonceHex");
  const aadHex = cleanHex(raw.aadHex, "aadHex");
  const ciphertextHex = cleanHex(raw.ciphertextHex, "ciphertextHex");

  if (nonceHex.length !== 24) {
    throw new Error("Field nonceHex must be 12 bytes (24 hex chars)");
  }
  if (ciphertextHex.length < 32) {
    throw new Error("Field ciphertextHex must include at least the 16-byte GCM authentication tag");
  }

  const byteLength = ciphertextHex.length / 2;
  const modelId =
    typeof raw.modelId === "string" && raw.modelId.trim().length > 0
      ? raw.modelId.trim().slice(0, 120)
      : "unknown";
  const nowSec = Math.floor(Date.now() / 1000);
  const createdAt =
    typeof raw.createdAt === "number" && Number.isFinite(raw.createdAt)
      ? Math.floor(raw.createdAt)
      : nowSec;
  const expiresAt =
    typeof raw.expiresAt === "number" && Number.isFinite(raw.expiresAt)
      ? Math.floor(raw.expiresAt)
      : createdAt + DEFAULT_TTL_SECONDS;

  const record: StoredFrozenBlob = {
    blobId,
    sessionIdHex,
    nonceHex,
    aadHex,
    ciphertextHex,
    byteLength,
    modelId,
    createdAt,
    expiresAt,
  };

  memoryStore().set(blobId, record);

  const db = await getMongoDb();
  if (db) {
    try {
      await db
        .collection<StoredFrozenBlob>("frozen_blobs")
        .updateOne({ blobId }, { $set: record }, { upsert: true });
    } catch {
      // Best-effort persistence when MongoDB is unreachable
    }
  }

  return record;
}

/**
 * Retrieves an encrypted blob by blobId from memory or MongoDB.
 */
export async function getFrozenBlob(blobId: string): Promise<StoredFrozenBlob | null> {
  if (typeof blobId !== "string" || !blobId.trim()) return null;
  const normalizedId = (blobId.startsWith("0x") ? blobId.slice(2) : blobId).toLowerCase();

  const cached = memoryStore().get(normalizedId);
  if (cached) return cached;

  const db = await getMongoDb();
  if (db) {
    try {
      const found = await db
        .collection<StoredFrozenBlob>("frozen_blobs")
        .findOne({ blobId: normalizedId }, { projection: { _id: 0 } });
      if (found) {
        memoryStore().set(normalizedId, found);
        return found;
      }
    } catch {
      // Fall through to null
    }
  }

  return null;
}

/**
 * Deletes an encrypted blob from memory and MongoDB.
 */
export async function deleteFrozenBlob(blobId: string): Promise<boolean> {
  if (typeof blobId !== "string" || !blobId.trim()) return false;
  const normalizedId = (blobId.startsWith("0x") ? blobId.slice(2) : blobId).toLowerCase();

  let deleted = memoryStore().delete(normalizedId);

  const db = await getMongoDb();
  if (db) {
    try {
      const res = await db
        .collection<StoredFrozenBlob>("frozen_blobs")
        .deleteOne({ blobId: normalizedId });
      if (res.deletedCount > 0) deleted = true;
    } catch {
      // Ignore MongoDB errors on delete
    }
  }

  return deleted;
}

/**
 * Lists metadata summaries (without ciphertext bodies) for stored frozen blobs.
 */
export async function listFrozenBlobSummaries(limit = 25): Promise<FrozenBlobSummary[]> {
  const byId = new Map<string, FrozenBlobSummary>();

  for (const b of memoryStore().values()) {
    byId.set(b.blobId, {
      blobId: b.blobId,
      sessionIdHex: b.sessionIdHex,
      byteLength: b.byteLength,
      modelId: b.modelId,
      createdAt: b.createdAt,
      expiresAt: b.expiresAt,
    });
  }

  const db = await getMongoDb();
  if (db) {
    try {
      const docs = await db
        .collection<StoredFrozenBlob>("frozen_blobs")
        .find(
          {},
          {
            projection: {
              _id: 0,
              blobId: 1,
              sessionIdHex: 1,
              byteLength: 1,
              modelId: 1,
              createdAt: 1,
              expiresAt: 1,
            },
          },
        )
        .sort({ createdAt: -1 })
        .limit(limit)
        .toArray();
      for (const d of docs) {
        if (!byId.has(d.blobId)) {
          byId.set(d.blobId, {
            blobId: d.blobId,
            sessionIdHex: d.sessionIdHex,
            byteLength: d.byteLength,
            modelId: d.modelId,
            createdAt: d.createdAt,
            expiresAt: d.expiresAt,
          });
        }
      }
    } catch {
      // Best-effort read from MongoDB
    }
  }

  return Array.from(byId.values())
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);
}
