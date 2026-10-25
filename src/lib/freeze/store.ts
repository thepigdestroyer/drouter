import { MongoClient, type Db } from "mongodb";
import { resolveDbName } from "@/lib/mongo/db-name";
import { coarsenEpochSecToHour } from "./crypto";

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
  expiresAtDate?: Date;
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

export interface FreezeCollectionLike {
  createIndex(
    indexSpec: Record<string, 1 | -1>,
    options?: Record<string, unknown>,
  ): Promise<string>;
  updateOne(
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  findOne(
    filter: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<StoredFrozenBlob | null>;
  deleteOne(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
  find(
    filter: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): {
    sort(spec: Record<string, 1 | -1>): {
      limit(n: number): { toArray(): Promise<StoredFrozenBlob[]> };
    };
  };
}

export interface FreezeStorageModeInfo {
  mode: "mongodb" | "memory";
  persisted: boolean;
  label: string;
}

export const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
export const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MAX_CIPHERTEXT_BYTES = 131_072; // 128 KB binary ciphertext cap
export const FREEZE_COLLECTION_NAME = "frozen_blobs";
export const FREEZE_TTL_INDEX_NAME = "expiresAtDate_ttl_0s";

const HEX_RE = /^[0-9a-fA-F]+$/;

const FORBIDDEN_PAYLOAD_KEYS = new Set([
  "freezesecrethex",
  "freezesecret",
  "secret",
  "key",
  "messages",
  "message",
  "prompt",
  "prompts",
  "completion",
  "completions",
  "plaintext",
  "ip",
  "clientip",
  "x-forwarded-for",
  "useragent",
  "user_agent",
  "headers",
]);

const globalForFreeze = globalThis as unknown as {
  __drouterFreezeStore?: Map<string, StoredFrozenBlob>;
  __drouterFreezeMongo?: Promise<MongoClient>;
  __drouterFreezeTtlIndexed?: Promise<boolean>;
  __drouterFreezeCollectionOverride?: FreezeCollectionLike | null;
};

function memoryStore(): Map<string, StoredFrozenBlob> {
  globalForFreeze.__drouterFreezeStore ??= new Map<string, StoredFrozenBlob>();
  return globalForFreeze.__drouterFreezeStore;
}

/**
 * Allows unit tests to inject a mock MongoDB collection for verifying TTL index
 * creation, persistence, and physical deletion without live network calls.
 */
export function setFreezeCollectionOverrideForTests(
  col: FreezeCollectionLike | null | undefined,
): void {
  globalForFreeze.__drouterFreezeCollectionOverride = col === undefined ? undefined : col;
  globalForFreeze.__drouterFreezeTtlIndexed = undefined;
}

/** Clears the local memory store and cached index state for isolated tests. */
export function resetFreezeStoreForTests(): void {
  globalForFreeze.__drouterFreezeStore?.clear();
  globalForFreeze.__drouterFreezeTtlIndexed = undefined;
  globalForFreeze.__drouterFreezeCollectionOverride = undefined;
}

export function getFreezeStorageMode(): FreezeStorageModeInfo {
  if (globalForFreeze.__drouterFreezeCollectionOverride) {
    return {
      mode: "mongodb",
      persisted: true,
      label: "MongoDB Atlas (TTL auto-shred enabled)",
    };
  }
  if (process.env.MONGODB_URI) {
    return {
      mode: "mongodb",
      persisted: true,
      label: "MongoDB Atlas (TTL auto-shred enabled)",
    };
  }
  return {
    mode: "memory",
    persisted: false,
    label: "Temporary memory (database not configured)",
  };
}

async function getMongoDb(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  try {
    globalForFreeze.__drouterFreezeMongo ??= new MongoClient(uri, {
      appName: "drouter-demo-freeze",
      maxPoolSize: 5,
      serverSelectionTimeoutMS: 5000,
    }).connect();
    const client = await globalForFreeze.__drouterFreezeMongo;
    return client.db(resolveDbName());
  } catch {
    globalForFreeze.__drouterFreezeMongo = undefined;
    return null;
  }
}

async function resolveCollection(): Promise<FreezeCollectionLike | null> {
  if (globalForFreeze.__drouterFreezeCollectionOverride !== undefined) {
    return globalForFreeze.__drouterFreezeCollectionOverride;
  }
  const db = await getMongoDb();
  if (!db) return null;
  return db.collection<StoredFrozenBlob>(FREEZE_COLLECTION_NAME) as unknown as FreezeCollectionLike;
}

/**
 * Ensures the MongoDB TTL index on `expiresAtDate` (`expireAfterSeconds: 0`) and
 * lookup index on `blobId` exist on `frozen_blobs` so expired ciphertexts are
 * physically deleted by MongoDB at expiry.
 */
export async function ensureFreezeTtlIndex(
  explicitCol?: FreezeCollectionLike | null,
): Promise<boolean> {
  const col = explicitCol !== undefined ? explicitCol : await resolveCollection();
  if (!col) return false;
  try {
    await col.createIndex(
      { expiresAtDate: 1 },
      { expireAfterSeconds: 0, name: FREEZE_TTL_INDEX_NAME },
    );
    await col.createIndex(
      { blobId: 1 },
      { unique: true, name: "blobId_unique_idx" },
    );
    return true;
  } catch {
    return false;
  }
}

async function getIndexedCollection(): Promise<FreezeCollectionLike | null> {
  const col = await resolveCollection();
  if (!col) return null;
  globalForFreeze.__drouterFreezeTtlIndexed ??= ensureFreezeTtlIndex(col);
  await globalForFreeze.__drouterFreezeTtlIndexed;
  return col;
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

function pruneExpiredMemoryBlobs(nowSec = Math.floor(Date.now() / 1000)): void {
  const store = memoryStore();
  for (const [id, rec] of store.entries()) {
    if (rec.expiresAt <= nowSec) {
      store.delete(id);
    }
  }
}

function stripInternalMongoFields(doc: StoredFrozenBlob): StoredFrozenBlob {
  return {
    blobId: doc.blobId,
    sessionIdHex: doc.sessionIdHex,
    nonceHex: doc.nonceHex,
    aadHex: doc.aadHex,
    ciphertextHex: doc.ciphertextHex,
    byteLength: doc.byteLength,
    modelId: doc.modelId,
    createdAt: coarsenEpochSecToHour(doc.createdAt),
    expiresAt: coarsenEpochSecToHour(doc.expiresAt),
  };
}

/**
 * Validates and stores an encrypted session blob.
 * Defense-in-depth:
 * - Refuses any payload that includes `freezeSecretHex`, `messages`, `prompt`, `ip`, etc.
 * - Coarsens `createdAt` and `expiresAt` to the UTC hour boundary (no exact timestamps stored).
 * - Caps ciphertext size to `MAX_CIPHERTEXT_BYTES` (128 KB).
 * - Persists `expiresAtDate` (BSON Date) with a MongoDB TTL index so blobs are physically deleted at expiry.
 */
export async function saveFrozenBlob(input: SaveFrozenBlobInput): Promise<StoredFrozenBlob> {
  if (!input || typeof input !== "object") {
    throw new Error("Invalid freeze blob payload");
  }

  const raw = input as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN_PAYLOAD_KEYS.has(key.toLowerCase())) {
      throw new Error(
        "Defense-in-depth rejection: server store refuses freezeSecretHex, plaintext messages, or client metadata",
      );
    }
  }

  const blobId = cleanHex(raw.blobId, "blobId");
  const sessionIdHex = cleanHex(raw.sessionIdHex, "sessionIdHex");
  const nonceHex = cleanHex(raw.nonceHex, "nonceHex");
  const aadHex = cleanHex(raw.aadHex, "aadHex");
  const ciphertextHex = cleanHex(raw.ciphertextHex, "ciphertextHex");

  if (blobId.length > 128) {
    throw new Error("Field blobId exceeds maximum length");
  }
  if (sessionIdHex.length > 128) {
    throw new Error("Field sessionIdHex exceeds maximum length");
  }
  if (nonceHex.length !== 24) {
    throw new Error("Field nonceHex must be 12 bytes (24 hex chars)");
  }
  if (ciphertextHex.length < 32) {
    throw new Error("Field ciphertextHex must include at least the 16-byte GCM authentication tag");
  }

  const byteLength = ciphertextHex.length / 2;
  if (byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new Error(`Field ciphertextHex exceeds maximum allowed size (${MAX_CIPHERTEXT_BYTES} bytes)`);
  }

  const modelId =
    typeof raw.modelId === "string" && raw.modelId.trim().length > 0
      ? raw.modelId.trim().slice(0, 120)
      : "unknown";

  const nowSec = Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);
  const createdAt =
    typeof raw.createdAt === "number" && Number.isFinite(raw.createdAt) && raw.createdAt > 0
      ? coarsenEpochSecToHour(raw.createdAt)
      : coarseNow;

  let requestedExpiresAt: number;
  if (typeof raw.expiresAt === "number" && Number.isFinite(raw.expiresAt) && raw.expiresAt > 0) {
    const rawExpSec = raw.expiresAt > 10_000_000_000 ? Math.floor(raw.expiresAt / 1000) : Math.floor(raw.expiresAt);
    if (rawExpSec <= nowSec) {
      requestedExpiresAt = rawExpSec;
    } else {
      const clampedTtl = Math.min(MAX_TTL_SECONDS, Math.max(3600, rawExpSec - createdAt));
      requestedExpiresAt = coarsenEpochSecToHour(Math.max(coarseNow, createdAt) + clampedTtl);
    }
  } else {
    requestedExpiresAt = coarsenEpochSecToHour(Math.max(coarseNow, createdAt) + DEFAULT_TTL_SECONDS);
  }

  const expiresAtDate = new Date(requestedExpiresAt * 1000);

  const record: StoredFrozenBlob = {
    blobId,
    sessionIdHex,
    nonceHex,
    aadHex,
    ciphertextHex,
    byteLength,
    modelId,
    createdAt,
    expiresAt: requestedExpiresAt,
    expiresAtDate,
  };

  const col = await getIndexedCollection();
  if (col) {
    await col.updateOne({ blobId }, { $set: record }, { upsert: true });
  } else if (process.env.MONGODB_URI) {
    throw new Error("Freeze store persistence unavailable: could not connect to MongoDB");
  } else {
    pruneExpiredMemoryBlobs(nowSec);
    memoryStore().set(blobId, record);
  }

  return stripInternalMongoFields(record);
}

/**
 * Retrieves an encrypted blob by blobId.
 * Enforces expiry immediately even before the MongoDB background TTL monitor pass runs.
 */
export async function getFrozenBlob(blobId: string): Promise<StoredFrozenBlob | null> {
  if (typeof blobId !== "string" || !blobId.trim()) return null;
  const normalizedId = (blobId.startsWith("0x") ? blobId.slice(2) : blobId).toLowerCase();
  const nowSec = Math.floor(Date.now() / 1000);

  const col = await getIndexedCollection();
  if (col) {
    const found = await col.findOne({ blobId: normalizedId }, { projection: { _id: 0 } });
    if (!found) {
      memoryStore().delete(normalizedId);
      return null;
    }
    if (typeof found.expiresAt === "number" && found.expiresAt <= nowSec) {
      await col.deleteOne({ blobId: normalizedId }).catch(() => {});
      memoryStore().delete(normalizedId);
      return null;
    }
    return stripInternalMongoFields(found);
  }

  if (process.env.MONGODB_URI) {
    return null;
  }

  pruneExpiredMemoryBlobs(nowSec);
  const cached = memoryStore().get(normalizedId);
  if (!cached) return null;
  return stripInternalMongoFields(cached);
}

/**
 * Deletes an encrypted blob from MongoDB and local memory, then verifies physical deletion
 * so callers can confirm the server-side ciphertext has been destroyed.
 */
export async function destroyFrozenBlobVerified(
  blobId: string,
): Promise<{ deleted: boolean; verifiedAbsent: boolean }> {
  if (typeof blobId !== "string" || !blobId.trim()) {
    return { deleted: false, verifiedAbsent: true };
  }
  const normalizedId = (blobId.startsWith("0x") ? blobId.slice(2) : blobId).toLowerCase();

  let deleted = memoryStore().delete(normalizedId);

  const col = await getIndexedCollection();
  if (col) {
    const res = await col.deleteOne({ blobId: normalizedId });
    if (res.deletedCount > 0) deleted = true;
    const stillPresent = await col.findOne(
      { blobId: normalizedId },
      { projection: { _id: 0, blobId: 1 } },
    );
    return {
      deleted,
      verifiedAbsent: stillPresent === null,
    };
  }

  const stillInMemory = memoryStore().has(normalizedId);
  return {
    deleted,
    verifiedAbsent: !stillInMemory,
  };
}

/**
 * Deletes an encrypted blob from memory and MongoDB.
 */
export async function deleteFrozenBlob(blobId: string): Promise<boolean> {
  const res = await destroyFrozenBlobVerified(blobId);
  return res.deleted && res.verifiedAbsent;
}

/**
 * Lists metadata summaries (without ciphertext bodies) for non-expired frozen blobs.
 */
export async function listFrozenBlobSummaries(limit = 25): Promise<FrozenBlobSummary[]> {
  const nowSec = Math.floor(Date.now() / 1000);
  const byId = new Map<string, FrozenBlobSummary>();

  const col = await getIndexedCollection();
  if (col) {
    const docs = await col
      .find(
        { expiresAt: { $gt: nowSec } },
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
      if (d.expiresAt > nowSec) {
        byId.set(d.blobId, {
          blobId: d.blobId,
          sessionIdHex: d.sessionIdHex,
          byteLength: d.byteLength,
          modelId: d.modelId,
          createdAt: coarsenEpochSecToHour(d.createdAt),
          expiresAt: coarsenEpochSecToHour(d.expiresAt),
        });
      }
    }
  } else if (!process.env.MONGODB_URI) {
    pruneExpiredMemoryBlobs(nowSec);
    for (const b of memoryStore().values()) {
      if (b.expiresAt > nowSec) {
        byId.set(b.blobId, {
          blobId: b.blobId,
          sessionIdHex: b.sessionIdHex,
          byteLength: b.byteLength,
          modelId: b.modelId,
          createdAt: coarsenEpochSecToHour(b.createdAt),
          expiresAt: coarsenEpochSecToHour(b.expiresAt),
        });
      }
    }
  }

  return Array.from(byId.values())
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);
}
