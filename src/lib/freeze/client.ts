import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { getCurrentVaultSession } from "@/lib/auth/vault";
import {
  coarsenEpochSecToHour,
  decryptFrozenState,
  encryptFrozenState,
  formatResumeCode,
  parseResumeCode,
} from "./crypto";
import type { FreezeReceipt, FrozenSessionState } from "@/lib/types";

export const FREEZE_STORAGE_KEY = "drouter.freeze.v1";
export const FREEZE_DEVICE_KEY_STORAGE = "drouter.freeze.device-key.v1";
export const FREEZE_IDB_DB_NAME = "drouter-freeze-keystore";
export const FREEZE_IDB_STORE_NAME = "keys";
export const FREEZE_IDB_KEY_ID = "device-key-v1";

const FREEZE_RECEIPT_STORAGE_AAD = utf8ToBytes("drouter/v1/freeze-receipt-storage");
const FREEZE_DEVICE_WRAP_SALT = utf8ToBytes("drouter/v1/freeze-device-wrap-salt");
const FREEZE_DEVICE_WRAP_INFO = utf8ToBytes("drouter/v1/freeze-device-wrap-key");
const FREEZE_IDB_HKDF_INFO = utf8ToBytes("drouter/v1/freeze-idb-wrap-key");

export interface StoredFreezeReceipt extends FreezeReceipt {
  byteLength?: number;
  expiresAt?: number;
  modelId?: string;
  storageMode?: "mongodb" | "memory";
  persisted?: boolean;
  resumeCode?: string;
}

export interface DestroyFrozenSessionResult {
  blobId: string;
  localSecretWiped: boolean;
  serverDeleted: boolean;
  verifiedAbsent: boolean;
}

export interface FrozenBlobStatusCheck {
  blobId: string;
  status: "resumable" | "expired" | "destroyed";
  expiresAt?: number;
  byteLength?: number;
  modelId?: string;
  storageMode?: "mongodb" | "memory";
  persisted?: boolean;
}

let memoryFallback: StoredFreezeReceipt[] = [];
let memoryDeviceSecretHex: string | null = null;
let cachedIdbDerivedKeyHex: string | null = null;
let pendingIdbMigration: Promise<Uint8Array | null> | null = null;

function hasLocalStorage(): boolean {
  try {
    return (
      typeof window !== "undefined" &&
      typeof window.localStorage !== "undefined" &&
      window.localStorage !== null &&
      typeof window.localStorage.getItem === "function"
    );
  } catch {
    return false;
  }
}

function getIndexedDBFactory(): IDBFactory | null {
  try {
    if (typeof globalThis !== "undefined" && globalThis.indexedDB && typeof globalThis.indexedDB.open === "function") {
      return globalThis.indexedDB;
    }
    if (typeof window !== "undefined" && window.indexedDB && typeof window.indexedDB.open === "function") {
      return window.indexedDB;
    }
  } catch {
    // IndexedDB unavailable or blocked
  }
  return null;
}

export function hasIndexedDB(): boolean {
  return getIndexedDBFactory() !== null;
}

function deriveWrappingKeyFromHex(rawHex: string): Uint8Array {
  const rawBytes = hexToBytes(rawHex);
  try {
    return hkdf(sha384, rawBytes, FREEZE_DEVICE_WRAP_SALT, FREEZE_DEVICE_WRAP_INFO, 32);
  } finally {
    rawBytes.fill(0);
  }
}

function openKeyStoreDb(idb: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    try {
      const req = idb.open(FREEZE_IDB_DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(FREEZE_IDB_STORE_NAME)) {
          db.createObjectStore(FREEZE_IDB_STORE_NAME);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed"));
    } catch (err) {
      reject(err);
    }
  });
}

function idbGetKey(db: IDBDatabase, key: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    try {
      const tx = db.transaction(FREEZE_IDB_STORE_NAME, "readonly");
      const store = tx.objectStore(FREEZE_IDB_STORE_NAME);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error ?? new Error("IndexedDB get failed"));
    } catch (err) {
      reject(err);
    }
  });
}

function idbPutKey(db: IDBDatabase, key: string, value: CryptoKey): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      const tx = db.transaction(FREEZE_IDB_STORE_NAME, "readwrite");
      const store = tx.objectStore(FREEZE_IDB_STORE_NAME);
      const req = store.put(value, key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error ?? new Error("IndexedDB put failed"));
    } catch (err) {
      reject(err);
    }
  });
}

function isCryptoKeyLike(val: unknown): val is CryptoKey {
  return Boolean(
    val &&
      typeof val === "object" &&
      "type" in (val as CryptoKey) &&
      "extractable" in (val as CryptoKey) &&
      "algorithm" in (val as CryptoKey) &&
      "usages" in (val as CryptoKey),
  );
}

async function importNonExtractableDeviceCryptoKey(rawKeyBytes: Uint8Array): Promise<CryptoKey> {
  const buf = new Uint8Array(rawKeyBytes.byteLength);
  buf.set(rawKeyBytes);
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      buf.buffer,
      { name: "HMAC", hash: "SHA-256" },
      false, // non-extractable
      ["sign"],
    );
  } finally {
    buf.fill(0);
  }
}

async function deriveWrappingKeyFromCryptoKey(cryptoKey: CryptoKey): Promise<Uint8Array> {
  const sig = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, FREEZE_IDB_HKDF_INFO);
  return new Uint8Array(sig, 0, 32);
}

/**
 * Ensures the non-extractable WebCrypto `CryptoKey` is stored in IndexedDB.
 * If a legacy plaintext `drouter.freeze.device-key.v1` exists in `localStorage`,
 * migrates it into IndexedDB as a non-extractable `CryptoKey`, re-encrypts any existing
 * receipts in `drouter.freeze.v1` under the new IndexedDB key, and deletes
 * `drouter.freeze.device-key.v1` from `localStorage`.
 */
export async function ensureIndexedDbDeviceKey(): Promise<Uint8Array | null> {
  const idb = getIndexedDBFactory();
  if (!idb || typeof globalThis.crypto?.subtle === "undefined") {
    return null;
  }
  if (pendingIdbMigration) {
    return pendingIdbMigration;
  }

  pendingIdbMigration = (async () => {
    let db: IDBDatabase | null = null;
    try {
      db = await openKeyStoreDb(idb);
      let legacyHex: string | null = null;
      if (hasLocalStorage()) {
        try {
          legacyHex = globalThis.localStorage.getItem(FREEZE_DEVICE_KEY_STORAGE);
        } catch {
          legacyHex = null;
        }
      }

      const existing = await idbGetKey(db, FREEZE_IDB_KEY_ID);
      let cryptoKey: CryptoKey;
      let oldLegacyWrappingKey: Uint8Array | null = null;

      if (legacyHex && /^[0-9a-fA-F]{64}$/.test(legacyHex)) {
        oldLegacyWrappingKey = deriveWrappingKeyFromHex(legacyHex);
      }

      if (isCryptoKeyLike(existing)) {
        cryptoKey = existing;
      } else {
        const seedBytes =
          legacyHex && /^[0-9a-fA-F]{64}$/.test(legacyHex)
            ? hexToBytes(legacyHex)
            : (() => {
                const rand = new Uint8Array(32);
                globalThis.crypto.getRandomValues(rand);
                return rand;
              })();
        try {
          cryptoKey = await importNonExtractableDeviceCryptoKey(seedBytes);
          await idbPutKey(db, FREEZE_IDB_KEY_ID, cryptoKey);
        } finally {
          seedBytes.fill(0);
        }
      }

      const derived = await deriveWrappingKeyFromCryptoKey(cryptoKey);
      cachedIdbDerivedKeyHex = bytesToHex(derived);

      if (legacyHex && hasLocalStorage()) {
        // Decrypt any existing receipts that were encrypted with the legacy localStorage key
        // and re-seal them under the IndexedDB key before deleting the localStorage key.
        try {
          const currentReceipts = readReceiptsWithExtraFallback(oldLegacyWrappingKey);
          try {
            globalThis.localStorage.removeItem(FREEZE_DEVICE_KEY_STORAGE);
          } catch {
            // Ignore storage removal errors
          }
          memoryDeviceSecretHex = null;
          if (currentReceipts.length > 0) {
            writeReceipts(currentReceipts);
          }
        } finally {
          if (oldLegacyWrappingKey) oldLegacyWrappingKey.fill(0);
        }
      } else if (memoryDeviceSecretHex && hasLocalStorage()) {
        // Re-seal any receipts written with the temporary pre-init memory key under the IndexedDB key
        const tempKey = deriveWrappingKeyFromHex(memoryDeviceSecretHex);
        try {
          const currentReceipts = readReceiptsWithExtraFallback(tempKey);
          memoryDeviceSecretHex = null;
          if (currentReceipts.length > 0) {
            writeReceipts(currentReceipts);
          }
        } finally {
          tempKey.fill(0);
        }
      } else if (oldLegacyWrappingKey) {
        oldLegacyWrappingKey.fill(0);
      }

      return derived;
    } catch {
      return null;
    } finally {
      if (db && typeof db.close === "function") {
        try {
          db.close();
        } catch {
          // Ignore close errors
        }
      }
      pendingIdbMigration = null;
    }
  })();

  return pendingIdbMigration;
}

/**
 * Reads the non-extractable `CryptoKey` directly from IndexedDB (for verification and tests).
 */
export async function getIndexedDbDeviceCryptoKey(): Promise<CryptoKey | null> {
  const idb = getIndexedDBFactory();
  if (!idb) return null;
  let db: IDBDatabase | null = null;
  try {
    db = await openKeyStoreDb(idb);
    const found = await idbGetKey(db, FREEZE_IDB_KEY_ID);
    return isCryptoKeyLike(found) ? found : null;
  } catch {
    return null;
  } finally {
    if (db && typeof db.close === "function") {
      try {
        db.close();
      } catch {
        // Ignore
      }
    }
  }
}

/**
 * Resets cached device key state for unit tests.
 */
export function resetFreezeClientStateForTests(): void {
  memoryFallback = [];
  memoryDeviceSecretHex = null;
  cachedIdbDerivedKeyHex = null;
  pendingIdbMigration = null;
}

function getOrCreateDeviceWrappingKey(): Uint8Array {
  if (cachedIdbDerivedKeyHex && /^[0-9a-fA-F]{64}$/.test(cachedIdbDerivedKeyHex)) {
    return hexToBytes(cachedIdbDerivedKeyHex);
  }

  const idbAvailable = hasIndexedDB();
  let rawHex: string | null = null;
  if (hasLocalStorage()) {
    try {
      rawHex = globalThis.localStorage.getItem(FREEZE_DEVICE_KEY_STORAGE);
    } catch {
      rawHex = null;
    }
  }

  if (idbAvailable) {
    // Kick off migration / IndexedDB key initialization asynchronously.
    // Never write FREEZE_DEVICE_KEY_STORAGE to localStorage when IndexedDB is available.
    void ensureIndexedDbDeviceKey();
    if (rawHex && /^[0-9a-fA-F]{64}$/.test(rawHex)) {
      return deriveWrappingKeyFromHex(rawHex);
    }
    if (!memoryDeviceSecretHex || !/^[0-9a-fA-F]{64}$/.test(memoryDeviceSecretHex)) {
      const rand = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rand);
      memoryDeviceSecretHex = bytesToHex(rand);
      rand.fill(0);
    }
    return deriveWrappingKeyFromHex(memoryDeviceSecretHex);
  }

  // Fallback ONLY when IndexedDB is unavailable:
  if (!rawHex || !/^[0-9a-fA-F]{64}$/.test(rawHex)) {
    if (memoryDeviceSecretHex && /^[0-9a-fA-F]{64}$/.test(memoryDeviceSecretHex)) {
      rawHex = memoryDeviceSecretHex;
    } else {
      const rand = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rand);
      rawHex = bytesToHex(rand);
      rand.fill(0);
    }
    memoryDeviceSecretHex = rawHex;
    if (hasLocalStorage()) {
      try {
        globalThis.localStorage.setItem(FREEZE_DEVICE_KEY_STORAGE, rawHex);
      } catch {
        // Ignore storage quota errors
      }
    }
  } else {
    memoryDeviceSecretHex = rawHex;
  }

  return deriveWrappingKeyFromHex(rawHex);
}

function getCandidateWrappingKeys(extraFallback?: Uint8Array | null): {
  primary: Uint8Array;
  fallbacks: Uint8Array[];
} {
  const deviceKey = getOrCreateDeviceWrappingKey();
  const fallbacks: Uint8Array[] = [];
  if (memoryDeviceSecretHex && /^[0-9a-fA-F]{64}$/.test(memoryDeviceSecretHex)) {
    fallbacks.push(deriveWrappingKeyFromHex(memoryDeviceSecretHex));
  }
  if (extraFallback) {
    const copy = new Uint8Array(extraFallback.byteLength);
    copy.set(extraFallback);
    fallbacks.push(copy);
  }
  const vault = getCurrentVaultSession();
  if (vault && vault.vaultKeyHex && /^[0-9a-fA-F]{64}$/.test(vault.vaultKeyHex)) {
    return {
      primary: hexToBytes(vault.vaultKeyHex),
      fallbacks: [deviceKey, ...fallbacks],
    };
  }
  return {
    primary: deviceKey,
    fallbacks,
  };
}

function readReceiptsWithExtraFallback(extraFallback?: Uint8Array | null): StoredFreezeReceipt[] {
  if (hasLocalStorage()) {
    try {
      const raw = globalThis.localStorage.getItem(FREEZE_STORAGE_KEY);
      if (!raw) return [...memoryFallback];
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && "nonceHex" in parsed && "ciphertextHex" in parsed) {
        const { primary, fallbacks } = getCandidateWrappingKeys(extraFallback);
        const nonce = hexToBytes(String((parsed as { nonceHex: string }).nonceHex));
        const ct = hexToBytes(String((parsed as { ciphertextHex: string }).ciphertextHex));
        const candidates = [primary, ...fallbacks];
        for (const key of candidates) {
          try {
            const pt = gcm(key, nonce, FREEZE_RECEIPT_STORAGE_AAD).decrypt(ct);
            const list = JSON.parse(new TextDecoder().decode(pt));
            pt.fill(0);
            if (Array.isArray(list)) {
              return list as StoredFreezeReceipt[];
            }
          } catch {
            // Try next candidate key
          } finally {
            key.fill(0);
          }
        }
        return [...memoryFallback];
      }
      return [];
    } catch {
      return [...memoryFallback];
    }
  }
  return [...memoryFallback];
}

function readReceipts(): StoredFreezeReceipt[] {
  return readReceiptsWithExtraFallback(null);
}

function writeReceipts(receipts: StoredFreezeReceipt[]): void {
  memoryFallback = receipts.map((r) => ({ ...r }));
  if (hasLocalStorage()) {
    const { primary, fallbacks } = getCandidateWrappingKeys();
    try {
      const nonce = new Uint8Array(12);
      globalThis.crypto.getRandomValues(nonce);
      const plaintext = utf8ToBytes(JSON.stringify(receipts));
      const ciphertext = gcm(primary, nonce, FREEZE_RECEIPT_STORAGE_AAD).encrypt(plaintext);
      plaintext.fill(0);
      globalThis.localStorage.setItem(
        FREEZE_STORAGE_KEY,
        JSON.stringify({
          format: "drouter-freeze-receipts-v1-gcm",
          nonceHex: bytesToHex(nonce),
          ciphertextHex: bytesToHex(ciphertext),
        }),
      );
    } catch {
      // Ignore quota/storage errors and rely on memoryFallback
    } finally {
      primary.fill(0);
      for (const k of fallbacks) k.fill(0);
    }
  }
}

/**
 * Lists all locally stored FreezeReceipts (decrypted on the fly from localStorage).
 */
export function listLocalFreezeReceipts(): StoredFreezeReceipt[] {
  return readReceipts();
}

/**
 * Saves or updates a local FreezeReceipt in encrypted localStorage.
 */
export function saveLocalFreezeReceipt(receipt: StoredFreezeReceipt): void {
  const existing = readReceipts().filter((r) => r.blobId !== receipt.blobId);
  writeReceipts([receipt, ...existing]);
}

/**
 * Encrypts session state locally on the client, uploads ONLY the ciphertext bundle
 * (without freezeSecretHex or plaintext messages) to the server store, and saves
 * the FreezeReceipt encrypted at rest in localStorage.
 */
export async function freezeAndUpload(
  baseUrl: string,
  state: FrozenSessionState,
): Promise<
  StoredFreezeReceipt & {
    byteLength: number;
    expiresAt: number;
    resumeCode: string;
    storageMode: "mongodb" | "memory";
    persisted: boolean;
  }
> {
  await ensureIndexedDbDeviceKey();
  const coarseState: FrozenSessionState = {
    ...state,
    createdAt: coarsenEpochSecToHour(state.createdAt),
  };
  const bundle = encryptFrozenState(coarseState);
  const prefix = baseUrl.replace(/\/+$/, "");

  const uploadPayload = {
    version: bundle.version,
    blobId: bundle.blobId,
    sessionIdHex: bundle.sessionIdHex,
    nonceHex: bundle.nonceHex,
    aadHex: bundle.aadHex,
    ciphertextHex: bundle.ciphertextHex,
    modelId: bundle.modelId,
    createdAt: bundle.createdAt,
  };

  const res = await fetch(`${prefix}/api/freeze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(uploadPayload),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(
      typeof errBody?.error === "string"
        ? errBody.error
        : `Freeze upload failed with status ${res.status}`,
    );
  }

  const data = (await res.json()) as {
    stored: boolean;
    blobId: string;
    byteLength: number;
    createdAt?: number;
    expiresAt?: number;
    storageMode?: "mongodb" | "memory";
    persisted?: boolean;
  };

  const byteLength =
    typeof data.byteLength === "number"
      ? data.byteLength
      : bundle.ciphertextHex.length / 2;
  const expiresAt =
    typeof data.expiresAt === "number"
      ? data.expiresAt
      : coarsenEpochSecToHour(bundle.createdAt + 7 * 24 * 60 * 60);
  const storageMode = data.storageMode ?? "mongodb";
  const persisted = data.persisted ?? true;
  const resumeCode = formatResumeCode({
    blobId: bundle.blobId,
    freezeSecretHex: bundle.freezeSecretHex,
    sessionIdHex: bundle.sessionIdHex,
  });

  const receipt: StoredFreezeReceipt = {
    blobId: bundle.blobId,
    freezeSecretHex: bundle.freezeSecretHex,
    sessionIdHex: bundle.sessionIdHex,
    createdAt: bundle.createdAt,
    byteLength,
    expiresAt,
    modelId: bundle.modelId,
    storageMode,
    persisted,
    resumeCode,
  };

  saveLocalFreezeReceipt(receipt);

  return {
    ...receipt,
    byteLength,
    expiresAt,
    resumeCode,
    storageMode,
    persisted,
  };
}

/**
 * Downloads an encrypted session blob by blobId and decrypts it locally using
 * the client-held freezeSecretHex.
 */
export async function downloadAndResume(
  baseUrl: string,
  blobId: string,
  freezeSecretHex: string,
): Promise<FrozenSessionState> {
  const prefix = baseUrl.replace(/\/+$/, "");
  const cleanBlobId = (blobId ?? "").trim();
  const res = await fetch(`${prefix}/api/freeze/${encodeURIComponent(cleanBlobId)}`, {
    method: "GET",
  });

  if (res.status === 404) {
    throw new Error(`Frozen blob ${cleanBlobId} was destroyed or has expired`);
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch frozen blob ${cleanBlobId}: status ${res.status}`);
  }

  const bundle = (await res.json()) as {
    version?: number;
    blobId: string;
    sessionIdHex: string;
    nonceHex: string;
    aadHex: string;
    ciphertextHex: string;
  };

  return decryptFrozenState(bundle, freezeSecretHex);
}

/**
 * Resumes a frozen session directly from a copyable resume code
 * (`drouter-freeze-v1:<blobId>:<freezeSecretHex>[:<sessionIdHex>]` or JSON receipt).
 */
export async function downloadAndResumeFromCode(
  baseUrl: string,
  resumeCode: string,
): Promise<{ parsed: ReturnType<typeof parseResumeCode>; state: FrozenSessionState }> {
  const parsed = parseResumeCode(resumeCode);
  const state = await downloadAndResume(baseUrl, parsed.blobId, parsed.freezeSecretHex);
  return { parsed, state };
}

/**
 * Checks whether a frozen blob is still present and resumable on the server,
 * or if it has expired or been destroyed.
 */
export async function checkFrozenBlobStatus(
  baseUrl: string,
  blobId: string,
  knownExpiresAt?: number,
): Promise<FrozenBlobStatusCheck> {
  await ensureIndexedDbDeviceKey();
  const prefix = baseUrl.replace(/\/+$/, "");
  const cleanBlobId = (blobId ?? "").trim();
  const nowSec = Math.floor(Date.now() / 1000);

  if (knownExpiresAt && knownExpiresAt <= nowSec) {
    return {
      blobId: cleanBlobId,
      status: "expired",
      expiresAt: knownExpiresAt,
    };
  }

  try {
    const res = await fetch(`${prefix}/api/freeze/${encodeURIComponent(cleanBlobId)}`, {
      method: "GET",
    });
    if (res.status === 404) {
      const expired = Boolean(knownExpiresAt && knownExpiresAt <= nowSec);
      return {
        blobId: cleanBlobId,
        status: expired ? "expired" : "destroyed",
        expiresAt: knownExpiresAt,
      };
    }
    if (!res.ok) {
      return {
        blobId: cleanBlobId,
        status: "destroyed",
      };
    }
    const data = (await res.json()) as {
      blobId: string;
      byteLength?: number;
      modelId?: string;
      expiresAt?: number;
      storageMode?: "mongodb" | "memory";
      persisted?: boolean;
    };
    if (typeof data.expiresAt === "number" && data.expiresAt <= nowSec) {
      return {
        blobId: cleanBlobId,
        status: "expired",
        expiresAt: data.expiresAt,
      };
    }
    return {
      blobId: cleanBlobId,
      status: "resumable",
      expiresAt: data.expiresAt,
      byteLength: data.byteLength,
      modelId: data.modelId,
      storageMode: data.storageMode,
      persisted: data.persisted,
    };
  } catch {
    return {
      blobId: cleanBlobId,
      status: "destroyed",
    };
  }
}

/**
 * Crypto-shreds a frozen session locally by permanently zeroing and removing its
 * freezeSecretHex from encrypted local storage.
 */
export function shredLocalFreezeSecret(blobId: string): { shredded: boolean } {
  const cleanId = (blobId ?? "").trim().toLowerCase();
  const current = readReceipts();
  let shredded = false;
  const next: StoredFreezeReceipt[] = [];
  for (const r of current) {
    if (r.blobId.toLowerCase() === cleanId) {
      r.freezeSecretHex = "0".repeat(64);
      r.resumeCode = "";
      shredded = true;
    } else {
      next.push(r);
    }
  }
  writeReceipts(next);
  return { shredded };
}

/**
 * Explicit Destroy action:
 * 1. Wipes the local freezeSecretHex from browser memory and encrypted localStorage.
 * 2. Issues `DELETE /api/freeze/[blobId]` to physically delete the server-side ciphertext.
 * 3. Verifies via `GET /api/freeze/[blobId]` (expecting 404) and the DELETE response that the blob is gone.
 */
export async function destroyFrozenSession(
  baseUrl: string,
  blobId: string,
): Promise<DestroyFrozenSessionResult> {
  await ensureIndexedDbDeviceKey();
  const cleanBlobId = (blobId ?? "").trim().toLowerCase();
  const prefix = baseUrl.replace(/\/+$/, "");

  // Step 1: Always wipe local key first so even if network fails, secret is shredded locally.
  const local = shredLocalFreezeSecret(cleanBlobId);

  let serverDeleted = false;
  let verifiedAbsent = false;

  try {
    const delRes = await fetch(`${prefix}/api/freeze/${encodeURIComponent(cleanBlobId)}`, {
      method: "DELETE",
    });
    if (delRes.ok) {
      const body = (await delRes.json().catch(() => ({}))) as {
        deleted?: boolean;
        verifiedAbsent?: boolean;
      };
      serverDeleted = Boolean(body.deleted);
      if (body.verifiedAbsent === true) {
        verifiedAbsent = true;
      }
    }
  } catch {
    serverDeleted = false;
  }

  // Step 3: Double-verify absence by querying GET /api/freeze/[blobId] if not already confirmed
  if (!verifiedAbsent) {
    try {
      const checkRes = await fetch(`${prefix}/api/freeze/${encodeURIComponent(cleanBlobId)}`, {
        method: "GET",
      });
      if (checkRes.status === 404) {
        verifiedAbsent = true;
      }
    } catch {
      // Leave verifiedAbsent false if network unreachable
    }
  }

  return {
    blobId: cleanBlobId,
    localSecretWiped: local.shredded || !readReceipts().some((r) => r.blobId.toLowerCase() === cleanBlobId),
    serverDeleted,
    verifiedAbsent,
  };
}

export { formatResumeCode, parseResumeCode };
