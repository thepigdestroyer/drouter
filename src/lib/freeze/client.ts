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
const FREEZE_RECEIPT_STORAGE_AAD = utf8ToBytes("drouter/v1/freeze-receipt-storage");
const FREEZE_DEVICE_WRAP_SALT = utf8ToBytes("drouter/v1/freeze-device-wrap-salt");
const FREEZE_DEVICE_WRAP_INFO = utf8ToBytes("drouter/v1/freeze-device-wrap-key");

export interface StoredFreezeReceipt extends FreezeReceipt {
  byteLength?: number;
  expiresAt?: number;
  modelId?: string;
  storageMode?: "mongodb" | "simulated-memory";
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
  storageMode?: "mongodb" | "simulated-memory";
  persisted?: boolean;
}

let memoryFallback: StoredFreezeReceipt[] = [];
let memoryDeviceSecretHex: string | null = null;

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

function getOrCreateDeviceWrappingKey(): Uint8Array {
  let rawHex: string | null = null;
  if (hasLocalStorage()) {
    try {
      rawHex = globalThis.localStorage.getItem(FREEZE_DEVICE_KEY_STORAGE);
    } catch {
      rawHex = null;
    }
  }
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

  const rawBytes = hexToBytes(rawHex);
  try {
    return hkdf(sha384, rawBytes, FREEZE_DEVICE_WRAP_SALT, FREEZE_DEVICE_WRAP_INFO, 32);
  } finally {
    rawBytes.fill(0);
  }
}

function getCandidateWrappingKeys(): { primary: Uint8Array; fallbacks: Uint8Array[] } {
  const deviceKey = getOrCreateDeviceWrappingKey();
  const vault = getCurrentVaultSession();
  if (vault && vault.vaultKeyHex && /^[0-9a-fA-F]{64}$/.test(vault.vaultKeyHex)) {
    return {
      primary: hexToBytes(vault.vaultKeyHex),
      fallbacks: [deviceKey],
    };
  }
  return {
    primary: deviceKey,
    fallbacks: [],
  };
}

function readReceipts(): StoredFreezeReceipt[] {
  if (hasLocalStorage()) {
    try {
      const raw = globalThis.localStorage.getItem(FREEZE_STORAGE_KEY);
      if (!raw) return [...memoryFallback];
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && "nonceHex" in parsed && "ciphertextHex" in parsed) {
        const { primary, fallbacks } = getCandidateWrappingKeys();
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
    storageMode: "mongodb" | "simulated-memory";
    persisted: boolean;
  }
> {
  const coarseState: FrozenSessionState = {
    ...state,
    createdAt: coarsenEpochSecToHour(state.createdAt),
  };
  const bundle = encryptFrozenState(coarseState);
  const prefix = baseUrl.replace(/\/+$/, "");

  const uploadPayload = {
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
    storageMode?: "mongodb" | "simulated-memory";
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
      storageMode?: "mongodb" | "simulated-memory";
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
