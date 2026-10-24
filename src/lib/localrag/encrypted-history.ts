/**
 * Spec §1 & §2.5 — Encrypted-at-Rest Local Session History Store
 *
 * Keeps the browser's full conversation and document history locally encrypted
 * at rest using AES-256-GCM under a per-device 256-bit key. Plaintext history
 * never touches disk or localStorage; only authenticated ciphertext bundles are persisted.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const LOCAL_HISTORY_STORAGE_KEY = "drouter.localrag.history.v1";
export const LOCAL_DEVICE_KEY_STORAGE_KEY = "drouter.localrag.device-key.v1";
export const LOCAL_HISTORY_AAD_PREFIX = "drouter/v1/local-history:";

export interface LocalHistoryMessage {
  id?: string;
  role: "user" | "assistant" | "system" | string;
  content: string;
  createdAt?: number;
}

export interface LocalSessionHistory {
  sessionId: string;
  messages: LocalHistoryMessage[];
  documents?: Array<{ id: string; title?: string; content: string }>;
  updatedAt?: number;
}

export interface EncryptedHistoryBundle {
  format: "drouter-local-history-v1";
  algorithm: "AES-256-GCM";
  sessionId: string;
  nonceHex: string;
  aadHex: string;
  ciphertextHex: string;
  nonceBytes: Uint8Array;
  aadBytes: Uint8Array;
  ciphertextBytes: Uint8Array;
  sha256Hex: string;
  encryptedAt: number;
}

export type DeviceKeyInput = Uint8Array | string;

const memoryStore = new Map<string, string>();

function normalizeHex(hex: string): string {
  const trimmed = (hex ?? "").trim();
  return trimmed.startsWith("0x") || trimmed.startsWith("0X")
    ? trimmed.slice(2)
    : trimmed;
}

/**
 * Generates a fresh 256-bit (32-byte) per-device key using CSPRNG.
 */
export function generateDeviceHistoryKey(): Uint8Array {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  return key;
}

/**
 * Generates a fresh 256-bit (32-byte) per-device key encoded as a 64-char hex string.
 */
export function generateDeviceHistoryKeyHex(): string {
  return bytesToHex(generateDeviceHistoryKey());
}

/**
 * Normalizes and validates a 256-bit (32-byte) AES-GCM device key from either
 * a `Uint8Array` or a 64-character hex string. Rejects empty, wrong-length, or all-zero keys.
 */
export function normalizeDeviceKey(key: DeviceKeyInput): Uint8Array {
  let keyBytes: Uint8Array;

  if (key instanceof Uint8Array) {
    keyBytes = key;
  } else if (typeof key === "string") {
    const clean = normalizeHex(key);
    if (clean.length !== 64 || !/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error("Invalid device key: expected 256-bit (32-byte / 64-hex-char) key");
    }
    keyBytes = hexToBytes(clean);
  } else {
    throw new Error("Invalid device key type");
  }

  if (keyBytes.length !== 32) {
    throw new Error(`Invalid device key length: expected 32 bytes, got ${keyBytes.length}`);
  }

  let allZero = true;
  for (let i = 0; i < keyBytes.length; i++) {
    if (keyBytes[i] !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw new Error("Invalid device key: zeroed key is not permitted");
  }

  return keyBytes;
}

/**
 * Encrypts local session history at rest using AES-256-GCM under a per-device 256-bit key.
 * Binds the session ID into the GCM Additional Authenticated Data (AAD) so ciphertext
 * cannot be transplanted across sessions or tampered with on disk.
 */
export function encryptHistoryAtRest<T = LocalSessionHistory | LocalHistoryMessage[]>(
  history: T,
  deviceKey: DeviceKeyInput,
  options?: { sessionId?: string; nonce?: Uint8Array },
): EncryptedHistoryBundle {
  const keyBytes = normalizeDeviceKey(deviceKey);

  const inferredSessionId =
    options?.sessionId ??
    (history &&
    typeof history === "object" &&
    "sessionId" in (history as Record<string, unknown>) &&
    typeof (history as Record<string, unknown>).sessionId === "string"
      ? ((history as Record<string, unknown>).sessionId as string)
      : "default-local-session");

  const nonce = options?.nonce ? new Uint8Array(options.nonce) : new Uint8Array(12);
  if (!options?.nonce) {
    globalThis.crypto.getRandomValues(nonce);
  }
  if (nonce.length !== 12) {
    throw new Error("AES-256-GCM nonce must be 12 bytes (96 bits)");
  }

  const aadBytes = utf8ToBytes(`${LOCAL_HISTORY_AAD_PREFIX}${inferredSessionId}`);
  const serialized = JSON.stringify(history);
  if (typeof serialized !== "string") {
    throw new Error("History payload must be JSON-serializable");
  }

  const plaintextBytes = utf8ToBytes(serialized);
  const ciphertextBytes = gcm(keyBytes, nonce, aadBytes).encrypt(plaintextBytes);
  const ciphertextHex = bytesToHex(ciphertextBytes);
  const nonceHex = bytesToHex(nonce);
  const aadHex = bytesToHex(aadBytes);
  const sha256Hex = bytesToHex(sha256(ciphertextBytes));

  return {
    format: "drouter-local-history-v1",
    algorithm: "AES-256-GCM",
    sessionId: inferredSessionId,
    nonceHex,
    aadHex,
    ciphertextHex,
    nonceBytes: nonce,
    aadBytes,
    ciphertextBytes,
    sha256Hex,
    encryptedAt: Date.now(),
  };
}

/**
 * Decrypts and authenticates an `EncryptedHistoryBundle` (or its serialized JSON string)
 * using the per-device 256-bit AES-256-GCM key.
 * Throws if the key is wrong, or if any byte of the ciphertext, GCM tag, nonce, or AAD was tampered with.
 */
export function decryptHistoryAtRest<T = LocalSessionHistory | LocalHistoryMessage[]>(
  bundleOrJson:
    | string
    | {
        sessionId?: string;
        nonceHex?: string;
        aadHex?: string;
        ciphertextHex?: string;
        nonceBytes?: Uint8Array;
        aadBytes?: Uint8Array;
        ciphertextBytes?: Uint8Array;
        sha256Hex?: string;
      },
  deviceKey: DeviceKeyInput,
): T {
  const keyBytes = normalizeDeviceKey(deviceKey);

  let bundle: {
    sessionId?: string;
    nonceHex?: string;
    aadHex?: string;
    ciphertextHex?: string;
    nonceBytes?: Uint8Array;
    aadBytes?: Uint8Array;
    ciphertextBytes?: Uint8Array;
    sha256Hex?: string;
  };

  if (typeof bundleOrJson === "string") {
    try {
      bundle = JSON.parse(bundleOrJson);
    } catch {
      throw new Error("Failed to decrypt local history at rest: malformed bundle JSON");
    }
  } else if (bundleOrJson && typeof bundleOrJson === "object") {
    bundle = bundleOrJson;
  } else {
    throw new Error("Failed to decrypt local history at rest: missing bundle");
  }

  try {
    // Resolve and cross-check ciphertext bytes vs hex (detects tampering on either field)
    let ciphertextBytes: Uint8Array;
    if (bundle.ciphertextBytes instanceof Uint8Array && typeof bundle.ciphertextHex === "string") {
      const hexFromBytes = bytesToHex(bundle.ciphertextBytes).toLowerCase();
      const normalizedHex = normalizeHex(bundle.ciphertextHex).toLowerCase();
      if (hexFromBytes !== normalizedHex) {
        throw new Error("Ciphertext integrity mismatch between bytes and hex");
      }
      ciphertextBytes = bundle.ciphertextBytes;
    } else if (bundle.ciphertextBytes instanceof Uint8Array) {
      ciphertextBytes = bundle.ciphertextBytes;
    } else if (typeof bundle.ciphertextHex === "string") {
      ciphertextBytes = hexToBytes(normalizeHex(bundle.ciphertextHex));
    } else {
      throw new Error("Missing ciphertext");
    }

    // Resolve and cross-check nonce bytes vs hex
    let nonceBytes: Uint8Array;
    if (bundle.nonceBytes instanceof Uint8Array && typeof bundle.nonceHex === "string") {
      const hexFromBytes = bytesToHex(bundle.nonceBytes).toLowerCase();
      const normalizedHex = normalizeHex(bundle.nonceHex).toLowerCase();
      if (hexFromBytes !== normalizedHex) {
        throw new Error("Nonce integrity mismatch");
      }
      nonceBytes = bundle.nonceBytes;
    } else if (bundle.nonceBytes instanceof Uint8Array) {
      nonceBytes = bundle.nonceBytes;
    } else if (typeof bundle.nonceHex === "string") {
      nonceBytes = hexToBytes(normalizeHex(bundle.nonceHex));
    } else {
      throw new Error("Missing nonce");
    }

    // Resolve and cross-check AAD bytes vs hex and sessionId binding
    const sessionId = bundle.sessionId ?? "default-local-session";
    const expectedAadBytes = utf8ToBytes(`${LOCAL_HISTORY_AAD_PREFIX}${sessionId}`);
    const expectedAadHex = bytesToHex(expectedAadBytes).toLowerCase();

    let aadBytes: Uint8Array;
    if (bundle.aadBytes instanceof Uint8Array && typeof bundle.aadHex === "string") {
      const hexFromBytes = bytesToHex(bundle.aadBytes).toLowerCase();
      const normalizedHex = normalizeHex(bundle.aadHex).toLowerCase();
      if (hexFromBytes !== normalizedHex) {
        throw new Error("AAD integrity mismatch");
      }
      aadBytes = bundle.aadBytes;
    } else if (bundle.aadBytes instanceof Uint8Array) {
      aadBytes = bundle.aadBytes;
    } else if (typeof bundle.aadHex === "string") {
      aadBytes = hexToBytes(normalizeHex(bundle.aadHex));
    } else {
      aadBytes = expectedAadBytes;
    }

    if (bytesToHex(aadBytes).toLowerCase() !== expectedAadHex) {
      throw new Error("Session AAD binding mismatch");
    }

    if (
      typeof bundle.sha256Hex === "string" &&
      bytesToHex(sha256(ciphertextBytes)).toLowerCase() !==
        normalizeHex(bundle.sha256Hex).toLowerCase()
    ) {
      throw new Error("Ciphertext SHA-256 digest mismatch");
    }

    const plaintextBytes = gcm(keyBytes, nonceBytes, aadBytes).decrypt(ciphertextBytes);
    const jsonStr = new TextDecoder().decode(plaintextBytes);
    return JSON.parse(jsonStr) as T;
  } catch {
    throw new Error(
      "Failed to decrypt local history at rest: wrong key or tampered ciphertext",
    );
  }
}

/**
 * Persists an encrypted history bundle to local storage (or in-memory fallback in Node tests),
 * stripping raw `Uint8Array` views so the stored JSON representation contains only hex fields.
 */
export function saveEncryptedHistoryToStorage<T>(
  history: T,
  deviceKey: DeviceKeyInput,
  storageKey: string = LOCAL_HISTORY_STORAGE_KEY,
): EncryptedHistoryBundle {
  const bundle = encryptHistoryAtRest(history, deviceKey);
  const serializable = {
    format: bundle.format,
    algorithm: bundle.algorithm,
    sessionId: bundle.sessionId,
    nonceHex: bundle.nonceHex,
    aadHex: bundle.aadHex,
    ciphertextHex: bundle.ciphertextHex,
    sha256Hex: bundle.sha256Hex,
    encryptedAt: bundle.encryptedAt,
  };
  const payload = JSON.stringify(serializable);
  memoryStore.set(storageKey, payload);
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(storageKey, payload);
    }
  } catch {
    // Fallback to memoryStore
  }
  return bundle;
}

/**
 * Reads the raw string persisted on disk/localStorage so callers or auditors can verify
 * that no plaintext message content appears in storage.
 */
export function readRawEncryptedHistoryFromStorage(
  storageKey: string = LOCAL_HISTORY_STORAGE_KEY,
): string | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const val = window.localStorage.getItem(storageKey);
      if (val !== null) return val;
    }
  } catch {
    // Fallback to memoryStore
  }
  return memoryStore.get(storageKey) ?? null;
}

/**
 * Loads and decrypts local session history from storage using the per-device 256-bit key.
 */
export function loadEncryptedHistoryFromStorage<T = LocalSessionHistory>(
  deviceKey: DeviceKeyInput,
  storageKey: string = LOCAL_HISTORY_STORAGE_KEY,
): T | null {
  const raw = readRawEncryptedHistoryFromStorage(storageKey);
  if (!raw) return null;
  return decryptHistoryAtRest<T>(raw, deviceKey);
}
