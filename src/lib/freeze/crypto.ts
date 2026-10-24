import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { FrozenSessionState } from "@/lib/types";

export const COARSE_TIME_WINDOW_SECONDS = 3600;
export const RESUME_CODE_PREFIX = "drouter-freeze-v1";

export interface EncryptedFrozenBundle {
  blobId: string;
  freezeSecretHex: string;
  sessionIdHex: string;
  nonceHex: string;
  aadHex: string;
  ciphertextHex: string;
  modelId: string;
  createdAt: number;
}

export interface ParsedResumeCode {
  blobId: string;
  freezeSecretHex: string;
  sessionIdHex?: string;
}

/**
 * Coarsens a Unix timestamp (in seconds or milliseconds) down to the start of its UTC hour
 * in Unix seconds, preventing exact timestamp correlation on the server or in logs.
 */
export function coarsenEpochSecToHour(timestamp?: number): number {
  const raw =
    typeof timestamp === "number" && Number.isFinite(timestamp) && timestamp > 0
      ? timestamp
      : Math.floor(Date.now() / 1000);
  // If passed milliseconds (e.g. > year 2100 in seconds), convert to seconds first
  const sec = raw > 10_000_000_000 ? Math.floor(raw / 1000) : Math.floor(raw);
  return sec - (sec % COARSE_TIME_WINDOW_SECONDS);
}

/**
 * Formats a compact, copyable resume code (`drouter-freeze-v1:<blobId>:<freezeSecretHex>[:<sessionIdHex>]`)
 * so a user can resume a frozen session across page reloads or devices without the server holding the key.
 */
export function formatResumeCode(params: {
  blobId: string;
  freezeSecretHex: string;
  sessionIdHex?: string;
}): string {
  const blobId = normalizeHex(params.blobId).toLowerCase();
  const secret = normalizeHex(params.freezeSecretHex).toLowerCase();
  if (!blobId || !secret || isZeroOrEmptyHex(secret)) {
    throw new Error("Cannot format resume code without valid blobId and freezeSecretHex");
  }
  const sid = params.sessionIdHex ? normalizeHex(params.sessionIdHex).toLowerCase() : "";
  return sid
    ? `${RESUME_CODE_PREFIX}:${blobId}:${secret}:${sid}`
    : `${RESUME_CODE_PREFIX}:${blobId}:${secret}`;
}

/**
 * Parses either a compact `drouter-freeze-v1:<blobId>:<freezeSecretHex>` resume code,
 * a `<blobId>:<freezeSecretHex>` pair, or a JSON receipt bundle.
 */
export function parseResumeCode(input: string): ParsedResumeCode {
  const trimmed = (input ?? "").trim();
  if (!trimmed) {
    throw new Error("Resume code is empty");
  }

  if (trimmed.startsWith("{")) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      throw new Error("Invalid JSON resume bundle");
    }
    const blobId = normalizeHex(String(parsed.blobId ?? "")).toLowerCase();
    const freezeSecretHex = normalizeHex(String(parsed.freezeSecretHex ?? "")).toLowerCase();
    const sessionIdHex = parsed.sessionIdHex
      ? normalizeHex(String(parsed.sessionIdHex)).toLowerCase()
      : undefined;
    if (!blobId || isZeroOrEmptyHex(blobId) || !freezeSecretHex || isZeroOrEmptyHex(freezeSecretHex)) {
      throw new Error("Resume JSON bundle is missing valid blobId or freezeSecretHex");
    }
    return { blobId, freezeSecretHex, sessionIdHex };
  }

  const parts = trimmed.split(":").map((p) => p.trim());
  if (parts[0] === RESUME_CODE_PREFIX) {
    if (parts.length < 3) {
      throw new Error("Malformed resume code");
    }
    const blobId = normalizeHex(parts[1]).toLowerCase();
    const freezeSecretHex = normalizeHex(parts[2]).toLowerCase();
    const sessionIdHex = parts[3] ? normalizeHex(parts[3]).toLowerCase() : undefined;
    if (isZeroOrEmptyHex(blobId) || isZeroOrEmptyHex(freezeSecretHex)) {
      throw new Error("Resume code contains invalid hex values");
    }
    return { blobId, freezeSecretHex, sessionIdHex };
  }

  if (parts.length === 2 || parts.length === 3) {
    const blobId = normalizeHex(parts[0]).toLowerCase();
    const freezeSecretHex = normalizeHex(parts[1]).toLowerCase();
    const sessionIdHex = parts[2] ? normalizeHex(parts[2]).toLowerCase() : undefined;
    if (!isZeroOrEmptyHex(blobId) && !isZeroOrEmptyHex(freezeSecretHex)) {
      return { blobId, freezeSecretHex, sessionIdHex };
    }
  }

  throw new Error("Unrecognized resume code format");
}

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

function normalizeHex(hex: string): string {
  const trimmed = (hex ?? "").trim();
  return trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  const cleanA = normalizeHex(a).toLowerCase();
  const cleanB = normalizeHex(b).toLowerCase();
  const maxLen = Math.max(cleanA.length, cleanB.length);
  let diff = cleanA.length ^ cleanB.length;
  for (let i = 0; i < maxLen; i++) {
    const codeA = i < cleanA.length ? cleanA.charCodeAt(i) : 0;
    const codeB = i < cleanB.length ? cleanB.charCodeAt(i) : 0;
    diff |= codeA ^ codeB;
  }
  return diff === 0;
}

function isZeroOrEmptyHex(hex: string): boolean {
  const clean = normalizeHex(hex || "");
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return true;
  }
  return /^0+$/.test(clean);
}

/**
 * Derives the 256-bit symmetric key K_freeze from the client-held freezeSecret
 * and sessionId using HKDF-SHA-384 with domain separation "drouter/v1/freeze".
 */
export function deriveFreezeKey(freezeSecretHex: string, sessionIdHex: string): Uint8Array {
  if (isZeroOrEmptyHex(freezeSecretHex) || isZeroOrEmptyHex(sessionIdHex)) {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  }
  const secretBytes = hexToBytes(normalizeHex(freezeSecretHex));
  const sessionBytes = hexToBytes(normalizeHex(sessionIdHex));
  try {
    return hkdf(sha384, secretBytes, sessionBytes, utf8ToBytes("drouter/v1/freeze"), 32);
  } finally {
    secretBytes.fill(0);
    sessionBytes.fill(0);
  }
}

/**
 * Encrypts a FrozenSessionState locally using AES-256-GCM under K_freeze.
 * The server only ever receives the resulting ciphertext bundle (without freezeSecretHex).
 */
export function encryptFrozenState(
  state: FrozenSessionState,
  freezeSecretHex?: string,
  sessionIdHex?: string,
): EncryptedFrozenBundle {
  const secretHex = freezeSecretHex
    ? normalizeHex(freezeSecretHex)
    : bytesToHex(randomBytes(32));
  const sidHex = sessionIdHex
    ? normalizeHex(sessionIdHex)
    : bytesToHex(randomBytes(16));

  const key = deriveFreezeKey(secretHex, sidHex);
  try {
    const nonce = randomBytes(12);
    const aad = utf8ToBytes("drouter/v1/freeze-blob:" + sidHex);
    const plaintext = utf8ToBytes(JSON.stringify(state));

    const ciphertext = gcm(key, nonce, aad).encrypt(plaintext);
    plaintext.fill(0);
    const blobId = bytesToHex(sha256(ciphertext)).slice(0, 32);

    return {
      blobId,
      freezeSecretHex: secretHex,
      sessionIdHex: sidHex,
      nonceHex: bytesToHex(nonce),
      aadHex: bytesToHex(aad),
      ciphertextHex: bytesToHex(ciphertext),
      modelId: state.modelId,
      createdAt: coarsenEpochSecToHour(state.createdAt),
    };
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypts an encrypted session bundle using the client-held freezeSecretHex.
 * Throws if the key is wrong, zeroed (crypto-shredded), or if ciphertext/AAD was tampered with.
 */
export function decryptFrozenState(
  bundle: {
    ciphertextHex: string;
    nonceHex: string;
    aadHex: string;
    sessionIdHex: string;
  },
  freezeSecretHex: string,
): FrozenSessionState {
  if (isZeroOrEmptyHex(freezeSecretHex)) {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  }

  let key: Uint8Array | null = null;
  try {
    const sidHex = normalizeHex(bundle.sessionIdHex);
    key = deriveFreezeKey(freezeSecretHex, sidHex);
    const cleanNonceHex = normalizeHex(bundle.nonceHex);
    if (cleanNonceHex.length !== 24) {
      throw new Error("Invalid nonce length");
    }
    const nonce = hexToBytes(cleanNonceHex);
    const aad = hexToBytes(normalizeHex(bundle.aadHex));
    const expectedAadHex = bytesToHex(utf8ToBytes("drouter/v1/freeze-blob:" + sidHex));
    if (!constantTimeEqualHex(bundle.aadHex, expectedAadHex)) {
      throw new Error("AAD mismatch");
    }
    const ciphertext = hexToBytes(normalizeHex(bundle.ciphertextHex));
    if (ciphertext.byteLength < 16) {
      throw new Error("Ciphertext too short");
    }
    const plaintextBytes = gcm(key, nonce, aad).decrypt(ciphertext);
    const decoded = new TextDecoder().decode(plaintextBytes);
    plaintextBytes.fill(0);
    return JSON.parse(decoded) as FrozenSessionState;
  } catch {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  } finally {
    if (key) key.fill(0);
  }
}
