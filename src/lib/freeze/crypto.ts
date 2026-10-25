import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { FrozenSessionState } from "@/lib/types";

export const COARSE_TIME_WINDOW_SECONDS = 3600;
export const RESUME_CODE_PREFIX = "drouter-freeze-v1";
export const MIN_FREEZE_BUCKET_BYTES = 4096;
export const FREEZE_BLOB_VERSION_LEGACY = 1;
export const FREEZE_BLOB_VERSION_PADDED = 2;

const PADDED_FRAME_MAGIC = new Uint8Array([0x44, 0x52, 0x46, 0x32]); // "DRF2"
const PADDED_FRAME_HEADER_BYTES = 8; // 4-byte magic + 4-byte big-endian uint32 length

export interface EncryptedFrozenBundle {
  version: number;
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
 * Computes the smallest power-of-two bucket size (>= minBucketBytes) that can hold `totalRequiredBytes`.
 */
export function computeFreezeBucketSize(
  totalRequiredBytes: number,
  minBucketBytes: number = MIN_FREEZE_BUCKET_BYTES,
): number {
  let bucket = Math.max(MIN_FREEZE_BUCKET_BYTES, Math.floor(minBucketBytes));
  // Ensure starting bucket is a power of two
  if ((bucket & (bucket - 1)) !== 0) {
    let p = MIN_FREEZE_BUCKET_BYTES;
    while (p < bucket) p *= 2;
    bucket = p;
  }
  const target = Math.max(0, Math.floor(totalRequiredBytes));
  while (bucket < target) {
    bucket *= 2;
  }
  return bucket;
}

/**
 * Pads serialized UTF-8 plaintext bytes into a power-of-two bucket (minimum 4096 bytes)
 * with an unambiguous 8-byte header: 4-byte magic ("DRF2") + 4-byte big-endian uint32 byte length.
 */
export function padFreezePlaintext(
  payloadBytes: Uint8Array,
  minBucketBytes: number = MIN_FREEZE_BUCKET_BYTES,
): Uint8Array {
  const payloadLen = payloadBytes.byteLength;
  const totalNeeded = PADDED_FRAME_HEADER_BYTES + payloadLen;
  const bucketSize = computeFreezeBucketSize(totalNeeded, minBucketBytes);
  const frame = new Uint8Array(bucketSize);
  frame.set(PADDED_FRAME_MAGIC, 0);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  view.setUint32(4, payloadLen, false);
  frame.set(payloadBytes, PADDED_FRAME_HEADER_BYTES);
  return frame;
}

/**
 * Unpads a decrypted freeze payload, stripping the length prefix and trailing zero padding.
 * Supports legacy v1 unpadded UTF-8 JSON blobs when `version === 1` or when no "DRF2" magic is present.
 */
export function unpadFreezePlaintext(
  decryptedBytes: Uint8Array,
  version?: number,
): Uint8Array {
  if (version === FREEZE_BLOB_VERSION_LEGACY) {
    return decryptedBytes;
  }

  const hasMagic =
    decryptedBytes.byteLength >= PADDED_FRAME_HEADER_BYTES &&
    decryptedBytes[0] === PADDED_FRAME_MAGIC[0] &&
    decryptedBytes[1] === PADDED_FRAME_MAGIC[1] &&
    decryptedBytes[2] === PADDED_FRAME_MAGIC[2] &&
    decryptedBytes[3] === PADDED_FRAME_MAGIC[3];

  if (version === FREEZE_BLOB_VERSION_PADDED && !hasMagic) {
    throw new Error("Invalid padded freeze blob header");
  }

  if (hasMagic) {
    const view = new DataView(
      decryptedBytes.buffer,
      decryptedBytes.byteOffset,
      decryptedBytes.byteLength,
    );
    const payloadLen = view.getUint32(4, false);
    const endOffset = PADDED_FRAME_HEADER_BYTES + payloadLen;
    if (endOffset > decryptedBytes.byteLength) {
      throw new Error("Corrupted padded freeze blob length prefix");
    }
    for (let i = endOffset; i < decryptedBytes.byteLength; i++) {
      if (decryptedBytes[i] !== 0) {
        throw new Error("Non-zero padding byte in padded freeze blob");
      }
    }
    return decryptedBytes.subarray(PADDED_FRAME_HEADER_BYTES, endOffset);
  }

  // Fallback for legacy unpadded v1 blobs when version was omitted
  return decryptedBytes;
}

/**
 * Encrypts a FrozenSessionState locally using AES-256-GCM under K_freeze after padding
 * the serialized session to a power-of-two bucket (minimum 4096 bytes).
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
    const rawPlaintext = utf8ToBytes(JSON.stringify(state));
    const paddedPlaintext = padFreezePlaintext(rawPlaintext, MIN_FREEZE_BUCKET_BYTES);
    rawPlaintext.fill(0);

    const ciphertext = gcm(key, nonce, aad).encrypt(paddedPlaintext);
    paddedPlaintext.fill(0);
    const blobId = bytesToHex(sha256(ciphertext)).slice(0, 32);

    return {
      version: FREEZE_BLOB_VERSION_PADDED,
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
 * Supports both v2 padded blobs and legacy v1 unpadded blobs.
 * Throws if the key is wrong, zeroed (crypto-shredded), or if ciphertext/AAD was tampered with.
 */
export function decryptFrozenState(
  bundle: {
    version?: number;
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
    const unpaddedBytes = unpadFreezePlaintext(plaintextBytes, bundle.version);
    const decoded = new TextDecoder().decode(unpaddedBytes);
    plaintextBytes.fill(0);
    return JSON.parse(decoded) as FrozenSessionState;
  } catch {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  } finally {
    if (key) key.fill(0);
  }
}
