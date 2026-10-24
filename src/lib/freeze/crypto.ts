import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { FrozenSessionState } from "@/lib/types";

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

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

function normalizeHex(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}

function isZeroOrEmptyHex(hex: string): boolean {
  const clean = normalizeHex(hex || "").trim();
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
  if (isZeroOrEmptyHex(freezeSecretHex)) {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  }
  const secretBytes = hexToBytes(normalizeHex(freezeSecretHex));
  const sessionBytes = hexToBytes(normalizeHex(sessionIdHex));
  return hkdf(sha384, secretBytes, sessionBytes, utf8ToBytes("drouter/v1/freeze"), 32);
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
  const nonce = randomBytes(12);
  const aad = utf8ToBytes("drouter/v1/freeze-blob:" + sidHex);
  const plaintext = utf8ToBytes(JSON.stringify(state));

  const ciphertext = gcm(key, nonce, aad).encrypt(plaintext);
  const blobId = bytesToHex(sha256(ciphertext)).slice(0, 32);

  return {
    blobId,
    freezeSecretHex: secretHex,
    sessionIdHex: sidHex,
    nonceHex: bytesToHex(nonce),
    aadHex: bytesToHex(aad),
    ciphertextHex: bytesToHex(ciphertext),
    modelId: state.modelId,
    createdAt: state.createdAt,
  };
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

  try {
    const sidHex = normalizeHex(bundle.sessionIdHex);
    const key = deriveFreezeKey(freezeSecretHex, sidHex);
    const nonce = hexToBytes(normalizeHex(bundle.nonceHex));
    const aad = hexToBytes(normalizeHex(bundle.aadHex));
    const expectedAadHex = bytesToHex(utf8ToBytes("drouter/v1/freeze-blob:" + sidHex));
    if (normalizeHex(bundle.aadHex).toLowerCase() !== expectedAadHex.toLowerCase()) {
      throw new Error("AAD mismatch");
    }
    const ciphertext = hexToBytes(normalizeHex(bundle.ciphertextHex));
    const plaintextBytes = gcm(key, nonce, aad).decrypt(ciphertext);
    const decoded = new TextDecoder().decode(plaintextBytes);
    return JSON.parse(decoded) as FrozenSessionState;
  } catch {
    throw new Error("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  }
}
