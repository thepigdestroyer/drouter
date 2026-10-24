import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * IETF RFC 9458 Oblivious HTTP (OHTTP) & RFC 9180 HPKE Cipher Suite Identifiers:
 * - KEM:  0x0020 (DHKEM(X25519, HKDF-SHA256))
 * - KDF:  0x0001 (HKDF-SHA256)
 * - AEAD: 0x0001 (AES-128-GCM, Nk = 16, Nn = 12, Nt = 16)
 * - AEAD: 0x0002 (AES-256-GCM, Nk = 32, Nn = 12, Nt = 16)
 * - AEAD: 0x0003 (ChaCha20Poly1305, Nk = 32, Nn = 12, Nt = 16)
 */
export const OHTTP_KEM_ID_X25519_HKDF_SHA256 = 0x0020;
export const OHTTP_KDF_ID_HKDF_SHA256 = 0x0001;
export const OHTTP_AEAD_ID_AES_128_GCM = 0x0001;
export const OHTTP_AEAD_ID_AES_256_GCM = 0x0002;
export const OHTTP_AEAD_ID_CHACHA20_POLY1305 = 0x0003;

export const OHTTP_HEADER_LENGTH = 7;
export const OHTTP_X25519_PUBLIC_KEY_LENGTH = 32;
export const OHTTP_RESPONSE_NONCE_LENGTH = 32;
export const OHTTP_GCM_TAG_LENGTH = 16;

export interface OhttpSymmetricAlgorithm {
  kdfId: number;
  aeadId: number;
}

export interface OhttpKeyConfigInput {
  keyId: number;
  publicKey: Uint8Array;
  kemId?: number;
  kdfId?: number;
  aeadId?: number;
  symmetricAlgorithms?: OhttpSymmetricAlgorithm[];
}

export interface DecodedOhttpKeyConfig {
  keyId: number;
  kemId: number;
  publicKey: Uint8Array;
  kdfId: number;
  aeadId: number;
  symmetricAlgorithms: OhttpSymmetricAlgorithm[];
}

export interface OhttpContext {
  sharedSecret: Uint8Array;
  exporterSecret?: Uint8Array;
  enc: Uint8Array;
  keyId: number;
  aeadId?: number;
}

export interface EncapsulatedOhttpRequestResult {
  encapsulatedRequest: Uint8Array;
  clientContext: OhttpContext;
  infoBytes: Uint8Array;
}

export interface DecapsulatedOhttpRequestResult {
  plaintextHttpJson: string;
  plaintextBytes: Uint8Array;
  serverContext: OhttpContext;
}

export interface OhttpGatewayKeypair {
  keyId: number;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  keyConfigBytes: Uint8Array;
  keyConfigHex: string;
}

const textDecoder = new TextDecoder();
const HPKE_VERSION_LABEL = utf8ToBytes("HPKE-v1");
const KEM_SUITE_ID_X25519 = new Uint8Array([0x4b, 0x45, 0x4d, 0x00, 0x20]); // "KEM" || 0x0020
const EMPTY_BYTES = new Uint8Array(0);

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function writeUint16BE(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function readUint16BE(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
}

function aeadKeyLength(aeadId: number): number {
  if (aeadId === OHTTP_AEAD_ID_AES_128_GCM) return 16;
  if (aeadId === OHTTP_AEAD_ID_AES_256_GCM) return 32;
  throw new Error(
    `Unsupported HPKE AEAD ID: 0x${aeadId.toString(16).padStart(4, "0")} (expected 0x0001 AES-128-GCM or 0x0002 AES-256-GCM)`
  );
}

function responseNonceLengthForAead(aeadId: number): number {
  // RFC 9458 §4.2: Nonce length is max(Nn, Nk) where Nn = 12
  return Math.max(12, aeadKeyLength(aeadId));
}

function buildHpkeSuiteId(kemId: number, kdfId: number, aeadId: number): Uint8Array {
  return concatBytes(
    utf8ToBytes("HPKE"),
    writeUint16BE(kemId),
    writeUint16BE(kdfId),
    writeUint16BE(aeadId)
  );
}

/**
 * RFC 9180 §4 LabeledExtract(salt, label, ikm)
 */
function hpkeLabeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array
): Uint8Array {
  const labeledIkm = concatBytes(HPKE_VERSION_LABEL, suiteId, utf8ToBytes(label), ikm);
  return extract(sha256, labeledIkm, salt.length > 0 ? salt : undefined);
}

/**
 * RFC 9180 §4 LabeledExpand(prk, label, info, L)
 */
function hpkeLabeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number
): Uint8Array {
  const labeledInfo = concatBytes(
    writeUint16BE(length),
    HPKE_VERSION_LABEL,
    suiteId,
    utf8ToBytes(label),
    info
  );
  return expand(sha256, prk, labeledInfo, length);
}

/**
 * RFC 9180 §4.1 DHKEM(X25519, HKDF-SHA256) ExtractAndExpand
 */
function deriveDhkemSharedSecret(
  dhShared: Uint8Array,
  enc: Uint8Array,
  gatewayPublicKey: Uint8Array
): Uint8Array {
  const kemContext = concatBytes(enc, gatewayPublicKey);
  const eaePrk = hpkeLabeledExtract(KEM_SUITE_ID_X25519, EMPTY_BYTES, "eae_prk", dhShared);
  return hpkeLabeledExpand(KEM_SUITE_ID_X25519, eaePrk, "shared_secret", kemContext, 32);
}

/**
 * RFC 9180 §5.1 KeySchedule(mode_base = 0x00, shared_secret, info, psk = "", psk_id = "")
 * and RFC 9458 §4.3 request info binding ("message/bhttp request" || 0x00 || hdr).
 */
function deriveHpkeKeySchedule(
  sharedSecret: Uint8Array,
  headerBytes: Uint8Array,
  aeadId = OHTTP_AEAD_ID_AES_256_GCM
): {
  key: Uint8Array;
  baseNonce: Uint8Array;
  exporterSecret: Uint8Array;
  infoBytes: Uint8Array;
} {
  const nk = aeadKeyLength(aeadId);
  const nn = 12;
  const nh = 32;
  const suiteId = buildHpkeSuiteId(
    OHTTP_KEM_ID_X25519_HKDF_SHA256,
    OHTTP_KDF_ID_HKDF_SHA256,
    aeadId
  );

  const infoBytes = concatBytes(
    utf8ToBytes("message/bhttp request"),
    new Uint8Array([0x00]),
    headerBytes
  );

  const pskIdHash = hpkeLabeledExtract(suiteId, EMPTY_BYTES, "psk_id_hash", EMPTY_BYTES);
  const infoHash = hpkeLabeledExtract(suiteId, EMPTY_BYTES, "info_hash", infoBytes);
  const ksContext = concatBytes(new Uint8Array([0x00]), pskIdHash, infoHash);

  const secret = hpkeLabeledExtract(suiteId, sharedSecret, "secret", EMPTY_BYTES);
  const key = hpkeLabeledExpand(suiteId, secret, "key", ksContext, nk);
  const baseNonce = hpkeLabeledExpand(suiteId, secret, "base_nonce", ksContext, nn);
  const exporterSecret = hpkeLabeledExpand(suiteId, secret, "exp", ksContext, nh);

  return { key, baseNonce, exporterSecret, infoBytes };
}

/**
 * RFC 9180 §5.3 Context.Export(exporter_context, L)
 */
export function hpkeContextExport(
  exporterSecret: Uint8Array,
  exporterContext: Uint8Array,
  length: number,
  aeadId = OHTTP_AEAD_ID_AES_256_GCM
): Uint8Array {
  const suiteId = buildHpkeSuiteId(
    OHTTP_KEM_ID_X25519_HKDF_SHA256,
    OHTTP_KDF_ID_HKDF_SHA256,
    aeadId
  );
  return hpkeLabeledExpand(suiteId, exporterSecret, "sec", exporterContext, length);
}

/**
 * RFC 9458 §4.4 Response Key and Nonce Derivation
 */
export function deriveResponseKeyAndNonce(
  context: OhttpContext,
  responseNonce: Uint8Array
): {
  exportedSecret: Uint8Array;
  prk: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  aad: Uint8Array;
} {
  const aeadId = context.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM;
  const nk = aeadKeyLength(aeadId);
  const nn = 12;
  const secretLen = Math.max(nn, nk);

  let exporterSecret = context.exporterSecret;
  if (!exporterSecret) {
    const headerBytes = buildOhttpHeader(
      context.keyId,
      OHTTP_KEM_ID_X25519_HKDF_SHA256,
      OHTTP_KDF_ID_HKDF_SHA256,
      aeadId
    );
    exporterSecret = deriveHpkeKeySchedule(context.sharedSecret, headerBytes, aeadId).exporterSecret;
  }

  const exportedSecret = hpkeContextExport(
    exporterSecret,
    utf8ToBytes("message/bhttp response"),
    secretLen,
    aeadId
  );

  const salt = concatBytes(context.enc, responseNonce);
  const prk = extract(sha256, exportedSecret, salt);
  const key = expand(sha256, prk, utf8ToBytes("key"), nk);
  const nonce = expand(sha256, prk, utf8ToBytes("nonce"), nn);

  return {
    exportedSecret,
    prk,
    key,
    nonce,
    aad: EMPTY_BYTES,
  };
}

/**
 * Encodes an RFC 9458 §3.1 OHTTP Key Configuration structure:
 *   Key Identifier (1B) ||
 *   HPKE KEM ID (2B, 0x0020) ||
 *   HPKE Public Key (32B X25519) ||
 *   HPKE Symmetric Algorithms Length (2B) ||
 *   (HPKE KDF ID (2B) || HPKE AEAD ID (2B))...
 */
export function encodeOhttpKeyConfig(config: OhttpKeyConfigInput): Uint8Array {
  if (!Number.isInteger(config.keyId) || config.keyId < 0 || config.keyId > 255) {
    throw new Error(`Invalid OHTTP keyId: ${config.keyId} (expected uint8 0..255)`);
  }
  if (
    !(config.publicKey instanceof Uint8Array) ||
    config.publicKey.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Invalid X25519 publicKey length: ${config.publicKey?.length ?? 0} (expected 32 bytes)`
    );
  }

  const kemId = config.kemId ?? OHTTP_KEM_ID_X25519_HKDF_SHA256;
  const algs: OhttpSymmetricAlgorithm[] =
    config.symmetricAlgorithms && config.symmetricAlgorithms.length > 0
      ? config.symmetricAlgorithms
      : [
          {
            kdfId: config.kdfId ?? OHTTP_KDF_ID_HKDF_SHA256,
            aeadId: config.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM,
          },
        ];

  const algBytes = algs.map((a) =>
    concatBytes(writeUint16BE(a.kdfId), writeUint16BE(a.aeadId))
  );

  return concatBytes(
    new Uint8Array([config.keyId & 0xff]),
    writeUint16BE(kemId),
    config.publicKey,
    writeUint16BE(algs.length * 4),
    ...algBytes
  );
}

/**
 * Decodes and validates an RFC 9458 §3.1 OHTTP Key Configuration structure.
 */
export function decodeOhttpKeyConfig(bytes: Uint8Array): DecodedOhttpKeyConfig {
  if (!(bytes instanceof Uint8Array) || bytes.length < 41) {
    throw new Error(
      `Invalid OHTTP KeyConfig length: ${bytes?.length ?? 0} (minimum 41 bytes required)`
    );
  }

  const keyId = bytes[0];
  const kemId = readUint16BE(bytes, 1);
  if (kemId !== OHTTP_KEM_ID_X25519_HKDF_SHA256) {
    throw new Error(
      `Unsupported OHTTP KEM ID: 0x${kemId.toString(16).padStart(4, "0")} (expected 0x0020)`
    );
  }

  const publicKey = bytes.slice(3, 3 + OHTTP_X25519_PUBLIC_KEY_LENGTH);
  const symAlgLength = readUint16BE(bytes, 35);
  if (symAlgLength < 4 || symAlgLength % 4 !== 0 || 37 + symAlgLength !== bytes.length) {
    throw new Error(
      `Invalid OHTTP Symmetric Algorithms length: ${symAlgLength} (remaining bytes: ${bytes.length - 37})`
    );
  }

  const symmetricAlgorithms: OhttpSymmetricAlgorithm[] = [];
  for (let offset = 37; offset < 37 + symAlgLength; offset += 4) {
    const kdfId = readUint16BE(bytes, offset);
    const aeadId = readUint16BE(bytes, offset + 2);
    if (kdfId !== OHTTP_KDF_ID_HKDF_SHA256) {
      throw new Error(
        `Unsupported OHTTP KDF ID: 0x${kdfId.toString(16).padStart(4, "0")} (expected 0x0001)`
      );
    }
    if (
      aeadId !== OHTTP_AEAD_ID_AES_128_GCM &&
      aeadId !== OHTTP_AEAD_ID_AES_256_GCM &&
      aeadId !== OHTTP_AEAD_ID_CHACHA20_POLY1305
    ) {
      throw new Error(
        `Unsupported OHTTP AEAD ID: 0x${aeadId.toString(16).padStart(4, "0")} (expected 0x0001, 0x0002, or 0x0003)`
      );
    }
    symmetricAlgorithms.push({ kdfId, aeadId });
  }

  return {
    keyId,
    kemId,
    publicKey,
    kdfId: symmetricAlgorithms[0].kdfId,
    aeadId: symmetricAlgorithms[0].aeadId,
    symmetricAlgorithms,
  };
}

function buildOhttpHeader(
  keyId: number,
  kemId = OHTTP_KEM_ID_X25519_HKDF_SHA256,
  kdfId = OHTTP_KDF_ID_HKDF_SHA256,
  aeadId = OHTTP_AEAD_ID_AES_256_GCM
): Uint8Array {
  return concatBytes(
    new Uint8Array([keyId & 0xff]),
    writeUint16BE(kemId),
    writeUint16BE(kdfId),
    writeUint16BE(aeadId)
  );
}

export interface EncapsulateOhttpRequestOptions {
  aeadId?: number;
  ephemeralPrivateKey?: Uint8Array;
}

/**
 * Encapsulates a plaintext HTTP/JSON or binary HTTP request into an RFC 9458 binary Encapsulated Request
 * using genuine RFC 9180 HPKE Base mode (DHKEM(X25519, HKDF-SHA256)):
 *   Header (7B: [keyId(1), kemId(2), kdfId(2), aeadId(2)]) ||
 *   enc (32B ephemeral X25519 public key) ||
 *   HPKE AEAD Ciphertext (plaintext + 16B GCM tag)
 */
export function encapsulateOhttpRequest(
  plaintextHttpJson: string | Uint8Array,
  gatewayPublicKey: Uint8Array,
  keyId = 1,
  options?: EncapsulateOhttpRequestOptions
): EncapsulatedOhttpRequestResult {
  if (
    !(gatewayPublicKey instanceof Uint8Array) ||
    gatewayPublicKey.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Invalid gatewayPublicKey length: ${gatewayPublicKey?.length ?? 0} (expected 32 bytes)`
    );
  }
  if (!Number.isInteger(keyId) || keyId < 0 || keyId > 255) {
    throw new Error(`Invalid OHTTP keyId: ${keyId} (expected uint8 0..255)`);
  }

  const aeadId = options?.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM;
  aeadKeyLength(aeadId);

  const headerBytes = buildOhttpHeader(
    keyId,
    OHTTP_KEM_ID_X25519_HKDF_SHA256,
    OHTTP_KDF_ID_HKDF_SHA256,
    aeadId
  );

  const ephemeralSecretKey =
    options?.ephemeralPrivateKey instanceof Uint8Array
      ? options.ephemeralPrivateKey
      : x25519.keygen().secretKey;
  if (ephemeralSecretKey.length !== 32) {
    throw new Error("Invalid ephemeralPrivateKey length: expected 32 bytes");
  }

  const enc = x25519.getPublicKey(ephemeralSecretKey);
  const dhShared = x25519.getSharedSecret(ephemeralSecretKey, gatewayPublicKey);
  const sharedSecret = deriveDhkemSharedSecret(dhShared, enc, gatewayPublicKey);

  const { key, baseNonce, exporterSecret, infoBytes } = deriveHpkeKeySchedule(
    sharedSecret,
    headerBytes,
    aeadId
  );

  const plaintextBytes =
    typeof plaintextHttpJson === "string"
      ? utf8ToBytes(plaintextHttpJson)
      : plaintextHttpJson;

  // RFC 9458 §4.3 step 4: ct = sctxt.Seal("", request)
  const cipher = gcm(key, baseNonce, EMPTY_BYTES);
  const ciphertext = cipher.encrypt(plaintextBytes);

  return {
    encapsulatedRequest: concatBytes(headerBytes, enc, ciphertext),
    clientContext: {
      sharedSecret,
      exporterSecret,
      enc,
      keyId: keyId & 0xff,
      aeadId,
    },
    infoBytes,
  };
}

/**
 * Decapsulates an RFC 9458 binary Encapsulated Request inside the OHTTP Target Gateway
 * using RFC 9180 HPKE SetupBaseR and Open("", ct).
 */
export function decapsulateOhttpRequest(
  encapsulatedRequest: Uint8Array,
  gatewayPrivateKey: Uint8Array
): DecapsulatedOhttpRequestResult {
  if (
    !(gatewayPrivateKey instanceof Uint8Array) ||
    gatewayPrivateKey.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Invalid gatewayPrivateKey length: ${gatewayPrivateKey?.length ?? 0} (expected 32 bytes)`
    );
  }

  const minLength =
    OHTTP_HEADER_LENGTH + OHTTP_X25519_PUBLIC_KEY_LENGTH + OHTTP_GCM_TAG_LENGTH;
  if (!(encapsulatedRequest instanceof Uint8Array) || encapsulatedRequest.length < minLength) {
    throw new Error(
      `Invalid encapsulatedRequest length: ${encapsulatedRequest?.length ?? 0} (minimum ${minLength} bytes)`
    );
  }

  const headerBytes = encapsulatedRequest.slice(0, OHTTP_HEADER_LENGTH);
  const keyId = headerBytes[0];
  const kemId = readUint16BE(headerBytes, 1);
  const kdfId = readUint16BE(headerBytes, 3);
  const aeadId = readUint16BE(headerBytes, 5);

  if (kemId !== OHTTP_KEM_ID_X25519_HKDF_SHA256) {
    throw new Error(
      `Unsupported or tampered OHTTP KEM ID in header: 0x${kemId.toString(16).padStart(4, "0")}`
    );
  }
  if (kdfId !== OHTTP_KDF_ID_HKDF_SHA256) {
    throw new Error(
      `Unsupported or tampered OHTTP KDF ID in header: 0x${kdfId.toString(16).padStart(4, "0")}`
    );
  }
  if (aeadId !== OHTTP_AEAD_ID_AES_128_GCM && aeadId !== OHTTP_AEAD_ID_AES_256_GCM) {
    throw new Error(
      `Unsupported or tampered OHTTP AEAD ID in header: 0x${aeadId.toString(16).padStart(4, "0")}`
    );
  }

  const enc = encapsulatedRequest.slice(
    OHTTP_HEADER_LENGTH,
    OHTTP_HEADER_LENGTH + OHTTP_X25519_PUBLIC_KEY_LENGTH
  );
  const ciphertext = encapsulatedRequest.slice(
    OHTTP_HEADER_LENGTH + OHTTP_X25519_PUBLIC_KEY_LENGTH
  );

  const gatewayPublicKey = x25519.getPublicKey(gatewayPrivateKey);
  const dhShared = x25519.getSharedSecret(gatewayPrivateKey, enc);
  const sharedSecret = deriveDhkemSharedSecret(dhShared, enc, gatewayPublicKey);

  const { key, baseNonce, exporterSecret } = deriveHpkeKeySchedule(
    sharedSecret,
    headerBytes,
    aeadId
  );
  const cipher = gcm(key, baseNonce, EMPTY_BYTES);
  const plaintextBytes = cipher.decrypt(ciphertext);

  return {
    plaintextHttpJson: textDecoder.decode(plaintextBytes),
    plaintextBytes,
    serverContext: {
      sharedSecret,
      exporterSecret,
      enc,
      keyId,
      aeadId,
    },
  };
}

/**
 * Encapsulates an HTTP/JSON or binary HTTP response from the OHTTP Gateway using RFC 9458 §4.4:
 *   responseNonce (max(Nn, Nk) random bytes) || AEAD-Protected Response
 */
export function encapsulateOhttpResponse(
  responseJson: string | Uint8Array,
  serverContext: OhttpContext,
  customResponseNonce?: Uint8Array
): Uint8Array {
  if (
    !serverContext ||
    !(serverContext.sharedSecret instanceof Uint8Array) ||
    serverContext.sharedSecret.length !== 32 ||
    !(serverContext.enc instanceof Uint8Array) ||
    serverContext.enc.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error("Invalid OHTTP serverContext");
  }

  const aeadId = serverContext.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM;
  const expectedNonceLen = responseNonceLengthForAead(aeadId);

  const responseNonce =
    customResponseNonce instanceof Uint8Array
      ? customResponseNonce
      : globalThis.crypto.getRandomValues(new Uint8Array(expectedNonceLen));

  if (responseNonce.length !== expectedNonceLen) {
    throw new Error(
      `Invalid OHTTP responseNonce length: ${responseNonce.length} (expected ${expectedNonceLen} bytes)`
    );
  }

  const { key, nonce, aad } = deriveResponseKeyAndNonce(serverContext, responseNonce);

  const responseBytes =
    typeof responseJson === "string" ? utf8ToBytes(responseJson) : responseJson;
  const cipher = gcm(key, nonce, aad);
  const ciphertext = cipher.encrypt(responseBytes);

  return concatBytes(responseNonce, ciphertext);
}

/**
 * Decapsulates an RFC 9458 binary Encapsulated Response on the client using clientContext.
 */
export function decapsulateOhttpResponseBytes(
  encapsulatedResponse: Uint8Array,
  clientContext: OhttpContext
): Uint8Array {
  if (
    !clientContext ||
    !(clientContext.sharedSecret instanceof Uint8Array) ||
    clientContext.sharedSecret.length !== 32 ||
    !(clientContext.enc instanceof Uint8Array) ||
    clientContext.enc.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error("Invalid OHTTP clientContext");
  }

  const aeadId = clientContext.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM;
  const responseNonceLen = responseNonceLengthForAead(aeadId);
  const minLength = responseNonceLen + OHTTP_GCM_TAG_LENGTH;
  if (
    !(encapsulatedResponse instanceof Uint8Array) ||
    encapsulatedResponse.length < minLength
  ) {
    throw new Error(
      `Invalid encapsulatedResponse length: ${encapsulatedResponse?.length ?? 0} (minimum ${minLength} bytes)`
    );
  }

  const responseNonce = encapsulatedResponse.slice(0, responseNonceLen);
  const ciphertext = encapsulatedResponse.slice(responseNonceLen);

  const { key, nonce, aad } = deriveResponseKeyAndNonce(clientContext, responseNonce);

  const cipher = gcm(key, nonce, aad);
  return cipher.decrypt(ciphertext);
}

export function decapsulateOhttpResponse(
  encapsulatedResponse: Uint8Array,
  clientContext: OhttpContext
): string {
  const plaintextBytes = decapsulateOhttpResponseBytes(encapsulatedResponse, clientContext);
  return textDecoder.decode(plaintextBytes);
}

let ephemeralFallbackSeed: Uint8Array | null = null;

function resolveServerOhttpSeed(explicitSeed?: Uint8Array | string): Uint8Array {
  if (explicitSeed instanceof Uint8Array && explicitSeed.byteLength >= 16) {
    return explicitSeed;
  }
  if (typeof explicitSeed === "string" && explicitSeed.trim().length > 0) {
    const clean = explicitSeed.trim().replace(/^0x/i, "");
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length >= 32 && clean.length % 2 === 0) {
      return hexToBytes(clean);
    }
    return utf8ToBytes(explicitSeed.trim());
  }

  const envSecret =
    (typeof process !== "undefined" && process.env?.OHTTP_GATEWAY_SECRET) ||
    (typeof process !== "undefined" && process.env?.SIM_HARDWARE_SEED);

  if (typeof envSecret === "string" && envSecret.trim().length > 0) {
    const clean = envSecret.trim().replace(/^0x/i, "");
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length >= 32 && clean.length % 2 === 0) {
      return hexToBytes(clean);
    }
    return utf8ToBytes(envSecret.trim());
  }

  if (!ephemeralFallbackSeed) {
    ephemeralFallbackSeed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(ephemeralFallbackSeed);
  }
  return ephemeralFallbackSeed;
}

export const OHTTP_ALLOWED_INTERNAL_TARGETS = [
  "/api/v1/chat/completions",
  "/v1/chat/completions",
  "/api/v1/models",
  "/v1/models",
  "/api/v1/verify",
  "/v1/verify",
] as const;

export const OHTTP_SAME_OPERATOR_DISCLOSURE =
  "OHTTP RFC 9458 requires non-colluding Relay and Target Gateway operators so the Gateway never sees the client IP and the Relay never sees the plaintext HTTP payload. In this single-deployment app, the built-in relay and `/api/ohttp` Target Gateway are operated by the same party unless requests are routed through an independent third-party OHTTP Relay.";

/**
 * Normalizes and validates an inner HTTP target path against the strict internal gateway allowlist.
 * Prevents SSRF or arbitrary internal route probing by rejecting external URLs, path traversal, and non-allowlisted routes.
 */
export function resolveAllowlistedOhttpTarget(rawPath: string): {
  allowed: boolean;
  canonicalPath: "/api/v1/chat/completions" | "/api/v1/models" | "/api/v1/verify" | null;
  reason?: string;
} {
  if (typeof rawPath !== "string" || !rawPath.trim()) {
    return { allowed: false, canonicalPath: null, reason: "Missing inner target path" };
  }
  const trimmed = rawPath.trim();
  if (trimmed.includes("://") || trimmed.startsWith("//") || trimmed.includes("..")) {
    return {
      allowed: false,
      canonicalPath: null,
      reason: `Disallowed OHTTP inner target path: ${trimmed}`,
    };
  }
  const pathOnly = trimmed.split("?")[0];
  if (pathOnly === "/api/v1/chat/completions" || pathOnly === "/v1/chat/completions") {
    return { allowed: true, canonicalPath: "/api/v1/chat/completions" };
  }
  if (pathOnly === "/api/v1/models" || pathOnly === "/v1/models") {
    return { allowed: true, canonicalPath: "/api/v1/models" };
  }
  if (pathOnly === "/api/v1/verify" || pathOnly === "/v1/verify") {
    return { allowed: true, canonicalPath: "/api/v1/verify" };
  }
  return {
    allowed: false,
    canonicalPath: null,
    reason: `Target path '${pathOnly}' is not in the OHTTP gateway allowlist (${OHTTP_ALLOWED_INTERNAL_TARGETS.join(", ")})`,
  };
}

/**
 * Derives the Target Gateway X25519 keypair and RFC 9458 KeyConfig from a server secret
 * (`OHTTP_GATEWAY_SECRET` or `SIM_HARDWARE_SEED` via HKDF-SHA-256 with distinct domain separation
 * `drouter/ohttp-gateway-x25519/v1/key-id:<keyId>`), never a hardcoded string.
 */
export function getDefaultOhttpGatewayKeypair(
  keyId = 1,
  seedOverride?: Uint8Array | string
): OhttpGatewayKeypair {
  if (!Number.isInteger(keyId) || keyId < 0 || keyId > 255) {
    throw new Error(`Invalid OHTTP keyId: ${keyId} (expected uint8 0..255)`);
  }
  const ikm = resolveServerOhttpSeed(seedOverride);
  const privateKey = hkdf(
    sha256,
    ikm,
    utf8ToBytes("drouter/ohttp-gateway-salt/v1"),
    utf8ToBytes(`drouter/ohttp-gateway-x25519/v1/key-id:${keyId}`),
    32
  );
  const publicKey = x25519.getPublicKey(privateKey);
  const keyConfigBytes = encodeOhttpKeyConfig({ keyId, publicKey });
  return {
    keyId,
    privateKey,
    publicKey,
    keyConfigBytes,
    keyConfigHex: bytesToHex(keyConfigBytes),
  };
}

/**
 * Runs a full RFC 9458 KeyConfig + Request/Response round-trip self-test.
 */
export function runOhttpSelfTest() {
  const gateway = getDefaultOhttpGatewayKeypair(1);
  const decodedConfig = decodeOhttpKeyConfig(gateway.keyConfigBytes);

  const sampleRequestJson = JSON.stringify({
    method: "POST",
    path: "/v1/chat/completions",
    headers: { "content-type": "application/json" },
    body: {
      model: "kimi-k3",
      messages: [{ role: "user", content: "Verify RFC 9458 OHTTP binary framing." }],
    },
  });

  const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
    sampleRequestJson,
    decodedConfig.publicKey,
    decodedConfig.keyId
  );

  const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
    encapsulatedRequest,
    gateway.privateKey
  );

  const parsedRequest = JSON.parse(plaintextHttpJson) as {
    method?: string;
    path?: string;
    body?: { model?: string };
  };

  const sampleResponseJson = JSON.stringify({
    status: 200,
    headers: { "content-type": "application/json" },
    body: {
      ohttp: "rfc9458-verified",
      echoedMethod: parsedRequest.method ?? "POST",
      echoedPath: parsedRequest.path ?? "/v1/chat/completions",
      model: parsedRequest.body?.model ?? "kimi-k3",
    },
  });

  const encapsulatedResponse = encapsulateOhttpResponse(
    sampleResponseJson,
    serverContext
  );
  const decapsulatedResponseJson = decapsulateOhttpResponse(
    encapsulatedResponse,
    clientContext
  );

  return {
    rfc: "RFC 9458",
    mediaTypes: {
      keyConfig: "application/ohttp-keys",
      request: "message/ohttp-req",
      response: "message/ohttp-res",
    },
    cipherSuite: {
      kemId: "0x0020 (DHKEM_X25519_HKDF_SHA256)",
      kdfId: "0x0001 (HKDF_SHA256)",
      aeadId: "0x0002 (AES_256_GCM)",
    },
    keyId: decodedConfig.keyId,
    gatewayPublicKeyHex: bytesToHex(gateway.publicKey),
    keyConfigHex: gateway.keyConfigHex,
    keyConfigByteLength: gateway.keyConfigBytes.length,
    encapsulatedRequestByteLength: encapsulatedRequest.length,
    encapsulatedResponseByteLength: encapsulatedResponse.length,
    roundTripVerified:
      plaintextHttpJson === sampleRequestJson &&
      decapsulatedResponseJson === sampleResponseJson,
  };
}

export { bytesToHex, hexToBytes };
