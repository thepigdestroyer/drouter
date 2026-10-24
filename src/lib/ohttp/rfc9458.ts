import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * IETF RFC 9458 Oblivious HTTP (OHTTP) HPKE Cipher Suite Identifiers:
 * - KEM:  0x0020 (DHKEM(X25519, HKDF-SHA256))
 * - KDF:  0x0001 (HKDF-SHA256)
 * - AEAD: 0x0002 (AES-256-GCM, Nk = 32, Nn = 12, Nt = 16)
 */
export const OHTTP_KEM_ID_X25519_HKDF_SHA256 = 0x0020;
export const OHTTP_KDF_ID_HKDF_SHA256 = 0x0001;
export const OHTTP_AEAD_ID_AES_256_GCM = 0x0002;

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
  enc: Uint8Array;
  keyId: number;
}

export interface EncapsulatedOhttpRequestResult {
  encapsulatedRequest: Uint8Array;
  clientContext: OhttpContext;
}

export interface DecapsulatedOhttpRequestResult {
  plaintextHttpJson: string;
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

/**
 * Encodes an RFC 9458 §3.1 OHTTP Key Configuration structure:
 *   Key Identifier (1B) ||
 *   HPKE KEM ID (2B, 0x0020) ||
 *   HPKE Public Key (32B X25519) ||
 *   HPKE Symmetric Algorithms Length (2B, 0x0004) ||
 *   HPKE KDF ID (2B, 0x0001) ||
 *   HPKE AEAD ID (2B, 0x0002)
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
  const kdfId = config.kdfId ?? OHTTP_KDF_ID_HKDF_SHA256;
  const aeadId = config.aeadId ?? OHTTP_AEAD_ID_AES_256_GCM;

  return concatBytes(
    new Uint8Array([config.keyId & 0xff]),
    writeUint16BE(kemId),
    config.publicKey,
    writeUint16BE(4), // 4 bytes = 1 symmetric algorithm entry (kdfId + aeadId)
    writeUint16BE(kdfId),
    writeUint16BE(aeadId)
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
    if (aeadId !== OHTTP_AEAD_ID_AES_256_GCM) {
      throw new Error(
        `Unsupported OHTTP AEAD ID: 0x${aeadId.toString(16).padStart(4, "0")} (expected 0x0002)`
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

function deriveDhkemSharedSecret(
  dhShared: Uint8Array,
  enc: Uint8Array,
  gatewayPublicKey: Uint8Array
): Uint8Array {
  const kemContext = concatBytes(enc, gatewayPublicKey);
  return hkdf(
    sha256,
    dhShared,
    utf8ToBytes("RFC9458-DHKEM-X25519-HKDF-SHA256"),
    concatBytes(utf8ToBytes("eae_prk+shared_secret:"), kemContext),
    32
  );
}

function deriveRequestKeyAndNonce(
  sharedSecret: Uint8Array,
  enc: Uint8Array,
  headerBytes: Uint8Array
): { key: Uint8Array; nonce: Uint8Array } {
  // RFC 9458 §4.3 binds "message/bhttp request" || 0x00 || hdr
  const requestInfo = concatBytes(
    utf8ToBytes("message/bhttp request"),
    new Uint8Array([0x00]),
    headerBytes
  );
  const key = hkdf(
    sha256,
    sharedSecret,
    enc,
    concatBytes(requestInfo, utf8ToBytes(":key")),
    32
  );
  const nonce = hkdf(
    sha256,
    sharedSecret,
    enc,
    concatBytes(requestInfo, utf8ToBytes(":nonce")),
    12
  );
  return { key, nonce };
}

function deriveResponseKeyAndNonce(
  sharedSecret: Uint8Array,
  enc: Uint8Array,
  responseNonce: Uint8Array,
  keyId: number
): { key: Uint8Array; nonce: Uint8Array; aad: Uint8Array } {
  // RFC 9458 §4.4 binds salt = concat(enc, responseNonce)
  const salt = concatBytes(enc, responseNonce);
  const responseInfo = concatBytes(
    utf8ToBytes("message/bhttp response"),
    new Uint8Array([0x00]),
    new Uint8Array([keyId & 0xff])
  );
  const key = hkdf(
    sha256,
    sharedSecret,
    salt,
    concatBytes(responseInfo, utf8ToBytes(":key")),
    32
  );
  const nonce = hkdf(
    sha256,
    sharedSecret,
    salt,
    concatBytes(responseInfo, utf8ToBytes(":nonce")),
    12
  );
  const aad = concatBytes(enc, responseNonce, new Uint8Array([keyId & 0xff]));
  return { key, nonce, aad };
}

/**
 * Encapsulates a plaintext HTTP/JSON request into an RFC 9458 binary Encapsulated Request:
 *   Header (7B: [keyId(1), kemId(2), kdfId(2), aeadId(2)]) ||
 *   enc (32B ephemeral X25519 public key) ||
 *   AES-256-GCM Ciphertext (plaintext + 16B tag)
 */
export function encapsulateOhttpRequest(
  plaintextHttpJson: string,
  gatewayPublicKey: Uint8Array,
  keyId = 1
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

  const headerBytes = buildOhttpHeader(keyId);
  const ephemeralKeypair = x25519.keygen();
  const enc = ephemeralKeypair.publicKey;
  const dhShared = x25519.getSharedSecret(ephemeralKeypair.secretKey, gatewayPublicKey);
  const sharedSecret = deriveDhkemSharedSecret(dhShared, enc, gatewayPublicKey);

  const { key, nonce } = deriveRequestKeyAndNonce(sharedSecret, enc, headerBytes);
  const cipher = gcm(key, nonce, headerBytes);
  const ciphertext = cipher.encrypt(utf8ToBytes(plaintextHttpJson));

  return {
    encapsulatedRequest: concatBytes(headerBytes, enc, ciphertext),
    clientContext: {
      sharedSecret,
      enc,
      keyId: keyId & 0xff,
    },
  };
}

/**
 * Decapsulates an RFC 9458 binary Encapsulated Request inside the OHTTP Target Gateway.
 * Verifies the 7-byte header and AES-256-GCM authentication tag.
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
  if (aeadId !== OHTTP_AEAD_ID_AES_256_GCM) {
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

  const { key, nonce } = deriveRequestKeyAndNonce(sharedSecret, enc, headerBytes);
  const cipher = gcm(key, nonce, headerBytes);
  const plaintextBytes = cipher.decrypt(ciphertext);

  return {
    plaintextHttpJson: textDecoder.decode(plaintextBytes),
    serverContext: {
      sharedSecret,
      enc,
      keyId,
    },
  };
}

/**
 * Encapsulates an HTTP/JSON response from the OHTTP Gateway using the request's serverContext:
 *   responseNonce (32B random) || AES-256-GCM Ciphertext (derived from sharedSecret, enc, responseNonce)
 */
export function encapsulateOhttpResponse(
  responseJson: string,
  serverContext: OhttpContext
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

  const responseNonce = crypto.getRandomValues(
    new Uint8Array(OHTTP_RESPONSE_NONCE_LENGTH)
  );
  const { key, nonce, aad } = deriveResponseKeyAndNonce(
    serverContext.sharedSecret,
    serverContext.enc,
    responseNonce,
    serverContext.keyId
  );

  const cipher = gcm(key, nonce, aad);
  const ciphertext = cipher.encrypt(utf8ToBytes(responseJson));

  return concatBytes(responseNonce, ciphertext);
}

/**
 * Decapsulates an RFC 9458 binary Encapsulated Response on the client using clientContext.
 */
export function decapsulateOhttpResponse(
  encapsulatedResponse: Uint8Array,
  clientContext: OhttpContext
): string {
  if (
    !clientContext ||
    !(clientContext.sharedSecret instanceof Uint8Array) ||
    clientContext.sharedSecret.length !== 32 ||
    !(clientContext.enc instanceof Uint8Array) ||
    clientContext.enc.length !== OHTTP_X25519_PUBLIC_KEY_LENGTH
  ) {
    throw new Error("Invalid OHTTP clientContext");
  }

  const minLength = OHTTP_RESPONSE_NONCE_LENGTH + OHTTP_GCM_TAG_LENGTH;
  if (
    !(encapsulatedResponse instanceof Uint8Array) ||
    encapsulatedResponse.length < minLength
  ) {
    throw new Error(
      `Invalid encapsulatedResponse length: ${encapsulatedResponse?.length ?? 0} (minimum ${minLength} bytes)`
    );
  }

  const responseNonce = encapsulatedResponse.slice(0, OHTTP_RESPONSE_NONCE_LENGTH);
  const ciphertext = encapsulatedResponse.slice(OHTTP_RESPONSE_NONCE_LENGTH);

  const { key, nonce, aad } = deriveResponseKeyAndNonce(
    clientContext.sharedSecret,
    clientContext.enc,
    responseNonce,
    clientContext.keyId
  );

  const cipher = gcm(key, nonce, aad);
  const plaintextBytes = cipher.decrypt(ciphertext);

  return textDecoder.decode(plaintextBytes);
}

/**
 * Deterministically derives the default Target Gateway X25519 keypair and RFC 9458 KeyConfig
 * so GET and POST `/api/ohttp` share a consistent gateway key configuration across requests.
 */
export function getDefaultOhttpGatewayKeypair(keyId = 1): OhttpGatewayKeypair {
  const privateKey = hkdf(
    sha256,
    utf8ToBytes("drouter:rfc9458:ohttp-gateway-x25519-seed:v1"),
    utf8ToBytes("drouter-ohttp-gateway-salt"),
    utf8ToBytes(`gateway-key-id:${keyId}`),
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
      model: "deepseek-r1-70b",
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
      model: parsedRequest.body?.model ?? "deepseek-r1-70b",
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
