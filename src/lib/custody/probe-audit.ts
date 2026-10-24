import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { CustodyCtrDrbg } from "./drbg";
import {
  HASH_BLOCK_TOKENS,
  PrefixCachePool,
  computePrefixBlockHashes,
  constantTimeEqualBytes,
} from "./prefix-cache";

export interface CustodyPrimitiveVerificationReport {
  executionEnvironment: "software-uint8array";
  observesPhysicalGpuMemory: false;
  ctrDrbg: {
    deterministicForIdenticalSeeds: boolean;
    divergesOnClientEntropyReseed: boolean;
    zeroizedBuffersVerified: boolean;
  };
  prefixCache: {
    blockSizeTokens: number;
    sameSessionHitBlocks: number;
    sameSessionHitTokens: number;
    crossSessionHitBlocks: number;
    crossSessionHitTokens: number;
    constantTimeCompareVerified: boolean;
    popZeroizedVerified: boolean;
  };
  aesGcmEnvelope: {
    framesEncrypted: number;
    totalCiphertextBytes: number;
    plaintextSubstringMatchesInCiphertext: number;
    repeated16ByteCipherBlocks: number;
    ciphertextShannonEntropyBitsPerByte: number;
    decryptAfterKeyZeroizeFailed: boolean;
  };
  allPrimitivesPassed: boolean;
}

export interface MemoryBusAndPopAuditReport {
  mode: "model";
  simulated: true;
  observesPhysicalGpuMemory: false;
  note: string;
  v1Passed: boolean;
  v6Passed: boolean;
  turnsSimulated: number;
  totalHostBytesObserved: number;
  plaintextLeakMatches: number;
  repeated16ByteBlocks: number;
  shannonEntropyBitsPerByte: number;
  postPopAllZero: boolean;
  postPopOffloadDecryptFailed: boolean;
}

/**
 * Construct a 12-byte AES-GCM nonce from a 4-byte session prefix, 4-byte channel tag,
 * and a strictly monotonic 32-bit counter.
 */
export function buildMonotonicGcmNonce(
  noncePrefix: Uint8Array,
  channelId: number,
  counter: number
): Uint8Array {
  if (!Number.isInteger(counter) || counter <= 0 || counter > 0xffffffff) {
    throw new Error(`Custody GCM nonce counter out of range or wrapped: ${counter}`);
  }
  const nonce = new Uint8Array(12);
  nonce.set(noncePrefix.subarray(0, 4), 0);
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  view.setUint32(4, channelId >>> 0, false);
  view.setUint32(8, counter >>> 0, false);
  return nonce;
}

/**
 * Compute Shannon entropy in bits per byte (range 0..8) over a byte buffer.
 */
export function computeShannonEntropyBitsPerByte(bytes: Uint8Array): number {
  if (bytes.byteLength === 0) {
    return 0;
  }
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.byteLength; i++) {
    counts[bytes[i]] += 1;
  }

  const total = bytes.byteLength;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = counts[i];
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(4));
}

/**
 * Count how many times any needle appears inside a byte buffer.
 */
function countPlaintextSubstrings(
  buffer: Uint8Array,
  needles: Uint8Array[]
): number {
  let matches = 0;
  for (const needle of needles) {
    if (needle.byteLength === 0 || buffer.byteLength < needle.byteLength) {
      continue;
    }
    const limit = buffer.byteLength - needle.byteLength;
    for (let offset = 0; offset <= limit; offset++) {
      let allMatch = true;
      for (let j = 0; j < needle.byteLength; j++) {
        if (buffer[offset + j] !== needle[j]) {
          allMatch = false;
          break;
        }
      }
      if (allMatch) {
        matches += 1;
      }
    }
  }
  return matches;
}

/**
 * Count repeated 16-byte cipher blocks across encrypted byte buffers.
 */
function countRepeated16ByteBlocks(buffers: Uint8Array[]): number {
  const seen = new Set<string>();
  let duplicates = 0;

  for (const buf of buffers) {
    const fullBlocks = Math.floor(buf.byteLength / 16);
    for (let b = 0; b < fullBlocks; b++) {
      const slice = buf.subarray(b * 16, (b + 1) * 16);
      let hex = "";
      for (let i = 0; i < 16; i++) {
        hex += slice[i].toString(16).padStart(2, "0");
      }
      if (seen.has(hex)) {
        duplicates += 1;
      } else {
        seen.add(hex);
      }
    }
  }
  return duplicates;
}

/**
 * Verifies the real software cryptographic primitives in `src/lib/custody`:
 * 1. AES-256 CTR-DRBG determinism, entropy mixing, and `Uint8Array` zeroization
 * 2. Keyed HMAC-SHA-256 512-token prefix-cache isolation and constant-time key comparison
 * 3. Monotonic-nonce AES-256-GCM encryption, ciphertext Shannon entropy, and post-zeroize decryption rejection
 */
export function verifyCustodyPrimitives(): CustodyPrimitiveVerificationReport {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    seed[i] = (0x5a ^ (i * 17 + 31)) & 0xff;
  }

  // 1. CTR-DRBG determinism and entropy reseed
  const drbgDetA = new CustodyCtrDrbg(seed);
  const drbgDetB = new CustodyCtrDrbg(seed);
  const streamA = bytesToHex(drbgDetA.generate(32));
  const streamB = bytesToHex(drbgDetB.generate(32));
  const deterministicForIdenticalSeeds = streamA === streamB;

  drbgDetA.reseed(utf8ToBytes("caller-ephemeral-entropy"));
  const streamA2 = bytesToHex(drbgDetA.generate(32));
  const streamB2 = bytesToHex(drbgDetB.generate(32));
  const divergesOnClientEntropyReseed = streamA2 !== streamB2;
  drbgDetA.zeroize();
  drbgDetB.zeroize();

  // 2. Prefix cache & constant-time compare
  const drbg = new CustodyCtrDrbg(seed, utf8ToBytes("client-ephemeral-x25519-contribution-v1"));
  const sessionAlpha = drbg.deriveSessionKeys("sess-alpha");
  const sessionBeta = drbg.deriveSessionKeys("sess-beta");

  const keyCopy = new Uint8Array(sessionAlpha.sessionPrefixKey);
  const tamperedKey = new Uint8Array(sessionAlpha.sessionPrefixKey);
  tamperedKey[0] ^= 0xff;
  const constantTimeCompareVerified =
    constantTimeEqualBytes(sessionAlpha.sessionPrefixKey, keyCopy) &&
    !constantTimeEqualBytes(sessionAlpha.sessionPrefixKey, tamperedKey) &&
    !constantTimeEqualBytes(sessionAlpha.sessionPrefixKey, sessionBeta.sessionPrefixKey) &&
    !constantTimeEqualBytes(sessionAlpha.sessionPrefixKey, new Uint8Array(16));

  const prefixPool = new PrefixCachePool();
  const sampleTokens = Array.from({ length: HASH_BLOCK_TOKENS * 3 }, (_, idx) => 1000 + idx);
  prefixPool.storePrefix(sessionAlpha.sessionId, sampleTokens, sessionAlpha.sessionPrefixKey);

  const sameSessionHit = prefixPool.lookupLongestPrefix(
    sessionAlpha.sessionId,
    sampleTokens,
    sessionAlpha.sessionPrefixKey
  );
  const crossSessionHit = prefixPool.lookupLongestPrefix(
    sessionBeta.sessionId,
    sampleTokens,
    sessionBeta.sessionPrefixKey
  );
  const hashesAlpha = computePrefixBlockHashes(sampleTokens, sessionAlpha.sessionPrefixKey);
  const hashesBeta = computePrefixBlockHashes(sampleTokens, sessionBeta.sessionPrefixKey);
  const hashesDistinct = hashesAlpha.every((h, idx) => h !== hashesBeta[idx]);

  // 3. Monotonic-nonce AES-256-GCM encryption in local Uint8Array memory
  const turns = 5;
  const sampleCore =
    "TRIAL_SUBJECT_ID=DR-0042;ARM=BLINDED_TREATMENT_B;TOKEN=sk_live_drouter_sample_token;";
  const repeatedPlaintext = Array.from({ length: 16 }, () => sampleCore).join("|");
  const plaintextBytes = utf8ToBytes(repeatedPlaintext);
  const needles: Uint8Array[] = [
    utf8ToBytes("TRIAL_SUBJECT_ID"),
    utf8ToBytes("BLINDED_TREATMENT_B"),
    utf8ToBytes("sk_live_drouter_sample_token"),
    plaintextBytes.subarray(0, 32),
  ];

  let trafficCounter = 1;
  let offloadCounter = 1;
  const trackedPlaintextBuffers: Uint8Array[] = [];
  const ciphertextBuffers: Uint8Array[] = [];
  const encryptedEnvelopes: Array<{
    nonce: Uint8Array;
    aad: Uint8Array;
    ciphertext: Uint8Array;
  }> = [];

  for (let turn = 0; turn < turns; turn++) {
    const turnPlaintext = new Uint8Array(plaintextBytes.byteLength);
    turnPlaintext.set(plaintextBytes);
    trackedPlaintextBuffers.push(turnPlaintext);
    drbg.trackCustodyBuffer(turnPlaintext);

    const trafficNonce = buildMonotonicGcmNonce(sessionAlpha.noncePrefix, 1, trafficCounter++);
    const trafficAad = utf8ToBytes(`${sessionAlpha.sessionId}:turn:${turn}:traffic`);
    const trafficCiphertext = gcm(
      sessionAlpha.sessionTrafficKey,
      trafficNonce,
      trafficAad
    ).encrypt(turnPlaintext);
    ciphertextBuffers.push(trafficCiphertext);

    const offloadNonce = buildMonotonicGcmNonce(sessionAlpha.noncePrefix, 2, offloadCounter++);
    const offloadAad = utf8ToBytes(`${sessionAlpha.sessionId}:turn:${turn}:offload`);
    const offloadCiphertext = gcm(
      sessionAlpha.sessionOffloadKey,
      offloadNonce,
      offloadAad
    ).encrypt(turnPlaintext);
    ciphertextBuffers.push(offloadCiphertext);
    encryptedEnvelopes.push({
      nonce: offloadNonce,
      aad: offloadAad,
      ciphertext: offloadCiphertext,
    });
  }

  const totalCiphertextBytes = ciphertextBuffers.reduce((acc, b) => acc + b.byteLength, 0);
  const combinedCiphertext = new Uint8Array(totalCiphertextBytes);
  let cursor = 0;
  for (const frame of ciphertextBuffers) {
    combinedCiphertext.set(frame, cursor);
    cursor += frame.byteLength;
  }

  const plaintextSubstringMatchesInCiphertext = countPlaintextSubstrings(
    combinedCiphertext,
    needles
  );
  const repeated16ByteCipherBlocks = countRepeated16ByteBlocks(ciphertextBuffers);
  const ciphertextShannonEntropyBitsPerByte = computeShannonEntropyBitsPerByte(combinedCiphertext);

  // Zeroize in-memory Uint8Array buffers
  const popAlpha = prefixPool.popSession(sessionAlpha.sessionId);
  const popBeta = prefixPool.popSession(sessionBeta.sessionId);
  drbg.zeroize();

  const drbgSnap = drbg.inspectInternalBuffers();
  const zeroizedBuffersVerified =
    drbgSnap.keyBytes.every((b) => b === 0) &&
    drbgSnap.counterBytes.every((b) => b === 0) &&
    sessionAlpha.sessionTrafficKey.every((b) => b === 0) &&
    sessionAlpha.sessionOffloadKey.every((b) => b === 0) &&
    sessionAlpha.sessionPrefixKey.every((b) => b === 0) &&
    sessionAlpha.noncePrefix.every((b) => b === 0) &&
    trackedPlaintextBuffers.every((buf) => buf.every((b) => b === 0));

  const popZeroizedVerified = popAlpha.allZeroVerified && popBeta.allZeroVerified;

  let decryptAfterKeyZeroizeFailed = false;
  try {
    const first = encryptedEnvelopes[0];
    gcm(sessionAlpha.sessionOffloadKey, first.nonce, first.aad).decrypt(first.ciphertext);
    decryptAfterKeyZeroizeFailed = false;
  } catch {
    decryptAfterKeyZeroizeFailed = true;
  }

  const allPrimitivesPassed =
    deterministicForIdenticalSeeds &&
    divergesOnClientEntropyReseed &&
    zeroizedBuffersVerified &&
    constantTimeCompareVerified &&
    sameSessionHit.hitBlocks === 3 &&
    crossSessionHit.hitBlocks === 0 &&
    hashesDistinct &&
    popZeroizedVerified &&
    plaintextSubstringMatchesInCiphertext === 0 &&
    repeated16ByteCipherBlocks === 0 &&
    ciphertextShannonEntropyBitsPerByte > 7.5 &&
    decryptAfterKeyZeroizeFailed;

  return {
    executionEnvironment: "software-uint8array",
    observesPhysicalGpuMemory: false,
    ctrDrbg: {
      deterministicForIdenticalSeeds,
      divergesOnClientEntropyReseed,
      zeroizedBuffersVerified,
    },
    prefixCache: {
      blockSizeTokens: HASH_BLOCK_TOKENS,
      sameSessionHitBlocks: sameSessionHit.hitBlocks,
      sameSessionHitTokens: sameSessionHit.hitTokens,
      crossSessionHitBlocks: crossSessionHit.hitBlocks,
      crossSessionHitTokens: crossSessionHit.hitTokens,
      constantTimeCompareVerified,
      popZeroizedVerified,
    },
    aesGcmEnvelope: {
      framesEncrypted: ciphertextBuffers.length,
      totalCiphertextBytes,
      plaintextSubstringMatchesInCiphertext,
      repeated16ByteCipherBlocks,
      ciphertextShannonEntropyBitsPerByte,
      decryptAfterKeyZeroizeFailed,
    },
    allPrimitivesPassed,
  };
}

/**
 * Software model of monotonic-nonce AES-256-GCM frame encryption and in-memory
 * `Uint8Array` buffer zeroization.
 *
 * Explicitly labelled `mode: "model"` (`simulated: true`, `observesPhysicalGpuMemory: false`):
 * this function checks ciphertext entropy, 16-byte block uniqueness, and `Uint8Array.fill(0)`
 * zeroization in JavaScript memory and does not observe physical GPU HBM or DDR5 memory-bus traffic.
 */
export function runMemoryBusAndPopAudit(): MemoryBusAndPopAuditReport {
  const primitives = verifyCustodyPrimitives();
  const v1Passed =
    primitives.aesGcmEnvelope.plaintextSubstringMatchesInCiphertext === 0 &&
    primitives.aesGcmEnvelope.repeated16ByteCipherBlocks === 0 &&
    primitives.aesGcmEnvelope.ciphertextShannonEntropyBitsPerByte > 7.5;
  const postPopAllZero =
    primitives.ctrDrbg.zeroizedBuffersVerified &&
    primitives.prefixCache.popZeroizedVerified;
  const postPopOffloadDecryptFailed =
    primitives.aesGcmEnvelope.decryptAfterKeyZeroizeFailed;
  const v6Passed = postPopAllZero && postPopOffloadDecryptFailed;

  return {
    mode: "model",
    simulated: true,
    observesPhysicalGpuMemory: false,
    note: "Simulated model: encrypts 5 turns in local JavaScript Uint8Array buffers with AES-256-GCM and monotonic nonces, measures ciphertext Shannon entropy and 16-byte block uniqueness, and verifies Uint8Array.fill(0) zeroization. Does not observe physical GPU HBM or DDR5 memory-bus traffic.",
    v1Passed,
    v6Passed,
    turnsSimulated: 5,
    totalHostBytesObserved: primitives.aesGcmEnvelope.totalCiphertextBytes,
    plaintextLeakMatches: primitives.aesGcmEnvelope.plaintextSubstringMatchesInCiphertext,
    repeated16ByteBlocks: primitives.aesGcmEnvelope.repeated16ByteCipherBlocks,
    shannonEntropyBitsPerByte: primitives.aesGcmEnvelope.ciphertextShannonEntropyBitsPerByte,
    postPopAllZero,
    postPopOffloadDecryptFailed,
  };
}
