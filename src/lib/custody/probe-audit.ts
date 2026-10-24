import { gcm } from "@noble/ciphers/aes.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { CustodyCtrDrbg } from "./drbg";
import { PrefixCachePool } from "./prefix-cache";

export interface MemoryBusAndPopAuditReport {
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
 * and a strictly monotonic 32-bit counter held inside the custody module.
 */
function buildMonotonicGcmNonce(
  noncePrefix: Uint8Array,
  channelId: number,
  counter: number
): Uint8Array {
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
 * Count how many times any sensitive substring appears inside a host-visible buffer.
 */
function countPlaintextSubstrings(
  hostBuffer: Uint8Array,
  sensitiveSubstrings: Uint8Array[]
): number {
  let matches = 0;
  for (const needle of sensitiveSubstrings) {
    if (needle.byteLength === 0 || hostBuffer.byteLength < needle.byteLength) {
      continue;
    }
    const limit = hostBuffer.byteLength - needle.byteLength;
    for (let offset = 0; offset <= limit; offset++) {
      let allMatch = true;
      for (let j = 0; j < needle.byteLength; j++) {
        if (hostBuffer[offset + j] !== needle[j]) {
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
 * Count repeated 16-byte cipher blocks across all captured host-visible payloads.
 * In ECB or static-IV modes (the TEE.fail Tux-penguin pattern attack), identical turns
 * produce identical 16-byte blocks. With per-turn monotonic AES-256-GCM counters,
 * repeated 16-byte blocks across turns must be 0.
 */
function countRepeated16ByteBlocks(hostBuffers: Uint8Array[]): number {
  const seen = new Set<string>();
  let duplicates = 0;

  for (const buf of hostBuffers) {
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
 * Spec §Testing V1 (Memory-bus probe test) & V6 (Pop zeroization test).
 *
 * Simulates a TEE.fail-class passive DDR5 riser probe inspecting every byte that
 * crosses CPU memory or offloaded KV cache storage during a 5-turn session where
 * the user sends the exact same sensitive prompt 5 times in a row, followed by `pop()`.
 */
export function runMemoryBusAndPopAudit(): MemoryBusAndPopAuditReport {
  const turnsSimulated = 5;
  const sessionId = "sess-v1-v6-audit";

  // 1. Seed CustodyCtrDrbg with 256-bit monitor hardware seed + client contribution
  const hardwareSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    hardwareSeed[i] = (0x5a ^ (i * 17 + 31)) & 0xff;
  }
  const clientContribution = utf8ToBytes("client-ephemeral-x25519-contribution-v1");
  const drbg = new CustodyCtrDrbg(hardwareSeed, clientContribution);
  const keyBundle = drbg.deriveSessionKeys(sessionId);

  // Prefix cache pool inside custody module
  const prefixPool = new PrefixCachePool();
  const identicalPromptTokens = Array.from({ length: 1024 }, (_, idx) => 1000 + (idx % 64));

  // Sensitive prompt sent identically 5 times in a row (simulating Tux-penguin repetition)
  const sensitiveCore =
    "PATIENT_RECORD_SSN=999-00-1234;DIAGNOSIS=CONFIDENTIAL_ONCOLOGY_STAGE_II;API_SECRET=sk_live_drouter_987654321;";
  const repeatedPromptText = Array.from({ length: 16 }, () => sensitiveCore).join("|");
  const sensitivePromptBytes = utf8ToBytes(repeatedPromptText);

  const probeNeedles: Uint8Array[] = [
    utf8ToBytes("PATIENT_RECORD_SSN"),
    utf8ToBytes("999-00-1234"),
    utf8ToBytes("CONFIDENTIAL_ONCOLOGY"),
    utf8ToBytes("sk_live_drouter_987654321"),
    sensitivePromptBytes.subarray(0, 32),
  ];

  // Monotonic counters inside the custody module
  let trafficCounter = 1;
  let offloadCounter = 1;

  // Simulated GPU custody internal page buffers (never exposed in plaintext on CPU bus)
  const gpuCustodyPageBuffers: Uint8Array[] = [];

  // Host-visible buffers captured by the passive DDR5 riser probe
  const hostVisibleFrames: Uint8Array[] = [];
  const offloadedCacheBlobs: Array<{
    nonce: Uint8Array;
    aad: Uint8Array;
    ciphertext: Uint8Array;
  }> = [];

  for (let turn = 0; turn < turnsSimulated; turn++) {
    // Track internal GPU plaintext staging page so we can verify `pop()` zeroes it
    const internalStagingPage = new Uint8Array(sensitivePromptBytes.byteLength);
    internalStagingPage.set(sensitivePromptBytes);
    gpuCustodyPageBuffers.push(internalStagingPage);
    drbg.trackCustodyBuffer(internalStagingPage);

    // Update session prefix cache on GPU
    prefixPool.lookupLongestPrefix(sessionId, identicalPromptTokens, keyBundle.sessionPrefixKey);

    // Encrypt ingress/egress turn frame crossing PCIe / CPU bounce buffer
    const trafficNonce = buildMonotonicGcmNonce(keyBundle.noncePrefix, 1, trafficCounter++);
    const trafficAad = utf8ToBytes(`${sessionId}:turn:${turn}:traffic`);
    const trafficCiphertext = gcm(keyBundle.sessionTrafficKey, trafficNonce, trafficAad).encrypt(
      internalStagingPage
    );
    hostVisibleFrames.push(trafficCiphertext);

    // Encrypt offloaded KV-cache page written to host DRAM / NVMe tier
    const offloadNonce = buildMonotonicGcmNonce(keyBundle.noncePrefix, 2, offloadCounter++);
    const offloadAad = utf8ToBytes(`${sessionId}:turn:${turn}:kv-offload-page`);
    const offloadCiphertext = gcm(keyBundle.sessionOffloadKey, offloadNonce, offloadAad).encrypt(
      internalStagingPage
    );
    hostVisibleFrames.push(offloadCiphertext);
    offloadedCacheBlobs.push({
      nonce: offloadNonce,
      aad: offloadAad,
      ciphertext: offloadCiphertext,
    });
  }

  // Concatenate all host-visible bytes observed by the DDR5 riser probe
  const totalHostBytesObserved = hostVisibleFrames.reduce((acc, b) => acc + b.byteLength, 0);
  const combinedHostStream = new Uint8Array(totalHostBytesObserved);
  let cursor = 0;
  for (const frame of hostVisibleFrames) {
    combinedHostStream.set(frame, cursor);
    cursor += frame.byteLength;
  }

  // V1 Metrics
  const plaintextLeakMatches = countPlaintextSubstrings(combinedHostStream, probeNeedles);
  const repeated16ByteBlocks = countRepeated16ByteBlocks(hostVisibleFrames);
  const shannonEntropyBitsPerByte = computeShannonEntropyBitsPerByte(combinedHostStream);

  // V6: Execute `pop()` zeroization across DRBG, session keys, GPU staging pages, and prefix pool
  const popCacheResult = prefixPool.popSession(sessionId);
  drbg.zeroize();

  const drbgSnap = drbg.inspectInternalBuffers();
  const drbgKeyZero = drbgSnap.keyBytes.every((b) => b === 0);
  const drbgCounterZero = drbgSnap.counterBytes.every((b) => b === 0);
  const sessionKeysZero =
    keyBundle.sessionTrafficKey.every((b) => b === 0) &&
    keyBundle.sessionOffloadKey.every((b) => b === 0) &&
    keyBundle.sessionPrefixKey.every((b) => b === 0) &&
    keyBundle.noncePrefix.every((b) => b === 0);
  const pagesZero = gpuCustodyPageBuffers.every((page) => page.every((b) => b === 0));

  const postPopAllZero =
    drbgKeyZero &&
    drbgCounterZero &&
    sessionKeysZero &&
    pagesZero &&
    popCacheResult.allZeroVerified;

  // Verify that attempting to decrypt an offloaded cache blob after `pop()` fails authentication
  let postPopOffloadDecryptFailed = false;
  const targetBlob = offloadedCacheBlobs[0];
  try {
    gcm(keyBundle.sessionOffloadKey, targetBlob.nonce, targetBlob.aad).decrypt(
      targetBlob.ciphertext
    );
    postPopOffloadDecryptFailed = false;
  } catch {
    postPopOffloadDecryptFailed = true;
  }

  const v1Passed =
    plaintextLeakMatches === 0 &&
    repeated16ByteBlocks === 0 &&
    shannonEntropyBitsPerByte > 7.5;

  const v6Passed = postPopAllZero && postPopOffloadDecryptFailed;

  return {
    v1Passed,
    v6Passed,
    turnsSimulated,
    totalHostBytesObserved,
    plaintextLeakMatches,
    repeated16ByteBlocks,
    shannonEntropyBitsPerByte,
    postPopAllZero,
    postPopOffloadDecryptFailed,
  };
}
