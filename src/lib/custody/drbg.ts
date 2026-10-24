import { ctr } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

export const DRBG_SEED_BYTES = 32;
export const AES_BLOCK_BYTES = 16;

export interface CustodySessionKeyBundle {
  sessionId: string;
  sessionTrafficKey: Uint8Array;
  sessionOffloadKey: Uint8Array;
  sessionPrefixKey: Uint8Array;
  noncePrefix: Uint8Array;
}

export interface DrbgInternalBufferSnapshot {
  keyBytes: Uint8Array;
  counterBytes: Uint8Array;
  trackedBuffers: Uint8Array[];
  destroyed: boolean;
  reseedCounter: number;
  generatedBlocks: number;
  executionEnvironment: "software-uint8array";
}

/**
 * Increment a 128-bit big-endian counter block in place by `steps`.
 */
function incrementCounterBlockBE(counter: Uint8Array, steps: number): void {
  let carry = steps >>> 0;
  for (let i = counter.length - 1; i >= 0 && carry > 0; i--) {
    const sum = counter[i] + (carry & 0xff);
    counter[i] = sum & 0xff;
    carry = (carry >>> 8) + (sum >>> 8);
  }
}

/**
 * AES-256 CTR-DRBG cryptographic primitive implemented in local JavaScript memory (`Uint8Array`).
 *
 * Expands a 256-bit seed using HMAC-SHA-256 conditioning and AES-256-CTR keystream generation
 * with backtracking-resistant ratcheting after every generate or reseed operation.
 * When `zeroize()` is invoked, internal key, counter, and tracked derived `Uint8Array` buffers
 * in process memory are overwritten with `0x00` and the instance refuses further calls.
 */
export class CustodyCtrDrbg {
  private readonly key: Uint8Array;
  private readonly counterBlock: Uint8Array;
  private readonly trackedBuffers: Uint8Array[] = [];
  private destroyed = false;
  private reseedCounter = 0;
  private generatedBlocks = 0;

  constructor(hardwareSeed: Uint8Array, initialClientEntropy?: Uint8Array) {
    if (!(hardwareSeed instanceof Uint8Array) || hardwareSeed.byteLength !== DRBG_SEED_BYTES) {
      throw new Error(
        `CustodyCtrDrbg requires a ${DRBG_SEED_BYTES}-byte hardware seed (got ${hardwareSeed?.byteLength ?? 0} bytes)`
      );
    }
    let nonZero = 0;
    for (let i = 0; i < hardwareSeed.byteLength; i++) {
      nonZero |= hardwareSeed[i];
    }
    if (nonZero === 0) {
      throw new Error("CustodyCtrDrbg refuses all-zero hardware seed (RNG fault)");
    }

    this.key = new Uint8Array(DRBG_SEED_BYTES);
    this.counterBlock = new Uint8Array(AES_BLOCK_BYTES);

    // Initial NIST SP 800-90A style conditioning + AES-256-CTR state initialization
    const domainInit = utf8ToBytes("drouter:custody:aes256-ctr-drbg:init:v1");
    const initialKeyMaterial = hmac(sha256, domainInit, hardwareSeed);
    const initialVMaterial = hmac(sha256, initialKeyMaterial, utf8ToBytes("drouter:custody:v-init"));

    this.key.set(initialKeyMaterial.subarray(0, DRBG_SEED_BYTES));
    this.counterBlock.set(initialVMaterial.subarray(0, AES_BLOCK_BYTES));
    initialKeyMaterial.fill(0);
    initialVMaterial.fill(0);

    // Run one CTR-DRBG update pass over the conditioned seed
    this.ctrDrbgUpdate(hardwareSeed);
    this.reseedCounter = 1;

    if (initialClientEntropy && initialClientEntropy.byteLength > 0) {
      this.reseed(initialClientEntropy);
    }
  }

  private assertAlive(): void {
    if (this.destroyed) {
      throw new Error("CustodyCtrDrbg has been zeroized and cannot be used");
    }
  }

  /**
   * Internal CTR-DRBG Update function: generates 48 bytes (3 AES blocks) using
   * the current (Key, V) in AES-256-CTR mode and mixes conditioned `providedData`
   * to produce the next (Key, V).
   */
  private ctrDrbgUpdate(providedData: Uint8Array): void {
    const conditioned = new Uint8Array(48);
    const blockA = hmac(sha256, this.key, providedData);
    const blockB = hmac(sha256, blockA, this.counterBlock);
    conditioned.set(blockA, 0);
    conditioned.set(blockB.subarray(0, 16), 32);

    incrementCounterBlockBE(this.counterBlock, 1);
    const stream = ctr(this.key, this.counterBlock).encrypt(conditioned);
    incrementCounterBlockBE(this.counterBlock, 2);
    this.generatedBlocks += 3;

    this.key.set(stream.subarray(0, 32));
    this.counterBlock.set(stream.subarray(32, 48));

    conditioned.fill(0);
    blockA.fill(0);
    blockB.fill(0);
    stream.fill(0);
  }

  /**
   * Mix caller entropy contribution into the CTR-DRBG state.
   */
  public reseed(clientEntropy: Uint8Array): void {
    this.assertAlive();
    if (!(clientEntropy instanceof Uint8Array) || clientEntropy.byteLength === 0) {
      throw new Error("CustodyCtrDrbg.reseed requires non-empty clientEntropy bytes");
    }
    this.ctrDrbgUpdate(clientEntropy);
    this.reseedCounter += 1;
  }

  /**
   * Generate `byteLength` deterministic pseudorandom bytes using AES-256 counter mode.
   */
  public generate(byteLength: number, additionalInput?: Uint8Array): Uint8Array {
    this.assertAlive();
    if (!Number.isInteger(byteLength) || byteLength <= 0 || byteLength > 16 * 1024 * 1024) {
      throw new Error(`CustodyCtrDrbg.generate requires a positive integer byteLength <= 16 MiB (got ${byteLength})`);
    }

    if (additionalInput && additionalInput.byteLength > 0) {
      this.ctrDrbgUpdate(additionalInput);
    }

    const blocksNeeded = Math.ceil(byteLength / AES_BLOCK_BYTES);
    const zeroInput = new Uint8Array(blocksNeeded * AES_BLOCK_BYTES);

    incrementCounterBlockBE(this.counterBlock, 1);
    const keystream = ctr(this.key, this.counterBlock).encrypt(zeroInput);
    if (blocksNeeded > 1) {
      incrementCounterBlockBE(this.counterBlock, blocksNeeded - 1);
    }
    this.generatedBlocks += blocksNeeded;

    const output = keystream.slice(0, byteLength);
    keystream.fill(0);

    // Backtracking resistance: update (Key, V) after every generation request
    const ratchetInput =
      additionalInput && additionalInput.byteLength > 0
        ? additionalInput
        : new Uint8Array(48);
    this.ctrDrbgUpdate(ratchetInput);

    this.trackedBuffers.push(output);
    return output;
  }

  /**
   * Derive a per-session key bundle (`sessionTrafficKey`, `sessionOffloadKey`,
   * `sessionPrefixKey`, `noncePrefix`), optionally mixing in caller entropy first.
   */
  public deriveSessionKeys(sessionId: string, clientEntropy?: Uint8Array): CustodySessionKeyBundle {
    this.assertAlive();
    if (clientEntropy && clientEntropy.byteLength > 0) {
      this.reseed(clientEntropy);
    }

    const sessionTrafficKey = this.generate(32, utf8ToBytes(`drouter:session:traffic:${sessionId}`));
    const sessionOffloadKey = this.generate(32, utf8ToBytes(`drouter:session:offload:${sessionId}`));
    const sessionPrefixKey = this.generate(32, utf8ToBytes(`drouter:session:prefix:${sessionId}`));
    const noncePrefix = this.generate(4, utf8ToBytes(`drouter:session:nonce-prefix:${sessionId}`));

    return {
      sessionId,
      sessionTrafficKey,
      sessionOffloadKey,
      sessionPrefixKey,
      noncePrefix,
    };
  }

  /**
   * Register an external `Uint8Array` buffer so `zeroize()` overwrites it with `0x00`.
   */
  public trackCustodyBuffer(buffer: Uint8Array): void {
    this.assertAlive();
    this.trackedBuffers.push(buffer);
  }

  /**
   * Overwrite internal key, counter, and tracked `Uint8Array` buffers in process memory
   * with `0x00` and mark the DRBG permanently destroyed.
   */
  public zeroize(): void {
    this.key.fill(0);
    this.counterBlock.fill(0);
    for (const buf of this.trackedBuffers) {
      buf.fill(0);
    }
    this.destroyed = true;
  }

  public isZeroized(): boolean {
    return this.destroyed;
  }

  /**
   * Exposes references to internal `Uint8Array` state buffers for zeroization checks.
   */
  public inspectInternalBuffers(): DrbgInternalBufferSnapshot {
    return {
      keyBytes: this.key,
      counterBytes: this.counterBlock,
      trackedBuffers: this.trackedBuffers,
      destroyed: this.destroyed,
      reseedCounter: this.reseedCounter,
      generatedBlocks: this.generatedBlocks,
      executionEnvironment: "software-uint8array",
    };
  }
}
