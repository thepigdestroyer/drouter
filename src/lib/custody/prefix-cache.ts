import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * 512-token block boundary for keyed HMAC-SHA-256 prefix hashing.
 */
export const HASH_BLOCK_TOKENS = 512;

export interface PrefixLookupResult {
  hitTokens: number;
  hitBlocks: number;
  totalCompleteBlocks: number;
  blockHashes: string[];
  crossSessionIsolated: true;
}

interface SessionPrefixState {
  sessionId: string;
  keyBuffer: Uint8Array;
  blockHashBuffers: Map<number, Uint8Array[]>;
  blockHashHexSet: Map<number, Set<string>>;
}

/**
 * Constant-time comparison of two `Uint8Array` byte slices.
 * Evaluates all byte positions up to `Math.max(a.byteLength, b.byteLength)` without
 * early exit on mismatch.
 */
export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }
  const maxLen = Math.max(a.byteLength, b.byteLength);
  let diff = a.byteLength ^ b.byteLength;
  for (let i = 0; i < maxLen; i++) {
    const byteA = i < a.byteLength ? a[i] : 0;
    const byteB = i < b.byteLength ? b[i] : 0;
    diff |= byteA ^ byteB;
  }
  return diff === 0;
}

function packTokenBlock(tokens: number[], start: number, end: number): string {
  const parts = new Array<string>(end - start);
  for (let i = start; i < end; i++) {
    parts[i - start] = String(tokens[i] >>> 0);
  }
  return parts.join(",");
}

/**
 * Computes chained 512-token block hashes using HMAC-SHA-256 with a 32-byte per-session key:
 *   h_i = HMAC-SHA-256(sessionPrefixKey, (h_{i-1} || "") + ":" + packedTokens)
 *
 * Partial trailing tokens (< 512 tokens) do not form a block hash.
 */
export function computePrefixBlockHashes(
  tokens: number[],
  sessionPrefixKey: Uint8Array
): string[] {
  if (!(sessionPrefixKey instanceof Uint8Array) || sessionPrefixKey.byteLength !== 32) {
    throw new Error(
      `computePrefixBlockHashes requires a 32-byte sessionPrefixKey (got ${sessionPrefixKey?.byteLength ?? 0} bytes)`
    );
  }
  let nonZero = 0;
  for (let i = 0; i < sessionPrefixKey.byteLength; i++) {
    nonZero |= sessionPrefixKey[i];
  }
  if (nonZero === 0) {
    throw new Error("computePrefixBlockHashes refuses all-zero sessionPrefixKey");
  }

  const fullBlocks = Math.floor(tokens.length / HASH_BLOCK_TOKENS);
  const hashes: string[] = [];
  let prevHash = "";

  for (let blockIdx = 0; blockIdx < fullBlocks; blockIdx++) {
    const start = blockIdx * HASH_BLOCK_TOKENS;
    const end = start + HASH_BLOCK_TOKENS;
    const packedTokens = packTokenBlock(tokens, start, end);
    const payload = utf8ToBytes(`${prevHash}:${packedTokens}`);
    const digest = hmac(sha256, sessionPrefixKey, payload);
    const hex = bytesToHex(digest);
    hashes.push(hex);
    prevHash = hex;
  }

  return hashes;
}

/**
 * In-memory Keyed HMAC-SHA-256 Prefix Cache Pool.
 *
 * Stores 512-token block digests per session keyed with each session's 32-byte HMAC key,
 * compares session keys in constant time via `constantTimeEqualBytes`, and overwrites
 * stored key and block-hash `Uint8Array` buffers in process memory on `popSession()`.
 */
export class PrefixCachePool {
  private readonly sessions = new Map<string, SessionPrefixState>();
  private readonly zeroizedRawBuffers: Uint8Array[] = [];

  private getOrCreateSession(sessionId: string, sessionPrefixKey: Uint8Array): SessionPrefixState {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      return existing;
    }
    const keyCopy = new Uint8Array(sessionPrefixKey.byteLength);
    keyCopy.set(sessionPrefixKey);
    const state: SessionPrefixState = {
      sessionId,
      keyBuffer: keyCopy,
      blockHashBuffers: new Map(),
      blockHashHexSet: new Map(),
    };
    this.sessions.set(sessionId, state);
    return state;
  }

  /**
   * Explicitly store a token sequence's 512-token block hashes for `sessionId`.
   */
  public storePrefix(
    sessionId: string,
    tokens: number[],
    sessionPrefixKey: Uint8Array
  ): string[] {
    const blockHashes = computePrefixBlockHashes(tokens, sessionPrefixKey);
    const state = this.getOrCreateSession(sessionId, sessionPrefixKey);

    for (let i = 0; i < blockHashes.length; i++) {
      const hex = blockHashes[i];
      let hexSet = state.blockHashHexSet.get(i);
      if (!hexSet) {
        hexSet = new Set<string>();
        state.blockHashHexSet.set(i, hexSet);
      }
      if (!hexSet.has(hex)) {
        hexSet.add(hex);
        const rawBuf = utf8ToBytes(hex);
        let bufList = state.blockHashBuffers.get(i);
        if (!bufList) {
          bufList = [];
          state.blockHashBuffers.set(i, bufList);
        }
        bufList.push(rawBuf);
      }
    }

    return blockHashes;
  }

  /**
   * Look up the longest contiguous prefix of 512-token blocks cached for `sessionId`.
   */
  public lookupLongestPrefix(
    sessionId: string,
    tokens: number[],
    sessionPrefixKey: Uint8Array,
    options?: { cacheOnLookup?: boolean }
  ): PrefixLookupResult {
    const blockHashes = computePrefixBlockHashes(tokens, sessionPrefixKey);
    const state = this.sessions.get(sessionId);

    let hitBlocks = 0;
    if (state) {
      const keyMatches = constantTimeEqualBytes(state.keyBuffer, sessionPrefixKey);

      if (keyMatches) {
        for (let i = 0; i < blockHashes.length; i++) {
          const hexSet = state.blockHashHexSet.get(i);
          if (hexSet && hexSet.has(blockHashes[i])) {
            hitBlocks += 1;
          } else {
            break;
          }
        }
      }
    }

    if (options?.cacheOnLookup !== false) {
      this.storePrefix(sessionId, tokens, sessionPrefixKey);
    }

    return {
      hitTokens: hitBlocks * HASH_BLOCK_TOKENS,
      hitBlocks,
      totalCompleteBlocks: blockHashes.length,
      blockHashes,
      crossSessionIsolated: true,
    };
  }

  /**
   * Overwrite stored key and block-hash `Uint8Array` buffers for `sessionId` with `0x00`
   * and evict the session from the in-memory map.
   */
  public popSession(sessionId: string): {
    evicted: boolean;
    zeroedBuffersCount: number;
    allZeroVerified: boolean;
  } {
    const state = this.sessions.get(sessionId);
    if (!state) {
      return {
        evicted: false,
        zeroedBuffersCount: 0,
        allZeroVerified: true,
      };
    }

    const buffersToZero: Uint8Array[] = [state.keyBuffer];
    for (const bufList of state.blockHashBuffers.values()) {
      for (const buf of bufList) {
        buffersToZero.push(buf);
      }
    }

    for (const buf of buffersToZero) {
      buf.fill(0);
      this.zeroizedRawBuffers.push(buf);
    }

    state.blockHashBuffers.clear();
    state.blockHashHexSet.clear();
    this.sessions.delete(sessionId);

    const allZeroVerified = buffersToZero.every((buf) => buf.every((byte) => byte === 0));
    return {
      evicted: true,
      zeroedBuffersCount: buffersToZero.length,
      allZeroVerified,
    };
  }

  public hasSession(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  public getZeroizedBuffersSnapshot(): Uint8Array[] {
    return this.zeroizedRawBuffers;
  }
}
