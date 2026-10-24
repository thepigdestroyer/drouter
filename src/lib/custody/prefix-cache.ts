import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Spec §2.3 & §2.4: Kimi K3-compatible 512-token block boundary for keyed prefix caching.
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

function packTokenBlock(tokens: number[], start: number, end: number): string {
  const parts = new Array<string>(end - start);
  for (let i = start; i < end; i++) {
    parts[i - start] = String(tokens[i] >>> 0);
  }
  return parts.join(",");
}

/**
 * Computes chained 512-token block hashes using HMAC-SHA-256 with a per-session key:
 *   h_i = HMAC-SHA-256(sessionPrefixKey, (h_{i-1} || "") + ":" + packedTokens)
 *
 * Partial trailing tokens (< 512 tokens) do not form a block hash, matching
 * 512-token KV cache page granularity.
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
 * Spec §2.3 & §2.4: Keyed HMAC Prefix Cache Pool.
 *
 * Stores cached 512-token block hashes per session using keyed HMAC-SHA-256.
 * Because block hashes are keyed with each session's custody-derived HMAC key
 * and partitioned per session, prefix lookups hit at 512-token boundaries within
 * a session and produce 0 hits across different sessions even on identical tokens.
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
   *
   * Also caches any newly observed blocks for `sessionId` by default (`cacheOnMiss = true`)
   * so subsequent turns in the same session automatically benefit from prefix hits,
   * while remaining completely isolated from other sessions.
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
      // Verify the session key matches the registered session key before matching blocks
      let keyMatches = state.keyBuffer.byteLength === sessionPrefixKey.byteLength;
      if (keyMatches) {
        for (let i = 0; i < sessionPrefixKey.byteLength; i++) {
          if (state.keyBuffer[i] !== sessionPrefixKey[i]) {
            keyMatches = false;
            break;
          }
        }
      }

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
   * Zeroize all stored keys and block hash buffers for `sessionId` and evict the session.
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
