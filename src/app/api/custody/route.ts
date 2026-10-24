import { NextResponse, connection } from "next/server";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  CustodyCtrDrbg,
  HASH_BLOCK_TOKENS,
  PrefixCachePool,
  constantTimeEqualBytes,
  verifyCustodyPrimitives,
} from "@/lib/custody";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const custodyLimiter = createTokenBucketLimiter({
  name: "custody-get",
  capacity: 120,
  refillPerSec: 4,
});

export async function GET(request?: Request) {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = custodyLimiter.check(request);
    if (limited) return limited;
  }

  // 1. Verify real software cryptographic primitives (CTR-DRBG, HMAC-SHA-256 prefix keys, constant-time compare, AES-256-GCM envelope)
  const primitives = verifyCustodyPrimitives();

  // 2. Prefix-Cache Isolation Check (1,536-token identical prefix = 3 blocks of 512 tokens)
  const hardwareSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    hardwareSeed[i] = (0xa5 ^ (i * 13 + 7)) & 0xff;
  }
  const drbg = new CustodyCtrDrbg(hardwareSeed, utf8ToBytes("custody-api-entropy-v1"));
  const sessionA = drbg.deriveSessionKeys("session-alpha");
  const sessionB = drbg.deriveSessionKeys("session-beta");

  const sharedPrefixTokens = Array.from({ length: HASH_BLOCK_TOKENS * 3 }, (_, i) => 2000 + i);
  const pool = new PrefixCachePool();

  // Populate session-alpha cache with 1,536 tokens (3 blocks)
  pool.storePrefix(sessionA.sessionId, sharedPrefixTokens, sessionA.sessionPrefixKey);

  // Lookup identical 1,536-token prefix within the same session -> 3 block hits (1,536 tokens)
  const sameSessionLookup = pool.lookupLongestPrefix(
    sessionA.sessionId,
    sharedPrefixTokens,
    sessionA.sessionPrefixKey
  );

  // Lookup identical 1,536-token prefix across a different session -> 0 block hits (0 tokens)
  const crossSessionLookup = pool.lookupLongestPrefix(
    sessionB.sessionId,
    sharedPrefixTokens,
    sessionB.sessionPrefixKey
  );

  const constantTimeCompareCheck =
    constantTimeEqualBytes(sessionA.sessionPrefixKey, new Uint8Array(sessionA.sessionPrefixKey)) &&
    !constantTimeEqualBytes(sessionA.sessionPrefixKey, sessionB.sessionPrefixKey);

  const popAlpha = pool.popSession(sessionA.sessionId);
  const popBeta = pool.popSession(sessionB.sessionId);
  drbg.zeroize();

  return NextResponse.json({
    subsystem: "custody-crypto-primitives",
    executionEnvironment: "software-uint8array",
    observesPhysicalGpuMemory: false,
    disclosure:
      "Exposes real software cryptographic primitives: AES-256 CTR-DRBG key derivation, HMAC-SHA-256 512-token prefix-cache key isolation, constant-time byte comparisons, monotonic-nonce AES-256-GCM envelope encryption, and Uint8Array buffer zeroization.",
    specRefs: ["§2.3", "§2.4"],
    primitives,
    prefixCacheDemo: {
      blockSizeTokens: HASH_BLOCK_TOKENS,
      testedPrefixTokens: sharedPrefixTokens.length,
      constantTimeCompareCheck,
      sameSession: {
        sessionId: sessionA.sessionId,
        hitBlocks: sameSessionLookup.hitBlocks,
        hitTokens: sameSessionLookup.hitTokens,
        blockHashes: sameSessionLookup.blockHashes,
      },
      crossSession: {
        sessionId: sessionB.sessionId,
        hitBlocks: crossSessionLookup.hitBlocks,
        hitTokens: crossSessionLookup.hitTokens,
        blockHashes: crossSessionLookup.blockHashes,
        crossSessionIsolated: crossSessionLookup.crossSessionIsolated,
      },
      popZeroized: popAlpha.allZeroVerified && popBeta.allZeroVerified && drbg.isZeroized(),
    },
  });
}
