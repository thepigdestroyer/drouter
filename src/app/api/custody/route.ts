import { NextResponse } from "next/server";
import { connection } from "next/server";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  CustodyCtrDrbg,
  HASH_BLOCK_TOKENS,
  PrefixCachePool,
  runMemoryBusAndPopAudit,
} from "@/lib/custody";

export async function GET() {
  await connection();

  // 1. Run V1 (memory-bus probe) and V6 (pop zeroization) audit
  const audit = runMemoryBusAndPopAudit();

  // 2. Run Prefix-Cache Isolation Demo (1,536-token identical prefix = 3 blocks of 512 tokens)
  const hardwareSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    hardwareSeed[i] = (0xa5 ^ (i * 13 + 7)) & 0xff;
  }
  const drbg = new CustodyCtrDrbg(hardwareSeed, utf8ToBytes("custody-api-demo-entropy"));
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

  const popAlpha = pool.popSession(sessionA.sessionId);
  const popBeta = pool.popSession(sessionB.sessionId);
  drbg.zeroize();

  return NextResponse.json({
    subsystem: "gpu-custody-module",
    specRefs: ["§2.3", "§2.4", "V1", "V6"],
    audit,
    prefixCacheDemo: {
      blockSizeTokens: HASH_BLOCK_TOKENS,
      testedPrefixTokens: sharedPrefixTokens.length,
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
