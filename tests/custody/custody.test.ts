import { describe, expect, it } from "vitest";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  CustodyCtrDrbg,
  HASH_BLOCK_TOKENS,
  PrefixCachePool,
  computePrefixBlockHashes,
  runMemoryBusAndPopAudit,
} from "@/lib/custody";

describe("Subsystem 10: GPU Custody Module (§2.3, §2.4, V1, V6)", () => {
  describe("CustodyCtrDrbg (Spec §2.4)", () => {
    it("produces deterministic streams for identical hardware seeds and diverges when client entropy is mixed in", () => {
      const seed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        seed[i] = i + 1;
      }

      const drbgA = new CustodyCtrDrbg(seed);
      const drbgB = new CustodyCtrDrbg(seed);

      const streamA1 = bytesToHex(drbgA.generate(64));
      const streamB1 = bytesToHex(drbgB.generate(64));
      expect(streamA1).toBe(streamB1);

      // Mix client entropy into drbgA only
      drbgA.reseed(utf8ToBytes("client-session-entropy-alpha"));
      const streamA2 = bytesToHex(drbgA.generate(64));
      const streamB2 = bytesToHex(drbgB.generate(64));
      expect(streamA2).not.toBe(streamB2);

      // Two DRBGs with the same client entropy mix-in remain deterministic
      const drbgC = new CustodyCtrDrbg(seed);
      drbgC.generate(64);
      drbgC.reseed(utf8ToBytes("client-session-entropy-alpha"));
      const streamC2 = bytesToHex(drbgC.generate(64));
      expect(streamA2).toBe(streamC2);
    });

    it("overwrites internal key/counter/derived buffers with 0x00 and throws after zeroize()", () => {
      const seed = new Uint8Array(32).fill(0x42);
      const drbg = new CustodyCtrDrbg(seed, utf8ToBytes("initial-client-entropy"));
      const generated = drbg.generate(48);
      const sessionBundle = drbg.deriveSessionKeys("sess-zeroize-check");

      expect(generated.some((b) => b !== 0)).toBe(true);
      expect(sessionBundle.sessionTrafficKey.some((b) => b !== 0)).toBe(true);

      drbg.zeroize();
      expect(drbg.isZeroized()).toBe(true);

      const snapshot = drbg.inspectInternalBuffers();
      expect(snapshot.keyBytes.every((b) => b === 0)).toBe(true);
      expect(snapshot.counterBytes.every((b) => b === 0)).toBe(true);
      expect(generated.every((b) => b === 0)).toBe(true);
      expect(sessionBundle.sessionTrafficKey.every((b) => b === 0)).toBe(true);
      expect(sessionBundle.sessionOffloadKey.every((b) => b === 0)).toBe(true);
      expect(sessionBundle.sessionPrefixKey.every((b) => b === 0)).toBe(true);

      expect(() => drbg.generate(32)).toThrow(/zeroized/i);
      expect(() => drbg.reseed(utf8ToBytes("more-entropy"))).toThrow(/zeroized/i);
      expect(() => drbg.deriveSessionKeys("sess-after-zeroize")).toThrow(/zeroized/i);
    });
  });

  describe("PrefixCachePool & Keyed HMAC Prefix Hashing (Spec §2.3 & §2.4)", () => {
    it("hits at 512-token block boundaries within the same session (1,200 matching tokens -> 1,024 tokens = 2 blocks)", () => {
      const seed = new Uint8Array(32).fill(0x19);
      const drbg = new CustodyCtrDrbg(seed);
      const session1 = drbg.deriveSessionKeys("session-1");
      const session2 = drbg.deriveSessionKeys("session-2");

      const pool = new PrefixCachePool();

      // Base prompt of 1,536 tokens (3 complete 512-token blocks)
      const baseTokens = Array.from({ length: 1536 }, (_, idx) => 500 + idx);
      pool.storePrefix(session1.sessionId, baseTokens, session1.sessionPrefixKey);

      // Follow-up turn shares the first 1,200 tokens and diverges for the remaining 336 tokens
      const followUpTokens = baseTokens.map((tok, idx) => (idx < 1200 ? tok : tok + 90000));
      const sameSessionHit = pool.lookupLongestPrefix(
        session1.sessionId,
        followUpTokens,
        session1.sessionPrefixKey
      );

      expect(HASH_BLOCK_TOKENS).toBe(512);
      expect(sameSessionHit.hitBlocks).toBe(2);
      expect(sameSessionHit.hitTokens).toBe(1024);
      expect(sameSessionHit.crossSessionIsolated).toBe(true);

      // Identical tokens in a different session produce 0 hits and completely distinct HMAC hashes
      const crossSessionHit = pool.lookupLongestPrefix(
        session2.sessionId,
        baseTokens,
        session2.sessionPrefixKey
      );
      expect(crossSessionHit.hitBlocks).toBe(0);
      expect(crossSessionHit.hitTokens).toBe(0);

      const hashesS1 = computePrefixBlockHashes(baseTokens, session1.sessionPrefixKey);
      const hashesS2 = computePrefixBlockHashes(baseTokens, session2.sessionPrefixKey);
      expect(hashesS1).toHaveLength(3);
      expect(hashesS2).toHaveLength(3);
      expect(hashesS1[0]).not.toBe(hashesS2[0]);
      expect(hashesS1[1]).not.toBe(hashesS2[1]);
      expect(hashesS1[2]).not.toBe(hashesS2[2]);

      // Pop session 1 and verify its keys/entries are zeroed and evicted
      const popResult = pool.popSession(session1.sessionId);
      expect(popResult.evicted).toBe(true);
      expect(popResult.allZeroVerified).toBe(true);
      expect(pool.hasSession(session1.sessionId)).toBe(false);
    });
  });

  describe("V1 Memory-Bus Probe & V6 Pop Zeroization Audit (Spec V1 & V6)", () => {
    it("passes both V1 and V6 verification checks across 5 identical sensitive turns", () => {
      const report = runMemoryBusAndPopAudit();

      expect(report.turnsSimulated).toBe(5);
      expect(report.totalHostBytesObserved).toBeGreaterThan(8000);
      expect(report.plaintextLeakMatches).toBe(0);
      expect(report.repeated16ByteBlocks).toBe(0);
      expect(report.shannonEntropyBitsPerByte).toBeGreaterThan(7.5);
      expect(report.postPopAllZero).toBe(true);
      expect(report.postPopOffloadDecryptFailed).toBe(true);
      expect(report.v1Passed).toBe(true);
      expect(report.v6Passed).toBe(true);
    });
  });
});
