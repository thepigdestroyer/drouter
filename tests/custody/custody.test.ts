import { describe, expect, it } from "vitest";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { GET as getCustodyRoute } from "@/app/api/custody/route";
import {
  CustodyCtrDrbg,
  HASH_BLOCK_TOKENS,
  PrefixCachePool,
  computePrefixBlockHashes,
  constantTimeEqualBytes,
  verifyCustodyPrimitives,
} from "@/lib/custody";

describe("Subsystem 10: Custody Cryptographic Primitives", () => {
  describe("CustodyCtrDrbg (AES-256 CTR-DRBG in software Uint8Array)", () => {
    it("produces deterministic streams for identical seeds and diverges when client entropy is mixed in", () => {
      const seed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        seed[i] = i + 1;
      }

      const drbgA = new CustodyCtrDrbg(seed);
      const drbgB = new CustodyCtrDrbg(seed);

      const streamA1 = bytesToHex(drbgA.generate(64));
      const streamB1 = bytesToHex(drbgB.generate(64));
      expect(streamA1).toBe(streamB1);

      drbgA.reseed(utf8ToBytes("client-session-entropy-alpha"));
      const streamA2 = bytesToHex(drbgA.generate(64));
      const streamB2 = bytesToHex(drbgB.generate(64));
      expect(streamA2).not.toBe(streamB2);

      const drbgC = new CustodyCtrDrbg(seed);
      drbgC.generate(64);
      drbgC.reseed(utf8ToBytes("client-session-entropy-alpha"));
      const streamC2 = bytesToHex(drbgC.generate(64));
      expect(streamA2).toBe(streamC2);
    });

    it("overwrites internal key/counter/derived Uint8Array buffers with 0x00 and throws after zeroize()", () => {
      const seed = new Uint8Array(32).fill(0x42);
      const drbg = new CustodyCtrDrbg(seed, utf8ToBytes("initial-client-entropy"));
      const generated = drbg.generate(48);
      const sessionBundle = drbg.deriveSessionKeys("sess-zeroize-check");

      expect(generated.some((b) => b !== 0)).toBe(true);
      expect(sessionBundle.sessionTrafficKey.some((b) => b !== 0)).toBe(true);

      drbg.zeroize();
      expect(drbg.isZeroized()).toBe(true);

      const snapshot = drbg.inspectInternalBuffers();
      expect(snapshot.executionEnvironment).toBe("software-uint8array");
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

  describe("PrefixCachePool, Keyed HMAC Prefix Hashing & Constant-Time Compare", () => {
    it("compares byte buffers in constant time via constantTimeEqualBytes", () => {
      const a = utf8ToBytes("drouter-session-prefix-key-32byt");
      const b = utf8ToBytes("drouter-session-prefix-key-32byt");
      const c = utf8ToBytes("drouter-session-prefix-key-32byX");
      const shorter = utf8ToBytes("short");

      expect(constantTimeEqualBytes(a, b)).toBe(true);
      expect(constantTimeEqualBytes(a, c)).toBe(false);
      expect(constantTimeEqualBytes(a, shorter)).toBe(false);
    });

    it("hits at 512-token block boundaries within the same session (1,200 matching tokens -> 1,024 tokens = 2 blocks)", () => {
      const seed = new Uint8Array(32).fill(0x19);
      const drbg = new CustodyCtrDrbg(seed);
      const session1 = drbg.deriveSessionKeys("session-1");
      const session2 = drbg.deriveSessionKeys("session-2");

      const pool = new PrefixCachePool();

      const baseTokens = Array.from({ length: 1536 }, (_, idx) => 500 + idx);
      pool.storePrefix(session1.sessionId, baseTokens, session1.sessionPrefixKey);

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

      const popResult = pool.popSession(session1.sessionId);
      expect(popResult.evicted).toBe(true);
      expect(popResult.allZeroVerified).toBe(true);
      expect(pool.hasSession(session1.sessionId)).toBe(false);
    });
  });

  describe("verifyCustodyPrimitives & GET /api/custody", () => {
    it("verifies real cryptographic primitives and serves GET /api/custody without simulated memory-bus model fields", async () => {
      const primitives = verifyCustodyPrimitives();
      expect(primitives.executionEnvironment).toBe("software-uint8array");
      expect(primitives.observesPhysicalGpuMemory).toBe(false);
      expect(primitives.allPrimitivesPassed).toBe(true);
      expect(primitives.ctrDrbg.deterministicForIdenticalSeeds).toBe(true);
      expect(primitives.ctrDrbg.divergesOnClientEntropyReseed).toBe(true);
      expect(primitives.ctrDrbg.zeroizedBuffersVerified).toBe(true);
      expect(primitives.prefixCache.constantTimeCompareVerified).toBe(true);
      expect(primitives.prefixCache.sameSessionHitBlocks).toBe(3);
      expect(primitives.prefixCache.crossSessionHitBlocks).toBe(0);
      expect(primitives.aesGcmEnvelope.plaintextSubstringMatchesInCiphertext).toBe(0);
      expect(primitives.aesGcmEnvelope.repeated16ByteCipherBlocks).toBe(0);
      expect(primitives.aesGcmEnvelope.ciphertextShannonEntropyBitsPerByte).toBeGreaterThan(7.5);
      expect(primitives.aesGcmEnvelope.decryptAfterKeyZeroizeFailed).toBe(true);

      const res = await getCustodyRoute(new Request("http://localhost:3000/api/custody"));
      expect(res.status).toBe(200);
      const json = (await res.json()) as {
        executionEnvironment: string;
        observesPhysicalGpuMemory: boolean;
        primitives: { allPrimitivesPassed: boolean };
        audit?: unknown;
        prefixCacheDemo: { constantTimeCompareCheck: boolean; popZeroized: boolean };
      };
      expect(json.executionEnvironment).toBe("software-uint8array");
      expect(json.observesPhysicalGpuMemory).toBe(false);
      expect(json.primitives.allPrimitivesPassed).toBe(true);
      expect(json.audit).toBeUndefined();
      expect(json.prefixCacheDemo.constantTimeCompareCheck).toBe(true);
      expect(json.prefixCacheDemo.popZeroized).toBe(true);
    });

    it("rejects all-zero hardware seeds, all-zero prefix keys, and non-positive or oversized generate requests", () => {
      expect(() => new CustodyCtrDrbg(new Uint8Array(32))).toThrow(/all-zero/i);
      expect(() => new CustodyCtrDrbg(new Uint8Array(16).fill(1))).toThrow(/32-byte/i);

      const validSeed = new Uint8Array(32).fill(0x33);
      const drbg = new CustodyCtrDrbg(validSeed);
      expect(() => drbg.generate(0)).toThrow();
      expect(() => drbg.generate(-8)).toThrow();
      expect(() => drbg.generate(32 * 1024 * 1024)).toThrow();

      for (const size of [1, 15, 16, 17, 1024 * 1024]) {
        const out = drbg.generate(size);
        expect(out.byteLength).toBe(size);
      }

      expect(() => computePrefixBlockHashes([1, 2, 3], new Uint8Array(32))).toThrow(
        /all-zero/i
      );
    });
  });
});
