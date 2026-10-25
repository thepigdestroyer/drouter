import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  COARSE_TIME_WINDOW_SECONDS,
  coarsenEpochSecToHour,
  computeFreezeBucketSize,
  decryptFrozenState,
  deriveFreezeKey,
  encryptFrozenState,
  formatResumeCode,
  FREEZE_BLOB_VERSION_LEGACY,
  FREEZE_BLOB_VERSION_PADDED,
  MIN_FREEZE_BUCKET_BYTES,
  padFreezePlaintext,
  parseResumeCode,
  unpadFreezePlaintext,
} from "@/lib/freeze/crypto";
import {
  deleteFrozenBlob,
  destroyFrozenBlobVerified,
  ensureFreezeTtlIndex,
  FREEZE_TTL_INDEX_NAME,
  getFreezeStorageMode,
  getFrozenBlob,
  listFrozenBlobSummaries,
  MAX_CIPHERTEXT_BYTES,
  resetFreezeStoreForTests,
  saveFrozenBlob,
  setFreezeCollectionOverrideForTests,
  type FreezeCollectionLike,
  type StoredFrozenBlob,
} from "@/lib/freeze/store";
import {
  checkFrozenBlobStatus,
  destroyFrozenSession,
  downloadAndResume,
  downloadAndResumeFromCode,
  ensureIndexedDbDeviceKey,
  FREEZE_DEVICE_KEY_STORAGE,
  FREEZE_STORAGE_KEY,
  freezeAndUpload,
  getIndexedDbDeviceCryptoKey,
  listLocalFreezeReceipts,
  resetFreezeClientStateForTests,
  saveLocalFreezeReceipt,
  shredLocalFreezeSecret,
} from "@/lib/freeze/client";
import { GET as listRouteGet, POST as freezeRoutePost } from "@/lib/../../src/app/api/freeze/route";
import {
  DELETE as blobRouteDelete,
  GET as blobRouteGet,
} from "@/lib/../../src/app/api/freeze/[blobId]/route";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import type { FrozenSessionState } from "@/lib/types";

const sampleState: FrozenSessionState = {
  modelId: "deepseek-r1-70b",
  nodeKind: "tinfoil",
  messages: [
    { role: "user", content: "Summarize patient [NAME_1]'s lab panel." },
    { role: "assistant", content: "All metabolic markers for [NAME_1] are within normal limits." },
  ],
  simContextTokens: 128,
  createdAt: 1760001234, // uncoarsened input timestamp
  turnCount: 1,
};

function createMockMongoCollection() {
  const docs = new Map<string, StoredFrozenBlob>();
  const indexes: Array<{ spec: Record<string, 1 | -1>; options?: Record<string, unknown> }> = [];

  const collection: FreezeCollectionLike & {
    docs: Map<string, StoredFrozenBlob>;
    indexes: typeof indexes;
  } = {
    docs,
    indexes,
    createIndex: vi.fn(async (spec, options) => {
      indexes.push({ spec, options });
      return String(options?.name ?? "idx");
    }),
    updateOne: vi.fn(async (filter, update) => {
      const blobId = String(filter.blobId);
      const setDoc = (update as { $set: StoredFrozenBlob }).$set;
      docs.set(blobId, { ...setDoc });
      return { acknowledged: true, upsertedCount: 1 };
    }),
    findOne: vi.fn(async (filter) => {
      const blobId = String(filter.blobId);
      return docs.get(blobId) ?? null;
    }),
    deleteOne: vi.fn(async (filter) => {
      const blobId = String(filter.blobId);
      const existed = docs.delete(blobId);
      return { deletedCount: existed ? 1 : 0 };
    }),
    find: vi.fn((filter) => {
      const gtSec = (filter?.expiresAt as { $gt?: number } | undefined)?.$gt ?? 0;
      const matching = Array.from(docs.values()).filter((d) => d.expiresAt > gtSec);
      return {
        sort: () => ({
          limit: (n: number) => ({
            toArray: async () =>
              matching.sort((a, b) => b.createdAt - a.createdAt).slice(0, n),
          }),
        }),
      };
    }),
  };

  return collection;
}

describe("Subsystem 2: Encrypted Session Freeze, Resume & Crypto-Shredding", () => {
  beforeEach(() => {
    resetFreezeStoreForTests();
    resetFreezeClientStateForTests();
    resetRateLimitStateForTests();
  });

  afterEach(() => {
    resetFreezeStoreForTests();
    resetFreezeClientStateForTests();
    resetRateLimitStateForTests();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("encrypt -> store -> fetch -> decrypt round trip restores FrozenSessionState with coarse UTC hour timestamps", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const encrypted = encryptFrozenState(sampleState);
    expect(encrypted.blobId).toMatch(/^[0-9a-f]{32}$/);
    expect(encrypted.freezeSecretHex).toMatch(/^[0-9a-f]{64}$/);
    expect(encrypted.sessionIdHex).toMatch(/^[0-9a-f]{32}$/);
    expect(encrypted.createdAt % COARSE_TIME_WINDOW_SECONDS).toBe(0);

    const saved = await saveFrozenBlob({
      blobId: encrypted.blobId,
      sessionIdHex: encrypted.sessionIdHex,
      nonceHex: encrypted.nonceHex,
      aadHex: encrypted.aadHex,
      ciphertextHex: encrypted.ciphertextHex,
      modelId: encrypted.modelId,
      createdAt: 1760001234, // exact timestamp sent by caller must be coarsened by store
    });

    expect(saved.blobId).toBe(encrypted.blobId);
    expect(saved.byteLength).toBe(encrypted.ciphertextHex.length / 2);
    expect(saved.createdAt % COARSE_TIME_WINDOW_SECONDS).toBe(0);
    expect(saved.expiresAt % COARSE_TIME_WINDOW_SECONDS).toBe(0);
    expect("freezeSecretHex" in saved).toBe(false);

    const fetched = await getFrozenBlob(encrypted.blobId);
    expect(fetched).not.toBeNull();
    expect(fetched!.ciphertextHex).toBe(encrypted.ciphertextHex);

    const summaries = await listFrozenBlobSummaries();
    expect(summaries.some((s) => s.blobId === encrypted.blobId)).toBe(true);

    const decrypted = decryptFrozenState(fetched!, encrypted.freezeSecretHex);
    expect(decrypted).toEqual(sampleState);

    const deleted = await deleteFrozenBlob(encrypted.blobId);
    expect(deleted).toBe(true);
    expect(await getFrozenBlob(encrypted.blobId)).toBeNull();
  });

  it("creates MongoDB TTL index on frozen_blobs (expiresAtDate with expireAfterSeconds: 0) and unique blobId index", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const encrypted = encryptFrozenState(sampleState);
    await saveFrozenBlob({
      blobId: encrypted.blobId,
      sessionIdHex: encrypted.sessionIdHex,
      nonceHex: encrypted.nonceHex,
      aadHex: encrypted.aadHex,
      ciphertextHex: encrypted.ciphertextHex,
      modelId: encrypted.modelId,
      createdAt: encrypted.createdAt,
    });

    expect(mockCol.createIndex).toHaveBeenCalledWith(
      { expiresAtDate: 1 },
      { expireAfterSeconds: 0, name: FREEZE_TTL_INDEX_NAME },
    );
    expect(mockCol.createIndex).toHaveBeenCalledWith(
      { blobId: 1 },
      { unique: true, name: "blobId_unique_idx" },
    );

    const storedDoc = mockCol.docs.get(encrypted.blobId);
    expect(storedDoc).toBeDefined();
    expect(storedDoc!.expiresAtDate).toBeInstanceOf(Date);
    expect(storedDoc!.expiresAtDate!.getTime()).toBe(storedDoc!.expiresAt * 1000);

    // Direct call to ensureFreezeTtlIndex also works idempotently
    const ok = await ensureFreezeTtlIndex(mockCol);
    expect(ok).toBe(true);
  });

  it("enforces blob expiry and purges expired blobs on read", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const encrypted = encryptFrozenState(sampleState);
    const pastSec = Math.floor(Date.now() / 1000) - 7200;

    await saveFrozenBlob({
      blobId: encrypted.blobId,
      sessionIdHex: encrypted.sessionIdHex,
      nonceHex: encrypted.nonceHex,
      aadHex: encrypted.aadHex,
      ciphertextHex: encrypted.ciphertextHex,
      modelId: encrypted.modelId,
      createdAt: pastSec - 3600,
      expiresAt: pastSec,
    });

    expect(mockCol.docs.has(encrypted.blobId)).toBe(true);
    const fetched = await getFrozenBlob(encrypted.blobId);
    expect(fetched).toBeNull();
    // Expired blob is deleted from collection upon read
    expect(mockCol.docs.has(encrypted.blobId)).toBe(false);
  });

  it("encrypts FreezeReceipt at rest in localStorage and survives simulated page reloads, plus supports cross-device resume codes", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const storeMap = new Map<string, string>();
    const fakeLocalStorage = {
      getItem: (k: string) => storeMap.get(k) ?? null,
      setItem: (k: string, v: string) => {
        storeMap.set(k, v);
      },
      removeItem: (k: string) => {
        storeMap.delete(k);
      },
    };
    vi.stubGlobal("window", { localStorage: fakeLocalStorage });
    vi.stubGlobal("localStorage", fakeLocalStorage);

    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      const method = init?.method ?? "GET";

      if (url.endsWith("/api/freeze") && method === "POST") {
        const req = new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: String(init?.body),
        });
        return freezeRoutePost(req);
      }

      const match = url.match(/\/api\/freeze\/([0-9a-fA-F]+)$/);
      if (match && method === "GET") {
        const req = new Request(url, { method: "GET" });
        return blobRouteGet(req, { params: Promise.resolve({ blobId: match[1] }) });
      }
      if (match && method === "DELETE") {
        const req = new Request(url, { method: "DELETE" });
        return blobRouteDelete(req, { params: Promise.resolve({ blobId: match[1] }) });
      }

      return new Response(JSON.stringify({ error: "Unhandled route" }), { status: 404 });
    });

    const receipt = await freezeAndUpload("http://localhost:3000", sampleState);
    expect(receipt.blobId).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.byteLength).toBeGreaterThan(0);
    expect(receipt.resumeCode).toMatch(/^drouter-freeze-v1:[0-9a-f]{32}:[0-9a-f]{64}:[0-9a-f]{32}$/);

    // Verify localStorage holds AES-256-GCM encrypted ciphertext, NEVER raw freezeSecretHex
    const rawStored = storeMap.get(FREEZE_STORAGE_KEY);
    expect(rawStored).toBeTruthy();
    expect(rawStored!).not.toContain(receipt.freezeSecretHex);
    const parsedStored = JSON.parse(rawStored!);
    expect(parsedStored.format).toBe("drouter-freeze-receipts-v1-gcm");
    expect(parsedStored.nonceHex).toMatch(/^[0-9a-f]{24}$/);
    expect(storeMap.get(FREEZE_DEVICE_KEY_STORAGE)).toMatch(/^[0-9a-f]{64}$/);

    // List local receipts (decrypts using persisted device wrapping key)
    const localReceipts = listLocalFreezeReceipts();
    expect(localReceipts.some((r) => r.blobId === receipt.blobId && r.freezeSecretHex === receipt.freezeSecretHex)).toBe(
      true,
    );

    // Cross-device resume using the copyable resumeCode
    const { parsed, state: resumedFromCode } = await downloadAndResumeFromCode(
      "http://localhost:3000",
      receipt.resumeCode,
    );
    expect(parsed.blobId).toBe(receipt.blobId);
    expect(resumedFromCode.messages).toEqual(sampleState.messages);
    expect(resumedFromCode.modelId).toBe(sampleState.modelId);
    expect(resumedFromCode.createdAt).toBe(coarsenEpochSecToHour(sampleState.createdAt));

    // Verify status check reports resumable
    const statusBefore = await checkFrozenBlobStatus(
      "http://localhost:3000",
      receipt.blobId,
      receipt.expiresAt,
    );
    expect(statusBefore.status).toBe("resumable");

    // Explicit Destroy action: deletes server blob, wipes local key, and verifies 404 absence
    const destroyRes = await destroyFrozenSession("http://localhost:3000", receipt.blobId);
    expect(destroyRes.localSecretWiped).toBe(true);
    expect(destroyRes.serverDeleted).toBe(true);
    expect(destroyRes.verifiedAbsent).toBe(true);
    expect(mockCol.docs.has(receipt.blobId)).toBe(false);
    expect(listLocalFreezeReceipts().some((r) => r.blobId === receipt.blobId)).toBe(false);

    // Status check after destroy reports destroyed
    const statusAfter = await checkFrozenBlobStatus("http://localhost:3000", receipt.blobId);
    expect(statusAfter.status).toBe("destroyed");

    // Attempting to resume after destroy throws 404/destroyed error
    await expect(
      downloadAndResume("http://localhost:3000", receipt.blobId, receipt.freezeSecretHex),
    ).rejects.toThrow(/destroyed|expired/i);
  });

  it("parses and formats resume codes in compact and JSON formats", () => {
    const blobId = "aa".repeat(16);
    const secret = "bb".repeat(32);
    const sid = "cc".repeat(16);

    const code = formatResumeCode({ blobId, freezeSecretHex: secret, sessionIdHex: sid });
    expect(code).toBe(`drouter-freeze-v1:${blobId}:${secret}:${sid}`);

    const parsed1 = parseResumeCode(code);
    expect(parsed1).toEqual({ blobId, freezeSecretHex: secret, sessionIdHex: sid });

    const parsed2 = parseResumeCode(JSON.stringify({ blobId, freezeSecretHex: secret, sessionIdHex: sid }));
    expect(parsed2).toEqual({ blobId, freezeSecretHex: secret, sessionIdHex: sid });

    const parsed3 = parseResumeCode(`${blobId}:${secret}`);
    expect(parsed3).toEqual({ blobId, freezeSecretHex: secret, sessionIdHex: undefined });

    expect(() => parseResumeCode("invalid-code")).toThrow();
    expect(() => formatResumeCode({ blobId, freezeSecretHex: "00".repeat(32) })).toThrow();
  });

  it("server store rejects any payload containing freezeSecretHex, plaintext messages, prompts, or IP metadata, and caps blob size", async () => {
    const encrypted = encryptFrozenState(sampleState);

    await expect(
      saveFrozenBlob({
        blobId: encrypted.blobId,
        sessionIdHex: encrypted.sessionIdHex,
        nonceHex: encrypted.nonceHex,
        aadHex: encrypted.aadHex,
        ciphertextHex: encrypted.ciphertextHex,
        freezeSecretHex: encrypted.freezeSecretHex,
      }),
    ).rejects.toThrow(/freezeSecretHex|messages/i);

    await expect(
      saveFrozenBlob({
        blobId: encrypted.blobId,
        sessionIdHex: encrypted.sessionIdHex,
        nonceHex: encrypted.nonceHex,
        aadHex: encrypted.aadHex,
        ciphertextHex: encrypted.ciphertextHex,
        messages: sampleState.messages,
      }),
    ).rejects.toThrow(/freezeSecretHex|messages/i);

    await expect(
      saveFrozenBlob({
        blobId: encrypted.blobId,
        sessionIdHex: encrypted.sessionIdHex,
        nonceHex: encrypted.nonceHex,
        aadHex: encrypted.aadHex,
        ciphertextHex: encrypted.ciphertextHex,
        ip: "203.0.113.5",
      }),
    ).rejects.toThrow(/refuses/i);

    const oversizedCiphertextHex = "aa".repeat(MAX_CIPHERTEXT_BYTES + 1);
    await expect(
      saveFrozenBlob({
        blobId: encrypted.blobId,
        sessionIdHex: encrypted.sessionIdHex,
        nonceHex: encrypted.nonceHex,
        aadHex: encrypted.aadHex,
        ciphertextHex: oversizedCiphertextHex,
      }),
    ).rejects.toThrow(/exceeds maximum allowed size/i);
  });

  it("enforces rate limiting and size caps on /api/freeze routes and labels storage mode clearly", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const getRes = await listRouteGet(new Request("http://localhost:3000/api/freeze"));
    expect(getRes.status).toBe(200);
    const getBody = (await getRes.json()) as {
      blobs: unknown[];
      storageMode: string;
      persisted: boolean;
    };
    expect(getBody.storageMode).toBe("mongodb");
    expect(getBody.persisted).toBe(true);

    // Verify memory label when MONGODB_URI is unset and no collection override is present
    setFreezeCollectionOverrideForTests(undefined);
    const origUri = process.env.MONGODB_URI;
    delete process.env.MONGODB_URI;
    try {
      const modeInfo = getFreezeStorageMode();
      expect(modeInfo.mode).toBe("memory");
      expect(modeInfo.persisted).toBe(false);
      expect(modeInfo.label).toBe("Temporary memory (database not configured)");
    } finally {
      if (origUri !== undefined) process.env.MONGODB_URI = origUri;
    }

    // Rate limiting on POST /api/freeze (capacity = 15)
    setFreezeCollectionOverrideForTests(mockCol);
    const encrypted = encryptFrozenState(sampleState);
    let lastStatus = 200;
    for (let i = 0; i < 17; i++) {
      const req = new Request("http://localhost:3000/api/freeze", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "198.51.100.42",
        },
        body: JSON.stringify({
          blobId: encrypted.blobId,
          sessionIdHex: encrypted.sessionIdHex,
          nonceHex: encrypted.nonceHex,
          aadHex: encrypted.aadHex,
          ciphertextHex: encrypted.ciphertextHex,
          modelId: encrypted.modelId,
          createdAt: encrypted.createdAt,
        }),
      });
      const res = await freezeRoutePost(req);
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(429);
  });

  it("wrong or shredded freezeSecretHex fails AES-GCM authentication and throws", () => {
    const encrypted = encryptFrozenState(sampleState);
    const wrongSecret = "ff".repeat(32);
    const zeroedSecret = "00".repeat(32);

    expect(() => decryptFrozenState(encrypted, wrongSecret)).toThrow(
      "Crypto-shredded or invalid freeze key: authentication tag mismatch",
    );
    expect(() => decryptFrozenState(encrypted, zeroedSecret)).toThrow(
      "Crypto-shredded or invalid freeze key: authentication tag mismatch",
    );
    expect(() => decryptFrozenState(encrypted, "")).toThrow(
      "Crypto-shredded or invalid freeze key: authentication tag mismatch",
    );
    expect(() => deriveFreezeKey(zeroedSecret, encrypted.sessionIdHex)).toThrow(
      "Crypto-shredded or invalid freeze key: authentication tag mismatch",
    );
  });

  it("tampered ciphertextHex, nonceHex, or aadHex fails AES-GCM authentication", () => {
    const encrypted = encryptFrozenState(sampleState);

    const flippedFirstByte =
      (encrypted.ciphertextHex.startsWith("00") ? "ff" : "00") +
      encrypted.ciphertextHex.slice(2);
    expect(() =>
      decryptFrozenState(
        { ...encrypted, ciphertextHex: flippedFirstByte },
        encrypted.freezeSecretHex,
      ),
    ).toThrow("Crypto-shredded or invalid freeze key: authentication tag mismatch");

    const tamperedAad =
      encrypted.aadHex.slice(0, -2) + (encrypted.aadHex.endsWith("00") ? "01" : "00");
    expect(() =>
      decryptFrozenState({ ...encrypted, aadHex: tamperedAad }, encrypted.freezeSecretHex),
    ).toThrow("Crypto-shredded or invalid freeze key: authentication tag mismatch");

    const tamperedNonce =
      encrypted.nonceHex.slice(0, -2) + (encrypted.nonceHex.endsWith("00") ? "01" : "00");
    expect(() =>
      decryptFrozenState({ ...encrypted, nonceHex: tamperedNonce }, encrypted.freezeSecretHex),
    ).toThrow("Crypto-shredded or invalid freeze key: authentication tag mismatch");
  });

  it("stress-tests 200 randomized freeze/resume round-trips and boundary payload sizes (0 turns, 1B, 1MB)", () => {
    const largeContent = "Z".repeat(1024 * 1024);
    const largeState: FrozenSessionState = {
      modelId: "kimi-k3",
      nodeKind: "tinfoil",
      messages: [{ role: "user", content: largeContent }],
      simContextTokens: 262144,
      createdAt: 1760000100,
      turnCount: 1,
    };
    const encLarge = encryptFrozenState(largeState);
    const decLarge = decryptFrozenState(encLarge, encLarge.freezeSecretHex);
    expect(decLarge.messages[0].content.length).toBe(1024 * 1024);

    for (let i = 0; i < 200; i++) {
      const state: FrozenSessionState = {
        modelId: "kimi-k3",
        nodeKind: i % 2 === 0 ? "tinfoil" : "sim",
        messages:
          i === 0
            ? []
            : [{ role: "user", content: `Turn ${i}: secret=${i * 997}` }],
        simContextTokens: i * 16,
        createdAt: 1760000000 + i,
        turnCount: i,
      };
      const bundle = encryptFrozenState(state);
      expect(decryptFrozenState(bundle, bundle.freezeSecretHex)).toEqual(state);
    }
  });

  it("destroyFrozenBlobVerified confirms physical removal from mock collection", async () => {
    const mockCol = createMockMongoCollection();
    setFreezeCollectionOverrideForTests(mockCol);

    const encrypted = encryptFrozenState(sampleState);
    await saveFrozenBlob({
      blobId: encrypted.blobId,
      sessionIdHex: encrypted.sessionIdHex,
      nonceHex: encrypted.nonceHex,
      aadHex: encrypted.aadHex,
      ciphertextHex: encrypted.ciphertextHex,
    });

    const res = await destroyFrozenBlobVerified(encrypted.blobId);
    expect(res).toEqual({ deleted: true, verifiedAbsent: true });
    expect(shredLocalFreezeSecret(encrypted.blobId).shredded).toBe(false);
  });

  it("pads serialized session plaintext to power-of-two buckets (min 4096 bytes) before AES-GCM encryption", () => {
    expect(computeFreezeBucketSize(0)).toBe(4096);
    expect(computeFreezeBucketSize(100)).toBe(4096);
    expect(computeFreezeBucketSize(4096)).toBe(4096);
    expect(computeFreezeBucketSize(4097)).toBe(8192);
    expect(computeFreezeBucketSize(8192)).toBe(8192);
    expect(computeFreezeBucketSize(8193)).toBe(16384);

    // Small payload (< 4088 bytes) -> 4096-byte plaintext + 16-byte GCM tag = 4112-byte ciphertext
    const smallEncrypted = encryptFrozenState(sampleState);
    expect(smallEncrypted.version).toBe(FREEZE_BLOB_VERSION_PADDED);
    expect(smallEncrypted.ciphertextHex.length / 2).toBe(MIN_FREEZE_BUCKET_BYTES + 16);
    expect(decryptFrozenState(smallEncrypted, smallEncrypted.freezeSecretHex)).toEqual(sampleState);

    // Medium payload (~5000 bytes) -> 8192-byte plaintext + 16-byte GCM tag = 8208-byte ciphertext
    const mediumState: FrozenSessionState = {
      ...sampleState,
      messages: [{ role: "user", content: "M".repeat(5000) }],
    };
    const mediumEncrypted = encryptFrozenState(mediumState);
    expect(mediumEncrypted.ciphertextHex.length / 2).toBe(8192 + 16);
    expect(decryptFrozenState(mediumEncrypted, mediumEncrypted.freezeSecretHex)).toEqual(mediumState);

    // Larger payload (~10000 bytes) -> 16384-byte plaintext + 16-byte GCM tag = 16400-byte ciphertext
    const largerState: FrozenSessionState = {
      ...sampleState,
      messages: [{ role: "user", content: "L".repeat(10000) }],
    };
    const largerEncrypted = encryptFrozenState(largerState);
    expect(largerEncrypted.ciphertextHex.length / 2).toBe(16384 + 16);
    expect(decryptFrozenState(largerEncrypted, largerEncrypted.freezeSecretHex)).toEqual(largerState);

    // Direct pad / unpad unit verification
    const raw = utf8ToBytes('{"hello":"world"}');
    const padded = padFreezePlaintext(raw);
    expect(padded.byteLength).toBe(4096);
    const unpadded = unpadFreezePlaintext(padded, FREEZE_BLOB_VERSION_PADDED);
    expect(new TextDecoder().decode(unpadded)).toBe('{"hello":"world"}');
  });

  it("keeps decrypting legacy unpadded v1 blobs (with or without explicit version field)", () => {
    const secretHex = "11".repeat(32);
    const sidHex = "22".repeat(16);
    const key = deriveFreezeKey(secretHex, sidHex);
    const nonce = new Uint8Array(12).fill(7);
    const aad = utf8ToBytes("drouter/v1/freeze-blob:" + sidHex);
    // Construct an old unpadded ciphertext directly (exact JSON UTF-8 bytes without DRF2 prefix)
    const unpaddedPlaintext = utf8ToBytes(JSON.stringify(sampleState));
    const legacyCiphertext = gcm(key, nonce, aad).encrypt(unpaddedPlaintext);
    const legacyBlobId = bytesToHex(sha256(legacyCiphertext)).slice(0, 32);

    const legacyBundleWithoutVersion = {
      blobId: legacyBlobId,
      sessionIdHex: sidHex,
      nonceHex: bytesToHex(nonce),
      aadHex: bytesToHex(aad),
      ciphertextHex: bytesToHex(legacyCiphertext),
    };

    // Decrypts when version field is absent (pre-F-09 stored MongoDB document)
    expect(decryptFrozenState(legacyBundleWithoutVersion, secretHex)).toEqual(sampleState);

    // Decrypts when version is explicitly 1 (FREEZE_BLOB_VERSION_LEGACY)
    expect(
      decryptFrozenState(
        { ...legacyBundleWithoutVersion, version: FREEZE_BLOB_VERSION_LEGACY },
        secretHex,
      ),
    ).toEqual(sampleState);
  });

  it("migrates legacy localStorage device key into IndexedDB as a non-extractable CryptoKey and deletes it from localStorage", async () => {
    const storeMap = new Map<string, string>();
    const fakeLocalStorage = {
      getItem: (k: string) => storeMap.get(k) ?? null,
      setItem: (k: string, v: string) => {
        storeMap.set(k, v);
      },
      removeItem: (k: string) => {
        storeMap.delete(k);
      },
    };

    // Minimal spec-compliant in-memory IndexedDB mock supporting structured clone of CryptoKey
    const idbDatabases = new Map<string, Map<string, Map<string, unknown>>>();
    const fakeIndexedDB = {
      open: (dbName: string) => {
        let dbStores = idbDatabases.get(dbName);
        const isNew = !dbStores;
        if (!dbStores) {
          dbStores = new Map();
          idbDatabases.set(dbName, dbStores);
        }
        const storesRef = dbStores;
        const dbObj = {
          objectStoreNames: {
            contains: (name: string) => storesRef.has(name),
          },
          createObjectStore: (name: string) => {
            if (!storesRef.has(name)) {
              storesRef.set(name, new Map());
            }
            return {};
          },
          transaction: (storeName: string) => ({
            objectStore: (name: string) => {
              const target = storesRef.get(name) ?? storesRef.get(storeName)!;
              return {
                get: (key: string) => {
                  const req: { result?: unknown; onsuccess?: () => void; onerror?: () => void } = {};
                  queueMicrotask(() => {
                    req.result = target.get(key) ?? null;
                    req.onsuccess?.();
                  });
                  return req;
                },
                put: (val: unknown, key: string) => {
                  const req: { result?: unknown; onsuccess?: () => void; onerror?: () => void } = {};
                  queueMicrotask(() => {
                    target.set(key, val);
                    req.onsuccess?.();
                  });
                  return req;
                },
              };
            },
          }),
          close: () => {},
        };
        const openReq: {
          result?: unknown;
          onupgradeneeded?: () => void;
          onsuccess?: () => void;
          onerror?: () => void;
        } = { result: dbObj };
        queueMicrotask(() => {
          if (isNew) openReq.onupgradeneeded?.();
          openReq.onsuccess?.();
        });
        return openReq;
      },
    };

    // Step 1: Simulate existing pre-migration state where IndexedDB was not yet used
    // and localStorage has both `drouter.freeze.device-key.v1` and `drouter.freeze.v1`.
    vi.stubGlobal("window", { localStorage: fakeLocalStorage });
    vi.stubGlobal("localStorage", fakeLocalStorage);

    const legacyReceipt = {
      blobId: "ab".repeat(16),
      freezeSecretHex: "cd".repeat(32),
      sessionIdHex: "ef".repeat(16),
      createdAt: 1760000400,
      byteLength: 4112,
      resumeCode: `drouter-freeze-v1:${"ab".repeat(16)}:${"cd".repeat(32)}:${"ef".repeat(16)}`,
    };
    saveLocalFreezeReceipt(legacyReceipt);
    expect(storeMap.get(FREEZE_DEVICE_KEY_STORAGE)).toMatch(/^[0-9a-f]{64}$/);
    const ciphertextBeforeMigration = storeMap.get(FREEZE_STORAGE_KEY);
    expect(ciphertextBeforeMigration).toBeTruthy();

    // Step 2: Enable IndexedDB and run migration
    resetFreezeClientStateForTests();
    vi.stubGlobal("window", { localStorage: fakeLocalStorage, indexedDB: fakeIndexedDB });
    vi.stubGlobal("indexedDB", fakeIndexedDB);

    const derivedKey = await ensureIndexedDbDeviceKey();
    expect(derivedKey).toBeInstanceOf(Uint8Array);
    expect(derivedKey!.byteLength).toBe(32);

    // Verify legacy plaintext key is deleted from localStorage after migration
    expect(storeMap.has(FREEZE_DEVICE_KEY_STORAGE)).toBe(false);

    // Verify IndexedDB holds a non-extractable WebCrypto CryptoKey
    const idbCryptoKey = await getIndexedDbDeviceCryptoKey();
    expect(idbCryptoKey).not.toBeNull();
    expect(idbCryptoKey!.extractable).toBe(false);
    expect(idbCryptoKey!.type).toBe("secret");
    await expect(
      globalThis.crypto.subtle.exportKey("raw", idbCryptoKey!),
    ).rejects.toThrow();

    // Verify existing receipts in localStorage were re-encrypted and still decrypt cleanly
    const migratedReceipts = listLocalFreezeReceipts();
    expect(migratedReceipts).toHaveLength(1);
    expect(migratedReceipts[0].blobId).toBe(legacyReceipt.blobId);
    expect(migratedReceipts[0].freezeSecretHex).toBe(legacyReceipt.freezeSecretHex);
  });
});
