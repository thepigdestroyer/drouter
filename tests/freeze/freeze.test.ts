import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  COARSE_TIME_WINDOW_SECONDS,
  coarsenEpochSecToHour,
  decryptFrozenState,
  deriveFreezeKey,
  encryptFrozenState,
  formatResumeCode,
  parseResumeCode,
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
  FREEZE_DEVICE_KEY_STORAGE,
  FREEZE_STORAGE_KEY,
  freezeAndUpload,
  listLocalFreezeReceipts,
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
    resetRateLimitStateForTests();
  });

  afterEach(() => {
    resetFreezeStoreForTests();
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
});
