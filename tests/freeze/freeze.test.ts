import { afterEach, describe, expect, it, vi } from "vitest";
import {
  decryptFrozenState,
  deriveFreezeKey,
  encryptFrozenState,
} from "@/lib/freeze/crypto";
import {
  deleteFrozenBlob,
  getFrozenBlob,
  listFrozenBlobSummaries,
  saveFrozenBlob,
} from "@/lib/freeze/store";
import {
  downloadAndResume,
  freezeAndUpload,
  listLocalFreezeReceipts,
  shredLocalFreezeSecret,
} from "@/lib/freeze/client";
import type { FrozenSessionState } from "@/lib/types";

const sampleState: FrozenSessionState = {
  modelId: "deepseek-r1-70b",
  nodeKind: "tinfoil",
  messages: [
    { role: "user", content: "Summarize patient [NAME_1]'s lab panel." },
    { role: "assistant", content: "All metabolic markers for [NAME_1] are within normal limits." },
  ],
  simContextTokens: 128,
  createdAt: 1760000000,
  turnCount: 1,
};

describe("Subsystem 2: Encrypted Session Freeze, Resume & Crypto-Shredding", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("encrypt -> store -> fetch -> decrypt round trip restores exact FrozenSessionState", async () => {
    const encrypted = encryptFrozenState(sampleState);
    expect(encrypted.blobId).toMatch(/^[0-9a-f]{32}$/);
    expect(encrypted.freezeSecretHex).toMatch(/^[0-9a-f]{64}$/);
    expect(encrypted.sessionIdHex).toMatch(/^[0-9a-f]{32}$/);

    const saved = await saveFrozenBlob({
      blobId: encrypted.blobId,
      sessionIdHex: encrypted.sessionIdHex,
      nonceHex: encrypted.nonceHex,
      aadHex: encrypted.aadHex,
      ciphertextHex: encrypted.ciphertextHex,
      modelId: encrypted.modelId,
      createdAt: encrypted.createdAt,
    });

    expect(saved.blobId).toBe(encrypted.blobId);
    expect(saved.byteLength).toBe(encrypted.ciphertextHex.length / 2);
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

  it("supports end-to-end client helper freezeAndUpload -> downloadAndResume -> shredLocalFreezeSecret", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      const method = init?.method ?? "GET";

      if (url.endsWith("/api/freeze") && method === "POST") {
        const body = JSON.parse(String(init?.body));
        const saved = await saveFrozenBlob(body);
        return new Response(
          JSON.stringify({
            stored: true,
            blobId: saved.blobId,
            byteLength: saved.byteLength,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      const match = url.match(/\/api\/freeze\/([0-9a-fA-F]+)$/);
      if (match && method === "GET") {
        const found = await getFrozenBlob(match[1]);
        if (!found) {
          return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
        }
        return new Response(JSON.stringify(found), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ error: "Unhandled route" }), { status: 404 });
    });

    const receipt = await freezeAndUpload("http://localhost:3000", sampleState);
    expect(receipt.blobId).toMatch(/^[0-9a-f]{32}$/);
    expect(receipt.byteLength).toBeGreaterThan(0);

    const localReceipts = listLocalFreezeReceipts();
    expect(localReceipts.some((r) => r.blobId === receipt.blobId)).toBe(true);

    const resumed = await downloadAndResume(
      "http://localhost:3000",
      receipt.blobId,
      receipt.freezeSecretHex,
    );
    expect(resumed).toEqual(sampleState);

    const shredResult = shredLocalFreezeSecret(receipt.blobId);
    expect(shredResult.shredded).toBe(true);
    expect(listLocalFreezeReceipts().some((r) => r.blobId === receipt.blobId)).toBe(false);
  });

  it("server store rejects any payload containing freezeSecretHex or messages", async () => {
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

  it("tampered ciphertextHex or aadHex fails AES-GCM authentication", () => {
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
});
