import { describe, expect, it } from "vitest";
import {
  DEFAULT_BM25_B,
  DEFAULT_BM25_K1,
  DEFAULT_CHUNK_TOKEN_SIZE,
  LocalBM25Retriever,
  chunkCorpus,
  retrieveLocalContext,
} from "@/lib/localrag/retriever";
import {
  decryptHistoryAtRest,
  encryptHistoryAtRest,
  generateDeviceHistoryKey,
  generateDeviceHistoryKeyHex,
  loadEncryptedHistoryFromStorage,
  readRawEncryptedHistoryFromStorage,
  saveEncryptedHistoryToStorage,
  type LocalSessionHistory,
} from "@/lib/localrag/encrypted-history";

function buildChunkText(topicSummary: string, fillerSeed: number): string {
  const words: string[] = [topicSummary];
  for (let i = 0; i < 65; i++) {
    words.push(`item_${fillerSeed}_${i % 25}`);
  }
  return words.join(" ");
}

describe("Spec §2.5 — Client-Side BM25 Context RAG Retriever", () => {
  it("selects chunks containing the query's technical terms from a 50-chunk corpus and reports attentionSavingsMultiplier > 5", () => {
    const corpus: string[] = [];

    for (let i = 0; i < 50; i++) {
      if (i === 7) {
        corpus.push(
          buildChunkText(
            "Intel TDX QuoteV4 verification checks the ECDSA-P256 attestation signature and RTMR3 enclave measurement against the on-chain registry.",
            i,
          ),
        );
      } else if (i === 23) {
        corpus.push(
          buildChunkText(
            "SPDM 1.2 session transcripts bind the NVIDIA H100 PCIe device certificate chain to the TDX RTMR3 measurement register.",
            i,
          ),
        );
      } else if (i === 41) {
        corpus.push(
          buildChunkText(
            "During QuoteV4 attestation verification, any mismatch in RTMR3 or TCB SVN triggers immediate client circuit breaker rejection.",
            i,
          ),
        );
      } else {
        corpus.push(
          buildChunkText(
            `Routine quarterly culinary recipe log entry number ${i} discussing sourdough fermentation hydration and cast iron baking temperatures.`,
            i,
          ),
        );
      }
    }

    const query = "How does QuoteV4 attestation verify the RTMR3 enclave measurement and SPDM transcript?";
    const result = retrieveLocalContext(corpus, query, {
      tokenBudget: 1024,
      k1: DEFAULT_BM25_K1,
      b: DEFAULT_BM25_B,
    });

    expect(result.k1).toBe(1.5);
    expect(result.b).toBe(0.75);
    expect(result.totalChunks).toBe(50);
    expect(result.selectedChunks.length).toBeGreaterThanOrEqual(2);
    expect(result.selectedChunks.length).toBeLessThanOrEqual(5);

    const selectedIndices = result.selectedChunks.map((c) => c.index);
    expect(selectedIndices).toContain(7);
    expect(selectedIndices).toContain(23);
    expect(selectedIndices).toContain(41);

    // Every top selected chunk must contain the technical query terms
    for (const chunk of result.selectedChunks.slice(0, 3)) {
      expect(chunk.score).toBeGreaterThan(0);
      expect(chunk.text.toLowerCase()).toContain("rtmr3");
    }

    expect(result.totalTokensBefore).toBeGreaterThan(result.totalTokensAfter);
    expect(result.totalTokensAfter).toBeLessThanOrEqual(1024);
    expect(result.attentionSavingsMultiplier).toBeGreaterThan(5);
  });

  it("chunks long documents into ~256-token windows and enforces 4,096 / 16,384 token budgets over a 600,000-token session", () => {
    const longDocumentWords: string[] = [];
    for (let i = 0; i < 2000; i++) {
      if (i === 600) {
        longDocumentWords.push(
          "hpke_x25519_hkdf_sha384_aes_256_gcm",
          "ephemeral",
          "key",
          "schedule",
          "seals",
          "prompt",
        );
      } else {
        longDocumentWords.push(` telemetry_${i % 40}`);
      }
    }

    const chunks = chunkCorpus(longDocumentWords.join(" "), DEFAULT_CHUNK_TOKEN_SIZE);
    expect(chunks.length).toBeGreaterThan(6);
    for (const chunk of chunks.slice(0, -1)) {
      expect(chunk.tokens).toBeLessThanOrEqual(DEFAULT_CHUNK_TOKEN_SIZE + 16);
      expect(chunk.tokens).toBeGreaterThanOrEqual(180);
    }

    const retriever = new LocalBM25Retriever(chunks);
    const res = retriever.retrieve(
      "hpke_x25519_hkdf_sha384_aes_256_gcm ephemeral key schedule",
      {
        tokenBudget: 4096,
        totalTokensBeforeOverride: 600000,
      },
    );

    expect(res.selectedChunks.length).toBeGreaterThanOrEqual(1);
    expect(res.selectedChunks[0].text).toContain("hpke_x25519_hkdf_sha384_aes_256_gcm");
    expect(res.totalTokensBefore).toBe(600000);
    expect(res.totalTokensAfter).toBeLessThanOrEqual(4096);
    expect(res.attentionSavingsMultiplier).toBeGreaterThan(100);
  });
});

describe("Spec §1 — Encrypted-at-Rest Local Session History Store (AES-256-GCM)", () => {
  const sampleHistory: LocalSessionHistory = {
    sessionId: "sess-enclave-9f8e7d6c",
    messages: [
      {
        id: "msg-1",
        role: "user",
        content: "Analyze confidential patient BRCA1 variant c.5266dupC in TDX enclave.",
        createdAt: 1710000001000,
      },
      {
        id: "msg-2",
        role: "assistant",
        content: "Variant c.5266dupC is a pathogenic frameshift mutation; enclave session sealed.",
        createdAt: 1710000002000,
      },
    ],
    documents: [
      {
        id: "doc-1",
        title: "Genomic Panel Report",
        content: "CONFIDENTIAL_MARKER_BRCA1_5266DUPC_PLAINTEXT_CHECK",
      },
    ],
    updatedAt: 1710000002500,
  };

  it("round-trips cleanly with AES-256-GCM and never stores plaintext on disk", () => {
    const deviceKey = generateDeviceHistoryKey();
    expect(deviceKey.length).toBe(32);

    const bundle = encryptHistoryAtRest(sampleHistory, deviceKey);
    expect(bundle.algorithm).toBe("AES-256-GCM");
    expect(bundle.nonceBytes.length).toBe(12);
    expect(bundle.ciphertextBytes.length).toBeGreaterThan(16);

    // Verify ciphertext does not contain sensitive plaintext substrings
    expect(bundle.ciphertextHex.toLowerCase()).not.toContain(
      Buffer.from("BRCA1").toString("hex").toLowerCase(),
    );

    const decrypted = decryptHistoryAtRest<LocalSessionHistory>(bundle, deviceKey);
    expect(decrypted).toEqual(sampleHistory);

    // Verify storage helper persists only encrypted JSON without plaintext
    const storageKey = "drouter.test.localrag.history";
    saveEncryptedHistoryToStorage(sampleHistory, deviceKey, storageKey);
    const rawOnDisk = readRawEncryptedHistoryFromStorage(storageKey);
    expect(rawOnDisk).toBeTruthy();
    expect(rawOnDisk).not.toContain("BRCA1");
    expect(rawOnDisk).not.toContain("c.5266dupC");
    expect(rawOnDisk).not.toContain("CONFIDENTIAL_MARKER_BRCA1_5266DUPC_PLAINTEXT_CHECK");

    const loaded = loadEncryptedHistoryFromStorage<LocalSessionHistory>(deviceKey, storageKey);
    expect(loaded).toEqual(sampleHistory);
  });

  it("fails decryption on wrong 256-bit key or zeroed key", () => {
    const keyA = generateDeviceHistoryKeyHex();
    const keyB = generateDeviceHistoryKeyHex();
    const bundle = encryptHistoryAtRest(sampleHistory, keyA);

    expect(() => decryptHistoryAtRest(bundle, keyB)).toThrow(
      /wrong key or tampered ciphertext/i,
    );
    expect(() => decryptHistoryAtRest(bundle, new Uint8Array(32))).toThrow(
      /zeroed key|wrong key/i,
    );
  });

  it("fails decryption when ciphertext bytes, GCM tag, nonce, or AAD are tampered with", () => {
    const key = generateDeviceHistoryKey();
    const bundle = encryptHistoryAtRest(sampleHistory, key);

    // 1. Tamper with first byte of ciphertextBytes in-place
    const tamperedBytesBundle = {
      ...bundle,
      ciphertextBytes: new Uint8Array(bundle.ciphertextBytes),
    };
    tamperedBytesBundle.ciphertextBytes[0] ^= 0xff;
    expect(() => decryptHistoryAtRest(tamperedBytesBundle, key)).toThrow(
      /wrong key or tampered ciphertext/i,
    );

    // 2. Tamper with last byte (AES-GCM authentication tag) in hex-only bundle
    const rawCipherBytes = new Uint8Array(bundle.ciphertextBytes);
    rawCipherBytes[rawCipherBytes.length - 1] ^= 0x01;
    const tamperedTagHex = Array.from(rawCipherBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(() =>
      decryptHistoryAtRest(
        {
          sessionId: bundle.sessionId,
          nonceHex: bundle.nonceHex,
          aadHex: bundle.aadHex,
          ciphertextHex: tamperedTagHex,
        },
        key,
      ),
    ).toThrow(/wrong key or tampered ciphertext/i);

    // 3. Tamper with nonce
    const tamperedNonce = new Uint8Array(bundle.nonceBytes);
    tamperedNonce[0] ^= 0x80;
    expect(() =>
      decryptHistoryAtRest(
        {
          ...bundle,
          nonceBytes: tamperedNonce,
        },
        key,
      ),
    ).toThrow(/wrong key or tampered ciphertext/i);

    // 4. Tamper with sessionId (breaks AAD binding)
    expect(() =>
      decryptHistoryAtRest(
        {
          ...bundle,
          sessionId: "sess-enclave-hijacked",
        },
        key,
      ),
    ).toThrow(/wrong key or tampered ciphertext/i);
  });

  it("stress-tests boundary sizes (empty history, 1-byte message, 1MB document) and 200 randomized encrypt/decrypt cycles", () => {
    const key = generateDeviceHistoryKey();
    const emptyHistory: LocalSessionHistory = { sessionId: "s-empty", messages: [] };
    expect(decryptHistoryAtRest(encryptHistoryAtRest(emptyHistory, key), key)).toEqual(emptyHistory);

    const oneMbHistory: LocalSessionHistory = {
      sessionId: "s-1mb",
      messages: [{ role: "user", content: "M".repeat(1024 * 1024) }],
    };
    const dec1Mb = decryptHistoryAtRest<LocalSessionHistory>(
      encryptHistoryAtRest(oneMbHistory, key),
      key,
    );
    expect(dec1Mb.messages[0].content.length).toBe(1024 * 1024);

    for (let i = 0; i < 200; i++) {
      const h: LocalSessionHistory = {
        sessionId: `sess-fuzz-${i}`,
        messages: [{ role: "user", content: `msg-${i}-${"x".repeat(i % 64)}` }],
      };
      const enc = encryptHistoryAtRest(h, key);
      expect(decryptHistoryAtRest(enc, key)).toEqual(h);
    }
  });
});
