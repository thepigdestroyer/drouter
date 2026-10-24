import { describe, expect, it } from "vitest";
import {
  ATLAS_COLLECTION_NAME,
  ATLAS_RECEIPTS_COLLECTION_NAME,
  ATLAS_SEED_DOCS,
  coarsenIsoToUtcHour,
  cosineSimilarity,
  EMBEDDING_DIMENSIONS,
  embedDocumentText,
  getAtlasDb,
  ingestAtlasDocument,
  LOCAL_STANDIN_EMBEDDING_MODEL,
  recordAgentVerificationReceipt,
  runAtlasHybridSearch,
  runAtlasStreamAnalytics,
  searchAgentVerificationReceipts,
} from "@/lib/atlas";
import { POST as atlasPost } from "@/app/api/atlas/route";

describe("MongoDB Atlas Developer Data Platform Showcase", () => {
  it("produces 128-dim unit-normalized vectors (L2 norm ≈ 1.0), names local stand-in honestly, and separates semantic clusters", () => {
    const embA = embedDocumentText("DDR5 memory bus interposer probe");
    const embB = embedDocumentText("TEE.fail DDR5 Riser Attack");
    const embUnrelated = embedDocumentText("Shamir 3-of-5 secret sharing RSA blind credit nullifier");

    expect(embA.dimensions).toBe(EMBEDDING_DIMENSIONS);
    expect(embA.vector).toHaveLength(128);
    expect(embA.model).toBe(LOCAL_STANDIN_EMBEDDING_MODEL);

    const l2NormA = Math.sqrt(embA.vector.reduce((acc, v) => acc + v * v, 0));
    const l2NormB = Math.sqrt(embB.vector.reduce((acc, v) => acc + v * v, 0));
    expect(l2NormA).toBeCloseTo(1.0, 5);
    expect(l2NormB).toBeCloseTo(1.0, 5);

    const relatedSim = cosineSimilarity(embA.vector, embB.vector);
    const unrelatedSim = cosineSimilarity(embA.vector, embUnrelated.vector);

    expect(relatedSim).toBeGreaterThan(0.55);
    expect(unrelatedSim).toBeLessThan(0.2);
    expect(relatedSim - unrelatedSim).toBeGreaterThan(0.4);
  });

  it("curates all 16 seed documents (10 providers, 4 hardware advisories, 2 architecture specs) with 128-d embeddings", () => {
    expect(ATLAS_SEED_DOCS).toHaveLength(16);

    const providers = ATLAS_SEED_DOCS.filter((d) => d.category === "provider");
    const advisories = ATLAS_SEED_DOCS.filter((d) => d.category === "advisory");
    const architecture = ATLAS_SEED_DOCS.filter((d) => d.category === "architecture");

    expect(providers).toHaveLength(10);
    expect(advisories).toHaveLength(4);
    expect(architecture).toHaveLength(2);

    for (const doc of ATLAS_SEED_DOCS) {
      expect(doc.embedding).toHaveLength(128);
      const norm = Math.sqrt(doc.embedding.reduce((acc, v) => acc + v * v, 0));
      expect(norm).toBeCloseTo(1.0, 5);
    }
  });

  it("ranks 'Kimi K3 8x GPU confidential enclave' and 'TEE.fail DDR5 memory bus' accurately using Reciprocal Rank Fusion and reports engines", async () => {
    const kimiSearch = await runAtlasHybridSearch("Kimi K3 8x GPU confidential enclave");
    expect(kimiSearch.results.length).toBeGreaterThan(0);
    expect(kimiSearch.engines).toBeDefined();
    expect(["atlas", "app-fallback"]).toContain(kimiSearch.engines.vectorSearch);
    expect(["atlas", "app-fallback"]).toContain(kimiSearch.engines.textSearch);
    expect(["$rankFusion", "app-rrf"]).toContain(kimiSearch.engines.fusion);
    expect(kimiSearch.engines.embedding).toContain("local-hashed-128");

    const topKimi = kimiSearch.results[0];
    expect(topKimi.docId).toBe("provider-tinfoil");
    expect(topKimi.vectorRank).toBeGreaterThanOrEqual(1);
    expect(topKimi.textRank).toBeGreaterThanOrEqual(1);
    const expectedKimiRrf = Number(
      (1 / (60 + topKimi.vectorRank) + 1 / (60 + topKimi.textRank)).toFixed(6),
    );
    expect(topKimi.rrfScore).toBeCloseTo(expectedKimiRrf, 5);

    const teeFailSearch = await runAtlasHybridSearch("TEE.fail DDR5 memory bus");
    expect(teeFailSearch.results.length).toBeGreaterThan(0);

    const topTeeFail = teeFailSearch.results[0];
    expect(topTeeFail.docId).toBe("advisory-tee-fail-ddr5");
    expect(topTeeFail.vectorRank).toBe(1);
    expect(topTeeFail.textRank).toBe(1);
    expect(topTeeFail.rrfScore).toBeCloseTo(2 / 61, 5);
  });

  it("stores and searches per-run agent verification receipts with coarsened UTC-hour timestamps and zero PII", async () => {
    const coarsened = coarsenIsoToUtcHour("2026-10-24T16:42:19.831Z");
    expect(coarsened).toBe("2026-10-24T16:00:00.000Z");

    const recorded = await recordAgentVerificationReceipt({
      receiptId: "argon-run-test-receipt-01",
      timestampIso: "2026-10-24T16:42:19.831Z",
      mode: "simulated",
      primaryModel: "gemini-4-argon",
      enclaveModel: "kimi-k3",
      routerHost: "router-0.tinfoil.sh",
      enclaveHost: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
      overallPassed: true,
      faultInjected: true,
      selfHealed: true,
      humanGateState: "paused_awaiting_human",
      checksSummary: [
        { id: "C1", passed: true },
        { id: "C5", passed: true },
      ],
      forensicProofDigestHex: "a".repeat(64),
      ed25519SignatureHex: "b".repeat(128),
      signerPublicKeyHex: "c".repeat(64),
    });

    expect(recorded.receipt.coarsenedAt).toBe("2026-10-24T16:00:00.000Z");
    expect(recorded.receipt.embedding).toHaveLength(128);

    const foundReceipts = await searchAgentVerificationReceipts("kimi-k3-inf14", 5);
    expect(foundReceipts.some((r) => r.receiptId === "argon-run-test-receipt-01")).toBe(true);

    const hybridWithReceipts = await runAtlasHybridSearch("kimi-k3-inf14");
    expect(
      hybridWithReceipts.matchingReceipts.some((r) => r.receiptId === "argon-run-test-receipt-01"),
    ).toBe(true);

    const db = await getAtlasDb();
    if (db) {
      await db
        .collection(ATLAS_RECEIPTS_COLLECTION_NAME)
        .deleteOne({ receiptId: "argon-run-test-receipt-01" })
        .catch(() => null);
    }
  });

  it("gates HTTP POST ingest with ATLAS_INGEST_TOKEN, caps document size, and rejects prompts", async () => {
    await expect(
      ingestAtlasDocument({
        title: "Test Prompt Leak",
        summary: "Summary text",
        category: "advisory",
        prompt: "secret user prompt",
      }),
    ).rejects.toThrow(/Prompts must never be stored/i);

    await expect(
      ingestAtlasDocument({
        title: "Oversized Document",
        summary: "x".repeat(9000),
        category: "advisory",
      }),
    ).rejects.toThrow(/exceeds maximum/i);

    const prevToken = process.env.ATLAS_INGEST_TOKEN;
    try {
      delete process.env.ATLAS_INGEST_TOKEN;
      const reqDisabled = new Request("http://localhost:3000/api/atlas", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "ingest",
          title: "Unauthenticated Ingest",
          summary: "Should be blocked",
        }),
      });
      const resDisabled = await atlasPost(reqDisabled);
      expect(resDisabled.status).toBe(403);

      process.env.ATLAS_INGEST_TOKEN = "test-ingest-token-secret";
      const reqUnauthorized = new Request("http://localhost:3000/api/atlas", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-atlas-ingest-token": "wrong-token",
        },
        body: JSON.stringify({
          action: "ingest",
          title: "Unauthenticated Ingest",
          summary: "Should be blocked",
        }),
      });
      const resUnauthorized = await atlasPost(reqUnauthorized);
      expect(resUnauthorized.status).toBe(401);
    } finally {
      if (prevToken === undefined) {
        delete process.env.ATLAS_INGEST_TOKEN;
      } else {
        process.env.ATLAS_INGEST_TOKEN = prevToken;
      }
    }
  });

  it("supports embedding on ingest and multi-collection $facet aggregation", async () => {
    const ingested = await ingestAtlasDocument({
      docId: "advisory-custom-cxl-probe",
      title: "CXL 3.0 SEV-TIO Fabric Link Replay Test",
      summary:
        "Evaluates CXL 3.0 IDE link encryption counters between AMD Turin SEV-SNP host and NVIDIA B200 HBM3e confidential memory.",
      category: "advisory",
      tags: ["cxl 3.0", "sev-tio", "b200", "ide"],
    });

    expect(ingested.document.embedding).toHaveLength(128);

    const searchAfterIngest = await runAtlasHybridSearch("CXL 3.0 SEV-TIO Fabric Link Replay", {
      category: "advisory",
    });
    expect(searchAfterIngest.results.some((r) => r.docId === "advisory-custom-cxl-probe")).toBe(
      true,
    );

    const analytics = await runAtlasStreamAnalytics();
    expect(analytics.totalIntelligenceDocs).toBeGreaterThanOrEqual(16);
    expect(analytics.categoryBreakdown.length).toBeGreaterThanOrEqual(3);
    expect(analytics.searchIndexes.length).toBeGreaterThanOrEqual(2);
    expect(analytics.pipelineStagesExecuted).toContain("$facet");

    const db = await getAtlasDb();
    if (db) {
      await db
        .collection(ATLAS_COLLECTION_NAME)
        .deleteOne({ docId: "advisory-custom-cxl-probe" })
        .catch(() => null);
    }
  });
});
