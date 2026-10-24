import { describe, expect, it } from "vitest";
import {
  ATLAS_COLLECTION_NAME,
  ATLAS_SEED_DOCS,
  cosineSimilarity,
  EMBEDDING_DIMENSIONS,
  embedDocumentText,
  getAtlasDb,
  ingestAtlasDocument,
  runAtlasHybridSearch,
  runAtlasStreamAnalytics,
} from "@/lib/atlas";

describe("MongoDB Atlas Developer Data Platform Showcase", () => {
  it("produces 128-dim unit-normalized vectors (L2 norm ≈ 1.0) and separates semantic clusters", () => {
    const embA = embedDocumentText("DDR5 memory bus interposer probe");
    const embB = embedDocumentText("TEE.fail DDR5 Riser Attack");
    const embUnrelated = embedDocumentText("Shamir 3-of-5 secret sharing RSA blind credit nullifier");

    expect(embA.dimensions).toBe(EMBEDDING_DIMENSIONS);
    expect(embA.vector).toHaveLength(128);

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

  it("ranks 'Kimi K3 8x GPU confidential enclave' and 'TEE.fail DDR5 memory bus' accurately using Reciprocal Rank Fusion", async () => {
    const kimiSearch = await runAtlasHybridSearch("Kimi K3 8x GPU confidential enclave");
    expect(kimiSearch.results.length).toBeGreaterThan(0);

    const topKimi = kimiSearch.results[0];
    expect(topKimi.docId).toBe("provider-tinfoil");
    expect(topKimi.vectorRank).toBeGreaterThanOrEqual(1);
    expect(topKimi.textRank).toBeGreaterThanOrEqual(1);
    const expectedKimiRrf = Number(
      (1 / (60 + topKimi.vectorRank) + 1 / (60 + topKimi.textRank)).toFixed(6)
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

  it("supports automatic embedding on ingest and real-time stream analytics aggregation", async () => {
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
      true
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
