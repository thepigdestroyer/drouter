import { afterEach, describe, expect, it } from "vitest";
import type { Db } from "mongodb";
import {
  ATLAS_SEED_DOCS,
  clearAtlasPrivacyCachesForTests,
  clearAtlasRuntimeStateForTests,
  clearEmbeddingCacheForTests,
  coarsenIsoToUtcHour,
  CORPUS_RETRIEVED_AT_UTC,
  cosineSimilarity,
  EMBEDDING_DIMENSIONS,
  embedBatchWithProvider,
  embedDocumentText,
  embedDocumentTextWithProvider,
  ingestAtlasDocument,
  LOCAL_STANDIN_EMBEDDING_MODEL,
  recordAgentVerificationReceipt,
  runAtlasHybridSearch,
  runAtlasStreamAnalytics,
  searchAgentVerificationReceipts,
  setAtlasAttestedPiiFilterForTests,
  setAtlasDbForTests,
  setAtlasMechanicalRedactorForTests,
  setTinfoilEmbeddingHandlerForTests,
  TINFOIL_ATTESTED_EMBEDDING_MODEL,
} from "@/lib/atlas";
import { GET as atlasGet, POST as atlasPost } from "@/app/api/atlas/route";

afterEach(() => {
  setTinfoilEmbeddingHandlerForTests(null);
  setAtlasDbForTests(undefined);
  setAtlasMechanicalRedactorForTests(null);
  setAtlasAttestedPiiFilterForTests(null);
  clearEmbeddingCacheForTests();
  clearAtlasPrivacyCachesForTests();
  clearAtlasRuntimeStateForTests();
});

describe("MongoDB Atlas Enclave Intelligence, D3/D4 Query Redaction & Hybrid Search", () => {
  it("produces 768-dim unit-normalized fallback vectors clearly labelled with fallbackUsed=true when Tinfoil is unreachable", () => {
    const embA = embedDocumentText("DDR5 memory bus interposer probe");
    const embB = embedDocumentText("TEE.fail DDR5 Riser Attack");
    const embUnrelated = embedDocumentText("Shamir 3-of-5 secret sharing RSA blind credit nullifier");

    expect(EMBEDDING_DIMENSIONS).toBe(768);
    expect(embA.dimensions).toBe(768);
    expect(embA.vector).toHaveLength(768);
    expect(embA.model).toBe(LOCAL_STANDIN_EMBEDDING_MODEL);
    expect(embA.isLiveModel).toBe(false);
    expect(embA.attestedEnclave).toBe(false);
    expect(embA.fallbackUsed).toBe(true);
    expect(embA.fallbackReason).toMatch(/Tinfoil/i);

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

  it("embeds batches and queries through Tinfoil's attested nomic-embed-text enclave and keys cache by SHA-256 digest without storing query text", async () => {
    let callCount = 0;
    setTinfoilEmbeddingHandlerForTests(async (texts) => {
      callCount += 1;
      return {
        vectors: texts.map((t) => embedDocumentText(t).vector),
        model: TINFOIL_ATTESTED_EMBEDDING_MODEL,
        enclaveHost: "router-0.tinfoil.sh",
      };
    });

    const sampleQuery = "AMD SEV-SNP router and Intel TDX model enclave";
    const batch = await embedBatchWithProvider([
      sampleQuery,
      "TEE.fail DDR5 memory bus interposer",
    ]);
    expect(callCount).toBe(1);
    expect(batch).toHaveLength(2);
    expect(batch[0].model).toBe(TINFOIL_ATTESTED_EMBEDDING_MODEL);
    expect(batch[0].dimensions).toBe(768);
    expect(batch[0].isLiveModel).toBe(true);
    expect(batch[0].attestedEnclave).toBe(true);
    expect(batch[0].fallbackUsed).toBe(false);
    expect(batch[0].vector).toHaveLength(768);

    // Verify in-memory cache keys are 64-char SHA-256 hex digests, never raw text
    const rawCache = (
      globalThis as unknown as { __drouterLiveEmbeddingCache?: Map<string, unknown> }
    ).__drouterLiveEmbeddingCache;
    expect(rawCache).toBeDefined();
    for (const key of rawCache!.keys()) {
      expect(key).toMatch(/^[0-9a-f]{64}$/);
      expect(key).not.toContain("AMD");
    }

    // Second call for an already-embedded string hits digest cache without network
    const cachedSingle = await embedDocumentTextWithProvider(sampleQuery);
    expect(callCount).toBe(1);
    expect(cachedSingle.model).toBe(TINFOIL_ATTESTED_EMBEDDING_MODEL);
    expect(cachedSingle.isLiveModel).toBe(true);
  });

  it("curates all 16 real, sourced seed documents with verified sourceUrl, retrievedAt UTC date, and zero fabricated advisories", () => {
    expect(ATLAS_SEED_DOCS).toHaveLength(16);

    const providers = ATLAS_SEED_DOCS.filter((d) => d.category === "provider");
    const advisories = ATLAS_SEED_DOCS.filter((d) => d.category === "advisory");
    const architecture = ATLAS_SEED_DOCS.filter((d) => d.category === "architecture");

    expect(providers).toHaveLength(10);
    expect(advisories).toHaveLength(4);
    expect(architecture).toHaveLength(2);

    for (const doc of ATLAS_SEED_DOCS) {
      expect(doc.embedding).toHaveLength(768);
      expect(doc.embeddingDimensions).toBe(768);
      expect(doc.sourceUrl).toMatch(/^https:\/\//);
      expect(doc.retrievedAt).toBe(CORPUS_RETRIEVED_AT_UTC);
      expect(doc.metadata.sourceUrl).toBe(doc.sourceUrl);
      expect(doc.metadata.retrievedAt).toBe(CORPUS_RETRIEVED_AT_UTC);
      expect(JSON.stringify(doc)).not.toContain("DROUTER-ADV-");
      expect(doc.summary).not.toMatch(/[\u2013\u2014]/);

      const norm = Math.sqrt(doc.embedding.reduce((acc, v) => acc + v * v, 0));
      expect(norm).toBeCloseTo(1.0, 5);
    }
  });

  it("redacts every query leaving the enclave boundary for MongoDB via D3 (mechanicalRedact) and D4 (attestedPiiFilter), never sends plaintext PII to $search, and reports counts and filters", async () => {
    const capturedPipelines: Array<Array<Record<string, unknown>>> = [];
    const teeFailDoc = ATLAS_SEED_DOCS.find((d) => d.docId === "advisory-tee-fail-ddr5")!;

    const mockCol = {
      createIndex: async () => "ok",
      createSearchIndex: async () => "ok",
      deleteMany: async () => ({ deletedCount: 0 }),
      listSearchIndexes: () => ({
        toArray: async () => [
          { name: "drouter_text_search", type: "search", status: "READY" },
          {
            name: "drouter_vector_index",
            type: "vectorSearch",
            status: "READY",
            latestDefinition: { fields: [{ numDimensions: 768 }] },
          },
        ],
      }),
      find: () => ({
        toArray: async () =>
          ATLAS_SEED_DOCS.map((d) => ({
            ...d,
            embeddingModel: TINFOIL_ATTESTED_EMBEDDING_MODEL,
          })),
        sort: () => ({
          limit: () => ({
            toArray: async () => [],
          }),
        }),
      }),
      bulkWrite: async () => ({ upsertedCount: 0, modifiedCount: 0 }),
      aggregate: (pipeline: Array<Record<string, unknown>>) => {
        capturedPipelines.push(pipeline);
        return {
          toArray: async () => {
            const firstStage = pipeline[0] ?? {};
            if ("$rankFusion" in firstStage) {
              return [
                {
                  ...teeFailDoc,
                  embeddingModel: TINFOIL_ATTESTED_EMBEDDING_MODEL,
                  scoreDetails: {
                    value: 2 / 61,
                    details: [
                      { inputPipelineName: "vectorPipeline", rank: 1, value: 0.96 },
                      { inputPipelineName: "textPipeline", rank: 1, value: 8.4 },
                    ],
                  },
                },
              ];
            }
            if ("$vectorSearch" in firstStage) {
              return [{ docId: teeFailDoc.docId, score: 0.96 }];
            }
            if ("$search" in firstStage) {
              return [{ docId: teeFailDoc.docId, score: 8.4 }];
            }
            return [];
          },
        };
      },
    };

    setAtlasDbForTests({
      collection: () => mockCol,
    } as unknown as Db);

    const sensitiveQuery =
      "Patient Alice Johnson (alice.johnson@hospital.org, phone +1 415-555-0199, IP 192.168.10.42, " +
      "SSN 123-45-6789, 742 Evergreen Terrace, date 2026-04-12, case #984512, key sk-live-9876543210abcdef, " +
      "portal https://portal.hospital.org/p/4829) asks about TEE.fail DDR5 memory bus";

    // 1. D3-only fallback when D4 (attestedPiiFilter) is unavailable
    const d3OnlyRes = await runAtlasHybridSearch(sensitiveQuery);
    expect(d3OnlyRes.filterRan).toBe("mechanical-only");
    expect(d3OnlyRes.redaction.filterRan).toBe("mechanical-only");
    expect(d3OnlyRes.redaction.filtersApplied).toEqual(["mechanical"]);
    expect(d3OnlyRes.redaction.attested.ran).toBe(false);
    expect(d3OnlyRes.redaction.attested.fallbackToMechanicalOnly).toBe(true);
    expect(d3OnlyRes.totalRedactions).toBeGreaterThanOrEqual(8);

    const serializedResponse = JSON.stringify(d3OnlyRes);
    const serializedPipelines = JSON.stringify(capturedPipelines);
    for (const forbiddenPii of [
      "Alice Johnson",
      "alice.johnson@hospital.org",
      "415-555-0199",
      "192.168.10.42",
      "123-45-6789",
      "742 Evergreen Terrace",
      "2026-04-12",
      "984512",
      "sk-live-9876543210abcdef",
      "portal.hospital.org",
    ]) {
      expect(d3OnlyRes.query).not.toContain(forbiddenPii);
      expect(serializedResponse).not.toContain(forbiddenPii);
      expect(serializedPipelines).not.toContain(forbiddenPii);
    }

    // 2. D3 + D4 (attestedPiiFilter) when attested enclave filter is available
    capturedPipelines.length = 0;
    setAtlasAttestedPiiFilterForTests(async (d3Text) => ({
      text: d3Text.replace(/\bSt\.?\s+Jude\b/gi, "[ATTESTED_ORG_1]"),
      redactionCount: 1,
      model: "pii-filter",
      verified: true,
    }));

    const d3AndD4Res = await runAtlasHybridSearch(
      `${sensitiveQuery} at St. Jude wing`,
    );
    expect(d3AndD4Res.filterRan).toBe("mechanical+attested");
    expect(d3AndD4Res.redaction.filterRan).toBe("mechanical+attested");
    expect(d3AndD4Res.redaction.filtersApplied).toEqual([
      "mechanical",
      "attested-pii-filter",
    ]);
    expect(d3AndD4Res.redaction.attested.ran).toBe(true);
    expect(d3AndD4Res.redaction.attested.verified).toBe(true);
    expect(d3AndD4Res.redaction.attested.model).toBe("pii-filter");
    expect(d3AndD4Res.redaction.attested.redactionCount).toBe(1);
    expect(d3AndD4Res.redaction.attested.fallbackToMechanicalOnly).toBe(false);
    expect(d3AndD4Res.redactionCounts.ATTESTED_PII).toBe(1);
    expect(d3AndD4Res.query).not.toContain("St. Jude");
    expect(JSON.stringify(capturedPipelines)).not.toContain("St. Jude");

    // 3. Verify GET /api/atlas and POST /api/atlas expose redaction counts and filterRan
    const getReq = new Request(
      `http://localhost:3000/api/atlas?q=${encodeURIComponent(sensitiveQuery)}`,
    );
    const getHttpRes = await atlasGet(getReq);
    expect(getHttpRes.status).toBe(200);
    const getBody = (await getHttpRes.json()) as Record<string, unknown>;
    expect(getBody.filterRan).toBe("mechanical+attested");
    expect(typeof getBody.totalRedactions).toBe("number");
    expect((getBody.totalRedactions as number) >= 8).toBe(true);
    expect(JSON.stringify(getBody)).not.toContain("alice.johnson@hospital.org");

    const postReq = new Request("http://localhost:3000/api/atlas", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        query: `${sensitiveQuery} at St. Jude wing`,
        customTerms: ["Project Nightfall"],
      }),
    });
    const postHttpRes = await atlasPost(postReq);
    expect(postHttpRes.status).toBe(200);
    const postBody = (await postHttpRes.json()) as Record<string, unknown>;
    expect(postBody.filterRan).toBe("mechanical+attested");
    expect((postBody.totalRedactions as number) >= 9).toBe(true);
    expect(JSON.stringify(postBody)).not.toContain("St. Jude");
  });

  it("ranks queries accurately using Reciprocal Rank Fusion and reports engines truthfully in both attested-enclave and fallback modes", async () => {
    // 1. Fallback mode when Tinfoil is unreachable in unit test env
    const fallbackSearch = await runAtlasHybridSearch("Kimi K3 8x GPU confidential enclave");
    expect(fallbackSearch.results.length).toBeGreaterThan(0);
    expect(fallbackSearch.embeddingFallbackUsed).toBe(true);
    expect(fallbackSearch.engines.vectorSearch).toBe("app-fallback");
    expect(fallbackSearch.engines.textSearch).toBe("app-fallback");
    expect(fallbackSearch.engines.fusion).toBe("app-rrf");
    expect(fallbackSearch.engines.embedding).toBe(LOCAL_STANDIN_EMBEDDING_MODEL);

    const topKimi = fallbackSearch.results[0];
    expect(topKimi.docId).toBe("provider-tinfoil");
    expect(topKimi.sourceUrl).toBe("https://confidentialinference.net/providers/tinfoil");
    expect(topKimi.retrievedAt).toBe(CORPUS_RETRIEVED_AT_UTC);
    const expectedKimiRrf = Number(
      (1 / (60 + topKimi.vectorRank) + 1 / (60 + topKimi.textRank)).toFixed(6),
    );
    expect(topKimi.rrfScore).toBeCloseTo(expectedKimiRrf, 5);

    // 2. Mocked attested Tinfoil embedding + mocked Atlas native $rankFusion/$vectorSearch/$search
    setTinfoilEmbeddingHandlerForTests(async (texts) => ({
      vectors: texts.map((t) => embedDocumentText(t).vector),
      model: TINFOIL_ATTESTED_EMBEDDING_MODEL,
      enclaveHost: "router-0.tinfoil.sh",
    }));

    const teeFailDoc = ATLAS_SEED_DOCS.find((d) => d.docId === "advisory-tee-fail-ddr5")!;
    const mockCol = {
      createIndex: async () => "ok",
      createSearchIndex: async () => "ok",
      deleteMany: async () => ({ deletedCount: 0 }),
      listSearchIndexes: () => ({
        toArray: async () => [
          { name: "drouter_text_search", type: "search", status: "READY" },
          {
            name: "drouter_vector_index",
            type: "vectorSearch",
            status: "READY",
            latestDefinition: { fields: [{ numDimensions: 768 }] },
          },
        ],
      }),
      find: () => ({
        toArray: async () =>
          ATLAS_SEED_DOCS.map((d) => ({
            ...d,
            embeddingModel: TINFOIL_ATTESTED_EMBEDDING_MODEL,
          })),
        sort: () => ({
          limit: () => ({
            toArray: async () => [],
          }),
        }),
      }),
      bulkWrite: async () => ({ upsertedCount: 0, modifiedCount: 0 }),
      aggregate: (pipeline: Array<Record<string, unknown>>) => ({
        toArray: async () => {
          const firstStage = pipeline[0] ?? {};
          if ("$rankFusion" in firstStage) {
            return [
              {
                ...teeFailDoc,
                embeddingModel: TINFOIL_ATTESTED_EMBEDDING_MODEL,
                scoreDetails: {
                  value: 2 / 61,
                  details: [
                    { inputPipelineName: "vectorPipeline", rank: 1, value: 0.96 },
                    { inputPipelineName: "textPipeline", rank: 1, value: 8.4 },
                  ],
                },
              },
            ];
          }
          if ("$vectorSearch" in firstStage) {
            return [{ docId: teeFailDoc.docId, score: 0.96 }];
          }
          if ("$search" in firstStage) {
            return [{ docId: teeFailDoc.docId, score: 8.4 }];
          }
          return [];
        },
      }),
    };

    setAtlasDbForTests({
      collection: () => mockCol,
    } as unknown as Db);

    const teeFailSearch = await runAtlasHybridSearch("TEE.fail DDR5 memory bus");
    expect(teeFailSearch.executionMode).toBe("atlas-hybrid-rrf");
    expect(teeFailSearch.embeddingFallbackUsed).toBe(false);
    expect(teeFailSearch.engines).toEqual({
      vectorSearch: "atlas",
      textSearch: "atlas",
      fusion: "$rankFusion",
      embedding: TINFOIL_ATTESTED_EMBEDDING_MODEL,
    });

    const topTeeFail = teeFailSearch.results[0];
    expect(topTeeFail.docId).toBe("advisory-tee-fail-ddr5");
    expect(topTeeFail.sourceUrl).toBe("https://tee.fail/");
    expect(topTeeFail.vectorRank).toBe(1);
    expect(topTeeFail.textRank).toBe(1);
    expect(topTeeFail.rrfScore).toBeCloseTo(2 / 61, 5);
  });

  it("stores and searches live agent verification receipts with coarsened UTC-hour timestamps, zero PII, and rejects simulated receipts", async () => {
    const coarsened = coarsenIsoToUtcHour("2026-10-24T16:42:19.831Z");
    expect(coarsened).toBe("2026-10-24T16:00:00.000Z");

    await expect(
      recordAgentVerificationReceipt({
        receiptId: "sim-receipt-rejected",
        timestampIso: "2026-10-24T16:42:19.831Z",
        mode: "simulated",
        primaryModel: "gemini-4-argon",
        enclaveModel: "kimi-k3",
        routerHost: "router-0.tinfoil.sh",
        enclaveHost: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
        overallPassed: true,
        faultInjected: false,
        selfHealed: false,
        humanGateState: "paused_awaiting_human",
        checksSummary: [{ id: "C1", passed: true }],
        forensicProofDigestHex: "a".repeat(64),
        ed25519SignatureHex: "b".repeat(128),
        signerPublicKeyHex: "c".repeat(64),
      }),
    ).rejects.toThrow(/Simulated agent verification receipts must not be stored/i);

    const recorded = await recordAgentVerificationReceipt({
      receiptId: "argon-run-live-receipt-ab",
      timestampIso: "2026-10-24T16:42:19.831Z",
      mode: "live",
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

    expect(recorded.receipt.mode).toBe("live");
    expect(recorded.receipt.coarsenedAt).toBe("2026-10-24T16:00:00.000Z");
    expect(recorded.receipt.embedding).toHaveLength(768);
    expect(recorded.receipt.embeddingDimensions).toBe(768);

    const foundReceipts = await searchAgentVerificationReceipts("kimi-k3-inf14", 5);
    expect(foundReceipts.some((r) => r.receiptId === "argon-run-live-receipt-ab")).toBe(true);

    const hybridWithReceipts = await runAtlasHybridSearch("kimi-k3-inf14");
    expect(
      hybridWithReceipts.matchingReceipts.some((r) => r.receiptId === "argon-run-live-receipt-ab"),
    ).toBe(true);
  });

  it("gates HTTP POST ingest with ATLAS_INGEST_TOKEN, caps document size, and rejects user text and prompts", async () => {
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
        title: "Test User Text Leak",
        summary: "Summary text",
        category: "advisory",
        userText: "secret user message",
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

      process.env.ATLAS_INGEST_TOKEN = "test-ingest-token-secret-2026";
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

  it("supports 768-d embedding on ingest with D3/D4 PII redaction and multi-collection $facet aggregation", async () => {
    setTinfoilEmbeddingHandlerForTests(async (texts) => ({
      vectors: texts.map((t) => embedDocumentText(t).vector),
      model: TINFOIL_ATTESTED_EMBEDDING_MODEL,
      enclaveHost: "router-0.tinfoil.sh",
    }));

    const ingested = await ingestAtlasDocument({
      docId: "advisory-custom-cxl-probe",
      title: "CXL 3.0 SEV-TIO Fabric Link Replay Test",
      summary:
        "Evaluates CXL 3.0 IDE link encryption counters between AMD Turin SEV-SNP host and NVIDIA B200 HBM3e confidential memory. Contact Dr. Jane Smith at security@example.com or 192.168.1.99 for details.",
      category: "advisory",
      sourceUrl: "https://www.amd.com/en/developer/sev.html",
      retrievedAt: CORPUS_RETRIEVED_AT_UTC,
      tags: ["cxl 3.0", "sev-tio", "b200", "ide"],
    });

    expect(ingested.document.embedding).toHaveLength(768);
    expect(ingested.document.embeddingDimensions).toBe(768);
    expect(ingested.document.embeddingModel).toBe(TINFOIL_ATTESTED_EMBEDDING_MODEL);
    expect(ingested.document.sourceUrl).toBe("https://www.amd.com/en/developer/sev.html");
    expect(ingested.document.retrievedAt).toBe(CORPUS_RETRIEVED_AT_UTC);
    expect(ingested.document.summary).not.toContain("security@example.com");
    expect(ingested.document.summary).not.toContain("Jane Smith");
    expect(ingested.document.summary).not.toContain("192.168.1.99");
    expect(ingested.redaction.totalRedactions).toBeGreaterThanOrEqual(3);

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
  });
});
