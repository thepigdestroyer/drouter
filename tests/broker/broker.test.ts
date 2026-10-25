import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { renderToStaticMarkup } from "react-dom/server";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CORPUS_CACHE_CONTROL,
  GET as corpusGet,
  type PublicCorpusDocument,
  setCorpusCollectionForTests,
} from "@/app/api/knowledge/corpus/route";
import { POST as atlasPost } from "@/app/api/atlas/route";
import {
  ATLAS_DEVICE_ONLY_LABEL,
  ATLAS_PUBLIC_SEARCH_NOTICE,
  AtlasExplorer,
  executeAtlasExplorerSearch,
} from "@/components/atlas-explorer";
import { findForbiddenPlainTerms } from "@/components/argon/argon-helpers";
import { ATLAS_SEED_DOCS } from "@/lib/atlas";
import {
  clearCorpusCacheForTests,
  computeCorpusContentSha256,
  type CorpusDocument,
  fetchCorpus,
  LOOKUP_TOPICS,
  LookupIntentValidationError,
  rankLocally,
  seedCorpusCache,
  validateLookupIntent,
} from "@/lib/broker";
import { canonicalJson } from "@/lib/transparency/log";

const ROOT = resolve(__dirname, "../..");

afterEach(() => {
  setCorpusCollectionForTests(undefined);
  clearCorpusCacheForTests();
  vi.restoreAllMocks();
});

describe("W6-B Step 1: GET /api/knowledge/corpus route", () => {
  it("returns every public document in stable (title, sourceUrl) order with documentCount, contentSha256, Cache-Control, and ETag using an injected mock collection", async () => {
    const unorderedDocs = [
      {
        _id: "mongo-id-1",
        docId: "doc-z",
        title: "Zeta Enclave Architecture",
        category: "architecture",
        summary: "Summary for Zeta architecture.",
        tags: ["zeta", "enclave"],
        sourceUrl: "https://example.org/zeta",
        retrievedAt: "2026-10-24",
        embedding: [0.1, 0.2, 0.3],
        secretInternalField: "must-not-appear",
      },
      {
        _id: "mongo-id-2",
        docId: "doc-a2",
        title: "Alpha Hardware Advisory",
        category: "advisory",
        summary: "Second source for Alpha advisory.",
        tags: ["alpha", "ddr5"],
        sourceUrl: "https://example.org/alpha-b",
        retrievedAt: "2026-10-24",
        embedding: [0.4, 0.5, 0.6],
      },
      {
        _id: "mongo-id-3",
        docId: "doc-a1",
        title: "Alpha Hardware Advisory",
        category: "advisory",
        summary: "First source for Alpha advisory.",
        tags: ["alpha", "memory"],
        sourceUrl: "https://example.org/alpha-a",
        retrievedAt: "2026-10-24",
        embedding: [0.7, 0.8, 0.9],
      },
    ];

    setCorpusCollectionForTests({
      find: () => ({
        toArray: async () => unorderedDocs,
      }),
    });

    const req1 = new Request("http://localhost:3000/api/knowledge/corpus");
    const req2 = new Request("http://localhost:3000/api/knowledge/corpus", {
      headers: { "user-agent": "DifferentCaller/1.0" },
    });

    const [res1, res2] = await Promise.all([corpusGet(req1), corpusGet(req2)]);
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);

    expect(res1.headers.get("Cache-Control")).toBe(
      "public, max-age=300, s-maxage=3600, stale-while-revalidate=86400",
    );
    expect(CORPUS_CACHE_CONTROL).toBe(
      "public, max-age=300, s-maxage=3600, stale-while-revalidate=86400",
    );

    const body1 = (await res1.json()) as {
      database: string;
      collection: string;
      documentCount: number;
      contentSha256: string;
      documents: PublicCorpusDocument[];
    };
    const body2 = await res2.json();

    // Identical for every caller
    expect(body1).toEqual(body2);
    expect(body1.database).toBe("drouter");
    expect(body1.collection).toBe("enclave_intelligence");
    expect(body1.documentCount).toBe(3);
    expect(body1.documents).toHaveLength(3);

    // Stable order: by title, then sourceUrl
    expect(
      body1.documents.map((d) => `${d.title}::${d.sourceUrl}`),
    ).toEqual([
      "Alpha Hardware Advisory::https://example.org/alpha-a",
      "Alpha Hardware Advisory::https://example.org/alpha-b",
      "Zeta Enclave Architecture::https://example.org/zeta",
    ]);

    // Exact public document shape: only title, summary, tags, sourceUrl, retrievedAt, embedding
    for (const doc of body1.documents) {
      expect(Object.keys(doc).sort()).toEqual([
        "embedding",
        "retrievedAt",
        "sourceUrl",
        "summary",
        "tags",
        "title",
      ]);
    }

    // contentSha256 is hex sha256 of canonicalJson(documents)
    const expectedHash = bytesToHex(
      sha256(utf8ToBytes(canonicalJson(body1.documents))),
    );
    expect(body1.contentSha256).toBe(expectedHash);
    expect(res1.headers.get("ETag")).toBe(expectedHash);
  });

  it("returns HTTP 400 if the request URL has any query parameter", async () => {
    setCorpusCollectionForTests({
      find: () => ({
        toArray: async () => [],
      }),
    });

    const disallowedUrls = [
      "http://localhost:3000/api/knowledge/corpus?q=tdx",
      "http://localhost:3000/api/knowledge/corpus?topic=provider:tinfoil",
      "http://localhost:3000/api/knowledge/corpus?limit=5",
      "http://localhost:3000/api/knowledge/corpus?empty=",
      "http://localhost:3000/api/knowledge/corpus?",
    ];

    for (const url of disallowedUrls) {
      const res = await corpusGet(new Request(url));
      expect(res.status, `URL ${url} must be rejected with 400`).toBe(400);
    }
  });

  it("contains no export const dynamic or runtime in src/app/api/knowledge/corpus/route.ts", () => {
    const routeSource = readFileSync(
      resolve(ROOT, "src/app/api/knowledge/corpus/route.ts"),
      "utf8",
    );
    expect(routeSource).not.toMatch(/\bexport\s+const\s+dynamic\b/);
    expect(routeSource).not.toMatch(/\bexport\s+const\s+runtime\b/);
  });
});

describe("W6-B Step 2: Broker validateLookupIntent, fetchCorpus, and rankLocally", () => {
  it("accepts every valid { kind: 'topic', topic } in LOOKUP_TOPICS and rejects extra fields, free text, and unknown topics", () => {
    expect(LOOKUP_TOPICS.length).toBeGreaterThanOrEqual(20);
    for (const topic of LOOKUP_TOPICS) {
      const validated = validateLookupIntent({ kind: "topic", topic });
      expect(validated).toEqual({ kind: "topic", topic });
    }

    const adversarialInputs: unknown[] = [
      null,
      undefined,
      "provider:tinfoil",
      123,
      true,
      [],
      [{ kind: "topic", topic: "provider:tinfoil" }],
      {},
      { kind: "topic" },
      { topic: "provider:tinfoil" },
      { kind: "query", topic: "provider:tinfoil" },
      { kind: "search", topic: "provider:tinfoil" },
      { kind: "topic", topic: "" },
      { kind: "topic", topic: "unknown:topic" },
      { kind: "topic", topic: "provider:openai" },
      { kind: "topic", topic: "tinfoil_enclave" },
      { kind: "topic", topic: "PROVIDER:TINFOIL" },
      { kind: "topic", topic: " provider:tinfoil" },
      { kind: "topic", topic: "provider:tinfoil " },
      { kind: "topic", topic: "provider:tinfoil?q=secret" },
      {
        kind: "topic",
        topic: "Patient Alice Johnson oncology survival notes",
      },
      {
        kind: "topic",
        topic: "provider:tinfoil",
        extraField: "not-allowed",
      },
      {
        kind: "topic",
        topic: "provider:tinfoil",
        query: "free text",
      },
      {
        kind: "topic",
        topic: "provider:tinfoil",
        limit: 5,
      },
    ];

    for (const bad of adversarialInputs) {
      expect(
        () => validateLookupIntent(bad),
        `Adversarial intent ${JSON.stringify(bad)} must throw`,
      ).toThrow(LookupIntentValidationError);
    }

    // Reject symbol keys
    const withSymbol = {
      kind: "topic",
      topic: "provider:tinfoil",
      [Symbol("smuggled")]: "secret",
    };
    expect(() => validateLookupIntent(withSymbol)).toThrow(
      LookupIntentValidationError,
    );

    // Reject getter properties
    const withGetter: Record<string, unknown> = { kind: "topic" };
    Object.defineProperty(withGetter, "topic", {
      enumerable: true,
      get() {
        return "provider:tinfoil";
      },
    });
    expect(() => validateLookupIntent(withGetter)).toThrow(
      LookupIntentValidationError,
    );
  });

  it("fetches the corpus, verifies contentSha256 by recomputing it, caches per page load, and throws on hash mismatch", async () => {
    const sampleDocs: CorpusDocument[] = [
      {
        title: "Alpha Doc",
        summary: "Alpha summary about AMD SEV-SNP.",
        tags: ["amd sev-snp"],
        sourceUrl: "https://example.org/alpha",
        retrievedAt: "2026-10-24",
        embedding: [0.5, 0.5, 0.70710678],
      },
      {
        title: "Beta Doc",
        summary: "Beta summary about Intel TDX.",
        tags: ["intel tdx"],
        sourceUrl: "https://example.org/beta",
        retrievedAt: "2026-10-24",
        embedding: [0.6, 0.8, 0.0],
      },
    ];
    const validSha = computeCorpusContentSha256(sampleDocs);

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe("/api/knowledge/corpus");
      return new Response(
        JSON.stringify({
          database: "drouter",
          collection: "enclave_intelligence",
          documentCount: sampleDocs.length,
          contentSha256: validSha,
          documents: sampleDocs,
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const first = await fetchCorpus(fetchMock);
    const second = await fetchCorpus(fetchMock);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(first).toEqual(second);
    expect(first.contentSha256).toBe(validSha);
    expect(first.documentCount).toBe(2);
    expect(first.documents).toEqual(sampleDocs);

    // Tampered response must throw on contentSha256 mismatch
    const tamperedFetchMock = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          database: "drouter",
          collection: "enclave_intelligence",
          documentCount: sampleDocs.length,
          contentSha256: validSha,
          documents: [
            {
              ...sampleDocs[0],
              summary: "TAMPERED SUMMARY BY MITM",
            },
            sampleDocs[1],
          ],
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    await expect(fetchCorpus(tamperedFetchMock)).rejects.toThrow(
      /contentSha256 mismatch/i,
    );
  });

  it("ranks corpus documents deterministically with BM25 over title, summary, and tags with zero network calls", () => {
    const forbiddenFetch = vi.fn(() => {
      throw new Error("rankLocally must never perform network calls");
    });
    vi.stubGlobal("fetch", forbiddenFetch);

    const corpusDocs: CorpusDocument[] = ATLAS_SEED_DOCS.map((d) => ({
      title: d.title,
      summary: d.summary,
      tags: [...d.tags],
      sourceUrl: d.sourceUrl,
      retrievedAt: d.retrievedAt,
      embedding: [...d.embedding],
    }));

    const ddr5Ranked = rankLocally(
      "TEE.fail DDR5 memory bus interposer",
      corpusDocs,
      5,
    );
    expect(ddr5Ranked).toHaveLength(5);
    expect(ddr5Ranked[0].sourceUrl).toBe("https://tee.fail/");
    expect(ddr5Ranked[0].rank).toBe(1);
    expect(ddr5Ranked[0].score).toBeGreaterThan(ddr5Ranked[1].score);

    const voltRanked = rankLocally(
      "VoltPillager SVID voltage glitching fault injection",
      corpusDocs,
      3,
    );
    expect(voltRanked).toHaveLength(3);
    expect(voltRanked[0].title).toContain("VoltPillager");
    expect(voltRanked[0].rank).toBe(1);

    const blindRanked = rankLocally(
      "Chaumian RSA blind signature credit nullifier double-spend",
      corpusDocs,
    );
    expect(blindRanked).toHaveLength(5);
    expect(blindRanked[0].sourceUrl).toBe(
      "https://www.rfc-editor.org/rfc/rfc9474.html",
    );

    // Deterministic across repeated invocations
    const repeatRanked = rankLocally(
      "Chaumian RSA blind signature credit nullifier double-spend",
      corpusDocs,
    );
    expect(repeatRanked).toEqual(blindRanked);
    expect(forbiddenFetch).not.toHaveBeenCalled();
  });
});

describe("W6-B Step 3: AtlasExplorer browser redaction, device-only search, and plain copy", () => {
  it("only ever sends mechanicalRedact-filtered text to /api/atlas and never leaks raw PII in URL or body", async () => {
    const capturedCalls: Array<{ url: string; method: string; bodyText: string }> =
      [];

    const mockFetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? "GET";
        const bodyText = typeof init?.body === "string" ? init.body : "";
        capturedCalls.push({ url, method, bodyText });

        return new Response(
          JSON.stringify({
            query: "[REDACTED]",
            results: [],
            engines: {
              vectorSearch: "atlas",
              textSearch: "atlas",
              fusion: "$rankFusion",
              embedding: "nomic-embed-text (Tinfoil attested enclave)",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    ) as unknown as typeof fetch;

    const piiRichQuery =
      "Patient Alice Johnson (alice.johnson@hospital.org, phone +1 415-555-0199, " +
      "SSN 123-45-6789, 742 Evergreen Terrace, date 2026-04-12, case #984512, " +
      "key sk-live-9876543210abcdef, portal https://portal.hospital.org/p/4829) " +
      "asks about DDR5 memory bus interposer mitigation";

    await executeAtlasExplorerSearch({
      rawInputQuery: piiRichQuery,
      deviceOnly: false,
      fetchImpl: mockFetch,
    });

    expect(capturedCalls).toHaveLength(1);
    const call = capturedCalls[0];
    expect(call.url).toBe("/api/atlas");
    expect(call.method).toBe("POST");
    expect(call.bodyText.length).toBeGreaterThan(0);

    const parsedBody = JSON.parse(call.bodyText) as { query: string };
    expect(typeof parsedBody.query).toBe("string");
    expect(parsedBody.query).toContain("DDR5 memory bus interposer mitigation");

    for (const secretPii of [
      "Alice Johnson",
      "alice.johnson@hospital.org",
      "415-555-0199",
      "123-45-6789",
      "742 Evergreen Terrace",
      "2026-04-12",
      "984512",
      "sk-live-9876543210abcdef",
      "portal.hospital.org",
    ]) {
      expect(call.url).not.toContain(secretPii);
      expect(call.bodyText).not.toContain(secretPii);
      expect(parsedBody.query).not.toContain(secretPii);
    }

    expect(parsedBody.query).toMatch(/\[EMAIL_\d+\]/);
    expect(parsedBody.query).toMatch(/\[SECRET_\d+\]/);
  });

  it("ranks the downloaded corpus locally with rankLocally and sends nothing when 'Search on my device only' is enabled", async () => {
    const corpusDocs: CorpusDocument[] = ATLAS_SEED_DOCS.map((d) => ({
      title: d.title,
      summary: d.summary,
      tags: [...d.tags],
      sourceUrl: d.sourceUrl,
      retrievedAt: d.retrievedAt,
      embedding: [...d.embedding],
    }));

    seedCorpusCache({
      database: "drouter",
      collection: "enclave_intelligence",
      documentCount: corpusDocs.length,
      contentSha256: computeCorpusContentSha256(corpusDocs),
      documents: corpusDocs,
    });

    const networkSpy = vi.fn(() => {
      throw new Error(
        "Device-only search must not send any network request!",
      );
    }) as unknown as typeof fetch;

    const res = await executeAtlasExplorerSearch({
      rawInputQuery:
        "Patient Alice Johnson (alice@hospital.org) asks about TEE.fail DDR5 memory bus interposer",
      deviceOnly: true,
      fetchImpl: networkSpy,
    });

    expect(networkSpy).not.toHaveBeenCalled();
    expect(res.results.length).toBeGreaterThan(0);
    expect(res.results[0].docId).toBe("advisory-tee-fail-ddr5");
    expect(res.results[0].sourceUrl).toBe("https://tee.fail/");
    expect(res.search?.executionMode).toBe("device-only-bm25");
  });

  it("renders the required plain notice and 'Search on my device only' toggle without em-dashes or forbidden plain terms, and keeps server-side filter in /api/atlas", async () => {
    expect(ATLAS_PUBLIC_SEARCH_NOTICE).toBe(
      "This searches public reference material. What you type is filtered on your device before it reaches the database.",
    );
    expect(ATLAS_DEVICE_ONLY_LABEL).toBe("Search on my device only");

    const html = renderToStaticMarkup(React.createElement(AtlasExplorer));
    expect(html).toContain(ATLAS_PUBLIC_SEARCH_NOTICE);
    expect(html).toContain(ATLAS_DEVICE_ONLY_LABEL);
    expect(html).not.toMatch(/[\u2013\u2014]/);

    const explorerSource = readFileSync(
      resolve(ROOT, "src/components/atlas-explorer.tsx"),
      "utf8",
    );
    const withoutTechDetails = explorerSource.replace(
      /<TechDetails[\s\S]*?<\/TechDetails>/g,
      "",
    );
    const jsxTextNodes = Array.from(
      withoutTechDetails.matchAll(/>([^<>{}]+)</g),
    )
      .map((m) => m[1].trim())
      .filter((t) => t.length > 0);

    for (const nodeText of jsxTextNodes) {
      expect(findForbiddenPlainTerms(nodeText)).toEqual([]);
      expect(nodeText).not.toMatch(/[\u2013\u2014]/);
    }

    // Verify server-side filter remains in /api/atlas route
    const serverRes = await atlasPost(
      new Request("http://localhost:3000/api/atlas", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          query:
            "Contact Dana Reyes at dana.reyes@example.org with key sk-live-1234567890abcdef about Intel TDX",
        }),
      }),
    );
    expect(serverRes.status).toBe(200);
    const serverJson = (await serverRes.json()) as {
      query: string;
      totalRedactions: number;
    };
    expect(serverJson.totalRedactions).toBeGreaterThanOrEqual(2);
    expect(serverJson.query).not.toContain("dana.reyes@example.org");
    expect(serverJson.query).not.toContain("sk-live-1234567890abcdef");
  });
});
