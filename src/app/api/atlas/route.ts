import { connection, NextResponse } from "next/server";
import {
  ingestAtlasDocument,
  MAX_INGEST_DOCUMENT_BYTES,
  runAtlasHybridSearch,
  runAtlasStreamAnalytics,
} from "@/lib/atlas";

const ATLAS_FEATURES_USED = [
  "Atlas Search ($search)",
  "Atlas Vector Search ($vectorSearch)",
  "Hybrid Search ($rankFusion / RRF)",
  "Multi-Collection $facet Aggregation",
  "Agent Verification Receipts Store",
] as const;

export async function GET(request: Request) {
  await connection();

  const url = new URL(request.url);
  const q =
    url.searchParams.get("q")?.trim() ||
    "AMD SEV-SNP 8x GPU confidential mode TEE.fail mitigation";
  const category = url.searchParams.get("category")?.trim() || undefined;
  const limitParam = Number(url.searchParams.get("limit") ?? 10);
  const limit = Number.isFinite(limitParam) && limitParam > 0 ? limitParam : 10;

  const [search, analytics] = await Promise.all([
    runAtlasHybridSearch(q, { category, limit }),
    runAtlasStreamAnalytics(),
  ]);

  return NextResponse.json({
    query: search.query,
    engines: search.engines,
    results: search.results,
    matchingReceipts: search.matchingReceipts,
    search,
    analytics,
    featuresUsed: [...ATLAS_FEATURES_USED],
  });
}

export async function POST(request: Request) {
  let rawText: string;
  try {
    rawText = await request.text();
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  if (new TextEncoder().encode(rawText).byteLength > MAX_INGEST_DOCUMENT_BYTES * 2) {
    return NextResponse.json(
      { error: `Payload exceeds maximum size limit (${MAX_INGEST_DOCUMENT_BYTES} bytes)` },
      { status: 413 },
    );
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawText) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (body.action === "ingest") {
    const expectedToken = process.env.ATLAS_INGEST_TOKEN?.trim();
    if (!expectedToken) {
      return NextResponse.json(
        {
          error:
            "HTTP POST ingest is disabled because ATLAS_INGEST_TOKEN is not configured on the server.",
        },
        { status: 403 },
      );
    }

    const headerToken =
      request.headers.get("x-atlas-ingest-token")?.trim() ||
      request.headers
        .get("authorization")
        ?.replace(/^Bearer\s+/i, "")
        .trim();

    if (!headerToken || headerToken !== expectedToken) {
      return NextResponse.json(
        { error: "Unauthorized: valid X-Atlas-Ingest-Token header is required for ingest." },
        { status: 401 },
      );
    }

    if ("prompt" in body || "rawPrompt" in body || "taskPrompt" in body) {
      return NextResponse.json(
        { error: "Prompts are never stored in MongoDB Atlas." },
        { status: 400 },
      );
    }

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const summary = typeof body.summary === "string" ? body.summary.trim() : "";
    const category =
      typeof body.category === "string" && body.category.trim().length > 0
        ? body.category.trim()
        : "advisory";
    const tags = Array.isArray(body.tags)
      ? body.tags.filter((t): t is string => typeof t === "string" && t.trim().length > 0)
      : [];

    if (!title || !summary) {
      return NextResponse.json(
        { error: "Both title and summary are required for action: 'ingest'" },
        { status: 400 },
      );
    }

    let ingested;
    try {
      ingested = await ingestAtlasDocument({
        docId: typeof body.docId === "string" ? body.docId : undefined,
        title,
        summary,
        category,
        tags,
        metadata:
          typeof body.metadata === "object" && body.metadata !== null
            ? (body.metadata as Record<string, unknown>)
            : undefined,
      });
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : "Ingest rejected" },
        { status: 400 },
      );
    }

    const followUpQuery =
      typeof body.query === "string" && body.query.trim().length > 0
        ? body.query.trim()
        : `${title} ${tags.join(" ")}`.trim();

    const [search, analytics] = await Promise.all([
      runAtlasHybridSearch(followUpQuery),
      runAtlasStreamAnalytics(),
    ]);

    return NextResponse.json({
      ingested: ingested.document,
      storedInAtlas: ingested.storedInAtlas,
      query: search.query,
      engines: search.engines,
      results: search.results,
      matchingReceipts: search.matchingReceipts,
      search,
      analytics,
      featuresUsed: [...ATLAS_FEATURES_USED],
    });
  }

  const query =
    typeof body.query === "string" && body.query.trim().length > 0
      ? body.query.trim()
      : "AMD SEV-SNP 8x GPU confidential mode TEE.fail mitigation";
  const category = typeof body.category === "string" ? body.category.trim() : undefined;
  const limit = typeof body.limit === "number" && body.limit > 0 ? body.limit : 10;

  const [search, analytics] = await Promise.all([
    runAtlasHybridSearch(query, { category, limit }),
    runAtlasStreamAnalytics(),
  ]);

  return NextResponse.json({
    query: search.query,
    engines: search.engines,
    results: search.results,
    matchingReceipts: search.matchingReceipts,
    search,
    analytics,
    featuresUsed: [...ATLAS_FEATURES_USED],
  });
}
