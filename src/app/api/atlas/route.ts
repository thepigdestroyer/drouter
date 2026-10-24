import { connection, NextResponse } from "next/server";
import {
  ingestAtlasDocument,
  runAtlasHybridSearch,
  runAtlasStreamAnalytics,
} from "@/lib/atlas";

const ATLAS_FEATURES_USED = [
  "Atlas Search ($search)",
  "Atlas Vector Search ($vectorSearch)",
  "Hybrid Search (Reciprocal Rank Fusion)",
  "Automated Embedding Pipeline (128-d + Voyage/Nomic)",
  "Real-Time Aggregation & Stream Analytics",
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
    results: search.results,
    search,
    analytics,
    featuresUsed: [...ATLAS_FEATURES_USED],
  });
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (body.action === "ingest") {
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
        { status: 400 }
      );
    }

    const ingested = await ingestAtlasDocument({
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
      results: search.results,
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
    results: search.results,
    search,
    analytics,
    featuresUsed: [...ATLAS_FEATURES_USED],
  });
}
