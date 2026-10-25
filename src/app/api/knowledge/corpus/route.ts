import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection, NextResponse } from "next/server";
import {
  ATLAS_COLLECTION_NAME,
  ATLAS_CORPUS_DB_NAME,
  ATLAS_SEED_DOCS,
  CORPUS_RETRIEVED_AT_UTC,
  getAtlasDb,
} from "@/lib/atlas";
import { canonicalJson } from "@/lib/transparency/log";

export const CORPUS_CACHE_CONTROL =
  "public, max-age=300, s-maxage=3600, stale-while-revalidate=86400";

export interface PublicCorpusDocument {
  title: string;
  summary: string;
  tags: string[];
  sourceUrl: string;
  retrievedAt: string;
  embedding: number[];
}

export interface PublicCorpusResponse {
  database: string;
  collection: string;
  documentCount: number;
  contentSha256: string;
  documents: PublicCorpusDocument[];
}

export interface CorpusCollectionLike {
  find(
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ):
    | {
        toArray(): Promise<unknown[]> | unknown[];
      }
    | Promise<unknown[]>
    | unknown[];
}

const globalForCorpusRoute = globalThis as unknown as {
  __drouterTestCorpusCollection?: CorpusCollectionLike | null;
};

/**
 * Injects a mock collection for unit tests so `/api/knowledge/corpus` can be tested
 * deterministically without live MongoDB credentials.
 */
export function setCorpusCollectionForTests(
  collection: CorpusCollectionLike | null | undefined,
): void {
  globalForCorpusRoute.__drouterTestCorpusCollection = collection;
}

function normalizePublicCorpusDocument(raw: unknown): PublicCorpusDocument | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const rec = raw as Record<string, unknown>;
  const metadata =
    typeof rec.metadata === "object" && rec.metadata !== null
      ? (rec.metadata as Record<string, unknown>)
      : undefined;

  const title = typeof rec.title === "string" ? rec.title.trim() : "";
  const summary = typeof rec.summary === "string" ? rec.summary.trim() : "";
  if (!title || !summary) {
    return null;
  }

  const sourceUrl =
    (typeof rec.sourceUrl === "string" && rec.sourceUrl.trim()) ||
    (typeof metadata?.sourceUrl === "string" && metadata.sourceUrl.trim()) ||
    (typeof metadata?.docsUrl === "string" && metadata.docsUrl.trim()) ||
    (typeof metadata?.url === "string" && metadata.url.trim()) ||
    "";

  const retrievedAt =
    (typeof rec.retrievedAt === "string" && rec.retrievedAt.trim()) ||
    (typeof metadata?.retrievedAt === "string" && metadata.retrievedAt.trim()) ||
    CORPUS_RETRIEVED_AT_UTC;

  const tags = Array.isArray(rec.tags)
    ? rec.tags
        .filter((t): t is string => typeof t === "string" && t.trim().length > 0)
        .map((t) => t.trim())
    : [];

  const embedding = Array.isArray(rec.embedding)
    ? rec.embedding.filter(
        (n): n is number => typeof n === "number" && Number.isFinite(n),
      )
    : [];

  return {
    title,
    summary,
    tags,
    sourceUrl,
    retrievedAt,
    embedding,
  };
}

export function sortCorpusDocuments(
  docs: readonly PublicCorpusDocument[],
): PublicCorpusDocument[] {
  return [...docs].sort((a, b) => {
    const byTitle = a.title.localeCompare(b.title);
    if (byTitle !== 0) return byTitle;
    const byUrl = a.sourceUrl.localeCompare(b.sourceUrl);
    if (byUrl !== 0) return byUrl;
    return a.summary.localeCompare(b.summary);
  });
}

export function computeCorpusSha256Hex(
  documents: readonly PublicCorpusDocument[],
): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalJson(documents))));
}

async function readDocsFromCollection(
  col: CorpusCollectionLike,
): Promise<PublicCorpusDocument[]> {
  const cursorOrDocs = await col.find(
    {},
    {
      projection: {
        _id: 0,
        title: 1,
        summary: 1,
        tags: 1,
        sourceUrl: 1,
        retrievedAt: 1,
        embedding: 1,
        metadata: 1,
      },
    },
  );

  let rawDocs: unknown[];
  if (Array.isArray(cursorOrDocs)) {
    rawDocs = cursorOrDocs;
  } else if (
    cursorOrDocs &&
    typeof cursorOrDocs === "object" &&
    typeof (cursorOrDocs as { toArray?: unknown }).toArray === "function"
  ) {
    rawDocs = await (cursorOrDocs as { toArray(): Promise<unknown[]> }).toArray();
  } else {
    rawDocs = [];
  }

  const normalized: PublicCorpusDocument[] = [];
  for (const item of rawDocs) {
    const doc = normalizePublicCorpusDocument(item);
    if (doc) {
      normalized.push(doc);
    }
  }
  return normalized;
}

export async function loadPublicCorpus(
  injectedCollection?: CorpusCollectionLike | null,
): Promise<PublicCorpusResponse> {
  const effectiveInjected =
    injectedCollection !== undefined
      ? injectedCollection
      : globalForCorpusRoute.__drouterTestCorpusCollection;

  let docs: PublicCorpusDocument[] | null = null;

  if (effectiveInjected) {
    docs = await readDocsFromCollection(effectiveInjected);
  } else {
    const db = await getAtlasDb();
    if (db && ATLAS_CORPUS_DB_NAME === "drouter") {
      try {
        const col = db.collection(
          ATLAS_COLLECTION_NAME,
        ) as unknown as CorpusCollectionLike;
        const fromDb = await readDocsFromCollection(col);
        if (fromDb.length > 0) {
          docs = fromDb;
        }
      } catch {
        docs = null;
      }
    }
  }

  if (!docs) {
    docs = ATLAS_SEED_DOCS.map((seed) => ({
      title: seed.title,
      summary: seed.summary,
      tags: [...seed.tags],
      sourceUrl: seed.sourceUrl,
      retrievedAt: seed.retrievedAt,
      embedding: [...seed.embedding],
    }));
  }

  const documents = sortCorpusDocuments(docs);
  const contentSha256 = computeCorpusSha256Hex(documents);

  return {
    database: ATLAS_CORPUS_DB_NAME,
    collection: ATLAS_COLLECTION_NAME,
    documentCount: documents.length,
    contentSha256,
    documents,
  };
}

export async function GET(request: Request) {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next.js AsyncLocalStorage request store
  }

  const rawUrl = request.url || "http://localhost/api/knowledge/corpus";
  const url = new URL(rawUrl, "http://localhost");
  if (
    rawUrl.includes("?") ||
    url.search.length > 0 ||
    Array.from(url.searchParams.keys()).length > 0
  ) {
    return NextResponse.json(
      {
        error:
          "Query parameters are not allowed on /api/knowledge/corpus. Every caller receives the identical public corpus.",
      },
      { status: 400 },
    );
  }

  const payload = await loadPublicCorpus();

  return NextResponse.json(payload, {
    status: 200,
    headers: {
      "Cache-Control": CORPUS_CACHE_CONTROL,
      ETag: payload.contentSha256,
    },
  });
}
