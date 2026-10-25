import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { canonicalJson } from "@/lib/transparency/log";
import {
  LOOKUP_TOPICS,
  LookupIntentValidationError,
  type LookupIntent,
  type LookupTopic,
  validateLookupIntent,
} from "./vocabulary";

export {
  LOOKUP_TOPICS,
  LookupIntentValidationError,
  type LookupIntent,
  type LookupTopic,
  validateLookupIntent,
};

export interface CorpusDocument {
  title: string;
  summary: string;
  tags: string[];
  sourceUrl: string;
  retrievedAt: string;
  embedding: number[];
}

export interface CorpusResponse {
  database?: string;
  collection?: string;
  documentCount: number;
  contentSha256: string;
  documents: CorpusDocument[];
}

export type CorpusInput =
  | readonly CorpusDocument[]
  | { readonly documents: readonly CorpusDocument[] };

export interface RankedCorpusDocument extends CorpusDocument {
  score: number;
  bm25Score: number;
  rank: number;
}

/**
 * Deterministic UTF-16 code-unit string comparison (locale-independent across all JS runtimes).
 */
export function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Total canonical ordering for public corpus documents using UTF-16 code-unit comparison
 * over `title`, `sourceUrl`, `summary`, `retrievedAt`, and finally `canonicalJson` as a
 * deterministic tie-breaker.
 */
export function compareCorpusDocuments(
  a: CorpusDocument,
  b: CorpusDocument,
): number {
  const byTitle = compareCodeUnits(a.title, b.title);
  if (byTitle !== 0) return byTitle;
  const byUrl = compareCodeUnits(a.sourceUrl, b.sourceUrl);
  if (byUrl !== 0) return byUrl;
  const bySummary = compareCodeUnits(a.summary, b.summary);
  if (bySummary !== 0) return bySummary;
  const byRetrievedAt = compareCodeUnits(a.retrievedAt, b.retrievedAt);
  if (byRetrievedAt !== 0) return byRetrievedAt;
  return compareCodeUnits(canonicalJson(a), canonicalJson(b));
}

/**
 * Returns a new array of corpus documents sorted in canonical code-unit order.
 */
export function sortCorpusDocuments<T extends CorpusDocument>(
  docs: readonly T[],
): T[] {
  return [...docs].sort(compareCorpusDocuments);
}

/**
 * Recomputes the hex SHA-256 of `canonicalJson(sortCorpusDocuments(documents))` (browser-safe).
 */
export function computeCorpusContentSha256(
  documents: readonly CorpusDocument[],
): string {
  const canonicalDocs = sortCorpusDocuments(
    documents.map((d) => ({
      title: d.title,
      summary: d.summary,
      tags: [...d.tags],
      sourceUrl: d.sourceUrl,
      retrievedAt: d.retrievedAt,
      embedding: [...d.embedding],
    })),
  );
  return bytesToHex(sha256(utf8ToBytes(canonicalJson(canonicalDocs))));
}

let cachedCorpusValue: CorpusResponse | null = null;
let cachedCorpusPromise: Promise<CorpusResponse> | null = null;
let cachedFetchRef: typeof fetch | undefined = undefined;

export function getCachedCorpus(): CorpusResponse | null {
  return cachedCorpusValue;
}

export function seedCorpusCache(corpus: CorpusResponse): void {
  const sortedDocs = sortCorpusDocuments(
    corpus.documents.map((d) => ({
      title: d.title,
      summary: d.summary,
      tags: [...d.tags],
      sourceUrl: d.sourceUrl,
      retrievedAt: d.retrievedAt,
      embedding: [...d.embedding],
    })),
  );
  const recomputed = computeCorpusContentSha256(sortedDocs);
  const expected = (corpus.contentSha256 || "").replace(/^0x/i, "").toLowerCase();
  if (!expected || expected !== recomputed.toLowerCase()) {
    throw new Error(
      `Corpus contentSha256 mismatch: expected ${corpus.contentSha256}, recomputed ${recomputed}`,
    );
  }
  const normalized: CorpusResponse = {
    ...corpus,
    documentCount: sortedDocs.length,
    contentSha256: recomputed,
    documents: sortedDocs,
  };
  cachedCorpusValue = normalized;
  cachedCorpusPromise = Promise.resolve(normalized);
}

export function clearCorpusCache(): void {
  cachedCorpusValue = null;
  cachedCorpusPromise = null;
  cachedFetchRef = undefined;
}

export const clearCorpusCacheForTests = clearCorpusCache;

function validateAndNormalizeCorpusDoc(
  raw: unknown,
  idx: number,
): CorpusDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`Invalid corpus document at index ${idx}: expected object.`);
  }
  const rec = raw as Record<string, unknown>;
  if (typeof rec.title !== "string" || typeof rec.summary !== "string") {
    throw new Error(
      `Invalid corpus document at index ${idx}: title and summary must be strings.`,
    );
  }
  if (!Array.isArray(rec.tags) || !rec.tags.every((t) => typeof t === "string")) {
    throw new Error(
      `Invalid corpus document at index ${idx}: tags must be an array of strings.`,
    );
  }
  if (
    typeof rec.sourceUrl !== "string" ||
    typeof rec.retrievedAt !== "string"
  ) {
    throw new Error(
      `Invalid corpus document at index ${idx}: sourceUrl and retrievedAt must be strings.`,
    );
  }
  if (
    !Array.isArray(rec.embedding) ||
    !rec.embedding.every((n) => typeof n === "number" && Number.isFinite(n))
  ) {
    throw new Error(
      `Invalid corpus document at index ${idx}: embedding must be an array of finite numbers.`,
    );
  }

  return {
    title: rec.title,
    summary: rec.summary,
    tags: [...rec.tags],
    sourceUrl: rec.sourceUrl,
    retrievedAt: rec.retrievedAt,
    embedding: [...rec.embedding],
  };
}

/**
 * Downloads the full public knowledge corpus from `GET /api/knowledge/corpus`,
 * verifies `contentSha256` by recomputing `sha256(canonicalJson(documents))` locally,
 * throws on hash or count mismatch, and caches the verified corpus per page load.
 */
export async function fetchCorpus(
  fetchImpl?: typeof fetch,
): Promise<CorpusResponse> {
  const effectiveFetch = fetchImpl ?? globalThis.fetch;
  if (typeof effectiveFetch !== "function") {
    throw new Error("No fetch implementation available for fetchCorpus.");
  }

  if (cachedCorpusPromise && cachedFetchRef === effectiveFetch) {
    return cachedCorpusPromise;
  }

  const loadPromise = (async (): Promise<CorpusResponse> => {
    const res = await effectiveFetch("/api/knowledge/corpus");
    if (!res || !res.ok) {
      throw new Error(
        `Failed to fetch public corpus (/api/knowledge/corpus): HTTP ${res?.status ?? "unknown"}`,
      );
    }

    const body = (await res.json()) as Record<string, unknown>;
    if (!body || typeof body !== "object" || !Array.isArray(body.documents)) {
      throw new Error(
        "Invalid /api/knowledge/corpus response: missing documents array.",
      );
    }

    const rawSha =
      typeof body.contentSha256 === "string" ? body.contentSha256.trim() : "";
    const normalizedExpectedSha = rawSha.replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalizedExpectedSha)) {
      throw new Error(
        `Invalid /api/knowledge/corpus response: invalid contentSha256 (${JSON.stringify(rawSha)}).`,
      );
    }

    const normalizedDocuments = body.documents.map((doc, idx) =>
      validateAndNormalizeCorpusDoc(doc, idx),
    );
    const documents = sortCorpusDocuments(normalizedDocuments);

    if (
      typeof body.documentCount === "number" &&
      body.documentCount !== documents.length
    ) {
      throw new Error(
        `Corpus documentCount mismatch: expected ${body.documentCount}, received ${documents.length} documents.`,
      );
    }

    const recomputedSha = computeCorpusContentSha256(documents).toLowerCase();
    if (recomputedSha !== normalizedExpectedSha) {
      throw new Error(
        `Corpus contentSha256 mismatch: header/body claimed ${rawSha}, recomputed ${recomputedSha}.`,
      );
    }

    const rawEtag = res.headers?.get?.("ETag") ?? res.headers?.get?.("etag");
    if (rawEtag) {
      const normalizedEtag = rawEtag
        .trim()
        .replace(/^W\//i, "")
        .replace(/^"|"$/g, "")
        .replace(/^0x/i, "")
        .toLowerCase();
      if (normalizedEtag && normalizedEtag !== recomputedSha) {
        throw new Error(
          `Corpus ETag mismatch: ETag claimed ${rawEtag}, recomputed ${recomputedSha}.`,
        );
      }
    }

    const verified: CorpusResponse = {
      ...(typeof body.database === "string" ? { database: body.database } : {}),
      ...(typeof body.collection === "string"
        ? { collection: body.collection }
        : {}),
      documentCount: documents.length,
      contentSha256: recomputedSha,
      documents,
    };

    cachedCorpusValue = verified;
    return verified;
  })();

  cachedFetchRef = effectiveFetch;
  cachedCorpusPromise = loadPromise;

  try {
    return await loadPromise;
  } catch (err) {
    if (cachedCorpusPromise === loadPromise) {
      cachedCorpusPromise = null;
      cachedCorpusValue = null;
      cachedFetchRef = undefined;
    }
    throw err;
  }
}

const STOPWORDS = new Set<string>([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "can",
  "do",
  "does",
  "for",
  "from",
  "how",
  "in",
  "is",
  "it",
  "of",
  "on",
  "or",
  "our",
  "that",
  "the",
  "their",
  "this",
  "to",
  "use",
  "we",
  "what",
  "when",
  "where",
  "which",
  "who",
  "why",
  "with",
  "you",
  "your",
]);

function stripPlaceholders(input: string): string {
  return (input || "")
    .replace(/\[[A-Z0-9_]+(?:_\d+)?\]/gi, " ")
    .replace(/<REDACTED[^>]*>/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function tokenizeForBm25(text: string, dropStopwords = false): string[] {
  const cleaned = stripPlaceholders(text).toLowerCase();
  if (!cleaned) return [];

  const rawTokens = cleaned
    .replace(/[^a-z0-9.+_-]+/g, " ")
    .split(/\s+/)
    .map((t) => t.replace(/^[.+_-]+|[.+_-]+$/g, ""))
    .filter((t) => t.length >= 2);

  const expanded: string[] = [];
  for (const token of rawTokens) {
    expanded.push(token);
    if (/[._-]/.test(token)) {
      const subParts = token
        .split(/[._-]+/)
        .filter((part) => part.length >= 2);
      for (const sub of subParts) {
        if (sub !== token) {
          expanded.push(sub);
        }
      }
    }
  }

  if (!dropStopwords) {
    return expanded;
  }
  const filtered = expanded.filter((t) => !STOPWORDS.has(t));
  return filtered.length > 0 ? filtered : expanded;
}

export function countTermOccurrences(
  tokens: readonly string[],
  queryTerm: string,
): number {
  let exactCount = 0;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === queryTerm) {
      exactCount += 1;
    }
  }
  if (exactCount > 0) {
    return exactCount;
  }
  if (queryTerm.length < 4 || /[._-]/.test(queryTerm)) {
    return 0;
  }
  let partialCount = 0;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (
      tok.length >= 3 &&
      !/[._-]/.test(tok) &&
      (tok.includes(queryTerm) || queryTerm.includes(tok))
    ) {
      partialCount += 0.5;
    }
  }
  return partialCount;
}

/**
 * Deterministic in-browser BM25 ranking over `title`, `summary`, and `tags`.
 * Performs zero network calls and is 100% browser-safe.
 */
export function rankLocally(
  query: string,
  corpus: CorpusInput,
  k = 5,
): RankedCorpusDocument[] {
  const docs: readonly CorpusDocument[] = Array.isArray(corpus)
    ? corpus
    : corpus && Array.isArray((corpus as { documents?: unknown }).documents)
      ? (corpus as { documents: readonly CorpusDocument[] }).documents
      : [];

  const limit = Number.isFinite(k) && k > 0 ? Math.floor(k) : 5;
  if (docs.length === 0) {
    return [];
  }

  const strippedQuery = stripPlaceholders(query || "");
  const qNorm = strippedQuery.toLowerCase().trim();
  const queryTerms = Array.from(new Set(tokenizeForBm25(qNorm, true)));

  const k1 = 1.2;
  const b = 0.75;
  const titleWeight = 3.0;
  const tagsWeight = 2.5;
  const summaryWeight = 1.0;

  const preparedDocs = docs.map((doc) => {
    const titleTokens = tokenizeForBm25(doc.title, false);
    const summaryTokens = tokenizeForBm25(doc.summary, false);
    const tagTokens = tokenizeForBm25((doc.tags ?? []).join(" "), false);
    return {
      doc,
      titleLower: doc.title.toLowerCase(),
      summaryLower: doc.summary.toLowerCase(),
      tagsLower: (doc.tags ?? []).map((t) => t.toLowerCase()),
      titleTokens,
      summaryTokens,
      tagTokens,
    };
  });

  const N = preparedDocs.length;
  const avgTitleLen =
    Math.max(
      1,
      preparedDocs.reduce((acc, d) => acc + d.titleTokens.length, 0) / N,
    );
  const avgSummaryLen =
    Math.max(
      1,
      preparedDocs.reduce((acc, d) => acc + d.summaryTokens.length, 0) / N,
    );
  const avgTagLen =
    Math.max(
      1,
      preparedDocs.reduce((acc, d) => acc + d.tagTokens.length, 0) / N,
    );

  // Document frequency per query term across all 3 fields
  const docFreq = new Map<string, number>();
  for (const term of queryTerms) {
    let df = 0;
    for (const p of preparedDocs) {
      const inTitle = countTermOccurrences(p.titleTokens, term) > 0;
      const inTags =
        countTermOccurrences(p.tagTokens, term) > 0 ||
        p.tagsLower.some((t) => t === term || t.includes(term));
      const inSummary = countTermOccurrences(p.summaryTokens, term) > 0;
      if (inTitle || inTags || inSummary) {
        df += 1;
      }
    }
    docFreq.set(term, df);
  }

  const scored = preparedDocs.map((p) => {
    if (queryTerms.length === 0) {
      return { doc: p.doc, score: 0 };
    }

    let totalScore = 0;

    // Exact multi-word phrase boosts
    if (qNorm.length >= 3) {
      if (p.titleLower.includes(qNorm)) {
        totalScore += 4.5;
      }
      if (p.tagsLower.some((t) => t === qNorm || t.includes(qNorm))) {
        totalScore += 3.5;
      }
      if (p.summaryLower.includes(qNorm)) {
        totalScore += 2.0;
      }
    }

    for (const term of queryTerms) {
      const df = docFreq.get(term) ?? 0;
      if (df === 0) continue;

      const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));

      const tfTitle = countTermOccurrences(p.titleTokens, term);
      if (tfTitle > 0) {
        const normTitle =
          tfTitle *
          (k1 + 1) /
          (tfTitle +
            k1 * (1 - b + b * (p.titleTokens.length / avgTitleLen)));
        totalScore += titleWeight * idf * normTitle;
      }

      const rawTagTf = countTermOccurrences(p.tagTokens, term);
      const exactTagHit = p.tagsLower.some((t) => t === term || t.includes(term))
        ? 1
        : 0;
      const tfTags = Math.max(rawTagTf, exactTagHit);
      if (tfTags > 0) {
        const normTags =
          tfTags *
          (k1 + 1) /
          (tfTags + k1 * (1 - b + b * (p.tagTokens.length / avgTagLen)));
        totalScore += tagsWeight * idf * normTags;
      }

      const tfSummary = countTermOccurrences(p.summaryTokens, term);
      if (tfSummary > 0) {
        const normSummary =
          tfSummary *
          (k1 + 1) /
          (tfSummary +
            k1 * (1 - b + b * (p.summaryTokens.length / avgSummaryLen)));
        totalScore += summaryWeight * idf * normSummary;
      }
    }

    const roundedScore = Number(totalScore.toFixed(6));
    return {
      doc: p.doc,
      score: roundedScore,
    };
  });

  scored.sort((a, b) => {
    if (b.score !== a.score) {
      return b.score - a.score;
    }
    return compareCorpusDocuments(a.doc, b.doc);
  });

  return scored.slice(0, limit).map((entry, idx) => ({
    title: entry.doc.title,
    summary: entry.doc.summary,
    tags: [...entry.doc.tags],
    sourceUrl: entry.doc.sourceUrl,
    retrievedAt: entry.doc.retrievedAt,
    embedding: [...entry.doc.embedding],
    score: entry.score,
    bm25Score: entry.score,
    rank: idx + 1,
  }));
}
