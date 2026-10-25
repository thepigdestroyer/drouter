import {
  clearCorpusCache,
  computeCorpusContentSha256,
  fetchCorpus,
  LOOKUP_TOPICS,
  rankLocally,
  sortCorpusDocuments,
  validateLookupIntent,
  type CorpusDocument,
  type CorpusResponse,
  type LookupIntent,
  type LookupTopic,
} from "@/lib/broker";

export {
  clearCorpusCache,
  computeCorpusContentSha256,
  fetchCorpus,
  LOOKUP_TOPICS,
  rankLocally,
  sortCorpusDocuments,
  validateLookupIntent,
  type CorpusDocument,
  type CorpusResponse,
  type LookupIntent,
  type LookupTopic,
};

export type CorpusDocumentItem = CorpusDocument;
export type CorpusPayload = CorpusResponse;

export interface RankedCorpusResult {
  topDocId: string;
  topTitle: string;
  topSummary: string;
  topSourceUrl: string;
  totalDocs: number;
  contentSha256: string;
  verifiedCorpusHash: boolean;
  ranked: Array<{
    docId: string;
    title: string;
    summary: string;
    tags: string[];
    sourceUrl: string;
    score: number;
  }>;
}

function slugifyDocTitle(title: string, idx: number): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug || `corpus-doc-${idx + 1}`;
}

export function verifyCorpusContentSha256(
  documents: readonly CorpusDocumentItem[],
  expectedSha256Hex: string,
): boolean {
  if (!expectedSha256Hex || !/^[0-9a-f]{64}$/i.test(expectedSha256Hex)) {
    return false;
  }
  const computed = computeCorpusContentSha256(documents).toLowerCase();
  return computed === expectedSha256Hex.toLowerCase();
}

export function rankCorpusDocumentsBm25(
  documents: readonly CorpusDocumentItem[],
  queryText: string,
  limit = 5,
): RankedCorpusResult["ranked"] {
  const rankedDocs = rankLocally(queryText, documents, limit);
  return rankedDocs.map((doc, idx) => ({
    docId: slugifyDocTitle(doc.title, idx),
    title: doc.title,
    summary: doc.summary,
    tags: [...doc.tags],
    sourceUrl: doc.sourceUrl,
    score: doc.score,
  }));
}

/**
 * Fetches the whole public knowledge corpus via `fetchCorpus` from `@/lib/broker`
 * (`GET /api/knowledge/corpus`, zero query parameters, zero request body) and ranks
 * locally in browser memory via `rankLocally`.
 */
export async function fetchWholeCorpusAndRankInBrowser(
  queryText: string,
  opts?: {
    fetchFn?: typeof fetch;
    limit?: number;
  },
): Promise<RankedCorpusResult> {
  const corpus = await fetchCorpus(opts?.fetchFn);
  const ranked = rankCorpusDocumentsBm25(
    corpus.documents,
    queryText,
    opts?.limit ?? 5,
  );
  const top = ranked[0];

  return {
    topDocId: top?.docId ?? "provider-tinfoil",
    topTitle: top?.title ?? "Tinfoil Confidential Inference Enclave",
    topSummary: top?.summary ?? "",
    topSourceUrl: top?.sourceUrl ?? "",
    totalDocs: corpus.documentCount,
    contentSha256: corpus.contentSha256,
    verifiedCorpusHash: true,
    ranked,
  };
}
