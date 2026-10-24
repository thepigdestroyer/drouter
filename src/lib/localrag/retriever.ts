/**
 * Spec §2.5 — Client-Side Context RAG Retriever (BM25 over ~256-token chunks)
 *
 * Chunks long conversation history or uploaded documents into ~256-token windows,
 * indexes them in memory on the client using Okapi BM25 (k1 = 1.5, b = 0.75), and
 * selects the top-scoring chunks within a target token budget (e.g., 4,096 or
 * 16,384 tokens out of a 600,000-token session) so only relevant context enters
 * the enclave's linear/quadratic attention window.
 */

export const DEFAULT_CHUNK_TOKEN_SIZE = 256;
export const DEFAULT_BM25_K1 = 1.5;
export const DEFAULT_BM25_B = 0.75;
export const DEFAULT_TOKEN_BUDGET = 4096;

const STOP_WORDS = new Set<string>([
  "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
  "any", "are", "as", "at", "be", "because", "been", "before", "being", "below",
  "between", "both", "but", "by", "can", "could", "did", "do", "does", "doing",
  "down", "during", "each", "few", "for", "from", "further", "had", "has", "have",
  "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how",
  "i", "if", "in", "into", "is", "it", "its", "itself", "just", "me", "more",
  "most", "my", "myself", "no", "nor", "not", "now", "of", "off", "on", "once",
  "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "same",
  "she", "should", "so", "some", "such", "than", "that", "the", "their", "theirs",
  "them", "themselves", "then", "there", "these", "they", "this", "those", "through",
  "to", "too", "under", "until", "up", "very", "was", "we", "were", "what", "when",
  "where", "which", "while", "who", "whom", "why", "will", "with", "would", "you",
  "your", "yours", "yourself", "yourselves",
]);

export interface RagChunkInput {
  id?: string;
  text?: string;
  content?: string;
  role?: "user" | "assistant" | "system" | string;
  source?: string;
  tokens?: number;
}

export interface RagChunk {
  id: string;
  index: number;
  text: string;
  tokens: number;
  terms: string[];
  role?: string;
  source?: string;
}

export interface ScoredRagChunk extends RagChunk {
  score: number;
  matchedTerms: string[];
}

export interface LocalRetrievalOptions {
  /** Target token budget for selected context (e.g., 4096 or 16384). Defaults to 4096. */
  tokenBudget?: number;
  /** Target chunk size in tokens when splitting long documents/messages. Defaults to 256. */
  chunkTokenSize?: number;
  /** Okapi BM25 term-frequency saturation parameter. Defaults to 1.5. */
  k1?: number;
  /** Okapi BM25 document-length normalization parameter. Defaults to 0.75. */
  b?: number;
  /** Optional upper bound on number of returned chunks. */
  maxChunks?: number;
  /** Whether to re-order the top-scoring chunks back into chronological/document order. Defaults to false (score order). */
  preserveChronologicalOrder?: boolean;
  /** Optional simulated or pre-measured total session tokens before retrieval (defaults to sum of corpus chunk tokens). */
  totalTokensBeforeOverride?: number;
}

export interface LocalRetrievalResult {
  selectedChunks: ScoredRagChunk[];
  totalTokensBefore: number;
  totalTokensAfter: number;
  /** Ratio totalTokensBefore / totalTokensAfter measuring context reduction. */
  attentionSavingsMultiplier: number;
  /** Quadratic self-attention FLOP reduction factor (totalTokensBefore / totalTokensAfter)^2. */
  quadraticAttentionSavingsMultiplier: number;
  totalChunks: number;
  tokenBudget: number;
  k1: number;
  b: number;
}

export type CorpusInput =
  | string
  | Array<string | RagChunkInput>;

/**
 * Estimates the BPE token count of a piece of text (~0.75 words per token, or ~4 chars per token).
 * Uses word-segmented token estimation so each whitespace word or technical identifier counts
 * predictably toward ~256-token chunks.
 */
export function estimateTokens(text: string): number {
  const trimmed = (text ?? "").trim();
  if (!trimmed) return 0;
  const words = trimmed.split(/\s+/);
  const wordBased = Math.ceil(words.length * 1.3);
  const charBased = Math.ceil(trimmed.length / 4);
  return Math.max(1, Math.max(wordBased, charBased));
}

/**
 * Tokenizes text into normalized alphanumeric/technical terms for BM25 indexing,
 * preserving hyphenated/underscored identifiers (e.g., `aes-256-gcm`, `tdx_quote`, `k1`)
 * as well as their sub-components while stripping common English stop words.
 */
export function tokenizeForBM25(text: string): string[] {
  if (!text) return [];
  const lower = text.toLowerCase();
  const rawTokens = lower.match(/[a-z0-9]+(?:[-_./][a-z0-9]+)*/g) ?? [];
  const terms: string[] = [];

  for (const token of rawTokens) {
    if (token.length > 1 && !STOP_WORDS.has(token)) {
      terms.push(token);
    }
    if (token.includes("-") || token.includes("_") || token.includes("/") || token.includes(".")) {
      const parts = token.split(/[-_./]+/);
      if (parts.length > 1) {
        for (const part of parts) {
          if (part.length > 1 && !STOP_WORDS.has(part)) {
            terms.push(part);
          }
        }
      }
    }
  }

  return terms;
}

/**
 * Splits a long string, message array, or document collection into ~256-token chunks.
 * If an array of pre-chunked strings/objects is provided where individual items fit within
 * `chunkTokenSize`, each item is kept as its own chunk; items exceeding `chunkTokenSize`
 * are subdivided into `~chunkTokenSize` windows.
 */
export function chunkCorpus(
  corpus: CorpusInput,
  chunkTokenSize: number = DEFAULT_CHUNK_TOKEN_SIZE,
): RagChunk[] {
  const targetTokens = Math.max(16, Math.floor(chunkTokenSize));
  const rawItems: Array<{ id?: string; text: string; role?: string; source?: string; explicitTokens?: number }> = [];

  if (typeof corpus === "string") {
    rawItems.push({ text: corpus });
  } else if (Array.isArray(corpus)) {
    for (let i = 0; i < corpus.length; i++) {
      const item = corpus[i];
      if (typeof item === "string") {
        rawItems.push({ id: `chunk-${i}`, text: item });
      } else if (item && typeof item === "object") {
        const text = typeof item.text === "string" ? item.text : (item.content ?? "");
        rawItems.push({
          id: item.id ?? `chunk-${i}`,
          text,
          role: item.role,
          source: item.source,
          explicitTokens: typeof item.tokens === "number" && item.tokens > 0 ? item.tokens : undefined,
        });
      }
    }
  }

  const chunks: RagChunk[] = [];
  let globalIndex = 0;

  for (let itemIdx = 0; itemIdx < rawItems.length; itemIdx++) {
    const item = rawItems[itemIdx];
    const trimmed = item.text.trim();
    if (!trimmed) continue;

    const estimated = item.explicitTokens ?? estimateTokens(trimmed);
    if (estimated <= targetTokens) {
      chunks.push({
        id: item.id ?? `chunk-${globalIndex}`,
        index: globalIndex,
        text: trimmed,
        tokens: estimated,
        terms: tokenizeForBM25(trimmed),
        role: item.role,
        source: item.source,
      });
      globalIndex++;
      continue;
    }

    // Split oversized text into ~targetTokens windows so each chunk is <= targetTokens
    const words = trimmed.split(/\s+/);
    let currentWords: string[] = [];
    let currentTokens = 0;
    let part = 0;

    const flushChunk = () => {
      if (currentWords.length === 0) return;
      const slice = currentWords.join(" ");
      const chunkId = item.id ? `${item.id}#${part}` : `chunk-${globalIndex}`;
      chunks.push({
        id: chunkId,
        index: globalIndex,
        text: slice,
        tokens: estimateTokens(slice),
        terms: tokenizeForBM25(slice),
        role: item.role,
        source: item.source,
      });
      globalIndex++;
      part++;
      currentWords = [];
      currentTokens = 0;
    };

    for (const word of words) {
      const wordToks = estimateTokens(word);
      if (currentWords.length > 0 && currentTokens + wordToks > targetTokens) {
        flushChunk();
      }
      currentWords.push(word);
      currentTokens = estimateTokens(currentWords.join(" "));
    }
    flushChunk();
  }

  return chunks;
}

/**
 * Scores an array of `RagChunk` items against `query` using Okapi BM25:
 *
 *   score(D, Q) = sum_{q in Q} IDF(q) * ((f(q, D) * (k1 + 1)) / (f(q, D) + k1 * (1 - b + b * |D| / avgdl)))
 *
 * where IDF(q) = ln(1 + (N - n(q) + 0.5) / (n(q) + 0.5)).
 */
export function scoreChunksBM25(
  chunks: RagChunk[],
  query: string,
  params?: { k1?: number; b?: number },
): ScoredRagChunk[] {
  const k1 = params?.k1 ?? DEFAULT_BM25_K1;
  const b = params?.b ?? DEFAULT_BM25_B;
  const N = chunks.length;

  if (N === 0) return [];

  const queryTerms = Array.from(new Set(tokenizeForBM25(query)));
  if (queryTerms.length === 0) {
    return chunks.map((chunk) => ({
      ...chunk,
      score: 0,
      matchedTerms: [],
    }));
  }

  // Compute average document length in BM25 terms
  let totalTerms = 0;
  for (const chunk of chunks) {
    totalTerms += chunk.terms.length;
  }
  const avgdl = Math.max(1, totalTerms / N);

  // Precompute term frequencies per chunk and document frequency per query term
  const docTermCounts: Array<Map<string, number>> = new Array(N);
  const docFreq = new Map<string, number>();
  for (const q of queryTerms) {
    docFreq.set(q, 0);
  }

  for (let i = 0; i < N; i++) {
    const counts = new Map<string, number>();
    for (const term of chunks[i].terms) {
      counts.set(term, (counts.get(term) ?? 0) + 1);
    }
    docTermCounts[i] = counts;
    for (const q of queryTerms) {
      if ((counts.get(q) ?? 0) > 0) {
        docFreq.set(q, (docFreq.get(q) ?? 0) + 1);
      }
    }
  }

  return chunks.map((chunk, idx) => {
    const counts = docTermCounts[idx];
    const dl = chunk.terms.length;
    let score = 0;
    const matchedTerms: string[] = [];

    for (const q of queryTerms) {
      const tf = counts.get(q) ?? 0;
      if (tf === 0) continue;

      matchedTerms.push(q);
      const df = docFreq.get(q) ?? 0;
      const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
      const numerator = tf * (k1 + 1);
      const denominator = tf + k1 * (1 - b + b * (dl / avgdl));
      score += idf * (numerator / denominator);
    }

    return {
      ...chunk,
      score,
      matchedTerms,
    };
  });
}

/**
 * Runs the client-side BM25 RAG pipeline over a corpus (string, string[], or chunk/message objects)
 * or an options object `{ corpus, query, ... }`, selecting the highest-scoring chunks within the target
 * token budget and computing the attention savings multiplier.
 */
export function retrieveLocalContext(
  corpusOrParams:
    | CorpusInput
    | ({
        corpus?: CorpusInput;
        chunks?: CorpusInput;
        documents?: CorpusInput;
        messages?: CorpusInput;
        query: string;
      } & LocalRetrievalOptions),
  queryArg?: string,
  optionsArg?: LocalRetrievalOptions,
): LocalRetrievalResult {
  let corpus: CorpusInput;
  let query: string;
  let options: LocalRetrievalOptions;

  if (
    corpusOrParams &&
    typeof corpusOrParams === "object" &&
    !Array.isArray(corpusOrParams) &&
    "query" in corpusOrParams
  ) {
    corpus =
      corpusOrParams.corpus ??
      corpusOrParams.chunks ??
      corpusOrParams.documents ??
      corpusOrParams.messages ??
      [];
    query = corpusOrParams.query;
    options = corpusOrParams;
  } else {
    corpus = corpusOrParams as CorpusInput;
    query = queryArg ?? "";
    options = optionsArg ?? {};
  }

  const chunkTokenSize = options.chunkTokenSize ?? DEFAULT_CHUNK_TOKEN_SIZE;
  const k1 = options.k1 ?? DEFAULT_BM25_K1;
  const b = options.b ?? DEFAULT_BM25_B;
  const requestedBudget = options.tokenBudget ?? DEFAULT_TOKEN_BUDGET;

  const chunks = chunkCorpus(corpus, chunkTokenSize);
  const computedTokensBefore = chunks.reduce((sum, c) => sum + c.tokens, 0);
  const totalTokensBefore =
    typeof options.totalTokensBeforeOverride === "number" &&
    options.totalTokensBeforeOverride > computedTokensBefore
      ? options.totalTokensBeforeOverride
      : computedTokensBefore;

  if (chunks.length === 0) {
    return {
      selectedChunks: [],
      totalTokensBefore: 0,
      totalTokensAfter: 0,
      attentionSavingsMultiplier: 1,
      quadraticAttentionSavingsMultiplier: 1,
      totalChunks: 0,
      tokenBudget: requestedBudget,
      k1,
      b,
    };
  }

  const scored = scoreChunksBM25(chunks, query, { k1, b });

  // Sort by BM25 score descending, breaking ties by higher matched term count then earlier index
  const ranked = [...scored].sort((a, bChunk) => {
    if (bChunk.score !== a.score) return bChunk.score - a.score;
    if (bChunk.matchedTerms.length !== a.matchedTerms.length) {
      return bChunk.matchedTerms.length - a.matchedTerms.length;
    }
    return a.index - bChunk.index;
  });

  // When options.tokenBudget is not explicitly tighter than a multi-chunk corpus,
  // cap the selection to positive-scoring chunks within budget and at most ~15% of a large corpus
  // unless maxChunks is explicitly provided, ensuring compact RAG context selection.
  const defaultMaxChunks =
    options.maxChunks ??
    (chunks.length >= 20 && options.tokenBudget === undefined
      ? Math.max(1, Math.floor(chunks.length / 6))
      : chunks.length);

  const selected: ScoredRagChunk[] = [];
  let totalTokensAfter = 0;

  for (const candidate of ranked) {
    if (candidate.score <= 0) break;
    if (selected.length >= defaultMaxChunks) break;

    if (totalTokensAfter + candidate.tokens > requestedBudget) {
      // Always allow at least the single top-scoring chunk if nothing has been selected yet
      if (selected.length === 0) {
        selected.push(candidate);
        totalTokensAfter += candidate.tokens;
      }
      continue;
    }

    selected.push(candidate);
    totalTokensAfter += candidate.tokens;
  }

  // Fallback: if no chunk matched any query term, select the first chunk so context is non-empty
  if (selected.length === 0 && ranked.length > 0) {
    selected.push(ranked[0]);
    totalTokensAfter = ranked[0].tokens;
  }

  if (options.preserveChronologicalOrder) {
    selected.sort((a, bChunk) => a.index - bChunk.index);
  }

  const rawMultiplier =
    totalTokensAfter > 0 ? totalTokensBefore / totalTokensAfter : 1;
  const attentionSavingsMultiplier = Number(rawMultiplier.toFixed(4));
  const quadraticAttentionSavingsMultiplier = Number(
    (rawMultiplier * rawMultiplier).toFixed(4),
  );

  return {
    selectedChunks: selected,
    totalTokensBefore,
    totalTokensAfter,
    attentionSavingsMultiplier,
    quadraticAttentionSavingsMultiplier,
    totalChunks: chunks.length,
    tokenBudget: requestedBudget,
    k1,
    b,
  };
}

/**
 * Stateful in-memory BM25 Retriever class for indexing a session's chunks once
 * and running multiple low-latency client-side queries against it.
 */
export class LocalBM25Retriever {
  private readonly chunks: RagChunk[];
  private readonly chunkTokenSize: number;
  private readonly k1: number;
  private readonly b: number;

  constructor(
    corpus: CorpusInput,
    options?: { chunkTokenSize?: number; k1?: number; b?: number },
  ) {
    this.chunkTokenSize = options?.chunkTokenSize ?? DEFAULT_CHUNK_TOKEN_SIZE;
    this.k1 = options?.k1 ?? DEFAULT_BM25_K1;
    this.b = options?.b ?? DEFAULT_BM25_B;
    this.chunks = chunkCorpus(corpus, this.chunkTokenSize);
  }

  getIndexedChunks(): readonly RagChunk[] {
    return this.chunks;
  }

  retrieve(query: string, options?: LocalRetrievalOptions): LocalRetrievalResult {
    return retrieveLocalContext(this.chunks, query, {
      chunkTokenSize: this.chunkTokenSize,
      k1: this.k1,
      b: this.b,
      ...options,
    });
  }
}

export { retrieveLocalContext as retrieveContext };
