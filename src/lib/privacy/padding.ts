export interface BucketPaddingInfo {
  tokenCount: number;
  bucketTokens: number;
  exponent: number;
  padTokens: number;
  overheadPct: number;
  frameCadenceMs: number;
}

export interface MinimizedHistoryResult<T> {
  selected: T[];
  droppedCount: number;
  tokensBefore: number;
  tokensAfter: number;
}

export const BASE_BUCKET_TOKENS = 1024;
export const STREAM_FRAME_CADENCE_MS = 50;

const STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "but",
  "by",
  "can",
  "did",
  "do",
  "does",
  "for",
  "from",
  "had",
  "has",
  "have",
  "how",
  "i",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "me",
  "my",
  "no",
  "not",
  "of",
  "on",
  "or",
  "our",
  "so",
  "that",
  "the",
  "their",
  "them",
  "then",
  "there",
  "these",
  "they",
  "this",
  "to",
  "up",
  "us",
  "was",
  "we",
  "were",
  "what",
  "when",
  "where",
  "which",
  "who",
  "why",
  "will",
  "with",
  "would",
  "you",
  "your",
]);

const utf8Encoder = new TextEncoder();

/**
 * Estimate token count using the UTF-8 byte length / 4 heuristic.
 * Returns 0 for empty strings and at least 1 for any non-empty string.
 */
export function estimateTokens(text: string): number {
  if (!text || text.length === 0) return 0;
  const byteLength = utf8Encoder.encode(text).byteLength;
  return Math.max(1, Math.ceil(byteLength / 4));
}

/**
 * Compute the Spec §6 power-of-two upload bucket (`2^j * 1024` tokens)
 * and fixed 50 ms output frame cadence for a given token count.
 */
export function bucketForTokens(tokenCount: number): BucketPaddingInfo {
  const normalizedCount = Math.max(0, Math.floor(Number.isFinite(tokenCount) ? tokenCount : 0));
  const effectiveTokens = Math.max(1, normalizedCount);

  let exponent = 0;
  let bucketTokens = BASE_BUCKET_TOKENS;
  while (bucketTokens < effectiveTokens) {
    exponent += 1;
    bucketTokens = BASE_BUCKET_TOKENS * Math.pow(2, exponent);
  }

  const padTokens = Math.max(0, bucketTokens - normalizedCount);
  const overheadPct =
    bucketTokens > 0 ? Math.round((padTokens / bucketTokens) * 10000) / 100 : 0;

  return {
    tokenCount: normalizedCount,
    bucketTokens,
    exponent,
    padTokens,
    overheadPct,
    frameCadenceMs: STREAM_FRAME_CADENCE_MS,
  };
}

function extractKeywords(text: string): string[] {
  const matches = text.toLowerCase().match(/[a-z0-9_]{2,}/g);
  if (!matches) return [];
  const filtered = matches.filter((w) => !STOPWORDS.has(w));
  return filtered.length > 0 ? filtered : matches;
}

/**
 * Local context minimizer (Spec §6):
 * Always keeps the first message and the most recent 2 messages.
 * Scores middle messages by keyword overlap with `query` and keeps the
 * top-scoring ones in chronological order within `maxTokensBudget`.
 */
export function minimizeHistory<T extends { role: "user" | "assistant"; content: string }>(
  messages: T[],
  query: string,
  maxTokensBudget: number,
): MinimizedHistoryResult<T> {
  if (messages.length === 0) {
    return {
      selected: [],
      droppedCount: 0,
      tokensBefore: 0,
      tokensAfter: 0,
    };
  }

  const msgTokens = messages.map((m) => estimateTokens(m.content));
  const tokensBefore = msgTokens.reduce((acc, n) => acc + n, 0);
  const budget = Math.max(0, Math.floor(maxTokensBudget));

  if (messages.length <= 3 || tokensBefore <= budget) {
    return {
      selected: [...messages],
      droppedCount: 0,
      tokensBefore,
      tokensAfter: tokensBefore,
    };
  }

  const pinnedSet = new Set<number>([0, messages.length - 2, messages.length - 1]);
  let usedTokens = 0;
  for (const idx of pinnedSet) {
    usedTokens += msgTokens[idx];
  }

  const queryKeywords = new Set(extractKeywords(query));

  interface MiddleCandidate {
    index: number;
    tokens: number;
    score: number;
  }

  const middleCandidates: MiddleCandidate[] = [];
  for (let i = 1; i < messages.length - 2; i++) {
    const words = extractKeywords(messages[i].content);
    const uniqueMatched = new Set<string>();
    let totalHits = 0;
    for (const w of words) {
      if (queryKeywords.has(w)) {
        uniqueMatched.add(w);
        totalHits += 1;
      }
    }
    // Primary score: distinct query keyword matches; tie-breaker: total keyword occurrences
    const score = uniqueMatched.size * 100 + totalHits;
    middleCandidates.push({
      index: i,
      tokens: msgTokens[i],
      score,
    });
  }

  // Sort by highest keyword overlap score first, then prefer more recent turns on ties
  middleCandidates.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return b.index - a.index;
  });

  const keptIndices = new Set<number>(pinnedSet);
  for (const candidate of middleCandidates) {
    if (usedTokens + candidate.tokens <= budget) {
      keptIndices.add(candidate.index);
      usedTokens += candidate.tokens;
    }
  }

  const sortedIndices = [...keptIndices].sort((a, b) => a - b);
  const selected = sortedIndices.map((idx) => messages[idx]);
  const tokensAfter = sortedIndices.reduce((acc, idx) => acc + msgTokens[idx], 0);

  return {
    selected,
    droppedCount: messages.length - selected.length,
    tokensBefore,
    tokensAfter,
  };
}
