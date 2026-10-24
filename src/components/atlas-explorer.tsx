"use client";

import React, { useCallback, useEffect, useState } from "react";

interface AtlasSearchResultItem {
  docId: string;
  title: string;
  category: string;
  summary: string;
  provider?: string;
  cpuTee?: string;
  gpuTee?: string;
  sourceUrl?: string;
  docsUrl?: string;
  url?: string;
  metadata?: {
    sourceUrl?: string;
    docsUrl?: string;
    url?: string;
    providerId?: string;
    cpuTee?: string;
    gpuTee?: string;
    [key: string]: unknown;
  };
  tags: string[];
  vectorScore: number;
  textScore: number;
  rrfScore: number;
  vectorRank: number;
  textRank: number;
  embeddingModel?: string;
}

interface AtlasEnginesInfo {
  vectorSearch: "atlas" | "app-fallback" | string;
  textSearch: "atlas" | "app-fallback" | string;
  fusion: "$rankFusion" | "app-rrf" | string;
  embedding: string;
}

interface AtlasResponse {
  query: string;
  results: AtlasSearchResultItem[];
  featuresUsed?: string[];
  engines?: AtlasEnginesInfo;
  embeddingModel?: string;
  search?: {
    engines?: AtlasEnginesInfo;
    embeddingModel?: string;
    executionMode?: string;
    totalCorpusDocs?: number;
  };
  analytics?: {
    connected?: boolean;
    totalKnowledgeDocs?: number;
    totalIntelligenceDocs?: number;
    verificationsCount?: number;
    receiptsCount?: number;
    agentVerificationReceiptsCount?: number;
    nullifiersCount?: number;
    frozenBlobsCount?: number;
    searchIndexes?: {
      name: string;
      type?: string;
      status?: string;
      numDimensions?: number;
    }[];
  };
  error?: string;
}

const PRESET_QUERIES = [
  "AMD SEV-SNP router and Intel TDX model enclave",
  "Kimi K3 Intel TDX and NVIDIA confidential GPU enclave",
  "DDR5 memory bus interposer probe mitigation",
  "Chaumian RSA blind signature credits",
];

function resolveItemSourceUrl(item: AtlasSearchResultItem): string | null {
  const candidates = [
    item.sourceUrl,
    item.docsUrl,
    item.url,
    typeof item.metadata?.sourceUrl === "string"
      ? item.metadata.sourceUrl
      : undefined,
    typeof item.metadata?.docsUrl === "string"
      ? item.metadata.docsUrl
      : undefined,
    typeof item.metadata?.url === "string" ? item.metadata.url : undefined,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && /^https?:\/\//i.test(c.trim())) {
      return c.trim();
    }
  }
  return null;
}

export function AtlasExplorer() {
  const [query, setQuery] = useState(PRESET_QUERIES[0]);
  const [data, setData] = useState<AtlasResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runSearch = useCallback(async (q: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/atlas?q=${encodeURIComponent(q)}`);
      const body = (await res.json().catch(() => null)) as AtlasResponse | null;
      if (!res.ok || !body) {
        const msg =
          body?.error || `Atlas search failed with HTTP ${res.status}.`;
        setError(msg);
        return;
      }
      setData(body);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Network error while querying /api/atlas.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void runSearch(PRESET_QUERIES[0]);
  }, [runSearch]);

  const engines = data?.engines ?? data?.search?.engines;
  const embeddingModel =
    engines?.embedding ??
    data?.embeddingModel ??
    data?.search?.embeddingModel ??
    data?.results?.[0]?.embeddingModel ??
    "unknown";

  const enginesLine = engines
    ? `vector: ${engines.vectorSearch} | text: ${engines.textSearch} | fusion: ${engines.fusion} | embedding: ${embeddingModel}`
    : data
      ? `embedding: ${embeddingModel}`
      : loading
        ? "loading..."
        : "unavailable";

  const indexList = data?.analytics?.searchIndexes ?? [];
  const totalDocs =
    data?.analytics?.totalKnowledgeDocs ??
    data?.analytics?.totalIntelligenceDocs ??
    data?.search?.totalCorpusDocs;
  const connectedState =
    data?.analytics?.connected === true
      ? "Atlas connected"
      : data?.analytics?.connected === false
        ? "Local corpus fallback"
        : null;

  const indexSummary =
    indexList.length > 0
      ? indexList
          .map(
            (idx) =>
              `${idx.name}${idx.type ? ` [${idx.type}${idx.numDimensions ? ` ${idx.numDimensions}d` : ""}]` : ""}: ${idx.status ?? "unknown"}`,
          )
          .join(" | ")
      : data
        ? "No live Atlas index report"
        : loading
          ? "checking indexes..."
          : "unavailable";

  return (
    <div className="ep-card p-5 sm:p-6 text-ink space-y-5">
      <div className="space-y-1.5">
        <div className="ep-label">Knowledge retrieval</div>
        <h3 className="font-serif text-xl sm:text-2xl text-ink">
          Search hardware and enclave documentation
        </h3>
        <p className="max-w-[70ch] text-sm text-ink-2">
          Queries our hardware advisory and provider catalog using hybrid vector
          and full-text search, falling back to local ranking when MongoDB Atlas
          search indexes are unavailable.
        </p>
      </div>

      {/* Search form */}
      <form
        className="flex flex-col gap-2 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          void runSearch(query);
        }}
      >
        <label htmlFor="atlas-search-input" className="sr-only">
          Search enclave knowledge base
        </label>
        <input
          id="atlas-search-input"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search providers, hardware checks, or threat notes..."
          className="ep-input flex-1"
        />
        <button type="submit" disabled={loading} className="ep-btn shrink-0">
          {loading ? "Searching..." : "Search"}
        </button>
      </form>

      {/* Preset queries */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="ep-label">Presets:</span>
        {PRESET_QUERIES.map((preset) => (
          <button
            key={preset}
            type="button"
            onClick={() => {
              setQuery(preset);
              void runSearch(preset);
            }}
            className="ep-muted-chip hover:border-ink hover:text-ink transition-colors cursor-pointer"
          >
            {preset}
          </button>
        ))}
      </div>

      {/* Honest Engines & Index Status bar */}
      <div className="ep-inset px-3.5 py-2.5 text-xs text-ink-2 space-y-1 font-mono">
        <div>
          <span className="text-ink font-medium">Engines:</span> {enginesLine}
        </div>
        <div>
          <span className="text-ink font-medium">Index status:</span>{" "}
          {indexSummary}
          {totalDocs !== undefined ? ` (${totalDocs} docs)` : ""}
          {connectedState ? ` | ${connectedState}` : ""}
        </div>
      </div>

      {/* Error banner with retry */}
      {error && (
        <div
          role="alert"
          className="ep-card border-accent bg-accent-soft/40 p-4 flex flex-wrap items-center justify-between gap-3 text-xs"
        >
          <div className="space-y-0.5">
            <div className="font-mono font-medium text-ink">
              Atlas search error
            </div>
            <p className="text-ink-2 font-mono">{error}</p>
          </div>
          <button
            type="button"
            disabled={loading}
            onClick={() => void runSearch(query)}
            className="ep-btn text-xs cursor-pointer"
          >
            Retry search
          </button>
        </div>
      )}

      {/* Results list */}
      <div className="divide-y divide-rule border-t border-b border-rule">
        {(data?.results ?? []).slice(0, 4).map((item) => {
          const sourceUrl = resolveItemSourceUrl(item);
          return (
            <article key={item.docId} className="py-4 space-y-2">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h4 className="font-serif text-base font-medium text-ink">
                  {sourceUrl ? (
                    <a
                      href={sourceUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="ep-link"
                    >
                      {item.title}
                    </a>
                  ) : (
                    item.title
                  )}
                </h4>
                <span className="ep-label">
                  {item.category}
                  {item.provider ? ` / ${item.provider}` : ""}
                </span>
              </div>
              <p className="max-w-[70ch] text-sm text-ink-2 leading-relaxed">
                {item.summary}
              </p>
              {sourceUrl && (
                <div className="font-mono text-xs text-ink-2">
                  Source:{" "}
                  <a
                    href={sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ep-link break-all"
                  >
                    {sourceUrl}
                  </a>
                </div>
              )}
              <details className="text-xs text-ink-3">
                <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                  Show score details
                </summary>
                <div className="mt-2 ep-inset p-2.5 font-mono text-xs text-ink-2 space-y-1">
                  <div>
                    RRF score: {item.rrfScore.toFixed(4)} | Vector rank: #
                    {item.vectorRank} ({item.vectorScore.toFixed(3)}) | Text
                    rank: #{item.textRank} ({item.textScore.toFixed(3)})
                  </div>
                  {item.embeddingModel && (
                    <div>Embedding model: {item.embeddingModel}</div>
                  )}
                  {item.tags.length > 0 && (
                    <div>Tags: {item.tags.join(", ")}</div>
                  )}
                </div>
              </details>
            </article>
          );
        })}
        {data && data.results.length === 0 && !error && (
          <p className="py-4 text-sm text-ink-3">
            No matching records found for this query.
          </p>
        )}
      </div>
    </div>
  );
}

export default AtlasExplorer;
