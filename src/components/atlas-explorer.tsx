"use client";

import React, { useCallback, useEffect, useState } from "react";
import { InkButton } from "@/components/ink/ink-button";
import { TechDetails } from "@/components/ink/tech-details";
import {
  formatPlainAtlasResult,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolveEffectiveAtlasQuery,
  sanitizeJargonToPlainWords,
} from "@/lib/plain-copy";
import { getActiveCustomScrubTerms } from "@/lib/auth/vault";
import {
  type CorpusDocument,
  type CorpusInput,
  fetchCorpus,
  getCachedCorpus,
  rankLocally,
} from "@/lib/broker";
import * as filterFingerprintMod from "@/lib/privacy/fingerprint";
import { evaluateLocalFilterFingerprint } from "@/lib/privacy/fingerprint";
import { mechanicalRedact } from "@/lib/privacy/mechanical";

export const ATLAS_PUBLIC_SEARCH_NOTICE =
  "This searches public reference material. What you type is filtered on your device before it reaches the database." as const;

export const ATLAS_DEVICE_ONLY_LABEL = "Search on my device only" as const;

export const ATLAS_FILTER_MISMATCH_BLOCKED_MESSAGE =
  "Sending is blocked because the personal-detail filter running in this browser does not match the published version in the public receipt book. Reload the page to get the latest version; if this keeps happening, wait until the public receipt book is updated." as const;

function assertFilterFingerprintAllowsSend(): void {
  const maybeAssert = (
    filterFingerprintMod as {
      assertFilterFingerprintAllowsSend?: () => void;
    }
  ).assertFilterFingerprintAllowsSend;
  if (typeof maybeAssert === "function") {
    maybeAssert();
    return;
  }
  const status = evaluateLocalFilterFingerprint();
  if (status.blockingSend) {
    throw new Error(
      status.blockReason ?? ATLAS_FILTER_MISMATCH_BLOCKED_MESSAGE,
    );
  }
}

export interface AtlasSearchResultItem {
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
  retrievedAt?: string;
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

export interface AtlasEnginesInfo {
  vectorSearch: "atlas" | "app-fallback" | string;
  textSearch: "atlas" | "app-fallback" | string;
  fusion: "$rankFusion" | "app-rrf" | string;
  embedding: string;
}

export interface AtlasResponse {
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

function inferCorpusDocMeta(doc: CorpusDocument): {
  docId: string;
  category: string;
} {
  const titleLower = doc.title.toLowerCase();
  const url = doc.sourceUrl.trim();

  if (url === "https://tee.fail/") {
    return { docId: "advisory-tee-fail-ddr5", category: "advisory" };
  }
  if (url === "https://ddropattack.eu/") {
    return { docId: "advisory-ddrop", category: "advisory" };
  }
  if (url === "https://cipherleaks.com/") {
    return { docId: "advisory-cipherleaks", category: "advisory" };
  }
  if (titleLower.startsWith("voltpillager:")) {
    return { docId: "advisory-voltpillager", category: "advisory" };
  }
  if (url === "https://www.rfc-editor.org/rfc/rfc9474.html") {
    return { docId: "arch-vmpl0-inner-monitor", category: "architecture" };
  }
  if (titleLower.startsWith("tinfoil chained two-hop")) {
    return { docId: "arch-two-hop-gpu-custody", category: "architecture" };
  }

  const providerPrefixMap: ReadonlyArray<[string, string]> = [
    ["tinfoil -", "provider-tinfoil"],
    ["phala cloud / redpill -", "provider-phala-redpill"],
    ["near ai cloud -", "provider-near-ai-cloud"],
    ["venice.ai -", "provider-venice-ai"],
    ["prem ai -", "provider-prem-ai"],
    ["ppq.ai -", "provider-ppq-ai"],
    ["confidential ai -", "provider-confidential-ai"],
    ["chutes -", "provider-chutes-bittensor"],
    ["privatemode", "provider-privatemode-cosmian"],
    ["nanogpt -", "provider-nanogpt"],
  ];
  for (const [prefix, id] of providerPrefixMap) {
    if (titleLower.startsWith(prefix)) {
      return { docId: id, category: "provider" };
    }
  }

  const slug = titleLower
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return {
    docId: `corpus-${slug || "doc"}`,
    category: "architecture",
  };
}

export interface ExecuteAtlasExplorerSearchOptions {
  rawInputQuery: string;
  deviceOnly?: boolean;
  customTerms?: string[];
  fetchImpl?: typeof fetch;
  corpus?: CorpusInput | null;
  limit?: number;
}

/**
 * Executes a public knowledge search from the browser:
 * - When `deviceOnly` is true: ranks the already-downloaded corpus locally with
 *   `rankLocally` (BM25 over title, summary, and tags) and sends nothing over the network.
 * - When `deviceOnly` is false: runs `mechanicalRedact` on the typed query in the browser
 *   before sending only the redacted text to `POST /api/atlas`.
 */
export async function executeAtlasExplorerSearch(
  options: ExecuteAtlasExplorerSearchOptions,
): Promise<AtlasResponse> {
  const {
    rawInputQuery,
    deviceOnly = false,
    customTerms,
    fetchImpl,
    corpus,
    limit = 4,
  } = options;

  const effectiveQuery = resolveEffectiveAtlasQuery(rawInputQuery);
  const activeCustomTerms =
    customTerms ??
    (typeof window !== "undefined" ? getActiveCustomScrubTerms() : []);

  if (deviceOnly) {
    const localCorpus: CorpusInput =
      corpus ?? getCachedCorpus() ?? (await fetchCorpus(fetchImpl));
    const totalCorpusDocs =
      "documents" in localCorpus
        ? localCorpus.documents.length
        : localCorpus.length;
    const ranked = rankLocally(effectiveQuery, localCorpus, limit);
    const results: AtlasSearchResultItem[] = ranked.map((doc) => {
      const meta = inferCorpusDocMeta(doc);
      return {
        docId: meta.docId,
        title: doc.title,
        category: meta.category,
        summary: doc.summary,
        sourceUrl: doc.sourceUrl,
        retrievedAt: doc.retrievedAt,
        tags: [...doc.tags],
        vectorScore: 0,
        textScore: doc.score,
        rrfScore: Number((1 / (60 + doc.rank)).toFixed(6)),
        vectorRank: doc.rank,
        textRank: doc.rank,
        embeddingModel: "local-bm25 (device-only)",
      };
    });

    return {
      query: effectiveQuery,
      results,
      embeddingModel: "local-bm25 (device-only)",
      engines: {
        vectorSearch: "none (device-only)",
        textSearch: "browser-bm25",
        fusion: "local-bm25",
        embedding: "local-bm25 (device-only)",
      },
      search: {
        engines: {
          vectorSearch: "none (device-only)",
          textSearch: "browser-bm25",
          fusion: "local-bm25",
          embedding: "local-bm25 (device-only)",
        },
        embeddingModel: "local-bm25 (device-only)",
        executionMode: "device-only-bm25",
        totalCorpusDocs,
      },
      analytics: {
        connected: false,
        totalKnowledgeDocs: totalCorpusDocs,
        totalIntelligenceDocs: totalCorpusDocs,
        searchIndexes: [],
      },
    };
  }

  // Verify the on-device personal-detail filter fingerprint matches the published version before sending
  assertFilterFingerprintAllowsSend();

  // Always redact on the device before sending anything to /api/atlas
  const scrubbedQuery = mechanicalRedact(effectiveQuery, {
    customTerms: activeCustomTerms,
  }).text;

  const effectiveFetch = fetchImpl ?? globalThis.fetch;
  const res = await effectiveFetch("/api/atlas", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      query: scrubbedQuery,
      limit,
    }),
  });

  const body = (await res.json().catch(() => null)) as AtlasResponse | null;
  if (!res.ok || !body) {
    const msg =
      body?.error || `Knowledge search failed with HTTP ${res.status}.`;
    throw new Error(msg);
  }
  return body;
}

export interface AtlasExplorerProps {
  initialDeviceOnly?: boolean;
  fetchImpl?: typeof fetch;
  preloadedCorpus?: CorpusInput | null;
}

export function AtlasExplorer({
  initialDeviceOnly = false,
  fetchImpl,
  preloadedCorpus = null,
}: AtlasExplorerProps) {
  const [query, setQuery] = useState<string>(
    PLAIN_ATLAS_PRESET_QUERIES[0].label,
  );
  const [deviceOnly, setDeviceOnly] = useState<boolean>(initialDeviceOnly);
  const [downloadedCorpus, setDownloadedCorpus] = useState<CorpusInput | null>(
    preloadedCorpus ?? getCachedCorpus(),
  );
  const [data, setData] = useState<AtlasResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runSearch = useCallback(
    async (rawInputQuery: string, useDeviceOnly = deviceOnly) => {
      setLoading(true);
      setError(null);
      try {
        let activeCorpus = downloadedCorpus ?? getCachedCorpus();
        if (useDeviceOnly && !activeCorpus) {
          const fetched = await fetchCorpus(fetchImpl);
          activeCorpus = fetched;
          setDownloadedCorpus(fetched);
        }

        const result = await executeAtlasExplorerSearch({
          rawInputQuery,
          deviceOnly: useDeviceOnly,
          fetchImpl,
          corpus: activeCorpus,
        });
        setData(result);
      } catch (err) {
        setError(
          sanitizeJargonToPlainWords(
            err instanceof Error
              ? err.message
              : "Network error while searching our knowledge base.",
          ),
        );
      } finally {
        setLoading(false);
      }
    },
    [deviceOnly, downloadedCorpus, fetchImpl],
  );

  useEffect(() => {
    void Promise.resolve().then(() =>
      runSearch(PLAIN_ATLAS_PRESET_QUERIES[0].query, initialDeviceOnly),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleToggleDeviceOnly = async (nextChecked: boolean) => {
    setDeviceOnly(nextChecked);
    if (nextChecked && !downloadedCorpus && !getCachedCorpus()) {
      try {
        const fetched = await fetchCorpus(fetchImpl);
        setDownloadedCorpus(fetched);
        void runSearch(query, true);
        return;
      } catch (err) {
        setError(
          sanitizeJargonToPlainWords(
            err instanceof Error
              ? err.message
              : "Could not download the public reference library.",
          ),
        );
        return;
      }
    }
    void runSearch(query, nextChecked);
  };

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
        <div className="ep-label">Knowledge search</div>
        <h3 className="font-serif text-xl sm:text-2xl text-ink">
          Public reference library
        </h3>
        <p className="max-w-[70ch] text-sm text-ink-2">
          Look up how deRoute protects your messages, which sealed computers we
          use, and how we guard against physical hardware attacks.
        </p>
        <p className="max-w-[70ch] text-xs text-ink-3">
          This searches public reference material. What you type is filtered on
          your device before it reaches the database.
        </p>
      </div>

      {/* Search form */}
      <form
        className="flex flex-col gap-2 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          void runSearch(query, deviceOnly);
        }}
      >
        <label htmlFor="atlas-search-input" className="sr-only">
          Search what we know about private AI
        </label>
        <input
          id="atlas-search-input"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Type a question about sealed computers or private AI..."
          className="ep-input flex-1"
        />
        <InkButton
          type="submit"
          variant="primary"
          disabled={loading}
          className="shrink-0"
        >
          {loading ? "Searching..." : "Search"}
        </InkButton>
      </form>

      {/* Device-only search toggle */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-2">
        <label
          htmlFor="atlas-device-only-toggle"
          className="inline-flex items-center gap-2 cursor-pointer select-none"
        >
          <input
            id="atlas-device-only-toggle"
            type="checkbox"
            checked={deviceOnly}
            onChange={(e) => void handleToggleDeviceOnly(e.target.checked)}
            className="h-4 w-4 accent-ink cursor-pointer"
          />
          <span className="font-medium text-ink">Search on my device only</span>
        </label>
        {deviceOnly && (
          <span className="text-ink-3">
            Ranks the downloaded reference library on your device and sends
            nothing.
          </span>
        )}
      </div>

      {/* Preset queries in plain words */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="ep-label">Try asking:</span>
        {PLAIN_ATLAS_PRESET_QUERIES.map((preset) => {
          const isSelected =
            query.trim().toLowerCase() === preset.label.toLowerCase();
          return (
            <button
              key={preset.label}
              type="button"
              aria-pressed={isSelected}
              onClick={() => {
                setQuery(preset.label);
                void runSearch(preset.query, deviceOnly);
              }}
              className={`ep-muted-chip max-w-full whitespace-normal text-left hover:border-ink hover:text-ink transition-colors cursor-pointer ${
                isSelected ? "border-ink text-ink" : ""
              }`}
            >
              {preset.label}
            </button>
          );
        })}
      </div>

      {/* Error banner with retry */}
      {error && (
        <div
          role="alert"
          className="ep-card border-accent bg-accent-soft/40 p-4 flex flex-wrap items-center justify-between gap-3 text-xs"
        >
          <div className="space-y-0.5">
            <div className="font-mono font-medium text-ink">Search error</div>
            <p className="text-ink-2">{sanitizeJargonToPlainWords(error)}</p>
          </div>
          <InkButton
            type="button"
            variant="ghost"
            disabled={loading}
            onClick={() => void runSearch(query, deviceOnly)}
            className="text-xs"
          >
            Try again
          </InkButton>
        </div>
      )}

      {/* Simple results list */}
      <div
        aria-live="polite"
        className="divide-y divide-rule border-t border-b border-rule"
      >
        {(data?.results ?? []).slice(0, 4).map((item) => {
          const sourceUrl = resolveItemSourceUrl(item);
          const plain = formatPlainAtlasResult(item);
          const rawTitleDeRoute = item.title.replace(/\bdRouter\b/g, "deRoute");
          const rawSummaryDeRoute = item.summary.replace(
            /\bdRouter\b/g,
            "deRoute",
          );
          return (
            <article key={item.docId} className="py-4 space-y-2.5">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h4 className="font-serif text-base sm:text-lg font-medium text-ink">
                  {plain.title}
                </h4>
                <span className="ep-muted-chip">{plain.categoryLabel}</span>
              </div>
              <p className="max-w-[70ch] text-sm text-ink-2 leading-relaxed">
                {plain.summary}
              </p>

              <TechDetails label="Show technical details">
                <div className="space-y-2 font-mono text-xs text-ink-2 break-words">
                  <div>
                    <span className="text-ink font-medium">Record ID:</span>{" "}
                    {item.docId} ({rawTitleDeRoute})
                  </div>
                  <p className="font-sans text-xs text-ink-2 leading-relaxed break-words">
                    {rawSummaryDeRoute}
                  </p>
                  {sourceUrl && (
                    <div>
                      <span className="text-ink font-medium">Source:</span>{" "}
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
                  <div>
                    <span className="text-ink font-medium">Scores:</span> RRF{" "}
                    {item.rrfScore.toFixed(4)} | Vector rank #{item.vectorRank}{" "}
                    ({item.vectorScore.toFixed(3)}) | Text rank #{item.textRank}{" "}
                    ({item.textScore.toFixed(3)})
                  </div>
                  {item.embeddingModel && (
                    <div>
                      <span className="text-ink font-medium">
                        Embedding model:
                      </span>{" "}
                      {item.embeddingModel}
                    </div>
                  )}
                  {item.tags.length > 0 && (
                    <div>
                      <span className="text-ink font-medium">Tags:</span>{" "}
                      {item.tags.join(", ")}
                    </div>
                  )}
                </div>
              </TechDetails>
            </article>
          );
        })}
        {data && data.results.length === 0 && !error && (
          <p className="py-4 text-sm text-ink-3">
            No matching notes found for that search.
          </p>
        )}
      </div>

      {/* Search engines & index details inside TechDetails */}
      <TechDetails label="Show search engine details">
        <div className="space-y-1.5 font-mono text-xs text-ink-2">
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
      </TechDetails>
    </div>
  );
}

export default AtlasExplorer;
