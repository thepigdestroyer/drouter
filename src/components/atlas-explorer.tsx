"use client";

import { useCallback, useEffect, useState } from "react";

interface AtlasSearchResultItem {
  docId: string;
  title: string;
  category: string;
  summary: string;
  provider?: string;
  cpuTee?: string;
  gpuTee?: string;
  tags: string[];
  vectorScore: number;
  textScore: number;
  rrfScore: number;
  vectorRank: number;
  textRank: number;
}

interface AtlasResponse {
  query: string;
  results: AtlasSearchResultItem[];
  featuresUsed: string[];
  analytics?: {
    totalKnowledgeDocs?: number;
    verificationsCount?: number;
    receiptsCount?: number;
    nullifiersCount?: number;
    frozenBlobsCount?: number;
    searchIndexes?: { name: string; type?: string; status?: string }[];
  };
}

const PRESET_QUERIES = [
  "DDR5 memory bus interposer probe TEE.fail mitigation",
  "Kimi K3 8x NVIDIA B200 confidential GPU enclave",
  "AMD SEV-SNP VCEK hardware attestation and Sigstore Rekor",
  "RSA blind signature unlinkable credits and Shamir threshold",
];

export function AtlasExplorer() {
  const [query, setQuery] = useState(PRESET_QUERIES[0]);
  const [data, setData] = useState<AtlasResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const runSearch = useCallback(async (q: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/atlas?q=${encodeURIComponent(q)}`);
      if (res.ok) {
        setData((await res.json()) as AtlasResponse);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void runSearch(PRESET_QUERIES[0]);
  }, [runSearch]);

  return (
    <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-5 text-[#ece7da]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(236,231,218,0.1)] pb-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-[#a6ff72]">
            MONGODB ATLAS DEVELOPER DATA PLATFORM · LIVE CLUSTER (`drouter`)
          </div>
          <h3 className="mt-1 text-lg font-semibold text-[#ece7da]">
            Hybrid Vector + Full-Text Enclave Intelligence Search
          </h3>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(data?.featuresUsed ?? [
            "Atlas Search ($search)",
            "Atlas Vector Search ($vectorSearch)",
            "Hybrid Search (RRF)",
            "Automated 128-d Embeddings",
            "Stream Analytics ($facet)",
          ]).map((f) => (
            <span
              key={f}
              className="rounded border border-[#a6ff72]/30 bg-[#133b22]/50 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]"
            >
              {f}
            </span>
          ))}
        </div>
      </div>

      {/* Live Search Bar */}
      <form
        className="mt-4 flex flex-col gap-2 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          void runSearch(query);
        }}
      >
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search confidential providers, CVEs, or enclave registers via Atlas Hybrid Search…"
          className="flex-1 rounded-lg border border-[rgba(236,231,218,0.18)] bg-[#050706] px-3.5 py-2 text-sm text-[#ece7da] placeholder:text-[#ece7da]/40"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-[#a6ff72] px-4 py-2 text-sm font-semibold text-[#050706] hover:bg-[#5fe07a] disabled:opacity-50"
        >
          {loading ? "Querying Atlas…" : "Run Hybrid Search"}
        </button>
      </form>

      <div className="mt-2.5 flex flex-wrap gap-2">
        {PRESET_QUERIES.map((preset) => (
          <button
            key={preset}
            type="button"
            onClick={() => {
              setQuery(preset);
              void runSearch(preset);
            }}
            className="rounded border border-[rgba(236,231,218,0.12)] bg-[#0f1512] px-2.5 py-1 text-xs text-[#ece7da]/75 hover:border-[#a6ff72]/50 hover:text-[#ece7da]"
          >
            {preset}
          </button>
        ))}
      </div>

      {/* Analytics Strip */}
      {data?.analytics && (
        <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-5">
          <div className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5">
            <div className="font-mono text-[10px] uppercase text-[#ece7da]/55">Embedded Docs</div>
            <div className="mt-0.5 font-mono text-base font-semibold text-[#a6ff72]">
              {data.analytics.totalKnowledgeDocs ?? 16} (128-d)
            </div>
          </div>
          <div className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5">
            <div className="font-mono text-[10px] uppercase text-[#ece7da]/55">Atlas Indexes</div>
            <div className="mt-0.5 font-mono text-xs font-semibold text-[#a6ff72]">
              {(data.analytics.searchIndexes ?? [])
                .map((idx) => `${idx.name} (${idx.status ?? "READY"})`)
                .join(" · ") || "search + vectorSearch READY"}
            </div>
          </div>
          <div className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5">
            <div className="font-mono text-[10px] uppercase text-[#ece7da]/55">Verifications</div>
            <div className="mt-0.5 font-mono text-base font-semibold text-[#ece7da]">
              {data.analytics.verificationsCount ?? 0}
            </div>
          </div>
          <div className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5">
            <div className="font-mono text-[10px] uppercase text-[#ece7da]/55">Spent Nullifiers</div>
            <div className="mt-0.5 font-mono text-base font-semibold text-[#ffb85c]">
              {data.analytics.nullifiersCount ?? 0}
            </div>
          </div>
          <div className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5">
            <div className="font-mono text-[10px] uppercase text-[#ece7da]/55">Frozen Ciphertexts</div>
            <div className="mt-0.5 font-mono text-base font-semibold text-[#ece7da]">
              {data.analytics.frozenBlobsCount ?? 0}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
        {(data?.results ?? []).slice(0, 4).map((item) => (
          <div
            key={item.docId}
            className="flex flex-col justify-between rounded-lg border border-[rgba(236,231,218,0.12)] bg-[#050706] p-3.5"
          >
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[10px] uppercase tracking-wider text-[#a6ff72]">
                  {item.category} {item.provider ? `· ${item.provider}` : ""}
                </span>
                <span className="font-mono text-[10px] text-[#ffb85c]">
                  RRF {item.rrfScore.toFixed(4)} · vec #{item.vectorRank} ({item.vectorScore.toFixed(2)}) · txt #{item.textRank}
                </span>
              </div>
              <h4 className="mt-1 text-sm font-semibold text-[#ece7da]">{item.title}</h4>
              <p className="mt-1 text-xs leading-relaxed text-[#ece7da]/70">{item.summary}</p>
            </div>
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {item.tags.slice(0, 5).map((t) => (
                <span
                  key={t}
                  className="rounded bg-[#0f1512] px-1.5 py-0.5 font-mono text-[10px] text-[#ece7da]/60"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
