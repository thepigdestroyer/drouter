## Split-Path Knowledge Retrieval: Whole-Library BM25 vs. Atlas Hybrid Search (`10-knowledge`)

Private enclave runs never send a search query to the server; instead, the browser downloads the entire public intelligence corpus from `/api/knowledge/corpus`, verifies its canonical SHA-256 digest, and ranks documents locally with BM25. When a user explicitly uses the public hybrid search explorer, the typed text is scrubbed on the device and again on the server before running MongoDB Atlas `$vectorSearch`, `$search`, and `$rankFusion`.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#f3f1ec","primaryTextColor":"#151515","primaryBorderColor":"#151515","lineColor":"#595752","secondaryColor":"#ffffff","tertiaryColor":"#f3f1ec","fontFamily":"Georgia, serif"}}}%%
flowchart TD
  subgraph PrivateRun["Path A: Private Runs (Zero-Leak Whole-Corpus Download & Local BM25)"]
    FetchCorpus["GET /api/knowledge/corpus (fetchCorpus in src/lib/broker)<br/>Rejects any ?query parameters (HTTP 400)<br/>Identical response for every caller"]
    VerifyCorpus["Browser Hash & Order Verification<br/>sortCorpusDocuments(compareCorpusDocuments)<br/>computeCorpusContentSha256() === contentSha256 & ETag"]
    LocalBM25["rankLocally(query, corpus, k)<br/>In-Browser BM25 (k1=1.2, b=0.75)<br/>Weights: title=3.0, tags=2.5, summary=1.0<br/>Zero Query Terms Sent Over Network"]
    FetchCorpus --> VerifyCorpus --> LocalBM25
  end

  subgraph PublicSearch["Path B: Public Hybrid Search (src/lib/atlas)"]
    DeviceFilter["1. On-Device Redaction<br/>mechanicalRedact(rawQuery) in Browser"]
    ServerFilter["2. Server Boundary Filter (redactForAtlasBoundary)<br/>mechanicalRedact (D3) + attestedPiiFilter (D4)<br/>stripRedactionPlaceholdersForScoring()"]
    EmbedQuery["3. Query Embedding (embedDocumentTextWithProvider)<br/>768-dim vector via attested nomic-embed-text"]
    DeviceFilter --> ServerFilter --> EmbedQuery

    subgraph AtlasCluster["4. MongoDB Atlas Hybrid Search (enclave_intelligence)"]
      VecSearch["$vectorSearch<br/>Index: drouter_vector_index<br/>768-dim cosine similarity"]
      TextSearch["$search<br/>Index: drouter_text_search<br/>Lucene BM25 (title/tags boost 3x, summary)"]
      RankFusion["$rankFusion (Reciprocal Rank Fusion)<br/>score = 1/(60 + vectorRank) + 1/(60 + textRank)"]
      VecSearch --> RankFusion
      TextSearch --> RankFusion
    end

    EmbedQuery --> VecSearch
    ServerFilter --> TextSearch
  end

  CorpusDB[("MongoDB Atlas: drouter.enclave_intelligence<br/>16 Curated Docs + 768-dim Embeddings")]
  CorpusDB --> FetchCorpus
  CorpusDB --> VecSearch
  CorpusDB --> TextSearch

  style LocalBM25 stroke:#d9531e,stroke-width:2.5px,fill:#ffffff,color:#151515
```

- **Queryless Whole-Corpus Endpoint (`GET /api/knowledge/corpus`)**: `src/app/api/knowledge/corpus/route.ts` rejects any URL containing `?` or search parameters (`HTTP 400`) and serves the full `enclave_intelligence` corpus in canonical UTF-16 code-unit order (`sortCorpusDocuments`) with `Cache-Control: public, max-age=300, s-maxage=3600, stale-while-revalidate=86400` so every caller receives identical bytes.
- **Browser Digest Verification & Local BM25 (`src/lib/broker/index.ts`)**: `fetchCorpus()` validates each document schema, sorts documents via `compareCorpusDocuments()`, recomputes `computeCorpusContentSha256(documents) = sha256(utf8(canonicalJson(sortedDocs)))`, verifies both `contentSha256` and the HTTP `ETag`, and ranks locally in memory with `rankLocally()` (`k1 = 1.2`, `b = 0.75`, field weights `title = 3.0`, `tags = 2.5`, `summary = 1.0`).
- **Dual-Stage Privacy Filter on Public Search (`redactForAtlasBoundary`)**: Before any public search query reaches MongoDB Atlas, `src/lib/atlas/privacy-filter.ts` runs deterministic `mechanicalRedact` (first in the browser and again on the server) followed by the attested `pii-filter` enclave (`attestedPiiFilter`) and strips bracketed placeholders (`stripRedactionPlaceholdersForScoring`) without ever logging or storing raw query text.
- **MongoDB Atlas `$vectorSearch`, `$search`, and `$rankFusion` (`runAtlasHybridSearch`)**: `src/lib/atlas/hybrid-search.ts` embeds the scrubbed query into a 768-dimensional vector (`nomic-embed-text`) and executes native `$vectorSearch` on `drouter_vector_index` (cosine similarity, 64 candidates) alongside `$search` on `drouter_text_search` (`lucene.standard`), combining both pipelines via MongoDB 8.0 `$rankFusion` (`score = 1 / (60 + vectorRank) + 1 / (60 + textRank)`).
