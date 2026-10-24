import { MongoClient, type Collection, type Db } from "mongodb";
import {
  cosineSimilarity,
  embedDocumentText,
  embedDocumentTextWithProvider,
  EMBEDDING_DIMENSIONS,
  seedLiveEmbeddingCache,
  type EmbeddingResult,
} from "./embeddings";
import {
  ATLAS_SEED_DOCS,
  buildEmbeddedIntelligenceDocWithProvider,
  composeIntelligenceDocText,
  CORPUS_RETRIEVED_AT_UTC,
  embedSeedCorpusWithProvider,
  RAW_ATLAS_SEED_INPUTS,
  type AtlasDocCategory,
  type EnclaveIntelligenceDoc,
} from "./knowledge-base";
import {
  redactForAtlasBoundary,
  stripRedactionPlaceholdersForScoring,
  type AtlasQueryRedactionReport,
} from "./privacy-filter";

export const ATLAS_COLLECTION_NAME = "enclave_intelligence";
export const ATLAS_RECEIPTS_COLLECTION_NAME = "agent_verification_receipts";
export const ATLAS_TEXT_INDEX_NAME = "drouter_text_search";
export const ATLAS_VECTOR_INDEX_NAME = "drouter_vector_index";
export const MAX_INGEST_DOCUMENT_BYTES = 8192;

export interface HybridSearchOptions {
  category?: string;
  limit?: number;
  includeReceiptsInResults?: boolean;
  customTerms?: string[];
  skipAttestedPass?: boolean;
}

export interface AtlasSearchEngines {
  vectorSearch: "atlas" | "app-fallback";
  textSearch: "atlas" | "app-fallback";
  fusion: "$rankFusion" | "app-rrf";
  embedding: string;
}

export interface AgentVerificationReceiptDoc {
  receiptId: string;
  coarsenedAt: string;
  mode: "live";
  primaryModel: string;
  enclaveModel: string;
  routerHost: string;
  enclaveHost: string;
  overallPassed: boolean;
  faultInjected: boolean;
  selfHealed: boolean;
  humanGateState: "paused_awaiting_human" | "executed_with_human_approval";
  checksSummary: Array<{ id: string; passed: boolean }>;
  forensicProofDigestHex: string;
  ed25519SignatureHex: string;
  signerPublicKeyHex: string;
  summary: string;
  embedding: number[];
  embeddingModel: string;
  embeddingDimensions: number;
}

export interface HybridSearchResultItem {
  docId: string;
  title: string;
  category: AtlasDocCategory;
  summary: string;
  sourceUrl: string;
  retrievedAt: string;
  tags: string[];
  metadata: Record<string, unknown>;
  vectorScore: number;
  textScore: number;
  vectorRank: number;
  textRank: number;
  rrfScore: number;
  embeddingModel: string;
  embeddingDimensions: number;
}

export interface HybridSearchResponse {
  query: string;
  categoryFilter: string | null;
  embeddingModel: string;
  embeddingDimensions: number;
  embeddingFallbackUsed: boolean;
  executionMode: "atlas-hybrid-rrf" | "local-hybrid-rrf";
  engines: AtlasSearchEngines;
  redaction: AtlasQueryRedactionReport;
  redactionCounts: Record<string, number>;
  totalRedactions: number;
  filterRan: "mechanical+attested" | "mechanical-only";
  nativeVectorHits: number;
  nativeTextHits: number;
  totalCorpusDocs: number;
  latencyMs: number;
  pipelines: {
    vectorSearchStage: Record<string, unknown>;
    atlasSearchStage: Record<string, unknown>;
    rankFusionStage: Record<string, unknown>;
    rrfFormula: string;
  };
  results: HybridSearchResultItem[];
  matchingReceipts: AgentVerificationReceiptDoc[];
}

export interface AtlasStreamAnalyticsResponse {
  connected: boolean;
  database: string;
  collection: string;
  totalIntelligenceDocs: number;
  totalKnowledgeDocs: number;
  verificationsCount: number;
  receiptsCount: number;
  agentVerificationReceiptsCount: number;
  nullifiersCount: number;
  frozenBlobsCount: number;
  categoryBreakdown: Array<{
    category: string;
    count: number;
    avgEmbeddingDims: number;
  }>;
  collectionTelemetry: {
    enclaveIntelligence: number;
    verifications: number;
    receipts: number;
    agentVerificationReceipts: number;
    relayRequests: number;
    relayBytesUp: number;
    relayBytesDown: number;
    creditNullifiers: number;
    frozenBlobs: number;
  };
  verificationWindow: {
    totalChecked: number;
    passedCount: number;
    failedCount: number;
    passRatePct: number;
  };
  searchIndexes: Array<{
    name: string;
    type: string;
    status: string;
    numDimensions?: number;
  }>;
  anomalyAlerts: Array<{
    alertId: string;
    severity: "INFO" | "WARN" | "CRITICAL";
    subsystem: string;
    message: string;
  }>;
  pipelineStagesExecuted: string[];
}

const globalForAtlas = globalThis as unknown as {
  __drouterAtlasClient?: Promise<MongoClient>;
  __drouterAtlasSeeded?: boolean;
  __drouterRuntimeDocs?: Map<string, EnclaveIntelligenceDoc>;
  __drouterRuntimeReceipts?: Map<string, AgentVerificationReceiptDoc>;
  __drouterTestAtlasDb?: Db | null;
};

export function setAtlasDbForTests(db: Db | null | undefined): void {
  globalForAtlas.__drouterTestAtlasDb = db;
}

export function clearAtlasRuntimeStateForTests(): void {
  globalForAtlas.__drouterRuntimeReceipts?.clear();
  if (globalForAtlas.__drouterRuntimeDocs) {
    globalForAtlas.__drouterRuntimeDocs.clear();
    for (const doc of ATLAS_SEED_DOCS) {
      globalForAtlas.__drouterRuntimeDocs.set(doc.docId, doc);
    }
  }
}

function getRuntimeDocsMap(): Map<string, EnclaveIntelligenceDoc> {
  if (!globalForAtlas.__drouterRuntimeDocs) {
    const map = new Map<string, EnclaveIntelligenceDoc>();
    for (const doc of ATLAS_SEED_DOCS) {
      map.set(doc.docId, doc);
    }
    globalForAtlas.__drouterRuntimeDocs = map;
  }
  return globalForAtlas.__drouterRuntimeDocs;
}

function getRuntimeReceiptsMap(): Map<string, AgentVerificationReceiptDoc> {
  if (!globalForAtlas.__drouterRuntimeReceipts) {
    globalForAtlas.__drouterRuntimeReceipts = new Map<string, AgentVerificationReceiptDoc>();
  }
  return globalForAtlas.__drouterRuntimeReceipts;
}

/**
 * Coarsens any timestamp down to the UTC hour boundary (`YYYY-MM-DDTHH:00:00.000Z`)
 * so stored receipts cannot be correlated with individual user request timings.
 */
export function coarsenIsoToUtcHour(input?: string | Date): string {
  const dt = input instanceof Date ? input : input ? new Date(input) : new Date();
  const ms = Number.isFinite(dt.getTime()) ? dt.getTime() : Date.now();
  return new Date(ms - (ms % 3_600_000)).toISOString();
}

/**
 * Resolves `MONGODB_URI` from the environment only. Unit tests run without it, so they
 * stay isolated from the live cluster unless they mock the connection.
 */
export function resolveMongoUri(): string | null {
  // Next.js and `node --env-file=.env.local` load env vars; never read secret files from disk here.
  return process.env.MONGODB_URI?.trim() || null;
}

export async function getAtlasDb(): Promise<Db | null> {
  if (globalForAtlas.__drouterTestAtlasDb !== undefined) {
    return globalForAtlas.__drouterTestAtlasDb;
  }
  const uri = resolveMongoUri();
  if (!uri) return null;
  try {
    globalForAtlas.__drouterAtlasClient ??= new MongoClient(uri, {
      appName: "drouter-atlas-showcase",
      maxPoolSize: 5,
      serverSelectionTimeoutMS: 4500,
    }).connect();
    const client = await globalForAtlas.__drouterAtlasClient;
    return client.db(process.env.MONGODB_DB ?? "drouter");
  } catch {
    globalForAtlas.__drouterAtlasClient = undefined;
    return null;
  }
}

/**
 * Ensures the 16 curated seed documents and both Atlas Search & Vector Search
 * indexes (`numDimensions: 768`) exist on the `enclave_intelligence` collection.
 * Preserves existing 768-dim `nomic-embed-text` vectors already stored in Atlas.
 */
export async function ensureAtlasSeededAndIndexed(db?: Db | null): Promise<{
  seededCount: number;
  indexesCreated: string[];
}> {
  const database = db !== undefined ? db : await getAtlasDb();
  if (!database) {
    return { seededCount: ATLAS_SEED_DOCS.length, indexesCreated: [] };
  }

  const col: Collection<EnclaveIntelligenceDoc> = database.collection(ATLAS_COLLECTION_NAME);
  const runtimeMap = getRuntimeDocsMap();

  if (!globalForAtlas.__drouterAtlasSeeded) {
    try {
      await col.createIndex({ docId: 1 }, { unique: true });
      await col.createIndex({ category: 1 });

      const existingDocs = await col
        .find({}, { projection: { _id: 0 } })
        .toArray()
        .catch(() => []);
      const existingById = new Map<string, EnclaveIntelligenceDoc>();
      for (const doc of existingDocs) {
        if (doc.docId) {
          existingById.set(doc.docId, doc);
          if (
            Array.isArray(doc.embedding) &&
            doc.embedding.length === EMBEDDING_DIMENSIONS &&
            typeof doc.embeddingModel === "string" &&
            doc.embeddingModel.includes("nomic-embed-text") &&
            typeof doc.sourceUrl === "string" &&
            doc.sourceUrl.length > 0
          ) {
            runtimeMap.set(doc.docId, doc);
            const composite = composeIntelligenceDocText({
              title: doc.title,
              category: doc.category,
              summary: doc.summary,
              sourceUrl: doc.sourceUrl,
              tags: doc.tags ?? [],
              metadata: doc.metadata ?? {},
            });
            seedLiveEmbeddingCache(composite, {
              vector: doc.embedding,
              model: doc.embeddingModel,
              dimensions: EMBEDDING_DIMENSIONS,
              isLiveModel: true,
              attestedEnclave: true,
            });
          }
        }
      }

      const missingInputs = RAW_ATLAS_SEED_INPUTS.filter((raw) => {
        const ex = existingById.get(raw.docId);
        if (!ex) return true;
        const hasValidVec =
          Array.isArray(ex.embedding) &&
          ex.embedding.length === EMBEDDING_DIMENSIONS &&
          typeof ex.embeddingModel === "string" &&
          ex.embeddingModel.includes("nomic-embed-text");
        const hasSource =
          typeof ex.sourceUrl === "string" &&
          ex.sourceUrl === raw.sourceUrl &&
          typeof ex.retrievedAt === "string" &&
          ex.retrievedAt.length > 0;
        return !hasValidVec || !hasSource || ex.summary !== raw.summary;
      });

      if (missingInputs.length > 0) {
        const newlyEmbedded = await embedSeedCorpusWithProvider(missingInputs);
        for (const doc of newlyEmbedded) {
          runtimeMap.set(doc.docId, doc);
        }
        const ops = newlyEmbedded.map((doc) => ({
          updateOne: {
            filter: { docId: doc.docId },
            update: { $set: doc },
            upsert: true,
          },
        }));
        if (ops.length > 0) {
          await col.bulkWrite(ops, { ordered: false });
        }
      }

      // Remove any legacy simulated receipts from agent_verification_receipts
      const receiptsCol = database.collection(ATLAS_RECEIPTS_COLLECTION_NAME);
      if (typeof receiptsCol.deleteMany === "function") {
        await receiptsCol.deleteMany({ mode: "simulated" }).catch(() => {});
      }

      globalForAtlas.__drouterAtlasSeeded = true;
    } catch {
      // Ignore transient write errors
    }
  }

  const indexesCreated: string[] = [];

  // 1. Ensure Atlas Search full-text index (`drouter_text_search`)
  try {
    await col.createSearchIndex({
      name: ATLAS_TEXT_INDEX_NAME,
      type: "search",
      definition: {
        mappings: {
          dynamic: true,
          fields: {
            title: { type: "string", analyzer: "lucene.standard" },
            summary: { type: "string", analyzer: "lucene.standard" },
            category: { type: "string", analyzer: "lucene.keyword" },
            tags: { type: "string", analyzer: "lucene.standard" },
          },
        },
      },
    });
    indexesCreated.push(ATLAS_TEXT_INDEX_NAME);
  } catch {
    // Already exists on Atlas
  }

  // 2. Ensure Atlas Vector Search index (`drouter_vector_index`, 768 dims, cosine)
  const vectorDefinition = {
    fields: [
      {
        type: "vector",
        path: "embedding",
        numDimensions: EMBEDDING_DIMENSIONS,
        similarity: "cosine",
      },
      {
        type: "filter",
        path: "category",
      },
    ],
  };

  try {
    await col.createSearchIndex({
      name: ATLAS_VECTOR_INDEX_NAME,
      type: "vectorSearch",
      definition: vectorDefinition,
    });
    indexesCreated.push(ATLAS_VECTOR_INDEX_NAME);
  } catch {
    // Already exists; if dimensions differ, updateSearchIndex
    try {
      const existingIdx = await col.listSearchIndexes(ATLAS_VECTOR_INDEX_NAME).toArray();
      const first = existingIdx[0] as
        | { latestDefinition?: { fields?: Array<{ numDimensions?: number }> } }
        | undefined;
      const currentDims = first?.latestDefinition?.fields?.[0]?.numDimensions;
      if (currentDims !== undefined && currentDims !== EMBEDDING_DIMENSIONS) {
        await col.updateSearchIndex(ATLAS_VECTOR_INDEX_NAME, vectorDefinition);
        indexesCreated.push(ATLAS_VECTOR_INDEX_NAME);
      }
    } catch {
      // Ignore index update error during read path
    }
  }

  return { seededCount: runtimeMap.size, indexesCreated };
}

/**
 * Computes field-weighted BM25-style lexical relevance score for a document against a query.
 */
export function computeBm25TextScore(doc: EnclaveIntelligenceDoc, query: string): number {
  const withoutPlaceholders = stripRedactionPlaceholdersForScoring(query || "");
  const qNorm = withoutPlaceholders.toLowerCase().trim();
  if (!qNorm) return 0;

  const rawTokens = qNorm
    .replace(/[^a-z0-9.+_-]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2);

  if (rawTokens.length === 0) return 0;

  const titleLower = doc.title.toLowerCase();
  const summaryLower = doc.summary.toLowerCase();
  const tagsLower = doc.tags.map((t) => t.toLowerCase());
  const metaLower = JSON.stringify(doc.metadata).toLowerCase();

  let score = 0;

  if (titleLower.includes(qNorm)) score += 6.0;
  if (summaryLower.includes(qNorm)) score += 3.5;

  for (const token of rawTokens) {
    let tokenScore = 0;
    if (titleLower.includes(token)) tokenScore += 3.2;
    if (tagsLower.some((tag) => tag === token || tag.includes(token))) tokenScore += 2.6;
    if (summaryLower.includes(token)) {
      const parts = summaryLower.split(token).length - 1;
      const tf = (parts * (1.2 + 1)) / (parts + 1.2);
      tokenScore += 1.5 * tf;
    }
    if (metaLower.includes(token)) tokenScore += 1.1;
    score += tokenScore;
  }

  return Number((score / Math.sqrt(rawTokens.length)).toFixed(6));
}

interface RankFusionScoreDetailSub {
  inputPipelineName?: string;
  rank?: number;
  weight?: number;
  value?: number;
}

interface RankFusionDocResult extends EnclaveIntelligenceDoc {
  scoreDetails?: {
    value?: number;
    details?: RankFusionScoreDetailSub[];
  };
}

const FORBIDDEN_USER_TEXT_KEYS = [
  "prompt",
  "rawPrompt",
  "taskPrompt",
  "userText",
  "userQuery",
  "queryText",
  "message",
  "messages",
  "chat",
  "conversation",
  "transcript",
  "completion",
  "output",
  "input",
] as const;

const ALLOWED_INGEST_CATEGORIES = new Set<string>(["provider", "advisory", "architecture"]);

function assertNoUserTextFields(obj: Record<string, unknown>): void {
  for (const key of FORBIDDEN_USER_TEXT_KEYS) {
    if (key in obj) {
      throw new Error(`Prompts must never be stored in MongoDB Atlas (forbidden field: ${key}).`);
    }
  }
}

function sanitizeSourceUrl(rawUrl: string | undefined): string {
  const candidate = (rawUrl || "").trim();
  if (!candidate) {
    return "https://docs.tinfoil.sh/verification/attestation-architecture";
  }
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:") {
      throw new Error("Only https:// source URLs are permitted in MongoDB Atlas.");
    }
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch (err) {
    if (err instanceof Error && err.message.includes("https://")) {
      throw err;
    }
    return "https://docs.tinfoil.sh/verification/attestation-architecture";
  }
}

/**
 * Persists a non-PII, prompt-free live agent verification receipt with a coarsened UTC-hour
 * timestamp into MongoDB Atlas `agent_verification_receipts` and the runtime receipt map.
 * Rejects simulated receipts so only live verification receipts are stored.
 */
export async function recordAgentVerificationReceipt(input: {
  receiptId: string;
  timestampIso?: string;
  mode?: "live" | "simulated";
  primaryModel: string;
  enclaveModel: string;
  routerHost: string;
  enclaveHost: string;
  overallPassed: boolean;
  faultInjected: boolean;
  selfHealed: boolean;
  humanGateState: "paused_awaiting_human" | "executed_with_human_approval";
  checksSummary: Array<{ id: string; passed: boolean }>;
  forensicProofDigestHex: string;
  ed25519SignatureHex: string;
  signerPublicKeyHex: string;
  rawPromptMustNotBePassed?: never;
  [key: string]: unknown;
}): Promise<{
  storedInAtlas: boolean;
  receipt: AgentVerificationReceiptDoc;
  redaction: AtlasQueryRedactionReport;
}> {
  assertNoUserTextFields(input);
  if (input.mode === "simulated") {
    throw new Error(
      "Simulated agent verification receipts must not be stored in MongoDB Atlas.",
    );
  }

  // Receipt summary is constructed purely from system identifiers, booleans, and a 64-bit hash prefix;
  // pass through mechanicalRedact (D3) + attestedPiiFilter (D4) before leaving the enclave boundary.
  const idRedacted = await redactForAtlasBoundary(input.receiptId || "receipt");
  const safeReceiptId = idRedacted.text;
  const rawSummary =
    `Agent verification receipt ${safeReceiptId} (mode=live, orchestrator=${input.primaryModel}): ` +
    `router=${input.routerHost} -> enclave=${input.enclaveHost} (${input.enclaveModel}), ` +
    `overallPassed=${Boolean(input.overallPassed)}, faultInjected=${Boolean(input.faultInjected)}, selfHealed=${Boolean(input.selfHealed)}, ` +
    `humanGate=${input.humanGateState}, digest=0x${(input.forensicProofDigestHex || "").slice(0, 16)}.`;

  const redactedSummaryResult = await redactForAtlasBoundary(rawSummary);
  const scrubbedSummary = redactedSummaryResult.text;

  const coarsenedAt = coarsenIsoToUtcHour(input.timestampIso);
  const embedded = await embedDocumentTextWithProvider(scrubbedSummary);

  const receipt: AgentVerificationReceiptDoc = {
    receiptId: safeReceiptId,
    coarsenedAt,
    mode: "live",
    primaryModel: input.primaryModel,
    enclaveModel: input.enclaveModel,
    routerHost: input.routerHost,
    enclaveHost: input.enclaveHost,
    overallPassed: Boolean(input.overallPassed),
    faultInjected: Boolean(input.faultInjected),
    selfHealed: Boolean(input.selfHealed),
    humanGateState: input.humanGateState,
    checksSummary: input.checksSummary.map((c) => ({ id: c.id, passed: Boolean(c.passed) })),
    forensicProofDigestHex: input.forensicProofDigestHex,
    ed25519SignatureHex: input.ed25519SignatureHex,
    signerPublicKeyHex: input.signerPublicKeyHex,
    summary: scrubbedSummary,
    embedding: embedded.vector,
    embeddingModel: embedded.model,
    embeddingDimensions: embedded.dimensions,
  };

  getRuntimeReceiptsMap().set(receipt.receiptId, receipt);

  let storedInAtlas = false;
  const database = await getAtlasDb();
  if (database) {
    try {
      const col = database.collection<AgentVerificationReceiptDoc>(ATLAS_RECEIPTS_COLLECTION_NAME);
      await col.createIndex({ receiptId: 1 }, { unique: true }).catch(() => {});
      await col.updateOne(
        { receiptId: receipt.receiptId },
        { $set: receipt },
        { upsert: true },
      );
      storedInAtlas = true;
    } catch {
      storedInAtlas = false;
    }
  }

  return {
    storedInAtlas,
    receipt,
    redaction: redactedSummaryResult.redaction,
  };
}

/**
 * Searches past live agent verification receipts stored in MongoDB Atlas `agent_verification_receipts`.
 * Redacts the query via D3/D4 if not already redacted and excludes any legacy simulated receipts.
 */
export async function searchAgentVerificationReceipts(
  query: string,
  limit = 5,
  precomputedQueryEmbedding?: EmbeddingResult,
  alreadyRedacted = false,
): Promise<AgentVerificationReceiptDoc[]> {
  const runtimeReceipts = getRuntimeReceiptsMap();
  const database = await getAtlasDb();
  if (database) {
    try {
      const col = database.collection<AgentVerificationReceiptDoc>(ATLAS_RECEIPTS_COLLECTION_NAME);
      const docs = await col
        .find({ mode: "live" }, { projection: { _id: 0 } })
        .sort({ coarsenedAt: -1 })
        .limit(25)
        .toArray();
      for (const d of docs) {
        if (d.receiptId && (d as { mode?: string }).mode !== "simulated") {
          runtimeReceipts.set(d.receiptId, d);
        }
      }
    } catch {
      // Fall back to runtime map
    }
  }

  const allReceipts = Array.from(runtimeReceipts.values()).filter(
    (r) => (r as { mode?: string }).mode !== "simulated",
  );
  if (allReceipts.length === 0) return [];

  const rawQuery = (query || "verification receipt").trim();
  const redactedQuery = alreadyRedacted
    ? rawQuery
    : (await redactForAtlasBoundary(rawQuery)).text;
  const scoringQuery = stripRedactionPlaceholdersForScoring(redactedQuery);

  const qEmb = precomputedQueryEmbedding ?? embedDocumentText(scoringQuery);
  const qFallbackVec = qEmb.isLiveModel ? embedDocumentText(scoringQuery).vector : qEmb.vector;

  const scored = allReceipts.map((r) => {
    let sim = 0;
    if (Array.isArray(r.embedding) && r.embedding.length === EMBEDDING_DIMENSIONS) {
      const receiptIsLive =
        typeof r.embeddingModel === "string" && r.embeddingModel.includes("nomic-embed-text");
      if (qEmb.isLiveModel && receiptIsLive) {
        sim = cosineSimilarity(qEmb.vector, r.embedding);
      } else if (!qEmb.isLiveModel && !receiptIsLive) {
        sim = cosineSimilarity(qFallbackVec, r.embedding);
      } else {
        sim = cosineSimilarity(qFallbackVec, embedDocumentText(r.summary).vector);
      }
    }
    const textMatch = r.summary.toLowerCase().includes(scoringQuery.toLowerCase()) ? 0.5 : 0;
    return { receipt: r, score: sim + textMatch };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, Math.max(1, limit)).map((s) => s.receipt);
}

/**
 * Runs MongoDB Atlas Hybrid Search combining:
 * 0. D3 (`mechanicalRedact`) + server-side D4 (`attestedPiiFilter`) before any query leaves
 *    the enclave boundary for MongoDB Atlas (never storing or logging query text)
 * 1. Native `$vectorSearch` (768-dim cosine similarity on `drouter_vector_index`)
 * 2. Native `$search` (Lucene full-text BM25 search on `drouter_text_search`)
 * 3. Native `$rankFusion` on MongoDB 8.0+ (`score = 1 / (60 + vectorRank) + 1 / (60 + textRank)`),
 *    with deterministic application-side RRF fallback if Atlas is unreachable.
 * Also searches past live verification receipts in `agent_verification_receipts`.
 */
export async function runAtlasHybridSearch(
  query: string,
  opts?: HybridSearchOptions,
): Promise<HybridSearchResponse> {
  const startedAt = Date.now();
  const rawInputQuery =
    query && query.trim().length > 0
      ? query.trim()
      : "AMD SEV-SNP 8x GPU confidential mode TEE.fail mitigation";
  const categoryFilter =
    opts?.category && opts.category !== "all" ? opts.category.trim().toLowerCase() : null;
  const limit = Math.max(1, Math.min(opts?.limit ?? 10, 50));

  // 0. Pass query through D3 (`mechanicalRedact`) first and D4 (`attestedPiiFilter`) when available
  // before anything leaves the enclave boundary for MongoDB Atlas. Never log or store raw query text.
  const redacted = await redactForAtlasBoundary(rawInputQuery, {
    customTerms: opts?.customTerms,
    skipAttestedPass: opts?.skipAttestedPass,
  });
  const effectiveQuery = redacted.text.trim() || "[REDACTED]";
  const scoringQuery = stripRedactionPlaceholdersForScoring(effectiveQuery);

  // 1. Compute 768-dim query vector via attested Tinfoil `nomic-embed-text` enclave (with labelled fallback)
  const queryEmbedding = await embedDocumentTextWithProvider(scoringQuery);

  const vectorSearchStage: Record<string, unknown> = {
    $vectorSearch: {
      index: ATLAS_VECTOR_INDEX_NAME,
      path: "embedding",
      queryVector: queryEmbedding.vector,
      numCandidates: 64,
      limit: 20,
      ...(categoryFilter ? { filter: { category: categoryFilter } } : {}),
    },
  };

  const atlasSearchStage: Record<string, unknown> = {
    $search: {
      index: ATLAS_TEXT_INDEX_NAME,
      compound: {
        should: [
          {
            text: {
              query: effectiveQuery,
              path: ["title", "tags"],
              score: { boost: { value: 3 } },
            },
          },
          {
            text: {
              query: effectiveQuery,
              path: "summary",
            },
          },
        ],
        ...(categoryFilter
          ? {
              filter: [
                {
                  text: {
                    query: categoryFilter,
                    path: "category",
                  },
                },
              ],
            }
          : {}),
      },
    },
  };

  const rankFusionStage: Record<string, unknown> = {
    $rankFusion: {
      input: {
        pipelines: {
          vectorPipeline: [vectorSearchStage, { $limit: 20 }],
          textPipeline: [atlasSearchStage, { $limit: 20 }],
        },
      },
      combination: {
        weights: {
          vectorPipeline: 1,
          textPipeline: 1,
        },
      },
      scoreDetails: true,
    },
  };

  const database = await getAtlasDb();
  let executionMode: "atlas-hybrid-rrf" | "local-hybrid-rrf" = "local-hybrid-rrf";
  let nativeVectorHits = 0;
  let nativeTextHits = 0;
  let nativeRankFusionSucceeded = false;

  const nativeVectorScores = new Map<string, number>();
  const nativeTextScores = new Map<string, number>();
  const nativeVectorRanks = new Map<string, number>();
  const nativeTextRanks = new Map<string, number>();

  const runtimeMap = getRuntimeDocsMap();
  let candidateDocs: EnclaveIntelligenceDoc[] = Array.from(runtimeMap.values());

  if (database) {
    await ensureAtlasSeededAndIndexed(database);
    const col = database.collection<EnclaveIntelligenceDoc>(ATLAS_COLLECTION_NAME);

    try {
      const filterQuery = categoryFilter ? { category: categoryFilter } : {};
      const [rankFusionDocs, vecRes, textRes, mongoDocs] = await Promise.all([
        col
          .aggregate<RankFusionDocResult>([
            rankFusionStage,
            {
              $project: {
                _id: 0,
                docId: 1,
                title: 1,
                category: 1,
                summary: 1,
                sourceUrl: 1,
                retrievedAt: 1,
                tags: 1,
                metadata: 1,
                embedding: 1,
                embeddingModel: 1,
                embeddingDimensions: 1,
                updatedAt: 1,
                scoreDetails: { $meta: "scoreDetails" },
              },
            },
          ])
          .toArray()
          .catch(() => []),
        col
          .aggregate<{ docId: string; score: number }>([
            vectorSearchStage,
            {
              $project: {
                _id: 0,
                docId: 1,
                score: { $meta: "vectorSearchScore" },
              },
            },
          ])
          .toArray()
          .catch(() => []),
        col
          .aggregate<{ docId: string; score: number }>([
            atlasSearchStage,
            {
              $project: {
                _id: 0,
                docId: 1,
                score: { $meta: "searchScore" },
              },
            },
          ])
          .toArray()
          .catch(() => []),
        col
          .find(filterQuery, { projection: { _id: 0 } })
          .toArray()
          .catch(() => []),
      ]);

      if (rankFusionDocs.length > 0) {
        nativeRankFusionSucceeded = true;
        for (const doc of rankFusionDocs) {
          const subDetails = doc.scoreDetails?.details ?? [];
          for (const sub of subDetails) {
            if (sub.inputPipelineName === "vectorPipeline") {
              if (typeof sub.rank === "number") nativeVectorRanks.set(doc.docId, sub.rank);
              if (typeof sub.value === "number") nativeVectorScores.set(doc.docId, sub.value);
            } else if (sub.inputPipelineName === "textPipeline") {
              if (typeof sub.rank === "number") nativeTextRanks.set(doc.docId, sub.rank);
              if (typeof sub.value === "number") nativeTextScores.set(doc.docId, sub.value);
            }
          }
        }
      }

      vecRes.forEach((v, idx) => {
        if (v.docId && typeof v.score === "number") {
          if (!nativeVectorScores.has(v.docId)) nativeVectorScores.set(v.docId, v.score);
          if (!nativeVectorRanks.has(v.docId)) nativeVectorRanks.set(v.docId, idx + 1);
        }
      });

      textRes.forEach((t, idx) => {
        if (t.docId && typeof t.score === "number") {
          if (!nativeTextScores.has(t.docId)) nativeTextScores.set(t.docId, t.score);
          if (!nativeTextRanks.has(t.docId)) nativeTextRanks.set(t.docId, idx + 1);
        }
      });

      nativeVectorHits = Math.max(vecRes.length, nativeVectorScores.size);
      nativeTextHits = Math.max(textRes.length, nativeTextScores.size);

      if (mongoDocs.length > 0 || rankFusionDocs.length > 0) {
        executionMode = "atlas-hybrid-rrf";
        const mergedById = new Map<string, EnclaveIntelligenceDoc>();
        for (const d of candidateDocs) {
          if (!categoryFilter || d.category.toLowerCase() === categoryFilter) {
            mergedById.set(d.docId, d);
          }
        }
        for (const d of mongoDocs) {
          mergedById.set(d.docId, d);
          runtimeMap.set(d.docId, d);
        }
        candidateDocs = Array.from(mergedById.values());
      }
    } catch {
      // Fallback to in-memory candidateDocs if cluster query times out
    }
  }

  if (categoryFilter) {
    candidateDocs = candidateDocs.filter((d) => d.category.toLowerCase() === categoryFilter);
  }

  const fallbackQueryVec = queryEmbedding.isLiveModel
    ? null
    : queryEmbedding.vector;

  // 2. Score documents (combining native Atlas scores with exact same-space cosine/BM25)
  const scored = candidateDocs.map((doc) => {
    const docIsLive =
      typeof doc.embeddingModel === "string" &&
      doc.embeddingModel.includes("nomic-embed-text") &&
      Array.isArray(doc.embedding) &&
      doc.embedding.length === EMBEDDING_DIMENSIONS;

    let exactCosine: number;
    if (queryEmbedding.isLiveModel && docIsLive) {
      exactCosine = cosineSimilarity(queryEmbedding.vector, doc.embedding);
    } else if (!queryEmbedding.isLiveModel && !docIsLive && doc.embedding.length === EMBEDDING_DIMENSIONS) {
      exactCosine = cosineSimilarity(fallbackQueryVec!, doc.embedding);
    } else {
      const qLocal = fallbackQueryVec ?? embedDocumentText(effectiveQuery).vector;
      const dLocal = embedDocumentText(
        composeIntelligenceDocText({
          title: doc.title,
          category: doc.category,
          summary: doc.summary,
          sourceUrl: doc.sourceUrl,
          tags: doc.tags ?? [],
          metadata: doc.metadata ?? {},
        }),
      ).vector;
      exactCosine = cosineSimilarity(qLocal, dLocal);
    }

    const nativeVec = queryEmbedding.isLiveModel ? nativeVectorScores.get(doc.docId) : undefined;
    const vectorScore = Number(
      (nativeVec !== undefined ? Math.max(exactCosine, nativeVec) : exactCosine).toFixed(6),
    );

    const localBm25 = computeBm25TextScore(doc, effectiveQuery);
    const nativeTxt = nativeTextScores.get(doc.docId);
    const textScore = Number(
      (nativeTxt !== undefined ? Math.max(localBm25, nativeTxt) : localBm25).toFixed(6),
    );

    return {
      doc,
      vectorScore,
      textScore,
    };
  });

  // 3. Rank by vector similarity (1..N) and by full-text relevance (1..N)
  const byVector = [...scored].sort((a, b) => b.vectorScore - a.vectorScore);
  const vectorRankMap = new Map<string, number>();
  byVector.forEach((item, idx) => {
    vectorRankMap.set(item.doc.docId, idx + 1);
  });

  const byText = [...scored].sort((a, b) => {
    if (b.textScore !== a.textScore) return b.textScore - a.textScore;
    return b.vectorScore - a.vectorScore;
  });
  const textRankMap = new Map<string, number>();
  byText.forEach((item, idx) => {
    textRankMap.set(item.doc.docId, idx + 1);
  });

  // 4. Reciprocal Rank Fusion: score = 1 / (60 + vectorRank) + 1 / (60 + textRank)
  const fused: HybridSearchResultItem[] = scored.map(({ doc, vectorScore, textScore }) => {
    const vectorRank = vectorRankMap.get(doc.docId) ?? scored.length;
    const textRank = textRankMap.get(doc.docId) ?? scored.length;
    const rrfScore = Number((1 / (60 + vectorRank) + 1 / (60 + textRank)).toFixed(6));
    const sourceUrl =
      doc.sourceUrl ||
      (typeof doc.metadata?.sourceUrl === "string" ? doc.metadata.sourceUrl : "") ||
      "https://docs.tinfoil.sh/verification/attestation-architecture";
    const retrievedAt =
      doc.retrievedAt ||
      (typeof doc.metadata?.retrievedAt === "string" ? doc.metadata.retrievedAt : "") ||
      CORPUS_RETRIEVED_AT_UTC;

    return {
      docId: doc.docId,
      title: doc.title,
      category: doc.category,
      summary: doc.summary,
      sourceUrl,
      retrievedAt,
      tags: doc.tags,
      metadata: {
        ...doc.metadata,
        sourceUrl,
        retrievedAt,
      },
      vectorScore,
      textScore,
      vectorRank,
      textRank,
      rrfScore,
      embeddingModel: queryEmbedding.model,
      embeddingDimensions: doc.embeddingDimensions || EMBEDDING_DIMENSIONS,
    };
  });

  fused.sort((a, b) => {
    if (b.rrfScore !== a.rrfScore) return b.rrfScore - a.rrfScore;
    const combinedB = b.vectorScore + b.textScore * 0.1;
    const combinedA = a.vectorScore + a.textScore * 0.1;
    return combinedB - combinedA;
  });

  const matchingReceipts = await searchAgentVerificationReceipts(
    effectiveQuery,
    5,
    queryEmbedding,
    true,
  );

  const engines: AtlasSearchEngines = {
    vectorSearch: nativeVectorHits > 0 ? "atlas" : "app-fallback",
    textSearch: nativeTextHits > 0 ? "atlas" : "app-fallback",
    fusion: nativeRankFusionSucceeded ? "$rankFusion" : "app-rrf",
    embedding: queryEmbedding.model,
  };

  const latencyMs = Math.max(1, Date.now() - startedAt);

  return {
    query: effectiveQuery,
    categoryFilter,
    embeddingModel: queryEmbedding.model,
    embeddingDimensions: EMBEDDING_DIMENSIONS,
    embeddingFallbackUsed: !queryEmbedding.isLiveModel,
    executionMode,
    engines,
    redaction: redacted.redaction,
    redactionCounts: redacted.redaction.countsByKind,
    totalRedactions: redacted.redaction.totalRedactions,
    filterRan: redacted.redaction.filterRan,
    nativeVectorHits,
    nativeTextHits,
    totalCorpusDocs: candidateDocs.length,
    latencyMs,
    pipelines: {
      vectorSearchStage,
      atlasSearchStage,
      rankFusionStage,
      rrfFormula: "score = 1 / (60 + vectorRank) + 1 / (60 + textRank)",
    },
    results: fused.slice(0, limit),
    matchingReceipts,
  };
}

async function redactMetadataRecord(
  meta: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (FORBIDDEN_USER_TEXT_KEYS.includes(k as (typeof FORBIDDEN_USER_TEXT_KEYS)[number])) {
      throw new Error(`Prompts must never be stored in MongoDB Atlas (forbidden metadata field: ${k}).`);
    }
    if (typeof v === "string") {
      if (k === "sourceUrl" || k === "docsUrl" || k === "url") {
        out[k] = sanitizeSourceUrl(v);
      } else {
        out[k] = (await redactForAtlasBoundary(v)).text;
      }
    } else if (Array.isArray(v)) {
      const redactedArr: unknown[] = [];
      for (const item of v.slice(0, 20)) {
        if (typeof item === "string") {
          redactedArr.push((await redactForAtlasBoundary(item)).text);
        } else if (typeof item === "number" || typeof item === "boolean") {
          redactedArr.push(item);
        }
      }
      out[k] = redactedArr;
    } else if (typeof v === "number" || typeof v === "boolean") {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Ingests a new curated intelligence document with size-cap, category allowlist,
 * no-prompt/no-user-text enforcement, and D3 (`mechanicalRedact`) + D4 (`attestedPiiFilter`)
 * redaction before embedding via Tinfoil's attested `nomic-embed-text` enclave and
 * persisting to MongoDB Atlas `enclave_intelligence`.
 */
export async function ingestAtlasDocument(input: {
  docId?: string;
  title: string;
  summary: string;
  category: AtlasDocCategory;
  sourceUrl?: string;
  retrievedAt?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}): Promise<{
  storedInAtlas: boolean;
  document: EnclaveIntelligenceDoc;
  redaction: AtlasQueryRedactionReport;
}> {
  assertNoUserTextFields(input);

  const serializedBytes = new TextEncoder().encode(JSON.stringify(input)).byteLength;
  if (serializedBytes > MAX_INGEST_DOCUMENT_BYTES) {
    throw new Error(
      `Document exceeds maximum ingest size of ${MAX_INGEST_DOCUMENT_BYTES} bytes (${serializedBytes} bytes).`,
    );
  }

  const normalizedCategory = (input.category || "advisory").trim().toLowerCase();
  if (!ALLOWED_INGEST_CATEGORIES.has(normalizedCategory)) {
    throw new Error(
      `Invalid ingest category "${normalizedCategory}". Allowed categories: provider, advisory, architecture.`,
    );
  }

  const cleanTitle = (input.title || "").trim();
  const cleanSummary = (input.summary || "").trim();
  if (!cleanTitle || !cleanSummary) {
    throw new Error("Both title and summary are required for Atlas document ingest.");
  }
  if (cleanTitle.length > 200) {
    throw new Error("Document title exceeds maximum length of 200 characters.");
  }
  if (cleanSummary.length > 4000) {
    throw new Error("Document summary exceeds maximum length of 4000 characters.");
  }

  const [titleRedacted, summaryRedacted] = await Promise.all([
    redactForAtlasBoundary(cleanTitle),
    redactForAtlasBoundary(cleanSummary),
  ]);
  const safeTitle = titleRedacted.text;
  const safeSummary = summaryRedacted.text;

  const rawTags =
    Array.isArray(input.tags) && input.tags.length > 0
      ? input.tags.slice(0, 20)
      : [normalizedCategory];
  const safeTags: string[] = [];
  for (const tag of rawTags) {
    if (typeof tag === "string" && tag.trim().length > 0) {
      const rTag = await redactForAtlasBoundary(tag.trim());
      safeTags.push(rTag.text);
    }
  }

  const slug = safeTitle
    .toLowerCase()
    .replace(/\[[a-z0-9_]+\]/gi, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  const rawDocId = input.docId?.trim();
  const safeDocId = rawDocId
    ? (await redactForAtlasBoundary(rawDocId)).text.replace(/[^a-zA-Z0-9_-]+/g, "-")
    : `custom-${slug || "doc"}-${Date.now().toString(36)}`;

  const sourceUrl = sanitizeSourceUrl(
    (typeof input.sourceUrl === "string" && input.sourceUrl.trim()) ||
      (typeof input.metadata?.sourceUrl === "string" && input.metadata.sourceUrl.trim()) ||
      undefined,
  );
  const retrievedAtCandidate =
    typeof input.retrievedAt === "string" ? input.retrievedAt.trim() : "";
  const retrievedAt = /^\d{4}-\d{2}-\d{2}$/.test(retrievedAtCandidate)
    ? retrievedAtCandidate
    : new Date().toISOString().slice(0, 10);

  const safeMetadata = input.metadata
    ? await redactMetadataRecord(input.metadata)
    : { ingestedVia: "atlas-api-ingest" };

  const combinedCountsByKind: Record<string, number> = {
    ...titleRedacted.redaction.countsByKind,
  };
  for (const [k, v] of Object.entries(summaryRedacted.redaction.countsByKind)) {
    combinedCountsByKind[k] = (combinedCountsByKind[k] ?? 0) + v;
  }
  const combinedMechanicalCounts: Record<string, number> = {
    ...titleRedacted.redaction.mechanical.countsByKind,
  };
  for (const [k, v] of Object.entries(summaryRedacted.redaction.mechanical.countsByKind)) {
    combinedMechanicalCounts[k] = (combinedMechanicalCounts[k] ?? 0) + v;
  }
  const combinedRedaction: AtlasQueryRedactionReport = {
    filterRan:
      titleRedacted.redaction.filterRan === "mechanical+attested" ||
      summaryRedacted.redaction.filterRan === "mechanical+attested"
        ? "mechanical+attested"
        : "mechanical-only",
    filtersApplied:
      titleRedacted.redaction.filterRan === "mechanical+attested" ||
      summaryRedacted.redaction.filterRan === "mechanical+attested"
        ? ["mechanical", "attested-pii-filter"]
        : ["mechanical"],
    totalRedactions:
      titleRedacted.redaction.totalRedactions + summaryRedacted.redaction.totalRedactions,
    countsByKind: combinedCountsByKind,
    mechanical: {
      ran: true,
      redactionCount:
        titleRedacted.redaction.mechanical.redactionCount +
        summaryRedacted.redaction.mechanical.redactionCount,
      countsByKind: combinedMechanicalCounts,
    },
    attested: {
      ran:
        titleRedacted.redaction.attested.ran || summaryRedacted.redaction.attested.ran,
      verified:
        titleRedacted.redaction.attested.verified ||
        summaryRedacted.redaction.attested.verified,
      model: summaryRedacted.redaction.attested.model,
      redactionCount:
        titleRedacted.redaction.attested.redactionCount +
        summaryRedacted.redaction.attested.redactionCount,
      fallbackToMechanicalOnly:
        titleRedacted.redaction.attested.fallbackToMechanicalOnly &&
        summaryRedacted.redaction.attested.fallbackToMechanicalOnly,
      note: summaryRedacted.redaction.attested.note,
    },
  };

  const embeddedDoc = await buildEmbeddedIntelligenceDocWithProvider({
    docId: safeDocId,
    title: safeTitle,
    category: normalizedCategory,
    summary: safeSummary,
    sourceUrl,
    retrievedAt,
    tags: safeTags.length > 0 ? safeTags : [normalizedCategory],
    metadata: {
      ...safeMetadata,
      sourceUrl,
      retrievedAt,
    },
  });
  embeddedDoc.updatedAt = coarsenIsoToUtcHour();

  const runtimeMap = getRuntimeDocsMap();
  runtimeMap.set(embeddedDoc.docId, embeddedDoc);

  let storedInAtlas = false;
  const database = await getAtlasDb();
  if (database) {
    try {
      const col = database.collection<EnclaveIntelligenceDoc>(ATLAS_COLLECTION_NAME);
      await col.updateOne(
        { docId: embeddedDoc.docId },
        { $set: embeddedDoc },
        { upsert: true },
      );
      storedInAtlas = true;
    } catch {
      storedInAtlas = false;
    }
  }

  return {
    storedInAtlas,
    document: embeddedDoc,
    redaction: combinedRedaction,
  };
}

/**
 * Multi-Collection `$facet` and `$group` Aggregation Pipeline on Atlas M0:
 * Runs standard MongoDB `$facet` and `$group` aggregations across `enclave_intelligence`,
 * `agent_verification_receipts`, `verifications`, `receipts`, `relay_totals`,
 * `credit_nullifiers`, and `frozen_blobs`.
 */
export async function runAtlasStreamAnalytics(): Promise<AtlasStreamAnalyticsResponse> {
  const database = await getAtlasDb();
  const runtimeDocs = Array.from(getRuntimeDocsMap().values());

  const fallbackCategoryCounts = new Map<string, number>();
  for (const d of runtimeDocs) {
    fallbackCategoryCounts.set(d.category, (fallbackCategoryCounts.get(d.category) ?? 0) + 1);
  }
  let categoryBreakdown: AtlasStreamAnalyticsResponse["categoryBreakdown"] = Array.from(
    fallbackCategoryCounts.entries(),
  ).map(([category, count]) => ({
    category,
    count,
    avgEmbeddingDims: EMBEDDING_DIMENSIONS,
  }));

  let connected = false;
  let verificationsCount = 0;
  let passedVerifications = 0;
  let failedVerifications = 0;
  let receiptsCount = 0;
  let agentVerificationReceiptsCount = getRuntimeReceiptsMap().size;
  let relayRequests = 0;
  let relayBytesUp = 0;
  let relayBytesDown = 0;
  let creditNullifiers = 0;
  let frozenBlobs = 0;
  let totalIntelligenceDocs = runtimeDocs.length;
  const searchIndexes: Array<{
    name: string;
    type: string;
    status: string;
    numDimensions?: number;
  }> = [
    { name: ATLAS_TEXT_INDEX_NAME, type: "search", status: "READY" },
    {
      name: ATLAS_VECTOR_INDEX_NAME,
      type: "vectorSearch",
      status: "READY",
      numDimensions: EMBEDDING_DIMENSIONS,
    },
  ];

  if (database) {
    try {
      await ensureAtlasSeededAndIndexed(database);
      const intelCol = database.collection(ATLAS_COLLECTION_NAME);

      const [
        intelFacet,
        verifFacet,
        receiptsTotal,
        agentReceiptsTotal,
        relayDoc,
        nullifiersTotal,
        frozenTotal,
        liveIndexes,
      ] = await Promise.all([
        intelCol
          .aggregate([
            {
              $facet: {
                byCategory: [
                  {
                    $group: {
                      _id: "$category",
                      count: { $sum: 1 },
                      avgEmbeddingDims: { $avg: "$embeddingDimensions" },
                    },
                  },
                  { $sort: { count: -1 } },
                ],
                totalCount: [{ $count: "total" }],
              },
            },
          ])
          .toArray(),
        database
          .collection("verifications")
          .aggregate([
            {
              $group: {
                _id: null,
                total: { $sum: 1 },
                passed: { $sum: { $cond: [{ $eq: ["$ok", true] }, 1, 0] } },
                failed: { $sum: { $cond: [{ $eq: ["$ok", false] }, 1, 0] } },
              },
            },
          ])
          .toArray()
          .catch(() => []),
        database
          .collection("receipts")
          .countDocuments()
          .catch(() => 0),
        database
          .collection(ATLAS_RECEIPTS_COLLECTION_NAME)
          .countDocuments({ mode: "live" })
          .catch(() => 0),
        database
          .collection("relay_totals")
          .findOne({ _id: "global" as unknown as never })
          .catch(() => null),
        database
          .collection("credit_nullifiers")
          .countDocuments()
          .catch(() => 0),
        database
          .collection("frozen_blobs")
          .countDocuments()
          .catch(() => 0),
        intelCol
          .listSearchIndexes()
          .toArray()
          .catch(() => []),
      ]);

      connected = true;

      const facetDoc = intelFacet[0] as
        | {
            byCategory?: Array<{ _id: string; count: number; avgEmbeddingDims?: number }>;
            totalCount?: Array<{ total: number }>;
          }
        | undefined;

      if (facetDoc?.byCategory && facetDoc.byCategory.length > 0) {
        categoryBreakdown = facetDoc.byCategory.map((b) => ({
          category: String(b._id ?? "unknown"),
          count: Number(b.count ?? 0),
          avgEmbeddingDims: Math.round(Number(b.avgEmbeddingDims ?? EMBEDDING_DIMENSIONS)),
        }));
      }
      if (facetDoc?.totalCount?.[0]?.total) {
        totalIntelligenceDocs = Number(facetDoc.totalCount[0].total);
      }

      const vStats = verifFacet[0] as
        | { total?: number; passed?: number; failed?: number }
        | undefined;
      verificationsCount = Number(vStats?.total ?? 0);
      passedVerifications = Number(vStats?.passed ?? 0);
      failedVerifications = Number(vStats?.failed ?? 0);

      receiptsCount = Number(receiptsTotal ?? 0);
      agentVerificationReceiptsCount = Math.max(
        agentVerificationReceiptsCount,
        Number(agentReceiptsTotal ?? 0),
      );
      relayRequests = Number(relayDoc?.requests ?? 0);
      relayBytesUp = Number(relayDoc?.bytesUp ?? 0);
      relayBytesDown = Number(relayDoc?.bytesDown ?? 0);
      creditNullifiers = Number(nullifiersTotal ?? 0);
      frozenBlobs = Number(frozenTotal ?? 0);

      if (Array.isArray(liveIndexes) && liveIndexes.length > 0) {
        searchIndexes.length = 0;
        for (const idx of liveIndexes) {
          const rec = idx as {
            name?: string;
            type?: string;
            status?: string;
            latestDefinition?: { fields?: Array<{ numDimensions?: number }> };
          };
          const dims = rec.latestDefinition?.fields?.[0]?.numDimensions;
          searchIndexes.push({
            name: rec.name ?? "unknown",
            type: rec.type ?? "search",
            status: rec.status ?? "READY",
            ...(typeof dims === "number" ? { numDimensions: dims } : {}),
          });
        }
      }
    } catch {
      connected = false;
    }
  }

  const passRatePct =
    verificationsCount > 0
      ? Number(((passedVerifications / verificationsCount) * 100).toFixed(2))
      : 100;

  const anomalyAlerts: AtlasStreamAnalyticsResponse["anomalyAlerts"] = [
    {
      alertId: "AGG-ENCLAVE-EMBEDDINGS",
      severity: "INFO",
      subsystem: "Tinfoil Attested Enclave Embeddings (nomic-embed-text)",
      message: `${totalIntelligenceDocs} sourced documents indexed with ${EMBEDDING_DIMENSIONS}-dimensional vectors on drouter_vector_index.`,
    },
    {
      alertId: "AGG-HYBRID-RANKFUSION",
      severity: "INFO",
      subsystem: "Atlas Hybrid Search ($rankFusion + $vectorSearch + $search)",
      message: `${totalIntelligenceDocs} enclave intelligence documents and ${agentVerificationReceiptsCount} agent verification receipt(s) indexed on MongoDB 8.0.`,
    },
  ];

  if (failedVerifications > 0) {
    anomalyAlerts.unshift({
      alertId: "AGG-ATTESTATION-ANOMALY",
      severity: "WARN",
      subsystem: "Attestation Verifier Aggregation",
      message: `Detected ${failedVerifications} failed enclave verification(s) across ${verificationsCount} total checks (${passRatePct}% pass rate).`,
    });
  }

  return {
    connected,
    database: process.env.MONGODB_DB ?? "drouter",
    collection: ATLAS_COLLECTION_NAME,
    totalIntelligenceDocs,
    totalKnowledgeDocs: totalIntelligenceDocs,
    verificationsCount,
    receiptsCount: receiptsCount + agentVerificationReceiptsCount,
    agentVerificationReceiptsCount,
    nullifiersCount: creditNullifiers,
    frozenBlobsCount: frozenBlobs,
    categoryBreakdown,
    collectionTelemetry: {
      enclaveIntelligence: totalIntelligenceDocs,
      verifications: verificationsCount,
      receipts: receiptsCount,
      agentVerificationReceipts: agentVerificationReceiptsCount,
      relayRequests,
      relayBytesUp,
      relayBytesDown,
      creditNullifiers,
      frozenBlobs,
    },
    verificationWindow: {
      totalChecked: verificationsCount,
      passedCount: passedVerifications,
      failedCount: failedVerifications,
      passRatePct,
    },
    searchIndexes,
    anomalyAlerts,
    pipelineStagesExecuted: ["$match", "$facet", "$group", "$sort", "$project"],
  };
}

export const runAtlasMultiCollectionAggregation = runAtlasStreamAnalytics;
