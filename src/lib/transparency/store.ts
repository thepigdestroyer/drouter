import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { MongoClient, type Collection, type Db } from "mongodb";
import { TinfoilAI, type VerificationDocument } from "tinfoil";
import { GET as getEnclaveMatrix } from "@/app/api/relay/enclave-matrix/route";
import { anchorReceipt, explorerTx, listNodes, type ListNodesResult } from "@/lib/arc/registry";
import { resolveDbName } from "@/lib/mongo/db-name";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";
import type { Hex } from "@/lib/types";
import {
  VERIFIER_CHECK_IDS,
  coarsenEpochSecToHour,
  computeAuditPathFromLeaves,
  computeMerkleRootFromLeaves,
  createVerificationLogEvent,
  getOperatorPublicKey,
  proveConsistencyFromLeaves,
  signTreeHead,
  verifyVerificationClaimSignature,
  type ConsistencyProof,
  type InclusionProof,
  type SignedTreeHead,
  type VerificationLogEvent,
  type VerifierCheckStatus,
  type VerifierModelClaim,
  type VerifierRouterClaim,
  type VerifierSubmissionClaim,
  type VerifierSubmissionRecord,
} from "./log";

export const TRANSPARENCY_COLLECTION = "transparency_log";
export const VERIFIER_SUBMISSIONS_COLLECTION = "verifier_submissions";
export const ANCHOR_INTERVAL_SEC = 3600; // Anchor at most once per hour

const TINFOIL_PROXY_WELL_KNOWN_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";
const PRIMARY_MODEL_IDS = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
] as const;

interface StoredLeafDocument extends VerificationLogEvent {
  docType: "leaf";
}

interface StoredTreeHeadDocument extends SignedTreeHead {
  docType: "tree_head";
}

export type TransparencyLogDocument = StoredLeafDocument | StoredTreeHeadDocument;

export interface TransparencyCollectionLike {
  find(
    filter: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): {
    sort(spec: Record<string, 1 | -1>): {
      toArray(): Promise<Record<string, unknown>[]>;
      limit(n: number): { toArray(): Promise<Record<string, unknown>[]> };
    };
    toArray(): Promise<Record<string, unknown>[]>;
  };
  findOne(filter: Record<string, unknown>, options?: Record<string, unknown>): Promise<Record<string, unknown> | null>;
  insertOne(doc: Record<string, unknown>): Promise<unknown>;
  insertMany(docs: Record<string, unknown>[]): Promise<unknown>;
  updateOne(
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  deleteMany?(filter: Record<string, unknown>): Promise<unknown>;
  countDocuments(filter?: Record<string, unknown>): Promise<number>;
}

export interface LiveVerificationView {
  router: VerifierRouterClaim;
  models: Record<string, VerifierModelClaim>;
  checks: VerifierCheckStatus[];
  overallOk: boolean;
}

const globalForTransparencyMongo = globalThis as unknown as {
  __drouterMongo?: Promise<MongoClient>;
  __drouterTransparencyOverride?: TransparencyCollectionLike | null;
  __drouterVerifierSubmissionsOverride?: TransparencyCollectionLike | null;
  __drouterAnchorOverride?: ((receiptHash: Hex) => Promise<Hex | null>) | null;
  __drouterLiveViewOverride?: (() => Promise<LiveVerificationView>) | null;
  __drouterCachedLiveView?: { view: LiveVerificationView; expiresAt: number } | null;
  __drouterLastAnchorSec?: number;
  __drouterLastAnchorTx?: string | null;
  __drouterLastAnchoredRoot?: string | null;
};

/** Allows unit tests to inject a mocked MongoDB `transparency_log` collection without touching real network. */
export function setTransparencyCollectionOverride(col: TransparencyCollectionLike | null): void {
  globalForTransparencyMongo.__drouterTransparencyOverride = col;
}

/** Allows unit tests to inject a mocked MongoDB `verifier_submissions` collection without touching real network. */
export function setVerifierSubmissionsCollectionOverride(col: TransparencyCollectionLike | null): void {
  globalForTransparencyMongo.__drouterVerifierSubmissionsOverride = col;
}

/** Allows unit tests to inject a mocked Arc anchorReceipt function without spending testnet gas. */
export function setAnchorReceiptOverride(fn: ((receiptHash: Hex) => Promise<Hex | null>) | null): void {
  globalForTransparencyMongo.__drouterAnchorOverride = fn;
}

/** Allows unit tests to inject a deterministic live enclave verification view. */
export function setLiveVerificationViewOverride(fn: (() => Promise<LiveVerificationView>) | null): void {
  globalForTransparencyMongo.__drouterLiveViewOverride = fn;
  globalForTransparencyMongo.__drouterCachedLiveView = null;
}

export function resetAnchorRateLimitState(): void {
  globalForTransparencyMongo.__drouterLastAnchorSec = undefined;
  globalForTransparencyMongo.__drouterLastAnchorTx = undefined;
  globalForTransparencyMongo.__drouterLastAnchoredRoot = undefined;
  globalForTransparencyMongo.__drouterCachedLiveView = null;
  memoryLeaves = [];
  memoryLatestSth = null;
  memorySubmissions = [];
}

async function getMongoDb(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;
  globalForTransparencyMongo.__drouterMongo ??= new MongoClient(uri, {
    appName: "drouter-demo",
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
  }).connect();
  const client = await globalForTransparencyMongo.__drouterMongo;
  return client.db(resolveDbName());
}

async function getTransparencyCollection(): Promise<TransparencyCollectionLike | null> {
  if (globalForTransparencyMongo.__drouterTransparencyOverride !== undefined) {
    return globalForTransparencyMongo.__drouterTransparencyOverride;
  }
  try {
    const db = await getMongoDb();
    if (!db) return null;
    const col: Collection = db.collection(TRANSPARENCY_COLLECTION);
    return col as unknown as TransparencyCollectionLike;
  } catch {
    return null;
  }
}

async function getVerifierSubmissionsCollection(): Promise<TransparencyCollectionLike | null> {
  if (globalForTransparencyMongo.__drouterVerifierSubmissionsOverride !== undefined) {
    return globalForTransparencyMongo.__drouterVerifierSubmissionsOverride;
  }
  try {
    const db = await getMongoDb();
    if (!db) return null;
    const col: Collection = db.collection(VERIFIER_SUBMISSIONS_COLLECTION);
    return col as unknown as TransparencyCollectionLike;
  } catch {
    return null;
  }
}

// In-memory fallback when MongoDB is not configured (starts empty; first entry is the first real verification)
let memoryLeaves: VerificationLogEvent[] = [];
let memoryLatestSth: SignedTreeHead | null = null;
let memorySubmissions: VerifierSubmissionRecord[] = [];

function getMemoryLeaves(): VerificationLogEvent[] {
  return memoryLeaves;
}

function isSimulatedLeafRecord(raw: Record<string, unknown>): boolean {
  if (raw.nodeKind === "sim") return true;
  if (typeof raw.nodeId === "string" && raw.nodeId.trim().toLowerCase().startsWith("sim-")) return true;
  return false;
}

export function sanitizeLeafRecord(raw: Record<string, unknown>, fallbackIndex: number): VerificationLogEvent | null {
  const rawTimestamp =
    typeof raw.epochHourSec === "number" && Number.isFinite(raw.epochHourSec) && raw.epochHourSec > 0
      ? raw.epochHourSec
      : typeof raw.timestampSec === "number" && Number.isFinite(raw.timestampSec) && raw.timestampSec > 0
        ? raw.timestampSec
        : null;
  if (rawTimestamp === null) {
    return null;
  }
  const index = typeof raw.index === "number" && Number.isInteger(raw.index) ? raw.index : fallbackIndex;
  const epochHourSec = coarsenEpochSecToHour(rawTimestamp);
  const kind =
    raw.kind === "release_approval"
      ? "release_approval"
      : raw.kind === "independent_verification"
        ? "independent_verification"
        : "verification_event";
  return createVerificationLogEvent({
    index,
    kind,
    nodeId: typeof raw.nodeId === "string" ? raw.nodeId : "tinfoil-router",
    nodeKind: "tinfoil",
    ok: raw.ok === true,
    measurement: typeof raw.measurement === "string" ? raw.measurement : "",
    evidenceHash: typeof raw.evidenceHash === "string" ? raw.evidenceHash : "",
    releaseDigest: typeof raw.releaseDigest === "string" ? raw.releaseDigest : undefined,
    enclaveHost: typeof raw.enclaveHost === "string" ? raw.enclaveHost : undefined,
    verifierFingerprint: typeof raw.verifierFingerprint === "string" ? raw.verifierFingerprint : undefined,
    timestampSec: epochHourSec,
  });
}

function sanitizeAndReindexLeafDocs(rawDocs: Record<string, unknown>[]): VerificationLogEvent[] {
  const out: VerificationLogEvent[] = [];
  for (const d of rawDocs) {
    if (isSimulatedLeafRecord(d)) continue;
    const sanitized = sanitizeLeafRecord({ ...d, index: out.length }, out.length);
    if (sanitized) {
      out.push(sanitized);
    }
  }
  return out;
}

async function loadOrSeedLeaves(col: TransparencyCollectionLike | null): Promise<{
  leaves: VerificationLogEvent[];
  persisted: boolean;
}> {
  if (!col) {
    memoryLeaves = sanitizeAndReindexLeafDocs(
      getMemoryLeaves() as unknown as Record<string, unknown>[],
    );
    return { leaves: [...memoryLeaves], persisted: false };
  }
  try {
    const rawDocs = await col.find({ docType: "leaf" }, { projection: { _id: 0 } }).sort({ index: 1 }).toArray();
    const realRawDocs = rawDocs.filter((d) => !isSimulatedLeafRecord(d));
    const hadSimulatedDocs = realRawDocs.length !== rawDocs.length;
    const leaves = sanitizeAndReindexLeafDocs(realRawDocs);

    if (hadSimulatedDocs && col.deleteMany) {
      await col.deleteMany({ docType: "leaf" });
      if (leaves.length > 0) {
        await col.insertMany(
          leaves.map((g) => ({
            ...g,
            docType: "leaf",
          })),
        );
      }
      return { leaves, persisted: true };
    }

    return { leaves, persisted: true };
  } catch {
    return { leaves: [...getMemoryLeaves()], persisted: false };
  }
}

async function loadLatestStoredSth(col: TransparencyCollectionLike | null): Promise<SignedTreeHead | null> {
  if (!col) return memoryLatestSth;
  try {
    const doc = await col.findOne({ docType: "tree_head", _id: "latest_sth" });
    if (!doc) return null;
    if (
      typeof doc.treeSize === "number" &&
      typeof doc.rootHash === "string" &&
      typeof doc.timestampSec === "number" &&
      typeof doc.operatorPublicKey === "string" &&
      typeof doc.signature === "string"
    ) {
      return {
        treeSize: doc.treeSize,
        rootHash: doc.rootHash,
        timestampSec: coarsenEpochSecToHour(doc.timestampSec),
        operatorPublicKey: doc.operatorPublicKey,
        signature: doc.signature,
        anchorTx: typeof doc.anchorTx === "string" ? doc.anchorTx : null,
        anchoredAtSec: typeof doc.anchoredAtSec === "number" ? doc.anchoredAtSec : null,
      };
    }
    return null;
  } catch {
    return null;
  }
}

async function saveLatestSth(col: TransparencyCollectionLike | null, sth: SignedTreeHead): Promise<void> {
  memoryLatestSth = sth;
  if (!col) return;
  try {
    await col.updateOne(
      { _id: "latest_sth", docType: "tree_head" },
      {
        $set: {
          docType: "tree_head",
          treeSize: sth.treeSize,
          rootHash: sth.rootHash,
          timestampSec: coarsenEpochSecToHour(sth.timestampSec),
          operatorPublicKey: sth.operatorPublicKey,
          signature: sth.signature,
          anchorTx: sth.anchorTx ?? null,
          anchoredAtSec: sth.anchoredAtSec ? coarsenEpochSecToHour(sth.anchoredAtSec) : null,
        },
      },
      { upsert: true },
    );
  } catch {
    // Non-fatal fallback
  }
}

/**
 * Anchors the signed tree head rootHash on Circle Arc via `anchorReceipt` at most once per hour.
 */
export async function maybeAnchorTreeHead(
  sth: SignedTreeHead,
  opts?: { forceAnchor?: boolean; nowSec?: number },
): Promise<{ anchorTx: string | null; anchoredAtSec: number | null; anchoredNow: boolean }> {
  const nowSec = opts?.nowSec ?? Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);
  const lastSec = globalForTransparencyMongo.__drouterLastAnchorSec ?? sth.anchoredAtSec ?? 0;

  if (
    !opts?.forceAnchor &&
    lastSec > 0 &&
    nowSec - lastSec < ANCHOR_INTERVAL_SEC &&
    (globalForTransparencyMongo.__drouterLastAnchorTx || sth.anchorTx)
  ) {
    return {
      anchorTx: globalForTransparencyMongo.__drouterLastAnchorTx ?? sth.anchorTx ?? null,
      anchoredAtSec: coarsenEpochSecToHour(lastSec),
      anchoredNow: false,
    };
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    return {
      anchorTx: sth.anchorTx ?? null,
      anchoredAtSec: sth.anchoredAtSec ?? null,
      anchoredNow: false,
    };
  }

  const doAnchor = globalForTransparencyMongo.__drouterAnchorOverride ?? anchorReceipt;
  const receiptHex = (sth.rootHash.startsWith("0x") ? sth.rootHash : `0x${sth.rootHash}`) as Hex;

  try {
    const tx = await doAnchor(receiptHex);
    if (tx) {
      globalForTransparencyMongo.__drouterLastAnchorSec = nowSec;
      globalForTransparencyMongo.__drouterLastAnchorTx = tx;
      globalForTransparencyMongo.__drouterLastAnchoredRoot = sth.rootHash;
      return {
        anchorTx: tx,
        anchoredAtSec: coarseNow,
        anchoredNow: true,
      };
    }
  } catch {
    // Ignore transient RPC failures
  }

  return {
    anchorTx: sth.anchorTx ?? globalForTransparencyMongo.__drouterLastAnchorTx ?? null,
    anchoredAtSec: sth.anchoredAtSec ?? null,
    anchoredNow: false,
  };
}

export interface PersistedTransparencyState {
  persisted: boolean;
  operatorPublicKey: string;
  signedTreeHead: SignedTreeHead;
  anchorExplorerUrl: string | null;
  events: VerificationLogEvent[];
  inclusionProofs: InclusionProof[];
  consistencyProof: ConsistencyProof;
}

/**
 * Loads the persisted transparency log from MongoDB `transparency_log`, computes the RFC 6962 Merkle root,
 * signs or refreshes the operator-signed tree head (STH), and optionally anchors on Arc (at most hourly).
 */
export async function getPersistedTransparencyLog(opts?: {
  leafIndex?: number;
  firstTreeSize?: number;
  secondTreeSize?: number;
  anchorIfDue?: boolean;
  forceAnchor?: boolean;
  nowSec?: number;
}): Promise<PersistedTransparencyState> {
  const col = await getTransparencyCollection();
  const { leaves, persisted } = await loadOrSeedLeaves(col);
  const leafBytes = leaves.map((l) => hexToBytes(l.leafHash));
  const rootHash = bytesToHex(computeMerkleRootFromLeaves(leafBytes));
  const nowSec = opts?.nowSec ?? Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);
  const operatorPublicKey = getOperatorPublicKey();

  const storedSth = await loadLatestStoredSth(col);
  let sth: SignedTreeHead;

  if (
    storedSth &&
    storedSth.treeSize === leaves.length &&
    storedSth.rootHash.toLowerCase() === rootHash.toLowerCase() &&
    storedSth.operatorPublicKey.toLowerCase() === operatorPublicKey.toLowerCase()
  ) {
    sth = storedSth;
  } else {
    sth = signTreeHead({
      treeSize: leaves.length,
      rootHash,
      timestampSec: coarseNow,
      anchorTx: storedSth?.anchorTx ?? null,
      anchoredAtSec: storedSth?.anchoredAtSec ?? null,
    });
  }

  if (opts?.anchorIfDue || opts?.forceAnchor) {
    const anchorRes = await maybeAnchorTreeHead(sth, {
      forceAnchor: opts.forceAnchor,
      nowSec,
    });
    if (anchorRes.anchorTx !== sth.anchorTx || anchorRes.anchoredAtSec !== sth.anchoredAtSec) {
      sth = {
        ...sth,
        anchorTx: anchorRes.anchorTx,
        anchoredAtSec: anchorRes.anchoredAtSec,
      };
    }
  }

  await saveLatestSth(col, sth);

  const inclusionProofs: InclusionProof[] =
    opts?.leafIndex !== undefined && opts.leafIndex >= 0 && opts.leafIndex < leaves.length
      ? [
          {
            leafHash: leaves[opts.leafIndex].leafHash,
            root: rootHash,
            auditPath: computeAuditPathFromLeaves(leafBytes, opts.leafIndex),
            leafIndex: opts.leafIndex,
            treeSize: leaves.length,
          },
        ]
      : leaves.map((l, idx) => ({
          leafHash: l.leafHash,
          root: rootHash,
          auditPath: computeAuditPathFromLeaves(leafBytes, idx),
          leafIndex: idx,
          treeSize: leaves.length,
        }));

  const secondSize =
    opts?.secondTreeSize !== undefined
      ? Math.min(Math.max(opts.secondTreeSize, 0), leaves.length)
      : leaves.length;
  const firstSize =
    opts?.firstTreeSize !== undefined
      ? Math.min(Math.max(opts.firstTreeSize, 0), secondSize)
      : Math.max(0, secondSize - 1);

  const consistencyProof = proveConsistencyFromLeaves(leafBytes, firstSize, secondSize);

  return {
    persisted,
    operatorPublicKey,
    signedTreeHead: sth,
    anchorExplorerUrl: sth.anchorTx ? explorerTx(sth.anchorTx) : null,
    events: leaves,
    inclusionProofs,
    consistencyProof,
  };
}

/**
 * Appends a new verification event to the RFC 6962 Merkle transparency log in MongoDB `transparency_log`,
 * signs the updated tree head with the operator Ed25519 key, and anchors on Arc if the hourly window has elapsed.
 */
export async function appendVerificationEventToLog(params: {
  kind?: "verification_event" | "release_approval" | "independent_verification";
  nodeId: string;
  nodeKind?: "tinfoil";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
  verifierFingerprint?: string;
  timestampSec?: number;
  anchorOnArc?: boolean;
  forceAnchor?: boolean;
}): Promise<{
  event: VerificationLogEvent;
  inclusionProof: InclusionProof;
  consistencyProof: ConsistencyProof;
  signedTreeHead: SignedTreeHead;
  persisted: boolean;
}> {
  if ((params.nodeKind as string) === "sim" || params.nodeId.trim().toLowerCase().startsWith("sim-")) {
    throw new Error("Simulated nodes are not permitted in the production transparency log");
  }

  const col = await getTransparencyCollection();
  const { leaves, persisted } = await loadOrSeedLeaves(col);
  const previousSize = leaves.length;
  const nowSec = params.timestampSec ?? Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);

  const newEvent = createVerificationLogEvent({
    index: previousSize,
    kind: params.kind ?? "verification_event",
    nodeId: params.nodeId,
    nodeKind: "tinfoil",
    ok: params.ok,
    measurement: params.measurement,
    evidenceHash: params.evidenceHash,
    releaseDigest: params.releaseDigest,
    enclaveHost: params.enclaveHost,
    verifierFingerprint: params.verifierFingerprint,
    timestampSec: coarseNow,
  });

  const updatedLeaves = [...leaves, newEvent];
  memoryLeaves = updatedLeaves;

  if (col) {
    try {
      await col.insertOne({
        ...newEvent,
        docType: "leaf",
      });
    } catch {
      // Fallback remains in memoryLeaves
    }
  }

  const leafBytes = updatedLeaves.map((l) => hexToBytes(l.leafHash));
  const rootHash = bytesToHex(computeMerkleRootFromLeaves(leafBytes));
  const storedSth = await loadLatestStoredSth(col);

  let sth = signTreeHead({
    treeSize: updatedLeaves.length,
    rootHash,
    timestampSec: coarseNow,
    anchorTx: storedSth?.anchorTx ?? null,
    anchoredAtSec: storedSth?.anchoredAtSec ?? null,
  });

  if (params.anchorOnArc !== false) {
    const anchorRes = await maybeAnchorTreeHead(sth, {
      forceAnchor: params.forceAnchor,
      nowSec,
    });
    sth = {
      ...sth,
      anchorTx: anchorRes.anchorTx,
      anchoredAtSec: anchorRes.anchoredAtSec,
    };
  }

  await saveLatestSth(col, sth);

  const inclusionProof: InclusionProof = {
    leafHash: newEvent.leafHash,
    root: rootHash,
    auditPath: computeAuditPathFromLeaves(leafBytes, newEvent.index),
    leafIndex: newEvent.index,
    treeSize: updatedLeaves.length,
  };

  const consistencyProof = proveConsistencyFromLeaves(leafBytes, previousSize, updatedLeaves.length);

  return {
    event: newEvent,
    inclusionProof,
    consistencyProof,
    signedTreeHead: sth,
    persisted,
  };
}

interface ProxyTableModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  };
  verification?: {
    configured?: number;
    verified?: number;
    healthy?: number;
  };
}

async function fetchProxyTableWithTimeout(timeoutMs = 5000): Promise<Record<string, ProxyTableModelEntry>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(TINFOIL_PROXY_WELL_KNOWN_URL, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return {};
    const data = (await res.json()) as { models?: Record<string, ProxyTableModelEntry> };
    return data?.models ?? {};
  } catch {
    return {};
  } finally {
    clearTimeout(timer);
  }
}

async function fetchRouterVerificationDoc(): Promise<VerificationDocument | null> {
  try {
    const client = new TinfoilAI({
      bearerToken: "drouter-verify",
      baseURL: "https://inference.tinfoil.sh/v1/",
      attestationBundleURL: "https://atc.tinfoil.sh",
    });
    await client.ready();
    return await client.getVerificationDocument();
  } catch {
    return null;
  }
}

async function fetchDeepAttestationMatrix(): Promise<DeepAttestationBundle | null> {
  try {
    const res = await getEnclaveMatrix();
    if (!res || !res.ok) return null;
    return (await res.json()) as DeepAttestationBundle;
  } catch {
    return null;
  }
}

function computeLiveRegistryStatus(registry: ListNodesResult | null): "pass" | "fail" | "skip" {
  if (!registry || !Array.isArray(registry.nodes)) return "skip";
  const node = registry.nodes.find((n) => n.kind === "tinfoil");
  if (!node) return "fail";
  if (registry.source !== "arc") return "skip";
  return node.status === "active" && Number(node.stake) > 0 ? "pass" : "fail";
}

/**
 * Computes the server's own live view of the Tinfoil router, model enclaves, and C1-C7 checks.
 */
export async function getLiveVerificationView(): Promise<LiveVerificationView> {
  if (globalForTransparencyMongo.__drouterLiveViewOverride) {
    return globalForTransparencyMongo.__drouterLiveViewOverride();
  }

  const now = Date.now();
  const cached = globalForTransparencyMongo.__drouterCachedLiveView;
  if (cached && cached.expiresAt > now) {
    return cached.view;
  }

  const [doc, matrix, proxyModels, registry] = await Promise.all([
    fetchRouterVerificationDoc(),
    fetchDeepAttestationMatrix(),
    fetchProxyTableWithTimeout(5000),
    listNodes().catch(() => null),
  ]);

  const enclaveHost = (doc?.enclaveHost || matrix?.routerHost || "router-0.tinfoil.sh").toLowerCase();
  const configRepo = doc?.configRepo || matrix?.routerConfigRepo || "tinfoilsh/confidential-model-router";
  const releaseDigest = (doc?.releaseDigest || matrix?.routerReleaseDigest || "").toLowerCase();
  const measurement = (
    doc?.codeFingerprint ||
    doc?.enclaveFingerprint ||
    matrix?.routerSnpReport?.measurementHex ||
    ""
  ).toLowerCase();

  const models: Record<string, VerifierModelClaim> = {};
  const modelIds = new Set<string>([
    ...PRIMARY_MODEL_IDS,
    ...Object.keys(matrix?.models ?? {}),
    ...Object.keys(proxyModels),
  ]);

  for (const id of modelIds) {
    const mAtt = matrix?.models?.[id];
    const pMod = proxyModels[id];
    const repo = mAtt?.repo || pMod?.repo || "";
    const tag = mAtt?.tag || pMod?.tag || "";
    const reg0 = mAtt?.measurementRegisters?.[0] || pMod?.measurement?.registers?.[0] || mAtt?.dmVerityRootHash || "";
    if (!repo || !tag || !reg0) continue;

    const healthy = mAtt ? mAtt.healthyHosts : (pMod?.verification?.healthy ?? 0);
    const available = mAtt ? mAtt.status !== "unavailable" : true;
    models[id] = {
      id,
      repo,
      tag,
      measurement: reg0.toLowerCase(),
      ...(mAtt?.dmVerityRootHash ? { dmVerityRootHash: mAtt.dmVerityRootHash.toLowerCase() } : {}),
      ...(mAtt?.weightRepoCommit ? { weightRepoCommit: mAtt.weightRepoCommit } : {}),
      ok: Boolean(available && healthy > 0),
    };
  }

  const stepStatus = (s: { status?: string } | undefined): "pass" | "fail" | "skip" =>
    !s ? "skip" : s.status === "success" ? "pass" : s.status === "failed" ? "fail" : "skip";

  const steps = doc?.steps;
  const primaryModels = PRIMARY_MODEL_IDS.map((id) => models[id]).filter(Boolean);
  const anyModelOk = primaryModels.length > 0 && primaryModels.some((m) => m.ok);
  const c1 = stepStatus(steps?.verifyEnclave);
  const c2 = stepStatus(steps?.verifyCode);
  const c3 = stepStatus(steps?.verifyCertificate);
  const c4 = stepStatus(steps?.compareMeasurements);
  const c5: "pass" | "fail" | "skip" = anyModelOk ? "pass" : "fail";
  const c6 = computeLiveRegistryStatus(registry);
  const c7: "pass" | "fail" | "skip" = anyModelOk ? "pass" : "fail";

  const checks: VerifierCheckStatus[] = [
    { id: "C1", status: c1 },
    { id: "C2", status: c2 },
    { id: "C3", status: c3 },
    { id: "C4", status: c4 },
    { id: "C5", status: c5 },
    { id: "C6", status: c6 },
    { id: "C7", status: c7 },
  ];

  const overallOk = Boolean(
    doc?.securityVerified &&
      c1 === "pass" &&
      c2 === "pass" &&
      c3 === "pass" &&
      c4 === "pass" &&
      c5 === "pass" &&
      c7 === "pass" &&
      c6 !== "fail",
  );

  const view: LiveVerificationView = {
    router: {
      nodeId: "tinfoil-router",
      enclaveHost,
      configRepo,
      releaseDigest,
      measurement,
    },
    models,
    checks,
    overallOk,
  };

  if (releaseDigest && measurement) {
    globalForTransparencyMongo.__drouterCachedLiveView = {
      view,
      expiresAt: now + 60_000,
    };
  }

  return view;
}

/**
 * Compares a verifier's signed claim against the server's live enclave view.
 * Returns `{ ok: true, mismatches: [] }` only if every claimed fact matches the live view.
 */
export function compareClaimAgainstLiveView(
  claim: VerifierSubmissionClaim,
  liveView: LiveVerificationView,
  nowSec: number = Math.floor(Date.now() / 1000),
): { ok: boolean; mismatches: string[] } {
  const mismatches: string[] = [];
  const coarseNow = coarsenEpochSecToHour(nowSec);

  if (Math.abs(claim.epochHourSec - coarseNow) > 3600) {
    mismatches.push(
      `epochHourSec (${claim.epochHourSec}) is outside the valid 1-hour verification window around ${coarseNow}`,
    );
  }

  if (claim.router.nodeId !== "tinfoil-router") {
    mismatches.push(`router.nodeId mismatch: claimed "${claim.router.nodeId}", expected "tinfoil-router"`);
  }

  const allowedHosts = new Set([
    liveView.router.enclaveHost.toLowerCase(),
    "router-0.tinfoil.sh",
    "inference.tinfoil.sh",
  ]);
  if (!allowedHosts.has(claim.router.enclaveHost.toLowerCase())) {
    mismatches.push(
      `router.enclaveHost mismatch: claimed "${claim.router.enclaveHost}", live "${liveView.router.enclaveHost}"`,
    );
  }

  if (claim.router.configRepo !== liveView.router.configRepo) {
    mismatches.push(
      `router.configRepo mismatch: claimed "${claim.router.configRepo}", live "${liveView.router.configRepo}"`,
    );
  }

  if (claim.router.releaseDigest.toLowerCase() !== liveView.router.releaseDigest.toLowerCase()) {
    mismatches.push(
      `router.releaseDigest mismatch: claimed "${claim.router.releaseDigest}", live "${liveView.router.releaseDigest}"`,
    );
  }

  if (claim.router.measurement.toLowerCase() !== liveView.router.measurement.toLowerCase()) {
    mismatches.push(
      `router.measurement mismatch: claimed "${claim.router.measurement}", live "${liveView.router.measurement}"`,
    );
  }

  if (!Array.isArray(claim.models) || claim.models.length === 0) {
    mismatches.push("claim.models must contain at least one verified live model enclave");
  } else {
    const seenIds = new Set<string>();
    for (const m of claim.models) {
      if (seenIds.has(m.id)) {
        mismatches.push(`Duplicate model entry "${m.id}" in claim.models`);
        continue;
      }
      seenIds.add(m.id);
      const liveModel = liveView.models[m.id];
      if (!liveModel) {
        mismatches.push(`Model "${m.id}" is not present in the live enclave view`);
        continue;
      }
      if (m.repo !== liveModel.repo) {
        mismatches.push(`Model "${m.id}" repo mismatch: claimed "${m.repo}", live "${liveModel.repo}"`);
      }
      if (m.tag !== liveModel.tag) {
        mismatches.push(`Model "${m.id}" tag mismatch: claimed "${m.tag}", live "${liveModel.tag}"`);
      }
      if (m.measurement.toLowerCase() !== liveModel.measurement.toLowerCase()) {
        mismatches.push(
          `Model "${m.id}" measurement mismatch: claimed "${m.measurement}", live "${liveModel.measurement}"`,
        );
      }
      if (
        m.dmVerityRootHash &&
        liveModel.dmVerityRootHash &&
        m.dmVerityRootHash.toLowerCase() !== liveModel.dmVerityRootHash.toLowerCase()
      ) {
        mismatches.push(
          `Model "${m.id}" dmVerityRootHash mismatch: claimed "${m.dmVerityRootHash}", live "${liveModel.dmVerityRootHash}"`,
        );
      }
      if (
        m.weightRepoCommit &&
        liveModel.weightRepoCommit &&
        m.weightRepoCommit !== liveModel.weightRepoCommit
      ) {
        mismatches.push(
          `Model "${m.id}" weightRepoCommit mismatch: claimed "${m.weightRepoCommit}", live "${liveModel.weightRepoCommit}"`,
        );
      }
      if (m.ok !== liveModel.ok) {
        mismatches.push(`Model "${m.id}" ok status mismatch: claimed ${String(m.ok)}, live ${String(liveModel.ok)}`);
      }
    }
  }

  const liveCheckMap = new Map(liveView.checks.map((c) => [c.id, c.status]));
  for (const checkId of VERIFIER_CHECK_IDS) {
    const claimed = claim.checks.find((c) => c.id === checkId)?.status;
    const expected = liveCheckMap.get(checkId);
    if (!claimed || !expected) {
      mismatches.push(`Missing check ${checkId}`);
      continue;
    }
    if (checkId === "C6") {
      // Allow skip vs pass only when one side experienced an RPC fallback, but never allow fail mismatch
      const bothNonFail = (claimed === "pass" || claimed === "skip") && (expected === "pass" || expected === "skip");
      if (claimed !== expected && !bothNonFail) {
        mismatches.push(`Check C6 mismatch: claimed "${claimed}", live "${expected}"`);
      }
    } else if (claimed !== expected) {
      mismatches.push(`Check ${checkId} mismatch: claimed "${claimed}", live "${expected}"`);
    }
  }

  const expectedOverallOk = claim.checks.every((c) => (c.id === "C6" ? c.status !== "fail" : c.status === "pass"));
  if (claim.overallOk !== expectedOverallOk) {
    mismatches.push(`claim.overallOk (${String(claim.overallOk)}) is inconsistent with claim.checks`);
  }
  if (claim.overallOk !== liveView.overallOk) {
    mismatches.push(`claim.overallOk mismatch: claimed ${String(claim.overallOk)}, live ${String(liveView.overallOk)}`);
  }

  return {
    ok: mismatches.length === 0,
    mismatches,
  };
}

function sanitizeSubmissionRecord(raw: Record<string, unknown>): VerifierSubmissionRecord | null {
  if (typeof raw.epochHourSec !== "number" || !Number.isFinite(raw.epochHourSec) || raw.epochHourSec <= 0) {
    return null;
  }
  const routerRaw = (raw.router && typeof raw.router === "object" ? raw.router : {}) as Record<string, unknown>;
  const modelsRaw = Array.isArray(raw.models) ? (raw.models as Record<string, unknown>[]) : [];
  const checksRaw = Array.isArray(raw.checks) ? (raw.checks as Record<string, unknown>[]) : [];

  return {
    verifierFingerprint: typeof raw.verifierFingerprint === "string" ? raw.verifierFingerprint.toLowerCase() : "",
    epochHourSec: coarsenEpochSecToHour(raw.epochHourSec),
    overallOk: raw.overallOk === true,
    checks: VERIFIER_CHECK_IDS.map((id) => {
      const found = checksRaw.find((c) => c && c.id === id);
      const st = found?.status;
      return {
        id,
        status: st === "pass" || st === "fail" || st === "skip" ? st : "skip",
      };
    }),
    router: {
      nodeId: typeof routerRaw.nodeId === "string" ? routerRaw.nodeId : "tinfoil-router",
      enclaveHost: typeof routerRaw.enclaveHost === "string" ? routerRaw.enclaveHost : "router-0.tinfoil.sh",
      configRepo:
        typeof routerRaw.configRepo === "string" ? routerRaw.configRepo : "tinfoilsh/confidential-model-router",
      releaseDigest: typeof routerRaw.releaseDigest === "string" ? routerRaw.releaseDigest : "",
      measurement: typeof routerRaw.measurement === "string" ? routerRaw.measurement : "",
    },
    models: modelsRaw.map((m) => ({
      id: typeof m.id === "string" ? m.id : "",
      repo: typeof m.repo === "string" ? m.repo : "",
      tag: typeof m.tag === "string" ? m.tag : "",
      measurement: typeof m.measurement === "string" ? m.measurement : "",
      ...(typeof m.dmVerityRootHash === "string" && m.dmVerityRootHash
        ? { dmVerityRootHash: m.dmVerityRootHash }
        : {}),
      ...(typeof m.weightRepoCommit === "string" && m.weightRepoCommit
        ? { weightRepoCommit: m.weightRepoCommit }
        : {}),
      ok: m.ok === true,
    })),
    evidenceHash: typeof raw.evidenceHash === "string" ? raw.evidenceHash : "",
    leafIndex: typeof raw.leafIndex === "number" && Number.isInteger(raw.leafIndex) ? raw.leafIndex : 0,
    leafHash: typeof raw.leafHash === "string" ? raw.leafHash : "",
  };
}

export async function getVerifierSubmissionsSummary(opts?: { limit?: number }): Promise<{
  persisted: boolean;
  distinctVerifierCount: number;
  totalSubmissions: number;
  recentSubmissions: VerifierSubmissionRecord[];
}> {
  const limit = Math.min(Math.max(opts?.limit ?? 20, 1), 100);
  const col = await getVerifierSubmissionsCollection();
  if (!col) {
    const sorted = [...memorySubmissions].sort(
      (a, b) => b.epochHourSec - a.epochHourSec || b.leafIndex - a.leafIndex,
    );
    const distinctVerifierCount = new Set(sorted.map((s) => s.verifierFingerprint).filter(Boolean)).size;
    return {
      persisted: false,
      distinctVerifierCount,
      totalSubmissions: sorted.length,
      recentSubmissions: sorted.slice(0, limit),
    };
  }

  try {
    const rawDocs = await col
      .find({}, { projection: { _id: 0 } })
      .sort({ leafIndex: -1 })
      .toArray();
    const records = rawDocs
      .map(sanitizeSubmissionRecord)
      .filter((r): r is VerifierSubmissionRecord => r !== null && Boolean(r.verifierFingerprint));
    const distinctVerifierCount = new Set(records.map((r) => r.verifierFingerprint)).size;
    return {
      persisted: true,
      distinctVerifierCount,
      totalSubmissions: records.length,
      recentSubmissions: records.slice(0, limit),
    };
  } catch {
    const sorted = [...memorySubmissions].sort(
      (a, b) => b.epochHourSec - a.epochHourSec || b.leafIndex - a.leafIndex,
    );
    const distinctVerifierCount = new Set(sorted.map((s) => s.verifierFingerprint).filter(Boolean)).size;
    return {
      persisted: false,
      distinctVerifierCount,
      totalSubmissions: sorted.length,
      recentSubmissions: sorted.slice(0, limit),
    };
  }
}

export type SubmitVerificationResult =
  | {
      ok: false;
      status: 400 | 422;
      error: string;
      mismatches?: string[];
    }
  | {
      ok: true;
      status: 200;
      persisted: boolean;
      verifierFingerprint: string;
      epochHourSec: number;
      submission: VerifierSubmissionRecord;
      distinctVerifierCount: number;
      totalSubmissions: number;
      event: VerificationLogEvent;
      inclusionProof: InclusionProof;
      consistencyProof: ConsistencyProof;
      signedTreeHead: SignedTreeHead;
      operatorPublicKey: string;
    };

/**
 * Verifies an Ed25519-signed C1-C7 verification submission, re-checks every claimed fact against the server's
 * live view, stores only the verifier key fingerprint, result, and coarse UTC hour in `verifier_submissions`
 * (never IP or sub-hour timestamp), and appends a leaf to the RFC 6962 transparency log.
 */
export async function submitIndependentVerification(params: {
  publicKey: string;
  signature: string;
  claim: VerifierSubmissionClaim;
  nowSec?: number;
  anchorOnArc?: boolean;
}): Promise<SubmitVerificationResult> {
  const nowSec = params.nowSec ?? Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);

  const sigCheck = verifyVerificationClaimSignature({
    publicKey: params.publicKey,
    signature: params.signature,
    claim: params.claim,
  });
  if (!sigCheck.ok || !sigCheck.normalizedClaim) {
    return {
      ok: false,
      status: 400,
      error: sigCheck.detail,
    };
  }

  const normalizedClaim = sigCheck.normalizedClaim;
  const liveView = await getLiveVerificationView();
  const comparison = compareClaimAgainstLiveView(normalizedClaim, liveView, nowSec);
  if (!comparison.ok) {
    return {
      ok: false,
      status: 422,
      error: "Claimed verification facts do not match live enclave view",
      mismatches: comparison.mismatches,
    };
  }

  const appended = await appendVerificationEventToLog({
    kind: "verification_event",
    nodeId: normalizedClaim.router.nodeId,
    nodeKind: "tinfoil",
    ok: normalizedClaim.overallOk,
    measurement: normalizedClaim.router.measurement,
    evidenceHash: sigCheck.evidenceHash,
    releaseDigest: normalizedClaim.router.releaseDigest,
    enclaveHost: normalizedClaim.router.enclaveHost,
    verifierFingerprint: sigCheck.verifierFingerprint,
    timestampSec: coarseNow,
    anchorOnArc: params.anchorOnArc ?? false,
  });

  const submission: VerifierSubmissionRecord = {
    verifierFingerprint: sigCheck.verifierFingerprint,
    epochHourSec: coarseNow,
    overallOk: normalizedClaim.overallOk,
    checks: normalizedClaim.checks,
    router: normalizedClaim.router,
    models: normalizedClaim.models,
    evidenceHash: sigCheck.evidenceHash,
    leafIndex: appended.event.index,
    leafHash: appended.event.leafHash,
  };

  memorySubmissions = [submission, ...memorySubmissions];

  const subCol = await getVerifierSubmissionsCollection();
  let subPersisted = false;
  if (subCol) {
    try {
      await subCol.insertOne({
        ...submission,
      });
      subPersisted = true;
    } catch {
      subPersisted = false;
    }
  }

  const summary = await getVerifierSubmissionsSummary({ limit: 20 });

  return {
    ok: true,
    status: 200,
    persisted: appended.persisted && (subCol ? subPersisted : true),
    verifierFingerprint: sigCheck.verifierFingerprint,
    epochHourSec: coarseNow,
    submission,
    distinctVerifierCount: summary.distinctVerifierCount,
    totalSubmissions: summary.totalSubmissions,
    event: appended.event,
    inclusionProof: appended.inclusionProof,
    consistencyProof: appended.consistencyProof,
    signedTreeHead: appended.signedTreeHead,
    operatorPublicKey: getOperatorPublicKey(),
  };
}
