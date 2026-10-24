import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { MongoClient, type Collection, type Db } from "mongodb";
import { anchorReceipt, explorerTx } from "@/lib/arc/registry";
import type { Hex } from "@/lib/types";
import {
  coarsenEpochSecToHour,
  computeAuditPathFromLeaves,
  computeMerkleRootFromLeaves,
  createVerificationLogEvent,
  getOperatorPublicKey,
  proveConsistencyFromLeaves,
  signTreeHead,
  type ConsistencyProof,
  type InclusionProof,
  type SignedTreeHead,
  type VerificationLogEvent,
} from "./log";

export const TRANSPARENCY_COLLECTION = "transparency_log";
export const ANCHOR_INTERVAL_SEC = 3600; // Anchor at most once per hour

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
  countDocuments(filter?: Record<string, unknown>): Promise<number>;
}

const globalForTransparencyMongo = globalThis as unknown as {
  __drouterMongo?: Promise<MongoClient>;
  __drouterTransparencyOverride?: TransparencyCollectionLike | null;
  __drouterAnchorOverride?: ((receiptHash: Hex) => Promise<Hex | null>) | null;
  __drouterLastAnchorSec?: number;
  __drouterLastAnchorTx?: string | null;
  __drouterLastAnchoredRoot?: string | null;
};

/** Allows unit tests to inject a mocked MongoDB collection without touching real network. */
export function setTransparencyCollectionOverride(col: TransparencyCollectionLike | null): void {
  globalForTransparencyMongo.__drouterTransparencyOverride = col;
}

/** Allows unit tests to inject a mocked Arc anchorReceipt function without spending testnet gas. */
export function setAnchorReceiptOverride(fn: ((receiptHash: Hex) => Promise<Hex | null>) | null): void {
  globalForTransparencyMongo.__drouterAnchorOverride = fn;
}

export function resetAnchorRateLimitState(): void {
  globalForTransparencyMongo.__drouterLastAnchorSec = undefined;
  globalForTransparencyMongo.__drouterLastAnchorTx = undefined;
  globalForTransparencyMongo.__drouterLastAnchoredRoot = undefined;
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
  return client.db(process.env.MONGODB_DB ?? "drouter");
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

/** Initial genesis verification events (no PII, coarse hour timestamps) so the log starts non-empty. */
export function buildGenesisVerificationEvents(): VerificationLogEvent[] {
  return [
    createVerificationLogEvent({
      index: 0,
      kind: "release_approval",
      nodeId: "tinfoil-router",
      nodeKind: "tinfoil",
      ok: true,
      measurement: bytesToHex(sha384(utf8ToBytes("tinfoilsh/confidential-model-router@v0.0.167"))),
      evidenceHash: bytesToHex(sha384(utf8ToBytes("genesis/tinfoil-router/v0.0.167")).slice(0, 32)),
      releaseDigest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
      enclaveHost: "router-0.tinfoil.sh",
      timestampSec: 1735689600, // 2025-01-01T00:00:00Z
    }),
    createVerificationLogEvent({
      index: 1,
      kind: "release_approval",
      nodeId: "sim-1",
      nodeKind: "sim",
      ok: true,
      measurement: bytesToHex(sha384(utf8ToBytes("drouter-sim-node-image/v0.1.0"))),
      evidenceHash: bytesToHex(sha384(utf8ToBytes("genesis/sim-1/v0.1.0")).slice(0, 32)),
      timestampSec: 1738368000, // 2025-02-01T00:00:00Z
    }),
    createVerificationLogEvent({
      index: 2,
      kind: "release_approval",
      nodeId: "sim-2",
      nodeKind: "sim",
      ok: true,
      measurement: bytesToHex(sha384(utf8ToBytes("drouter-sim-node-image/v0.1.0"))),
      evidenceHash: bytesToHex(sha384(utf8ToBytes("genesis/sim-2/v0.1.0")).slice(0, 32)),
      timestampSec: 1740787200, // 2025-03-01T00:00:00Z
    }),
  ];
}

// In-memory fallback when MongoDB is not configured
let memoryLeaves: VerificationLogEvent[] = buildGenesisVerificationEvents();
let memoryLatestSth: SignedTreeHead | null = null;

function sanitizeLeafRecord(raw: Record<string, unknown>, fallbackIndex: number): VerificationLogEvent {
  const index = typeof raw.index === "number" && Number.isInteger(raw.index) ? raw.index : fallbackIndex;
  const epochHourSec =
    typeof raw.epochHourSec === "number" && Number.isFinite(raw.epochHourSec)
      ? coarsenEpochSecToHour(raw.epochHourSec)
      : coarsenEpochSecToHour(1735689600);
  return createVerificationLogEvent({
    index,
    kind: raw.kind === "release_approval" ? "release_approval" : "verification_event",
    nodeId: typeof raw.nodeId === "string" ? raw.nodeId : "unknown-node",
    nodeKind: raw.nodeKind === "tinfoil" ? "tinfoil" : "sim",
    ok: raw.ok === true,
    measurement: typeof raw.measurement === "string" ? raw.measurement : "",
    evidenceHash: typeof raw.evidenceHash === "string" ? raw.evidenceHash : "",
    releaseDigest: typeof raw.releaseDigest === "string" ? raw.releaseDigest : undefined,
    enclaveHost: typeof raw.enclaveHost === "string" ? raw.enclaveHost : undefined,
    timestampSec: epochHourSec,
  });
}

async function loadOrSeedLeaves(col: TransparencyCollectionLike | null): Promise<{
  leaves: VerificationLogEvent[];
  persisted: boolean;
}> {
  if (!col) {
    return { leaves: [...memoryLeaves], persisted: false };
  }
  try {
    const rawDocs = await col.find({ docType: "leaf" }, { projection: { _id: 0 } }).sort({ index: 1 }).toArray();
    if (rawDocs.length === 0) {
      const genesis = buildGenesisVerificationEvents();
      await col.insertMany(
        genesis.map((g) => ({
          ...g,
          docType: "leaf",
        })),
      );
      return { leaves: genesis, persisted: true };
    }
    const leaves = rawDocs.map((d, idx) => sanitizeLeafRecord(d, idx));
    return { leaves, persisted: true };
  } catch {
    return { leaves: [...memoryLeaves], persisted: false };
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
  kind?: "verification_event" | "release_approval";
  nodeId: string;
  nodeKind: "tinfoil" | "sim";
  ok: boolean;
  measurement: string;
  evidenceHash: string;
  releaseDigest?: string;
  enclaveHost?: string;
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
  const col = await getTransparencyCollection();
  const { leaves, persisted } = await loadOrSeedLeaves(col);
  const previousSize = leaves.length;
  const nowSec = params.timestampSec ?? Math.floor(Date.now() / 1000);
  const coarseNow = coarsenEpochSecToHour(nowSec);

  const newEvent = createVerificationLogEvent({
    index: previousSize,
    kind: params.kind ?? "verification_event",
    nodeId: params.nodeId,
    nodeKind: params.nodeKind,
    ok: params.ok,
    measurement: params.measurement,
    evidenceHash: params.evidenceHash,
    releaseDigest: params.releaseDigest,
    enclaveHost: params.enclaveHost,
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
