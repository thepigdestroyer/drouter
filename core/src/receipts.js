import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { canonicalJson, coarsenEpochSecToHour, sha256Hex } from "./canonical.js";
import { getMongoDb } from "./corpus.js";
import { assertContentFree } from "./firewall.js";
import { getKeyRing } from "./keys.js";

export const GEMINI_EGRESS_RECEIPT_KIND = "gemini-egress";
export const STH_DOMAIN = "drouter/transparency/sth/v1";
export const TRANSPARENCY_COLLECTION_NAME = "transparency_log";

/**
 * Builds the canonical signing bytes for a Gemini egress receipt:
 * `canonicalJson({ sha256, epochHourSec, kind: "gemini-egress" })`
 */
export function geminiEgressSigningPayload({ sha256, epochHourSec }) {
  return utf8ToBytes(
    canonicalJson({
      sha256: String(sha256).toLowerCase(),
      epochHourSec,
      kind: GEMINI_EGRESS_RECEIPT_KIND,
    }),
  );
}

/**
 * Canonicalises an outbound Gemini request, verifies it passes `assertContentFree`,
 * computes `sha256(canonicalRequest)`, and signs `{ sha256, epochHourSec, kind: "gemini-egress" }`
 * with the attested Ed25519 key `egress-signing`.
 */
export function signGeminiEgressReceipt(
  outboundRequest,
  keyPair = getKeyRing()["egress-signing"],
  timestampSec = Math.floor(Date.now() / 1000),
) {
  // Never sign or transmit a Gemini payload that violates the content-free firewall.
  assertContentFree(outboundRequest, "$.outboundGeminiRequest");

  const canonicalRequest = canonicalJson(outboundRequest);
  const sha256Digest = sha256Hex(canonicalRequest);
  const epochHourSec = coarsenEpochSecToHour(timestampSec);
  const signingBytes = geminiEgressSigningPayload({ sha256: sha256Digest, epochHourSec });
  const signature = bytesToHex(ed25519.sign(signingBytes, keyPair.secretKey)).toLowerCase();

  return {
    canonicalRequest,
    sha256: sha256Digest,
    epochHourSec,
    kind: GEMINI_EGRESS_RECEIPT_KIND,
    signature,
    publicKey: keyPair.publicKeyHex,
    spkiPublicKey: keyPair.spkiHex,
    keyId: "egress-signing",
  };
}

/**
 * Verifies a Gemini egress receipt:
 * 1. `sha256(canonicalRequest) === receipt.sha256`
 * 2. `JSON.parse(canonicalRequest)` passes `assertContentFree`
 * 3. `epochHourSec` is coarsened to the UTC hour (divisible by 3600)
 * 4. Ed25519 signature over `{ sha256, epochHourSec, kind: "gemini-egress" }` is valid under `publicKey`
 */
export function verifyGeminiEgressReceipt(receipt, expectedPublicKeyHex) {
  try {
    if (!receipt || typeof receipt !== "object") {
      return { ok: false, detail: "Receipt must be a non-null object." };
    }
    if (typeof receipt.canonicalRequest !== "string" || receipt.canonicalRequest.length === 0) {
      return { ok: false, detail: "Missing canonicalRequest string." };
    }
    if (typeof receipt.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(receipt.sha256)) {
      return { ok: false, detail: "Invalid sha256 hex digest." };
    }
    if (receipt.kind !== GEMINI_EGRESS_RECEIPT_KIND) {
      return { ok: false, detail: `Invalid receipt kind '${String(receipt.kind)}'.` };
    }
    if (
      typeof receipt.epochHourSec !== "number" ||
      !Number.isInteger(receipt.epochHourSec) ||
      receipt.epochHourSec <= 0 ||
      receipt.epochHourSec % 3600 !== 0
    ) {
      return { ok: false, detail: "epochHourSec must be a positive integer divisible by 3600." };
    }
    const pubHex = String(expectedPublicKeyHex ?? receipt.publicKey ?? "")
      .replace(/^0x/i, "")
      .toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubHex) || String(receipt.publicKey).toLowerCase() !== pubHex) {
      return { ok: false, detail: "Invalid or mismatched Ed25519 public key." };
    }
    const sigHex = String(receipt.signature ?? "").replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{128}$/.test(sigHex)) {
      return { ok: false, detail: "Invalid Ed25519 signature hex." };
    }

    const computedSha256 = sha256Hex(receipt.canonicalRequest);
    if (computedSha256 !== receipt.sha256) {
      return { ok: false, detail: "canonicalRequest SHA-256 does not match receipt.sha256." };
    }

    let parsedRequest;
    try {
      parsedRequest = JSON.parse(receipt.canonicalRequest);
    } catch {
      return { ok: false, detail: "canonicalRequest is not valid JSON." };
    }

    if (canonicalJson(parsedRequest) !== receipt.canonicalRequest) {
      return { ok: false, detail: "canonicalRequest is not in canonical JSON form." };
    }

    try {
      assertContentFree(parsedRequest, "$.canonicalRequest");
    } catch (err) {
      return {
        ok: false,
        detail: err instanceof Error ? err.message : "canonicalRequest failed assertContentFree.",
      };
    }

    const payload = geminiEgressSigningPayload({
      sha256: receipt.sha256,
      epochHourSec: receipt.epochHourSec,
    });
    const sigValid = ed25519.verify(hexToBytes(sigHex), payload, hexToBytes(pubHex));
    if (!sigValid) {
      return { ok: false, detail: "Ed25519 signature verification failed on egress receipt." };
    }

    return {
      ok: true,
      detail: "Gemini egress receipt SHA-256, content-free firewall, and Ed25519 signature verified.",
    };
  } catch {
    return { ok: false, detail: "Failed to verify Gemini egress receipt." };
  }
}

function concatBytes(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** RFC 6962 raw byte leaf hash: sha256(0x00 || rawLeafBytes) */
export function computeRawLeafHash(rawLeafBytes) {
  return sha256(concatBytes(Uint8Array.of(0x00), rawLeafBytes));
}

/** RFC 6962 leaf hash: sha256(0x00 || utf8ToBytes(canonicalJson(entry))) */
export function computeLeafHash(entry) {
  if (entry instanceof Uint8Array) {
    return computeRawLeafHash(entry);
  }
  const payload = utf8ToBytes(canonicalJson(entry));
  return computeRawLeafHash(payload);
}

/** RFC 6962 internal node hash: sha256(0x01 || left || right) */
export function computeNodeHash(left, right) {
  return sha256(concatBytes(Uint8Array.of(0x01), left, right));
}

function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/**
 * RFC 6962 Merkle tree root computation matching `src/lib/transparency/log.ts`.
 */
export function computeMerkleRootFromLeaves(leaves) {
  if (leaves.length === 0) {
    return sha256(new Uint8Array(0));
  }
  if (leaves.length === 1) {
    return leaves[0];
  }
  const k = largestPowerOfTwoLessThan(leaves.length);
  const left = computeMerkleRootFromLeaves(leaves.slice(0, k));
  const right = computeMerkleRootFromLeaves(leaves.slice(k));
  return computeNodeHash(left, right);
}

/**
 * Canonical leaf event builder matching `createVerificationLogEvent` in `src/lib/transparency/log.ts`.
 */
export function createVerificationLogEvent(params) {
  const epochHourSec = coarsenEpochSecToHour(
    params.timestampSec ?? params.epochHourSec ?? Math.floor(Date.now() / 1000),
  );
  const kind =
    params.kind === "release_approval"
      ? "release_approval"
      : params.kind === "independent_verification"
        ? "independent_verification"
        : "verification_event";
  const core = {
    index: params.index,
    kind,
    nodeId: String(params.nodeId ?? "tinfoil-router").slice(0, 80),
    nodeKind: "tinfoil",
    ok: Boolean(params.ok),
    measurement: String(params.measurement ?? "").slice(0, 256),
    evidenceHash: String(params.evidenceHash ?? "").slice(0, 128),
    ...(typeof params.releaseDigest === "string" && params.releaseDigest
      ? { releaseDigest: String(params.releaseDigest).slice(0, 128) }
      : {}),
    ...(typeof params.enclaveHost === "string" && params.enclaveHost
      ? { enclaveHost: String(params.enclaveHost).slice(0, 128) }
      : {}),
    ...(typeof params.verifierFingerprint === "string" && params.verifierFingerprint
      ? { verifierFingerprint: String(params.verifierFingerprint).slice(0, 64) }
      : {}),
    epochHourSec,
  };
  const leafHash = bytesToHex(computeLeafHash(core)).toLowerCase();
  return {
    ...core,
    leafHash,
  };
}

export class TreeHeadStateVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "TreeHeadStateVerificationError";
  }
}

function isSimulatedLeafRecord(raw) {
  if (!raw || typeof raw !== "object") return true;
  if (raw.nodeKind === "sim") return true;
  if (typeof raw.nodeId === "string" && raw.nodeId.trim().toLowerCase().startsWith("sim-")) {
    return true;
  }
  return false;
}

/**
 * Recomputes the RFC 6962 Merkle root from `drouter.transparency_log` in MongoDB
 * and verifies that the submitted `(treeSize, rootHash)` matches before signing.
 */
export async function verifyTreeHeadAgainstLog({ treeSize, rootHash, db }) {
  const database = db !== undefined ? db : await getMongoDb();
  if (!database || typeof database.collection !== "function") {
    throw new TreeHeadStateVerificationError(
      "Transparency log database is unavailable; refusing to sign unverified tree head.",
    );
  }

  const col = database.collection(TRANSPARENCY_COLLECTION_NAME);
  const queryCursor = col.find({ docType: "leaf" }, { projection: { _id: 0 } });
  const rawDocs =
    typeof queryCursor.sort === "function"
      ? await queryCursor.sort({ index: 1 }).toArray()
      : await queryCursor.toArray();

  if (!Array.isArray(rawDocs)) {
    throw new TreeHeadStateVerificationError("Failed to read leaves from transparency_log.");
  }

  const realDocs = rawDocs.filter((d) => !isSimulatedLeafRecord(d));
  if (realDocs.length !== treeSize) {
    throw new TreeHeadStateVerificationError(
      `Submitted treeSize (${treeSize}) does not match transparency_log leaf count (${realDocs.length}).`,
    );
  }

  const leafBytes = [];
  for (let idx = 0; idx < realDocs.length; idx++) {
    const raw = realDocs[idx];
    const sanitized = createVerificationLogEvent({
      ...raw,
      index: idx,
      timestampSec: raw.epochHourSec ?? raw.timestampSec,
    });
    if (
      typeof raw.leafHash === "string" &&
      raw.leafHash.toLowerCase() !== sanitized.leafHash.toLowerCase()
    ) {
      throw new TreeHeadStateVerificationError(
        `Transparency log leaf #${idx} stored leafHash does not match recomputed RFC 6962 leaf hash.`,
      );
    }
    leafBytes.push(hexToBytes(sanitized.leafHash));
  }

  const computedRootHash = bytesToHex(computeMerkleRootFromLeaves(leafBytes)).toLowerCase();
  if (computedRootHash !== String(rootHash).toLowerCase()) {
    throw new TreeHeadStateVerificationError(
      `Submitted rootHash (${String(rootHash).slice(0, 16)}...) does not match recomputed RFC 6962 Merkle root (${computedRootHash.slice(0, 16)}...).`,
    );
  }

  return {
    verified: true,
    treeSize: realDocs.length,
    rootHash: computedRootHash,
  };
}

/**
 * Exact canonical tree-head signing payload from `src/lib/transparency/log.ts`.
 */
export function treeHeadSigningPayload(sth) {
  return utf8ToBytes(
    canonicalJson({
      domain: STH_DOMAIN,
      rootHash: sth.rootHash.toLowerCase(),
      timestampSec: sth.timestampSec,
      treeSize: sth.treeSize,
    }),
  );
}

const ALLOWED_TREE_HEAD_KEYS = new Set([
  "treeSize",
  "rootHash",
  "timestampSec",
  "anchorTx",
  "anchoredAtSec",
]);

/**
 * Strictly validates a tree-head signing request for `POST /transparency/sign-tree-head`.
 */
export function validateTreeHeadInput(input) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.prototype.toString.call(input) !== "[object Object]"
  ) {
    return {
      valid: false,
      errors: ["Tree head payload must be a non-null plain JSON object."],
    };
  }

  const errors = [];
  for (const k of Object.getOwnPropertyNames(input)) {
    if (!ALLOWED_TREE_HEAD_KEYS.has(k)) {
      errors.push(`Unexpected field '${String(k).slice(0, 32)}' in tree head request.`);
    }
  }

  if (
    typeof input.treeSize !== "number" ||
    !Number.isInteger(input.treeSize) ||
    input.treeSize < 0 ||
    input.treeSize > 1_000_000_000
  ) {
    errors.push("'treeSize' must be a non-negative integer.");
  }

  if (typeof input.rootHash !== "string" || !/^[0-9a-fA-F]{64}$/.test(input.rootHash)) {
    errors.push("'rootHash' must be a 64-character hexadecimal SHA-256 digest.");
  }

  if (
    typeof input.timestampSec !== "number" ||
    !Number.isInteger(input.timestampSec) ||
    input.timestampSec <= 0 ||
    input.timestampSec % 3600 !== 0
  ) {
    errors.push(
      "'timestampSec' must be a positive integer coarsened to the UTC hour (divisible by 3600).",
    );
  }

  if (input.anchorTx !== undefined && input.anchorTx !== null) {
    if (typeof input.anchorTx !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(input.anchorTx)) {
      errors.push("'anchorTx' must be null or a 0x-prefixed 32-byte hex transaction hash.");
    }
  }

  if (input.anchoredAtSec !== undefined && input.anchoredAtSec !== null) {
    if (
      typeof input.anchoredAtSec !== "number" ||
      !Number.isInteger(input.anchoredAtSec) ||
      input.anchoredAtSec <= 0 ||
      input.anchoredAtSec % 3600 !== 0
    ) {
      errors.push("'anchoredAtSec' must be null or a positive UTC-hour integer timestamp.");
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    errors: [],
    treeHead: {
      treeSize: input.treeSize,
      rootHash: input.rootHash.toLowerCase(),
      timestampSec: input.timestampSec,
      anchorTx: input.anchorTx ?? null,
      anchoredAtSec: input.anchoredAtSec ?? null,
    },
  };
}

/**
 * Signs a validated tree head using the attested Ed25519 key `tree-signing`.
 */
export function signTreeHeadWithAttestedKey(
  input,
  keyPair = getKeyRing()["tree-signing"],
) {
  const validation = validateTreeHeadInput(input);
  if (!validation.valid || !validation.treeHead) {
    const err = new Error(`INVALID_TREE_HEAD: ${validation.errors.join("; ")}`);
    err.name = "TreeHeadValidationError";
    err.errors = validation.errors;
    throw err;
  }

  const th = validation.treeHead;
  const payload = treeHeadSigningPayload(th);
  const signature = bytesToHex(ed25519.sign(payload, keyPair.secretKey)).toLowerCase();

  return {
    treeSize: th.treeSize,
    rootHash: th.rootHash,
    timestampSec: th.timestampSec,
    operatorPublicKey: keyPair.publicKeyHex,
    spkiPublicKey: keyPair.spkiHex,
    keyId: "tree-signing",
    signature,
    anchorTx: th.anchorTx,
    anchoredAtSec: th.anchoredAtSec,
  };
}

/**
 * Validates input, recomputes the RFC 6962 Merkle root from `drouter.transparency_log` in MongoDB,
 * verifies `(treeSize, rootHash)` matches, and signs with the attested `tree-signing` key.
 */
export async function verifyAndSignTreeHead(
  input,
  { keyPair = getKeyRing()["tree-signing"], db } = {},
) {
  const validation = validateTreeHeadInput(input);
  if (!validation.valid || !validation.treeHead) {
    const err = new Error(`INVALID_TREE_HEAD: ${validation.errors.join("; ")}`);
    err.name = "TreeHeadValidationError";
    err.errors = validation.errors;
    throw err;
  }

  await verifyTreeHeadAgainstLog({
    treeSize: validation.treeHead.treeSize,
    rootHash: validation.treeHead.rootHash,
    db,
  });

  return signTreeHeadWithAttestedKey(validation.treeHead, keyPair);
}

/**
 * Verifies a signed tree head (matches `verifySignedTreeHeadClient` in `src/lib/transparency/log.ts`).
 */
export function verifySignedTreeHead(sth, expectedOperatorPublicKey) {
  try {
    if (!sth || typeof sth !== "object") {
      return { ok: false, detail: "Invalid signed tree head object" };
    }
    const pubHex = String(expectedOperatorPublicKey ?? sth.operatorPublicKey ?? "")
      .replace(/^0x/i, "")
      .toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubHex) || String(sth.operatorPublicKey).toLowerCase() !== pubHex) {
      return { ok: false, detail: "Operator public key mismatch or invalid format" };
    }
    if (!/^[0-9a-fA-F]{64}$/.test(sth.rootHash) || !/^[0-9a-fA-F]{128}$/.test(sth.signature)) {
      return { ok: false, detail: "Invalid rootHash or Ed25519 signature hex" };
    }
    if (!Number.isInteger(sth.treeSize) || sth.treeSize < 0) {
      return { ok: false, detail: "Invalid treeSize" };
    }
    if (!Number.isInteger(sth.timestampSec) || sth.timestampSec <= 0 || sth.timestampSec % 3600 !== 0) {
      return { ok: false, detail: "STH timestampSec must be coarsened to the UTC hour" };
    }
    const payload = treeHeadSigningPayload(sth);
    const verified = ed25519.verify(hexToBytes(sth.signature), payload, hexToBytes(pubHex));
    return {
      ok: verified,
      detail: verified
        ? `Attested tree-signing Ed25519 signature verified on tree head (size=${sth.treeSize}, root=${sth.rootHash.slice(0, 16)}...).`
        : "Ed25519 signature verification failed on signed tree head",
    };
  } catch {
    return { ok: false, detail: "Failed to verify signed tree head" };
  }
}
