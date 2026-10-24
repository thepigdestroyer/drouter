import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection } from "next/server";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import { SYNTHETIC_CHIP_ID_HEX_PREFIX } from "@/lib/sim/hardware";
import {
  deriveEd25519Key,
  getOperatorPublicKey,
  getSeedBytes,
  getTransparencyLog,
  proveConsistency,
  proveInclusion,
} from "@/lib/transparency/log";
import { getVerifierSet, issueQuorumTicket } from "@/lib/transparency/quorum";
import {
  appendVerificationEventToLog,
  getPersistedTransparencyLog,
} from "@/lib/transparency/store";

const transparencyGetLimiter = createTokenBucketLimiter({
  name: "transparency-get",
  capacity: 120,
  refillPerSec: 4,
});

const transparencyPostLimiter = createTokenBucketLimiter({
  name: "transparency-post-ip",
  capacity: 20,
  refillPerSec: 20 / 60,
});

const transparencyGlobalLimiter = createGlobalBucketLimiter({
  name: "transparency-post-global",
  capacity: 120,
  refillPerSec: 120 / 3600,
});

const MAX_TRANSPARENCY_BODY_BYTES = 16_384;
const HEX_RE = /^(0x)?[0-9a-fA-F]{1,256}$/;

function deriveNodeChipAndIdentity(nodeId: string): { chipId: string; nodeIdentityPk: string } {
  const seed = getSeedBytes();
  const tail = bytesToHex(hkdf(sha256, seed, undefined, utf8ToBytes(`sim/chip/${nodeId}`), 48));
  const chipId = `${SYNTHETIC_CHIP_ID_HEX_PREFIX}${tail}`;
  const nodeIdentityPk = deriveEd25519Key(`sim/identity/${nodeId}`).publicKeyHex;
  return { chipId, nodeIdentityPk };
}

function parseIntParam(url: URL, name: string): number | undefined {
  const raw = url.searchParams.get(name);
  if (raw === null || raw.trim() === "") return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = transparencyGetLimiter.check(request);
    if (limited) return limited;
  }

  let leafIndex: number | undefined;
  let firstSize: number | undefined;
  let secondSize: number | undefined;
  let anchorIfDue = false;

  if (request) {
    try {
      const url = new URL(request.url, "http://localhost");
      leafIndex = parseIntParam(url, "leafIndex");
      firstSize = parseIntParam(url, "first");
      secondSize = parseIntParam(url, "second");
      anchorIfDue = url.searchParams.get("anchor") === "1";
    } catch {
      // Ignore malformed URL query
    }
  }

  const log = getTransparencyLog();
  const proofs = [proveInclusion(0), proveInclusion(1), proveInclusion(2)];
  const releaseConsistencyProof = proveConsistency(
    firstSize !== undefined ? Math.min(firstSize, log.entries.length) : 1,
    secondSize !== undefined ? Math.min(secondSize, log.entries.length) : log.entries.length,
  );
  const verifierSet = getVerifierSet();
  const operatorPublicKey = getOperatorPublicKey();

  const nodeIds = ["tinfoil-router", "sim-1", "sim-2", "sim-3"] as const;
  const tickets = Object.fromEntries(
    nodeIds.map((nodeId) => {
      const { chipId, nodeIdentityPk } = deriveNodeChipAndIdentity(nodeId);
      return [
        nodeId,
        issueQuorumTicket({
          nodeId,
          chipId,
          nodeIdentityPk,
          epoch: 1,
          status: "full",
          weight: 10000,
          signerCount: 5,
        }),
      ];
    }),
  );

  const persistedLog = await getPersistedTransparencyLog({
    leafIndex,
    firstTreeSize: firstSize,
    secondTreeSize: secondSize,
    anchorIfDue,
  });

  return Response.json({
    quorumSimulated: true,
    operatorPublicKey,
    signedTreeHead: persistedLog.signedTreeHead,
    anchorExplorerUrl: persistedLog.anchorExplorerUrl,
    persisted: persistedLog.persisted,
    verificationLog: {
      root: persistedLog.signedTreeHead.rootHash,
      treeSize: persistedLog.signedTreeHead.treeSize,
      events: persistedLog.events,
      inclusionProofs: persistedLog.inclusionProofs,
      consistencyProof: persistedLog.consistencyProof,
    },
    consistencyProof: persistedLog.consistencyProof,
    releaseConsistencyProof,
    log,
    proofs,
    verifierSet,
    tickets,
  });
}

export async function POST(request: Request) {
  const limited = transparencyPostLimiter.check(request);
  if (limited) return limited;

  let body: Record<string, unknown>;
  try {
    const parsed = await readBoundedJson(request, MAX_TRANSPARENCY_BODY_BYTES);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Response.json({ error: "Invalid JSON object" }, { status: 400 });
    }
    body = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON" },
      { status: 400 },
    );
  }

  const globalCheck = transparencyGlobalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return Response.json(
      { error: "Transparency log write quota exceeded", retryAfterSec: globalCheck.retryAfterSec },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  const nodeId = typeof body.nodeId === "string" && body.nodeId.trim().length > 0 ? body.nodeId.trim().slice(0, 80) : null;
  const nodeKind = body.nodeKind === "tinfoil" || body.kind === "tinfoil" ? "tinfoil" : body.nodeKind === "sim" || body.kind === "sim" ? "sim" : null;
  const measurement = typeof body.measurement === "string" && body.measurement.trim().length > 0 ? body.measurement.trim().slice(0, 256) : null;
  const evidenceHash = typeof body.evidenceHash === "string" && HEX_RE.test(body.evidenceHash) ? body.evidenceHash : null;

  if (!nodeId || !nodeKind || !measurement || !evidenceHash) {
    return Response.json(
      { error: "nodeId, nodeKind ('tinfoil'|'sim'), measurement, and hex evidenceHash are required" },
      { status: 400 },
    );
  }

  const appended = await appendVerificationEventToLog({
    kind: body.eventKind === "release_approval" ? "release_approval" : "verification_event",
    nodeId,
    nodeKind,
    ok: body.ok !== false,
    measurement,
    evidenceHash,
    releaseDigest: typeof body.releaseDigest === "string" ? body.releaseDigest.slice(0, 128) : undefined,
    enclaveHost: typeof body.enclaveHost === "string" ? body.enclaveHost.slice(0, 128) : undefined,
    anchorOnArc: body.anchorOnArc === true,
  });

  return Response.json({
    ok: true,
    quorumSimulated: true,
    operatorPublicKey: getOperatorPublicKey(),
    persisted: appended.persisted,
    event: appended.event,
    inclusionProof: appended.inclusionProof,
    consistencyProof: appended.consistencyProof,
    signedTreeHead: appended.signedTreeHead,
  });
}
