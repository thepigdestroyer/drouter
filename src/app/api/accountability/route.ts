import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection } from "next/server";
import {
  createCompromiseClaimForDemo,
  DEFAULT_OPERATOR_STAKE_USDC,
  FORBIDDEN_PREFIX_HEX,
  type KeyCompromiseClaim,
  type KeyCompromiseVerdict,
  verifyKeyCompromiseBounty,
} from "@/lib/accountability/bounty";
import {
  type CanaryLeakVerdict,
  type CanarySession,
  createCanarySession,
  verifyCanaryLeak,
} from "@/lib/accountability/canary";
import { defaultLatencyTriangulations } from "@/lib/accountability/latency";
import {
  defaultManifests,
  deriveNodeChipId,
  deriveNodeIdentityKey,
} from "@/lib/accountability/manifest";
import {
  evaluateHeartbeatWindow,
  type HeartbeatEvaluation,
  type HeartbeatEvent,
} from "@/lib/accountability/ramp";
import {
  ARC_EXPLORER,
  explorerAddress,
  explorerTx,
  hashEvidenceObject,
  listNodes,
  nodeIdFor,
  readMinStakeUsdc,
  readOnChainNode,
  recordVerification,
} from "@/lib/arc/registry";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import type { Hex } from "@/lib/types";

const MAX_ACCOUNTABILITY_BODY_BYTES = 8192;
const MAX_RECENT_CLAIMS = 50;
const MAX_HEARTBEATS_PER_NODE = 64;

const getLimiter = createTokenBucketLimiter({
  name: "accountability-get",
  capacity: 60,
  refillPerSec: 2,
});

// Strict per-IP rate limit for human-triggered accountability actions
const postLimiter = createTokenBucketLimiter({
  name: "accountability-post",
  capacity: 6,
  refillPerSec: 6 / 3600,
});

// Strict global rate limit to protect the Arc verifier wallet USDC gas
const globalAccountabilityLimiter = createGlobalBucketLimiter({
  name: "accountability-arc-global",
  capacity: 12,
  refillPerSec: 12 / 3600,
});

export function resetAccountabilityRateLimitForTests(): void {
  globalAccountabilityLimiter.reset();
}

const DEMO_NODE_IDS = ["tinfoil-router", "sim-1", "sim-2", "sim-3"] as const;
const BASE_NOW_SEC = 1760100000;
const APPROVED_MEASUREMENT_HEX = bytesToHex(
  sha384(utf8ToBytes("drouter-sim-node-image/v0.1.0")),
);

export interface RecordedClaimEvent {
  id: string;
  kind: "canary-leak" | "key-compromise" | "restart" | "clone-detected";
  nodeId: string;
  timestamp: number;
  slashUsdc: number;
  bountyUsdc: number;
  compensationPoolUsdc: number;
  summary: string;
  detail: unknown;
  evidenceHash: Hex;
  txHash: Hex | null;
  explorerUrl: string | null;
  onChain: boolean;
}

interface AccountabilityStore {
  nowSec: number;
  epoch: number;
  heartbeatsByNode: Record<string, HeartbeatEvent[]>;
  activeCanaries: Record<string, CanarySession>;
  recentClaims: RecordedClaimEvent[];
}

function createInitialStore(): AccountabilityStore {
  const heartbeatsByNode: Record<string, HeartbeatEvent[]> = {};
  const activeCanaries: Record<string, CanarySession> = {};

  for (const nodeId of DEMO_NODE_IDS) {
    const { publicKeyHex } = deriveNodeIdentityKey(nodeId);
    heartbeatsByNode[nodeId] = [
      { nodeIdentityPk: publicKeyHex, timestamp: BASE_NOW_SEC - 30 },
      { nodeIdentityPk: publicKeyHex, timestamp: BASE_NOW_SEC - 20 },
      { nodeIdentityPk: publicKeyHex, timestamp: BASE_NOW_SEC - 10 },
      { nodeIdentityPk: publicKeyHex, timestamp: BASE_NOW_SEC },
    ];
    activeCanaries[nodeId] = createCanarySession(nodeId, publicKeyHex, 1);
  }

  return {
    nowSec: BASE_NOW_SEC,
    epoch: 1,
    heartbeatsByNode,
    activeCanaries,
    recentClaims: [],
  };
}

const store: AccountabilityStore = createInitialStore();

function computeRampStates(): Record<string, HeartbeatEvaluation & { nodeId: string }> {
  const out: Record<string, HeartbeatEvaluation & { nodeId: string }> = {};
  for (const nodeId of DEMO_NODE_IDS) {
    const events = store.heartbeatsByNode[nodeId] ?? [];
    out[nodeId] = {
      nodeId,
      ...evaluateHeartbeatWindow(events, store.nowSec),
    };
  }
  return out;
}

async function resolveNodeStakeUsdc(nodeId: string): Promise<{
  stakeUsdc: number;
  onChainRead: boolean;
}> {
  const onChainNode = await readOnChainNode(nodeId);
  if (onChainNode) {
    const parsed = Number(onChainNode.stake);
    if (Number.isFinite(parsed) && parsed > 0) {
      return { stakeUsdc: parsed, onChainRead: true };
    }
  }
  const minStake = await readMinStakeUsdc();
  if (minStake !== null && minStake > 0) {
    return { stakeUsdc: minStake, onChainRead: true };
  }
  return { stakeUsdc: DEFAULT_OPERATOR_STAKE_USDC, onChainRead: false };
}

async function recordAccountabilityEvidenceOnChain(
  nodeId: string,
  evidencePayload: unknown,
): Promise<{
  evidenceHash: Hex;
  txHash: Hex | null;
  explorerUrl: string | null;
  onChain: boolean;
}> {
  const evidenceHash = hashEvidenceObject(evidencePayload);
  const registryNodeId = nodeIdFor(nodeId);
  if (!registryNodeId || process.env.DROUTER_STUB_UPSTREAM === "1") {
    return {
      evidenceHash,
      txHash: null,
      explorerUrl: null,
      onChain: false,
    };
  }

  const txHash = await recordVerification(registryNodeId, false, evidenceHash);
  const explorerUrl = txHash ? explorerTx(txHash) : null;
  return {
    evidenceHash,
    txHash,
    explorerUrl,
    onChain: Boolean(txHash),
  };
}

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }

  const registry = await listNodes();
  const latestClaim = store.recentClaims[0];
  const latestTx = latestClaim?.txHash ?? null;
  const explorerUrl = latestTx
    ? explorerTx(latestTx)
    : registry.address
      ? explorerAddress(registry.address)
      : ARC_EXPLORER;

  return Response.json({
    manifests: defaultManifests(),
    rampStates: computeRampStates(),
    activeCanaries: store.activeCanaries,
    recentClaims: store.recentClaims,
    forbiddenPrefix: FORBIDDEN_PREFIX_HEX,
    latencyTriangulations: defaultLatencyTriangulations(),
    registrySource: registry.source,
    registryNodes: registry.nodes,
    minStakeUsdc: registry.minStake ?? String(DEFAULT_OPERATOR_STAKE_USDC),
    txHash: latestTx,
    explorerUrl,
    onChain: registry.onChain,
  });
}

function pushClaim(eventRecord: RecordedClaimEvent) {
  store.recentClaims.unshift(eventRecord);
  if (store.recentClaims.length > MAX_RECENT_CLAIMS) {
    store.recentClaims.length = MAX_RECENT_CLAIMS;
  }
}

export async function POST(request: Request) {
  const limited = postLimiter.check(request);
  if (limited) return limited;

  let body: { action?: string; nodeId?: string };
  try {
    body = await readBoundedJson<{ action?: string; nodeId?: string }>(
      request,
      MAX_ACCOUNTABILITY_BODY_BYTES,
    );
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON request body" },
      { status: 400 },
    );
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return Response.json({ error: "Invalid JSON request body" }, { status: 400 });
  }

  const action = body.action;
  const nodeId = typeof body.nodeId === "string" && body.nodeId ? body.nodeId : "sim-1";

  if (!DEMO_NODE_IDS.includes(nodeId as (typeof DEMO_NODE_IDS)[number])) {
    return Response.json({ error: "Unknown nodeId" }, { status: 400 });
  }

  if (
    action !== "trigger-canary" &&
    action !== "claim-key-bounty" &&
    action !== "simulate-restart" &&
    action !== "simulate-clone"
  ) {
    return Response.json(
      {
        error:
          "Unsupported action. Expected trigger-canary, claim-key-bounty, simulate-restart, or simulate-clone.",
      },
      { status: 400 },
    );
  }

  const globalCheck = globalAccountabilityLimiter.consume(1);
  if (!globalCheck.allowed) {
    return Response.json(
      {
        error: "Hourly on-chain accountability transaction cap reached.",
        retryAfterSec: globalCheck.retryAfterSec,
      },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  store.nowSec += 10;
  const { publicKeyHex } = deriveNodeIdentityKey(nodeId);
  const { stakeUsdc } = await resolveNodeStakeUsdc(nodeId);

  if (action === "trigger-canary") {
    const canary =
      store.activeCanaries[nodeId] ??
      createCanarySession(nodeId, publicKeyHex, store.epoch);
    const verdict: CanaryLeakVerdict = verifyCanaryLeak({
      honeytoken: canary.honeytoken,
      salt: canary.salt,
      nodeIdentityPk: publicKeyHex,
      epoch: store.epoch,
      commitment: canary.commitment,
      stakeUsdc,
    });

    const evidenceObj = {
      kind: "canary-leak",
      nodeId,
      sessionId: canary.sessionId,
      commitment: canary.commitment,
      honeytokenHash: bytesToHex(sha256(utf8ToBytes(canary.honeytoken))),
      salt: canary.salt,
      epoch: store.epoch,
      stakeUsdc,
      valid: verdict.valid,
    };
    const chainRes = await recordAccountabilityEvidenceOnChain(nodeId, evidenceObj);

    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.epoch}-${store.recentClaims.length + 1}`,
      kind: "canary-leak",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: verdict.slashUsdc,
      bountyUsdc: verdict.reporterBountyUsdc,
      compensationPoolUsdc: verdict.compensationPoolUsdc,
      summary: verdict.reason,
      detail: { canary, verdict, evidenceHash: chainRes.evidenceHash },
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
    };
    pushClaim(eventRecord);
    store.epoch += 1;
    store.activeCanaries[nodeId] = createCanarySession(nodeId, publicKeyHex, store.epoch);

    return Response.json({
      ok: true,
      action,
      nodeId,
      canary,
      verdict,
      event: eventRecord,
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
      rampStates: computeRampStates(),
      activeCanaries: store.activeCanaries,
      recentClaims: store.recentClaims,
    });
  }

  if (action === "claim-key-bounty") {
    const chipId = deriveNodeChipId(nodeId);
    const claim: KeyCompromiseClaim = createCompromiseClaimForDemo(
      nodeId,
      chipId,
      APPROVED_MEASUREMENT_HEX,
    );
    const verdict: KeyCompromiseVerdict = verifyKeyCompromiseBounty(
      claim,
      APPROVED_MEASUREMENT_HEX,
      stakeUsdc,
    );

    const evidenceObj = {
      kind: "key-compromise",
      nodeId,
      chipId: claim.chipId,
      measurement: claim.measurement,
      reportDataHex: claim.reportDataHex,
      signatureHex: claim.signatureHex,
      vcekPublicKeyHex: claim.vcekPublicKeyHex,
      stakeUsdc,
      valid: verdict.valid,
    };
    const chainRes = await recordAccountabilityEvidenceOnChain(nodeId, evidenceObj);

    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.epoch}-${store.recentClaims.length + 1}`,
      kind: "key-compromise",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: verdict.slashUsdc,
      bountyUsdc: verdict.submitterBountyUsdc,
      compensationPoolUsdc: 0,
      summary: verdict.reason,
      detail: { claim, verdict, evidenceHash: chainRes.evidenceHash },
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
    };
    pushClaim(eventRecord);

    return Response.json({
      ok: true,
      action,
      nodeId,
      claim,
      verdict,
      event: eventRecord,
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
      rampStates: computeRampStates(),
      activeCanaries: store.activeCanaries,
      recentClaims: store.recentClaims,
    });
  }

  if (action === "simulate-restart") {
    const rotatedPk = bytesToHex(
      sha256(utf8ToBytes(`rotated-identity/${nodeId}/${store.nowSec}`)),
    );
    const events = store.heartbeatsByNode[nodeId] ?? [];
    // Advance by > 60s and rotate ephemeral enclave identity key
    store.nowSec += 120;
    events.push({
      nodeIdentityPk: rotatedPk,
      timestamp: store.nowSec,
    });
    if (events.length > MAX_HEARTBEATS_PER_NODE) {
      events.splice(0, events.length - MAX_HEARTBEATS_PER_NODE);
    }
    store.heartbeatsByNode[nodeId] = events;

    const evaluation = evaluateHeartbeatWindow(events, store.nowSec);
    const evidenceObj = {
      kind: "restart",
      nodeId,
      rotatedIdentityPk: rotatedPk,
      restartsIn30d: evaluation.restartsIn30d,
      phase: evaluation.phase,
      weightBps: evaluation.weightBps,
      timestamp: store.nowSec,
    };
    const chainRes = await recordAccountabilityEvidenceOnChain(nodeId, evidenceObj);

    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.epoch}-${store.recentClaims.length + 1}`,
      kind: "restart",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: 0,
      bountyUsdc: 0,
      compensationPoolUsdc: 0,
      summary: evaluation.detail,
      detail: { ...evaluation, evidenceHash: chainRes.evidenceHash },
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
    };
    pushClaim(eventRecord);

    return Response.json({
      ok: true,
      action,
      nodeId,
      evaluation,
      event: eventRecord,
      evidenceHash: chainRes.evidenceHash,
      txHash: chainRes.txHash,
      explorerUrl: chainRes.explorerUrl,
      onChain: chainRes.onChain,
      rampStates: computeRampStates(),
      activeCanaries: store.activeCanaries,
      recentClaims: store.recentClaims,
    });
  }

  // action === "simulate-clone"
  const clonedPkA = bytesToHex(
    sha256(utf8ToBytes(`clone-a/${nodeId}/${store.nowSec}`)),
  );
  const clonedPkB = bytesToHex(
    sha256(utf8ToBytes(`clone-b/${nodeId}/${store.nowSec}`)),
  );
  const events = store.heartbeatsByNode[nodeId] ?? [];
  events.push(
    { nodeIdentityPk: clonedPkA, timestamp: store.nowSec - 5 },
    { nodeIdentityPk: clonedPkB, timestamp: store.nowSec },
  );
  if (events.length > MAX_HEARTBEATS_PER_NODE) {
    events.splice(0, events.length - MAX_HEARTBEATS_PER_NODE);
  }
  store.heartbeatsByNode[nodeId] = events;

  const evaluation = evaluateHeartbeatWindow(events, store.nowSec);
  const evidenceObj = {
    kind: "clone-detected",
    nodeId,
    clonedPkA,
    clonedPkB,
    dualIdentityDetected: evaluation.dualIdentityDetected,
    phase: evaluation.phase,
    weightBps: evaluation.weightBps,
    stakeUsdc,
    timestamp: store.nowSec,
  };
  const chainRes = await recordAccountabilityEvidenceOnChain(nodeId, evidenceObj);

  const eventRecord: RecordedClaimEvent = {
    id: `claim-${store.epoch}-${store.recentClaims.length + 1}`,
    kind: "clone-detected",
    nodeId,
    timestamp: store.nowSec,
    slashUsdc: stakeUsdc,
    bountyUsdc: 0,
    compensationPoolUsdc: 0,
    summary: evaluation.detail,
    detail: { ...evaluation, evidenceHash: chainRes.evidenceHash },
    evidenceHash: chainRes.evidenceHash,
    txHash: chainRes.txHash,
    explorerUrl: chainRes.explorerUrl,
    onChain: chainRes.onChain,
  };
  pushClaim(eventRecord);

  return Response.json({
    ok: true,
    action,
    nodeId,
    evaluation,
    event: eventRecord,
    evidenceHash: chainRes.evidenceHash,
    txHash: chainRes.txHash,
    explorerUrl: chainRes.explorerUrl,
    onChain: chainRes.onChain,
    rampStates: computeRampStates(),
    activeCanaries: store.activeCanaries,
    recentClaims: store.recentClaims,
  });
}
