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

export async function GET() {
  await connection();

  return Response.json({
    manifests: defaultManifests(),
    rampStates: computeRampStates(),
    activeCanaries: store.activeCanaries,
    recentClaims: store.recentClaims,
    forbiddenPrefix: FORBIDDEN_PREFIX_HEX,
    latencyTriangulations: defaultLatencyTriangulations(),
  });
}

export async function POST(request: Request) {
  let body: { action?: string; nodeId?: string };
  try {
    body = (await request.json()) as { action?: string; nodeId?: string };
  } catch {
    return Response.json({ error: "Invalid JSON request body" }, { status: 400 });
  }

  const action = body.action;
  const nodeId = body.nodeId || "sim-1";

  if (!DEMO_NODE_IDS.includes(nodeId as (typeof DEMO_NODE_IDS)[number])) {
    return Response.json({ error: `Unknown nodeId: ${nodeId}` }, { status: 400 });
  }

  store.nowSec += 10;
  const { publicKeyHex } = deriveNodeIdentityKey(nodeId);

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
      stakeUsdc: DEFAULT_OPERATOR_STAKE_USDC,
    });

    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.recentClaims.length + 1}`,
      kind: "canary-leak",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: verdict.slashUsdc,
      bountyUsdc: verdict.reporterBountyUsdc,
      compensationPoolUsdc: verdict.compensationPoolUsdc,
      summary: verdict.reason,
      detail: { canary, verdict },
    };
    store.recentClaims.unshift(eventRecord);
    store.epoch += 1;
    store.activeCanaries[nodeId] = createCanarySession(nodeId, publicKeyHex, store.epoch);

    return Response.json({
      ok: true,
      action,
      nodeId,
      canary,
      verdict,
      event: eventRecord,
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
      DEFAULT_OPERATOR_STAKE_USDC,
    );

    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.recentClaims.length + 1}`,
      kind: "key-compromise",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: verdict.slashUsdc,
      bountyUsdc: verdict.submitterBountyUsdc,
      compensationPoolUsdc: verdict.slashUsdc - verdict.submitterBountyUsdc,
      summary: verdict.reason,
      detail: { claim, verdict },
    };
    store.recentClaims.unshift(eventRecord);

    return Response.json({
      ok: true,
      action,
      nodeId,
      claim,
      verdict,
      event: eventRecord,
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
    store.heartbeatsByNode[nodeId] = events;

    const evaluation = evaluateHeartbeatWindow(events, store.nowSec);
    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.recentClaims.length + 1}`,
      kind: "restart",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: 0,
      bountyUsdc: 0,
      compensationPoolUsdc: 0,
      summary: evaluation.detail,
      detail: evaluation,
    };
    store.recentClaims.unshift(eventRecord);

    return Response.json({
      ok: true,
      action,
      nodeId,
      evaluation,
      event: eventRecord,
      rampStates: computeRampStates(),
      activeCanaries: store.activeCanaries,
      recentClaims: store.recentClaims,
    });
  }

  if (action === "simulate-clone") {
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
    store.heartbeatsByNode[nodeId] = events;

    const evaluation = evaluateHeartbeatWindow(events, store.nowSec);
    const eventRecord: RecordedClaimEvent = {
      id: `claim-${store.recentClaims.length + 1}`,
      kind: "clone-detected",
      nodeId,
      timestamp: store.nowSec,
      slashUsdc: DEFAULT_OPERATOR_STAKE_USDC,
      bountyUsdc: 0,
      compensationPoolUsdc: DEFAULT_OPERATOR_STAKE_USDC,
      summary: evaluation.detail,
      detail: evaluation,
    };
    store.recentClaims.unshift(eventRecord);

    return Response.json({
      ok: true,
      action,
      nodeId,
      evaluation,
      event: eventRecord,
      rampStates: computeRampStates(),
      activeCanaries: store.activeCanaries,
      recentClaims: store.recentClaims,
    });
  }

  return Response.json(
    {
      error: `Unsupported action: ${String(action)}. Expected trigger-canary, claim-key-bounty, simulate-restart, or simulate-clone.`,
    },
    { status: 400 },
  );
}
