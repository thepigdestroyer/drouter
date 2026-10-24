import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { fromHex, toHex, utf8 } from "./bytes";
import {
  APPROVED_MEASUREMENT,
  GPUS_PER_NODE,
  MAX_CONTEXT_TOKENS,
  SIM_MODEL_ID,
  SIM_MODEL_ROOT,
  SIM_TCB,
} from "./constants";
import { SimError } from "./errors";
import { chipId, gpuEvidence, identity, vcek, vcekCertificate } from "./hardware";
import { buildManifest, manifestHash, simNodeSpec } from "./manifest";
import {
  MSG,
  computeReportData,
  deriveSessionKeys,
  detokenize,
  nodeKeyAgreement,
  openMessage,
  sealMessage,
  signPop,
  splitIntoFrames,
  tokenize,
  transcriptHashFromPrefix,
  transcriptPrefix,
  unpadTokens,
} from "./protocol";
import { SIM_POLICY, signReport, tcbToU64, type SnpReportFields } from "./snp";
import { openTicket, sealTicket } from "./ticket";
import type {
  CloseRequest,
  EvidenceBundle,
  HelloRequest,
  HelloResponse,
  KeyshareRequest,
  KeyshareResponse,
  PopReceiptWire,
  TurnRequest,
  TurnResponse,
} from "./types";

/**
 * The simulated enclave node. Real cryptography, simulated hardware roots. Inputs and outputs are
 * the JSON wire shapes (hex strings for bytes); invalid input throws SimError with an HTTP status.
 */

export interface NodeContext {
  /** Clock override in milliseconds since the epoch (tests). */
  now?: number;
}

function nowMs(ctx: NodeContext): number {
  return ctx.now ?? Date.now();
}

function bytesField(name: string, value: unknown, length?: number): Uint8Array {
  try {
    return fromHex(value as string, length);
  } catch {
    throw new SimError(400, `${name} must be ${length ? `${length} bytes of ` : ""}hex`);
  }
}

export function nodeHello(simId: string, req: HelloRequest, ctx: NodeContext = {}): HelloResponse {
  simNodeSpec(simId);
  const now = nowMs(ctx);
  const clientNonce = bytesField("clientNonce", req?.clientNonce, 32);
  if (req.modelId !== SIM_MODEL_ID) throw new SimError(400, `unsupported model ${String(req.modelId)}`);

  const manifest = buildManifest(simId);
  const mHash = manifestHash(manifest);
  const nodeIdentity = identity(simId);
  const custodyX = x25519.keygen();
  const custodyQ = ml_kem768.keygen();

  const reportData = computeReportData({
    clientNonce,
    nodeIdentityPk: nodeIdentity.publicKey,
    custodyX25519Pk: custodyX.publicKey,
    custodyMlkemPk: custodyQ.publicKey,
    manifestHash: mHash,
    modelRoot: SIM_MODEL_ROOT,
  });

  const tcb = tcbToU64(SIM_TCB);
  const fields: SnpReportFields = {
    version: 3,
    guestSvn: 1,
    policy: SIM_POLICY,
    familyId: new Uint8Array(16),
    imageId: new Uint8Array(16),
    vmpl: 0,
    signatureAlgo: 1,
    currentTcb: tcb,
    platformInfo: BigInt(0),
    flags: 0,
    reportData,
    measurement: APPROVED_MEASUREMENT,
    hostData: new Uint8Array(32),
    idKeyDigest: new Uint8Array(48),
    authorKeyDigest: new Uint8Array(48),
    reportId: crypto.getRandomValues(new Uint8Array(32)),
    reportIdMa: new Uint8Array(32).fill(0xff),
    reportedTcb: tcb,
    chipId: chipId(simId),
    committedTcb: tcb,
    launchTcb: tcb,
  };

  const evidence: EvidenceBundle = {
    simId,
    simulated: true,
    report: toHex(signReport(fields, vcek(simId).secretKey)),
    vcekCertificate: vcekCertificate(simId),
    gpus: Array.from({ length: GPUS_PER_NODE }, (_, i) => gpuEvidence(simId, i, clientNonce)),
    manifest,
    manifestHash: toHex(mHash),
    modelId: SIM_MODEL_ID,
    modelRoot: toHex(SIM_MODEL_ROOT),
    custody: { x25519PublicKey: toHex(custodyX.publicKey), mlkemPublicKey: toHex(custodyQ.publicKey) },
    identityPublicKey: toHex(nodeIdentity.publicKey),
  };

  const hello = { clientNonce: toHex(clientNonce), modelId: req.modelId };
  const prefix = transcriptPrefix(hello, evidence);

  const ticket = sealTicket(
    {
      kind: "pending",
      simId,
      clientNonce: hello.clientNonce,
      modelId: req.modelId,
      transcriptPrefix: new TextDecoder().decode(prefix),
      custodyX25519Sk: toHex(custodyX.secretKey),
      custodyMlkemSk: toHex(custodyQ.secretKey),
    },
    now,
  );
  return { simulated: true, evidence, ticket };
}

export function nodeKeyshare(simId: string, req: KeyshareRequest, ctx: NodeContext = {}): KeyshareResponse {
  simNodeSpec(simId);
  const now = nowMs(ctx);
  const pending = openTicket(simId, req?.ticket, "pending", now);
  const clientX25519Pk = bytesField("clientX25519Pk", req.clientX25519Pk, 32);
  const mlkemCt = bytesField("mlkemCt", req.mlkemCt, 1088);
  const sealed = bytesField("sealed", req.sealed);

  let ikm: Uint8Array;
  try {
    ikm = nodeKeyAgreement(
      fromHex(pending.custodyX25519Sk),
      fromHex(pending.custodyMlkemSk),
      clientX25519Pk,
      mlkemCt,
    );
  } catch {
    throw new SimError(400, "key agreement failed");
  }
  const th = transcriptHashFromPrefix(utf8(pending.transcriptPrefix), clientX25519Pk, mlkemCt);
  const keys = deriveSessionKeys({ clientNonce: fromHex(pending.clientNonce), ikm, transcriptHash: th });

  let params: { modelId?: unknown };
  try {
    const opened = openMessage(keys.kUp, "up", keys.sessionId, 0, MSG.params, sealed, BigInt(0));
    if (opened.counter !== BigInt(0)) throw new Error("session params must use counter 0");
    params = JSON.parse(new TextDecoder().decode(opened.plaintext));
  } catch {
    throw new SimError(400, "session parameters failed authentication");
  }
  if (params.modelId !== pending.modelId) throw new SimError(400, "session model does not match hello");

  const ready = sealMessage(keys.kDown, "down", BigInt(0), keys.sessionId, 0, MSG.ready, utf8("ready"));
  const ticket = sealTicket(
    {
      kind: "session",
      simId,
      kUp: toHex(keys.kUp),
      kDown: toHex(keys.kDown),
      sessionId: toHex(keys.sessionId),
      upNext: 1,
      downNext: 1,
      nextTurn: 1,
      context: "",
    },
    now,
  );
  return { simulated: true, ready: toHex(ready), ticket };
}

function respondTo(simId: string, input: string, tokensIn: number, contextBefore: number): string {
  if (input === "/count") return String(contextBefore);
  return (
    `Simulated enclave ${simId} received ${tokensIn} tokens inside the bubble. ` +
    `Session context: ${contextBefore + tokensIn} tokens. ` +
    "This node simulates the hardware; route to a Tinfoil node for a real model."
  );
}

export function nodeTurn(simId: string, req: TurnRequest, ctx: NodeContext = {}): TurnResponse {
  simNodeSpec(simId);
  const now = nowMs(ctx);
  const session = openTicket(simId, req?.ticket, "session", now);
  const ct = bytesField("ct", req.ct);
  if (!Number.isInteger(req.turn) || req.turn !== session.nextTurn) {
    throw new SimError(409, "unexpected turn index");
  }

  const kUp = fromHex(session.kUp);
  const kDown = fromHex(session.kDown);
  const sessionId = fromHex(session.sessionId);

  let tokens: number[];
  let upCounter: bigint;
  try {
    const opened = openMessage(kUp, "up", sessionId, req.turn, MSG.input, ct, BigInt(session.upNext));
    upCounter = opened.counter;
    tokens = unpadTokens(opened.plaintext);
  } catch (err) {
    const replay = err instanceof Error && /counter/.test(err.message);
    throw new SimError(400, replay ? "replayed or out-of-order counter" : "message failed authentication");
  }

  if (tokens.some((t) => t > 0xff)) throw new SimError(400, "tokens outside the UTF-8 byte vocabulary");
  const context = fromHex(session.context);
  if (context.length + tokens.length > MAX_CONTEXT_TOKENS) throw new SimError(413, "session context is full");

  // No real model runs here; the reply is a fixed template (see respondTo).
  const reply = tokenize(respondTo(simId, detokenize(tokens), tokens.length, context.length));

  let downCounter = session.downNext;
  const frames = splitIntoFrames(reply).map((plain) =>
    toHex(sealMessage(kDown, "down", BigInt(downCounter++), sessionId, req.turn, MSG.output, plain)),
  );

  const nextContext = new Uint8Array(context.length + tokens.length);
  nextContext.set(context);
  nextContext.set(tokens, context.length);

  const ticket = sealTicket(
    {
      ...session,
      upNext: Number(upCounter) + 1,
      downNext: downCounter,
      nextTurn: session.nextTurn + 1,
      context: toHex(nextContext),
    },
    now,
  );
  return { simulated: true, frames, ticket };
}

export function nodeClose(simId: string, req: CloseRequest, ctx: NodeContext = {}): PopReceiptWire {
  simNodeSpec(simId);
  const now = nowMs(ctx);
  const session = openTicket(simId, req?.ticket, "session", now);
  return {
    simulated: true,
    ...signPop(
      {
        nodeId: simId,
        sessionIdHash: toHex(sha256(fromHex(session.sessionId))),
        time: Math.floor(now / 1000),
        measurement: toHex(APPROVED_MEASUREMENT),
      },
      identity(simId).secretKey,
    ),
  };
}
