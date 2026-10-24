import { sha256 } from "@noble/hashes/sha2.js";
import type { CheckResult, PopReceipt } from "../types";
import { fromHex, toHex, utf8 } from "./bytes";
import { runChecks, type SimEvidenceSummary } from "./checks";
import {
  MSG,
  clientKeyAgreement,
  decodeFrame,
  deriveSessionKeys,
  openMessage,
  padTokens,
  sealMessage,
  tokenize,
  transcriptHash,
  verifyPop,
} from "./protocol";
import type {
  EvidenceBundle,
  HelloResponse,
  KeyshareResponse,
  PopReceiptWire,
  SimRoots,
  TurnResponse,
} from "./types";

/** Browser client for a simulated dRouter enclave node. Runs the attestation checks locally. */

export type { SimEvidenceSummary } from "./checks";

export interface SimSession {
  simId: string;
  checks: CheckResult[];
  evidence: SimEvidenceSummary;
  send(text: string): AsyncIterable<string>;
  close(): Promise<PopReceipt>;
}

export interface OpenSimSessionOptions {
  onCheck?: (c: CheckResult) => void;
  /** Fetch implementation override (tests, server-side use). Defaults to the global fetch. */
  fetch?: typeof fetch;
}

export async function openSimSession(
  baseUrl: string,
  simId: string,
  opts: OpenSimSessionOptions = {},
): Promise<SimSession> {
  const doFetch = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const base = baseUrl.replace(/\/+$/, "");

  async function call<T>(path: string, body?: unknown): Promise<T> {
    const res = await doFetch(`${base}/api/sim/${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
    const json = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new Error(json.error ?? `sim node request failed (${res.status})`);
    return json as T;
  }

  const roots = await call<SimRoots>("roots");
  const node = roots.nodes.find((n) => n.simId === simId);
  if (!node) throw new Error(`unknown simulated node ${simId}`);

  // 1. Hello with a fresh nonce, then verify the evidence before sending anything private.
  const modelId = roots.model.id;
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const hello = { clientNonce: toHex(clientNonce), modelId };
  const helloRes = await call<HelloResponse>(`${encodeURIComponent(simId)}/hello`, hello);
  const evidence: EvidenceBundle = helloRes.evidence;

  const { checks, summary } = runChecks({ roots, simId, modelId, clientNonce, evidence }, opts.onCheck);

  // 2. Hybrid key share bound to the transcript, then confirm the node derived the same keys.
  const kem = clientKeyAgreement(
    fromHex(evidence.custody.x25519PublicKey, 32),
    fromHex(evidence.custody.mlkemPublicKey),
  );
  const th = transcriptHash(hello, evidence, kem.clientX25519Pk, kem.mlkemCt);
  const keys = deriveSessionKeys({ clientNonce, ikm: kem.ikm, transcriptHash: th });
  const sealedParams = sealMessage(
    keys.kUp,
    "up",
    BigInt(0),
    keys.sessionId,
    0,
    MSG.params,
    utf8(JSON.stringify({ modelId })),
  );
  const keyshare = await call<KeyshareResponse>(`${encodeURIComponent(simId)}/keyshare`, {
    ticket: helloRes.ticket,
    clientX25519Pk: toHex(kem.clientX25519Pk),
    mlkemCt: toHex(kem.mlkemCt),
    sealed: toHex(sealedParams),
  });
  const ready = openMessage(keys.kDown, "down", keys.sessionId, 0, MSG.ready, fromHex(keyshare.ready), BigInt(0));
  if (new TextDecoder().decode(ready.plaintext) !== "ready") throw new Error("node did not confirm the session");

  let ticket = keyshare.ticket;
  let upCounter = BigInt(1);
  let downNext = ready.counter + BigInt(1);
  let turn = 1;
  let busy = false;
  let closed = false;

  async function* send(text: string): AsyncGenerator<string> {
    if (closed) throw new Error("session is closed");
    if (busy) throw new Error("a turn is already in progress");
    busy = true;
    try {
      const thisTurn = turn;
      const padded = padTokens(tokenize(text));
      const ct = sealMessage(keys.kUp, "up", upCounter++, keys.sessionId, thisTurn, MSG.input, padded);
      const res = await call<TurnResponse>(`${encodeURIComponent(simId)}/turn`, {
        ticket,
        turn: thisTurn,
        ct: toHex(ct),
      });
      ticket = res.ticket;
      turn = thisTurn + 1;

      const decoder = new TextDecoder();
      let sawFinal = false;
      for (const hex of res.frames) {
        if (sawFinal) throw new Error("node sent frames after the final frame");
        const opened = openMessage(keys.kDown, "down", keys.sessionId, thisTurn, MSG.output, fromHex(hex), downNext);
        downNext = opened.counter + BigInt(1);
        const frame = decodeFrame(opened.plaintext);
        sawFinal = frame.final;
        const chunk = decoder.decode(Uint8Array.from(frame.tokens), { stream: !frame.final });
        if (chunk) yield chunk;
      }
      if (!sawFinal) throw new Error("node response ended without a final frame");
    } finally {
      busy = false;
    }
  }

  async function close(): Promise<PopReceipt> {
    if (closed) throw new Error("session is already closed");
    const wire = await call<PopReceiptWire>(`${encodeURIComponent(simId)}/close`, { ticket });
    closed = true;
    const verified =
      verifyPop(wire, fromHex(node!.identityPublicKey, 32)) &&
      wire.nodeId === simId &&
      wire.sessionIdHash === toHex(sha256(keys.sessionId)) &&
      wire.measurement.toLowerCase() === roots.approvedMeasurement.toLowerCase();
    keys.kUp.fill(0);
    keys.kDown.fill(0);
    return { ...wire, verified };
  }

  return {
    simId,
    checks,
    evidence: summary,
    send: (text: string) => send(text),
    close,
  };
}
