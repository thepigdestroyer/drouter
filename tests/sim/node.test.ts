import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { fromHex, toHex, utf8 } from "@/lib/sim/bytes";
import { TICKET_IDLE_MS } from "@/lib/sim/constants";
import { identity } from "@/lib/sim/hardware";
import { nodeClose, nodeHello, nodeKeyshare, nodeTurn } from "@/lib/sim/node";
import {
  MSG,
  clientKeyAgreement,
  decodeFrame,
  deriveSessionKeys,
  detokenize,
  openMessage,
  padTokens,
  sealMessage,
  tokenize,
  transcriptHash,
  verifyPop,
} from "@/lib/sim/protocol";
import { SimError } from "@/lib/sim/errors";
import { flipHexByte } from "./helpers";

const T0 = 1_800_000_000_000;

/** Drives the node by hand (no client module) so the node is tested independently. */
function handshake(simId = "sim-1", now = T0) {
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const hello = { clientNonce: toHex(clientNonce), modelId: "sim-echo-1" };
  const res = nodeHello(simId, hello, { now });
  const kem = clientKeyAgreement(
    fromHex(res.evidence.custody.x25519PublicKey),
    fromHex(res.evidence.custody.mlkemPublicKey),
  );
  const th = transcriptHash(hello, res.evidence, kem.clientX25519Pk, kem.mlkemCt);
  const keys = deriveSessionKeys({ clientNonce, ikm: kem.ikm, transcriptHash: th });
  const sealed = sealMessage(keys.kUp, "up", BigInt(0), keys.sessionId, 0, MSG.params, utf8(JSON.stringify({ modelId: "sim-echo-1" })));
  const ks = nodeKeyshare(
    simId,
    { ticket: res.ticket, clientX25519Pk: toHex(kem.clientX25519Pk), mlkemCt: toHex(kem.mlkemCt), sealed: toHex(sealed) },
    { now },
  );
  return { simId, res, keys, ks, kem };
}

function doTurn(h: ReturnType<typeof handshake>, ticket: string, turn: number, counter: bigint, text: string, now = T0) {
  const ct = sealMessage(h.keys.kUp, "up", counter, h.keys.sessionId, turn, MSG.input, padTokens(tokenize(text)));
  return nodeTurn(h.simId, { ticket, turn, ct: toHex(ct) }, { now });
}

function readFrames(h: ReturnType<typeof handshake>, frames: string[], turn: number, minCounter: bigint) {
  let next = minCounter;
  const tokens: number[] = [];
  const sizes = new Set<number>();
  for (const f of frames) {
    sizes.add(f.length);
    const opened = openMessage(h.keys.kDown, "down", h.keys.sessionId, turn, MSG.output, fromHex(f), next);
    next = opened.counter + BigInt(1);
    tokens.push(...decodeFrame(opened.plaintext).tokens);
  }
  return { text: detokenize(tokens), sizes, next };
}

describe("sim node session", () => {
  it("runs hello, keyshare, turn, /count and close end to end", () => {
    const h = handshake();
    const ready = openMessage(h.keys.kDown, "down", h.keys.sessionId, 0, MSG.ready, fromHex(h.ks.ready), BigInt(0));
    expect(new TextDecoder().decode(ready.plaintext)).toBe("ready");

    const t1 = doTurn(h, h.ks.ticket, 1, BigInt(1), "hello world");
    const r1 = readFrames(h, t1.frames, 1, BigInt(1));
    expect(r1.text).toBe(
      "Simulated enclave sim-1 received 11 tokens inside the bubble. Session context: 11 tokens. " +
        "This node simulates the hardware; route to a Tinfoil node for a real model.",
    );

    const t2 = doTurn(h, t1.ticket, 2, BigInt(2), "/count");
    const r2 = readFrames(h, t2.frames, 2, r1.next);
    expect(r2.text).toBe("11");

    const t3 = doTurn(h, t2.ticket, 3, BigInt(3), "again");
    expect(readFrames(h, t3.frames, 3, r2.next).text).toContain("Session context: 22 tokens");

    const receipt = nodeClose(h.simId, { ticket: t3.ticket }, { now: T0 + 5000 });
    expect(receipt.nodeId).toBe("sim-1");
    expect(receipt.time).toBe(Math.floor((T0 + 5000) / 1000));
    expect(receipt.sessionIdHash).toBe(toHex(sha256(h.keys.sessionId)));
    expect(verifyPop(receipt, identity("sim-1").publicKey)).toBe(true);
    expect(ed25519.verify(fromHex(receipt.signature), utf8(
      `{"measurement":"${receipt.measurement}","nodeId":"sim-1","sessionIdHash":"${receipt.sessionIdHash}","time":${receipt.time},"type":"pop"}`,
    ), identity("sim-1").publicKey)).toBe(true);
  });

  it("sends identical-size frames for short and long replies", () => {
    const h = handshake();
    const a = doTurn(h, h.ks.ticket, 1, BigInt(1), "hi");
    const b = doTurn(h, a.ticket, 2, BigInt(2), "/count");
    const sizesA = readFrames(h, a.frames, 1, BigInt(1)).sizes;
    const sizesB = readFrames(h, b.frames, 2, BigInt(1) + BigInt(a.frames.length)).sizes;
    expect(sizesA.size).toBe(1);
    expect([...sizesA]).toEqual([...sizesB]);
  });

  it("rejects a replayed upstream counter", () => {
    const h = handshake();
    const t1 = doTurn(h, h.ks.ticket, 1, BigInt(1), "first");
    expect(() => doTurn(h, t1.ticket, 2, BigInt(1), "replay")).toThrow(/counter/);
    expect(() => doTurn(h, t1.ticket, 1, BigInt(1), "replay")).toThrow(SimError);
  });

  it("rejects a turn from an old ticket with a stale counter", () => {
    const h = handshake();
    const t1 = doTurn(h, h.ks.ticket, 1, BigInt(1), "first");
    const t2 = doTurn(h, t1.ticket, 2, BigInt(2), "second");
    expect(() => doTurn(h, t2.ticket, 3, BigInt(2), "stale")).toThrow(/counter/);
  });

  it("rejects an upstream message under the wrong turn", () => {
    const h = handshake();
    const ct = sealMessage(h.keys.kUp, "up", BigInt(1), h.keys.sessionId, 5, MSG.input, padTokens(tokenize("x")));
    expect(() => nodeTurn(h.simId, { ticket: h.ks.ticket, turn: 1, ct: toHex(ct) }, { now: T0 })).toThrow(/authentication/);
  });

  it("rejects tampered tickets", () => {
    const h = handshake();
    for (const index of [0, 12, 40]) {
      expect(() => doTurn(h, flipHexByte(h.ks.ticket, index), 1, BigInt(1), "x")).toThrow(/invalid ticket/);
    }
    expect(() => doTurn(h, h.ks.ticket.slice(0, 20), 1, BigInt(1), "x")).toThrow(/invalid ticket/);
    expect(() => doTurn(h, "zz", 1, BigInt(1), "x")).toThrow(/invalid ticket/);
    expect(() => nodeClose(h.simId, { ticket: flipHexByte(h.ks.ticket, 30) }, { now: T0 })).toThrow(/invalid ticket/);
  });

  it("rejects a pending ticket where a session ticket is required, and another node's ticket", () => {
    const h = handshake();
    expect(() => doTurn(h, h.res.ticket, 1, BigInt(1), "x")).toThrow(/invalid ticket/);
    expect(() => nodeTurn("sim-2", { ticket: h.ks.ticket, turn: 1, ct: "00".repeat(40) }, { now: T0 })).toThrow(
      /invalid ticket/,
    );
  });

  it("rejects expired tickets after 30 minutes idle but not before", () => {
    const h = handshake();
    expect(() => doTurn(h, h.ks.ticket, 1, BigInt(1), "ok", T0 + TICKET_IDLE_MS - 1)).not.toThrow();
    expect(() => doTurn(h, h.ks.ticket, 1, BigInt(1), "late", T0 + TICKET_IDLE_MS + 1)).toThrow(/ticket expired/);
    expect(() => nodeClose(h.simId, { ticket: h.ks.ticket }, { now: T0 + TICKET_IDLE_MS + 1 })).toThrow(/ticket expired/);
  });

  it("rejects an expired pending ticket at keyshare", () => {
    const clientNonce = toHex(new Uint8Array(32).fill(1));
    const res = nodeHello("sim-1", { clientNonce, modelId: "sim-echo-1" }, { now: T0 });
    expect(() =>
      nodeKeyshare("sim-1", { ticket: res.ticket, clientX25519Pk: "00".repeat(32), mlkemCt: "00".repeat(1088), sealed: "00".repeat(40) }, { now: T0 + TICKET_IDLE_MS + 1 }),
    ).toThrow(/ticket expired/);
  });

  it("rejects bad input and unknown nodes with HTTP statuses", () => {
    const clientNonce = toHex(new Uint8Array(32));
    expect(() => nodeHello("sim-9", { clientNonce, modelId: "sim-echo-1" })).toThrow(/unknown/);
    expect(() => nodeHello("sim-1", { clientNonce: "abcd", modelId: "sim-echo-1" })).toThrow(/clientNonce/);
    expect(() => nodeHello("sim-1", { clientNonce, modelId: "other" })).toThrow(/unsupported model/);
  });

  it("emits a fresh report and custody keys on every hello", () => {
    const nonce = toHex(new Uint8Array(32).fill(3));
    const a = nodeHello("sim-1", { clientNonce: nonce, modelId: "sim-echo-1" }, { now: T0 });
    const b = nodeHello("sim-1", { clientNonce: nonce, modelId: "sim-echo-1" }, { now: T0 });
    expect(a.evidence.custody.x25519PublicKey).not.toBe(b.evidence.custody.x25519PublicKey);
    expect(a.evidence.report).not.toBe(b.evidence.report);
    expect(a.evidence.identityPublicKey).toBe(b.evidence.identityPublicKey);
  });
});
