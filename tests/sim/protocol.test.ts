import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { fromHex, toHex, utf8 } from "@/lib/sim/bytes";
import {
  FRAME_PLAINTEXT_SIZE,
  MSG,
  canonical,
  clientKeyAgreement,
  computeReportData,
  decodeFrame,
  deriveSessionKeys,
  detokenize,
  nodeKeyAgreement,
  openMessage,
  padTokens,
  signPop,
  sealMessage,
  splitIntoFrames,
  tokenize,
  unpadTokens,
  verifyPop,
} from "@/lib/sim/protocol";

describe("canonical JSON", () => {
  it("sorts keys, drops whitespace and hex-encodes byte arrays", () => {
    const out = canonical({ b: 1, a: [true, null, "x"], c: { z: new Uint8Array([1, 255]), y: 2 } });
    expect(out).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":"01ff"}}');
  });

  it("is independent of insertion order", () => {
    expect(canonical({ a: 1, b: 2 })).toBe(canonical({ b: 2, a: 1 }));
  });
});

describe("REPORT_DATA", () => {
  it("is sha512 over the labelled concatenation and changes with every input", () => {
    const base = {
      clientNonce: new Uint8Array(32).fill(1),
      nodeIdentityPk: new Uint8Array(32).fill(2),
      custodyX25519Pk: new Uint8Array(32).fill(3),
      custodyMlkemPk: new Uint8Array(1184).fill(4),
      manifestHash: new Uint8Array(32).fill(5),
      modelRoot: new Uint8Array(32).fill(6),
    };
    const rd = computeReportData(base);
    expect(rd.length).toBe(64);
    for (const key of Object.keys(base) as Array<keyof typeof base>) {
      const mutated = { ...base, [key]: base[key].slice() };
      mutated[key][0] ^= 1;
      expect(toHex(computeReportData(mutated)), key).not.toBe(toHex(rd));
    }
  });
});

describe("hybrid KEM and session keys", () => {
  it("client and node derive identical keys", () => {
    const x = x25519.keygen();
    const q = ml_kem768.keygen();
    const nonce = new Uint8Array(32).fill(9);
    const client = clientKeyAgreement(x.publicKey, q.publicKey);
    const nodeIkm = nodeKeyAgreement(x.secretKey, q.secretKey, client.clientX25519Pk, client.mlkemCt);
    expect(toHex(nodeIkm)).toBe(toHex(client.ikm));
    const th = new Uint8Array(48).fill(7);
    const a = deriveSessionKeys({ clientNonce: nonce, ikm: client.ikm, transcriptHash: th });
    const b = deriveSessionKeys({ clientNonce: nonce, ikm: nodeIkm, transcriptHash: th });
    expect(toHex(a.kUp)).toBe(toHex(b.kUp));
    expect(toHex(a.kDown)).toBe(toHex(b.kDown));
    expect(toHex(a.sessionId)).toBe(toHex(sha256(th).slice(0, 16)));
    expect(toHex(a.kUp)).not.toBe(toHex(a.kDown));
    const c = deriveSessionKeys({ clientNonce: nonce, ikm: client.ikm, transcriptHash: new Uint8Array(48) });
    expect(toHex(c.kUp)).not.toBe(toHex(a.kUp));
  });
});

describe("AEAD messages", () => {
  const key = new Uint8Array(32).fill(5);
  const sid = new Uint8Array(16).fill(6);

  it("round-trips and binds turn, message type, direction and session", () => {
    const wire = sealMessage(key, "up", BigInt(0), sid, 1, MSG.input, utf8("hi"));
    expect(openMessage(key, "up", sid, 1, MSG.input, wire, BigInt(0)).plaintext).toEqual(utf8("hi"));
    expect(() => openMessage(key, "up", sid, 2, MSG.input, wire, BigInt(0))).toThrow();
    expect(() => openMessage(key, "up", sid, 1, MSG.params, wire, BigInt(0))).toThrow();
    expect(() => openMessage(key, "down", sid, 1, MSG.input, wire, BigInt(0))).toThrow();
    expect(() => openMessage(key, "up", new Uint8Array(16), 1, MSG.input, wire, BigInt(0))).toThrow();
  });

  it("rejects replayed and out-of-order counters but accepts increases", () => {
    const w0 = sealMessage(key, "up", BigInt(0), sid, 1, MSG.input, utf8("a"));
    const w5 = sealMessage(key, "up", BigInt(5), sid, 1, MSG.input, utf8("b"));
    expect(openMessage(key, "up", sid, 1, MSG.input, w5, BigInt(0)).counter).toBe(BigInt(5));
    expect(() => openMessage(key, "up", sid, 1, MSG.input, w5, BigInt(6))).toThrow(/counter/);
    expect(() => openMessage(key, "up", sid, 1, MSG.input, w0, BigInt(6))).toThrow(/counter/);
  });

  it("rejects a rewritten counter (nonce is authenticated)", () => {
    const wire = sealMessage(key, "up", BigInt(1), sid, 1, MSG.input, utf8("a"));
    const forged = wire.slice();
    forged[7] = 2;
    expect(() => openMessage(key, "up", sid, 1, MSG.input, forged, BigInt(0))).toThrow();
  });
});

describe("padding and framing", () => {
  it("pads uploads to 2^j x 1024 token buckets", () => {
    const sizes = [0, 1, 1024, 1025, 2048, 2049].map((n) => padTokens(new Array(n).fill(65)).length);
    expect(sizes).toEqual([1024, 1024, 1024, 2048, 2048, 4096].map((b) => 4 + 4 * b));
    const tokens = tokenize("héllo");
    expect(unpadTokens(padTokens(tokens))).toEqual(tokens);
    expect(detokenize(tokens)).toBe("héllo");
  });

  it("rejects malformed padded uploads", () => {
    const padded = padTokens([1, 2, 3]);
    expect(() => unpadTokens(padded.slice(0, padded.length - 1))).toThrow();
    const bad = padded.slice();
    new DataView(bad.buffer).setUint32(0, 5000, false);
    expect(() => unpadTokens(bad)).toThrow();
  });

  it("produces identical-size frames regardless of content, final flag on the last", () => {
    const short = splitIntoFrames([1, 2, 3]);
    const long = splitIntoFrames(new Array(200).fill(7));
    const empty = splitIntoFrames([]);
    expect(short.length).toBe(1);
    expect(long.length).toBe(4);
    expect(empty.length).toBe(1);
    for (const f of [...short, ...long, ...empty]) expect(f.length).toBe(FRAME_PLAINTEXT_SIZE);
    expect(FRAME_PLAINTEXT_SIZE).toBe(2 + 1 + 64 * 4);
    expect(long.map((f) => decodeFrame(f).final)).toEqual([false, false, false, true]);
    expect(decodeFrame(long[3]).tokens.length).toBe(200 - 192);
    expect(decodeFrame(short[0]).tokens).toEqual([1, 2, 3]);
  });
});

describe("proof-of-processing receipt", () => {
  it("verifies, and fails on altered fields or wrong key", () => {
    const id = ed25519.keygen();
    const fields = { nodeId: "sim-1", sessionIdHash: "aa".repeat(32), time: 1700000000, measurement: "bb".repeat(48) };
    const receipt = signPop(fields, id.secretKey);
    expect(receipt.signerPublicKey).toBe(toHex(id.publicKey));
    expect(verifyPop(receipt, id.publicKey)).toBe(true);
    expect(verifyPop({ ...receipt, time: receipt.time + 1 }, id.publicKey)).toBe(false);
    expect(verifyPop(receipt, ed25519.keygen().publicKey)).toBe(false);
    expect(fromHex(receipt.signature).length).toBe(64);
  });
});
