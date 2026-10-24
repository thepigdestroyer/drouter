import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { bytesEqual, concat, fromHex, toHex, u32be, u64be, u8, utf8 } from "./bytes";
import { SESSION_LABEL } from "./constants";
import type { PopReceiptWire } from "./types";

/** Session protocol crypto shared by the node and the browser client. */

// ---------- canonical JSON ----------

type Json = null | boolean | number | string | Uint8Array | Json[] | { [key: string]: Json | undefined };

function canonicalize(value: Json | undefined): string {
  if (value === null) return "null";
  if (value instanceof Uint8Array) return JSON.stringify(toHex(value));
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("canonical JSON cannot encode non-finite numbers");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
      const entries = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
      return `{${entries.join(",")}}`;
    }
    default:
      throw new Error(`canonical JSON cannot encode ${typeof value}`);
  }
}

/** Sorted keys, no whitespace, byte arrays as lowercase hex. */
export function canonical(value: unknown): string {
  return canonicalize(value as Json);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(canonical(value));
}

// ---------- REPORT_DATA ----------

export interface ReportDataInput {
  clientNonce: Uint8Array;
  nodeIdentityPk: Uint8Array;
  custodyX25519Pk: Uint8Array;
  custodyMlkemPk: Uint8Array;
  manifestHash: Uint8Array;
  modelRoot: Uint8Array;
}

/** sha512("drouter/v1/session" ‖ nonce ‖ identityPk ‖ x25519Pk ‖ sha256(mlkemPk) ‖ manifestHash ‖ modelRoot) */
export function computeReportData(input: ReportDataInput): Uint8Array {
  return sha512(
    concat(
      utf8(SESSION_LABEL),
      input.clientNonce,
      input.nodeIdentityPk,
      input.custodyX25519Pk,
      sha256(input.custodyMlkemPk),
      input.manifestHash,
      input.modelRoot,
    ),
  );
}

// ---------- hybrid KEM (X25519 + ML-KEM-768) ----------

export function clientKeyAgreement(custodyX25519Pk: Uint8Array, custodyMlkemPk: Uint8Array) {
  const eph = x25519.keygen();
  const x25519Shared = x25519.getSharedSecret(eph.secretKey, custodyX25519Pk);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(custodyMlkemPk);
  return {
    clientX25519Pk: eph.publicKey,
    mlkemCt: cipherText,
    ikm: concat(x25519Shared, sharedSecret),
  };
}

export function nodeKeyAgreement(
  custodyX25519Sk: Uint8Array,
  custodyMlkemSk: Uint8Array,
  clientX25519Pk: Uint8Array,
  mlkemCt: Uint8Array,
): Uint8Array {
  const x25519Shared = x25519.getSharedSecret(custodyX25519Sk, clientX25519Pk);
  const mlkemShared = ml_kem768.decapsulate(mlkemCt, custodyMlkemSk);
  return concat(x25519Shared, mlkemShared);
}

// ---------- transcript and keys ----------

/** canonical(hello) ‖ canonical(evidenceBundle): the part of the transcript known before key share. */
export function transcriptPrefix(hello: unknown, evidenceBundle: unknown): Uint8Array {
  return concat(canonicalBytes(hello), canonicalBytes(evidenceBundle));
}

export function transcriptHashFromPrefix(prefix: Uint8Array, clientX25519Pk: Uint8Array, mlkemCt: Uint8Array): Uint8Array {
  return sha384(concat(prefix, clientX25519Pk, mlkemCt));
}

export function transcriptHash(
  hello: unknown,
  evidenceBundle: unknown,
  clientX25519Pk: Uint8Array,
  mlkemCt: Uint8Array,
): Uint8Array {
  return transcriptHashFromPrefix(transcriptPrefix(hello, evidenceBundle), clientX25519Pk, mlkemCt);
}

export interface SessionKeys {
  kUp: Uint8Array;
  kDown: Uint8Array;
  sessionId: Uint8Array;
}

export function deriveSessionKeys(input: {
  clientNonce: Uint8Array;
  ikm: Uint8Array;
  transcriptHash: Uint8Array;
}): SessionKeys {
  const okm = hkdf(sha384, input.ikm, input.clientNonce, concat(utf8(SESSION_LABEL), input.transcriptHash), 64);
  return {
    kUp: okm.slice(0, 32),
    kDown: okm.slice(32, 64),
    sessionId: sha256(input.transcriptHash).slice(0, 16),
  };
}

// ---------- AEAD ----------

export type Direction = "up" | "down";

export const MSG = { params: 1, input: 2, output: 3, ready: 4 } as const;

const DIRECTION_TAG: Record<Direction, Uint8Array> = {
  up: Uint8Array.of(0x75, 0x70, 0, 0), // "up\0\0"
  down: utf8("down"),
};

const COUNTER_BYTES = 8;

function aeadNonce(direction: Direction, counter: bigint): Uint8Array {
  return concat(DIRECTION_TAG[direction], u64be(counter));
}

function aeadAad(sessionId: Uint8Array, turn: number, msgType: number): Uint8Array {
  return concat(sessionId, u32be(turn), u8(msgType));
}

/** Wire format: u64 big-endian counter ‖ AES-256-GCM ciphertext+tag. */
export function sealMessage(
  key: Uint8Array,
  direction: Direction,
  counter: bigint,
  sessionId: Uint8Array,
  turn: number,
  msgType: number,
  plaintext: Uint8Array,
): Uint8Array {
  const ct = gcm(key, aeadNonce(direction, counter), aeadAad(sessionId, turn, msgType)).encrypt(plaintext);
  return concat(u64be(counter), ct);
}

/** Opens a message; rejects counters below `minCounter` (replayed or out-of-order). */
export function openMessage(
  key: Uint8Array,
  direction: Direction,
  sessionId: Uint8Array,
  turn: number,
  msgType: number,
  wire: Uint8Array,
  minCounter: bigint,
): { plaintext: Uint8Array; counter: bigint } {
  if (wire.length < COUNTER_BYTES + 16) throw new Error("message too short");
  const counter = new DataView(wire.buffer, wire.byteOffset, wire.byteLength).getBigUint64(0, false);
  if (counter < minCounter) throw new Error("replayed or out-of-order counter");
  const plaintext = gcm(key, aeadNonce(direction, counter), aeadAad(sessionId, turn, msgType)).decrypt(
    wire.subarray(COUNTER_BYTES),
  );
  return { plaintext, counter };
}

// ---------- tokens, padding, frames ----------

/** The sim tokenizer is UTF-8 bytes. */
export function tokenize(text: string): number[] {
  return Array.from(utf8(text));
}

export function detokenize(tokens: number[]): string {
  return new TextDecoder().decode(Uint8Array.from(tokens));
}

const BUCKET_BASE = 1024;
const MAX_BUCKET_EXPONENT = 6; // 65 536 tokens

function bucketFor(count: number): number {
  for (let j = 0; j <= MAX_BUCKET_EXPONENT; j++) {
    const bucket = BUCKET_BASE * 2 ** j;
    if (count <= bucket) return bucket;
  }
  throw new Error("input exceeds the largest upload bucket");
}

/** u32 count prefix + u32 tokens, zero padded to a 2^j x 1024 token bucket. */
export function padTokens(tokens: number[]): Uint8Array {
  const bucket = bucketFor(tokens.length);
  const out = new Uint8Array(4 + 4 * bucket);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, tokens.length, false);
  tokens.forEach((t, i) => dv.setUint32(4 + 4 * i, t, false));
  return out;
}

export function unpadTokens(bytes: Uint8Array): number[] {
  if (bytes.length < 8 || (bytes.length - 4) % 4 !== 0) throw new Error("malformed padded input");
  const bucket = (bytes.length - 4) / 4;
  const valid = Array.from({ length: MAX_BUCKET_EXPONENT + 1 }, (_, j) => BUCKET_BASE * 2 ** j).includes(bucket);
  if (!valid) throw new Error("malformed padded input");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = dv.getUint32(0, false);
  if (count > bucket) throw new Error("malformed padded input");
  return Array.from({ length: count }, (_, i) => dv.getUint32(4 + 4 * i, false));
}

export const FRAME_TOKENS = 64;
export const FRAME_PLAINTEXT_SIZE = 2 + 1 + 4 * FRAME_TOKENS;
const FLAG_FINAL = 1;

export function encodeFrame(tokens: number[], final: boolean): Uint8Array {
  if (tokens.length > FRAME_TOKENS) throw new Error("too many tokens for one frame");
  const out = new Uint8Array(FRAME_PLAINTEXT_SIZE);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, tokens.length, false);
  out[2] = final ? FLAG_FINAL : 0;
  tokens.forEach((t, i) => dv.setUint32(3 + 4 * i, t, false));
  return out;
}

export function decodeFrame(bytes: Uint8Array): { tokens: number[]; final: boolean } {
  if (bytes.length !== FRAME_PLAINTEXT_SIZE) throw new Error("malformed output frame");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = dv.getUint16(0, false);
  if (count > FRAME_TOKENS) throw new Error("malformed output frame");
  return {
    tokens: Array.from({ length: count }, (_, i) => dv.getUint32(3 + 4 * i, false)),
    final: (bytes[2] & FLAG_FINAL) === FLAG_FINAL,
  };
}

/** Splits response tokens into fixed-size frame plaintexts; the last carries the final flag. */
export function splitIntoFrames(tokens: number[]): Uint8Array[] {
  const frames: Uint8Array[] = [];
  const count = Math.max(1, Math.ceil(tokens.length / FRAME_TOKENS));
  for (let i = 0; i < count; i++) {
    frames.push(encodeFrame(tokens.slice(i * FRAME_TOKENS, (i + 1) * FRAME_TOKENS), i === count - 1));
  }
  return frames;
}

// ---------- proof-of-processing receipt ----------

export interface PopFields {
  nodeId: string;
  sessionIdHash: string;
  time: number;
  measurement: string;
}

function popMessage(fields: PopFields): Uint8Array {
  return canonicalBytes({
    type: "pop",
    nodeId: fields.nodeId,
    sessionIdHash: fields.sessionIdHash,
    time: fields.time,
    measurement: fields.measurement,
  });
}

export function signPop(fields: PopFields, identitySecretKey: Uint8Array): PopReceiptWire {
  return {
    nodeId: fields.nodeId,
    sessionIdHash: fields.sessionIdHash,
    time: fields.time,
    measurement: fields.measurement,
    signature: toHex(ed25519.sign(popMessage(fields), identitySecretKey)),
    signerPublicKey: toHex(ed25519.getPublicKey(identitySecretKey)),
  };
}

export function verifyPop(receipt: PopReceiptWire, expectedSignerPublicKey: Uint8Array): boolean {
  try {
    if (!bytesEqual(fromHex(receipt.signerPublicKey), expectedSignerPublicKey)) return false;
    return ed25519.verify(fromHex(receipt.signature), popMessage(receipt), expectedSignerPublicKey);
  } catch {
    return false;
  }
}
