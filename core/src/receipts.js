import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { canonicalJson, coarsenEpochSecToHour, sha256Hex } from "./canonical.js";
import { assertContentFree } from "./firewall.js";
import { getKeyRing } from "./keys.js";

export const GEMINI_EGRESS_RECEIPT_KIND = "gemini-egress";
export const STH_DOMAIN = "drouter/transparency/sth/v1";

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
  const sha256 = sha256Hex(canonicalRequest);
  const epochHourSec = coarsenEpochSecToHour(timestampSec);
  const signingBytes = geminiEgressSigningPayload({ sha256, epochHourSec });
  const signature = bytesToHex(ed25519.sign(signingBytes, keyPair.secretKey)).toLowerCase();

  return {
    canonicalRequest,
    sha256,
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
  for (const k of Object.keys(input)) {
    if (!ALLOWED_TREE_HEAD_KEYS.has(k)) {
      errors.push(`Unexpected field '${k}' in tree head request.`);
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
