import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

function canonicalize(value) {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonicalJson cannot encode non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(",")}]`;
      }
      if (Object.prototype.toString.call(value) !== "[object Object]") {
        throw new Error("canonicalJson only encodes plain objects");
      }
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
      return `{${pairs.join(",")}}`;
    }
    default:
      throw new Error(`canonicalJson cannot encode ${typeof value}`);
  }
}

/**
 * Deterministic canonical JSON serializer (sorted keys, no whitespace).
 * Matches `src/lib/transparency/log.ts` byte-for-byte.
 */
export function canonicalJson(value) {
  return canonicalize(value);
}

/**
 * Computes a 64-character lowercase SHA-256 hex digest over a UTF-8 string or Uint8Array.
 */
export function sha256Hex(input) {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return bytesToHex(sha256(bytes)).toLowerCase();
}

/**
 * Coarsens a Unix timestamp in seconds down to the start of the UTC hour (divisible by 3600).
 */
export function coarsenEpochSecToHour(sec = Math.floor(Date.now() / 1000)) {
  const n = Number.isFinite(sec) ? Math.floor(sec) : Math.floor(Date.now() / 1000);
  return Math.floor(n / 3600) * 3600;
}
