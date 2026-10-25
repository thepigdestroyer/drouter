import { utf8ToBytes } from "@noble/hashes/utils.js";
import { CREDIT_DENOMINATIONS, nullifierFor } from "@/lib/credits/blind";
import { canonicalJson } from "@/lib/transparency/log";
import type { BlindCreditToken } from "@/lib/types";

export const ACCESS_KEY_PREFIX = "drk_";
export const ACCESS_KEY_VERSION = 1;
export const ACCESS_KEY_ORIGIN = "https://drouter-demo.vercel.app";
export const MAX_ACCESS_KEY_TOKENS = 50;

export interface CompactAccessKeyToken {
  t: string;
  s: string;
  d: number;
}

export interface AccessKeyPayload {
  v: 1;
  origin: string;
  tokens: CompactAccessKeyToken[];
}

export interface DecodedAccessKey {
  version: 1;
  origin: string;
  tokens: BlindCreditToken[];
}

export type DecodeAccessKeyResult =
  | {
      ok: true;
      version: 1;
      origin: string;
      tokens: BlindCreditToken[];
    }
  | {
      ok: false;
      error: string;
    };

function toBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64UrlStrict(encoded: string): Uint8Array | null {
  if (!encoded || encoded.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
  if (encoded.length % 4 === 1) return null;

  const padded = encoded
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(encoded.length + ((4 - (encoded.length % 4)) % 4), "=");

  let bytes: Uint8Array;
  try {
    if (typeof Buffer !== "undefined") {
      bytes = new Uint8Array(Buffer.from(padded, "base64"));
    } else {
      const bin = atob(padded);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
    }
  } catch {
    return null;
  }

  // Reject non-canonical trailing bits
  if (toBase64Url(bytes) !== encoded) {
    return null;
  }

  return bytes;
}

function normalizeEvenHexStrict(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  if (raw.length === 0 || raw !== raw.trim()) return null;
  const withoutPrefix = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw;
  if (withoutPrefix.length < 2 || withoutPrefix.length > 1024 || withoutPrefix.length % 2 !== 0) {
    return null;
  }
  if (!/^[0-9a-fA-F]+$/.test(withoutPrefix)) {
    return null;
  }
  return withoutPrefix.toLowerCase();
}

function validateAndNormalizeTokens(
  tokens: readonly BlindCreditToken[],
): { ok: true; compact: CompactAccessKeyToken[]; normalized: BlindCreditToken[] } | { ok: false; error: string } {
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return { ok: false, error: "Access key must contain at least 1 token" };
  }
  if (tokens.length > MAX_ACCESS_KEY_TOKENS) {
    return {
      ok: false,
      error: `Access key cannot contain more than ${MAX_ACCESS_KEY_TOKENS} tokens`,
    };
  }

  const seenNullifiers = new Set<string>();
  const compact: CompactAccessKeyToken[] = [];
  const normalized: BlindCreditToken[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const item = tokens[i];
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return { ok: false, error: `Token at index ${i} must be an object` };
    }
    const t = normalizeEvenHexStrict(item.token);
    if (!t) {
      return { ok: false, error: `Malformed token hex at index ${i}` };
    }
    const s = normalizeEvenHexStrict(item.signature);
    if (!s) {
      return { ok: false, error: `Malformed signature hex at index ${i}` };
    }
    const d = item.denomination;
    if (typeof d !== "number" || !Number.isInteger(d) || !CREDIT_DENOMINATIONS.includes(d)) {
      return {
        ok: false,
        error: `Unsupported credit denomination at index ${i}`,
      };
    }

    const nullifier = nullifierFor(t);
    if (seenNullifiers.has(nullifier)) {
      return {
        ok: false,
        error: `Duplicate token in access key at index ${i}`,
      };
    }
    seenNullifiers.add(nullifier);

    compact.push({ t, s, d });
    normalized.push({ token: t, signature: s, denomination: d });
  }

  return { ok: true, compact, normalized };
}

/**
 * Encodes 1..50 blind-signed credit tokens into a portable `drk_...` access key.
 * Format: `drk_` + base64url(no padding) of UTF-8 `canonicalJson({ v: 1, origin, tokens: [{ t, s, d }, ...] })`.
 */
export function encodeAccessKey(
  tokens: readonly BlindCreditToken[],
  origin: string = ACCESS_KEY_ORIGIN,
): string {
  if (origin !== ACCESS_KEY_ORIGIN) {
    throw new Error(`Invalid access key origin: expected ${ACCESS_KEY_ORIGIN}`);
  }
  const checked = validateAndNormalizeTokens(tokens);
  if (!checked.ok) {
    throw new Error(checked.error);
  }
  const payload: AccessKeyPayload = {
    v: ACCESS_KEY_VERSION,
    origin: ACCESS_KEY_ORIGIN,
    tokens: checked.compact,
  };
  const jsonBytes = utf8ToBytes(canonicalJson(payload));
  return ACCESS_KEY_PREFIX + toBase64Url(jsonBytes);
}

/**
 * Strictly parses and validates a `drk_...` access key string.
 * Rejects unknown versions, unknown keys, malformed hex, wrong origin, duplicate tokens, or > 50 tokens.
 */
export function decodeAccessKey(
  rawKey: unknown,
  expectedOrigin: string = ACCESS_KEY_ORIGIN,
): DecodeAccessKeyResult {
  if (typeof rawKey !== "string") {
    return { ok: false, error: "Access key must be a string" };
  }
  const trimmed = rawKey.trim();
  if (!trimmed.startsWith(ACCESS_KEY_PREFIX)) {
    return { ok: false, error: "Access key must start with drk_" };
  }
  const encodedBody = trimmed.slice(ACCESS_KEY_PREFIX.length);
  if (!encodedBody || encodedBody.length > 131_072) {
    return { ok: false, error: "Malformed base64url payload in access key" };
  }

  const decodedBytes = fromBase64UrlStrict(encodedBody);
  if (!decodedBytes) {
    return { ok: false, error: "Malformed base64url payload in access key" };
  }

  let jsonText: string;
  try {
    jsonText = new TextDecoder("utf-8", { fatal: true }).decode(decodedBytes);
  } catch {
    return { ok: false, error: "Access key payload is not valid UTF-8" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return { ok: false, error: "Access key payload is not valid JSON" };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "Access key payload must be a JSON object" };
  }

  const obj = parsed as Record<string, unknown>;
  const topKeys = Object.keys(obj);
  if (
    topKeys.length !== 3 ||
    !topKeys.includes("v") ||
    !topKeys.includes("origin") ||
    !topKeys.includes("tokens")
  ) {
    return { ok: false, error: "Unknown or missing top-level keys in access key" };
  }

  if (obj.v !== ACCESS_KEY_VERSION) {
    return { ok: false, error: `Unsupported access key version: ${String(obj.v)}` };
  }

  if (typeof obj.origin !== "string" || obj.origin !== expectedOrigin) {
    return {
      ok: false,
      error: `Wrong access key origin: expected ${expectedOrigin}`,
    };
  }

  if (!Array.isArray(obj.tokens)) {
    return { ok: false, error: "Access key tokens must be an array" };
  }

  if (obj.tokens.length < 1) {
    return { ok: false, error: "Access key must contain at least 1 token" };
  }

  if (obj.tokens.length > MAX_ACCESS_KEY_TOKENS) {
    return {
      ok: false,
      error: `Access key cannot contain more than ${MAX_ACCESS_KEY_TOKENS} tokens`,
    };
  }

  const candidateTokens: BlindCreditToken[] = [];
  for (let i = 0; i < obj.tokens.length; i++) {
    const rawItem = obj.tokens[i];
    if (!rawItem || typeof rawItem !== "object" || Array.isArray(rawItem)) {
      return { ok: false, error: `Token entry at index ${i} must be an object` };
    }
    const entry = rawItem as Record<string, unknown>;
    const entryKeys = Object.keys(entry);
    if (
      entryKeys.length !== 3 ||
      !entryKeys.includes("t") ||
      !entryKeys.includes("s") ||
      !entryKeys.includes("d")
    ) {
      return {
        ok: false,
        error: `Unknown or missing keys in token entry at index ${i}`,
      };
    }

    if (typeof entry.t !== "string" || !/^[0-9a-f]+$/.test(entry.t) || entry.t.length < 2 || entry.t.length % 2 !== 0) {
      return { ok: false, error: `Malformed token hex at index ${i}` };
    }
    if (typeof entry.s !== "string" || !/^[0-9a-f]+$/.test(entry.s) || entry.s.length < 2 || entry.s.length % 2 !== 0) {
      return { ok: false, error: `Malformed signature hex at index ${i}` };
    }
    if (
      typeof entry.d !== "number" ||
      !Number.isInteger(entry.d) ||
      !CREDIT_DENOMINATIONS.includes(entry.d)
    ) {
      return { ok: false, error: `Unsupported credit denomination at index ${i}` };
    }

    candidateTokens.push({
      token: entry.t,
      signature: entry.s,
      denomination: entry.d,
    });
  }

  const checked = validateAndNormalizeTokens(candidateTokens);
  if (!checked.ok) {
    return { ok: false, error: checked.error };
  }

  return {
    ok: true,
    version: ACCESS_KEY_VERSION,
    origin: expectedOrigin,
    tokens: checked.normalized,
  };
}
