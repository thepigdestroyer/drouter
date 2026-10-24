import type { Hex } from "@/lib/types";

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

export function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && HEX32.test(value);
}

export interface AnchorBody {
  receiptHash: Hex;
  nodeId: Hex;
  ok?: boolean;
  evidenceHash?: Hex;
}

export type ParsedAnchorBody = { ok: true; value: AnchorBody } | { ok: false; error: string };

export function parseAnchorBody(body: unknown): ParsedAnchorBody {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, error: "body must be a JSON object" };
  }
  const b = body as Record<string, unknown>;
  if (!isHex32(b.receiptHash)) return { ok: false, error: "receiptHash must be 32-byte 0x-prefixed hex" };
  if (!isHex32(b.nodeId)) return { ok: false, error: "nodeId must be 32-byte 0x-prefixed hex" };
  const value: AnchorBody = { receiptHash: b.receiptHash, nodeId: b.nodeId };
  if (b.ok !== undefined) {
    if (typeof b.ok !== "boolean") return { ok: false, error: "ok must be a boolean" };
    value.ok = b.ok;
  }
  if (b.evidenceHash !== undefined) {
    if (!isHex32(b.evidenceHash)) return { ok: false, error: "evidenceHash must be 32-byte 0x-prefixed hex" };
    value.evidenceHash = b.evidenceHash;
  }
  return { ok: true, value };
}

/** Fixed-window in-memory limiter. Returns true when the request is allowed. */
export function createRateLimiter(opts: { max: number; windowMs: number; now?: () => number }) {
  const now = opts.now ?? Date.now;
  const hits = new Map<string, { start: number; count: number }>();
  return (key: string): boolean => {
    const t = now();
    if (hits.size > 1000) {
      for (const [k, v] of hits) if (t - v.start >= opts.windowMs) hits.delete(k);
    }
    const entry = hits.get(key);
    if (!entry || t - entry.start >= opts.windowMs) {
      hits.set(key, { start: t, count: 1 });
      return true;
    }
    entry.count += 1;
    return entry.count <= opts.max;
  };
}
