import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export interface TokenBucketConfig {
  /** Bucket name / namespace (separates counters per route or route class). */
  name: string;
  /** Maximum burst capacity in tokens. */
  capacity: number;
  /** Tokens refilled per second. */
  refillPerSec: number;
  /** Maximum tracked buckets before oldest-idle eviction. */
  maxEntries?: number;
  /** Custom clock in ms (for deterministic testing). */
  now?: () => number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  limit: number;
  retryAfterSec: number;
  keyHash: string;
}

interface BucketState {
  tokens: number;
  lastRefillMs: number;
}

interface SaltState {
  dayIndex: number;
  saltHex: string;
}

const MS_PER_DAY = 86_400_000;

const globalForRateLimit = globalThis as unknown as {
  __drouterRateLimitSalt?: SaltState;
  __drouterRateLimitBuckets?: Map<string, Map<string, BucketState>>;
};

function randomSaltHex(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Returns the current daily-rotating random salt held only in memory.
 * Rotates automatically when the UTC day index advances.
 */
export function getDailySalt(nowMs = Date.now()): string {
  const dayIndex = Math.floor(nowMs / MS_PER_DAY);
  let current = globalForRateLimit.__drouterRateLimitSalt;
  if (!current || current.dayIndex !== dayIndex) {
    current = {
      dayIndex,
      saltHex: randomSaltHex(),
    };
    globalForRateLimit.__drouterRateLimitSalt = current;
  }
  return current.saltHex;
}

/** Resets the in-memory salt and all buckets (for tests). */
export function resetRateLimitStateForTests(): void {
  delete globalForRateLimit.__drouterRateLimitSalt;
  globalForRateLimit.__drouterRateLimitBuckets?.clear();
}

/**
 * Extracts client IP from request headers without ever storing or logging the raw IP,
 * and returns `SHA-256(dailySalt || ":" || namespace || ":" || rawIp)`.
 */
export function hashClientIp(
  req: Request | string,
  namespace = "default",
  nowMs = Date.now(),
): string {
  let rawIp = "unknown";
  if (typeof req === "string") {
    rawIp = req.trim() || "unknown";
  } else {
    const fwd = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    const real = req.headers.get("x-real-ip")?.trim();
    const cf = req.headers.get("cf-connecting-ip")?.trim();
    rawIp = fwd || real || cf || "unknown";
  }
  const salt = getDailySalt(nowMs);
  return bytesToHex(sha256(utf8ToBytes(`${salt}:${namespace}:${rawIp}`)));
}

function getBucketMap(name: string): Map<string, BucketState> {
  globalForRateLimit.__drouterRateLimitBuckets ??= new Map();
  let map = globalForRateLimit.__drouterRateLimitBuckets.get(name);
  if (!map) {
    map = new Map();
    globalForRateLimit.__drouterRateLimitBuckets.set(name, map);
  }
  return map;
}

/**
 * Creates a privacy-preserving per-IP token bucket limiter in memory.
 * Keys are `SHA-256(dailySalt || ":" || name || ":" || ip)` so raw IP addresses
 * are never stored in memory or logs.
 */
export function createTokenBucketLimiter(config: TokenBucketConfig) {
  const { name, capacity, refillPerSec, maxEntries = 5000 } = config;
  const nowFn = config.now ?? Date.now;

  function consume(reqOrIp: Request | string, cost = 1): RateLimitDecision {
    const nowMs = nowFn();
    const keyHash = hashClientIp(reqOrIp, name, nowMs);
    const buckets = getBucketMap(name);

    if (buckets.size >= maxEntries && !buckets.has(keyHash)) {
      // Evict expired/full buckets or oldest entry to bound memory
      const idleThresholdMs = nowMs - Math.ceil((capacity / Math.max(refillPerSec, 0.001)) * 1000);
      for (const [k, v] of buckets) {
        if (v.lastRefillMs <= idleThresholdMs || buckets.size >= maxEntries) {
          buckets.delete(k);
          if (buckets.size < maxEntries * 0.8) break;
        }
      }
    }

    let state = buckets.get(keyHash);
    if (!state) {
      state = { tokens: capacity, lastRefillMs: nowMs };
      buckets.set(keyHash, state);
    } else {
      const elapsedSec = Math.max(0, (nowMs - state.lastRefillMs) / 1000);
      if (elapsedSec > 0) {
        state.tokens = Math.min(capacity, state.tokens + elapsedSec * refillPerSec);
        state.lastRefillMs = nowMs;
      }
    }

    if (state.tokens >= cost) {
      state.tokens -= cost;
      return {
        allowed: true,
        remaining: Math.floor(state.tokens),
        limit: capacity,
        retryAfterSec: 0,
        keyHash,
      };
    }

    const deficit = cost - state.tokens;
    const retryAfterSec = Math.max(1, Math.ceil(deficit / Math.max(refillPerSec, 0.0001)));
    return {
      allowed: false,
      remaining: 0,
      limit: capacity,
      retryAfterSec,
      keyHash,
    };
  }

  return {
    consume,
    /** Checks the request and returns a 429 Response with Retry-After if rate-limited, or null if allowed. */
    check(req: Request, extraHeaders?: Record<string, string>, cost = 1): Response | null {
      const decision = consume(req, cost);
      if (decision.allowed) return null;
      return Response.json(
        {
          error: "Rate limit exceeded. Please slow down and retry later.",
          retryAfterSec: decision.retryAfterSec,
        },
        {
          status: 429,
          headers: {
            "Retry-After": String(decision.retryAfterSec),
            "Cache-Control": "no-store",
            ...(extraHeaders ?? {}),
          },
        },
      );
    },
    /** Credits tokens back into the caller's bucket (up to capacity * maxCapMultiplier). */
    credit(reqOrIp: Request | string, bonusTokens: number, maxCapMultiplier = 4): void {
      if (!Number.isFinite(bonusTokens) || bonusTokens <= 0) return;
      const nowMs = nowFn();
      const keyHash = hashClientIp(reqOrIp, name, nowMs);
      const buckets = getBucketMap(name);
      const maxCap = capacity * Math.max(1, maxCapMultiplier);
      let state = buckets.get(keyHash);
      if (!state) {
        state = { tokens: Math.min(maxCap, capacity + bonusTokens), lastRefillMs: nowMs };
        buckets.set(keyHash, state);
      } else {
        const elapsedSec = Math.max(0, (nowMs - state.lastRefillMs) / 1000);
        if (elapsedSec > 0) {
          state.tokens = Math.min(capacity, state.tokens + elapsedSec * refillPerSec);
          state.lastRefillMs = nowMs;
        }
        state.tokens = Math.min(maxCap, state.tokens + bonusTokens);
      }
    },
  };
}

/**
 * Global (non-IP) token bucket for capping total spend on shared operator resources
 * such as on-chain Arc verifier transactions per hour.
 */
export function createGlobalBucketLimiter(opts: {
  name: string;
  capacity: number;
  refillPerSec: number;
  now?: () => number;
}) {
  const nowFn = opts.now ?? Date.now;
  let state: BucketState | null = null;

  return {
    consume(cost = 1): { allowed: boolean; remaining: number; retryAfterSec: number } {
      const nowMs = nowFn();
      if (!state) {
        state = { tokens: opts.capacity, lastRefillMs: nowMs };
      } else {
        const elapsedSec = Math.max(0, (nowMs - state.lastRefillMs) / 1000);
        if (elapsedSec > 0) {
          state.tokens = Math.min(opts.capacity, state.tokens + elapsedSec * opts.refillPerSec);
          state.lastRefillMs = nowMs;
        }
      }
      if (state.tokens >= cost) {
        state.tokens -= cost;
        return { allowed: true, remaining: Math.floor(state.tokens), retryAfterSec: 0 };
      }
      const deficit = cost - state.tokens;
      const retryAfterSec = Math.max(1, Math.ceil(deficit / Math.max(opts.refillPerSec, 0.0001)));
      return { allowed: false, remaining: 0, retryAfterSec };
    },
    credit(bonusTokens: number, maxCapMultiplier = 4): void {
      if (!Number.isFinite(bonusTokens) || bonusTokens <= 0) return;
      const nowMs = nowFn();
      const maxCap = opts.capacity * Math.max(1, maxCapMultiplier);
      if (!state) {
        state = { tokens: Math.min(maxCap, opts.capacity + bonusTokens), lastRefillMs: nowMs };
      } else {
        const elapsedSec = Math.max(0, (nowMs - state.lastRefillMs) / 1000);
        if (elapsedSec > 0) {
          state.tokens = Math.min(opts.capacity, state.tokens + elapsedSec * opts.refillPerSec);
          state.lastRefillMs = nowMs;
        }
        state.tokens = Math.min(maxCap, state.tokens + bonusTokens);
      }
    },
    reset() {
      state = null;
    },
  };
}

export class BodyTooLargeError extends Error {
  readonly status = 413;
  constructor(maxBytes: number) {
    super(`Request body exceeds maximum allowed size (${maxBytes} bytes)`);
    this.name = "BodyTooLargeError";
  }
}

export class InvalidJsonBodyError extends Error {
  readonly status = 400;
  constructor(message = "Invalid JSON in request body") {
    super(message);
    this.name = "InvalidJsonBodyError";
  }
}

/**
 * Reads a request body up to `maxBytes` bytes, rejecting oversized payloads both via
 * Content-Length header pre-check and streaming byte accumulation.
 */
export async function readBoundedBytes(req: Request, maxBytes: number): Promise<Uint8Array> {
  const contentLength = req.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new BodyTooLargeError(maxBytes);
    }
  }

  if (!req.body) {
    return new Uint8Array(0);
  }

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel("Body exceeded maxBytes").catch(() => {});
          throw new BodyTooLargeError(maxBytes);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (chunks.length === 0) return new Uint8Array(0);
  if (chunks.length === 1) return chunks[0];
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return merged;
}

/**
 * Reads and parses a JSON request body with a strict byte size limit and NUL-byte check.
 */
export async function readBoundedJson<T = unknown>(
  req: Request,
  maxBytes = 65_536,
): Promise<T> {
  const bytes = await readBoundedBytes(req, maxBytes);
  if (bytes.byteLength === 0) {
    throw new InvalidJsonBodyError("Empty JSON request body");
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new InvalidJsonBodyError("Invalid JSON in request body");
  }
}
