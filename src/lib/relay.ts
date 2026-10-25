/** Rules for the dRouter relay that sits between browsers and Tinfoil enclaves. */

export const ATC_ATTESTATION_URL = "https://atc.tinfoil.sh/attestation";

export const RELAY_HOPS = [
  { id: "relay-eu-zurich", name: "Zurich Oblivious Relay", region: "eu-central", operator: "SwissPrivacy AG" },
  { id: "relay-us-virginia", name: "Virginia Oblivious Relay", region: "us-east", operator: "NullRoute Labs" },
  { id: "relay-ap-tokyo", name: "Tokyo Oblivious Relay", region: "ap-northeast", operator: "Kuroshio Net" },
] as const;

export type RelayHopId = (typeof RELAY_HOPS)[number]["id"];

/** Validates a relay hop identifier against known hops or safe alphanumeric IDs <= 32 chars. */
export function isValidRelayId(relayId: string | null | undefined): relayId is string {
  if (!relayId) return false;
  if (RELAY_HOPS.some((h) => h.id === relayId)) return true;
  return /^[a-zA-Z0-9_-]{1,32}$/.test(relayId);
}

/** Allowed upstream v1 endpoint paths that the oblivious relay may forward to a Tinfoil enclave. */
export const ALLOWED_RELAY_V1_PATHS = [
  "chat/completions",
  "completions",
  "embeddings",
  "models",
  "audio/transcriptions",
  "audio/speech",
  "responses",
  "redact",
] as const;

const ALLOWED_RELAY_V1_PATH_SET = new Set<string>(ALLOWED_RELAY_V1_PATHS);

/** Hostname of Tinfoil's dedicated attested PII filter enclave, which serves POST /redact at root rather than under /v1. */
export const TINFOIL_PII_FILTER_HOST = "pii-filter.tinfoil.sh";

/**
 * Resolves the upstream URL on a verified Tinfoil enclave for a validated relay path.
 * Returns null if the (enclaveHost, validatedPath) combination is not allowed:
 * - For `pii-filter.tinfoil.sh`, both `redact` and `chat/completions` resolve to `https://pii-filter.tinfoil.sh/redact`
 *   (any other path on `pii-filter.tinfoil.sh`, or `redact` on any other host, is rejected).
 * - Standard OpenAI-compatible v1 paths are forwarded to `${origin}/v1/${validatedPath}` on router/model enclaves.
 */
export function resolveRelayUpstreamUrl(
  parsedEnclave: URL,
  validatedPath: string,
): string | null {
  const host = parsedEnclave.hostname.toLowerCase();
  if (host === TINFOIL_PII_FILTER_HOST) {
    if (validatedPath === "redact" || validatedPath === "chat/completions") {
      return `${parsedEnclave.origin}/redact`;
    }
    return null;
  }
  if (validatedPath === "redact") {
    return null;
  }
  return `${parsedEnclave.origin}/v1/${validatedPath}`;
}

/**Allowed models that can be specified in `x-tinfoil-model`. */
export const ALLOWED_TINFOIL_MODELS = new Set<string>([
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
  "gemma4-31b",
  "voxtral-small-24b",
  "voxtral-mini-4b-realtime",
  "voxtral-tts",
  "qwen3-tts",
  "whisper-large-v3-turbo",
  "nomic-embed-text",
  "pii-filter",
]);

/**
 * Validates that the `[...path]` segments under `/api/relay/v1/[...path]` contain no traversal,
 * backslashes, control characters, or unapproved upstream routes, and returns the canonical relative path.
 */
export function validateRelayPath(pathSegments: unknown): string | null {
  if (!Array.isArray(pathSegments) || pathSegments.length === 0 || pathSegments.length > 4) {
    return null;
  }
  const cleaned: string[] = [];
  for (const seg of pathSegments) {
    if (typeof seg !== "string" || seg.length === 0 || seg.length > 64) return null;
    if (
      seg === "." ||
      seg === ".." ||
      seg.includes("/") ||
      seg.includes("\\") ||
      seg.includes("%") ||
      seg.includes("\0") ||
      !/^[a-zA-Z0-9_-]+$/.test(seg)
    ) {
      return null;
    }
    cleaned.push(seg);
  }
  const joined = cleaned.join("/");
  if (!ALLOWED_RELAY_V1_PATH_SET.has(joined)) {
    return null;
  }
  return joined;
}

/** Validates optional `x-tinfoil-model` header against the allowlist. */
export function isAllowedRelayModel(modelHeader: string | null | undefined): boolean {
  if (modelHeader === null || modelHeader === undefined || modelHeader === "") return true;
  const trimmed = modelHeader.trim();
  if (/[\r\n\0]/.test(trimmed)) return false;
  return ALLOWED_TINFOIL_MODELS.has(trimmed);
}

/** Only forward to HTTPS Tinfoil enclave origins, so the relay cannot be used as an open proxy. */
export function isAllowedEnclave(rawUrl: string | null): rawUrl is string {
  if (!rawUrl || typeof rawUrl !== "string" || rawUrl.length > 256) return false;
  if (/[\r\n\0\\]/.test(rawUrl)) return false;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port) return false;
  if (url.pathname !== "/" || url.search || url.hash) return false;
  const host = url.hostname.toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..")) return false;
  return (
    host === "tinfoil.sh" ||
    host.endsWith(".tinfoil.sh") ||
    host.endsWith(".tinfoil.dev")
  );
}

const HEADER_VALUE_SAFE_RE = /^[\x20-\x7E]{1,512}$/;

/**
 * Credit-backed relay limit policy:
 * - Free tier (no `x-drouter-credit` header): per-salted-IP token bucket (20 burst, 0.5/sec)
 *   and 256 KB max HPKE body (`MAX_RELAY_BODY_BYTES`).
 * - Credit-backed tier (valid `x-drouter-credit` header verified against the per-denomination
 *   RSA exponent and atomically recorded in `credit_nullifiers`):
 *   1. Bypasses the per-IP free-tier limiter even when the caller's free bucket is exhausted.
 *   2. Credits `denomination * CREDIT_RATE_BONUS_PER_DENOM` (4x denomination) tokens back into
 *      the caller's per-IP bucket (up to 4x burst capacity = 80 requests) and credits the
 *      global bucket by `denomination`.
 *   3. Raises the maximum HPKE encrypted request body cap from 256 KB to 512 KB (`MAX_CREDIT_RELAY_BODY_BYTES`).
 */
export const MAX_RELAY_BODY_BYTES = 262_144; // 256 KB free-tier max HPKE ciphertext
export const MAX_CREDIT_RELAY_BODY_BYTES = 524_288; // 512 KB credit-backed max HPKE ciphertext
export const CREDIT_RATE_BONUS_PER_DENOM = 4;

/** Request headers the relay forwards unchanged. The body is HPKE-encrypted and is never read. */
export const FORWARD_REQUEST_HEADERS = ["content-type", "accept", "ehbp-encapsulated-key", "x-tinfoil-model"];

/** Response headers the relay passes back to the browser. */
export const FORWARD_RESPONSE_HEADERS = ["content-type", "ehbp-response-nonce", "cache-control"];

export function pickHeaders(src: Headers, names: string[]): Headers {
  const out = new Headers();
  for (const name of names) {
    const value = src.get(name);
    if (value !== null && HEADER_VALUE_SAFE_RE.test(value)) {
      out.set(name, value);
    }
  }
  return out;
}

/**
 * Pads a UTF-8 JSON string to the smallest power-of-two byte bucket `minBucketBytes * 2^j`
 * using RFC 8259 trailing ASCII whitespace (`0x20`), so `JSON.parse(paddedJson)` is identical
 * to `JSON.parse(jsonText)` while hiding exact prompt length before HPKE encryption (Spec §2.2).
 */
export function padJsonPayloadToBucket(
  jsonText: string,
  minBucketBytes = 4096,
): { paddedJson: string; originalBytes: number; bucketBytes: number } {
  const encoder = new TextEncoder();
  const originalBytes = encoder.encode(jsonText).byteLength;
  let bucketBytes = Math.max(1, Math.floor(minBucketBytes));
  while (bucketBytes < originalBytes) {
    bucketBytes *= 2;
  }
  const padLen = bucketBytes - originalBytes;
  const paddedJson = padLen > 0 ? jsonText + " ".repeat(padLen) : jsonText;
  return { paddedJson, originalBytes, bucketBytes };
}

/**
 * Buffers a response byte stream and flushes accumulated bytes on a fixed `cadenceMs`
 * interval (Spec §2.2 response frame cadence pacing) until the upstream closes.
 */
export function pacedStream(
  body: ReadableStream<Uint8Array>,
  cadenceMs: number,
): ReadableStream<Uint8Array> {
  if (!Number.isFinite(cadenceMs) || cadenceMs <= 0) return body;
  const intervalMs = Math.max(1, Math.round(cadenceMs));
  const queue: Uint8Array[] = [];
  let queuedBytes = 0;
  let upstreamDone = false;
  let upstreamError: unknown = null;
  let timer: ReturnType<typeof setInterval> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  const flush = (controller: ReadableStreamDefaultController<Uint8Array>) => {
    if (queuedBytes > 0) {
      if (queue.length === 1) {
        controller.enqueue(queue[0]);
      } else {
        const merged = new Uint8Array(queuedBytes);
        let offset = 0;
        for (const chunk of queue) {
          merged.set(chunk, offset);
          offset += chunk.byteLength;
        }
        controller.enqueue(merged);
      }
      queue.length = 0;
      queuedBytes = 0;
    }
    if (upstreamError !== null) {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      controller.error(upstreamError);
      return;
    }
    if (upstreamDone && queuedBytes === 0) {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      controller.close();
    }
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      reader = body.getReader();
      void (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              upstreamDone = true;
              break;
            }
            if (value && value.byteLength > 0) {
              queue.push(value);
              queuedBytes += value.byteLength;
            }
          }
        } catch (err) {
          upstreamError = err;
        }
      })();
      timer = setInterval(() => flush(controller), intervalMs);
    },
    cancel(reason) {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      return reader ? reader.cancel(reason) : undefined;
    },
  });
}

/** Wraps a body stream to count bytes as they pass through, without reading their contents. */
export function countingStream(
  body: ReadableStream<Uint8Array>,
  onDone: (bytes: number) => void,
): ReadableStream<Uint8Array> {
  let bytes = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        bytes += chunk.byteLength;
        controller.enqueue(chunk);
      },
      flush() {
        onDone(bytes);
      },
    }),
  );
}
