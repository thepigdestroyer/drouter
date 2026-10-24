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

/** Only forward to HTTPS Tinfoil enclave origins, so the relay cannot be used as an open proxy. */
export function isAllowedEnclave(rawUrl: string | null): rawUrl is string {
  if (!rawUrl) return false;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port) return false;
  const host = url.hostname;
  return host === "tinfoil.sh" || host.endsWith(".tinfoil.sh");
}

/** Request headers the relay forwards unchanged. The body is HPKE-encrypted and is never read. */
export const FORWARD_REQUEST_HEADERS = ["content-type", "accept", "ehbp-encapsulated-key", "x-tinfoil-model"];

/** Response headers the relay passes back to the browser. */
export const FORWARD_RESPONSE_HEADERS = ["content-type", "ehbp-response-nonce", "cache-control"];

export function pickHeaders(src: Headers, names: string[]): Headers {
  const out = new Headers();
  for (const name of names) {
    const value = src.get(name);
    if (value !== null) out.set(name, value);
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
