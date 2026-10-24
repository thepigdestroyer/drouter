/** Rules for the dRouter relay that sits between browsers and Tinfoil enclaves. */

export const ATC_ATTESTATION_URL = "https://atc.tinfoil.sh/attestation";

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
