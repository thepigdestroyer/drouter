import { after } from "next/server";
import { logRelay } from "@/lib/db";
import {
  BodyTooLargeError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedBytes,
} from "@/lib/ratelimit";
import {
  FORWARD_REQUEST_HEADERS,
  FORWARD_RESPONSE_HEADERS,
  countingStream,
  isAllowedEnclave,
  isAllowedRelayModel,
  pacedStream,
  pickHeaders,
  validateRelayPath,
} from "@/lib/relay";

export const maxDuration = 300;

const MAX_RELAY_BODY_BYTES = 262_144; // 256 KB max HPKE ciphertext

const ipLimiter = createTokenBucketLimiter({
  name: "relay-v1",
  capacity: 20,
  refillPerSec: 0.5,
});

const globalLimiter = createGlobalBucketLimiter({
  name: "relay-v1-global",
  capacity: 100,
  refillPerSec: 2,
});

/**
 * dRouter relay. Forwards HPKE-encrypted request bodies to the enclave the browser verified, adds
 * the operator's API key, and streams the encrypted response back. It never decrypts anything and
 * logs only byte counts.
 */
export async function POST(request: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const limited = ipLimiter.check(request);
  if (limited) return limited;

  const globalCheck = globalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return Response.json(
      { error: "Global relay capacity reached. Please retry shortly." },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  const { path } = await ctx.params;
  const validatedPath = validateRelayPath(path);
  if (!validatedPath) {
    return Response.json({ error: "Disallowed or invalid upstream v1 path" }, { status: 400 });
  }

  const enclaveUrl = request.headers.get("x-tinfoil-enclave-url");
  if (!isAllowedEnclave(enclaveUrl)) {
    return Response.json({ error: "Unapproved or missing enclave URL" }, { status: 400 });
  }

  const modelHeader = request.headers.get("x-tinfoil-model");
  if (!isAllowedRelayModel(modelHeader)) {
    return Response.json({ error: "Unsupported model in x-tinfoil-model header" }, { status: 400 });
  }

  const ehbpKey = request.headers.get("ehbp-encapsulated-key");
  if (!ehbpKey || ehbpKey.trim().length < 16 || ehbpKey.length > 512) {
    return Response.json(
      { error: "Relay requires an EHBP HPKE-encapsulated request key" },
      { status: 400 },
    );
  }

  let requestBody: Uint8Array;
  try {
    requestBody = await readBoundedBytes(request, MAX_RELAY_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json({ error: "Failed to read request body" }, { status: 400 });
  }

  if (requestBody.byteLength === 0) {
    return Response.json({ error: "Empty encrypted request body" }, { status: 400 });
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    return Response.json(
      { stubbed: true, path: validatedPath, bytesUp: requestBody.byteLength },
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }

  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    return Response.json(
      { error: "This relay has no Tinfoil API key configured. Simulated nodes still work." },
      { status: 503 },
    );
  }

  const parsedEnclave = new URL(enclaveUrl);
  const target = `${parsedEnclave.origin}/v1/${validatedPath}`;
  const headers = pickHeaders(request.headers, FORWARD_REQUEST_HEADERS);
  headers.set("authorization", `Bearer ${apiKey}`);

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: "POST",
      headers,
      body: requestBody as unknown as BodyInit,
      cache: "no-store",
    });
  } catch {
    return Response.json({ error: "Upstream enclave connection failed" }, { status: 502 });
  }

  const responseHeaders = pickHeaders(upstream.headers, FORWARD_RESPONSE_HEADERS);
  const enclaveHost = parsedEnclave.host;
  let reportBytes: (bytes: number) => void = () => {};
  const bytesDown = new Promise<number>((resolve) => (reportBytes = resolve));
  after(async () => {
    await logRelay({
      enclaveHost,
      bytesUp: requestBody.byteLength,
      bytesDown: await bytesDown,
      status: upstream.status,
      at: new Date(),
    });
  });

  // Never echo plaintext upstream error bodies (4xx/5xx without EHBP response nonce)
  if (!upstream.ok && !upstream.headers.get("ehbp-response-nonce")) {
    reportBytes(0);
    return Response.json(
      { error: `Upstream enclave returned HTTP ${upstream.status}` },
      { status: upstream.status >= 500 ? 502 : upstream.status },
    );
  }

  if (!upstream.body) {
    reportBytes(0);
    return new Response(null, { status: upstream.status, headers: responseHeaders });
  }
  const rawCadence = request.headers.get("x-drouter-cadence-ms");
  const cadenceMs =
    rawCadence !== null
      ? Number.isFinite(Number(rawCadence)) && Number(rawCadence) > 0
        ? Math.min(500, Math.max(10, Number(rawCadence)))
        : 50
      : 0;
  const counted = countingStream(upstream.body, reportBytes);
  const stream = cadenceMs > 0 ? pacedStream(counted, cadenceMs) : counted;
  return new Response(stream, {
    status: upstream.status,
    headers: responseHeaders,
  });
}
