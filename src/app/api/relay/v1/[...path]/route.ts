import { after } from "next/server";
import { verifyAndSpendCreditHeader } from "@/lib/credits/ledger";
import { logRelay } from "@/lib/db";
import {
  BodyTooLargeError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedBytes,
} from "@/lib/ratelimit";
import {
  CREDIT_RATE_BONUS_PER_DENOM,
  FORWARD_REQUEST_HEADERS,
  FORWARD_RESPONSE_HEADERS,
  MAX_CREDIT_RELAY_BODY_BYTES,
  MAX_RELAY_BODY_BYTES,
  countingStream,
  isAllowedEnclave,
  isAllowedRelayModel,
  pacedStream,
  pickHeaders,
  validateRelayPath,
} from "@/lib/relay";

export const maxDuration = 300;

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
 *
 * Credit-backed limit policy:
 * - Without `x-drouter-credit`, requests use the per-IP free tier (20 burst, 0.5/s, 256 KB body cap).
 * - With `x-drouter-credit`, the RSA blind signature is verified against the per-denomination exponent
 *   and the nullifier is recorded atomically in `credit_nullifiers` (HTTP 409 on double-spend).
 *   Spending a credit bypasses the per-IP free-tier gate, refills `denomination * 4` tokens into the
 *   caller's per-IP bucket (up to 4x capacity), credits `denomination` to the global bucket, and raises
 *   the request body cap to 512 KB.
 */
export async function POST(request: Request, ctx: { params: Promise<{ path: string[] }> }) {
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

  const rawCreditHeader =
    request.headers.get("x-drouter-credit") ?? request.headers.get("x-drouter-credit-token");
  let spentCredit: { nullifier: string; denomination: number } | null = null;

  if (rawCreditHeader !== null && rawCreditHeader.trim().length > 0) {
    const spendResult = await verifyAndSpendCreditHeader(rawCreditHeader, "relay-v1");
    if (!spendResult.ok) {
      return Response.json({ error: spendResult.error }, { status: spendResult.status });
    }
    spentCredit = {
      nullifier: spendResult.nullifier,
      denomination: spendResult.denomination,
    };
    ipLimiter.credit(request, spendResult.denomination * CREDIT_RATE_BONUS_PER_DENOM, 4);
    globalLimiter.credit(spendResult.denomination, 4);
  } else {
    const limited = ipLimiter.check(request);
    if (limited) return limited;

    const globalCheck = globalLimiter.consume(1);
    if (!globalCheck.allowed) {
      return Response.json(
        { error: "Global relay capacity reached. Please retry shortly." },
        { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
      );
    }
  }

  const maxBodyBytes = spentCredit ? MAX_CREDIT_RELAY_BODY_BYTES : MAX_RELAY_BODY_BYTES;
  let requestBody: Uint8Array;
  try {
    requestBody = await readBoundedBytes(request, maxBodyBytes);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json({ error: "Failed to read request body" }, { status: 400 });
  }

  if (requestBody.byteLength === 0) {
    return Response.json({ error: "Empty encrypted request body" }, { status: 400 });
  }

  const creditHeaders: Record<string, string> = spentCredit
    ? {
        "X-DRouter-Credit-Nullifier": spentCredit.nullifier,
        "X-DRouter-Credit-Denomination": String(spentCredit.denomination),
      }
    : {};

  if (process.env.VITEST === "true" && process.env.DROUTER_STUB_UPSTREAM === "1") {
    return new Response(new Uint8Array(0), {
      status: 200,
      headers: { "content-type": "application/octet-stream", ...creditHeaders },
    });
  }

  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    return Response.json(
      { error: "This relay has no Tinfoil API key configured." },
      { status: 503, headers: creditHeaders },
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
    return Response.json(
      { error: "Upstream enclave connection failed" },
      { status: 502, headers: creditHeaders },
    );
  }

  const responseHeaders = pickHeaders(upstream.headers, FORWARD_RESPONSE_HEADERS);
  for (const [k, v] of Object.entries(creditHeaders)) {
    responseHeaders.set(k, v);
  }

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
      { status: upstream.status >= 500 ? 502 : upstream.status, headers: creditHeaders },
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
