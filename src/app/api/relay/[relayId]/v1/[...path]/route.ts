import { after } from "next/server";
import { logRelay } from "@/lib/db";
import {
  FORWARD_REQUEST_HEADERS,
  FORWARD_RESPONSE_HEADERS,
  countingStream,
  isAllowedEnclave,
  isValidRelayId,
  pacedStream,
  pickHeaders,
} from "@/lib/relay";

export const maxDuration = 300;

/**
 * Multi-relay hop route (`/api/relay/[relayId]/v1/[...path]`).
 * Forwards HPKE-encrypted request bodies to the attested Tinfoil enclave via the selected
 * oblivious relay hop, optionally enforces Spec §2.2 fixed-cadence response framing, and
 * records only encrypted byte counts.
 */
export async function POST(
  request: Request,
  ctx: { params: Promise<{ relayId: string; path: string[] }> },
) {
  const { relayId, path } = await ctx.params;
  if (!isValidRelayId(relayId)) {
    return Response.json({ error: "Invalid relay hop identifier" }, { status: 400 });
  }

  const enclaveUrl = request.headers.get("x-tinfoil-enclave-url");
  if (!isAllowedEnclave(enclaveUrl)) {
    return Response.json({ error: "Unapproved or missing enclave URL" }, { status: 400 });
  }
  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    return Response.json(
      { error: "This relay has no Tinfoil API key configured. Simulated nodes still work." },
      { status: 503 },
    );
  }

  const target = `${enclaveUrl.replace(/\/+$/, "")}/v1/${path.map(encodeURIComponent).join("/")}`;
  const headers = pickHeaders(request.headers, FORWARD_REQUEST_HEADERS);
  headers.set("authorization", `Bearer ${apiKey}`);

  const requestBody = await request.arrayBuffer();
  const upstream = await fetch(target, {
    method: "POST",
    headers,
    body: requestBody,
    cache: "no-store",
  });

  const responseHeaders = pickHeaders(upstream.headers, FORWARD_RESPONSE_HEADERS);
  responseHeaders.set("X-DRouter-Relay-Hop", relayId);

  const enclaveHost = new URL(enclaveUrl).host;
  let reportBytes: (bytes: number) => void = () => {};
  const bytesDown = new Promise<number>((resolve) => (reportBytes = resolve));
  after(async () => {
    await logRelay({
      enclaveHost: `${enclaveHost} (via ${relayId})`,
      bytesUp: requestBody.byteLength,
      bytesDown: await bytesDown,
      status: upstream.status,
      at: new Date(),
    });
  });

  if (!upstream.body) {
    reportBytes(0);
    return new Response(null, { status: upstream.status, headers: responseHeaders });
  }

  const rawCadence = request.headers.get("x-drouter-cadence-ms");
  const cadenceMs =
    rawCadence !== null
      ? Number.isFinite(Number(rawCadence)) && Number(rawCadence) > 0
        ? Number(rawCadence)
        : 50
      : 0;
  const counted = countingStream(upstream.body, reportBytes);
  const stream = cadenceMs > 0 ? pacedStream(counted, cadenceMs) : counted;
  return new Response(stream, {
    status: upstream.status,
    headers: responseHeaders,
  });
}
