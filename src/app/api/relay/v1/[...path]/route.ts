import { after } from "next/server";
import { logRelay } from "@/lib/db";
import {
  FORWARD_REQUEST_HEADERS,
  FORWARD_RESPONSE_HEADERS,
  countingStream,
  isAllowedEnclave,
  pickHeaders,
} from "@/lib/relay";

export const maxDuration = 300;

/**
 * dRouter relay. Forwards HPKE-encrypted request bodies to the enclave the browser verified, adds
 * the operator's API key, and streams the encrypted response back. It never decrypts anything and
 * logs only byte counts.
 */
export async function POST(request: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
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
  const upstream = await fetch(target, { method: "POST", headers, body: requestBody, cache: "no-store" });

  const responseHeaders = pickHeaders(upstream.headers, FORWARD_RESPONSE_HEADERS);
  const enclaveHost = new URL(enclaveUrl).host;
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
  if (!upstream.body) {
    reportBytes(0);
    return new Response(null, { status: upstream.status, headers: responseHeaders });
  }
  return new Response(countingStream(upstream.body, reportBytes), {
    status: upstream.status,
    headers: responseHeaders,
  });
}
