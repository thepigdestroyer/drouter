import { ATC_ATTESTATION_URL, isValidRelayId } from "@/lib/relay";

/**
 * Hop-specific attestation relay (`/api/relay/[relayId]/attestation`).
 * Validates `relayId`, proxies the attestation bundle from Tinfoil's ATC service,
 * and stamps `X-DRouter-Relay-Hop` so the browser can verify multi-relay hop routing.
 */
async function relay(
  request: Request,
  ctx: { params: Promise<{ relayId: string }> },
): Promise<Response> {
  const { relayId } = await ctx.params;
  if (!isValidRelayId(relayId)) {
    return Response.json({ error: "Invalid relay hop identifier" }, { status: 400 });
  }

  const init: RequestInit = { method: request.method, cache: "no-store" };
  if (request.method === "POST") {
    init.body = await request.text();
    init.headers = { "content-type": request.headers.get("content-type") ?? "application/json" };
  }
  const upstream = await fetch(ATC_ATTESTATION_URL, init);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/json",
      "X-DRouter-Relay-Hop": relayId,
    },
  });
}

export const GET = relay;
export const POST = relay;
