import { ATC_ATTESTATION_URL } from "@/lib/relay";


/**
 * Relays the attestation bundle from Tinfoil's attestation service. The browser verifies the
 * bundle itself (AMD SEV-SNP report, VCEK chain, Sigstore provenance), so the relay is untrusted.
 */
async function relay(request: Request): Promise<Response> {
  const init: RequestInit = { method: request.method, cache: "no-store" };
  if (request.method === "POST") {
    init.body = await request.text();
    init.headers = { "content-type": request.headers.get("content-type") ?? "application/json" };
  }
  const upstream = await fetch(ATC_ATTESTATION_URL, init);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { "content-type": upstream.headers.get("content-type") ?? "application/json" },
  });
}

export const GET = relay;
export const POST = relay;
