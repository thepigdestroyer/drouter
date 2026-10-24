import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import { ATC_ATTESTATION_URL, isAllowedEnclave } from "@/lib/relay";

const limiter = createTokenBucketLimiter({
  name: "relay-attestation",
  capacity: 60,
  refillPerSec: 1,
});

const ALLOWED_REPOS = new Set<string>([
  "tinfoilsh/confidential-model-router",
  "tinfoilsh/confidential-kimi-k3",
  "tinfoilsh/confidential-glm5-3-nvfp4",
  "tinfoilsh/confidential-deepseek-v4-1-flash",
  "tinfoilsh/confidential-gpt-oss-120b",
  "tinfoilsh/confidential-llama3-3-70b",
]);

/**
 * Relays the attestation bundle from Tinfoil's attestation service. The browser verifies the
 * bundle itself (AMD SEV-SNP report, VCEK chain, Sigstore provenance), so the relay is untrusted.
 */
async function relay(request: Request): Promise<Response> {
  const limited = limiter.check(request);
  if (limited) return limited;

  const init: RequestInit = { method: request.method, cache: "no-store" };
  if (request.method === "POST") {
    try {
      const parsed = await readBoundedJson<Record<string, unknown>>(request, 4096);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return Response.json({ error: "Attestation POST body must be a JSON object" }, { status: 400 });
      }
      const cleanPayload: Record<string, string> = {};
      if (parsed.enclaveUrl !== undefined) {
        if (typeof parsed.enclaveUrl !== "string" || !isAllowedEnclave(parsed.enclaveUrl)) {
          return Response.json({ error: "Invalid enclaveUrl in attestation request" }, { status: 400 });
        }
        cleanPayload.enclaveUrl = parsed.enclaveUrl;
      }
      if (parsed.repo !== undefined) {
        if (typeof parsed.repo !== "string" || !ALLOWED_REPOS.has(parsed.repo)) {
          return Response.json({ error: "Unsupported repo in attestation request" }, { status: 400 });
        }
        cleanPayload.repo = parsed.repo;
      }
      init.body = JSON.stringify(cleanPayload);
      init.headers = { "content-type": "application/json" };
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return Response.json({ error: err.message }, { status: 413 });
      }
      if (err instanceof InvalidJsonBodyError) {
        return Response.json({ error: err.message }, { status: 400 });
      }
      return Response.json({ error: "Invalid attestation request body" }, { status: 400 });
    }
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    return Response.json({ domain: "router-0.tinfoil.sh", stubbed: true }, { status: 200 });
  }

  try {
    const upstream = await fetch(ATC_ATTESTATION_URL, init);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "content-type": upstream.headers.get("content-type") ?? "application/json" },
    });
  } catch {
    return Response.json({ error: "Upstream attestation service unreachable" }, { status: 502 });
  }
}

export const GET = relay;
export const POST = relay;
