import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import { ATC_ATTESTATION_URL, isAllowedEnclave, isValidRelayId } from "@/lib/relay";

const limiter = createTokenBucketLimiter({
  name: "relay-hop-attestation",
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
 * Hop-specific attestation relay (`/api/relay/[relayId]/attestation`).
 * Validates `relayId`, proxies the attestation bundle from Tinfoil's ATC service,
 * and stamps `X-DRouter-Relay-Hop` so the browser can verify multi-relay hop routing.
 */
async function relay(
  request: Request,
  ctx: { params: Promise<{ relayId: string }> },
): Promise<Response> {
  const limited = limiter.check(request);
  if (limited) return limited;

  const { relayId } = await ctx.params;
  if (!isValidRelayId(relayId)) {
    return Response.json({ error: "Invalid relay hop identifier" }, { status: 400 });
  }

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
    return Response.json(
      { domain: "router-0.tinfoil.sh", stubbed: true },
      { status: 200, headers: { "X-DRouter-Relay-Hop": relayId } },
    );
  }

  try {
    const upstream = await fetch(ATC_ATTESTATION_URL, init);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
        "X-DRouter-Relay-Hop": relayId,
      },
    });
  } catch {
    return Response.json(
      { error: "Upstream attestation service unreachable" },
      { status: 502, headers: { "X-DRouter-Relay-Hop": relayId } },
    );
  }
}

export const GET = relay;
export const POST = relay;
