import { connection } from "next/server";
import { fetchLiveGatewayModels } from "@/lib/gateway/harness-config";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const modelsLimiter = createTokenBucketLimiter({
  name: "v1-models",
  capacity: 120,
  refillPerSec: 5,
});

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Accept, X-DRouter-Credit, X-DRouter-Credit-Token, X-DRouter-Scrub-PII, OpenAI-Organization, OpenAI-Project, X-Stainless-Lang, X-Stainless-Package-Version, X-Stainless-OS, X-Stainless-Arch, X-Stainless-Runtime, X-Stainless-Runtime-Version, X-Stainless-Async, X-Stainless-Retry-Count, X-Stainless-Timeout",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

export async function GET(req?: Request): Promise<Response> {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next request storage
  }
  if (req) {
    const limited = modelsLimiter.check(req, CORS_HEADERS);
    if (limited) return limited;
  }

  const models = await fetchLiveGatewayModels();

  return Response.json(
    {
      object: "list",
      data: models.map((m) => ({
        id: m.id,
        object: "model",
        created: m.created ?? 1792800000,
        owned_by: m.provider,
        enclave_attested: m.enclave_attested,
        ...(m.repo ? { repo: m.repo } : {}),
        ...(m.tag ? { tag: m.tag } : {}),
        ...(m.predicate ? { predicate: m.predicate } : {}),
        ...(m.healthy_hosts !== undefined ? { healthy_hosts: m.healthy_hosts } : {}),
        ...(m.configured_hosts !== undefined ? { configured_hosts: m.configured_hosts } : {}),
        ...(m.verified_hosts !== undefined ? { verified_hosts: m.verified_hosts } : {}),
      })),
    },
    {
      status: 200,
      headers: CORS_HEADERS,
    },
  );
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}
