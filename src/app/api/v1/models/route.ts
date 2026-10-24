import { connection } from "next/server";
import { SUPPORTED_GATEWAY_MODELS } from "@/lib/gateway/harness-config";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, X-DRouter-Scrub-PII, X-DRouter-Credit-Token",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

export async function GET(): Promise<Response> {
  await connection();
  return Response.json(
    {
      object: "list",
      data: SUPPORTED_GATEWAY_MODELS.map((m) => ({
        id: m.id,
        object: "model",
        created: 1792800000,
        owned_by: m.provider,
        enclave_attested: true,
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
