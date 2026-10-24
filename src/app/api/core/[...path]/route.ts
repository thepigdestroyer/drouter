/**
 * Next.js Route Handler for `/api/core/[...path]` (G5).
 *
 * Proxies an allowlist of paths (`attestation`, `keys`, `health`, `knowledge/corpus`, `agent/plan`)
 * to the Google Cloud Confidential Space VM (`https://<CORE_HOST>:8443`) with verify-then-pin TLS.
 * Never forwards client IP addresses, cookies, or user-agent headers.
 */

import { proxyCoreRequest } from "@/lib/core-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function handle(
  request: Request,
  ctx: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  try {
    const { path } = await ctx.params;
    const result = await proxyCoreRequest(request, path ?? []);
    return new Response(result.body, {
      status: result.status,
      headers: result.headers,
    });
  } catch {
    return new Response(
      JSON.stringify({
        ok: false,
        error: "internal_proxy_error",
        message: "Failed to process core proxy request.",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    );
  }
}

export async function GET(
  request: Request,
  ctx: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  return handle(request, ctx);
}

export async function POST(
  request: Request,
  ctx: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  return handle(request, ctx);
}
