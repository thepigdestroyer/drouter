import { NextRequest, NextResponse } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const MAX_API_BODY_BYTES = 262_144; // 256 KB global ceiling for API routes

const proxyApiLimiter = createTokenBucketLimiter({
  name: "proxy-api-global",
  capacity: 180,
  refillPerSec: 6,
});

/**
 * Next.js 16 edge/node request proxy (`src/proxy.ts`).
 * Enforces baseline body-size ceilings, method checks, and malformed JSON `null` guards
 * across `/api/*` and `/v1/*` routes, including routes owned by other subsystems.
 */
export async function proxy(request: NextRequest): Promise<Response | undefined> {
  const { pathname } = request.nextUrl;
  if (!pathname.startsWith("/api/") && !pathname.startsWith("/v1/")) {
    return undefined;
  }

  const limited = proxyApiLimiter.check(request);
  if (limited) return limited;

  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    const cl = request.headers.get("content-length");
    if (cl !== null) {
      const len = Number(cl);
      if (Number.isFinite(len) && len > MAX_API_BODY_BYTES) {
        return NextResponse.json(
          { error: `Request body exceeds maximum allowed size (${MAX_API_BODY_BYTES} bytes)` },
          { status: 413 },
        );
      }
    }

    // Protect downstream JSON POST handlers (such as /api/atlas and /api/gemini) from
    // non-object JSON literals (`null`, `[]`, primitives) or oversized streaming bodies.
    if (!pathname.includes("/relay/")) {
      try {
        const cloned = request.clone();
        const buf = await cloned.arrayBuffer();
        if (buf.byteLength > MAX_API_BODY_BYTES) {
          return NextResponse.json(
            { error: `Request body exceeds maximum allowed size (${MAX_API_BODY_BYTES} bytes)` },
            { status: 413 },
          );
        }
        if (buf.byteLength > 0) {
          const text = new TextDecoder().decode(buf).trim();
          if (text === "null" || text.startsWith("[") || text.startsWith('"')) {
            return NextResponse.json(
              { error: "Request body must be a JSON object" },
              { status: 400 },
            );
          }
        }
      } catch {
        return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
      }
    }
  }

  return undefined;
}

export const config = {
  matcher: ["/api/:path*", "/v1/:path*"],
};
