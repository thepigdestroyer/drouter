import { NextRequest, NextResponse } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const MAX_API_BODY_BYTES = 262_144; // 256 KB global ceiling for API routes

export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://atc.tinfoil.sh https://inference.tinfoil.sh https://router-0.tinfoil.sh https://github-proxy.tinfoil.sh https://kds-proxy.tinfoil.sh https://*.tinfoil.sh https://*.containers.tinfoil.dev https://github.com https://api.github.com https://objects.githubusercontent.com https://release-assets.githubusercontent.com https://rekor.sigstore.dev https://log2025-1.rekor.sigstore.dev https://fulcio.sigstore.dev https://ctfe.sigstore.dev https://timestamp.sigstore.dev https://search.sigstore.dev https://kdsintf.amd.com https://rpc.testnet.arc.io",
    "worker-src 'self' blob:",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "form-action 'self'",
  ].join("; "),
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": [
    "accelerometer=()",
    "autoplay=()",
    "browsing-topics=()",
    "camera=()",
    "display-capture=()",
    "geolocation=()",
    "gyroscope=()",
    "hid=()",
    "idle-detection=()",
    "interest-cohort=()",
    "local-fonts=()",
    "magnetometer=()",
    "microphone=()",
    "midi=()",
    "payment=()",
    "publickey-credentials-get=()",
    "screen-wake-lock=()",
    "serial=()",
    "usb=()",
    "xr-spatial-tracking=()",
  ].join(", "),
  "Cross-Origin-Opener-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(k)) headers.set(k, v);
  }
  headers.delete("x-powered-by");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

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
  if (limited) return withSecurityHeaders(limited);

  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    const cl = request.headers.get("content-length");
    if (cl !== null) {
      const len = Number(cl);
      if (Number.isFinite(len) && len > MAX_API_BODY_BYTES) {
        return withSecurityHeaders(
          NextResponse.json(
            { error: `Request body exceeds maximum allowed size (${MAX_API_BODY_BYTES} bytes)` },
            { status: 413 },
          ),
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
          return withSecurityHeaders(
            NextResponse.json(
              { error: `Request body exceeds maximum allowed size (${MAX_API_BODY_BYTES} bytes)` },
              { status: 413 },
            ),
          );
        }
        if (buf.byteLength > 0) {
          const text = new TextDecoder().decode(buf).trim();
          if (text === "null" || text.startsWith("[") || text.startsWith('"')) {
            return withSecurityHeaders(
              NextResponse.json(
                { error: "Request body must be a JSON object" },
                { status: 400 },
              ),
            );
          }
        }
      } catch {
        return withSecurityHeaders(
          NextResponse.json({ error: "Invalid request body" }, { status: 400 }),
        );
      }
    }
  }

  return undefined;
}

export const config = {
  matcher: ["/api/:path*", "/v1/:path*"],
};
