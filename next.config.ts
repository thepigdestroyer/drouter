import type { NextConfig } from "next";

const CSP_DIRECTIVES = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' https://atc.tinfoil.sh https://inference.tinfoil.sh https://router-0.tinfoil.sh https://github-proxy.tinfoil.sh https://kds-proxy.tinfoil.sh https://*.tinfoil.sh https://*.containers.tinfoil.dev https://github.com https://api.github.com https://objects.githubusercontent.com https://release-assets.githubusercontent.com https://rekor.sigstore.dev https://log2025-1.rekor.sigstore.dev https://fulcio.sigstore.dev https://ctfe.sigstore.dev https://timestamp.sigstore.dev https://search.sigstore.dev https://kdsintf.amd.com https://rpc.testnet.arc.network",
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'self'",
].join("; ");

const PERMISSIONS_POLICY = [
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
].join(", ");

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  poweredByHeader: false,
  serverExternalPackages: ["@vercel/sandbox", "node-seal"],
  // node-seal loads its WebAssembly binary from a computed path that file tracing
  // cannot see, so ship it explicitly with the routes that run SEAL.
  outputFileTracingIncludes: {
    "/api/ashi": ["./node_modules/node-seal/dist/*.wasm"],
    "/api/tiers": ["./node_modules/node-seal/dist/*.wasm"],
    "/about": ["./node_modules/node-seal/dist/*.wasm"],
  },
  turbopack: {
    resolveAlias: {
      "@vercel/sandbox": { browser: "./src/lib/types.ts" },
    },
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [
      {
        source: "/v1/:path*",
        destination: "/api/v1/:path*",
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: CSP_DIRECTIVES },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: PERMISSIONS_POLICY },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
