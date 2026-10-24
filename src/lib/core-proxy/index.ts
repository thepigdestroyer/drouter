/**
 * Confidential Space attestation proxy (`src/lib/core-proxy/index.ts`) (G5).
 *
 * Responsibilities:
 * 1. Strict path allowlist (`attestation`, `keys`, `health`, `knowledge/corpus`, `agent/plan`).
 * 2. Verify-then-pin TLS with `node:https`:
 *    - First fetches `/attestation` over TLS (collecting the peer certificate DER),
 *    - Verifies the Google Cloud Confidential Space PKI token using G4 (`verifyConfidentialSpaceAttestation`),
 *      confirming the root CA, 3-cert chain, RS256 signature, STABLE image posture, expected image digest,
 *      allowed env overrides, and `eat_nonce` binding (`keysDigest` and `tlsSpkiDigest`).
 *    - Pins subsequent TLS connections to `tlsSpkiSha256` via a custom `checkServerIdentity` callback
 *      that hashes the peer certificate's SubjectPublicKeyInfo DER (`rejectUnauthorized: false` is used
 *      exclusively alongside this mandatory SPKI SHA-256 pin).
 *    - Caches the verified attestation until 5 minutes (300 s) before `exp`.
 * 3. Never forwards client IP addresses, cookies, or user-agent headers.
 * 4. Enforces strict request/response byte limits and timeouts, and returns plain error JSON with no stack traces.
 * 5. Reads `CORE_HOST` and `CORE_IMAGE_DIGESTS` (comma-separated) from env; if `CORE_HOST` is unset,
 *    returns HTTP 503 `{ core: "not-deployed" }` and never returns fake data.
 */

import crypto from "node:crypto";
import https from "node:https";
import type { PeerCertificate, TLSSocket } from "node:tls";
import {
  type ConfidentialSpaceVerificationResult,
  DEFAULT_ALLOWED_ENV_OVERRIDES,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  verifyConfidentialSpaceAttestation,
} from "@/lib/attestation/confidential-space";

export const ALLOWED_CORE_PATHS = new Set([
  "attestation",
  "keys",
  "health",
  "knowledge/corpus",
  "agent/plan",
]);

export const DEFAULT_CORE_PORT = 8443;
export const MAX_CORE_REQUEST_BODY_BYTES = 16_384; // 16 KiB
export const MAX_CORE_RESPONSE_BODY_BYTES = 2 * 1024 * 1024; // 2 MiB
export const CORE_REQUEST_TIMEOUT_MS = 25_000; // 25 seconds
export const ATTESTATION_CACHE_SAFETY_MARGIN_SEC = 300; // 5 minutes before `exp`

export interface CachedCoreAttestation {
  host: string;
  port: number;
  tlsSpkiSha256: string;
  keysDigest: string;
  keys: {
    egress: string;
    tree: string;
  };
  token: string;
  expiresAtSec: number;
  cacheUntilSec: number;
  verification: ConfidentialSpaceVerificationResult;
  rawAttestationPayload: Record<string, unknown>;
}

export interface CoreProxyConfig {
  /** Override `process.env.CORE_HOST` (for tests). Formats: `host` or `host:port`. */
  coreHost?: string;
  /** Override `process.env.CORE_IMAGE_DIGESTS` (comma-separated `sha256:...`). */
  coreImageDigests?: readonly string[];
  /** Override expected JWT audience. */
  expectedAudience?: string;
  /** Override allowed `env_override` keys. */
  allowedEnvOverrides?: readonly string[];
  /** Optional pinned root CA PEM override for unit tests with synthetic 3-cert chains. */
  pinnedRootCaPem?: string;
  /** Optional clock override in seconds for unit tests. */
  nowSec?: () => number;
  /** Optional timeout override in ms. */
  timeoutMs?: number;
  /** Optional max request body bytes override. */
  maxRequestBodyBytes?: number;
  /** Optional max response body bytes override. */
  maxResponseBodyBytes?: number;
}

export interface CoreProxyResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

let cachedAttestation: CachedCoreAttestation | null = null;

export function clearCoreAttestationCache(): void {
  cachedAttestation = null;
}

export function getCachedCoreAttestation(): CachedCoreAttestation | null {
  return cachedAttestation;
}

/**
 * Validates and normalizes the `[...path]` route segments against the strict allowlist.
 */
export function normalizeAllowedCorePath(pathSegments: readonly string[] | string): {
  ok: true;
  path: string;
  allowedMethod: "GET" | "POST";
} | {
  ok: false;
  status: number;
  error: string;
  message: string;
} {
  const joined = Array.isArray(pathSegments)
    ? pathSegments.map((s) => String(s ?? "").trim()).filter(Boolean).join("/")
    : String(pathSegments ?? "").replace(/^\/+|\/+$/g, "");

  if (!joined || joined.includes("..") || joined.includes("\\") || joined.includes("?")) {
    return {
      ok: false,
      status: 404,
      error: "path_not_allowed",
      message: "Requested core path is not on the allowlist.",
    };
  }

  if (!ALLOWED_CORE_PATHS.has(joined)) {
    return {
      ok: false,
      status: 404,
      error: "path_not_allowed",
      message: `Path '${joined}' is not in the deroute-core proxy allowlist.`,
    };
  }

  const allowedMethod = joined === "agent/plan" ? "POST" : "GET";
  return { ok: true, path: joined, allowedMethod };
}

export function parseCoreHost(rawHost: string | undefined): {
  host: string;
  port: number;
} | null {
  const clean = typeof rawHost === "string" ? rawHost.trim() : "";
  if (!clean) return null;

  // Strip optional https:// prefix or trailing slash if accidentally provided
  const stripped = clean.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!stripped || /[/?#\s]/.test(stripped)) return null;

  const colonIdx = stripped.lastIndexOf(":");
  if (colonIdx > 0 && !stripped.endsWith("]")) {
    const hostPart = stripped.slice(0, colonIdx);
    const portPart = Number(stripped.slice(colonIdx + 1));
    if (!hostPart || !Number.isInteger(portPart) || portPart < 1 || portPart > 65535) {
      return null;
    }
    return { host: hostPart, port: portPart };
  }

  return { host: stripped, port: DEFAULT_CORE_PORT };
}

export function parseCoreImageDigests(
  override?: readonly string[],
  envVal = process.env.CORE_IMAGE_DIGESTS,
): string[] {
  if (override && override.length > 0) {
    return override.map((d) => d.trim()).filter(Boolean);
  }
  if (!envVal) return [];
  return envVal
    .split(",")
    .map((d) => d.trim())
    .filter(Boolean);
}

/**
 * Computes the lowercase 64-character SHA-256 hex digest of a peer TLS certificate's
 * SubjectPublicKeyInfo (SPKI) DER directly from its raw X.509 DER bytes.
 */
export function computePeerCertSpkiSha256(certDer: Buffer | Uint8Array): string {
  const x509Cert = new crypto.X509Certificate(certDer);
  const spkiDer = x509Cert.publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spkiDer).digest("hex").toLowerCase();
}

interface RawHttpsResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  peerCertDer: Buffer;
  peerSpkiSha256: string;
}

/**
 * Performs an HTTPS request to `<host>:<port>` using `node:https`.
 * When `pinnedSpkiSha256` is provided, `checkServerIdentity` enforces that the
 * peer certificate's SPKI SHA-256 equals `pinnedSpkiSha256` before any application
 * data is exchanged.
 */
function httpsRequestWithSpkiPin(params: {
  host: string;
  port: number;
  path: string;
  method: "GET" | "POST";
  body?: Buffer;
  pinnedSpkiSha256?: string;
  timeoutMs: number;
  maxResponseBytes: number;
}): Promise<RawHttpsResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let capturedPeerDer: Buffer | null = null;
    let capturedPeerSpkiSha256: string | null = null;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const reqHeaders: Record<string, string> = {
      Accept: "application/json",
      Connection: "close",
    };

    if (params.method === "POST" && params.body) {
      reqHeaders["Content-Type"] = "application/json; charset=utf-8";
      reqHeaders["Content-Length"] = String(params.body.byteLength);
    }

    const verifyPeerCertificate = (cert: PeerCertificate | undefined | null): Error | undefined => {
      if (!cert || !cert.raw || cert.raw.byteLength === 0) {
        return new Error("TLS peer did not present a certificate");
      }
      let actualSpkiSha256: string;
      try {
        actualSpkiSha256 = computePeerCertSpkiSha256(cert.raw);
      } catch {
        return new Error("Failed to extract SPKI from TLS peer certificate");
      }
      capturedPeerDer = Buffer.from(cert.raw);
      capturedPeerSpkiSha256 = actualSpkiSha256;

      if (params.pinnedSpkiSha256) {
        const expected = params.pinnedSpkiSha256.toLowerCase();
        if (actualSpkiSha256 !== expected) {
          return new Error(
            `TLS SPKI pin mismatch: peer certificate SPKI sha256 ${actualSpkiSha256} !== attested ${expected}`,
          );
        }
      }
      return undefined;
    };

    const req = https.request(
      {
        host: params.host,
        port: params.port,
        path: params.path,
        method: params.method,
        headers: reqHeaders,
        // Self-signed enclave certificate is authenticated via hardware attestation + SPKI pinning
        rejectUnauthorized: false,
        agent: false,
        checkServerIdentity: (_servername: string, cert: PeerCertificate) =>
          verifyPeerCertificate(cert),
      },
      (res) => {
        const socket = res.socket as TLSSocket;
        if (!capturedPeerDer || !capturedPeerSpkiSha256) {
          const peer = socket.getPeerCertificate?.(false);
          const verifyErr = verifyPeerCertificate(peer);
          if (verifyErr) {
            res.destroy();
            fail(verifyErr);
            return;
          }
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          totalBytes += chunk.byteLength;
          if (totalBytes > params.maxResponseBytes) {
            res.destroy();
            fail(new Error("Upstream response exceeded maximum allowed byte limit"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", (err) => {
          fail(err instanceof Error ? err : new Error(String(err)));
        });

        res.on("end", () => {
          if (settled) return;
          settled = true;
          resolve({
            statusCode: res.statusCode ?? 502,
            headers: res.headers,
            body: Buffer.concat(chunks),
            peerCertDer: capturedPeerDer!,
            peerSpkiSha256: capturedPeerSpkiSha256!,
          });
        });
      },
    );

    req.on("socket", (socket) => {
      socket.on("secureConnect", () => {
        const tlsSocket = socket as TLSSocket;
        if (!capturedPeerDer || !capturedPeerSpkiSha256) {
          const peer = tlsSocket.getPeerCertificate?.(false);
          const verifyErr = verifyPeerCertificate(peer);
          if (verifyErr) {
            req.destroy(verifyErr);
          }
        }
      });
    });

    req.setTimeout(params.timeoutMs, () => {
      req.destroy(new Error("Upstream core request timed out"));
    });

    req.on("error", (err) => {
      fail(err instanceof Error ? err : new Error(String(err)));
    });

    if (params.method === "POST" && params.body) {
      req.write(params.body);
    }
    req.end();
  });
}

/**
 * Fetches `/attestation` from the Confidential Space VM, verifies it with G4,
 * ensures the TLS peer certificate's SPKI matches the attested `tlsSpkiSha256`,
 * and caches the verified entry until 5 minutes before `exp`.
 */
export async function ensureVerifiedCoreAttestation(
  target: { host: string; port: number },
  config: CoreProxyConfig = {},
): Promise<
  | { ok: true; attested: CachedCoreAttestation }
  | { ok: false; status: number; body: Record<string, unknown> }
> {
  const nowSec = config.nowSec ? config.nowSec() : Math.floor(Date.now() / 1000);

  if (
    cachedAttestation &&
    cachedAttestation.host === target.host &&
    cachedAttestation.port === target.port &&
    nowSec < cachedAttestation.cacheUntilSec
  ) {
    return { ok: true, attested: cachedAttestation };
  }

  const expectedDigests = parseCoreImageDigests(config.coreImageDigests);
  if (expectedDigests.length === 0) {
    return {
      ok: false,
      status: 503,
      body: {
        ok: false,
        core: "not-configured",
        error: "missing_core_image_digests",
        message: "CORE_IMAGE_DIGESTS is not configured for Confidential Space verification.",
      },
    };
  }

  const timeoutMs = config.timeoutMs ?? CORE_REQUEST_TIMEOUT_MS;
  const maxResponseBytes = config.maxResponseBodyBytes ?? MAX_CORE_RESPONSE_BODY_BYTES;

  let attRes: RawHttpsResponse;
  try {
    attRes = await httpsRequestWithSpkiPin({
      host: target.host,
      port: target.port,
      path: "/attestation",
      method: "GET",
      timeoutMs,
      maxResponseBytes,
    });
  } catch {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "core_unreachable",
        message: "Failed to reach Confidential Space workload /attestation endpoint.",
      },
    };
  }

  if (attRes.statusCode !== 200) {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "attestation_http_error",
        message: `Workload /attestation returned HTTP ${attRes.statusCode}.`,
      },
    };
  }

  let parsedAtt: Record<string, unknown>;
  try {
    parsedAtt = JSON.parse(attRes.body.toString("utf8")) as Record<string, unknown>;
  } catch {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "invalid_attestation_json",
        message: "Workload /attestation did not return valid JSON.",
      },
    };
  }

  const token = typeof parsedAtt.token === "string" ? parsedAtt.token : "";
  const keysObj =
    parsedAtt.keys && typeof parsedAtt.keys === "object"
      ? (parsedAtt.keys as Record<string, unknown>)
      : null;
  const egressKey = typeof keysObj?.egress === "string" ? keysObj.egress : "";
  const treeKey = typeof keysObj?.tree === "string" ? keysObj.tree : "";
  const servedTlsSpkiSha256 =
    typeof parsedAtt.tlsSpkiSha256 === "string"
      ? parsedAtt.tlsSpkiSha256.trim().toLowerCase()
      : "";

  if (!token || !egressKey || !treeKey) {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "incomplete_attestation_payload",
        message: "Workload /attestation response is missing token or attested public keys.",
      },
    };
  }

  // Verify that the TLS certificate presented during the /attestation handshake matches servedTlsSpkiSha256
  if (servedTlsSpkiSha256 && servedTlsSpkiSha256 !== attRes.peerSpkiSha256) {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "tls_spki_mismatch",
        message:
          "TLS peer certificate SPKI digest does not match the workload's reported tlsSpkiSha256.",
      },
    };
  }

  const verification = await verifyConfidentialSpaceAttestation({
    token,
    keys: { egress: egressKey, tree: treeKey },
    tlsCertificatePemOrDer: new Uint8Array(attRes.peerCertDer),
    tlsSpkiSha256: attRes.peerSpkiSha256,
    expectedAudience: config.expectedAudience ?? DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    expectedImageDigests: expectedDigests,
    allowedEnvOverrides: config.allowedEnvOverrides ?? DEFAULT_ALLOWED_ENV_OVERRIDES,
    pinnedRootCaPem: config.pinnedRootCaPem,
    nowSec,
  });

  if (!verification.ok || !verification.expiresAtSec || !verification.tlsSpkiDigest) {
    const failedChecks = verification.checks.filter((c) => !c.passed).map((c) => c.id);
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "attestation_verification_failed",
        message: "Google Confidential Space hardware attestation verification failed.",
        failedChecks,
        checks: verification.checks,
      },
    };
  }

  const cacheUntilSec = Math.max(
    nowSec,
    verification.expiresAtSec - ATTESTATION_CACHE_SAFETY_MARGIN_SEC,
  );

  const entry: CachedCoreAttestation = {
    host: target.host,
    port: target.port,
    tlsSpkiSha256: verification.tlsSpkiDigest,
    keysDigest: verification.keysDigest ?? "",
    keys: {
      egress: egressKey.toLowerCase(),
      tree: treeKey.toLowerCase(),
    },
    token,
    expiresAtSec: verification.expiresAtSec,
    cacheUntilSec,
    verification,
    rawAttestationPayload: parsedAtt,
  };

  cachedAttestation = entry;
  return { ok: true, attested: entry };
}

async function readBoundedRequestBody(
  request: Request,
  maxBytes: number,
): Promise<{ ok: true; buffer: Buffer } | { ok: false; status: number; error: string; message: string }> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isFinite(declared) || declared < 0) {
      return {
        ok: false,
        status: 400,
        error: "invalid_content_length",
        message: "Invalid Content-Length header.",
      };
    }
    if (declared > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: "payload_too_large",
        message: `Request body exceeds maximum size of ${maxBytes} bytes.`,
      };
    }
  }

  if (!request.body) {
    return {
      ok: false,
      status: 400,
      error: "empty_body",
      message: "POST request requires a JSON body.",
    };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          return {
            ok: false,
            status: 413,
            error: "payload_too_large",
            message: `Request body exceeds maximum size of ${maxBytes} bytes.`,
          };
        }
        chunks.push(value);
      }
    }
  } catch {
    return {
      ok: false,
      status: 400,
      error: "body_read_failed",
      message: "Failed to read request body.",
    };
  }

  if (total === 0) {
    return {
      ok: false,
      status: 400,
      error: "empty_body",
      message: "POST request requires a non-empty JSON body.",
    };
  }

  const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  try {
    JSON.parse(buf.toString("utf8"));
  } catch {
    return {
      ok: false,
      status: 400,
      error: "invalid_json",
      message: "Request body must be valid JSON.",
    };
  }

  return { ok: true, buffer: buf };
}

/**
 * Proxies an incoming Next.js `Request` to `https://<CORE_HOST>:8443/<path>`
 * after verifying the Confidential Space attestation and pinning TLS to `tlsSpkiSha256`.
 *
 * Strips all caller metadata: no client IP, cookies, or user-agent headers are ever sent upstream.
 */
export async function proxyCoreRequest(
  request: Request,
  pathSegments: readonly string[] | string,
  config: CoreProxyConfig = {},
): Promise<CoreProxyResult> {
  const defaultHeaders: Record<string, string> = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };

  // 1. Validate path against allowlist first
  const pathCheck = normalizeAllowedCorePath(pathSegments);
  if (!pathCheck.ok) {
    return {
      status: pathCheck.status,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: pathCheck.error,
        message: pathCheck.message,
      }),
    };
  }

  // 2. Reject query parameters on all core endpoints
  let parsedReqUrl: URL;
  try {
    parsedReqUrl = new URL(request.url);
  } catch {
    return {
      status: 400,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: "invalid_url",
        message: "Malformed request URL.",
      }),
    };
  }

  if (parsedReqUrl.search.length > 0) {
    return {
      status: 400,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: "query_parameters_forbidden",
        message: "Query parameters are not permitted on deroute-core proxy endpoints.",
      }),
    };
  }

  // 3. Enforce HTTP method per path
  const method = (request.method || "GET").toUpperCase();
  if (method !== pathCheck.allowedMethod) {
    return {
      status: 405,
      headers: {
        ...defaultHeaders,
        Allow: pathCheck.allowedMethod,
      },
      body: JSON.stringify({
        ok: false,
        error: "method_not_allowed",
        message: `Endpoint /${pathCheck.path} only accepts ${pathCheck.allowedMethod}.`,
      }),
    };
  }

  // 4. Resolve CORE_HOST; if unset return 503 { core: "not-deployed" }
  const rawCoreHost = config.coreHost !== undefined ? config.coreHost : process.env.CORE_HOST;
  const target = parseCoreHost(rawCoreHost);
  if (!target) {
    return {
      status: 503,
      headers: defaultHeaders,
      body: JSON.stringify({ core: "not-deployed" }),
    };
  }

  // 5. Read and validate bounded POST body before contacting upstream
  let postBody: Buffer | undefined;
  if (method === "POST") {
    const maxReqBytes = config.maxRequestBodyBytes ?? MAX_CORE_REQUEST_BODY_BYTES;
    const bodyRes = await readBoundedRequestBody(request, maxReqBytes);
    if (!bodyRes.ok) {
      return {
        status: bodyRes.status,
        headers: defaultHeaders,
        body: JSON.stringify({
          ok: false,
          error: bodyRes.error,
          message: bodyRes.message,
        }),
      };
    }
    postBody = bodyRes.buffer;
  }

  // 6. Verify /attestation (or use cached attestation valid until exp - 5 min)
  const attStatus = await ensureVerifiedCoreAttestation(target, config);
  if (!attStatus.ok) {
    return {
      status: attStatus.status,
      headers: defaultHeaders,
      body: JSON.stringify(attStatus.body),
    };
  }

  const attested = attStatus.attested;

  // If the caller requested `/attestation`, return the verified attestation payload + G4 verification summary
  if (pathCheck.path === "attestation") {
    return {
      status: 200,
      headers: {
        ...defaultHeaders,
        "X-DeRoute-Attested-HwModel": String(attested.verification.hwmodel ?? ""),
        "X-DeRoute-Attested-Image": String(attested.verification.imageDigest ?? ""),
      },
      body: JSON.stringify({
        ...attested.rawAttestationPayload,
        verification: attested.verification,
      }),
    };
  }

  // 7. Forward request over TLS pinned to `attested.tlsSpkiSha256`
  const timeoutMs = config.timeoutMs ?? CORE_REQUEST_TIMEOUT_MS;
  const maxResBytes = config.maxResponseBodyBytes ?? MAX_CORE_RESPONSE_BODY_BYTES;

  let upstreamRes: RawHttpsResponse;
  try {
    upstreamRes = await httpsRequestWithSpkiPin({
      host: target.host,
      port: target.port,
      path: `/${pathCheck.path}`,
      method: pathCheck.allowedMethod,
      body: postBody,
      pinnedSpkiSha256: attested.tlsSpkiSha256,
      timeoutMs,
      maxResponseBytes: maxResBytes,
    });
  } catch (err) {
    // Invalidate cache if TLS pin or connection failed
    clearCoreAttestationCache();
    const isPinError =
      err instanceof Error && err.message.toLowerCase().includes("spki pin mismatch");
    return {
      status: 502,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: isPinError ? "tls_spki_pin_mismatch" : "upstream_request_failed",
        message: isPinError
          ? "Upstream TLS certificate SPKI did not match the attested enclave key."
          : "Upstream request to Confidential Space workload failed.",
      }),
    };
  }

  // Ensure response is valid UTF-8 JSON (never echo stack traces or non-JSON error pages)
  let responseJsonText: string;
  try {
    const decoded = upstreamRes.body.toString("utf8");
    const parsed = JSON.parse(decoded);
    // Strip any accidental stack property if upstream ever included one
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && "stack" in parsed) {
      delete (parsed as Record<string, unknown>).stack;
    }
    responseJsonText = JSON.stringify(parsed);
  } catch {
    return {
      status: 502,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: "invalid_upstream_json",
        message: "Confidential Space workload returned a non-JSON response.",
      }),
    };
  }

  return {
    status: upstreamRes.statusCode,
    headers: {
      ...defaultHeaders,
      "X-DeRoute-Attested-HwModel": String(attested.verification.hwmodel ?? ""),
      "X-DeRoute-Attested-Image": String(attested.verification.imageDigest ?? ""),
    },
    body: responseJsonText,
  };
}
