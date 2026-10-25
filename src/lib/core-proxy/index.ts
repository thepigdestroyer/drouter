/**
 * Confidential Space attestation proxy (`src/lib/core-proxy/index.ts`) (G5).
 *
 * Responsibilities:
 * 1. Strict path allowlist (`attestation`, `keys`, `health`, `knowledge/corpus`, `agent/plan`).
 * 2. Verify-then-pin TLS with `node:https`:
 *    - First fetches `/attestation` (unpinned initial fetch) which returns the workload's
 *      PKI token, Ed25519 public keys, and TLS certificate PEM (`tlsCertPem`).
 *    - Verifies the Google Cloud Confidential Space PKI token using G4 (`verifyConfidentialSpaceAttestation`),
 *      proving `sha256(SPKI of tlsCertPem)` is one of the two distinct Google-signed nonces.
 *    - Creates a dedicated `https.Agent` per pin configured with `ca: [tlsCertPem]`,
 *      `rejectUnauthorized: true`, and a custom `checkServerIdentity` that returns an `Error`
 *      unless the peer certificate's SPKI SHA-256 equals the attested pin.
 *    - Caches the verified attestation until 5 minutes (300 s) before `exp`, destroying the old
 *      `https.Agent` (dropping all old keep-alive sockets) whenever the pin changes or cache clears.
 * 3. Never forwards client IP addresses, cookies, or user-agent headers.
 * 4. Never spreads unverified attestation fields; returns only verified fields.
 * 5. Enforces strict request/response byte limits and timeouts, and returns plain error JSON with no stack traces.
 * 6. Reads `CORE_HOST` and `CORE_IMAGE_DIGESTS` (comma-separated) from env; if `CORE_HOST` is unset,
 *    returns HTTP 503 `{ core: "not-deployed" }` and never returns fake data.
 */

import crypto from "node:crypto";
import https from "node:https";
import type { Socket } from "node:net";
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
  expectedAudience: string;
  tlsSpkiSha256: string;
  tlsCertPem: string;
  keysDigest: string;
  keys: {
    egress: string;
    tree: string;
  };
  token: string;
  expiresAtSec: number;
  refreshedAtSec: number;
  cacheUntilSec: number;
  verification: ConfidentialSpaceVerificationResult;
  agent: https.Agent;
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
  if (cachedAttestation) {
    try {
      cachedAttestation.agent.destroy();
    } catch {
      // ignore agent destroy errors
    }
    cachedAttestation = null;
  }
}

export function getCachedCoreAttestation(): CachedCoreAttestation | null {
  return cachedAttestation;
}

/**
 * Validates and normalizes the `[...path]` route segments against the strict allowlist.
 * Rejects empty segments, non-lowercase-alpha segments, and any path not in `ALLOWED_CORE_PATHS`.
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
  let segments: string[];
  if (Array.isArray(pathSegments)) {
    if (pathSegments.length === 0) {
      return {
        ok: false,
        status: 404,
        error: "path_not_allowed",
        message: "Requested core path is not on the allowlist.",
      };
    }
    for (const seg of pathSegments) {
      if (typeof seg !== "string" || !/^[a-z]+$/.test(seg)) {
        return {
          ok: false,
          status: 404,
          error: "path_not_allowed",
          message: "Requested core path is not on the allowlist.",
        };
      }
    }
    segments = [...pathSegments];
  } else if (typeof pathSegments === "string") {
    const trimmed = pathSegments.replace(/^\/+|\/+$/g, "");
    if (!trimmed) {
      return {
        ok: false,
        status: 404,
        error: "path_not_allowed",
        message: "Requested core path is not on the allowlist.",
      };
    }
    const parts = trimmed.split("/");
    for (const seg of parts) {
      if (!/^[a-z]+$/.test(seg)) {
        return {
          ok: false,
          status: 404,
          error: "path_not_allowed",
          message: "Requested core path is not on the allowlist.",
        };
      }
    }
    segments = parts;
  } else {
    return {
      ok: false,
      status: 404,
      error: "path_not_allowed",
      message: "Requested core path is not on the allowlist.",
    };
  }

  const joined = segments.join("/");
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

/**
 * Parses `CORE_HOST` (supporting IPv4, IPv6 in brackets `[::1]:8443`, or DNS hostnames)
 * while rejecting userinfo, paths, queries, fragments, or invalid characters.
 */
export function parseCoreHost(rawHost: string | undefined): {
  host: string;
  port: number;
} | null {
  const clean = typeof rawHost === "string" ? rawHost.trim() : "";
  if (!clean) return null;

  const stripped = clean.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!stripped || /[/?#@\s]/.test(stripped)) return null;

  // Reject bare unbracketed IPv6 literals (must be bracketed like [::1] or [::1]:8443)
  const colonCount = (stripped.match(/:/g) || []).length;
  if (colonCount > 1 && !stripped.startsWith("[")) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(`https://${stripped}`);
  } catch {
    return null;
  }

  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    return null;
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!hostname || !/^[A-Za-z0-9.:-]+$/.test(hostname)) {
    return null;
  }

  // Check if an explicit port was provided in `stripped`
  const afterHost = stripped.startsWith("[")
    ? stripped.slice(stripped.indexOf("]") + 1)
    : stripped.includes(":")
      ? stripped.slice(stripped.lastIndexOf(":"))
      : "";

  if (afterHost !== "") {
    if (!/^:[0-9]+$/.test(afterHost)) {
      return null;
    }
    const explicitPort = Number(afterHost.slice(1));
    if (!Number.isInteger(explicitPort) || explicitPort < 1 || explicitPort > 65535) {
      return null;
    }
    return { host: hostname, port: explicitPort };
  }

  return { host: hostname, port: DEFAULT_CORE_PORT };
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

/**
 * Creates a `checkServerIdentity` function that returns an `Error` unless the peer
 * certificate's SubjectPublicKeyInfo SHA-256 equals `pinnedSpkiSha256`.
 * Because `rejectUnauthorized: true` is used on pinned connections, Node.js enforces
 * this return value before any HTTP request bytes are sent.
 */
export function createSpkiPinCheckServerIdentity(
  pinnedSpkiSha256: string,
): (_servername: string, cert: PeerCertificate) => Error | undefined {
  const expected = pinnedSpkiSha256.trim().toLowerCase();
  return (_servername: string, cert: PeerCertificate): Error | undefined => {
    if (!cert || !cert.raw || cert.raw.byteLength === 0) {
      return new Error("TLS SPKI pin mismatch: peer did not present a certificate");
    }
    let actualSpkiSha256: string;
    try {
      actualSpkiSha256 = computePeerCertSpkiSha256(cert.raw);
    } catch {
      return new Error("TLS SPKI pin mismatch: failed to extract SPKI from peer certificate");
    }
    if (actualSpkiSha256 !== expected) {
      return new Error(
        `TLS SPKI pin mismatch: peer certificate SPKI sha256 ${actualSpkiSha256} !== attested ${expected}`,
      );
    }
    return undefined;
  };
}

/**
 * Creates a dedicated `https.Agent` for a single attested TLS certificate and SPKI pin.
 * Uses `ca: [tlsCertPem]`, `rejectUnauthorized: true`, and `checkServerIdentity` pinned
 * to `pinnedSpkiSha256`.
 */
export function createPinnedHttpsAgent(
  tlsCertPem: string,
  pinnedSpkiSha256: string,
): https.Agent {
  return new https.Agent({
    keepAlive: true,
    maxSockets: 32,
    ca: [tlsCertPem],
    rejectUnauthorized: true,
    checkServerIdentity: createSpkiPinCheckServerIdentity(pinnedSpkiSha256),
  });
}

interface RawHttpsResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  peerCertDer: Buffer;
  peerCertPem: string;
  peerSpkiSha256: string;
}

/**
 * Performs the initial unpinned `GET /attestation` fetch.
 * Its response content is untrusted until G4 verification proves that
 * `sha256(SPKI of tlsCertPem)` is one of the Google-signed nonces in the PKI token.
 */
function httpsFetchUnpinnedAttestation(params: {
  host: string;
  port: number;
  timeoutMs: number;
  maxResponseBytes: number;
}): Promise<RawHttpsResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let capturedPeerDer: Buffer | null = null;
    let capturedPeerPem: string | null = null;
    let capturedPeerSpkiSha256: string | null = null;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const capturePeer = (cert: PeerCertificate | undefined | null): Error | undefined => {
      if (!cert || !cert.raw || cert.raw.byteLength === 0) {
        return new Error("TLS peer did not present a certificate");
      }
      try {
        const x509Cert = new crypto.X509Certificate(cert.raw);
        const spkiDer = x509Cert.publicKey.export({ type: "spki", format: "der" });
        capturedPeerDer = Buffer.from(cert.raw);
        capturedPeerPem = x509Cert.toString().trim();
        capturedPeerSpkiSha256 = crypto
          .createHash("sha256")
          .update(spkiDer)
          .digest("hex")
          .toLowerCase();
        return undefined;
      } catch {
        return new Error("Failed to parse TLS peer certificate");
      }
    };

    const req = https.request(
      {
        host: params.host,
        port: params.port,
        path: "/attestation",
        method: "GET",
        headers: {
          Accept: "application/json",
          Connection: "close",
        },
        rejectUnauthorized: false,
        agent: false,
      },
      (res) => {
        const socket = res.socket as TLSSocket;
        if (!capturedPeerDer || !capturedPeerSpkiSha256 || !capturedPeerPem) {
          const peer = socket.getPeerCertificate?.(false);
          const err = capturePeer(peer);
          if (err) {
            res.destroy();
            fail(err);
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
            peerCertPem: capturedPeerPem!,
            peerSpkiSha256: capturedPeerSpkiSha256!,
          });
        });
      },
    );

    req.on("socket", (socket: Socket) => {
      socket.on("secureConnect", () => {
        const tlsSocket = socket as TLSSocket;
        const peer = tlsSocket.getPeerCertificate?.(false);
        const err = capturePeer(peer);
        if (err) {
          req.destroy(err);
          fail(err);
        }
      });
    });

    req.setTimeout(params.timeoutMs, () => {
      req.destroy(new Error("Upstream core request timed out"));
    });

    req.on("error", (err) => {
      fail(err instanceof Error ? err : new Error(String(err)));
    });

    req.end();
  });
}

/**
 * Performs a strictly pinned HTTPS request using the attested `https.Agent`,
 * `ca: [tlsCertPem]`, `rejectUnauthorized: true`, and `checkServerIdentity`
 * enforcing `peerSpkiSha256 === pinnedSpkiSha256`.
 *
 * Also re-verifies the peer certificate on keep-alive socket reuse before any
 * request body bytes are written.
 */
function httpsRequestPinned(params: {
  host: string;
  port: number;
  path: string;
  method: "GET" | "POST";
  body?: Buffer;
  tlsCertPem: string;
  pinnedSpkiSha256: string;
  agent: https.Agent;
  timeoutMs: number;
  maxResponseBytes: number;
}): Promise<RawHttpsResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let peerVerified = false;
    let capturedPeerDer: Buffer | null = null;
    let capturedPeerPem: string | null = null;
    let capturedPeerSpkiSha256: string | null = null;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const checkIdentity = createSpkiPinCheckServerIdentity(params.pinnedSpkiSha256);

    const verifyAndCapturePeer = (cert: PeerCertificate | undefined | null): Error | undefined => {
      const identityErr = checkIdentity(params.host, cert as PeerCertificate);
      if (identityErr) {
        return identityErr;
      }
      const x509Cert = new crypto.X509Certificate(cert!.raw);
      capturedPeerDer = Buffer.from(cert!.raw);
      capturedPeerPem = x509Cert.toString().trim();
      capturedPeerSpkiSha256 = params.pinnedSpkiSha256.toLowerCase();
      peerVerified = true;
      return undefined;
    };

    const reqHeaders: Record<string, string> = {
      Accept: "application/json",
    };

    if (params.method === "POST" && params.body) {
      reqHeaders["Content-Type"] = "application/json; charset=utf-8";
      reqHeaders["Content-Length"] = String(params.body.byteLength);
    }

    const req = https.request(
      {
        host: params.host,
        port: params.port,
        path: params.path,
        method: params.method,
        headers: reqHeaders,
        ca: [params.tlsCertPem],
        rejectUnauthorized: true,
        agent: params.agent,
        checkServerIdentity: (_servername: string, cert: PeerCertificate) => {
          const err = verifyAndCapturePeer(cert);
          if (err) {
            return err;
          }
          return undefined;
        },
      },
      (res) => {
        const tlsSocket = res.socket as TLSSocket;
        if (!peerVerified || !tlsSocket.authorized) {
          const peer = tlsSocket.getPeerCertificate?.(false);
          const verifyErr =
            verifyAndCapturePeer(peer) ??
            (!tlsSocket.authorized
              ? new Error(
                  `TLS SPKI pin mismatch: unauthorized TLS socket (${String(tlsSocket.authorizationError ?? "untrusted")})`,
                )
              : undefined);
          if (verifyErr) {
            res.destroy();
            req.destroy(verifyErr);
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
            peerCertPem: capturedPeerPem!,
            peerSpkiSha256: capturedPeerSpkiSha256!,
          });
        });
      },
    );

    req.on("socket", (socket: Socket) => {
      const tlsSocket = socket as TLSSocket;
      const onReady = () => {
        if (settled) return;
        if (!tlsSocket.authorized) {
          const authErr = new Error(
            `TLS SPKI pin mismatch: peer certificate rejected by CA pin (${String(tlsSocket.authorizationError ?? "unauthorized")})`,
          );
          req.destroy(authErr);
          fail(authErr);
          return;
        }
        const peer = tlsSocket.getPeerCertificate?.(false);
        const verifyErr = verifyAndCapturePeer(peer);
        if (verifyErr) {
          req.destroy(verifyErr);
          fail(verifyErr);
          return;
        }
        if (params.method === "POST" && params.body) {
          req.write(params.body);
        }
        req.end();
      };

      if (tlsSocket.connecting) {
        tlsSocket.once("secureConnect", onReady);
      } else {
        // Keep-alive socket reuse: re-verify pin before writing any request bytes
        onReady();
      }
    });

    req.setTimeout(params.timeoutMs, () => {
      req.destroy(new Error("Upstream core request timed out"));
    });

    req.on("error", (err) => {
      fail(err instanceof Error ? err : new Error(String(err)));
    });
  });
}

function isTlsPinOrCertError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message.toLowerCase();
  const code = String((err as NodeJS.ErrnoException).code ?? "").toUpperCase();
  if (msg.includes("spki pin mismatch") || msg.includes("certificate")) {
    return true;
  }
  return (
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "UNABLE_TO_GET_ISSUER_CERT" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "CERT_NOT_YET_VALID" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "INVALID_CA"
  );
}

/**
 * Fetches `/attestation` from the Confidential Space VM, verifies it with G4,
 * ensures the TLS peer certificate PEM and SPKI match the attested `tlsSpkiSha256`,
 * creates a dedicated pinned `https.Agent`, and caches the verified entry until
 * 5 minutes before `exp`.
 */
export async function ensureVerifiedCoreAttestation(
  target: { host: string; port: number },
  config: CoreProxyConfig = {},
): Promise<
  | { ok: true; attested: CachedCoreAttestation }
  | { ok: false; status: number; body: Record<string, unknown> }
> {
  const nowSec = config.nowSec ? config.nowSec() : Math.floor(Date.now() / 1000);
  const expectedAudience = config.expectedAudience ?? DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE;
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

  if (
    cachedAttestation &&
    cachedAttestation.host === target.host &&
    cachedAttestation.port === target.port &&
    cachedAttestation.expectedAudience === expectedAudience &&
    expectedDigests.includes(cachedAttestation.verification.imageDigest ?? "") &&
    nowSec < cachedAttestation.cacheUntilSec &&
    nowSec < cachedAttestation.expiresAtSec
  ) {
    return { ok: true, attested: cachedAttestation };
  }

  const timeoutMs = config.timeoutMs ?? CORE_REQUEST_TIMEOUT_MS;
  const maxResponseBytes = config.maxResponseBodyBytes ?? MAX_CORE_RESPONSE_BODY_BYTES;

  let attRes: RawHttpsResponse;
  try {
    attRes = await httpsFetchUnpinnedAttestation({
      host: target.host,
      port: target.port,
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
    const parsed = JSON.parse(attRes.body.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Attestation payload is not a JSON object");
    }
    parsedAtt = parsed as Record<string, unknown>;
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

  const token = typeof parsedAtt.token === "string" ? parsedAtt.token.trim() : "";
  const keysObj =
    parsedAtt.keys && typeof parsedAtt.keys === "object" && !Array.isArray(parsedAtt.keys)
      ? (parsedAtt.keys as Record<string, unknown>)
      : null;
  const egressKey = typeof keysObj?.egress === "string" ? keysObj.egress.trim().toLowerCase() : "";
  const treeKey = typeof keysObj?.tree === "string" ? keysObj.tree.trim().toLowerCase() : "";
  const servedKeysDigest =
    typeof parsedAtt.keysDigest === "string" ? parsedAtt.keysDigest.trim().toLowerCase() : "";
  const servedTlsSpkiSha256 =
    typeof parsedAtt.tlsSpkiSha256 === "string"
      ? parsedAtt.tlsSpkiSha256.trim().toLowerCase()
      : "";
  const servedTlsCertPemRaw =
    typeof parsedAtt.tlsCertPem === "string" ? parsedAtt.tlsCertPem.trim() : "";
  const refreshedAtSec =
    typeof parsedAtt.refreshedAtSec === "number" && Number.isFinite(parsedAtt.refreshedAtSec)
      ? Math.floor(parsedAtt.refreshedAtSec)
      : nowSec;

  if (
    !token ||
    !egressKey ||
    !treeKey ||
    !servedKeysDigest ||
    !servedTlsSpkiSha256 ||
    !servedTlsCertPemRaw
  ) {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "incomplete_attestation_payload",
        message:
          "Workload /attestation response is missing token, keys, keysDigest, tlsSpkiSha256, or tlsCertPem.",
      },
    };
  }

  let canonicalTlsCertPem: string;
  let certPemSpkiSha256: string;
  try {
    const parsedX509 = new crypto.X509Certificate(servedTlsCertPemRaw);
    if (!parsedX509.raw.equals(attRes.peerCertDer)) {
      return {
        ok: false,
        status: 502,
        body: {
          ok: false,
          error: "tls_cert_mismatch",
          message:
            "TLS peer certificate presented during handshake does not match /attestation tlsCertPem.",
        },
      };
    }
    canonicalTlsCertPem = parsedX509.toString().trim();
    const spkiDer = parsedX509.publicKey.export({ type: "spki", format: "der" });
    certPemSpkiSha256 = crypto.createHash("sha256").update(spkiDer).digest("hex").toLowerCase();
  } catch {
    return {
      ok: false,
      status: 502,
      body: {
        ok: false,
        error: "invalid_tls_cert_pem",
        message: "Workload /attestation returned an invalid X.509 tlsCertPem.",
      },
    };
  }

  // Verify that the TLS certificate SPKI matches both the handshake peer and servedTlsSpkiSha256
  if (
    servedTlsSpkiSha256 !== attRes.peerSpkiSha256 ||
    certPemSpkiSha256 !== attRes.peerSpkiSha256
  ) {
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
    tlsCertificatePemOrDer: canonicalTlsCertPem,
    tlsSpkiSha256: servedTlsSpkiSha256,
    expectedAudience,
    expectedImageDigests: expectedDigests,
    allowedEnvOverrides: config.allowedEnvOverrides ?? DEFAULT_ALLOWED_ENV_OVERRIDES,
    pinnedRootCaPem: config.pinnedRootCaPem,
    nowSec,
  });

  if (
    !verification.ok ||
    verification.expiresAtSec === null ||
    verification.expiresAtSec <= nowSec ||
    !verification.tlsSpkiDigest ||
    !verification.keysDigest ||
    verification.tlsSpkiDigest !== servedTlsSpkiSha256 ||
    verification.keysDigest !== servedKeysDigest ||
    verification.keysDigest === verification.tlsSpkiDigest
  ) {
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

  // If an older cached attestation exists, check if it shares the exact same pin & cert;
  // otherwise destroy the old https.Agent so all old keep-alive sockets are dropped immediately.
  let agent: https.Agent;
  if (
    cachedAttestation &&
    cachedAttestation.host === target.host &&
    cachedAttestation.port === target.port &&
    cachedAttestation.tlsSpkiSha256 === verification.tlsSpkiDigest &&
    cachedAttestation.tlsCertPem === canonicalTlsCertPem
  ) {
    agent = cachedAttestation.agent;
  } else {
    if (cachedAttestation) {
      try {
        cachedAttestation.agent.destroy();
      } catch {
        // ignore
      }
    }
    agent = createPinnedHttpsAgent(canonicalTlsCertPem, verification.tlsSpkiDigest);
  }

  const cacheUntilSec = Math.max(
    nowSec,
    verification.expiresAtSec - ATTESTATION_CACHE_SAFETY_MARGIN_SEC,
  );

  const entry: CachedCoreAttestation = {
    host: target.host,
    port: target.port,
    expectedAudience,
    tlsSpkiSha256: verification.tlsSpkiDigest,
    tlsCertPem: canonicalTlsCertPem,
    keysDigest: verification.keysDigest,
    keys: {
      egress: egressKey,
      tree: treeKey,
    },
    token,
    expiresAtSec: verification.expiresAtSec,
    refreshedAtSec,
    cacheUntilSec,
    verification,
    agent,
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
 * after verifying the Confidential Space attestation and pinning TLS to `tlsCertPem` + `tlsSpkiSha256`.
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

  // 1. Validate URL and reject encoded path characters or query parameters
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

  if (parsedReqUrl.pathname.includes("%")) {
    return {
      status: 404,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: "path_not_allowed",
        message: "Percent-encoded path characters are not permitted on deroute-core proxy endpoints.",
      }),
    };
  }

  // 2. Validate path against allowlist
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

  // 3. Reject query parameters on all core endpoints
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

  // 4. Enforce HTTP method per path
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

  // 5. Resolve CORE_HOST; if unset return 503 { core: "not-deployed" }
  const rawCoreHost = config.coreHost !== undefined ? config.coreHost : process.env.CORE_HOST;
  const target = parseCoreHost(rawCoreHost);
  if (!target) {
    return {
      status: 503,
      headers: defaultHeaders,
      body: JSON.stringify({ core: "not-deployed" }),
    };
  }

  // 6. Read and validate bounded POST body before contacting upstream
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

  // 7. Verify /attestation (or use cached attestation valid until exp - 5 min)
  const attStatus = await ensureVerifiedCoreAttestation(target, config);
  if (!attStatus.ok) {
    return {
      status: attStatus.status,
      headers: defaultHeaders,
      body: JSON.stringify(attStatus.body),
    };
  }

  const attested = attStatus.attested;

  // If the caller requested `/attestation`, return ONLY the explicitly verified fields + G4 verification summary
  if (pathCheck.path === "attestation") {
    return {
      status: 200,
      headers: {
        ...defaultHeaders,
        "X-DeRoute-Attested-HwModel": String(attested.verification.hwmodel ?? ""),
        "X-DeRoute-Attested-Image": String(attested.verification.imageDigest ?? ""),
      },
      body: JSON.stringify({
        token: attested.token,
        keys: attested.keys,
        keysDigest: attested.keysDigest,
        tlsSpkiSha256: attested.tlsSpkiSha256,
        tlsCertPem: attested.tlsCertPem,
        expiresAtSec: attested.expiresAtSec,
        refreshedAtSec: attested.refreshedAtSec,
        verification: attested.verification,
      }),
    };
  }

  // 8. Forward request over TLS pinned to `attested.tlsCertPem` + `attested.tlsSpkiSha256`
  const timeoutMs = config.timeoutMs ?? CORE_REQUEST_TIMEOUT_MS;
  const maxResBytes = config.maxResponseBodyBytes ?? MAX_CORE_RESPONSE_BODY_BYTES;

  let upstreamRes: RawHttpsResponse;
  try {
    upstreamRes = await httpsRequestPinned({
      host: target.host,
      port: target.port,
      path: `/${pathCheck.path}`,
      method: pathCheck.allowedMethod,
      body: postBody,
      tlsCertPem: attested.tlsCertPem,
      pinnedSpkiSha256: attested.tlsSpkiSha256,
      agent: attested.agent,
      timeoutMs,
      maxResponseBytes: maxResBytes,
    });
  } catch (err) {
    // Invalidate cache and destroy pinned agent if TLS pin or connection failed
    clearCoreAttestationCache();
    const isPinError = isTlsPinOrCertError(err);
    return {
      status: 502,
      headers: defaultHeaders,
      body: JSON.stringify({
        ok: false,
        error: isPinError ? "tls_spki_pin_mismatch" : "upstream_request_failed",
        message: isPinError
          ? "Upstream TLS certificate or SPKI did not match the attested enclave key."
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
