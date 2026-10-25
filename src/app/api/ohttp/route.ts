import { NextRequest, NextResponse, connection } from "next/server";
import {
  OHTTP_ALLOWED_INTERNAL_TARGETS,
  OHTTP_SAME_OPERATOR_DISCLOSURE,
  bytesToHex,
  decapsulateOhttpRequest,
  encapsulateOhttpResponse,
  getDefaultOhttpGatewayKeypair,
  hexToBytes,
  resolveAllowlistedOhttpTarget,
  runOhttpSelfTest,
} from "@/lib/ohttp/rfc9458";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedBytes,
  readBoundedJson,
} from "@/lib/ratelimit";
import { POST as chatCompletionsPost } from "@/app/api/v1/chat/completions/route";
import { GET as modelsGet } from "@/app/api/v1/models/route";
import { GET as verifyGet } from "@/app/api/v1/verify/route";

const MAX_OHTTP_BODY_BYTES = 65_536;
const MAX_OHTTP_HEX_LEN = 65_536;

const ohttpLimiter = createTokenBucketLimiter({
  name: "ohttp-route",
  capacity: 60,
  refillPerSec: 2,
});

interface InnerOhttpRequestEnvelope {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: unknown;
}

function wantsBinaryOhttpKeys(request?: NextRequest | Request): boolean {
  if (!request) return false;
  try {
    const accept = (request.headers.get("accept") ?? "").toLowerCase();
    if (accept.includes("application/ohttp-keys")) {
      return true;
    }
    const url = new URL(request.url);
    const format = (url.searchParams.get("format") ?? "").toLowerCase();
    if (format === "raw" || format === "binary" || format === "ohttp-keys") {
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

function isBinaryOhttpRequest(request: NextRequest | Request): boolean {
  const ct = (request.headers.get("content-type") ?? "").toLowerCase();
  return ct.includes("message/ohttp-req") || ct.includes("application/octet-stream");
}

function wantsBinaryOhttpResponse(request: NextRequest | Request, inputWasBinary: boolean): boolean {
  if (inputWasBinary) return true;
  const accept = (request.headers.get("accept") ?? "").toLowerCase();
  return accept.includes("message/ohttp-res");
}

async function dispatchAllowlistedInternalTarget(
  inner: InnerOhttpRequestEnvelope,
): Promise<{
  status: number;
  headers: Record<string, string>;
  body: unknown;
  forwardedTo: string | null;
}> {
  const rawMethod = (inner.method ?? "POST").toUpperCase();
  const rawPath = typeof inner.path === "string" ? inner.path : "/api/v1/chat/completions";
  const target = resolveAllowlistedOhttpTarget(rawPath);

  if (!target.allowed || !target.canonicalPath) {
    return {
      status: 403,
      headers: {
        "content-type": "application/json",
        "x-ohttp-gateway": "rfc9458-target-gateway",
      },
      body: {
        error: target.reason ?? "Target path is not allowlisted",
        allowedTargets: OHTTP_ALLOWED_INTERNAL_TARGETS,
      },
      forwardedTo: null,
    };
  }

  // Forward only safe inner headers; strip any client-identifying headers
  const safeHeaders = new Headers({
    "content-type": "application/json",
    "x-ohttp-gateway-forwarded": "1",
  });
  if (inner.headers && typeof inner.headers === "object") {
    for (const [k, v] of Object.entries(inner.headers)) {
      const lower = k.toLowerCase();
      if (
        lower === "authorization" ||
        lower === "x-drouter-credit" ||
        lower === "x-drouter-credit-token" ||
        lower === "x-tinfoil-model"
      ) {
        safeHeaders.set(k, String(v));
      }
    }
  }

  const internalUrl = `http://ohttp-gateway.drouter.internal${target.canonicalPath}`;

    if (target.canonicalPath === "/api/v1/models") {
    if (rawMethod !== "GET") {
      return {
        status: 405,
        headers: { "content-type": "application/json" },
        body: { error: "Only GET is allowed for /api/v1/models" },
        forwardedTo: target.canonicalPath,
      };
    }
    const res = await modelsGet(new Request(internalUrl, { method: "GET", headers: safeHeaders }));
    const data = await res.json().catch(() => null);
    return {
      status: res.status,
      headers: {
        "content-type": "application/json",
        "x-ohttp-gateway": "rfc9458-target-gateway",
        "x-ohttp-target": target.canonicalPath,
      },
      body: data,
      forwardedTo: target.canonicalPath,
    };
  }

  if (target.canonicalPath === "/api/v1/verify") {
    if (rawMethod !== "GET") {
      return {
        status: 405,
        headers: { "content-type": "application/json" },
        body: { error: "Only GET is allowed for /api/v1/verify" },
        forwardedTo: target.canonicalPath,
      };
    }
    const res = await verifyGet(new Request(internalUrl, { method: "GET", headers: safeHeaders }));
    const data = await res.json().catch(() => null);
    return {
      status: res.status,
      headers: {
        "content-type": "application/json",
        "x-ohttp-gateway": "rfc9458-target-gateway",
        "x-ohttp-target": target.canonicalPath,
      },
      body: data,
      forwardedTo: target.canonicalPath,
    };
  }

  // Default allowlisted target: /api/v1/chat/completions
  if (rawMethod !== "POST") {
    return {
      status: 405,
      headers: { "content-type": "application/json" },
      body: { error: "Only POST is allowed for /api/v1/chat/completions" },
      forwardedTo: target.canonicalPath,
    };
  }

  // Only forward when inner body is a valid chat completions request object with messages;
  // if the inner body is a minimal echo/probe payload without messages, return 200 with the
  // decapsulated metadata and target validation status unless messages are provided.
  const rawInnerBody = inner.body;
  const hasMessages =
    rawInnerBody &&
    typeof rawInnerBody === "object" &&
    !Array.isArray(rawInnerBody) &&
    Array.isArray((rawInnerBody as { messages?: unknown }).messages) &&
    ((rawInnerBody as { messages: unknown[] }).messages.length > 0);

  if (hasMessages) {
    const bodyObj = {
      ...(rawInnerBody as Record<string, unknown>),
      // OHTTP responses are framed as single binary responses, so force non-streaming inner execution
      stream: false,
    };
    const internalReq = new Request(internalUrl, {
      method: "POST",
      headers: safeHeaders,
      body: JSON.stringify(bodyObj),
    });
    const res = await chatCompletionsPost(internalReq);
    const data = await res.json().catch(() => null);
    return {
      status: res.status,
      headers: {
        "content-type": "application/json",
        "x-ohttp-gateway": "rfc9458-target-gateway",
        "x-ohttp-target": target.canonicalPath,
        ...(res.headers.get("x-drouter-attested")
          ? { "x-drouter-attested": res.headers.get("x-drouter-attested")! }
          : {}),
        ...(res.headers.get("x-drouter-redactions")
          ? { "x-drouter-redactions": res.headers.get("x-drouter-redactions")! }
          : {}),
      },
      body: data,
      forwardedTo: target.canonicalPath,
    };
  }

  return {
    status: 200,
    headers: {
      "content-type": "application/json",
      "x-ohttp-gateway": "rfc9458-target-gateway",
      "x-ohttp-target": target.canonicalPath,
    },
    body: {
      ohttp: "rfc9458-gateway-forwarded",
      target: target.canonicalPath,
      note: "Inner request did not include a messages[] array for inference execution; decapsulated envelope verified.",
    },
    forwardedTo: target.canonicalPath,
  };
}

/**
 * RFC 9458 Oblivious HTTP Target Gateway & KeyConfig Endpoint.
 * - GET returns raw `application/ohttp-keys` binary KeyConfig when requested via `Accept: application/ohttp-keys`
 *   or `?format=raw`, and returns JSON metadata (including `keyConfigHex` and operator disclosure) by default.
 * - POST accepts either binary `message/ohttp-req` or JSON `{ encapsulatedRequestHex }`, decapsulates with
 *   the server secret-derived X25519 gateway key, forwards the inner request ONLY to allowlisted internal
 *   targets (`/api/v1/chat/completions`, `/api/v1/models`, `/api/v1/verify`), and encapsulates the response.
 */
export async function GET(request?: NextRequest) {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = ohttpLimiter.check(request);
    if (limited) return limited;
  }

  const gateway = getDefaultOhttpGatewayKeypair(1);

  if (wantsBinaryOhttpKeys(request)) {
    return new Response(Buffer.from(gateway.keyConfigBytes), {
      status: 200,
      headers: {
        "Content-Type": "application/ohttp-keys",
        "Cache-Control": "public, max-age=3600",
        "X-OHTTP-Key-Id": String(gateway.keyId),
        "X-OHTTP-Operator-Model": "same-operator-unless-external-relay",
      },
    });
  }

  const selfTest = runOhttpSelfTest();

  return NextResponse.json(
    {
      protocol: "IETF RFC 9458 Oblivious HTTP (OHTTP)",
      contentTypePreview: "application/ohttp-keys",
      keyId: gateway.keyId,
      gatewayPublicKeyHex: bytesToHex(gateway.publicKey),
      keyConfigHex: gateway.keyConfigHex,
      allowedTargets: OHTTP_ALLOWED_INTERNAL_TARGETS,
      operatorDisclosure: OHTTP_SAME_OPERATOR_DISCLOSURE,
      selfTest,
    },
    {
      headers: {
        "X-OHTTP-Key-Config-Hex": gateway.keyConfigHex,
      },
    },
  );
}

export async function POST(request: NextRequest) {
  const limited = ohttpLimiter.check(request);
  if (limited) return limited;

  try {
    const binaryInput = isBinaryOhttpRequest(request);
    let encapsulatedRequest: Uint8Array;
    let requestedKeyId: number | undefined;

    if (binaryInput) {
      const rawBytes = await readBoundedBytes(request, MAX_OHTTP_BODY_BYTES);
      if (rawBytes.byteLength === 0) {
        return NextResponse.json(
          { error: "Empty message/ohttp-req request body" },
          { status: 400 },
        );
      }
      encapsulatedRequest = rawBytes;
    } else {
      const body = await readBoundedJson<{
        encapsulatedRequestHex?: string;
        keyId?: number;
      }>(request, MAX_OHTTP_BODY_BYTES);

      if (
        !body ||
        typeof body.encapsulatedRequestHex !== "string" ||
        body.encapsulatedRequestHex.trim().length === 0
      ) {
        return NextResponse.json(
          { error: "Missing required field: encapsulatedRequestHex" },
          { status: 400 },
        );
      }

      const cleanHex = body.encapsulatedRequestHex.trim();
      if (
        cleanHex.length > MAX_OHTTP_HEX_LEN ||
        cleanHex.length % 2 !== 0 ||
        !/^[0-9a-fA-F]+$/.test(cleanHex)
      ) {
        return NextResponse.json(
          { error: "encapsulatedRequestHex must be valid even-length hex <= 65536 chars" },
          { status: 400 },
        );
      }

      encapsulatedRequest = hexToBytes(cleanHex);
      if (
        typeof body.keyId === "number" &&
        Number.isInteger(body.keyId) &&
        body.keyId >= 0 &&
        body.keyId <= 255
      ) {
        requestedKeyId = body.keyId;
      }
    }

    const keyId = requestedKeyId ?? encapsulatedRequest[0] ?? 1;
    // Snapshot the gateway keypair before inner dispatch so response encapsulation uses the exact key
    // even if an inner simulated route initializes a fallback env var during test execution.
    const gateway = getDefaultOhttpGatewayKeypair(keyId);

    const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
      encapsulatedRequest,
      gateway.privateKey,
    );

    let parsedPayload: unknown = plaintextHttpJson;
    let innerEnvelope: InnerOhttpRequestEnvelope = {
      method: "POST",
      path: "/api/v1/chat/completions",
    };

    try {
      const parsed = JSON.parse(plaintextHttpJson);
      parsedPayload = parsed;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const record = parsed as Record<string, unknown>;
        if (typeof record.path === "string" || typeof record.method === "string") {
          innerEnvelope = {
            method: typeof record.method === "string" ? record.method : "POST",
            path: typeof record.path === "string" ? record.path : "/api/v1/chat/completions",
            headers:
              record.headers && typeof record.headers === "object" && !Array.isArray(record.headers)
                ? (record.headers as Record<string, string>)
                : undefined,
            body: record.body,
          };
        } else if (Array.isArray(record.messages)) {
          // Direct OpenAI chat completion body sent inside OHTTP
          innerEnvelope = {
            method: "POST",
            path: "/api/v1/chat/completions",
            body: record,
          };
        }
      }
    } catch {
      parsedPayload = plaintextHttpJson;
    }

    const dispatched = await dispatchAllowlistedInternalTarget(innerEnvelope);

    const gatewayResponsePayload = JSON.stringify({
      status: dispatched.status,
      headers: dispatched.headers,
      body: dispatched.body,
      forwardedTo: dispatched.forwardedTo,
      operatorDisclosure: OHTTP_SAME_OPERATOR_DISCLOSURE,
      decapsulatedRequest: parsedPayload,
    });

    const encapsulatedResponse = encapsulateOhttpResponse(
      gatewayResponsePayload,
      serverContext,
    );

    if (wantsBinaryOhttpResponse(request, binaryInput)) {
      return new Response(Buffer.from(encapsulatedResponse), {
        status: 200,
        headers: {
          "Content-Type": "message/ohttp-res",
          "Cache-Control": "no-store",
          "X-OHTTP-Key-Id": String(serverContext.keyId),
        },
      });
    }

    return NextResponse.json({
      encapsulatedResponseHex: bytesToHex(encapsulatedResponse),
      keyId: serverContext.keyId,
      contentType: "message/ohttp-res",
      forwardedTo: dispatched.forwardedTo,
      innerStatus: dispatched.status,
      operatorDisclosure: OHTTP_SAME_OPERATOR_DISCLOSURE,
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    const message =
      err instanceof InvalidJsonBodyError
        ? err.message
        : err instanceof Error
          ? err.message
          : "OHTTP decapsulation failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
