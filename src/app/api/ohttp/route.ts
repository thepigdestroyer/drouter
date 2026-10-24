import { NextRequest, NextResponse, connection } from "next/server";
import {
  bytesToHex,
  decapsulateOhttpRequest,
  encapsulateOhttpResponse,
  getDefaultOhttpGatewayKeypair,
  hexToBytes,
  runOhttpSelfTest,
} from "@/lib/ohttp/rfc9458";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_OHTTP_BODY_BYTES = 65_536;
const MAX_OHTTP_HEX_LEN = 65_536;

const ohttpLimiter = createTokenBucketLimiter({
  name: "ohttp-route",
  capacity: 60,
  refillPerSec: 2,
});

export async function GET(request?: NextRequest) {
  await connection();
  if (request) {
    const limited = ohttpLimiter.check(request);
    if (limited) return limited;
  }

  const gateway = getDefaultOhttpGatewayKeypair(1);
  const selfTest = runOhttpSelfTest();

  return NextResponse.json({
    protocol: "IETF RFC 9458 Oblivious HTTP (OHTTP)",
    contentTypePreview: "application/ohttp-keys",
    keyId: gateway.keyId,
    gatewayPublicKeyHex: bytesToHex(gateway.publicKey),
    keyConfigHex: gateway.keyConfigHex,
    selfTest,
  });
}

export async function POST(request: NextRequest) {
  const limited = ohttpLimiter.check(request);
  if (limited) return limited;

  try {
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
        { status: 400 }
      );
    }

    const cleanHex = body.encapsulatedRequestHex.trim();
    if (cleanHex.length > MAX_OHTTP_HEX_LEN || cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
      return NextResponse.json(
        { error: "encapsulatedRequestHex must be valid even-length hex <= 65536 chars" },
        { status: 400 },
      );
    }

    const encapsulatedRequest = hexToBytes(cleanHex);
    const keyId =
      typeof body.keyId === "number" && Number.isInteger(body.keyId) && body.keyId >= 0 && body.keyId <= 255
        ? body.keyId
        : encapsulatedRequest[0] ?? 1;
    const gateway = getDefaultOhttpGatewayKeypair(keyId);

    const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
      encapsulatedRequest,
      gateway.privateKey
    );

    let parsedPayload: unknown = plaintextHttpJson;
    try {
      parsedPayload = JSON.parse(plaintextHttpJson);
    } catch {
      parsedPayload = plaintextHttpJson;
    }

    const gatewayResponsePayload = JSON.stringify({
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-ohttp-gateway": "rfc9458-target-gateway",
      },
      decapsulatedRequest: parsedPayload,
    });

    const encapsulatedResponse = encapsulateOhttpResponse(
      gatewayResponsePayload,
      serverContext
    );

    return NextResponse.json({
      encapsulatedResponseHex: bytesToHex(encapsulatedResponse),
      keyId: serverContext.keyId,
      contentType: "message/ohttp-res",
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
