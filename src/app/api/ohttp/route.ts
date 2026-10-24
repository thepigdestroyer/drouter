import { NextRequest, NextResponse, connection } from "next/server";
import {
  bytesToHex,
  decapsulateOhttpRequest,
  encapsulateOhttpResponse,
  getDefaultOhttpGatewayKeypair,
  hexToBytes,
  runOhttpSelfTest,
} from "@/lib/ohttp/rfc9458";

export async function GET() {
  await connection();

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
  try {
    const body = (await request.json()) as {
      encapsulatedRequestHex?: string;
      keyId?: number;
    };

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

    const encapsulatedRequest = hexToBytes(body.encapsulatedRequestHex.trim());
    const keyId = typeof body.keyId === "number" ? body.keyId : encapsulatedRequest[0] ?? 1;
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
    const message = err instanceof Error ? err.message : "OHTTP decapsulation failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
