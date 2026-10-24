import { describe, expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  OHTTP_AEAD_ID_AES_256_GCM,
  OHTTP_HEADER_LENGTH,
  OHTTP_KDF_ID_HKDF_SHA256,
  OHTTP_KEM_ID_X25519_HKDF_SHA256,
  OHTTP_RESPONSE_NONCE_LENGTH,
  OHTTP_X25519_PUBLIC_KEY_LENGTH,
  bytesToHex,
   decapsulateOhttpRequest,
  decapsulateOhttpResponse,
  decodeOhttpKeyConfig,
  encapsulateOhttpRequest,
  encapsulateOhttpResponse,
  encodeOhttpKeyConfig,
  getDefaultOhttpGatewayKeypair,
  runOhttpSelfTest,
} from "@/lib/ohttp/rfc9458";

describe("RFC 9458 Oblivious HTTP (OHTTP) Binary KeyConfig & Framing", () => {
  it("encodes and decodes an RFC 9458 KeyConfig binary structure round-trip", () => {
    const gatewayKeys = x25519.keygen();
    const encoded = encodeOhttpKeyConfig({
      keyId: 7,
      publicKey: gatewayKeys.publicKey,
    });

    // 1B keyId + 2B kemId + 32B pubKey + 2B symAlgLen + 2B kdfId + 2B aeadId = 41 bytes
    expect(encoded.byteLength).toBe(41);
    expect(encoded[0]).toBe(7);
    expect((encoded[1] << 8) | encoded[2]).toBe(OHTTP_KEM_ID_X25519_HKDF_SHA256);

    const decoded = decodeOhttpKeyConfig(encoded);
    expect(decoded.keyId).toBe(7);
    expect(decoded.kemId).toBe(OHTTP_KEM_ID_X25519_HKDF_SHA256);
    expect(decoded.kdfId).toBe(OHTTP_KDF_ID_HKDF_SHA256);
    expect(decoded.aeadId).toBe(OHTTP_AEAD_ID_AES_256_GCM);
    expect(bytesToHex(decoded.publicKey)).toBe(bytesToHex(gatewayKeys.publicKey));
    expect(decoded.symmetricAlgorithms).toEqual([
      {
        kdfId: OHTTP_KDF_ID_HKDF_SHA256,
        aeadId: OHTTP_AEAD_ID_AES_256_GCM,
      },
    ]);
  });

  it("performs a full RFC 9458 request encapsulation -> gateway decapsulation -> response encapsulation -> client decapsulation round-trip", () => {
    const gateway = getDefaultOhttpGatewayKeypair(3);
    const decodedKeyConfig = decodeOhttpKeyConfig(gateway.keyConfigBytes);

    const requestPayload = JSON.stringify({
      method: "POST",
      path: "/v1/chat/completions",
      headers: {
        "content-type": "application/json",
        "x-ohttp-client": "blinded-relay-hop",
      },
      body: {
        model: "llama-3.3-70b-instruct",
        messages: [{ role: "user", content: "Hello over RFC 9458 Oblivious HTTP" }],
      },
    });

    const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
      requestPayload,
      decodedKeyConfig.publicKey,
      decodedKeyConfig.keyId
    );

    // Verify 7-byte RFC 9458 header [keyId(1), kemId(2), kdfId(2), aeadId(2)]
    expect(encapsulatedRequest[0]).toBe(3);
    expect((encapsulatedRequest[1] << 8) | encapsulatedRequest[2]).toBe(
      OHTTP_KEM_ID_X25519_HKDF_SHA256
    );
    expect((encapsulatedRequest[3] << 8) | encapsulatedRequest[4]).toBe(
      OHTTP_KDF_ID_HKDF_SHA256
    );
    expect((encapsulatedRequest[5] << 8) | encapsulatedRequest[6]).toBe(
      OHTTP_AEAD_ID_AES_256_GCM
    );
    expect(clientContext.enc.byteLength).toBe(OHTTP_X25519_PUBLIC_KEY_LENGTH);

    // Target Gateway decapsulates the request
    const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
      encapsulatedRequest,
      gateway.privateKey
    );
    expect(plaintextHttpJson).toBe(requestPayload);
    expect(serverContext.keyId).toBe(3);
    expect(bytesToHex(serverContext.sharedSecret)).toBe(
      bytesToHex(clientContext.sharedSecret)
    );

    // Target Gateway encapsulates the response
    const responsePayload = JSON.stringify({
      status: 200,
      headers: { "content-type": "application/json" },
      body: {
        id: "chatcmpl-ohttp-9458",
        choices: [{ message: { role: "assistant", content: "Oblivious response OK." } }],
      },
    });

    const encapsulatedResponse = encapsulateOhttpResponse(
      responsePayload,
      serverContext
    );
    expect(encapsulatedResponse.byteLength).toBeGreaterThan(
      OHTTP_RESPONSE_NONCE_LENGTH + 16
    );

    // Client decapsulates the response
    const decapsulatedResponse = decapsulateOhttpResponse(
      encapsulatedResponse,
      clientContext
    );
    expect(decapsulatedResponse).toBe(responsePayload);
  });

  it("rejects tampered headers, wrong gateway private key, and modified request/response ciphertexts", () => {
    const gateway = getDefaultOhttpGatewayKeypair(1);
    const wrongGateway = x25519.keygen();

    const plaintext = JSON.stringify({ method: "GET", path: "/v1/models" });
    const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
      plaintext,
      gateway.publicKey,
      gateway.keyId
    );

    // 1. Tampered keyId in 7-byte header (bound via HKDF info + GCM AAD)
    const tamperedKeyIdReq = new Uint8Array(encapsulatedRequest);
    tamperedKeyIdReq[0] ^= 0x01;
    expect(() =>
      decapsulateOhttpRequest(tamperedKeyIdReq, gateway.privateKey)
    ).toThrow();

    // 2. Tampered KEM ID in 7-byte header
    const tamperedKemReq = new Uint8Array(encapsulatedRequest);
    tamperedKemReq[2] ^= 0x01;
    expect(() =>
      decapsulateOhttpRequest(tamperedKemReq, gateway.privateKey)
    ).toThrow(/KEM ID/i);

    // 3. Wrong gateway private key
    expect(() =>
      decapsulateOhttpRequest(encapsulatedRequest, wrongGateway.secretKey)
    ).toThrow();

    // 4. Modified request ciphertext byte
    const tamperedCiphertextReq = new Uint8Array(encapsulatedRequest);
    tamperedCiphertextReq[tamperedCiphertextReq.length - 1] ^= 0xff;
    expect(() =>
      decapsulateOhttpRequest(tamperedCiphertextReq, gateway.privateKey)
    ).toThrow();

    // 5. Modified response ciphertext or responseNonce
    const { serverContext } = decapsulateOhttpRequest(
      encapsulatedRequest,
      gateway.privateKey
    );
    const encapsulatedResponse = encapsulateOhttpResponse(
      JSON.stringify({ status: 200 }),
      serverContext
    );

    const tamperedResponseCiphertext = new Uint8Array(encapsulatedResponse);
    tamperedResponseCiphertext[tamperedResponseCiphertext.length - 1] ^= 0xff;
    expect(() =>
      decapsulateOhttpResponse(tamperedResponseCiphertext, clientContext)
    ).toThrow();

    const tamperedResponseNonce = new Uint8Array(encapsulatedResponse);
    tamperedResponseNonce[0] ^= 0x80;
    expect(() =>
      decapsulateOhttpResponse(tamperedResponseNonce, clientContext)
    ).toThrow();

    // 6. Verify live self-test helper
    const selfTest = runOhttpSelfTest();
    expect(selfTest.roundTripVerified).toBe(true);
    expect(selfTest.encapsulatedRequestByteLength).toBeGreaterThan(
      OHTTP_HEADER_LENGTH + OHTTP_X25519_PUBLIC_KEY_LENGTH + 16
    );
  });

  it("decapsulates and encapsulates via POST /api/ohttp route handler", async () => {
    const { POST } = await import("@/app/api/ohttp/route");
    const { NextRequest } = await import("next/server");

    const gateway = getDefaultOhttpGatewayKeypair(1);
    const plaintextRequest = JSON.stringify({
      method: "POST",
      path: "/v1/chat/completions",
      body: { model: "qwen-2.5-72b", prompt: "OHTTP route test" },
    });

    const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
      plaintextRequest,
      gateway.publicKey,
      gateway.keyId
    );

    const req = new NextRequest("http://localhost:3000/api/ohttp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        encapsulatedRequestHex: bytesToHex(encapsulatedRequest),
      }),
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      encapsulatedResponseHex: string;
      keyId: number;
    };
    expect(typeof data.encapsulatedResponseHex).toBe("string");
    expect(data.keyId).toBe(1);

    const { hexToBytes } = await import("@/lib/ohttp/rfc9458");
    const decapsulatedJson = decapsulateOhttpResponse(
      hexToBytes(data.encapsulatedResponseHex),
      clientContext
    );
    const parsedResponse = JSON.parse(decapsulatedJson) as {
      status: number;
      decapsulatedRequest: { path: string };
    };
    expect(parsedResponse.status).toBe(200);
    expect(parsedResponse.decapsulatedRequest.path).toBe("/v1/chat/completions");
  });
});
