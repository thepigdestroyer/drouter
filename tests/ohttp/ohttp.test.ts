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

  it("matches the IETF RFC 9458 Appendix A complete request and response test vector byte-for-byte", async () => {
    const {
      OHTTP_AEAD_ID_AES_128_GCM,
      OHTTP_AEAD_ID_CHACHA20_POLY1305,
      decapsulateOhttpResponseBytes,
      deriveResponseKeyAndNonce,
      hexToBytes,
    } = await import("@/lib/ohttp/rfc9458");

    // RFC 9458 Appendix A vectors
    const skR = hexToBytes("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
    const pkR = x25519.getPublicKey(skR);
    expect(bytesToHex(pkR)).toBe(
      "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155"
    );

    const expectedKeyConfigHex =
      "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003";
    const encodedKeyConfig = encodeOhttpKeyConfig({
      keyId: 1,
      publicKey: pkR,
      symmetricAlgorithms: [
        { kdfId: OHTTP_KDF_ID_HKDF_SHA256, aeadId: OHTTP_AEAD_ID_AES_128_GCM },
        { kdfId: OHTTP_KDF_ID_HKDF_SHA256, aeadId: OHTTP_AEAD_ID_CHACHA20_POLY1305 },
      ],
    });
    expect(bytesToHex(encodedKeyConfig)).toBe(expectedKeyConfigHex);

    const decodedKeyConfig = decodeOhttpKeyConfig(encodedKeyConfig);
    expect(decodedKeyConfig.keyId).toBe(1);
    expect(decodedKeyConfig.symmetricAlgorithms).toHaveLength(2);

    const bhttpRequest = hexToBytes("00034745540568747470730b6578616d706c652e636f6d012f");
    const skE = hexToBytes("bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73");
    const expectedEncHex = "4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472";
    const expectedInfoHex = "6d6573736167652f626874747020726571756573740001002000010001";
    const expectedEncapsulatedReqHex =
      "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525";

    const { encapsulatedRequest, clientContext, infoBytes } = encapsulateOhttpRequest(
      bhttpRequest,
      pkR,
      1,
      {
        aeadId: OHTTP_AEAD_ID_AES_128_GCM,
        ephemeralPrivateKey: skE,
      }
    );

    expect(bytesToHex(clientContext.enc)).toBe(expectedEncHex);
    expect(bytesToHex(infoBytes)).toBe(expectedInfoHex);
    expect(bytesToHex(encapsulatedRequest)).toBe(expectedEncapsulatedReqHex);

    // Gateway decapsulates the Appendix A request
    const { plaintextBytes, serverContext } = decapsulateOhttpRequest(
      encapsulatedRequest,
      skR
    );
    expect(bytesToHex(plaintextBytes)).toBe(bytesToHex(bhttpRequest));

    // Appendix A response derivation & encapsulation
    const bhttpResponse = hexToBytes("0140c8");
    const responseNonce = hexToBytes("c789e7151fcba46158ca84b04464910d");
    const derivedResp = deriveResponseKeyAndNonce(serverContext, responseNonce);

    expect(bytesToHex(derivedResp.exportedSecret)).toBe("62d87a6ba569ee81014c2641f52bea36");
    expect(bytesToHex(derivedResp.prk)).toBe(
      "979aaeae066cf211ab407b31ae49767f344e1501e475c84e8aff547cc5a683db"
    );
    expect(bytesToHex(derivedResp.key)).toBe("5d0172a080e428b16d298c4ea0db620d");
    expect(bytesToHex(derivedResp.nonce)).toBe("f6bf1aeb88d6df87007fa263");

    const encapsulatedResponse = encapsulateOhttpResponse(
      bhttpResponse,
      serverContext,
      responseNonce
    );
    expect(bytesToHex(encapsulatedResponse)).toBe(
      "c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd"
    );

    const decapsulatedRespBytes = decapsulateOhttpResponseBytes(
      encapsulatedResponse,
      clientContext
    );
    expect(bytesToHex(decapsulatedRespBytes)).toBe("0140c8");
  });

  it("handles boundary payload sizes (0B, 1B, 4095B, 4096B, 4097B, 1MB) and 200 randomized round-trips", () => {
    const gateway = getDefaultOhttpGatewayKeypair(9);
    const boundaryLengths = [0, 1, 4095, 4096, 4097, 1024 * 1024];

    for (const len of boundaryLengths) {
      const payload = "x".repeat(len);
      const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
        payload,
        gateway.publicKey,
        gateway.keyId
      );
      const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
        encapsulatedRequest,
        gateway.privateKey
      );
      expect(plaintextHttpJson.length).toBe(len);
      expect(plaintextHttpJson).toBe(payload);

      const encRes = encapsulateOhttpResponse(payload, serverContext);
      const decRes = decapsulateOhttpResponse(encRes, clientContext);
      expect(decRes.length).toBe(len);
    }

    for (let i = 0; i < 200; i++) {
      const msg = `ohttp-fuzz-${i}-${Math.imul(i + 1, 0x9e3779b1)}`;
      const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
        msg,
        gateway.publicKey,
        i % 256
      );
      const { plaintextHttpJson, serverContext } = decapsulateOhttpRequest(
        encapsulatedRequest,
        gateway.privateKey
      );
      expect(plaintextHttpJson).toBe(msg);
      const resp = encapsulateOhttpResponse(`ack:${msg}`, serverContext);
      expect(decapsulateOhttpResponse(resp, clientContext)).toBe(`ack:${msg}`);
    }
  });
});
