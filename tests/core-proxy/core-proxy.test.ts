import crypto from "node:crypto";
import https from "node:https";
import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
} from "@/lib/attestation/confidential-space";
import {
  clearCoreAttestationCache,
  getCachedCoreAttestation,
  proxyCoreRequest,
} from "@/lib/core-proxy";
import { GET, POST } from "@/app/api/core/[...path]/route";
import * as x509 from "@peculiar/x509";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

const TEST_NOW_SEC = 1_792_886_400;
const TEST_IMAGE_DIGEST =
  "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const TEST_KEYS = {
  egress: "aa".repeat(32),
  tree: "bb".repeat(32),
};

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(view)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function jsonToBase64Url(obj: unknown): string {
  return bytesToBase64Url(Buffer.from(JSON.stringify(obj), "utf8"));
}

async function generateSelfSignedEcdsaTlsPair(commonName: string): Promise<{
  certPem: string;
  keyPem: string;
  spkiSha256: string;
}> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });

  const webPriv = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    pkcs8Der,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const webPub = await globalThis.crypto.subtle.importKey(
    "spki",
    spkiDer,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${commonName}`,
    notBefore: new Date((TEST_NOW_SEC - 86_400) * 1000),
    notAfter: new Date((TEST_NOW_SEC + 86_400 * 365) * 1000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: { privateKey: webPriv, publicKey: webPub },
  });

  const certPem = cert.toString("pem");
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const spkiSha256 = await computeTlsCertSpkiSha256(certPem);
  return { certPem, keyPem, spkiSha256 };
}

interface ProxyTestFixture {
  rootCertPem: string;
  x5cChain: string[];
  leafPrivateKey: CryptoKey;
  tls1: { certPem: string; keyPem: string; spkiSha256: string };
  tls2: { certPem: string; keyPem: string; spkiSha256: string };
  keysDigest: string;
  validTokenForTls1: string;
}

let fixture: ProxyTestFixture;

async function generateRsaPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

beforeAll(async () => {
  const [rootKeys, interKeys, leafKeys, tls1, tls2] = await Promise.all([
    generateRsaPair(),
    generateRsaPair(),
    generateRsaPair(),
    generateSelfSignedEcdsaTlsPair("deroute-core-1.internal"),
    generateSelfSignedEcdsaTlsPair("deroute-core-mitm.internal"),
  ]);

  const notBefore = new Date((TEST_NOW_SEC - 86_400) * 1000);
  const notAfter = new Date((TEST_NOW_SEC + 86_400 * 365) * 1000);
  const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "11",
    name: "C=US, O=Google LLC, CN=Test CS Root CA",
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    keys: rootKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 2, true)],
  });

  const interCert = await x509.X509CertificateGenerator.create({
    serialNumber: "12",
    subject: "C=US, O=Google LLC, CN=Test CS Intermediate CA",
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: interKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  });

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: "13",
    subject: "C=US, O=Google LLC, CN=confidentialcomputing.googleapis.com",
    issuer: interCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: leafKeys.publicKey,
    signingKey: interKeys.privateKey,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
  });

  const x5cChain = [
    Buffer.from(leafCert.rawData).toString("base64"),
    Buffer.from(interCert.rawData).toString("base64"),
    Buffer.from(rootCert.rawData).toString("base64"),
  ];

  const keysDigest = await computeAttestedKeysDigest(TEST_KEYS);

  const header = { alg: "RS256", typ: "JWT", x5c: x5cChain };
  const payload = {
    iss: EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
    aud: DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    iat: TEST_NOW_SEC - 30,
    nbf: TEST_NOW_SEC - 30,
    exp: TEST_NOW_SEC + 3600,
    swname: "CONFIDENTIAL_SPACE",
    dbgstat: "disabled-since-boot",
    secboot: true,
    hwmodel: "GCP_AMD_SEV",
    eat_nonce: [keysDigest, tls1.spkiSha256],
    submods: {
      confidential_space: {
        support_attributes: ["LATEST", "STABLE", "USABLE"],
      },
      container: {
        image_digest: TEST_IMAGE_DIGEST,
        env_override: {
          CORE_KEY_SOURCE: "boot",
        },
      },
    },
  };

  const h = jsonToBase64Url(header);
  const p = jsonToBase64Url(payload);
  const sig = await globalThis.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    leafKeys.privateKey,
    new TextEncoder().encode(`${h}.${p}`),
  );
  const validTokenForTls1 = `${h}.${p}.${bytesToBase64Url(sig)}`;

  fixture = {
    rootCertPem: rootCert.toString("pem"),
    x5cChain,
    leafPrivateKey: leafKeys.privateKey,
    tls1,
    tls2,
    keysDigest,
    validTokenForTls1,
  };
});

afterEach(() => {
  clearCoreAttestationCache();
  delete process.env.CORE_HOST;
  delete process.env.CORE_IMAGE_DIGESTS;
});

describe("Confidential Space Core Proxy (G5)", () => {
  it("returns 503 { core: 'not-deployed' } when CORE_HOST is unset and never returns fake data", async () => {
    delete process.env.CORE_HOST;
    const req = new Request("https://drouter-demo.vercel.app/api/core/health", {
      method: "GET",
    });
    const res = await GET(req, { params: Promise.resolve({ path: ["health"] }) });
    expect(res.status).toBe(503);
    const json = await res.json();
    expect(json).toEqual({ core: "not-deployed" });
  });

  it("enforces the strict path and method allowlist before making any upstream calls", async () => {
    // Disallowed path: transparency/sign-tree-head or arbitrary path
    for (const badPath of [
      ["transparency", "sign-tree-head"],
      ["admin", "secrets"],
      [".."],
      ["health", "extra"],
    ]) {
      const req = new Request(`https://drouter-demo.vercel.app/api/core/${badPath.join("/")}`, {
        method: "GET",
      });
      const res = await GET(req, { params: Promise.resolve({ path: badPath }) });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toBe("path_not_allowed");
    }

    // Wrong HTTP method on allowlisted path
    const postHealth = new Request("https://drouter-demo.vercel.app/api/core/health", {
      method: "POST",
      body: JSON.stringify({}),
    });
    const resPostHealth = await POST(postHealth, {
      params: Promise.resolve({ path: ["health"] }),
    });
    expect(resPostHealth.status).toBe(405);

    const getPlan = new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
      method: "GET",
    });
    const resGetPlan = await GET(getPlan, {
      params: Promise.resolve({ path: ["agent", "plan"] }),
    });
    expect(resGetPlan.status).toBe(405);

    // Query parameters forbidden
    const queryReq = new Request(
      "https://drouter-demo.vercel.app/api/core/knowledge/corpus?topic=tdx",
      { method: "GET" },
    );
    const resQuery = await GET(queryReq, {
      params: Promise.resolve({ path: ["knowledge", "corpus"] }),
    });
    expect(resQuery.status).toBe(400);
  });

  it("verifies /attestation, pins TLS to tlsSpkiSha256, caches attestation, and strips IP/cookie/user-agent headers", async () => {
    let attestationFetchCount = 0;
    const receivedUpstreamHeaders: Record<string, unknown>[] = [];

    const httpsServer = https.createServer(
      {
        key: fixture.tls1.keyPem,
        cert: fixture.tls1.certPem,
      },
      (req, res) => {
        receivedUpstreamHeaders.push({ ...req.headers });
        res.setHeader("Content-Type", "application/json; charset=utf-8");

        if (req.url === "/attestation" && req.method === "GET") {
          attestationFetchCount += 1;
          res.writeHead(200);
          res.end(
            JSON.stringify({
              token: fixture.validTokenForTls1,
              keys: TEST_KEYS,
              keysDigest: fixture.keysDigest,
              tlsSpkiSha256: fixture.tls1.spkiSha256,
              refreshedAtSec: TEST_NOW_SEC - 10,
            }),
          );
          return;
        }

        if (req.url === "/health" && req.method === "GET") {
          res.writeHead(200);
          res.end(JSON.stringify({ ok: true, service: "deroute-core" }));
          return;
        }

        if (req.url === "/agent/plan" && req.method === "POST") {
          const chunks: Buffer[] = [];
          req.on("data", (c) => chunks.push(c));
          req.on("end", () => {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            res.writeHead(200);
            res.end(
              JSON.stringify({
                ok: true,
                receivedTaskKind: parsed.taskKind,
                stack: "should-be-stripped-by-proxy",
              }),
            );
          });
          return;
        }

        res.writeHead(404);
        res.end(JSON.stringify({ ok: false }));
      },
    );

    await new Promise<void>((resolve) => httpsServer.listen(0, "127.0.0.1", resolve));
    const address = httpsServer.address() as { port: number };
    const coreHost = `127.0.0.1:${address.port}`;

    try {
      let simulatedNowSec = TEST_NOW_SEC;
      const proxyConfig = {
        coreHost,
        coreImageDigests: [TEST_IMAGE_DIGEST],
        pinnedRootCaPem: fixture.rootCertPem,
        nowSec: () => simulatedNowSec,
      };

      // 1. First request to /health triggers /attestation fetch + verification + TLS pin
      const req1 = new Request("https://drouter-demo.vercel.app/api/core/health", {
        method: "GET",
        headers: {
          "x-forwarded-for": "203.0.113.42",
          "x-real-ip": "203.0.113.42",
          cookie: "session=secret-cookie",
          "user-agent": "Mozilla/5.0 SecretBrowser",
        },
      });
      const res1 = await proxyCoreRequest(req1, ["health"], proxyConfig);
      expect(res1.status).toBe(200);
      expect(JSON.parse(res1.body)).toEqual({ ok: true, service: "deroute-core" });
      expect(attestationFetchCount).toBe(1);
      expect(getCachedCoreAttestation()?.tlsSpkiSha256).toBe(fixture.tls1.spkiSha256);

      // Verify zero forwarding of client IP, cookies, or user-agent on both /attestation and /health
      expect(receivedUpstreamHeaders.length).toBe(2);
      for (const h of receivedUpstreamHeaders) {
        expect(h["x-forwarded-for"]).toBeUndefined();
        expect(h["x-real-ip"]).toBeUndefined();
        expect(h["cookie"]).toBeUndefined();
        expect(h["user-agent"]).toBeUndefined();
      }

      // 2. Second request to POST /agent/plan reuses cached attestation without re-fetching /attestation
      const req2 = new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ taskKind: "summarize", inputHandle: "$INPUT" }),
      });
      const res2 = await proxyCoreRequest(req2, ["agent", "plan"], proxyConfig);
      expect(res2.status).toBe(200);
      const body2 = JSON.parse(res2.body);
      expect(body2).toEqual({ ok: true, receivedTaskKind: "summarize" });
      expect(body2.stack).toBeUndefined(); // stack stripped
      expect(attestationFetchCount).toBe(1);

      // 3. Advance clock to within 5 minutes of token exp -> cache expires and re-fetches /attestation
      simulatedNowSec = TEST_NOW_SEC + 3600 - 299;
      const req3 = new Request("https://drouter-demo.vercel.app/api/core/health", {
        method: "GET",
      });
      const res3 = await proxyCoreRequest(req3, ["health"], proxyConfig);
      expect(res3.status).toBe(200);
      expect(attestationFetchCount).toBe(2);
    } finally {
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("aborts TLS connection with 502 tls_spki_pin_mismatch if the server swaps its TLS key after attestation", async () => {
    const httpsServer = https.createServer(
      {
        key: fixture.tls1.keyPem,
        cert: fixture.tls1.certPem,
      },
      (req, res) => {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        if (req.url === "/attestation") {
          res.writeHead(200);
          res.end(
            JSON.stringify({
              token: fixture.validTokenForTls1,
              keys: TEST_KEYS,
              keysDigest: fixture.keysDigest,
              tlsSpkiSha256: fixture.tls1.spkiSha256,
              refreshedAtSec: TEST_NOW_SEC,
            }),
          );
          return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true }));
      },
    );

    await new Promise<void>((resolve) => httpsServer.listen(0, "127.0.0.1", resolve));
    const address = httpsServer.address() as { port: number };
    const coreHost = `127.0.0.1:${address.port}`;

    try {
      const proxyConfig = {
        coreHost,
        coreImageDigests: [TEST_IMAGE_DIGEST],
        pinnedRootCaPem: fixture.rootCertPem,
        nowSec: () => TEST_NOW_SEC,
      };

      // First call establishes verified attestation and pins tls1.spkiSha256
      const okRes = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/health"),
        ["health"],
        proxyConfig,
      );
      expect(okRes.status).toBe(200);

      // Now swap the server's TLS certificate to tls2 while cache holds pin for tls1
      httpsServer.setSecureContext({
        key: fixture.tls2.keyPem,
        cert: fixture.tls2.certPem,
      });

      const mitmRes = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/health"),
        ["health"],
        proxyConfig,
      );
      expect(mitmRes.status).toBe(502);
      const mitmBody = JSON.parse(mitmRes.body);
      expect(mitmBody.ok).toBe(false);
      expect(mitmBody.error).toBe("tls_spki_pin_mismatch");
      expect(mitmBody.stack).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("enforces request body size limits (413) on POST /agent/plan", async () => {
    const hugeBody = JSON.stringify({ pad: "a".repeat(20_000) });
    const req = new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: hugeBody,
    });
    const res = await proxyCoreRequest(req, ["agent", "plan"], {
      coreHost: "127.0.0.1:8443",
      coreImageDigests: [TEST_IMAGE_DIGEST],
      maxRequestBodyBytes: 1024,
    });
    expect(res.status).toBe(413);
    const body = JSON.parse(res.body);
    expect(body.error).toBe("payload_too_large");
  });
});
