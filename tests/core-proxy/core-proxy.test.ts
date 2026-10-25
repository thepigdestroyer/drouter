import crypto from "node:crypto";
import https from "node:https";
import type { TLSSocket } from "node:tls";
import type * as x509Types from "@peculiar/x509";
import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  ensureReflectMetadata,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
} from "@/lib/attestation/confidential-space";
import {
  clearCoreAttestationCache,
  getCachedCoreAttestation,
  normalizeAllowedCorePath,
  parseCoreHost,
  proxyCoreRequest,
} from "@/lib/core-proxy";
import { GET, POST } from "@/app/api/core/[...path]/route";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

let x509: typeof import("@peculiar/x509");

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

interface GeneratedTlsMaterial {
  cert: x509Types.X509Certificate;
  certPem: string;
  keyPem: string;
  spkiSha256: string;
  webPriv: CryptoKey;
}

async function generateEcdsaTlsPair(
  commonName: string,
  options: {
    isCa?: boolean;
    issuerCert?: x509Types.X509Certificate;
    issuerKey?: CryptoKey;
  } = {},
): Promise<GeneratedTlsMaterial> {
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

  const extensions: x509Types.Extension[] = options.isCa
    ? [
        new x509.BasicConstraintsExtension(true, 1, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.digitalSignature,
          true,
        ),
      ]
    : [new x509.BasicConstraintsExtension(false, undefined, true)];

  const cert = options.issuerCert && options.issuerKey
    ? await x509.X509CertificateGenerator.create({
        serialNumber: "02",
        subject: `CN=${commonName}`,
        issuer: options.issuerCert.subject,
        notBefore: new Date((TEST_NOW_SEC - 86_400) * 1000),
        notAfter: new Date((TEST_NOW_SEC + 86_400 * 365) * 1000),
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        publicKey: webPub,
        signingKey: options.issuerKey,
        extensions,
      })
    : await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: `CN=${commonName}`,
        notBefore: new Date((TEST_NOW_SEC - 86_400) * 1000),
        notAfter: new Date((TEST_NOW_SEC + 86_400 * 365) * 1000),
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        keys: { privateKey: webPriv, publicKey: webPub },
        extensions,
      });

  const certPem = cert.toString("pem").trim();
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const spkiSha256 = await computeTlsCertSpkiSha256(certPem);
  return { cert, certPem, keyPem, spkiSha256, webPriv };
}

interface ProxyTestFixture {
  rootCertPem: string;
  x5cChain: string[];
  leafPrivateKey: CryptoKey;
  tls1: GeneratedTlsMaterial;
  tls2DifferentCa: GeneratedTlsMaterial;
  tlsChildDifferentSpki: GeneratedTlsMaterial;
  keysDigest: string;
  validTokenForTls1: string;
  validTokenForTls2: string;
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

async function signAttestationToken(
  x5cChain: string[],
  leafPrivateKey: CryptoKey,
  keysDigest: string,
  tlsSpkiSha256: string,
  exp = TEST_NOW_SEC + 3600,
): Promise<string> {
  const header = { alg: "RS256", typ: "JWT", x5c: x5cChain };
  const payload = {
    iss: EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
    aud: DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    iat: TEST_NOW_SEC - 30,
    nbf: TEST_NOW_SEC - 30,
    exp,
    swname: "CONFIDENTIAL_SPACE",
    dbgstat: "disabled-since-boot",
    secboot: true,
    hwmodel: "GCP_AMD_SEV",
    eat_nonce: [keysDigest, tlsSpkiSha256],
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
    leafPrivateKey,
    new TextEncoder().encode(`${h}.${p}`),
  );
  return `${h}.${p}.${bytesToBase64Url(sig)}`;
}

beforeAll(async () => {
  ensureReflectMetadata();
  x509 = await import("@peculiar/x509");

  const [rootKeys, interKeys, leafKeys, tls1, tls2DifferentCa] = await Promise.all([
    generateRsaPair(),
    generateRsaPair(),
    generateRsaPair(),
    // Make tls1 CA-capable so we can also sign a child leaf certificate with a different SPKI
    // to test that checkServerIdentity refuses it even when OpenSSL CA chain verification passes!
    generateEcdsaTlsPair("deroute-core-1.internal", { isCa: true }),
    generateEcdsaTlsPair("deroute-core-mitm-ca.internal", { isCa: true }),
  ]);

  const tlsChildDifferentSpki = await generateEcdsaTlsPair("deroute-core-mitm-leaf.internal", {
    isCa: false,
    issuerCert: tls1.cert,
    issuerKey: tls1.webPriv,
  });

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
  const validTokenForTls1 = await signAttestationToken(
    x5cChain,
    leafKeys.privateKey,
    keysDigest,
    tls1.spkiSha256,
  );
  const validTokenForTls2 = await signAttestationToken(
    x5cChain,
    leafKeys.privateKey,
    keysDigest,
    tls2DifferentCa.spkiSha256,
  );

  fixture = {
    rootCertPem: rootCert.toString("pem"),
    x5cChain,
    leafPrivateKey: leafKeys.privateKey,
    tls1,
    tls2DifferentCa,
    tlsChildDifferentSpki,
    keysDigest,
    validTokenForTls1,
    validTokenForTls2,
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

  it("validates CORE_HOST (including IPv6 brackets) and rejects malformed path segments or percent-encoded paths", async () => {
    expect(parseCoreHost("127.0.0.1:8443")).toEqual({ host: "127.0.0.1", port: 8443 });
    expect(parseCoreHost("[::1]:8443")).toEqual({ host: "::1", port: 8443 });
    expect(parseCoreHost("[::1]")).toEqual({ host: "::1", port: 8443 });
    expect(parseCoreHost("::1")).toBeNull();
    expect(parseCoreHost("user@127.0.0.1:8443")).toBeNull();
    expect(parseCoreHost("127.0.0.1:0")).toBeNull();
    expect(parseCoreHost("127.0.0.1:99999")).toBeNull();

    // Empty segment inside array must be rejected, not collapsed
    expect(normalizeAllowedCorePath(["knowledge", "", "corpus"]).ok).toBe(false);
    expect(normalizeAllowedCorePath(["knowledge", "corpus"]).ok).toBe(true);

    // Percent-encoded URL path is rejected
    const encodedReq = new Request("https://drouter-demo.vercel.app/api/core/health%2f..", {
      method: "GET",
    });
    const encodedRes = await GET(encodedReq, {
      params: Promise.resolve({ path: ["health"] }),
    });
    expect(encodedRes.status).toBe(404);
  });

  it("enforces the strict path and method allowlist before making any upstream calls", async () => {
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

    const queryReq = new Request(
      "https://drouter-demo.vercel.app/api/core/knowledge/corpus?topic=tdx",
      { method: "GET" },
    );
    const resQuery = await GET(queryReq, {
      params: Promise.resolve({ path: ["knowledge", "corpus"] }),
    });
    expect(resQuery.status).toBe(400);
  });

  it("verifies /attestation, pins TLS with ca:[tlsCertPem] + rejectUnauthorized:true + checkServerIdentity, reuses keep-alive sockets, strips headers, and never spreads unverified attestation fields", async () => {
    let attestationFetchCount = 0;
    let pinnedTlsHandshakeCount = 0;
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
              tlsCertPem: fixture.tls1.certPem,
              refreshedAtSec: TEST_NOW_SEC - 10,
              untrustedExtraField: "must-never-be-spread-by-proxy",
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

    httpsServer.on("secureConnection", () => {
      pinnedTlsHandshakeCount += 1;
    });

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

      // 1. First request to /attestation returns only verified fields (never spreads untrustedExtraField)
      const attReq = new Request("https://drouter-demo.vercel.app/api/core/attestation", {
        method: "GET",
      });
      const attRes = await proxyCoreRequest(attReq, ["attestation"], proxyConfig);
      expect(attRes.status).toBe(200);
      const attJson = JSON.parse(attRes.body);
      expect(attJson.token).toBe(fixture.validTokenForTls1);
      expect(attJson.keys).toEqual(TEST_KEYS);
      expect(attJson.keysDigest).toBe(fixture.keysDigest);
      expect(attJson.tlsSpkiSha256).toBe(fixture.tls1.spkiSha256);
      expect(attJson.tlsCertPem).toBe(fixture.tls1.certPem);
      expect(attJson.verification.ok).toBe(true);
      expect(attJson.untrustedExtraField).toBeUndefined();
      expect(attestationFetchCount).toBe(1);
      expect(pinnedTlsHandshakeCount).toBe(1); // 1 handshake for /attestation

      // 2. Request to /health uses the dedicated pinned https.Agent
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
      expect(pinnedTlsHandshakeCount).toBe(2); // 1 new handshake for the pinned keepAlive agent

      // Verify zero forwarding of client IP, cookies, or user-agent
      for (const h of receivedUpstreamHeaders) {
        expect(h["x-forwarded-for"]).toBeUndefined();
        expect(h["x-real-ip"]).toBeUndefined();
        expect(h["cookie"]).toBeUndefined();
        expect(h["user-agent"]).toBeUndefined();
      }

      // 3. Second pinned request to POST /agent/plan reuses the keep-alive TLS socket in the pinned Agent!
      const req2 = new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ taskKind: "summarize", inputHandle: "$INPUT" }),
      });
      const res2 = await proxyCoreRequest(req2, ["agent", "plan"], proxyConfig);
      expect(res2.status).toBe(200);
      const body2 = JSON.parse(res2.body);
      expect(body2).toEqual({ ok: true, receivedTaskKind: "summarize" });
      expect(body2.stack).toBeUndefined();
      expect(attestationFetchCount).toBe(1);
      expect(pinnedTlsHandshakeCount).toBe(2); // Reused keep-alive TLS socket!
    } finally {
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("refuses both (a) a MITM server with a different self-signed CA and (b) a MITM server with a cert signed by the pinned CA whose SPKI differs, before any request bytes are written", async () => {
    let mitmHttpRequestsReceived = 0;
    let mitmTlsApplicationBytesReceived = 0;
    let attestationPhase = true;

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
              tlsCertPem: fixture.tls1.certPem,
              refreshedAtSec: TEST_NOW_SEC,
            }),
          );
          return;
        }
        if (!attestationPhase) {
          mitmHttpRequestsReceived += 1;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true }));
      },
    );

    const activeServerSockets = new Set<TLSSocket>();
    httpsServer.on("secureConnection", (tlsSocket: TLSSocket) => {
      activeServerSockets.add(tlsSocket);
      tlsSocket.on("close", () => activeServerSockets.delete(tlsSocket));
      if (!attestationPhase) {
        tlsSocket.on("data", (chunk: Buffer) => {
          mitmTlsApplicationBytesReceived += chunk.byteLength;
        });
      }
    });

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

      // Prime the attestation cache with genuine tls1
      const okRes = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/attestation"),
        ["attestation"],
        proxyConfig,
      );
      expect(okRes.status).toBe(200);

      // Case A: MITM server with a certificate from a different self-signed CA
      attestationPhase = false;
      httpsServer.setSecureContext({
        key: fixture.tls2DifferentCa.keyPem,
        cert: fixture.tls2DifferentCa.certPem,
      });

      const mitmResA = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ taskKind: "summarize", secretProbe: "never-sent" }),
        }),
        ["agent", "plan"],
        proxyConfig,
      );
      expect(mitmResA.status).toBe(502);
      const mitmBodyA = JSON.parse(mitmResA.body);
      expect(mitmBodyA.ok).toBe(false);
      expect(mitmBodyA.error).toBe("tls_spki_pin_mismatch");
      expect(mitmHttpRequestsReceived).toBe(0);
      expect(mitmTlsApplicationBytesReceived).toBe(0);

      // Re-prime attestation cache with genuine tls1 for Case B
      attestationPhase = true;
      httpsServer.setSecureContext({
        key: fixture.tls1.keyPem,
        cert: fixture.tls1.certPem,
      });
      const rePrimeRes = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/attestation"),
        ["attestation"],
        proxyConfig,
      );
      expect(rePrimeRes.status).toBe(200);

      // Case B: MITM server presents a leaf certificate signed by tls1 (so OpenSSL CA check passes
      // with ca: [tls1.certPem] and rejectUnauthorized: true!), but whose SPKI differs from tls1!
      // Node's checkServerIdentity must refuse the connection before any request bytes are written.
      attestationPhase = false;
      httpsServer.setSecureContext({
        key: fixture.tlsChildDifferentSpki.keyPem,
        cert: `${fixture.tlsChildDifferentSpki.certPem}\n${fixture.tls1.certPem}`,
      });

      const mitmResB = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/agent/plan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ taskKind: "summarize", secretProbe: "never-sent" }),
        }),
        ["agent", "plan"],
        proxyConfig,
      );
      expect(mitmResB.status).toBe(502);
      const mitmBodyB = JSON.parse(mitmResB.body);
      expect(mitmBodyB.ok).toBe(false);
      expect(mitmBodyB.error).toBe("tls_spki_pin_mismatch");
      expect(mitmHttpRequestsReceived).toBe(0);
      expect(mitmTlsApplicationBytesReceived).toBe(0);
    } finally {
      for (const s of activeServerSockets) s.destroy();
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("drops old keep-alive sockets and replaces the https.Agent when the pin changes after re-attestation", async () => {
    let currentTls = fixture.tls1;
    let currentToken = fixture.validTokenForTls1;
    const serverSideSockets: TLSSocket[] = [];

    const httpsServer = https.createServer(
      {
        key: currentTls.keyPem,
        cert: currentTls.certPem,
      },
      (req, res) => {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        if (req.url === "/attestation") {
          res.writeHead(200);
          res.end(
            JSON.stringify({
              token: currentToken,
              keys: TEST_KEYS,
              keysDigest: fixture.keysDigest,
              tlsSpkiSha256: currentTls.spkiSha256,
              tlsCertPem: currentTls.certPem,
              refreshedAtSec: TEST_NOW_SEC,
            }),
          );
          return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true, pin: currentTls.spkiSha256 }));
      },
    );

    httpsServer.on("secureConnection", (tlsSocket: TLSSocket) => {
      serverSideSockets.push(tlsSocket);
    });

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

      // 1. Connect with pin 1 (tls1)
      const res1 = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/health"),
        ["health"],
        proxyConfig,
      );
      expect(res1.status).toBe(200);
      const agent1 = getCachedCoreAttestation()!.agent;
      expect(getCachedCoreAttestation()!.tlsSpkiSha256).toBe(fixture.tls1.spkiSha256);

      // Capture the keep-alive client socket inside agent1
      const freeSocketsList1 = Object.values(agent1.freeSockets).flat();
      expect(freeSocketsList1.length).toBe(1);
      const oldClientSocket = freeSocketsList1[0]!;
      expect(oldClientSocket.destroyed).toBe(false);

      // 2. Rotate server to tls2DifferentCa with a valid attestation token for tls2,
      //    and advance clock to trigger re-attestation (within 5 minutes of token exp)
      currentTls = fixture.tls2DifferentCa;
      currentToken = fixture.validTokenForTls2;
      httpsServer.setSecureContext({
        key: currentTls.keyPem,
        cert: currentTls.certPem,
      });
      simulatedNowSec = TEST_NOW_SEC + 3600 - 200;

      const res2 = await proxyCoreRequest(
        new Request("https://drouter-demo.vercel.app/api/core/health"),
        ["health"],
        proxyConfig,
      );
      expect(res2.status).toBe(200);
      expect(JSON.parse(res2.body)).toEqual({
        ok: true,
        pin: fixture.tls2DifferentCa.spkiSha256,
      });

      const agent2 = getCachedCoreAttestation()!.agent;
      expect(agent2).not.toBe(agent1);
      expect(getCachedCoreAttestation()!.tlsSpkiSha256).toBe(
        fixture.tls2DifferentCa.spkiSha256,
      );
      // Old keep-alive socket from agent1 must be destroyed immediately upon pin change!
      expect(oldClientSocket.destroyed).toBe(true);
    } finally {
      for (const s of serverSideSockets) s.destroy();
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
