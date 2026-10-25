import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import util from "node:util";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  DEFAULT_ATTESTATION_AUDIENCE,
  resetAttestationForTests,
} from "../src/attestation-gcp.js";
import { canonicalJson, coarsenEpochSecToHour, sha256Hex } from "../src/canonical.js";
import { resetKeyRingForTests } from "../src/keys.js";
import {
  computeMerkleRootFromLeaves,
  createVerificationLogEvent,
  verifySignedTreeHead,
} from "../src/receipts.js";
import {
  loadSecrets,
  resetLoadedSecretsForTests,
  resolveSecretsSource,
} from "../src/secrets-gcp.js";
import {
  createCoreServer,
  DEFAULT_BOOT_HTTPS_PORT,
  DEFAULT_TINFOIL_HTTP_PORT,
  resolveServerPort,
  startCoreServer,
} from "../src/server.js";
import {
  getBootTlsMaterial,
  privateKey as bootTlsPrivateKey,
  TLS_CERT_COMMON_NAME,
  TLS_CERT_VALIDITY_DAYS,
  tlsCertPem as bootTlsCertPem,
  tlsSpkiSha256 as bootTlsSpkiSha256,
} from "../src/tls.js";

function makeFakeJwt(payloadObj) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = Buffer.from("fake-google-cs-signature").toString("base64url");
  return `${header}.${payload}.${sig}`;
}

function httpsGetJson({ host, port, path: reqPath, caCertPem, headers = {} }) {
  return new Promise((resolve, reject) => {
    let peerSpkiSha256 = null;
    let peerCertPem = null;

    const req = https.request(
      {
        host,
        port,
        path: reqPath,
        method: "GET",
        headers: {
          Accept: "application/json",
          ...headers,
        },
        ca: [caCertPem],
        rejectUnauthorized: true,
        checkServerIdentity: (_servername, cert) => {
          const x509Cert = new crypto.X509Certificate(cert.raw);
          const spkiDer = x509Cert.publicKey.export({ type: "spki", format: "der" });
          peerSpkiSha256 = sha256Hex(new Uint8Array(spkiDer));
          peerCertPem = x509Cert.toString().trim();
          return undefined;
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const rawBody = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = JSON.parse(rawBody);
          } catch {
            json = null;
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: json,
            rawBody,
            peerSpkiSha256,
            peerCertPem,
          });
        });
      },
    );

    req.on("error", reject);
    req.end();
  });
}

function httpsPostJson({ host, port, path: reqPath, caCertPem, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const req = https.request(
      {
        host,
        port,
        path: reqPath,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": payload.length,
          Accept: "application/json",
          ...headers,
        },
        ca: [caCertPem],
        rejectUnauthorized: true,
        checkServerIdentity: () => undefined,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const rawBody = Buffer.concat(chunks).toString("utf8");
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: JSON.parse(rawBody),
          });
        });
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

test("HTTPS server starts with boot ECDSA P-256 certificate (CN=deroute-core, 30 days) and TLS peer SPKI equals tlsSpkiSha256", async () => {
  assert.ok(bootTlsCertPem.includes("-----BEGIN CERTIFICATE-----"));
  assert.ok(bootTlsPrivateKey.includes("-----BEGIN PRIVATE KEY-----"));
  assert.match(bootTlsSpkiSha256, /^[0-9a-f]{64}$/);

  const parsedX509 = new crypto.X509Certificate(bootTlsCertPem);
  assert.equal(parsedX509.subject, `CN=${TLS_CERT_COMMON_NAME}`);
  assert.equal(parsedX509.publicKey.asymmetricKeyType, "ec");
  assert.equal(parsedX509.publicKey.asymmetricKeyDetails.namedCurve, "prime256v1");

  const validFromMs = Date.parse(parsedX509.validFrom);
  const validToMs = Date.parse(parsedX509.validTo);
  const validityDays = Math.round((validToMs - validFromMs) / (24 * 60 * 60 * 1000));
  assert.equal(validityDays, TLS_CERT_VALIDITY_DAYS);

  const bootMat = getBootTlsMaterial();
  assert.equal(Object.keys(bootMat).includes("privateKey"), false);
  assert.equal(JSON.stringify(bootMat).includes("PRIVATE KEY"), false);

  assert.equal(resolveServerPort("boot", undefined), DEFAULT_BOOT_HTTPS_PORT);
  assert.equal(resolveServerPort("tinfoil", undefined), DEFAULT_TINFOIL_HTTP_PORT);
  assert.equal(DEFAULT_BOOT_HTTPS_PORT, 8443);
  assert.equal(DEFAULT_TINFOIL_HTTP_PORT, 8080);

  const server = createCoreServer({
    keySource: "boot",
    tlsOnly: true,
    db: null,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  try {
    const res = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/health",
      caCertPem: bootTlsCertPem,
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.peerSpkiSha256, bootTlsSpkiSha256);
    assert.equal(res.peerCertPem, bootTlsCertPem);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.keySource, "boot");

    const keysRes = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/keys",
      caCertPem: bootTlsCertPem,
    });
    assert.equal(keysRes.statusCode, 200);
    assert.equal(keysRes.body.tlsSpkiSha256, bootTlsSpkiSha256);
  } finally {
    resetAttestationForTests();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("GET /attestation returns exact shape expected by core-proxy and returns 503 on expired or missing token", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-gcp-srv-"));
  const socketPath = path.join(tmpDir, "teeserver.sock");

  let clockSec = 1_792_886_400;
  let tokenExpOffsetSec = 3600;
  let launcherStatus = 200;
  const launcherRequests = [];

  const fakeLauncher = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const bodyObj = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      launcherRequests.push({
        method: req.method,
        url: req.url,
        body: bodyObj,
      });

      if (launcherStatus !== 200) {
        res.writeHead(launcherStatus, { "Content-Type": "text/plain" });
        res.end("launcher unavailable");
        return;
      }

      const token = makeFakeJwt({
        iss: "https://confidentialcomputing.googleapis.com",
        aud: bodyObj.audience,
        iat: clockSec,
        nbf: clockSec,
        exp: clockSec + tokenExpOffsetSec,
        eat_nonce: bodyObj.nonces,
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(token);
    });
  });

  await new Promise((resolve) => fakeLauncher.listen(socketPath, resolve));

  const server = createCoreServer({
    keySource: "boot",
    tlsOnly: true,
    socketPath,
    nowSec: () => clockSec,
    refreshIntervalMs: 0,
    db: null,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  try {
    // 1. Valid GET /attestation returns exact shape src/lib/core-proxy/index.ts reads
    const attRes = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/attestation",
      caCertPem: bootTlsCertPem,
    });

    assert.equal(attRes.statusCode, 200);
    assert.equal(attRes.peerSpkiSha256, bootTlsSpkiSha256);

    const att = attRes.body;
    assert.deepEqual(
      Object.keys(att).sort(),
      [
        "expiresAtSec",
        "keys",
        "keysDigest",
        "refreshedAtSec",
        "tlsCertPem",
        "tlsSpkiSha256",
        "token",
      ],
    );
    assert.equal(typeof att.token, "string");
    assert.equal(att.token.split(".").length, 3);
    assert.match(att.keys.egress, /^[0-9a-f]{64}$/);
    assert.match(att.keys.tree, /^[0-9a-f]{64}$/);

    const expectedKeysDigest = sha256Hex(
      canonicalJson({ egress: att.keys.egress, tree: att.keys.tree }),
    );
    assert.equal(att.keysDigest, expectedKeysDigest);
    assert.equal(att.tlsSpkiSha256, bootTlsSpkiSha256);
    assert.equal(att.tlsCertPem, bootTlsCertPem);
    assert.equal(att.refreshedAtSec, clockSec);
    assert.equal(att.expiresAtSec, clockSec + 3600);

    assert.equal(launcherRequests.length, 1);
    assert.equal(launcherRequests[0].method, "POST");
    assert.equal(launcherRequests[0].url, "/v1/token");
    assert.deepEqual(launcherRequests[0].body, {
      audience: DEFAULT_ATTESTATION_AUDIENCE,
      token_type: "PKI",
      nonces: [expectedKeysDigest, bootTlsSpkiSha256],
    });

    // Rejects query parameters and non-GET methods on /attestation
    const queryRes = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/attestation?nonce=123",
      caCertPem: bootTlsCertPem,
    });
    assert.equal(queryRes.statusCode, 400);

    const postRes = await httpsPostJson({
      host: "127.0.0.1",
      port,
      path: "/attestation",
      caCertPem: bootTlsCertPem,
      body: {},
    });
    assert.equal(postRes.statusCode, 405);

    // 2. Advance clock past token expiration and have launcher return an already-expired token -> 503
    clockSec += 3601;
    tokenExpOffsetSec = -5;
    const expiredRes = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/attestation",
      caCertPem: bootTlsCertPem,
    });
    assert.equal(expiredRes.statusCode, 503);
    assert.equal(expiredRes.body.ok, false);
    assert.equal(expiredRes.body.error, "attestation_unavailable");

    // 3. When launcher returns HTTP 500 and no valid non-expired token exists -> 503
    launcherStatus = 500;
    const downRes = await httpsGetJson({
      host: "127.0.0.1",
      port,
      path: "/attestation",
      caCertPem: bootTlsCertPem,
    });
    assert.equal(downRes.statusCode, 503);
    assert.equal(downRes.body.ok, false);
    assert.equal(downRes.body.error, "attestation_unavailable");
  } finally {
    resetAttestationForTests();
    await new Promise((resolve) => server.close(resolve));
    await new Promise((resolve) => fakeLauncher.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("secrets-gcp loads secrets from fake GCE metadata and Secret Manager servers, keeps values in memory only, and fails closed on missing secrets", async () => {
  const expectedMongoUri = "mongodb+srv://enclave-user:enclave-pass@cluster0.example.mongodb.net/drouter";
  const expectedGeminiKey = "AIzaSyFakeEnclaveGeminiKeyForUnitTestOnly";
  const expectedOperatorToken = "op-token-confidential-space-2026";
  const expectedAccessToken = "ya29.fake-confidential-space-sa-token";
  const expectedProjectId = "deroute-confidential-prod";

  let metadataRequireHeader = true;
  const secretStore = new Map([
    ["MONGODB_URI", expectedMongoUri],
    ["GEMINI_API_KEY", expectedGeminiKey],
    ["CORE_OPERATOR_TOKEN", expectedOperatorToken],
  ]);
  const smRequests = [];

  const fakeMetadataServer = http.createServer((req, res) => {
    if (metadataRequireHeader && req.headers["metadata-flavor"] !== "Google") {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Missing Metadata-Flavor: Google header");
      return;
    }
    if (req.url === "/computeMetadata/v1/instance/service-accounts/default/token") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: expectedAccessToken,
          expires_in: 3599,
          token_type: "Bearer",
        }),
      );
      return;
    }
    if (req.url === "/computeMetadata/v1/project/project-id") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(expectedProjectId);
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });

  const fakeSecretManagerServer = http.createServer((req, res) => {
    smRequests.push({
      method: req.method,
      url: req.url,
      authorization: req.headers.authorization,
    });

    if (req.headers.authorization !== `Bearer ${expectedAccessToken}`) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }

    const match = /^\/v1\/projects\/([^/]+)\/secrets\/([^/]+)\/versions\/latest:access$/.exec(
      req.url || "",
    );
    if (!match || match[1] !== expectedProjectId) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }

    const secretName = decodeURIComponent(match[2]);
    if (!secretStore.has(secretName)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "secret_not_found" }));
      return;
    }

    const rawVal = secretStore.get(secretName);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        name: `projects/${expectedProjectId}/secrets/${secretName}/versions/1`,
        payload: {
          data: Buffer.from(rawVal, "utf8").toString("base64"),
        },
      }),
    );
  });

  await new Promise((resolve) => fakeMetadataServer.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => fakeSecretManagerServer.listen(0, "127.0.0.1", resolve));

  const metadataBaseUrl = `http://127.0.0.1:${fakeMetadataServer.address().port}`;
  const secretManagerBaseUrl = `http://127.0.0.1:${fakeSecretManagerServer.address().port}`;

  try {
    const loaded = await loadSecrets({
      source: "gcp-secret-manager",
      metadataBaseUrl,
      secretManagerBaseUrl,
    });

    assert.equal(loaded.source, "gcp-secret-manager");
    assert.equal(loaded.MONGODB_URI, expectedMongoUri);
    assert.equal(loaded.GEMINI_API_KEY, expectedGeminiKey);
    assert.equal(loaded.CORE_OPERATOR_TOKEN, expectedOperatorToken);

    // Secret values are non-enumerable and never appear in JSON.stringify or util.inspect
    assert.deepEqual(Object.keys(loaded), ["source"]);
    assert.equal(JSON.stringify(loaded).includes(expectedMongoUri), false);
    assert.equal(JSON.stringify(loaded).includes(expectedGeminiKey), false);
    assert.equal(JSON.stringify(loaded).includes(expectedOperatorToken), false);
    assert.equal(util.inspect(loaded).includes(expectedGeminiKey), false);

    assert.equal(smRequests.length, 3);
    assert.deepEqual(
      smRequests.map((r) => r.url),
      [
        `/v1/projects/${expectedProjectId}/secrets/MONGODB_URI/versions/latest:access`,
        `/v1/projects/${expectedProjectId}/secrets/GEMINI_API_KEY/versions/latest:access`,
        `/v1/projects/${expectedProjectId}/secrets/CORE_OPERATOR_TOKEN/versions/latest:access`,
      ],
    );

    // Verify startCoreServer loads secrets from Secret Manager before serving and uses them
    const leaves = [
      createVerificationLogEvent({
        index: 0,
        kind: "verification_event",
        nodeId: "tinfoil-router",
        ok: true,
        measurement: "9134838da8aa4e17",
        evidenceHash: "5233a27f1468f474",
        timestampSec: 1792886400,
      }),
    ];
    const validMerkleRoot = bytesToHex(
      computeMerkleRootFromLeaves(leaves.map((l) => hexToBytes(l.leafHash))),
    ).toLowerCase();
    const mockDb = {
      collection() {
        return {
          find() {
            return {
              sort() {
                return {
                  async toArray() {
                    return leaves.map((l) => ({ ...l, docType: "leaf" }));
                  },
                };
              },
            };
          },
        };
      },
    };

    const startedServer = await startCoreServer({
      keySource: "boot",
      host: "127.0.0.1",
      port: 0,
      db: mockDb,
      secretsSource: "gcp-secret-manager",
      secretsOptions: {
        metadataBaseUrl,
        secretManagerBaseUrl,
      },
    });

    try {
      const srvPort = startedServer.address().port;
      const sthRes = await httpsPostJson({
        host: "127.0.0.1",
        port: srvPort,
        path: "/transparency/sign-tree-head",
        caCertPem: bootTlsCertPem,
        headers: {
          Authorization: `Bearer ${expectedOperatorToken}`,
        },
        body: {
          treeSize: 1,
          rootHash: validMerkleRoot,
          timestampSec: coarsenEpochSecToHour(1792886400),
        },
      });
      assert.equal(sthRes.statusCode, 200);
      assert.equal(sthRes.body.ok, true);
      assert.equal(
        verifySignedTreeHead(sthRes.body.sth, sthRes.body.sth.operatorPublicKey).ok,
        true,
      );
    } finally {
      await new Promise((resolve) => startedServer.close(resolve));
    }

    // Fail closed when any secret is missing in Secret Manager
    secretStore.delete("GEMINI_API_KEY");
    await assert.rejects(
      () =>
        loadSecrets({
          source: "gcp-secret-manager",
          metadataBaseUrl,
          secretManagerBaseUrl,
        }),
      /Secret Manager access failed for secret 'GEMINI_API_KEY' with HTTP 404/,
    );

    // Fail closed when secret value is empty
    secretStore.set("GEMINI_API_KEY", "   ");
    await assert.rejects(
      () =>
        loadSecrets({
          source: "gcp-secret-manager",
          metadataBaseUrl,
          secretManagerBaseUrl,
        }),
      /decoded to an empty value/,
    );

    // Rejects custom base URLs when NODE_ENV === "production"
    const prevNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      await assert.rejects(
        () =>
          loadSecrets({
            source: "gcp-secret-manager",
            metadataBaseUrl,
            secretManagerBaseUrl,
          }),
        /only permitted in tests/,
      );
    } finally {
      if (prevNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = prevNodeEnv;
      }
    }

    // CORE_SECRETS_SOURCE=env reads from environment and fails closed if any is missing
    const envLoaded = await loadSecrets({
      source: "env",
      env: {
        MONGODB_URI: expectedMongoUri,
        GEMINI_API_KEY: expectedGeminiKey,
        CORE_OPERATOR_TOKEN: expectedOperatorToken,
      },
    });
    assert.equal(envLoaded.source, "env");
    assert.equal(envLoaded.MONGODB_URI, expectedMongoUri);
    assert.equal(envLoaded.GEMINI_API_KEY, expectedGeminiKey);
    assert.equal(envLoaded.CORE_OPERATOR_TOKEN, expectedOperatorToken);

    await assert.rejects(
      () =>
        loadSecrets({
          source: "env",
          env: {
            MONGODB_URI: expectedMongoUri,
            GEMINI_API_KEY: expectedGeminiKey,
          },
        }),
      /Missing required secret 'CORE_OPERATOR_TOKEN'/,
    );
  } finally {
    resetLoadedSecretsForTests();
    resetAttestationForTests();
    await new Promise((resolve) => fakeMetadataServer.close(resolve));
    await new Promise((resolve) => fakeSecretManagerServer.close(resolve));
  }
});

test("Refuses to start on unknown CORE_SECRETS_SOURCE or CORE_KEY_SOURCE", async () => {
  const prevKeySource = process.env.CORE_KEY_SOURCE;
  const prevSecretsSource = process.env.CORE_SECRETS_SOURCE;

  try {
    // 1. Default CORE_SECRETS_SOURCE is "env"
    assert.equal(resolveSecretsSource(undefined), "env");
    assert.equal(resolveSecretsSource(""), "env");
    assert.equal(resolveSecretsSource("env"), "env");
    assert.equal(resolveSecretsSource("gcp-secret-manager"), "gcp-secret-manager");

    // 2. Unknown CORE_SECRETS_SOURCE throws in resolveSecretsSource, loadSecrets, createCoreServer, startCoreServer
    assert.throws(
      () => resolveSecretsSource("aws-secrets-manager"),
      /Invalid CORE_SECRETS_SOURCE/,
    );
    await assert.rejects(
      () => loadSecrets({ source: "hashicorp-vault" }),
      /Invalid CORE_SECRETS_SOURCE/,
    );
    assert.throws(
      () => createCoreServer({ keySource: "boot", secretsSource: "unknown-source", db: null }),
      /Invalid CORE_SECRETS_SOURCE/,
    );
    await assert.rejects(
      () => startCoreServer({ keySource: "boot", secretsSource: "unknown-source" }),
      /Invalid CORE_SECRETS_SOURCE/,
    );

    // 3. Unknown or missing CORE_KEY_SOURCE throws in createCoreServer and startCoreServer
    delete process.env.CORE_KEY_SOURCE;
    resetKeyRingForTests();
    assert.throws(
      () => createCoreServer({ db: null }),
      /Invalid or missing CORE_KEY_SOURCE/,
    );
    assert.throws(
      () => createCoreServer({ keySource: "invalid-tee", db: null }),
      /Invalid or missing CORE_KEY_SOURCE/,
    );
    await assert.rejects(
      () =>
        startCoreServer({
          keySource: "invalid-tee",
          secretsSource: "env",
          allowPartialEnv: true,
        }),
      /Invalid or missing CORE_KEY_SOURCE/,
    );
  } finally {
    if (prevKeySource === undefined) {
      delete process.env.CORE_KEY_SOURCE;
    } else {
      process.env.CORE_KEY_SOURCE = prevKeySource;
    }
    if (prevSecretsSource === undefined) {
      delete process.env.CORE_SECRETS_SOURCE;
    } else {
      process.env.CORE_SECRETS_SOURCE = prevSecretsSource;
    }
    resetLoadedSecretsForTests();
    resetAttestationForTests();
  }
});
