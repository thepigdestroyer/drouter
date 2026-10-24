import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  computeKeysDigest,
  computeTlsSpkiDigest,
  configureAttestation,
  createAttestationManager,
  DEFAULT_ATTESTATION_AUDIENCE,
  DEFAULT_REFRESH_INTERVAL_MS,
  getAttestation,
  resetAttestationForTests,
} from "../src/attestation-gcp.js";
import { canonicalJson, sha256Hex } from "../src/canonical.js";

function makeFakeJwt(payloadObj) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = Buffer.from("fake-signature-bytes").toString("base64url");
  return `${header}.${payload}.${sig}`;
}

test("attestation-gcp requests PKI token over unix socket, binds keysDigest and tlsSpkiDigest, and refreshes after 45 minutes", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cs-launcher-"));
  const socketPath = path.join(tmpDir, "teeserver.sock");

  const egressPubHex = "11".repeat(32);
  const treePubHex = "22".repeat(32);

  // Generate an ECDSA P-256 key pair and extract its SPKI DER to test computeTlsSpkiDigest
  const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const expectedTlsSpkiSha256 = sha256Hex(new Uint8Array(spkiDer));
  const expectedKeysDigest = sha256Hex(
    canonicalJson({ egress: egressPubHex, tree: treePubHex }),
  );

  assert.equal(computeTlsSpkiDigest(spkiPem), expectedTlsSpkiSha256);
  assert.equal(computeTlsSpkiDigest(spkiDer), expectedTlsSpkiSha256);
  assert.equal(
    computeKeysDigest({ egress: egressPubHex, tree: treePubHex }).keysDigest,
    expectedKeysDigest,
  );
  assert.equal(DEFAULT_REFRESH_INTERVAL_MS, 45 * 60 * 1000);

  const receivedRequests = [];
  let tokenCounter = 0;

  const fakeLauncher = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const bodyText = Buffer.concat(chunks).toString("utf8");
      let parsedBody = null;
      try {
        parsedBody = JSON.parse(bodyText);
      } catch {
        parsedBody = null;
      }

      receivedRequests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: parsedBody,
      });

      if (req.method !== "POST" || req.url !== "/v1/token") {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("not found");
        return;
      }

      tokenCounter += 1;
      const jwt = makeFakeJwt({
        seq: tokenCounter,
        aud: parsedBody.audience,
        eat_nonce: parsedBody.nonces,
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(jwt);
    });
  });

  await new Promise((resolve) => fakeLauncher.listen(socketPath, resolve));

  try {
    let clockSec = 1_792_886_400;

    configureAttestation({
      socketPath,
      keys: { egress: egressPubHex, tree: treePubHex },
      tlsCert: spkiPem,
      nowSec: () => clockSec,
      refreshIntervalMs: 0, // disable background timer in unit test; test clock-based 45m refresh deterministically
    });

    // 1. Initial call to getAttestation() fetches from unix socket
    const att1 = await getAttestation();
    assert.equal(receivedRequests.length, 1);
    assert.equal(receivedRequests[0].method, "POST");
    assert.equal(receivedRequests[0].url, "/v1/token");
    assert.deepEqual(receivedRequests[0].body, {
      audience: DEFAULT_ATTESTATION_AUDIENCE,
      token_type: "PKI",
      nonces: [expectedKeysDigest, expectedTlsSpkiSha256],
    });

    assert.equal(att1.keys.egress, egressPubHex);
    assert.equal(att1.keys.tree, treePubHex);
    assert.equal(att1.keysDigest, expectedKeysDigest);
    assert.equal(att1.tlsSpkiSha256, expectedTlsSpkiSha256);
    assert.equal(att1.refreshedAtSec, 1_792_886_400);
    assert.equal(att1.token.split(".").length, 3);

    // 2. Test 45-minute refresh lifecycle with createAttestationManager
    const manager = createAttestationManager({
      socketPath,
      keys: { egress: egressPubHex, tree: treePubHex },
      tlsCert: spkiPem,
      nowSec: () => clockSec,
      refreshIntervalMs: DEFAULT_REFRESH_INTERVAL_MS,
    });

    try {
      const m1 = await manager.getAttestation();
      assert.equal(receivedRequests.length, 2);
      assert.equal(m1.refreshedAtSec, 1_792_886_400);

      // Advance 44 minutes (2640s): still cached, does not re-fetch
      clockSec += 44 * 60;
      const m2 = await manager.getAttestation();
      assert.equal(receivedRequests.length, 2);
      assert.equal(m2.token, m1.token);

      // Advance 1 more minute (total 45 minutes = 2700s): triggers refresh
      clockSec += 60;
      const m3 = await manager.getAttestation();
      assert.equal(receivedRequests.length, 3);
      assert.notEqual(m3.token, m1.token);
      assert.equal(m3.refreshedAtSec, 1_792_886_400 + 2700);
    } finally {
      manager.stop();
    }
  } finally {
    resetAttestationForTests();
    await new Promise((resolve) => fakeLauncher.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("attestation-gcp surfaces launcher HTTP errors cleanly", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cs-launcher-err-"));
  const socketPath = path.join(tmpDir, "teeserver.sock");

  const errorServer = http.createServer((_req, res) => {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("attestation service unavailable");
  });

  await new Promise((resolve) => errorServer.listen(socketPath, resolve));

  try {
    const manager = createAttestationManager({
      socketPath,
      keys: { egress: "aa".repeat(32), tree: "bb".repeat(32) },
      tlsSpkiSha256: "cc".repeat(32),
      refreshIntervalMs: 0,
    });

    await assert.rejects(
      () => manager.getAttestation(),
      /Confidential Space launcher returned HTTP 500/,
    );
  } finally {
    await new Promise((resolve) => errorServer.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
