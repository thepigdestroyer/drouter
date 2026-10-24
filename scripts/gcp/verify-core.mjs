#!/usr/bin/env node
/**
 * Independent command-line verifier for the deRoute Google Cloud Confidential Space VM (G7).
 *
 * Connects directly to `https://<CORE_HOST>:8443/attestation`, extracts the peer TLS certificate's
 * SubjectPublicKeyInfo (SPKI) DER, verifies the Google Cloud Confidential Space PKI token against
 * the pinned Google Confidential Space Root CA, checks all G4 claims, and prints the check table.
 *
 * Usage:
 *   CORE_HOST=<ip>:8443 CORE_IMAGE_DIGESTS=sha256:<digest> node scripts/gcp/verify-core.mjs
 */

import crypto from "node:crypto";
import https from "node:https";

const GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
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
uyT5CnJulxSC5CT1
-----END CERTIFICATE-----`;

const PINNED_ROOT_SHA256 = "148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39";
const EXPECTED_ISSUER = "https://confidentialcomputing.googleapis.com";
const DEFAULT_AUDIENCE = "https://drouter-demo.vercel.app/deroute-core";
const ALLOWED_HWMODELS = new Set(["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"]);
const ALLOWED_ENV_OVERRIDES = new Set(["CORE_KEY_SOURCE", "CORE_PUBLIC_ORIGIN"]);

function canonicalJson(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "string" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((x) => canonicalJson(x === undefined ? null : x)).join(",")}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

function sha256HexLower(bufOrStr) {
  return crypto.createHash("sha256").update(bufOrStr).digest("hex").toLowerCase();
}

function parseHostPort(rawHost) {
  const clean = String(rawHost || "").trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!clean) return null;
  const idx = clean.lastIndexOf(":");
  if (idx > 0) {
    return { host: clean.slice(0, idx), port: Number(clean.slice(idx + 1)) || 8443 };
  }
  return { host: clean, port: 8443 };
}

function fetchAttestationWithPeerCert({ host, port }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host,
        port,
        path: "/attestation",
        method: "GET",
        rejectUnauthorized: false,
        agent: false,
        headers: { Accept: "application/json", Connection: "close" },
      },
      (res) => {
        const peer = res.socket.getPeerCertificate(false);
        if (!peer || !peer.raw) {
          reject(new Error("Peer did not present a TLS certificate"));
          return;
        }
        const x509Peer = new crypto.X509Certificate(peer.raw);
        const spkiDer = x509Peer.publicKey.export({ type: "spki", format: "der" });
        const peerSpkiSha256 = sha256HexLower(spkiDer);

        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            resolve({ statusCode: res.statusCode, payload, peerSpkiSha256 });
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error("Connection timed out")));
    req.on("error", reject);
    req.end();
  });
}

async function main() {
  const rawHost = process.env.CORE_HOST || process.argv[2];
  const target = parseHostPort(rawHost);
  if (!target) {
    console.error("Usage: CORE_HOST=<ip>:8443 CORE_IMAGE_DIGESTS=sha256:<digest> node scripts/gcp/verify-core.mjs");
    process.exit(1);
  }

  const expectedDigests = new Set(
    String(process.env.CORE_IMAGE_DIGESTS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const expectedAudience = process.env.CORE_ATTESTATION_AUDIENCE || DEFAULT_AUDIENCE;

  const { statusCode, payload, peerSpkiSha256 } = await fetchAttestationWithPeerCert(target);
  if (statusCode !== 200) {
    console.error(`Error: /attestation returned HTTP ${statusCode}`);
    process.exit(1);
  }

  const token = String(payload.token || "");
  const parts = token.split(".");
  if (parts.length !== 3) {
    console.error("Error: /attestation did not return a 3-part JWT");
    process.exit(1);
  }

  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const sigBytes = Buffer.from(parts[2], "base64url");
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "utf8");

  const x5c = Array.isArray(header.x5c) ? header.x5c : [];
  const checks = [];

  // 1. Header & x5c count
  const headerOk = header.alg === "RS256" && x5c.length === 3;
  checks.push({
    id: "jwt_header_and_x5c",
    passed: headerOk,
    technical: `alg=${header.alg}, x5c.length=${x5c.length}`,
  });

  // 2. Root CA match
  const leafCert = x5c[0] ? new crypto.X509Certificate(Buffer.from(x5c[0], "base64")) : null;
  const interCert = x5c[1] ? new crypto.X509Certificate(Buffer.from(x5c[1], "base64")) : null;
  const rootCert = x5c[2] ? new crypto.X509Certificate(Buffer.from(x5c[2], "base64")) : null;
  const pinnedRoot = new crypto.X509Certificate(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM);

  const rootSha256 = rootCert
    ? crypto.createHash("sha256").update(rootCert.raw).digest("hex").toUpperCase()
    : "";
  const rootOk = Boolean(rootCert && rootCert.raw.equals(pinnedRoot.raw) && rootSha256 === PINNED_ROOT_SHA256);
  checks.push({
    id: "pinned_root_ca",
    passed: rootOk,
    technical: `root sha256=${rootSha256}`,
  });

  // 3. Chain signatures & validity
  const nowMs = Date.now();
  const withinValidity = (c) =>
    c && nowMs >= Date.parse(c.validFrom) && nowMs <= Date.parse(c.validTo);
  const chainOk = Boolean(
    leafCert &&
      interCert &&
      rootCert &&
      withinValidity(leafCert) &&
      withinValidity(interCert) &&
      withinValidity(rootCert) &&
      leafCert.verify(interCert.publicKey) &&
      interCert.verify(rootCert.publicKey) &&
      rootCert.verify(rootCert.publicKey),
  );
  checks.push({
    id: "x5c_chain_and_validity",
    passed: chainOk,
    technical: `leaf->inter->root verified=${chainOk}`,
  });

  // 4. RS256 JWS signature
  const sigOk = Boolean(
    leafCert &&
      crypto.verify("RSA-SHA256", signingInput, leafCert.publicKey, sigBytes),
  );
  checks.push({
    id: "jwt_rs256_signature",
    passed: sigOk,
    technical: `RS256 signature verified=${sigOk}`,
  });

  // 5. Claims
  const nowSec = Math.floor(nowMs / 1000);
  const issAudOk = claims.iss === EXPECTED_ISSUER && claims.aud === expectedAudience;
  checks.push({
    id: "issuer_and_audience",
    passed: issAudOk,
    technical: `iss=${claims.iss}, aud=${claims.aud}`,
  });

  const timeOk =
    typeof claims.nbf === "number" &&
    typeof claims.iat === "number" &&
    typeof claims.exp === "number" &&
    nowSec + 60 >= claims.nbf &&
    nowSec + 60 >= claims.iat &&
    nowSec - 60 < claims.exp;
  checks.push({
    id: "token_lifetime",
    passed: timeOk,
    technical: `nbf=${claims.nbf}, iat=${claims.iat}, exp=${claims.exp}`,
  });

  const supportAttrs = claims.submods?.confidential_space?.support_attributes || [];
  const postureOk =
    claims.swname === "CONFIDENTIAL_SPACE" &&
    claims.dbgstat === "disabled-since-boot" &&
    claims.secboot === true &&
    Array.isArray(supportAttrs) &&
    supportAttrs.includes("STABLE");
  checks.push({
    id: "confidential_space_posture",
    passed: postureOk,
    technical: `swname=${claims.swname}, dbgstat=${claims.dbgstat}, secboot=${claims.secboot}, support=${JSON.stringify(supportAttrs)}`,
  });

  const hwOk = ALLOWED_HWMODELS.has(claims.hwmodel);
  checks.push({
    id: "hardware_tee_model",
    passed: hwOk,
    technical: `hwmodel=${claims.hwmodel}`,
  });

  const imageDigest = claims.submods?.container?.image_digest || "";
  const digestOk =
    expectedDigests.size > 0 ? expectedDigests.has(imageDigest) : /^sha256:[0-9a-f]{64}$/.test(imageDigest);
  checks.push({
    id: "container_image_digest",
    passed: digestOk,
    technical: `image_digest=${imageDigest}`,
  });

  const envOverride = claims.submods?.container?.env_override || {};
  const overrideKeys = Object.keys(envOverride);
  const envOk = overrideKeys.every((k) => ALLOWED_ENV_OVERRIDES.has(k));
  checks.push({
    id: "container_env_override",
    passed: envOk,
    technical: `env_override=${JSON.stringify(overrideKeys)}`,
  });

  const recomputedKeysDigest = sha256HexLower(
    canonicalJson({
      egress: String(payload.keys?.egress || "").toLowerCase(),
      tree: String(payload.keys?.tree || "").toLowerCase(),
    }),
  );
  const nonces = Array.isArray(claims.eat_nonce)
    ? claims.eat_nonce
    : typeof claims.eat_nonce === "string"
      ? [claims.eat_nonce]
      : [];
  const nonceOk =
    nonces.includes(recomputedKeysDigest) && nonces.includes(peerSpkiSha256);
  checks.push({
    id: "eat_nonce_binding",
    passed: nonceOk,
    technical: `keysDigest=${recomputedKeysDigest}, tlsSpkiDigest=${peerSpkiSha256}`,
  });

  const allOk = checks.every((c) => c.passed);
  console.log(JSON.stringify({ ok: allOk, hwmodel: claims.hwmodel, imageDigest, checks }, null, 2));
  process.exit(allOk ? 0 : 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
