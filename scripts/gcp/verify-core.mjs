#!/usr/bin/env node
/**
 * Independent command-line verifier for the deRoute Google Cloud Confidential Space VM (G7).
 *
 * Connects directly to `https://<CORE_HOST>:8443/attestation`, extracts the peer TLS certificate's
 * SubjectPublicKeyInfo (SPKI) DER, verifies the Google Cloud Confidential Space PKI token against
 * the pinned Google Confidential Space Root CA, checks all G4 claims, and prints the check table.
 *
 * Refuses to run without `CORE_IMAGE_DIGESTS`.
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
const ALLOWED_ENV_OVERRIDES = new Set(["CORE_KEY_SOURCE", "CORE_PUBLIC_ORIGIN", "CORE_SECRETS_SOURCE"]);

function ensureReflectMetadata() {
  if (
    typeof Reflect.getMetadata === "function" &&
    typeof Reflect.getOwnMetadata === "function" &&
    typeof Reflect.defineMetadata === "function" &&
    typeof Reflect.metadata === "function"
  ) {
    return;
  }
  const store = new WeakMap();
  const getMap = (target, key, create) => {
    if ((typeof target !== "object" || target === null) && typeof target !== "function") {
      return undefined;
    }
    let tm = store.get(target);
    if (!tm) {
      if (!create) return undefined;
      tm = new Map();
      store.set(target, tm);
    }
    let pm = tm.get(key);
    if (!pm && create) {
      pm = new Map();
      tm.set(key, pm);
    }
    return pm;
  };
  const defs = {
    defineMetadata: (k, v, t, p) => {
      const m = getMap(t, p, true);
      if (m) m.set(k, v);
    },
    getOwnMetadata: (k, t, p) => {
      const m = getMap(t, p, false);
      return m ? m.get(k) : undefined;
    },
    getMetadata: (k, t, p) => {
      let cur = t;
      while (cur && (typeof cur === "object" || typeof cur === "function")) {
        const own = Reflect.getOwnMetadata(k, cur, p);
        if (own !== undefined) return own;
        cur = Object.getPrototypeOf(cur);
      }
      return undefined;
    },
    metadata: (k, v) => (t, p) => Reflect.defineMetadata(k, v, t, p),
  };
  for (const [name, fn] of Object.entries(defs)) {
    if (typeof Reflect[name] !== "function") {
      Object.defineProperty(Reflect, name, {
        value: fn,
        configurable: true,
        writable: true,
        enumerable: false,
      });
    }
  }
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

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
  if (!clean || /[/?#@\s]/.test(clean)) return null;
  const colonCount = (clean.match(/:/g) || []).length;
  if (colonCount > 1 && !clean.startsWith("[")) return null;
  try {
    const parsed = new URL(`https://${clean}`);
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    if (!hostname || !/^[A-Za-z0-9.:-]+$/.test(hostname)) return null;
    const port = parsed.port ? Number(parsed.port) : 8443;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host: hostname, port };
  } catch {
    return null;
  }
}

function isSha256WithRsaEncryptionCert(cert) {
  const sigAlg = cert.signatureAlgorithm;
  const hashName =
    typeof sigAlg?.hash === "string"
      ? sigAlg.hash
      : typeof sigAlg?.hash?.name === "string"
        ? sigAlg.hash.name
        : "";
  if (sigAlg?.name !== "RSASSA-PKCS1-v1_5" || hashName.toUpperCase() !== "SHA-256") {
    return false;
  }
  const pubAlg = cert.publicKey.algorithm;
  return (
    pubAlg?.name === "RSASSA-PKCS1-v1_5" &&
    typeof pubAlg.modulusLength === "number" &&
    pubAlg.modulusLength >= 2048
  );
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
        const peerCertRaw = Buffer.from(peer.raw);
        const x509Peer = new crypto.X509Certificate(peerCertRaw);
        const spkiDer = x509Peer.publicKey.export({ type: "spki", format: "der" });
        const peerSpkiSha256 = sha256HexLower(spkiDer);

        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            resolve({ statusCode: res.statusCode, payload, peerCertRaw, peerSpkiSha256 });
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
    console.error(
      "Usage: CORE_HOST=<ip>:8443 CORE_IMAGE_DIGESTS=sha256:<digest> node scripts/gcp/verify-core.mjs",
    );
    process.exit(1);
  }

  const expectedDigests = new Set(
    String(process.env.CORE_IMAGE_DIGESTS || "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => /^sha256:[0-9a-f]{64}$/.test(s)),
  );
  if (expectedDigests.size === 0) {
    console.error(
      "Error: CORE_IMAGE_DIGESTS is required and must contain at least one sha256:<64-hex> digest.",
    );
    process.exit(1);
  }

  const expectedAudience = process.env.CORE_ATTESTATION_AUDIENCE || DEFAULT_AUDIENCE;

  ensureReflectMetadata();
  const x509 = await import("@peculiar/x509");

  const { statusCode, payload, peerCertRaw, peerSpkiSha256 } =
    await fetchAttestationWithPeerCert(target);
  if (statusCode !== 200 || !isPlainObject(payload)) {
    console.error(`Error: /attestation returned HTTP ${statusCode}`);
    process.exit(1);
  }

  const token = String(payload.token || "").trim();
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
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
  const headerOk =
    isPlainObject(header) &&
    isPlainObject(claims) &&
    header.alg === "RS256" &&
    header.crit === undefined &&
    x5c.length === 3 &&
    x5c.every((c) => typeof c === "string" && c.length > 0);
  checks.push({
    id: "jwt_header_and_x5c",
    passed: headerOk,
    technical: `alg=${header?.alg}, crit=${header?.crit}, x5c.length=${x5c.length}`,
  });

  // 2. Root CA match
  const leafCert = x5c[0] ? new crypto.X509Certificate(Buffer.from(x5c[0], "base64")) : null;
  const interCert = x5c[1] ? new crypto.X509Certificate(Buffer.from(x5c[1], "base64")) : null;
  const rootCert = x5c[2] ? new crypto.X509Certificate(Buffer.from(x5c[2], "base64")) : null;
  const pinnedRoot = new crypto.X509Certificate(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM);

  const rootSha256 = rootCert
    ? crypto.createHash("sha256").update(rootCert.raw).digest("hex").toUpperCase()
    : "";
  const rootOk = Boolean(
    rootCert && rootCert.raw.equals(pinnedRoot.raw) && rootSha256 === PINNED_ROOT_SHA256,
  );
  checks.push({
    id: "pinned_root_ca",
    passed: rootOk,
    technical: `root sha256=${rootSha256}`,
  });

  // 3. Chain signatures, BasicConstraints, pathLen, KeyUsage, sigAlg, and validity
  const nowMs = Date.now();
  let chainOk = false;
  if (leafCert && interCert && rootCert) {
    try {
      const pLeaf = new x509.X509Certificate(x5c[0]);
      const pInter = new x509.X509Certificate(x5c[1]);
      const pRoot = new x509.X509Certificate(x5c[2]);

      const leafTimeOk =
        nowMs >= pLeaf.notBefore.getTime() && nowMs <= pLeaf.notAfter.getTime();
      const interTimeOk =
        nowMs >= pInter.notBefore.getTime() && nowMs <= pInter.notAfter.getTime();
      const rootTimeOk =
        nowMs >= pRoot.notBefore.getTime() && nowMs <= pRoot.notAfter.getTime();

      const leafCaExt = pLeaf.getExtension(x509.BasicConstraintsExtension);
      const interCaExt = pInter.getExtension(x509.BasicConstraintsExtension);
      const rootCaExt = pRoot.getExtension(x509.BasicConstraintsExtension);

      const caConstraintsOk =
        Boolean(interCaExt && interCaExt.ca === true) &&
        Boolean(rootCaExt && rootCaExt.ca === true) &&
        (!leafCaExt || leafCaExt.ca === false) &&
        (rootCaExt?.pathLength === undefined ||
          (Number.isInteger(rootCaExt.pathLength) && rootCaExt.pathLength >= 1)) &&
        (interCaExt?.pathLength === undefined ||
          (Number.isInteger(interCaExt.pathLength) && interCaExt.pathLength >= 0));

      const rootKu = pRoot.getExtension(x509.KeyUsagesExtension);
      const interKu = pInter.getExtension(x509.KeyUsagesExtension);
      const leafKu = pLeaf.getExtension(x509.KeyUsagesExtension);
      const keyUsageOk =
        (!rootKu || (rootKu.usages & x509.KeyUsageFlags.keyCertSign) !== 0) &&
        (!interKu || (interKu.usages & x509.KeyUsageFlags.keyCertSign) !== 0) &&
        (!leafKu ||
          ((leafKu.usages & x509.KeyUsageFlags.digitalSignature) !== 0 &&
            (leafKu.usages & x509.KeyUsageFlags.keyCertSign) === 0));

      const certAlgorithmsOk =
        isSha256WithRsaEncryptionCert(pLeaf) &&
        isSha256WithRsaEncryptionCert(pInter) &&
        isSha256WithRsaEncryptionCert(pRoot);

      const issuerMatchOk =
        pLeaf.issuer === pInter.subject &&
        pInter.issuer === pRoot.subject &&
        pRoot.issuer === pRoot.subject;

      const sigsOk =
        leafCert.verify(interCert.publicKey) &&
        interCert.verify(rootCert.publicKey) &&
        rootCert.verify(rootCert.publicKey);

      chainOk =
        leafTimeOk &&
        interTimeOk &&
        rootTimeOk &&
        caConstraintsOk &&
        keyUsageOk &&
        certAlgorithmsOk &&
        issuerMatchOk &&
        sigsOk;
    } catch {
      chainOk = false;
    }
  }
  checks.push({
    id: "x5c_chain_and_validity",
    passed: chainOk,
    technical: `leaf->inter->root verified=${chainOk}`,
  });

  // 4. RS256 JWS signature
  const sigOk = Boolean(
    headerOk &&
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
    Number.isFinite(claims.nbf) &&
    Number.isFinite(claims.iat) &&
    Number.isFinite(claims.exp) &&
    claims.nbf <= claims.exp &&
    claims.iat <= claims.exp &&
    nowSec + 60 >= claims.nbf &&
    nowSec + 60 >= claims.iat &&
    nowSec - 60 < claims.exp;
  checks.push({
    id: "token_lifetime",
    passed: timeOk,
    technical: `nbf=${claims.nbf}, iat=${claims.iat}, exp=${claims.exp}`,
  });

  const submods = isPlainObject(claims.submods) ? claims.submods : null;
  const csSubmod = isPlainObject(submods?.confidential_space)
    ? submods.confidential_space
    : null;
  const supportAttrs = Array.isArray(csSubmod?.support_attributes)
    ? csSubmod.support_attributes
    : [];
  const postureOk =
    claims.swname === "CONFIDENTIAL_SPACE" &&
    claims.dbgstat === "disabled-since-boot" &&
    claims.secboot === true &&
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

  const containerSubmod = isPlainObject(submods?.container) ? submods.container : null;
  const imageDigest =
    typeof containerSubmod?.image_digest === "string" ? containerSubmod.image_digest : "";
  const digestOk =
    /^sha256:[0-9a-f]{64}$/.test(imageDigest) &&
    expectedDigests.size > 0 &&
    expectedDigests.has(imageDigest);
  checks.push({
    id: "container_image_digest",
    passed: digestOk,
    technical: `image_digest=${imageDigest}`,
  });

  const envOverride =
    containerSubmod?.env_override === undefined
      ? {}
      : isPlainObject(containerSubmod.env_override)
        ? containerSubmod.env_override
        : null;
  const overrideKeys = envOverride ? Object.keys(envOverride) : [];
  const envOk =
    envOverride !== null &&
    overrideKeys.every(
      (k) => ALLOWED_ENV_OVERRIDES.has(k) && typeof envOverride[k] === "string",
    );
  checks.push({
    id: "container_env_override",
    passed: envOk,
    technical: `env_override=${JSON.stringify(overrideKeys)}`,
  });

  const egressHex = String(payload.keys?.egress || "").trim().toLowerCase();
  const treeHex = String(payload.keys?.tree || "").trim().toLowerCase();
  const validKeysFormat = /^[0-9a-f]{64}$/.test(egressHex) && /^[0-9a-f]{64}$/.test(treeHex);
  const recomputedKeysDigest = validKeysFormat
    ? sha256HexLower(canonicalJson({ egress: egressHex, tree: treeHex }))
    : "";

  const reportedTlsSpki = String(payload.tlsSpkiSha256 || "").trim().toLowerCase();
  const reportedKeysDigest = String(payload.keysDigest || "").trim().toLowerCase();
  let certPemMatchesPeer = true;
  if (typeof payload.tlsCertPem === "string" && payload.tlsCertPem.trim().length > 0) {
    try {
      const parsedCert = new crypto.X509Certificate(payload.tlsCertPem.trim());
      certPemMatchesPeer = parsedCert.raw.equals(peerCertRaw);
    } catch {
      certPemMatchesPeer = false;
    }
  }

  const nonces = Array.isArray(claims.eat_nonce)
    ? claims.eat_nonce.filter((n) => typeof n === "string")
    : typeof claims.eat_nonce === "string"
      ? [claims.eat_nonce]
      : [];
  const uniqueNonces = new Set(nonces);
  const nonceOk =
    validKeysFormat &&
    certPemMatchesPeer &&
    recomputedKeysDigest.length === 64 &&
    recomputedKeysDigest !== peerSpkiSha256 &&
    (!reportedKeysDigest || reportedKeysDigest === recomputedKeysDigest) &&
    reportedTlsSpki === peerSpkiSha256 &&
    nonces.length === 2 &&
    uniqueNonces.size === 2 &&
    uniqueNonces.has(recomputedKeysDigest) &&
    uniqueNonces.has(peerSpkiSha256);
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
