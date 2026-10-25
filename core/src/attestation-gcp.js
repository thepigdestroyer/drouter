/**
 * Google Cloud Confidential Space Launcher Attestation Client (G3).
 *
 * Requests a PKI attestation token over the Confidential Space launcher Unix domain socket
 * (`/run/container_launcher/teeserver.sock` via `POST http://localhost/v1/token`), binding:
 * 1. `keysDigest` = lowercase hex SHA-256 of `canonicalJson({ egress: <raw ed25519 pub hex>, tree: <raw ed25519 pub hex> })`
 * 2. `tlsSpkiDigest` = lowercase hex SHA-256 of the TLS certificate's SubjectPublicKeyInfo DER.
 *
 * Verifies the returned JWT's `exp` and `eat_nonce` claims against the current keys and TLS SPKI,
 * refreshes every 45 minutes (2,700,000 ms) or whenever the token is expired, and exports
 * `getAttestation()` returning `{ token, keys: { egress, tree }, keysDigest, tlsSpkiSha256, tlsCertPem, expiresAtSec, refreshedAtSec }`.
 *
 * Official documentation:
 * https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#retrieve_attestation_tokens
 */

import crypto from "node:crypto";
import http from "node:http";
import { canonicalJson, sha256Hex } from "./canonical.js";

export const DEFAULT_LAUNCHER_SOCKET_PATH = "/run/container_launcher/teeserver.sock";
export const DEFAULT_ATTESTATION_AUDIENCE = "https://drouter-demo.vercel.app/deroute-core";
export const DEFAULT_REFRESH_INTERVAL_MS = 45 * 60 * 1000; // 45 minutes
export const LAUNCHER_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Computes `keysDigest` = lowercase 64-char hex SHA-256 of
 * `canonicalJson({ egress: <raw ed25519 pub hex>, tree: <raw ed25519 pub hex> })`.
 *
 * Accepts either `{ egress: "<64-hex>", tree: "<64-hex>" }` or a full keyRing from `keys.js`.
 */
export function computeKeysDigest(keysOrRing) {
  if (!keysOrRing || typeof keysOrRing !== "object") {
    throw new Error("computeKeysDigest requires a keys object or keyRing");
  }

  const extractRawHex = (entry) => {
    if (typeof entry === "string") {
      return entry.trim().replace(/^0x/i, "").toLowerCase();
    }
    if (entry && typeof entry === "object") {
      const candidate = entry.publicKeyHex ?? entry.rawHex;
      if (typeof candidate === "string") {
        return candidate.trim().replace(/^0x/i, "").toLowerCase();
      }
    }
    return "";
  };

  const egress = extractRawHex(
    keysOrRing.egress ?? keysOrRing["egress-signing"] ?? keysOrRing.egressSigning,
  );
  const tree = extractRawHex(
    keysOrRing.tree ?? keysOrRing["tree-signing"] ?? keysOrRing.treeSigning,
  );

  if (!/^[0-9a-f]{64}$/.test(egress) || !/^[0-9a-f]{64}$/.test(tree)) {
    throw new Error(
      "computeKeysDigest requires 64-character hex Ed25519 public keys for egress and tree",
    );
  }

  return {
    keys: { egress, tree },
    keysDigest: sha256Hex(canonicalJson({ egress, tree })),
  };
}

/**
 * Extracts `{ tlsSpkiSha256, tlsCertPem }` from a TLS certificate (PEM/DER), public key, or SPKI digest.
 */
export function extractTlsMaterial(tlsInput, explicitCertPem) {
  let tlsCertPem = null;
  if (typeof explicitCertPem === "string" && explicitCertPem.includes("BEGIN CERTIFICATE")) {
    const cert = new crypto.X509Certificate(explicitCertPem.trim());
    tlsCertPem = cert.toString().trim();
  }

  if (typeof tlsInput === "string") {
    const trimmed = tlsInput.trim();
    const cleanHex = trimmed.replace(/^0x/i, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(cleanHex)) {
      if (tlsCertPem) {
        const cert = new crypto.X509Certificate(tlsCertPem);
        const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
        const fromCert = sha256Hex(new Uint8Array(spkiDer));
        if (fromCert !== cleanHex) {
          throw new Error("Provided tlsCertPem SPKI digest does not match tlsSpkiSha256");
        }
      }
      return { tlsSpkiSha256: cleanHex, tlsCertPem };
    }
    if (trimmed.includes("BEGIN CERTIFICATE")) {
      const cert = new crypto.X509Certificate(trimmed);
      const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
      return {
        tlsSpkiSha256: sha256Hex(new Uint8Array(spkiDer)),
        tlsCertPem: cert.toString().trim(),
      };
    }
    if (trimmed.includes("BEGIN PUBLIC KEY")) {
      const pubKey = crypto.createPublicKey({ key: trimmed, format: "pem" });
      const spkiDer = pubKey.export({ type: "spki", format: "der" });
      return {
        tlsSpkiSha256: sha256Hex(new Uint8Array(spkiDer)),
        tlsCertPem,
      };
    }
  }

  if (tlsInput instanceof Uint8Array || Buffer.isBuffer(tlsInput)) {
    try {
      const cert = new crypto.X509Certificate(tlsInput);
      const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
      return {
        tlsSpkiSha256: sha256Hex(new Uint8Array(spkiDer)),
        tlsCertPem: cert.toString().trim(),
      };
    } catch {
      const pubKey = crypto.createPublicKey({
        key: Buffer.from(tlsInput),
        format: "der",
        type: "spki",
      });
      const spkiDer = pubKey.export({ type: "spki", format: "der" });
      return {
        tlsSpkiSha256: sha256Hex(new Uint8Array(spkiDer)),
        tlsCertPem,
      };
    }
  }

  if (tlsInput && typeof tlsInput === "object" && typeof tlsInput.export === "function") {
    const spkiDer = tlsInput.export({ type: "spki", format: "der" });
    return {
      tlsSpkiSha256: sha256Hex(new Uint8Array(spkiDer)),
      tlsCertPem,
    };
  }

  throw new Error(
    "computeTlsSpkiDigest requires a TLS certificate (PEM/DER), public key, or 64-char hex SPKI SHA-256 digest",
  );
}

/**
 * Computes `tlsSpkiDigest` = lowercase 64-char hex SHA-256 of the TLS certificate's
 * SubjectPublicKeyInfo (SPKI) DER.
 */
export function computeTlsSpkiDigest(tlsInput) {
  return extractTlsMaterial(tlsInput).tlsSpkiSha256;
}

/**
 * Decodes and validates the payload of a 3-part JWT returned by the launcher,
 * checking `exp` and `eat_nonce` against the expected two distinct nonces.
 */
export function validateLauncherJwtClaims(token, expectedNonces, nowSec) {
  if (typeof token !== "string") {
    throw new Error("Confidential Space launcher did not return a JWT string");
  }
  const parts = token.trim().split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new Error("Confidential Space launcher did not return a 3-part JWT");
  }

  let claims;
  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    claims = JSON.parse(json);
  } catch {
    throw new Error("Confidential Space launcher returned a JWT with an unparseable payload");
  }

  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("Confidential Space launcher JWT payload must be a JSON object");
  }

  if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
    throw new Error("Confidential Space launcher JWT is missing a numeric exp claim");
  }

  if (claims.exp <= nowSec) {
    throw new Error(
      `Confidential Space launcher returned an already-expired JWT (exp=${claims.exp}, now=${nowSec})`,
    );
  }

  const rawEatNonce = claims.eat_nonce;
  const nonceList = Array.isArray(rawEatNonce)
    ? rawEatNonce.filter((n) => typeof n === "string")
    : typeof rawEatNonce === "string"
      ? [rawEatNonce]
      : [];

  const uniqueNonces = new Set(nonceList);
  if (
    expectedNonces.length !== 2 ||
    expectedNonces[0] === expectedNonces[1] ||
    nonceList.length !== 2 ||
    uniqueNonces.size !== 2 ||
    !uniqueNonces.has(expectedNonces[0]) ||
    !uniqueNonces.has(expectedNonces[1])
  ) {
    throw new Error(
      `Confidential Space launcher JWT eat_nonce (${JSON.stringify(rawEatNonce)}) does not match expected nonces (${JSON.stringify(expectedNonces)})`,
    );
  }

  return {
    claims,
    expiresAtSec: claims.exp,
  };
}

/**
 * Requests a PKI attestation token from the Confidential Space launcher over Unix domain socket:
 * `POST http://localhost/v1/token` with `{ audience, token_type: "PKI", nonces: [keysDigest, tlsSpkiDigest] }`.
 */
export function requestLauncherPkiToken({
  socketPath = process.env.TEE_LAUNCHER_SOCKET_PATH || DEFAULT_LAUNCHER_SOCKET_PATH,
  audience = process.env.CORE_ATTESTATION_AUDIENCE || DEFAULT_ATTESTATION_AUDIENCE,
  nonces,
  timeoutMs = LAUNCHER_REQUEST_TIMEOUT_MS,
}) {
  if (!Array.isArray(nonces) || nonces.length !== 2) {
    return Promise.reject(
      new Error("requestLauncherPkiToken requires exactly two nonces: [keysDigest, tlsSpkiDigest]"),
    );
  }
  for (const nonce of nonces) {
    if (typeof nonce !== "string" || nonce.length < 10 || nonce.length > 74) {
      return Promise.reject(
        new Error("Each Confidential Space nonce must be a string between 10 and 74 bytes"),
      );
    }
  }
  if (nonces[0] === nonces[1]) {
    return Promise.reject(
      new Error("Confidential Space nonces (keysDigest and tlsSpkiDigest) must be distinct"),
    );
  }

  const requestBody = JSON.stringify({
    audience,
    token_type: "PKI",
    nonces,
  });

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const req = http.request(
      {
        socketPath,
        host: "localhost",
        path: "/v1/token",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(requestBody, "utf8"),
          Accept: "text/plain, application/jwt, application/json",
        },
      },
      (res) => {
        const chunks = [];
        let total = 0;

        res.on("data", (chunk) => {
          if (settled) return;
          total += chunk.length;
          if (total > 262_144) {
            res.destroy();
            fail(new Error("Launcher token response exceeded 256 KiB limit"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", (err) => fail(err));

        res.on("end", () => {
          if (settled) return;
          const rawText = Buffer.concat(chunks).toString("utf8").trim();
          if (res.statusCode !== 200) {
            fail(
              new Error(
                `Confidential Space launcher returned HTTP ${res.statusCode}: ${rawText.slice(0, 200)}`,
              ),
            );
            return;
          }

          let token = rawText;
          if (rawText.startsWith("{")) {
            try {
              const parsed = JSON.parse(rawText);
              if (typeof parsed.token === "string") {
                token = parsed.token.trim();
              }
            } catch {
              // treat as raw token string
            }
          }

          if (!token || token.split(".").length !== 3) {
            fail(new Error("Confidential Space launcher did not return a 3-part JWT"));
            return;
          }

          settled = true;
          resolve(token);
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error("Confidential Space launcher token request timed out"));
    });

    req.on("error", (err) => fail(err));
    req.write(requestBody);
    req.end();
  });
}

let activeManager = null;

/**
 * Creates a stateful Confidential Space attestation manager that fetches a PKI token
 * at boot and refreshes it every 45 minutes (`refreshIntervalMs`) or before `exp`.
 */
export function createAttestationManager(options = {}) {
  const socketPath =
    options.socketPath || process.env.TEE_LAUNCHER_SOCKET_PATH || DEFAULT_LAUNCHER_SOCKET_PATH;
  const audience =
    options.audience || process.env.CORE_ATTESTATION_AUDIENCE || DEFAULT_ATTESTATION_AUDIENCE;
  const refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS;
  const nowSecFn =
    typeof options.nowSec === "function"
      ? options.nowSec
      : () => Math.floor(Date.now() / 1000);

  const { keys, keysDigest } = computeKeysDigest(options.keys ?? options.keyRing);
  const { tlsSpkiSha256, tlsCertPem } = extractTlsMaterial(
    options.tlsCert ?? options.tlsCertPem ?? options.tlsSpkiSha256 ?? options.tlsSpkiDigest,
    options.tlsCertPem,
  );

  if (keysDigest === tlsSpkiSha256) {
    throw new Error("keysDigest and tlsSpkiSha256 must be distinct nonces");
  }

  let currentSnapshot = null;
  let inflightRefresh = null;
  let timer = null;

  async function refresh() {
    if (inflightRefresh) {
      return inflightRefresh;
    }
    inflightRefresh = (async () => {
      try {
        const expectedNonces = [keysDigest, tlsSpkiSha256];
        const token = await requestLauncherPkiToken({
          socketPath,
          audience,
          nonces: expectedNonces,
          timeoutMs: options.timeoutMs ?? LAUNCHER_REQUEST_TIMEOUT_MS,
        });
        const refreshedAtSec = nowSecFn();
        const { expiresAtSec } = validateLauncherJwtClaims(
          token,
          expectedNonces,
          refreshedAtSec,
        );
        const snapshot = {
          token,
          keys: {
            egress: keys.egress,
            tree: keys.tree,
          },
          keysDigest,
          tlsSpkiSha256,
          tlsCertPem,
          expiresAtSec,
          refreshedAtSec,
        };
        currentSnapshot = snapshot;
        return snapshot;
      } finally {
        inflightRefresh = null;
      }
    })();
    return inflightRefresh;
  }

  function startAutoRefresh() {
    if (timer) return;
    if (refreshIntervalMs > 0) {
      timer = setInterval(() => {
        refresh().catch(() => {
          // Keep existing snapshot until next retry or manual getAttestation() call
        });
      }, refreshIntervalMs);
      if (typeof timer.unref === "function") {
        timer.unref();
      }
    }
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function isSnapshotValidAt(snapshot, now) {
    if (!snapshot) return false;
    if (snapshot.keysDigest !== keysDigest || snapshot.tlsSpkiSha256 !== tlsSpkiSha256) {
      return false;
    }
    if (typeof snapshot.expiresAtSec !== "number" || now >= snapshot.expiresAtSec) {
      return false;
    }
    const maxAgeSec = Math.floor(refreshIntervalMs / 1000);
    if (maxAgeSec > 0 && now - snapshot.refreshedAtSec >= maxAgeSec) {
      return false;
    }
    return true;
  }

  async function getAttestation(getOptions = {}) {
    const forceRefresh = Boolean(getOptions.forceRefresh);
    const now = nowSecFn();

    if (forceRefresh || !isSnapshotValidAt(currentSnapshot, now)) {
      await refresh();
    }
    startAutoRefresh();
    return currentSnapshot;
  }

  return {
    initOptions: { ...options },
    keys,
    keysDigest,
    tlsSpkiSha256,
    tlsCertPem,
    refresh,
    getAttestation,
    startAutoRefresh,
    stop,
  };
}

/**
 * Configures the singleton Confidential Space attestation manager.
 */
export function configureAttestation(options) {
  if (activeManager) {
    activeManager.stop();
  }
  activeManager = createAttestationManager(options);
  return activeManager;
}

/**
 * Resets the singleton attestation manager (for unit tests).
 */
export function resetAttestationForTests() {
  if (activeManager) {
    activeManager.stop();
    activeManager = null;
  }
}

/**
 * Returns `{ token, keys: { egress, tree }, keysDigest, tlsSpkiSha256, tlsCertPem, expiresAtSec, refreshedAtSec }`.
 * Fetches a fresh PKI token from `/run/container_launcher/teeserver.sock` on first call,
 * when the cached token is older than 45 minutes or expired, or when keys / TLS cert change.
 */
export async function getAttestation(options = {}) {
  const hasKeyOption = Boolean(options.keys || options.keyRing);
  const hasTlsOption = Boolean(
    options.tlsCert || options.tlsCertPem || options.tlsSpkiSha256 || options.tlsSpkiDigest,
  );

  if (hasKeyOption || hasTlsOption) {
    if (!activeManager || options.reconfigure) {
      configureAttestation({ ...(activeManager?.initOptions ?? {}), ...options });
    } else {
      let needsReconfigure = false;
      if (hasKeyOption) {
        const { keysDigest: nextKeysDigest } = computeKeysDigest(options.keys ?? options.keyRing);
        if (nextKeysDigest !== activeManager.keysDigest) {
          needsReconfigure = true;
        }
      }
      if (hasTlsOption) {
        const nextTls = extractTlsMaterial(
          options.tlsCert ?? options.tlsCertPem ?? options.tlsSpkiSha256 ?? options.tlsSpkiDigest,
          options.tlsCertPem,
        );
        if (
          nextTls.tlsSpkiSha256 !== activeManager.tlsSpkiSha256 ||
          (nextTls.tlsCertPem && nextTls.tlsCertPem !== activeManager.tlsCertPem)
        ) {
          needsReconfigure = true;
        }
      }
      if (needsReconfigure) {
        configureAttestation({ ...activeManager.initOptions, ...options });
      }
    }
  }

  if (!activeManager) {
    throw new Error(
      "Confidential Space attestation manager is not initialized; call configureAttestation({ keys, tlsCert }) or pass options to getAttestation()",
    );
  }
  return activeManager.getAttestation(options);
}
