/**
 * Google Cloud Confidential Space Launcher Attestation Client (G3).
 *
 * Requests a PKI attestation token over the Confidential Space launcher Unix domain socket
 * (`/run/container_launcher/teeserver.sock` via `POST http://localhost/v1/token`), binding:
 * 1. `keysDigest` = lowercase hex SHA-256 of `canonicalJson({ egress: <raw ed25519 pub hex>, tree: <raw ed25519 pub hex> })`
 * 2. `tlsSpkiDigest` = lowercase hex SHA-256 of the TLS certificate's SubjectPublicKeyInfo DER.
 *
 * Refreshes every 45 minutes (2,700,000 ms) and exports `getAttestation()` returning
 * `{ token, keys: { egress, tree }, keysDigest, tlsSpkiSha256, refreshedAtSec }`.
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
 * Computes `tlsSpkiDigest` = lowercase 64-char hex SHA-256 of the TLS certificate's
 * SubjectPublicKeyInfo (SPKI) DER.
 *
 * Accepts:
 * - A precomputed 64-char hex SHA-256 string (`tlsSpkiSha256` / `tlsSpkiDigest`),
 * - An X.509 certificate PEM string or DER Buffer/Uint8Array,
 * - A Node `crypto.KeyObject` or SPKI PEM/DER.
 */
export function computeTlsSpkiDigest(tlsInput) {
  if (typeof tlsInput === "string") {
    const trimmed = tlsInput.trim();
    const cleanHex = trimmed.replace(/^0x/i, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(cleanHex)) {
      return cleanHex;
    }
    if (trimmed.includes("BEGIN CERTIFICATE")) {
      const cert = new crypto.X509Certificate(trimmed);
      const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
      return sha256Hex(new Uint8Array(spkiDer));
    }
    if (trimmed.includes("BEGIN PUBLIC KEY")) {
      const pubKey = crypto.createPublicKey({ key: trimmed, format: "pem" });
      const spkiDer = pubKey.export({ type: "spki", format: "der" });
      return sha256Hex(new Uint8Array(spkiDer));
    }
  }

  if (tlsInput instanceof Uint8Array || Buffer.isBuffer(tlsInput)) {
    try {
      const cert = new crypto.X509Certificate(tlsInput);
      const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
      return sha256Hex(new Uint8Array(spkiDer));
    } catch {
      // If raw SPKI DER bytes were passed directly:
      const pubKey = crypto.createPublicKey({ key: Buffer.from(tlsInput), format: "der", type: "spki" });
      const spkiDer = pubKey.export({ type: "spki", format: "der" });
      return sha256Hex(new Uint8Array(spkiDer));
    }
  }

  if (tlsInput && typeof tlsInput === "object" && typeof tlsInput.export === "function") {
    const spkiDer = tlsInput.export({ type: "spki", format: "der" });
    return sha256Hex(new Uint8Array(spkiDer));
  }

  throw new Error(
    "computeTlsSpkiDigest requires a TLS certificate (PEM/DER), public key, or 64-char hex SPKI SHA-256 digest",
  );
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
 * at boot and refreshes it every 45 minutes (`refreshIntervalMs`).
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
  const tlsSpkiSha256 = computeTlsSpkiDigest(
    options.tlsCert ?? options.tlsSpkiSha256 ?? options.tlsSpkiDigest,
  );

  let currentSnapshot = null;
  let inflightRefresh = null;
  let timer = null;

  async function refresh() {
    if (inflightRefresh) {
      return inflightRefresh;
    }
    inflightRefresh = (async () => {
      try {
        const token = await requestLauncherPkiToken({
          socketPath,
          audience,
          nonces: [keysDigest, tlsSpkiSha256],
          timeoutMs: options.timeoutMs ?? LAUNCHER_REQUEST_TIMEOUT_MS,
        });
        const refreshedAtSec = nowSecFn();
        currentSnapshot = {
          token,
          keys: {
            egress: keys.egress,
            tree: keys.tree,
          },
          keysDigest,
          tlsSpkiSha256,
          refreshedAtSec,
        };
        return currentSnapshot;
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

  async function getAttestation(getOptions = {}) {
    const forceRefresh = Boolean(getOptions.forceRefresh);
    const maxAgeSec = Math.floor(refreshIntervalMs / 1000);
    const now = nowSecFn();

    if (
      !currentSnapshot ||
      forceRefresh ||
      now - currentSnapshot.refreshedAtSec >= maxAgeSec
    ) {
      await refresh();
    }
    startAutoRefresh();
    return currentSnapshot;
  }

  return {
    keys,
    keysDigest,
    tlsSpkiSha256,
    refresh,
    getAttestation,
    startAutoRefresh,
    stop,
  };
}

/**
 * Configures the singleton Confidential Space attestation manager and performs an optional
 * immediate boot fetch.
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
 * Returns `{ token, keys: { egress, tree }, keysDigest, tlsSpkiSha256, refreshedAtSec }`.
 * Fetches a fresh PKI token from `/run/container_launcher/teeserver.sock` on first call
 * or when the cached token is older than 45 minutes.
 */
export async function getAttestation(options = {}) {
  if (options.keys || options.keyRing || options.tlsCert || options.tlsSpkiSha256) {
    if (!activeManager || options.reconfigure) {
      configureAttestation(options);
    }
  }
  if (!activeManager) {
    throw new Error(
      "Confidential Space attestation manager is not initialized; call configureAttestation({ keys, tlsCert }) or pass options to getAttestation()",
    );
  }
  return activeManager.getAttestation(options);
}
