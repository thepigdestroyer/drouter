import "reflect-metadata";
import crypto from "node:crypto";
import * as x509 from "@peculiar/x509";
import { sha256Hex } from "./canonical.js";

export const TLS_CERT_COMMON_NAME = "deroute-core";
export const TLS_CERT_VALIDITY_DAYS = 30;
export const TLS_CERT_VALIDITY_MS = TLS_CERT_VALIDITY_DAYS * 24 * 60 * 60 * 1000;

/**
 * Generates an ephemeral ECDSA P-256 key pair and a 30-day self-signed X.509 certificate
 * (`CN=deroute-core`) in memory using `@peculiar/x509@2.2.0` and WebCrypto.
 *
 * Security invariants:
 * - Private key is generated and held strictly in memory; it is never written to disk.
 * - `tlsSpkiSha256` is the lowercase 64-char hex SHA-256 of the SubjectPublicKeyInfo (SPKI) DER,
 *   which is bound into the Confidential Space attestation token's `eat_nonce`.
 */
export async function generateBootTlsCertificate(options = {}) {
  const commonName = options.commonName || TLS_CERT_COMMON_NAME;
  const nowMs = typeof options.nowMs === "number" ? options.nowMs : Date.now();
  const validityMs =
    typeof options.validityMs === "number" ? options.validityMs : TLS_CERT_VALIDITY_MS;

  const { privateKey: privateKeyObj, publicKey: publicKeyObj } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  const pkcs8Der = privateKeyObj.export({ type: "pkcs8", format: "der" });
  const spkiDer = publicKeyObj.export({ type: "spki", format: "der" });

  const webPrivateKey = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    pkcs8Der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const webPublicKey = await globalThis.crypto.subtle.importKey(
    "spki",
    spkiDer,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  const notBefore = new Date(nowMs);
  const notAfter = new Date(nowMs + validityMs);
  const serialNumber = crypto.randomBytes(16).toString("hex");

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber,
    name: `CN=${commonName}`,
    notBefore,
    notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: {
      privateKey: webPrivateKey,
      publicKey: webPublicKey,
    },
  });

  const certPemString = cert.toString("pem").trim();
  const privateKeyPemString = privateKeyObj
    .export({ type: "pkcs8", format: "pem" })
    .toString()
    .trim();

  // Verify the generated certificate's SPKI DER matches the key pair's SPKI DER
  const parsedX509 = new crypto.X509Certificate(certPemString);
  const certSpkiDer = parsedX509.publicKey.export({ type: "spki", format: "der" });
  const computedSpkiSha256 = sha256Hex(new Uint8Array(certSpkiDer));

  const material = {
    commonName,
    tlsCertPem: certPemString,
    certPem: certPemString,
    tlsSpkiSha256: computedSpkiSha256,
    spkiSha256: computedSpkiSha256,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  };

  Object.defineProperty(material, "privateKey", {
    value: privateKeyPemString,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(material, "tlsPrivateKey", {
    value: privateKeyPemString,
    enumerable: false,
    writable: false,
    configurable: false,
  });

  return material;
}

const bootTlsMaterial = await generateBootTlsCertificate();

export const tlsCertPem = bootTlsMaterial.tlsCertPem;
export const certPem = bootTlsMaterial.tlsCertPem;
export const privateKey = bootTlsMaterial.privateKey;
export const tlsPrivateKey = bootTlsMaterial.privateKey;
export const tlsKeyPem = bootTlsMaterial.privateKey;
export const tlsSpkiSha256 = bootTlsMaterial.tlsSpkiSha256;
export const spkiSha256 = bootTlsMaterial.tlsSpkiSha256;

export function getBootTlsMaterial() {
  return bootTlsMaterial;
}
