import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

export const DEFAULT_TINFOIL_KEYS_DIR = "/run/tinfoil/keys";

export const ATTESTED_KEY_IDS = ["egress-signing", "tree-signing"];

/**
 * RFC 8410 SubjectPublicKeyInfo (SPKI) DER prefix for Ed25519 (12 bytes / 24 hex chars).
 * Full Ed25519 SPKI DER is 44 bytes (88 hex chars): this 12-byte ASN.1 header + 32-byte raw public key.
 * Matches Tinfoil `https://tinfoil.sh/key/spki/v1` `crypto_material` attestation format.
 */
export const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

/**
 * RFC 8410 PKCS#8 v1 PrivateKeyInfo DER prefix for Ed25519 (16 bytes / 32 hex chars).
 */
export const ED25519_PKCS8_PREFIX_HEX = "302e020100300506032b657004220420";

export function rawPublicKeyToSpkiHex(rawPublicKeyHexOrBytes) {
  const rawHex =
    typeof rawPublicKeyHexOrBytes === "string"
      ? rawPublicKeyHexOrBytes.replace(/^0x/i, "").toLowerCase()
      : bytesToHex(rawPublicKeyHexOrBytes).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(rawHex)) {
    throw new Error("Ed25519 raw public key must be 32 bytes (64 hex chars)");
  }
  return `${ED25519_SPKI_PREFIX_HEX}${rawHex}`;
}

export function spkiHexToRawPublicKeyHex(spkiHex) {
  const clean = String(spkiHex ?? "").replace(/^0x/i, "").toLowerCase();
  if (
    clean.length !== 88 ||
    !clean.startsWith(ED25519_SPKI_PREFIX_HEX) ||
    !/^[0-9a-f]{88}$/.test(clean)
  ) {
    throw new Error("Invalid Ed25519 SPKI DER hex (expected 44 bytes with RFC 8410 Ed25519 OID 1.3.101.112)");
  }
  return clean.slice(ED25519_SPKI_PREFIX_HEX.length);
}

/**
 * Loads an attested Ed25519 key pair mounted by Tinfoil at
 * `/run/tinfoil/keys/<keyId>/private_key.pem` (PKCS#8 PEM) and `public_key.pem` (SPKI PEM).
 * If the enclave mount is not present (e.g. local unit test environment), generates
 * an ephemeral Ed25519 key pair at boot and marks `source: "ephemeral-boot"`.
 */
export function loadAttestedKeyPair(keyId, keysDir = process.env.TINFOIL_KEYS_DIR || DEFAULT_TINFOIL_KEYS_DIR) {
  if (!ATTESTED_KEY_IDS.includes(keyId)) {
    throw new Error(`Unsupported attested key id: ${keyId}`);
  }

  const keyFolder = path.join(keysDir, keyId);
  const privPemPath = path.join(keyFolder, "private_key.pem");
  const pubPemPath = path.join(keyFolder, "public_key.pem");

  if (fs.existsSync(privPemPath)) {
    const privPem = fs.readFileSync(privPemPath, "utf8");
    const privKeyObj = crypto.createPrivateKey({ key: privPem, format: "pem" });
    const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
    if (pkcs8Der.length < 32) {
      throw new Error(`Invalid PKCS#8 Ed25519 private key in ${privPemPath}`);
    }
    const secretKey = new Uint8Array(pkcs8Der.subarray(pkcs8Der.length - 32));
    const derivedPub = ed25519.getPublicKey(secretKey);
    const publicKeyHex = bytesToHex(derivedPub).toLowerCase();

    let spkiHex = rawPublicKeyToSpkiHex(derivedPub);
    if (fs.existsSync(pubPemPath)) {
      const pubPem = fs.readFileSync(pubPemPath, "utf8");
      const pubKeyObj = crypto.createPublicKey({ key: pubPem, format: "pem" });
      const spkiDer = pubKeyObj.export({ type: "spki", format: "der" });
      const candidateSpkiHex = bytesToHex(new Uint8Array(spkiDer)).toLowerCase();
      const rawFromSpki = spkiHexToRawPublicKeyHex(candidateSpkiHex);
      if (rawFromSpki !== publicKeyHex) {
        throw new Error(`Public key mismatch between private_key.pem and public_key.pem for ${keyId}`);
      }
      spkiHex = candidateSpkiHex;
    }

    return {
      id: keyId,
      algorithm: "ed25519",
      format: "https://tinfoil.sh/key/spki/v1",
      secretKey,
      publicKey: derivedPub,
      publicKeyHex,
      rawHex: publicKeyHex,
      spkiHex,
      source: "attested-mount",
    };
  }

  // Outside the Tinfoil enclave (e.g. unit tests or local dev), generate a fresh in-memory key pair.
  const secretKey = new Uint8Array(crypto.randomBytes(32));
  const publicKey = ed25519.getPublicKey(secretKey);
  const publicKeyHex = bytesToHex(publicKey).toLowerCase();
  const spkiHex = rawPublicKeyToSpkiHex(publicKey);

  return {
    id: keyId,
    algorithm: "ed25519",
    format: "https://tinfoil.sh/key/spki/v1",
    secretKey,
    publicKey,
    publicKeyHex,
    rawHex: publicKeyHex,
    spkiHex,
    source: "ephemeral-boot",
  };
}

/**
 * Helper for tests to write valid RFC 8410 Ed25519 PKCS#8 and SPKI PEM files into a temp directory
 * matching Tinfoil's `/run/tinfoil/keys/<id>/` layout.
 */
export function writeTestAttestedKeyPemFiles(baseDir, keyId, seedHex) {
  const seedBytes = seedHex ? hexToBytes(seedHex) : new Uint8Array(crypto.randomBytes(32));
  if (seedBytes.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const pubBytes = ed25519.getPublicKey(seedBytes);
  const pkcs8Der = Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX_HEX, "hex"), Buffer.from(seedBytes)]);
  const spkiDer = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_HEX, "hex"), Buffer.from(pubBytes)]);

  const privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const pubKeyObj = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });

  const dir = path.join(baseDir, keyId);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "private_key.pem"),
    privKeyObj.export({ format: "pem", type: "pkcs8" }),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(dir, "public_key.pem"),
    pubKeyObj.export({ format: "pem", type: "spki" }),
    { mode: 0o644 },
  );
}

let cachedKeyRing = null;

export function getKeyRing(keysDir) {
  if (!cachedKeyRing || keysDir !== undefined) {
    const egressSigning = loadAttestedKeyPair("egress-signing", keysDir);
    const treeSigning = loadAttestedKeyPair("tree-signing", keysDir);
    const ring = {
      "egress-signing": egressSigning,
      "tree-signing": treeSigning,
      egressSigning,
      treeSigning,
    };
    if (keysDir === undefined) {
      cachedKeyRing = ring;
    }
    return ring;
  }
  return cachedKeyRing;
}

export function resetKeyRingForTests(keysDir) {
  cachedKeyRing = null;
  if (keysDir !== undefined) {
    cachedKeyRing = getKeyRing(keysDir);
  }
  return cachedKeyRing;
}

function serializePublicKeyEntry(kp) {
  return {
    id: kp.id,
    algorithm: kp.algorithm,
    format: kp.format,
    publicKeyHex: kp.publicKeyHex,
    rawHex: kp.rawHex,
    spkiHex: kp.spkiHex,
    source: kp.source,
  };
}

export function getPublicKeysResponse(ring = getKeyRing()) {
  const egress = serializePublicKeyEntry(ring["egress-signing"]);
  const tree = serializePublicKeyEntry(ring["tree-signing"]);
  return {
    ok: true,
    keys: {
      "egress-signing": egress,
      "tree-signing": tree,
    },
    egressSigning: egress,
    treeSigning: tree,
  };
}
