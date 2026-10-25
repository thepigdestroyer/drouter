import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { canonicalJson, sha256Hex } from "./canonical.js";
import { tlsCertPem, tlsSpkiSha256 } from "./tls.js";

export { tlsCertPem, tlsSpkiSha256 };

export const DEFAULT_TINFOIL_KEYS_DIR = "/run/tinfoil/keys";

export const ATTESTED_KEY_IDS = ["egress-signing", "tree-signing"];

export const VALID_KEY_SOURCES = ["tinfoil", "boot"];

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
 * Validates and returns the explicit platform-neutral key source (`"tinfoil"` or `"boot"`).
 * Refuses to start when `CORE_KEY_SOURCE` is missing or set to an unknown value.
 */
export function resolveKeySource(explicitSource = process.env.CORE_KEY_SOURCE) {
  const candidate = typeof explicitSource === "string" ? explicitSource.trim() : "";
  if (candidate !== "tinfoil" && candidate !== "boot") {
    throw new Error(
      `Invalid or missing CORE_KEY_SOURCE '${String(explicitSource ?? "")}': must be explicitly set to 'tinfoil' or 'boot'.`,
    );
  }
  return candidate;
}

function attachNonEnumerableSecretKey(target, secretKey) {
  Object.defineProperty(target, "secretKey", {
    value: secretKey,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return target;
}

/**
 * Loads or generates an Ed25519 key pair according to explicit `CORE_KEY_SOURCE`:
 * - `CORE_KEY_SOURCE=tinfoil`: loads the attested key pair mounted by Tinfoil at
 *   `/run/tinfoil/keys/<keyId>/private_key.pem` (RFC 8410 PKCS#8 PEM) and `public_key.pem` (SPKI PEM).
 *   Fails closed if either file is missing or malformed (never falls back to ephemeral keys).
 * - `CORE_KEY_SOURCE=boot`: generates a fresh Ed25519 key pair in memory at boot (never written to disk).
 */
export function loadAttestedKeyPair(keyId, optionsOrKeysDir, explicitKeySource) {
  if (!ATTESTED_KEY_IDS.includes(keyId)) {
    throw new Error(`Unsupported attested key id: ${keyId}`);
  }

  let keysDir;
  let keySource = explicitKeySource;
  if (typeof optionsOrKeysDir === "string") {
    keysDir = optionsOrKeysDir;
  } else if (optionsOrKeysDir && typeof optionsOrKeysDir === "object") {
    keysDir = optionsOrKeysDir.keysDir;
    if (optionsOrKeysDir.keySource !== undefined) {
      keySource = optionsOrKeysDir.keySource;
    }
  }

  const resolvedSource = resolveKeySource(
    keySource !== undefined ? keySource : process.env.CORE_KEY_SOURCE,
  );

  if (resolvedSource === "tinfoil") {
    const baseDir = keysDir || process.env.TINFOIL_KEYS_DIR || DEFAULT_TINFOIL_KEYS_DIR;
    const keyFolder = path.join(baseDir, keyId);
    const privPemPath = path.join(keyFolder, "private_key.pem");
    const pubPemPath = path.join(keyFolder, "public_key.pem");

    if (!fs.existsSync(privPemPath) || !fs.existsSync(pubPemPath)) {
      throw new Error(
        `Missing attested Ed25519 key PEM files for '${keyId}' in ${keyFolder} (CORE_KEY_SOURCE=tinfoil).`,
      );
    }

    const privPem = fs.readFileSync(privPemPath, "utf8");
    const privKeyObj = crypto.createPrivateKey({ key: privPem, format: "pem" });
    const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
    const expectedPrefix = Buffer.from(ED25519_PKCS8_PREFIX_HEX, "hex");
    if (
      privKeyObj.asymmetricKeyType !== "ed25519" ||
      pkcs8Der.length !== 48 ||
      !pkcs8Der.subarray(0, 16).equals(expectedPrefix)
    ) {
      throw new Error(`Invalid RFC 8410 PKCS#8 Ed25519 private key in ${privPemPath}`);
    }
    const secretKey = new Uint8Array(pkcs8Der.subarray(16, 48));
    const derivedPub = ed25519.getPublicKey(secretKey);
    const publicKeyHex = bytesToHex(derivedPub).toLowerCase();

    const pubPem = fs.readFileSync(pubPemPath, "utf8");
    const pubKeyObj = crypto.createPublicKey({ key: pubPem, format: "pem" });
    if (pubKeyObj.asymmetricKeyType !== "ed25519") {
      throw new Error(`Invalid Ed25519 public key type in ${pubPemPath}`);
    }
    const spkiDer = pubKeyObj.export({ type: "spki", format: "der" });
    const spkiHex = bytesToHex(new Uint8Array(spkiDer)).toLowerCase();
    const rawFromSpki = spkiHexToRawPublicKeyHex(spkiHex);
    if (rawFromSpki !== publicKeyHex) {
      throw new Error(`Public key mismatch between private_key.pem and public_key.pem for ${keyId}`);
    }

    return attachNonEnumerableSecretKey(
      {
        id: keyId,
        algorithm: "ed25519",
        format: "https://tinfoil.sh/key/spki/v1",
        publicKey: derivedPub,
        publicKeyHex,
        rawHex: publicKeyHex,
        spkiHex,
        source: "attested-mount",
        keySource: "tinfoil",
      },
      secretKey,
    );
  }

  // CORE_KEY_SOURCE=boot: generate Ed25519 key pair in memory at boot (never written to disk)
  const secretKey = new Uint8Array(crypto.randomBytes(32));
  const publicKey = ed25519.getPublicKey(secretKey);
  const publicKeyHex = bytesToHex(publicKey).toLowerCase();
  const spkiHex = rawPublicKeyToSpkiHex(publicKey);

  return attachNonEnumerableSecretKey(
    {
      id: keyId,
      algorithm: "ed25519",
      format: "https://tinfoil.sh/key/spki/v1",
      publicKey,
      publicKeyHex,
      rawHex: publicKeyHex,
      spkiHex,
      source: "ephemeral-boot",
      keySource: "boot",
    },
    secretKey,
  );
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

export function getKeyRing(optionsOrKeysDir) {
  let keysDir;
  let keySource;
  if (typeof optionsOrKeysDir === "string") {
    keysDir = optionsOrKeysDir;
  } else if (optionsOrKeysDir && typeof optionsOrKeysDir === "object") {
    keysDir = optionsOrKeysDir.keysDir;
    keySource = optionsOrKeysDir.keySource;
  }

  const effectiveSource = resolveKeySource(
    keySource !== undefined ? keySource : process.env.CORE_KEY_SOURCE,
  );

  if (
    !cachedKeyRing ||
    optionsOrKeysDir !== undefined ||
    cachedKeyRing.keySource !== effectiveSource
  ) {
    const egressSigning = loadAttestedKeyPair("egress-signing", {
      keysDir,
      keySource: effectiveSource,
    });
    const treeSigning = loadAttestedKeyPair("tree-signing", {
      keysDir,
      keySource: effectiveSource,
    });
    const ring = {
      keySource: effectiveSource,
      "egress-signing": egressSigning,
      "tree-signing": treeSigning,
      egressSigning,
      treeSigning,
    };
    if (optionsOrKeysDir === undefined) {
      cachedKeyRing = ring;
    }
    return ring;
  }
  return cachedKeyRing;
}

export function resetKeyRingForTests(optionsOrKeysDir) {
  cachedKeyRing = null;
  if (optionsOrKeysDir !== undefined) {
    cachedKeyRing = getKeyRing(optionsOrKeysDir);
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

/**
 * Computes `sha256(canonicalJson({ egress, tree }))` over the 64-hex Ed25519 public keys
 * so a platform attestation (Google Confidential Space token nonce, or a TDX quote report_data) can bind them.
 */
export function computePublicKeysBindingSha256(ring = getKeyRing()) {
  const egress = ring["egress-signing"].publicKeyHex;
  const tree = ring["tree-signing"].publicKeyHex;
  return sha256Hex(canonicalJson({ egress, tree }));
}

export function getPublicKeysResponse(ring = getKeyRing(), options = {}) {
  const egress = serializePublicKeyEntry(ring["egress-signing"]);
  const tree = serializePublicKeyEntry(ring["tree-signing"]);
  const keySource = ring.keySource ?? ring["egress-signing"].keySource;
  const keysDigest = sha256Hex(
    canonicalJson({
      egress: egress.publicKeyHex,
      tree: tree.publicKeyHex,
    }),
  );
  const resolvedTlsSpkiSha256 =
    typeof options.tlsSpkiSha256 === "string" && /^[0-9a-f]{64}$/.test(options.tlsSpkiSha256)
      ? options.tlsSpkiSha256
      : tlsSpkiSha256;
  return {
    ok: true,
    keySource,
    keysDigest,
    publicKeysSha256: keysDigest,
    bindingSha256: keysDigest,
    rawPublicKeysSha256: keysDigest,
    ...(keySource === "boot" ? { tlsSpkiSha256: resolvedTlsSpkiSha256 } : {}),
    keys: {
      "egress-signing": egress,
      "tree-signing": tree,
      egress: egress.publicKeyHex,
      tree: tree.publicKeyHex,
    },
    egress,
    tree,
    egressSigning: egress,
    treeSigning: tree,
  };
}
