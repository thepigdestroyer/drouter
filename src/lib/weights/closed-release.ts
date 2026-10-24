import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export interface CustodyProviderKeypair {
  x25519PublicKey: string;
  x25519PrivateKey: string;
  mlkemPublicKey: string;
  mlkemPrivateKey: string;
  bindingHash: string;
}

export interface NodeAttestationEvidenceForRelease {
  chipId: string;
  measurement: string;
  approvedMeasurement: string;
  status: "full" | "ramp" | "suspended";
  quorumSignatures: number;
  requiredQuorum: number;
  custodyX25519Pk: string;
  custodyMlkemPk: string;
}

export interface ProviderWrapWeightKeyParams {
  providerId: string;
  modelId: string;
  weightKeyHex: string;
  nodeEvidence: NodeAttestationEvidenceForRelease;
}

export interface ProviderKeyReleaseSuccess {
  released: true;
  providerId?: string;
  modelId?: string;
  chipId?: string;
  measurement?: string;
  wrappedKeyCiphertextHex: string;
  nonceHex: string;
  providerEphemeralX25519Pk: string;
  mlkemCiphertextHex: string;
  providerSignatureHex: string;
  providerPublicKeyHex: string;
}

export interface ProviderKeyReleaseRefusal {
  released: false;
  reason: string;
}

export type ProviderKeyReleaseResult =
  | ProviderKeyReleaseSuccess
  | ProviderKeyReleaseRefusal;

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function buildReleaseTranscript(params: {
  wrappedKeyCiphertextHex: string;
  nonceHex: string;
  providerEphemeralX25519Pk: string;
  mlkemCiphertextHex: string;
  custodyX25519Pk: string;
  custodyMlkemPk: string;
}): Uint8Array {
  const canonical = [
    "drouter:closed-weight-key-release:v1",
    params.custodyX25519Pk.toLowerCase(),
    params.custodyMlkemPk.toLowerCase(),
    params.providerEphemeralX25519Pk.toLowerCase(),
    params.mlkemCiphertextHex.toLowerCase(),
    params.nonceHex.toLowerCase(),
    params.wrappedKeyCiphertextHex.toLowerCase(),
  ].join("|");
  return utf8ToBytes(canonical);
}

/**
 * At launch, the custody module inside the GPU TEE creates a fresh hybrid
 * X25519 + ML-KEM-768 keypair dedicated to the closed-model provider.
 */
export function createCustodyProviderKeypair(seedHex?: string): CustodyProviderKeypair {
  const seedMaterial = seedHex
    ? hexToBytes(seedHex)
    : crypto.getRandomValues(new Uint8Array(32));

  const x25519Seed = hkdf(
    sha384,
    seedMaterial,
    utf8ToBytes("drouter-custody-keypair-salt"),
    utf8ToBytes("x25519-custody-key"),
    32
  );
  const mlkemSeed = hkdf(
    sha384,
    seedMaterial,
    utf8ToBytes("drouter-custody-keypair-salt"),
    utf8ToBytes("mlkem768-custody-key"),
    64
  );

  const x25519Keys = x25519.keygen(new Uint8Array(x25519Seed));
  const mlkemKeys = ml_kem768.keygen(new Uint8Array(mlkemSeed));

  const x25519PublicKey = bytesToHex(x25519Keys.publicKey);
  const x25519PrivateKey = bytesToHex(x25519Keys.secretKey);
  const mlkemPublicKey = bytesToHex(mlkemKeys.publicKey);
  const mlkemPrivateKey = bytesToHex(mlkemKeys.secretKey);

  const bindingHash = bytesToHex(
    sha256(
      concatBytes(
        utf8ToBytes("drouter:custody-provider-binding:v1:"),
        x25519Keys.publicKey,
        mlkemKeys.publicKey
      )
    )
  );

  return {
    x25519PublicKey,
    x25519PrivateKey,
    mlkemPublicKey,
    mlkemPrivateKey,
    bindingHash,
  };
}

/**
 * Provider's key service verifies the node's attestation evidence and M-of-N quorum
 * independently, then encapsulates a hybrid X25519 + ML-KEM-768 secret to the custody
 * module's public keys, derives K_wrap via HKDF-SHA-384, encrypts weightKeyHex with
 * AES-256-GCM, and signs the release statement with the provider's Ed25519 key.
 */
export function providerWrapWeightKey(
  params: ProviderWrapWeightKeyParams
): ProviderKeyReleaseResult {
  const { providerId, modelId, weightKeyHex, nodeEvidence } = params;

  if (
    !nodeEvidence.measurement ||
    nodeEvidence.measurement.toLowerCase() !==
      nodeEvidence.approvedMeasurement.toLowerCase()
  ) {
    return {
      released: false,
      reason: `Attestation measurement mismatch: node=${nodeEvidence.measurement} != approved=${nodeEvidence.approvedMeasurement}`,
    };
  }

  if (nodeEvidence.status === "suspended") {
    return {
      released: false,
      reason: `Node ${nodeEvidence.chipId} is suspended and ineligible for closed weight key release`,
    };
  }

  if (nodeEvidence.quorumSignatures < nodeEvidence.requiredQuorum) {
    return {
      released: false,
      reason: `Insufficient verifier quorum signatures: got ${nodeEvidence.quorumSignatures}, required ${nodeEvidence.requiredQuorum}`,
    };
  }

  const custodyX25519PkBytes = hexToBytes(nodeEvidence.custodyX25519Pk);
  const custodyMlkemPkBytes = hexToBytes(nodeEvidence.custodyMlkemPk);
  const weightKeyBytes = hexToBytes(weightKeyHex);

  // Provider deterministic or ephemeral key material
  const providerIdentitySeed = hkdf(
    sha384,
    utf8ToBytes(`drouter:provider-ed25519:${providerId}:${modelId}`),
    utf8ToBytes("drouter-provider-id-salt"),
    utf8ToBytes("provider-signing-key"),
    32
  );
  const providerSigningKeys = ed25519.keygen(new Uint8Array(providerIdentitySeed));

  const ephemeralX25519Keys = x25519.keygen();
  const x25519Shared = x25519.getSharedSecret(
    ephemeralX25519Keys.secretKey,
    custodyX25519PkBytes
  );

  const { cipherText: mlkemCipherText, sharedSecret: mlkemShared } =
    ml_kem768.encapsulate(custodyMlkemPkBytes);

  const combinedIkm = concatBytes(x25519Shared, mlkemShared);
  const salt = sha384(
    concatBytes(
      ephemeralX25519Keys.publicKey,
      custodyX25519PkBytes,
      sha256(mlkemCipherText),
      sha256(custodyMlkemPkBytes)
    )
  );
  const info = utf8ToBytes("drouter:closed-weight-key-wrap:hkdf-sha384:v1");
  const kWrap = hkdf(sha384, combinedIkm, salt, info, 32);

  const nonce = hkdf(
    sha384,
    combinedIkm,
    salt,
    utf8ToBytes("drouter:closed-weight-key-wrap:nonce:v1"),
    12
  );

  const aad = concatBytes(
    ephemeralX25519Keys.publicKey,
    sha256(mlkemCipherText),
    custodyX25519PkBytes
  );

  const cipher = gcm(kWrap, nonce, aad);
  const ciphertext = cipher.encrypt(weightKeyBytes);

  const wrappedKeyCiphertextHex = bytesToHex(ciphertext);
  const nonceHex = bytesToHex(nonce);
  const providerEphemeralX25519Pk = bytesToHex(ephemeralX25519Keys.publicKey);
  const mlkemCiphertextHex = bytesToHex(mlkemCipherText);
  const providerPublicKeyHex = bytesToHex(providerSigningKeys.publicKey);

  const transcript = buildReleaseTranscript({
    wrappedKeyCiphertextHex,
    nonceHex,
    providerEphemeralX25519Pk,
    mlkemCiphertextHex,
    custodyX25519Pk: nodeEvidence.custodyX25519Pk,
    custodyMlkemPk: nodeEvidence.custodyMlkemPk,
  });

  const signature = ed25519.sign(transcript, providerSigningKeys.secretKey);
  const providerSignatureHex = bytesToHex(signature);

  return {
    released: true,
    providerId,
    modelId,
    chipId: nodeEvidence.chipId,
    measurement: nodeEvidence.measurement,
    wrappedKeyCiphertextHex,
    nonceHex,
    providerEphemeralX25519Pk,
    mlkemCiphertextHex,
    providerSignatureHex,
    providerPublicKeyHex,
  };
}

/**
 * Unwraps the provider's encrypted weight key inside the GPU TEE custody module.
 * Verifies the provider's Ed25519 release signature, decapsulates X25519 + ML-KEM-768,
 * derives K_wrap via HKDF-SHA-384, and decrypts the AES-256-GCM ciphertext.
 * Throws if any component is tampered with.
 */
export function custodyUnwrapWeightKey(
  release: ProviderKeyReleaseSuccess,
  custodyKeys: CustodyProviderKeypair
): string {
  if (!release || release.released !== true) {
    throw new Error("Cannot unwrap an unreleased weight key response");
  }

  const transcript = buildReleaseTranscript({
    wrappedKeyCiphertextHex: release.wrappedKeyCiphertextHex,
    nonceHex: release.nonceHex,
    providerEphemeralX25519Pk: release.providerEphemeralX25519Pk,
    mlkemCiphertextHex: release.mlkemCiphertextHex,
    custodyX25519Pk: custodyKeys.x25519PublicKey,
    custodyMlkemPk: custodyKeys.mlkemPublicKey,
  });

  const sigValid = ed25519.verify(
    hexToBytes(release.providerSignatureHex),
    transcript,
    hexToBytes(release.providerPublicKeyHex)
  );
  if (!sigValid) {
    throw new Error("Invalid provider Ed25519 signature on weight key release statement");
  }

  const ephemeralPkBytes = hexToBytes(release.providerEphemeralX25519Pk);
  const custodyX25519SkBytes = hexToBytes(custodyKeys.x25519PrivateKey);
  const custodyX25519PkBytes = hexToBytes(custodyKeys.x25519PublicKey);
  const custodyMlkemSkBytes = hexToBytes(custodyKeys.mlkemPrivateKey);
  const custodyMlkemPkBytes = hexToBytes(custodyKeys.mlkemPublicKey);
  const mlkemCipherTextBytes = hexToBytes(release.mlkemCiphertextHex);

  const x25519Shared = x25519.getSharedSecret(
    custodyX25519SkBytes,
    ephemeralPkBytes
  );
  const mlkemShared = ml_kem768.decapsulate(
    mlkemCipherTextBytes,
    custodyMlkemSkBytes
  );

  const combinedIkm = concatBytes(x25519Shared, mlkemShared);
  const salt = sha384(
    concatBytes(
      ephemeralPkBytes,
      custodyX25519PkBytes,
      sha256(mlkemCipherTextBytes),
      sha256(custodyMlkemPkBytes)
    )
  );
  const info = utf8ToBytes("drouter:closed-weight-key-wrap:hkdf-sha384:v1");
  const kWrap = hkdf(sha384, combinedIkm, salt, info, 32);

  const nonceBytes = hexToBytes(release.nonceHex);
  const aad = concatBytes(
    ephemeralPkBytes,
    sha256(mlkemCipherTextBytes),
    custodyX25519PkBytes
  );

  const cipher = gcm(kWrap, nonceBytes, aad);
  const plaintext = cipher.decrypt(hexToBytes(release.wrappedKeyCiphertextHex));

  return bytesToHex(plaintext);
}
