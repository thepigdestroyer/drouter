import { p384 } from "@noble/curves/nist.js";
import { sha384 } from "@noble/hashes/sha2.js";

/** ECDSA P-384 / SHA-384. Signatures are raw r‖s, 48 bytes each, big-endian (96 bytes). */

export function p384Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return p384.sign(sha384(message), secretKey, { prehash: false });
}

export function p384Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    // lowS is off because AMD's silicon does not normalise S.
    return p384.verify(signature, sha384(message), publicKey, { prehash: false, lowS: false });
  } catch {
    return false;
  }
}
