import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  deriveVaultIdentityFromKeyMaterial,
  unlockVaultWithKeyMaterial,
  type VaultIdentity,
  type VaultSession,
} from "@/lib/auth/vault";

export const PASSKEY_RP_NAME = "deRoute";
export const PASSKEY_DISPLAY_NAME = "deRoute account";
export const PASSKEY_PRF_SALT_LABEL = "drouter/v1/passkey-prf-salt";

export class PasskeyPrfUnsupportedError extends Error {
  readonly code = "PASSKEY_PRF_UNSUPPORTED";

  constructor(
    message = "Your browser or device does not support passkey encryption keys (PRF). Use the 6 secret words option instead.",
  ) {
    super(message);
    this.name = "PasskeyPrfUnsupportedError";
  }
}

interface PrfExtensionInput {
  eval: {
    first: Uint8Array;
  };
}

interface PrfExtensionOutput {
  enabled?: boolean;
  results?: {
    first?: ArrayBuffer | ArrayBufferView;
  };
}

interface ExtendedClientExtensionResults {
  prf?: PrfExtensionOutput;
}

export function getPasskeyPrfSalt(): Uint8Array {
  return sha256(utf8ToBytes(PASSKEY_PRF_SALT_LABEL));
}

function getRpId(): string {
  if (typeof globalThis.window !== "undefined" && globalThis.window.location?.hostname) {
    return globalThis.window.location.hostname;
  }
  return "localhost";
}

function toUint8Array(buf: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (buf instanceof Uint8Array) {
    return new Uint8Array(buf);
  }
  if (ArrayBuffer.isView(buf)) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  if (buf instanceof ArrayBuffer) {
    return new Uint8Array(buf);
  }
  throw new PasskeyPrfUnsupportedError("Invalid PRF output buffer returned by authenticator.");
}

function extractPrfOutput(credential: Credential | null): {
  prfBytes: Uint8Array | null;
  enabled: boolean;
} {
  if (!credential || typeof (credential as PublicKeyCredential).getClientExtensionResults !== "function") {
    return { prfBytes: null, enabled: false };
  }
  const ext = (
    credential as PublicKeyCredential
  ).getClientExtensionResults() as ExtendedClientExtensionResults;
  const first = ext?.prf?.results?.first;
  if (first) {
    const bytes = toUint8Array(first);
    if (bytes.byteLength >= 32) {
      return { prfBytes: bytes, enabled: true };
    }
  }
  return {
    prfBytes: null,
    enabled: Boolean(ext?.prf?.enabled),
  };
}

/**
 * Deterministically derives a deRoute VaultIdentity from a 32-byte WebAuthn PRF output using HKDF-SHA-384.
 */
export function deriveVaultIdentityFromPrfOutput(
  prfOutput: ArrayBuffer | ArrayBufferView,
): VaultIdentity {
  const bytes = toUint8Array(prfOutput);
  if (bytes.byteLength < 32) {
    bytes.fill(0);
    throw new PasskeyPrfUnsupportedError("PRF output must be at least 32 bytes.");
  }
  try {
    return deriveVaultIdentityFromKeyMaterial(bytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * Feature-detects whether the current browser environment supports WebAuthn passkeys with the PRF extension.
 * Resolves to false instead of throwing when WebAuthn or PRF is unavailable.
 */
export async function isPasskeyPrfSupported(): Promise<boolean> {
  try {
    if (
      typeof globalThis.window === "undefined" ||
      typeof globalThis.navigator === "undefined" ||
      typeof globalThis.PublicKeyCredential === "undefined" ||
      typeof globalThis.navigator.credentials?.create !== "function" ||
      typeof globalThis.navigator.credentials?.get !== "function"
    ) {
      return false;
    }

    const pkc = globalThis.PublicKeyCredential as unknown as {
      getClientCapabilities?: () => Promise<Record<string, boolean>>;
      isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
    };

    if (typeof pkc.getClientCapabilities === "function") {
      const capabilities = await pkc.getClientCapabilities();
      if (capabilities && typeof capabilities === "object") {
        if ("extension:prf" in capabilities) {
          return Boolean(capabilities["extension:prf"]);
        }
        if (
          capabilities.passkeyPlatformAuthenticator === false &&
          capabilities.userVerifyingPlatformAuthenticator === false
        ) {
          return false;
        }
      }
    }

    if (typeof pkc.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      const uvpa = await pkc.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!uvpa) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Creates a client-side WebAuthn passkey with the PRF extension (`attestation: "none"`,
 * `userVerification: "required"`, `residentKey: "required"`, random 32-byte user handle,
 * generic display name `"deRoute account"`, `rpId = current hostname`), derives the vault keys
 * via HKDF, and opens an active vault session.
 */
export async function createPasskeyAccount(): Promise<VaultSession> {
  if (
    typeof globalThis.navigator === "undefined" ||
    typeof globalThis.navigator.credentials?.create !== "function" ||
    typeof globalThis.navigator.credentials?.get !== "function"
  ) {
    throw new PasskeyPrfUnsupportedError();
  }

  const challenge = new Uint8Array(32);
  const userHandle = new Uint8Array(32);
  globalThis.crypto.getRandomValues(challenge);
  globalThis.crypto.getRandomValues(userHandle);

  const rpId = getRpId();
  const prfSalt = getPasskeyPrfSalt();
  const prfInput: PrfExtensionInput = {
    eval: {
      first: prfSalt,
    },
  };

  try {
    const created = await globalThis.navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: PASSKEY_RP_NAME,
          id: rpId,
        },
        user: {
          id: userHandle,
          name: PASSKEY_DISPLAY_NAME,
          displayName: PASSKEY_DISPLAY_NAME,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
          { type: "public-key", alg: -8 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
        extensions: {
          prf: prfInput,
        } as unknown as AuthenticationExtensionsClientInputs,
      },
    });

    if (!created) {
      throw new Error("Passkey creation was cancelled.");
    }

    const { prfBytes, enabled } = extractPrfOutput(created);
    if (prfBytes) {
      try {
        return unlockVaultWithKeyMaterial(prfBytes, true, "passkey");
      } finally {
        prfBytes.fill(0);
      }
    }

    if (!enabled) {
      throw new PasskeyPrfUnsupportedError();
    }

    // Authenticator enabled PRF during registration and requires a get() assertion to evaluate PRF output.
    const rawId = (created as PublicKeyCredential).rawId;
    const evalChallenge = new Uint8Array(32);
    globalThis.crypto.getRandomValues(evalChallenge);

    const assertion = await globalThis.navigator.credentials.get({
      publicKey: {
        challenge: evalChallenge,
        rpId,
        userVerification: "required",
        allowCredentials: rawId
          ? [{ type: "public-key", id: rawId }]
          : undefined,
        extensions: {
          prf: prfInput,
        } as unknown as AuthenticationExtensionsClientInputs,
      },
    });

    const evaluated = extractPrfOutput(assertion);
    if (!evaluated.prfBytes) {
      throw new PasskeyPrfUnsupportedError();
    }

    try {
      return unlockVaultWithKeyMaterial(evaluated.prfBytes, true, "passkey");
    } finally {
      evaluated.prfBytes.fill(0);
    }
  } finally {
    userHandle.fill(0);
    challenge.fill(0);
  }
}

/**
 * Signs in with an existing discoverable WebAuthn passkey using the PRF extension,
 * derives the vault key material with HKDF, and unlocks the active vault session.
 */
export async function signInWithPasskey(): Promise<VaultSession> {
  if (
    typeof globalThis.navigator === "undefined" ||
    typeof globalThis.navigator.credentials?.get !== "function"
  ) {
    throw new PasskeyPrfUnsupportedError();
  }

  const challenge = new Uint8Array(32);
  globalThis.crypto.getRandomValues(challenge);

  const rpId = getRpId();
  const prfSalt = getPasskeyPrfSalt();
  const prfInput: PrfExtensionInput = {
    eval: {
      first: prfSalt,
    },
  };

  try {
    const assertion = await globalThis.navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        userVerification: "required",
        extensions: {
          prf: prfInput,
        } as unknown as AuthenticationExtensionsClientInputs,
      },
    });

    if (!assertion) {
      throw new Error("Sign-in was cancelled.");
    }

    const { prfBytes } = extractPrfOutput(assertion);
    if (!prfBytes) {
      throw new PasskeyPrfUnsupportedError();
    }

    try {
      return unlockVaultWithKeyMaterial(prfBytes, true, "passkey");
    } finally {
      prfBytes.fill(0);
    }
  } finally {
    challenge.fill(0);
  }
}
