import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildLoginRedirectHref,
  sanitizeNextPath,
} from "@/components/auth/auth-gate";
import {
  PASSKEY_DISPLAY_NAME,
  PASSKEY_RP_NAME,
  PasskeyPrfUnsupportedError,
  createPasskeyAccount,
  deriveVaultIdentityFromPrfOutput,
  getPasskeyPrfSalt,
  isPasskeyPrfSupported,
  signInWithPasskey,
} from "@/lib/auth/passkey";
import {
  exportEncryptedVaultJson,
  getActiveCustomScrubTerms,
  getCurrentVaultSession,
  importEncryptedVaultWithActiveSession,
  lockVault,
  updateVaultPayload,
  wipeLocalVault,
} from "@/lib/auth/vault";

describe("deRoute WebAuthn PRF Passkeys & AuthGate helpers", () => {
  const origWindow = (globalThis as { window?: unknown }).window;
  const origNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const origPublicKeyCredential = (globalThis as { PublicKeyCredential?: unknown })
    .PublicKeyCredential;

  function setMockNavigator(value: unknown) {
    Object.defineProperty(globalThis, "navigator", {
      value,
      configurable: true,
      writable: true,
    });
  }

  beforeEach(() => {
    wipeLocalVault();
  });

  afterEach(() => {
    wipeLocalVault();
    if (origWindow === undefined) {
      delete (globalThis as { window?: unknown }).window;
    } else {
      (globalThis as { window?: unknown }).window = origWindow;
    }
    if (origNavigatorDesc) {
      Object.defineProperty(globalThis, "navigator", origNavigatorDesc);
    } else {
      delete (globalThis as { navigator?: unknown }).navigator;
    }
    if (origPublicKeyCredential === undefined) {
      delete (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential;
    } else {
      (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential =
        origPublicKeyCredential;
    }
  });

  it("feature-detects WebAuthn PRF support cleanly without throwing", async () => {
    delete (globalThis as { window?: unknown }).window;
    expect(await isPasskeyPrfSupported()).toBe(false);

    (globalThis as { window?: unknown }).window = {
      location: { hostname: "deroute.example" },
    };
    setMockNavigator({
      credentials: {
        create: vi.fn(),
        get: vi.fn(),
      },
    });
    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      getClientCapabilities: async () => ({ "extension:prf": false }),
    };
    expect(await isPasskeyPrfSupported()).toBe(false);

    (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential = {
      getClientCapabilities: async () => ({ "extension:prf": true }),
    };
    expect(await isPasskeyPrfSupported()).toBe(true);
  });

  it("derives deterministic vault identities from 32-byte PRF output via HKDF", () => {
    const prfA = new Uint8Array(32);
    const prfB = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      prfA[i] = (i * 7 + 11) & 0xff;
      prfB[i] = (i * 13 + 5) & 0xff;
    }

    const idA1 = deriveVaultIdentityFromPrfOutput(prfA);
    const idA2 = deriveVaultIdentityFromPrfOutput(prfA.buffer.slice(0));
    const idB = deriveVaultIdentityFromPrfOutput(prfB);

    expect(idA1).toEqual(idA2);
    expect(idA1.vaultId).toMatch(/^vault-[0-9a-f]{10}$/);
    expect(idA1.ed25519PublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA1.x25519PublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA1.vaultKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA1.vaultId).not.toEqual(idB.vaultId);
    expect(idA1.vaultKeyHex).not.toEqual(idB.vaultKeyHex);

    expect(() => deriveVaultIdentityFromPrfOutput(new Uint8Array(16))).toThrow(
      PasskeyPrfUnsupportedError,
    );
  });

  it("creates a passkey account with exact privacy-first WebAuthn parameters and restores custom hidden words on signInWithPasskey", async () => {
    const fakeStorage = new Map<string, string>();
    const prfOutput = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      prfOutput[i] = (i * 19 + 3) & 0xff;
    }

    const createSpy = vi.fn(async (options?: CredentialCreationOptions) => {
      const pk = options?.publicKey;
      expect(pk).toBeDefined();
      expect(pk?.attestation).toBe("none");
      expect(pk?.authenticatorSelection?.userVerification).toBe("required");
      expect(pk?.authenticatorSelection?.residentKey).toBe("required");
      expect(pk?.rp.name).toBe(PASSKEY_RP_NAME);
      expect(pk?.rp.id).toBe("deroute.local");
      expect(pk?.user.name).toBe(PASSKEY_DISPLAY_NAME);
      expect(pk?.user.displayName).toBe(PASSKEY_DISPLAY_NAME);
      expect((pk?.user.id as Uint8Array).byteLength).toBe(32);

      const ext = pk?.extensions as unknown as {
        prf?: { eval?: { first?: Uint8Array } };
      };
      expect(ext?.prf?.eval?.first).toEqual(getPasskeyPrfSalt());

      return {
        id: "cred-1",
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        type: "public-key",
        getClientExtensionResults: () => ({
          prf: {
            enabled: true,
            results: {
              first: prfOutput.slice().buffer,
            },
          },
        }),
      } as unknown as Credential;
    });

    const getSpy = vi.fn(async (options?: CredentialRequestOptions) => {
      const pk = options?.publicKey;
      expect(pk?.userVerification).toBe("required");
      expect(pk?.rpId).toBe("deroute.local");
      return {
        id: "cred-1",
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        type: "public-key",
        getClientExtensionResults: () => ({
          prf: {
            results: {
              first: prfOutput.slice().buffer,
            },
          },
        }),
      } as unknown as Credential;
    });

    (globalThis as { window?: unknown }).window = {
      location: { hostname: "deroute.local" },
      localStorage: {
        getItem: (k: string) => fakeStorage.get(k) ?? null,
        setItem: (k: string, v: string) => {
          fakeStorage.set(k, v);
        },
        removeItem: (k: string) => {
          fakeStorage.delete(k);
        },
      },
    };
    setMockNavigator({
      credentials: {
        create: createSpy,
        get: getSpy,
      },
    });

    const createdSession = await createPasskeyAccount();
    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(createdSession.authMethod).toBe("passkey");
    expect(getCurrentVaultSession()?.vaultId).toBe(createdSession.vaultId);

    updateVaultPayload({
      customScrubTerms: ["Project Aurora", "Client-771"],
      notes: "Encrypted passkey note",
    });
    expect(getActiveCustomScrubTerms()).toEqual(["Project Aurora", "Client-771"]);

    const exportedBackup = exportEncryptedVaultJson();
    expect(exportedBackup).not.toContain("Project Aurora");

    // Sign out (locks in-memory session)
    lockVault();
    expect(getCurrentVaultSession()).toBeNull();
    expect(getActiveCustomScrubTerms()).toEqual([]);

    // Sign back in with the same passkey PRF output -> restores custom hidden words automatically
    const signedInSession = await signInWithPasskey();
    expect(getSpy).toHaveBeenCalledTimes(1);
    expect(signedInSession.vaultId).toBe(createdSession.vaultId);
    expect(signedInSession.authMethod).toBe("passkey");
    expect(getActiveCustomScrubTerms()).toEqual(["Project Aurora", "Client-771"]);

    // Modify terms, then restore from backup using active passkey session
    updateVaultPayload({ customScrubTerms: ["Temporary"] });
    const restored = importEncryptedVaultWithActiveSession(exportedBackup);
    expect(restored.payload.customScrubTerms).toEqual(["Project Aurora", "Client-771"]);
  });

  it("supports two-step PRF evaluation when create() only reports enabled: true and rejects when PRF is unsupported", async () => {
    const prfOutput = new Uint8Array(32).fill(0x42);

    (globalThis as { window?: unknown }).window = {
      location: { hostname: "deroute.local" },
    };
    setMockNavigator({
      credentials: {
        create: vi.fn(async () => ({
          id: "cred-2",
          rawId: new Uint8Array([9, 9, 9]).buffer,
          type: "public-key",
          getClientExtensionResults: () => ({
            prf: { enabled: true },
          }),
        })),
        get: vi.fn(async () => ({
          id: "cred-2",
          rawId: new Uint8Array([9, 9, 9]).buffer,
          type: "public-key",
          getClientExtensionResults: () => ({
            prf: {
              results: {
                first: prfOutput.slice().buffer,
              },
            },
          }),
        })),
      },
    });

    const session = await createPasskeyAccount();
    expect(session.authMethod).toBe("passkey");
    expect(session.vaultId).toMatch(/^vault-[0-9a-f]{10}$/);

    // Now simulate an authenticator that does not support PRF
    setMockNavigator({
      credentials: {
        create: vi.fn(async () => ({
          id: "cred-no-prf",
          type: "public-key",
          getClientExtensionResults: () => ({
            prf: { enabled: false },
          }),
        })),
        get: vi.fn(),
      },
    });

    await expect(createPasskeyAccount()).rejects.toThrow(
      PasskeyPrfUnsupportedError,
    );
  });

  it("sanitizes ?next= redirect paths to allow only same-site paths starting with a single /", () => {
    expect(sanitizeNextPath("/app")).toBe("/app");
    expect(sanitizeNextPath("/account")).toBe("/account");
    expect(sanitizeNextPath("/audit?view=1")).toBe("/audit?view=1");
    expect(sanitizeNextPath("https://evil.example/phish")).toBe("/app");
    expect(sanitizeNextPath("//evil.example/phish")).toBe("/app");
    expect(sanitizeNextPath("/\\evil.example")).toBe("/app");
    expect(sanitizeNextPath("javascript:alert(1)")).toBe("/app");
    expect(sanitizeNextPath(null)).toBe("/app");
    expect(buildLoginRedirectHref("/argon")).toBe("/login?next=/argon");
  });

  it("ensures /login, /account, and AuthGate default views contain zero banned jargon, zero em-dashes, and rename dRouter to deRoute", () => {
    const files = [
      "src/app/login/page.tsx",
      "src/app/account/page.tsx",
      "src/components/auth/auth-gate.tsx",
    ];
    const forbiddenOutsideTechDetails = [
      /\battestation\b/i,
      /\battested\b/i,
      /\benclave\b/i,
      /\bTEE\b/,
      /\bSEV-SNP\b/i,
      /\bSNP\b/,
      /\bTDX\b/,
      /\bHPKE\b/i,
      /\bRFC\b/,
      /\bMerkle\b/i,
      /\bnullifier\b/i,
      /\bRSA\b/,
      /\bquorum\b/i,
      /\bSigstore\b/i,
      /\bRekor\b/i,
      /\bVCEK\b/i,
      /\bCKKS\b/i,
      /\bFHE\b/,
      /\bhomomorphic\b/i,
      /\bdm-verity\b/i,
      /\bmeasurement\b/i,
      /\bciphertext\b/i,
      /\bhash\b/i,
      /\bdigest\b/i,
      /\bECDSA\b/i,
      /\bX25519\b/i,
      /\bPII\b/,
      /\bOHTTP\b/i,
      /\bSPRT\b/,
      /\bArc testnet\b/i,
      /\brelay hop\b/i,
      /\bbucket bytes\b/i,
    ];

    for (const relPath of files) {
      const fullPath = path.join(process.cwd(), relPath);
      const raw = fs.readFileSync(fullPath, "utf8");

      // No em-dashes anywhere in our files
      expect(raw).not.toContain("—");
      // No user-visible "dRouter" (internal ".drouter-vault.json" / "drouter/v1" / "drouter-zk-vault-v1" allowed)
      expect(raw).not.toMatch(/\bdRouter\b/);

      // Strip <TechDetails ...>...</TechDetails> blocks and import/identifier lines before checking default view copy
      const withoutTechDetails = raw
        .replace(/<TechDetails[\s\S]*?<\/TechDetails>/g, "")
        .replace(/bucketBytes/g, "");

      for (const pattern of forbiddenOutsideTechDetails) {
        expect(withoutTechDetails).not.toMatch(pattern);
      }
    }
  });
});
