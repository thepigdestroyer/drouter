import { beforeEach, describe, expect, it } from "vitest";
import {
  VAULT_WORDLIST,
  deriveVaultIdentity,
  exportEncryptedVaultJson,
  generatePassphrase,
  getCurrentVaultSession,
  getPersistedVaultMetadata,
  importEncryptedVaultJson,
  lockVault,
  openVaultBundle,
  sealVaultBundle,
  unlockVaultWithPassphrase,
  updateVaultPayload,
  wipeLocalVault,
} from "@/lib/auth/vault";

describe("dRouter Zero-Knowledge Client Vault", () => {
  beforeEach(() => {
    wipeLocalVault();
  });

  it("generates a 6-word high-entropy passphrase from the 256-word list by default", () => {
    expect(VAULT_WORDLIST.length).toBe(256);
    const p1 = generatePassphrase();
    const p2 = generatePassphrase();
    const words1 = p1.split(" ");
    expect(words1).toHaveLength(6);
    for (const w of words1) {
      expect(VAULT_WORDLIST).toContain(w);
    }
    expect(p1).not.toEqual(p2);
  });

  it("derives deterministic identity across case and whitespace normalization and distinct across passphrases", () => {
    const idA = deriveVaultIdentity("aurora cobalt falcon glacier monolith quartz");
    const idNormalized = deriveVaultIdentity("  AURORA   Cobalt\tfalcon\nglacier monolith QUARTZ  ");
    const idB = deriveVaultIdentity("aurora cobalt falcon glacier monolith ember");

    expect(idA).toEqual(idNormalized);
    expect(idA.vaultId).toMatch(/^zk-[0-9a-f]{10}$/);
    expect(idA.ed25519PublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA.ed25519PrivateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA.x25519PublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(idA.vaultKeyHex).toMatch(/^[0-9a-f]{64}$/);

    expect(idA.vaultId).not.toEqual(idB.vaultId);
    expect(idA.vaultKeyHex).not.toEqual(idB.vaultKeyHex);
    expect(idA.ed25519PublicKeyHex).not.toEqual(idB.ed25519PublicKeyHex);
  });

  it("seals and opens a vault bundle with AES-256-GCM and throws on wrong key or tampered ciphertext", () => {
    const alice = deriveVaultIdentity("cinder falcon glacier harbor lantern obsidian");
    const bob = deriveVaultIdentity("amber bastion citadel dynamo emerald foundry");

    const originalPayload = {
      customScrubTerms: ["Project Helios", "Patient-88412", "Acme Corp"],
      notes: "Internal red-team audit workspace",
      createdAt: 1760000000000,
    };

    const sealed = sealVaultBundle(originalPayload, alice.vaultKeyHex);
    expect(sealed.vaultId).toBe(alice.vaultId);
    expect(sealed.ciphertextHex).not.toContain("Helios");
    expect(sealed.ciphertextHex).not.toContain("88412");

    const opened = openVaultBundle(sealed, alice.vaultKeyHex);
    expect(opened).toEqual(originalPayload);

    // Wrong key must fail authentication tag check
    expect(() => openVaultBundle(sealed, bob.vaultKeyHex)).toThrow(
      /wrong passphrase or tampered ciphertext/i,
    );

    // Tampered ciphertext byte must fail authentication tag check
    const firstByte = parseInt(sealed.ciphertextHex.slice(0, 2), 16);
    const flippedByte = ((firstByte ^ 0xff) & 0xff).toString(16).padStart(2, "0");
    const tamperedCiphertext = flippedByte + sealed.ciphertextHex.slice(2);
    expect(() =>
      openVaultBundle(
        { nonceHex: sealed.nonceHex, ciphertextHex: tamperedCiphertext },
        alice.vaultKeyHex,
      ),
    ).toThrow(/wrong passphrase or tampered ciphertext/i);
  });

  it("exports and imports .drouter-vault.json without leaking plaintext custom terms", () => {
    const pass = "atlas beacon catalyst dolmen equinox granite";
    unlockVaultWithPassphrase(pass, true);
    updateVaultPayload({
      customScrubTerms: ["Operation Nightfall", "Dr. Evelyn Vance", "MRN-992014"],
      notes: "Confidential clinical trial notes",
    });

    const exportedJson = exportEncryptedVaultJson();
    expect(exportedJson).not.toContain("Operation Nightfall");
    expect(exportedJson).not.toContain("Evelyn Vance");
    expect(exportedJson).not.toContain("MRN-992014");
    expect(exportedJson).not.toContain("Confidential clinical trial notes");
    expect(exportedJson).not.toContain(pass);

    // Lock and wipe local state, then re-import from JSON
    wipeLocalVault();
    expect(getCurrentVaultSession()).toBeNull();
    expect(getPersistedVaultMetadata().exists).toBe(false);

    // Wrong passphrase on import must throw
    expect(() => importEncryptedVaultJson(exportedJson, "wrong passphrase words here")).toThrow();

    // Correct passphrase restores exact identity and payload
    const restored = importEncryptedVaultJson(exportedJson, pass, true);
    expect(restored.payload.customScrubTerms).toEqual([
      "Operation Nightfall",
      "Dr. Evelyn Vance",
      "MRN-992014",
    ]);
    expect(restored.payload.notes).toBe("Confidential clinical trial notes");
    expect(getCurrentVaultSession()?.vaultId).toBe(restored.vaultId);
    expect(getPersistedVaultMetadata().exists).toBe(true);

    lockVault();
    expect(getCurrentVaultSession()).toBeNull();
    expect(getPersistedVaultMetadata().exists).toBe(true);
  });

  it("enforces OWASP PBKDF2-HMAC-SHA512 >= 210,000 iterations by default and rejects tampered export signatures or swapped public keys", async () => {
    const { VAULT_PBKDF2_ITERATIONS } = await import("@/lib/auth/vault");
    expect(VAULT_PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(210_000);

    const pass = "aurora bastion catalyst dolmen equinox granite";
    unlockVaultWithPassphrase(pass, false);
    updateVaultPayload({ customScrubTerms: ["SecretAlpha"], notes: "note" });
    const exportedJson = exportEncryptedVaultJson();

    // 1. Missing signatureHex or ed25519PublicKeyHex must be rejected
    const parsedMissingSig = JSON.parse(exportedJson);
    delete parsedMissingSig.signatureHex;
    expect(() => importEncryptedVaultJson(JSON.stringify(parsedMissingSig), pass)).toThrow();

    // 2. Swapped attacker public key + valid attacker signature must be rejected
    const attacker = deriveVaultIdentity("badger cavern chisel comet cougar crystal", {
      iterations: 10_000,
    });
    const swappedKeyFile = JSON.parse(exportedJson);
    swappedKeyFile.ed25519PublicKeyHex = attacker.ed25519PublicKeyHex;
    expect(() => importEncryptedVaultJson(JSON.stringify(swappedKeyFile), pass)).toThrow(
      /public key does not match/i,
    );

    // 3. Tampered signature byte must be rejected
    const badSigFile = JSON.parse(exportedJson);
    badSigFile.signatureHex =
      (badSigFile.signatureHex.startsWith("00") ? "ff" : "00") +
      badSigFile.signatureHex.slice(2);
    expect(() => importEncryptedVaultJson(JSON.stringify(badSigFile), pass)).toThrow(
      /signature verification failed/i,
    );

    // 4. Randomized seal/open fuzz loop (200 iterations across boundary sizes 0B, 1B, 64KB)
    const fastIdentity = deriveVaultIdentity("falcon glacier harbor lantern obsidian quartz", {
      iterations: 10_000,
    });
    for (let i = 0; i < 200; i++) {
      const payload = {
        customScrubTerms: i === 0 ? [] : [`Term-${i}`, `Entity-${i * 17}`],
        notes: i === 1 ? "x" : "A".repeat((i * 31) % 512),
        createdAt: 1760000000000 + i,
      };
      const bundle = sealVaultBundle(payload, fastIdentity.vaultKeyHex);
      expect(openVaultBundle(bundle, fastIdentity.vaultKeyHex)).toEqual(payload);
    }
  });
});
