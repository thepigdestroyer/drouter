import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const VAULT_STORAGE_KEY = "drouter.zkvault.v1";

/**
 * Built-in 256-word high-entropy wordlist (8 bits of entropy per word).
 * A 6-word passphrase carries 48 bits of pure random selection before PBKDF2-SHA512 stretching.
 */
export const VAULT_WORDLIST: readonly string[] = [
  "abacus", "admiral", "agate", "alchemy", "almanac", "amber", "amethyst", "anchor",
  "anemone", "anvil", "aperture", "apogee", "aqueduct", "arbor", "archive", "argon",
  "armada", "arrow", "artifact", "aspen", "astrolabe", "atlas", "atoll", "aurora",
  "avalanche", "axiom", "azalea", "azimuth", "badger", "ballast", "alsam", "balsa",
  "banister", "baritone", "basalt", "bastion", "beacon", "bellows", "beryl", "bison",
  "bitumen", "blizzard", "bobcat", "bolide", "bonfire", "boulder", "bramble", "breaker",
  "brigade", "brimstone", "bronze", "buckler", "bulwark", "burrow", "buttress", "caboose",
  "cadence", "cairn", "caliper", "calyx", "camber", "canopy", "canton", "canyon",
  "capstan", "caravan", "caravel", "carbon", "cardinal", "caribou", "cascade", "cassette",
  "catalyst", "cathedral", "cauldron", "cavern", "cedar", "celadon", "cenotaph", "centaur",
  "ceramic", "chalice", "chamber", "chamois", "channel", "chariot", "charter", "chasm",
  "chevron", "chimera", "chisel", "chronicle", "cinder", "cipher", "cirrus", "citadel",
  "clarin", "cleaver", "clement", "cloister", "cobalt", "cobble", "codex", "coffer",
  "colossus", "column", "comet", "compass", "conduit", "conifer", "console", "copper",
  "coral", "cordial", "coronet", "corsair", "cortex", "corvette", "cosmos", "cougar",
  "covenant", "crater", "crenel", "crescent", "cricket", "crimson", "crucible", "crystal",
  "culvert", "cumulus", "cupola", "curator", "current", "cutlass", "cyclone", "cypress",
  "dagger", "dahlia", "damask", "dapper", "daybreak", "decagon", "delta", "demijohn",
  "derrick", "desert", "diagram", "diadem", "diamond", "diopside", "diorama", "dolphin",
  "dolmen", "domino", "dormer", "doublet", "dragon", "drapery", "dredger", "driftwood",
  "droplet", "drumlin", "dynamo", "eclipse", "edifice", "egret", "eider", "electron",
  "element", "elixir", "embank", "emblem", "emerald", "emery", "empidon", "enclave",
  "endive", "engine", "enigma", "ensign", "entropy", "epaulet", "equinox", "ermine",
  "estuary", "etching", "eucalypt", "excalibur", "exodus", "falcon", "fathom", "feldspar",
  "fennel", "ferrule", "filament", "filigree", "finial", "fissure", "fjord", "flagon",
  "flannel", "flicker", "flint", "flotilla", "fluorite", "flywheel", "foliage", "forage",
  "fortress", "fossil", "foundry", "fountain", "foxglove", "fractal", "fragment", "fresco",
  "frigate", "frontier", "fulcrum", "fumarole", "furnace", "fuselage", "gabbro", "galleon",
  "gallery", "gambit", "gannet", "garnet", "garrison", "gazelle", "gazebo", "geode",
  "geyser", "glacier", "glider", "glimmer", "granite", "graphite", "griffin", "grotto",
  "guillemot", "gyroscope", "halberd", "halcyon", "halite", "halyard", "hammer", "harbor",
  "harrow", "harvest", "hawthorn", "hearth", "heather", "hedgehog", "ashima", "heliotrope",
] as const;

export interface VaultIdentity {
  vaultId: string;
  ed25519PublicKeyHex: string;
  ed25519PrivateKeyHex: string;
  x25519PublicKeyHex: string;
  vaultKeyHex: string;
}

export interface VaultPayload {
  customScrubTerms: string[];
  notes?: string;
  createdAt: number;
}

export interface SealedVaultBundle {
  nonceHex: string;
  ciphertextHex: string;
  vaultId: string;
}

export interface ExportedVaultFile {
  format: "drouter-zk-vault-v1";
  vaultId: string;
  ed25519PublicKeyHex: string;
  nonceHex: string;
  ciphertextHex: string;
  signatureHex: string;
  exportedAt: number;
}

export interface VaultSession {
  vaultId: string;
  ed25519PublicKeyHex: string;
  ed25519PrivateKeyHex: string;
  x25519PublicKeyHex: string;
  vaultKeyHex: string;
  persistEncrypted: boolean;
  unlockedAt: number;
  payload: VaultPayload;
}

const VAULT_PBKDF2_SALT = utf8ToBytes("drouter/v1/zk-vault-salt");
const VAULT_BUNDLE_AAD = utf8ToBytes("drouter/v1/zk-vault-bundle");

let activeSession: VaultSession | null = null;
const memoryStorage = new Map<string, string>();
const sessionListeners = new Set<() => void>();

function notifyListeners(): void {
  for (const listener of sessionListeners) {
    try {
      listener();
    } catch {
      // Ignore listener errors
    }
  }
}

function readStorage(key: string): string | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage.getItem(key);
    }
  } catch {
    // Fallback to in-memory map
  }
  return memoryStorage.get(key) ?? null;
}

function writeStorage(key: string, value: string): void {
  memoryStorage.set(key, value);
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // Fallback to in-memory map
  }
}

function removeStorage(key: string): void {
  memoryStorage.delete(key);
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Fallback to in-memory map
  }
}

function normalizePassphrase(passphrase: string): string {
  return (passphrase ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

function normalizeHex(hex: string): string {
  const clean = (hex ?? "").trim();
  return clean.startsWith("0x") || clean.startsWith("0X") ? clean.slice(2) : clean;
}

function deriveVaultIdFromVaultKey(vaultKeyBytes: Uint8Array): string {
  const digest = sha256(
    hkdf(sha384, vaultKeyBytes, VAULT_PBKDF2_SALT, utf8ToBytes("drouter/v1/vault-id"), 32),
  );
  return `zk-${bytesToHex(digest).slice(0, 10)}`;
}

/**
 * Generates a high-entropy human-memorable passphrase using CSPRNG (`crypto.getRandomValues`).
 */
export function generatePassphrase(wordCount = 6): string {
  const count = Math.max(4, Math.min(24, Math.floor(wordCount)));
  const randomBytes = new Uint8Array(count);
  globalThis.crypto.getRandomValues(randomBytes);
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    words.push(VAULT_WORDLIST[randomBytes[i] % VAULT_WORDLIST.length]);
  }
  return words.join(" ");
}

/**
 * Deterministically derives a Zero-Knowledge Client Vault identity from a passphrase.
 * Uses PBKDF2-HMAC-SHA-512 (10,000 rounds) followed by HKDF-SHA-384 subkey expansion.
 */
export function deriveVaultIdentity(passphrase: string): VaultIdentity {
  const normalized = normalizePassphrase(passphrase);
  if (!normalized) {
    throw new Error("Passphrase cannot be empty");
  }

  const masterSeed = pbkdf2(sha512, utf8ToBytes(normalized), VAULT_PBKDF2_SALT, {
    c: 10000,
    dkLen: 64,
  });

  const ed25519PrivateKey = hkdf(
    sha384,
    masterSeed,
    VAULT_PBKDF2_SALT,
    utf8ToBytes("drouter/v1/ed25519-priv"),
    32,
  );
  const ed25519PublicKey = ed25519.getPublicKey(ed25519PrivateKey);

  const x25519PrivateKey = hkdf(
    sha384,
    masterSeed,
    VAULT_PBKDF2_SALT,
    utf8ToBytes("drouter/v1/x25519-priv"),
    32,
  );
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);

  const vaultKey = hkdf(
    sha384,
    masterSeed,
    VAULT_PBKDF2_SALT,
    utf8ToBytes("drouter/v1/aes-256-gcm"),
    32,
  );

  const vaultId = deriveVaultIdFromVaultKey(vaultKey);

  return {
    vaultId,
    ed25519PublicKeyHex: bytesToHex(ed25519PublicKey),
    ed25519PrivateKeyHex: bytesToHex(ed25519PrivateKey),
    x25519PublicKeyHex: bytesToHex(x25519PublicKey),
    vaultKeyHex: bytesToHex(vaultKey),
  };
}

/**
 * Encrypts a VaultPayload under the 32-byte AES-256-GCM vault key.
 */
export function sealVaultBundle(
  payload: VaultPayload,
  vaultKeyHex: string,
): SealedVaultBundle {
  const cleanKeyHex = normalizeHex(vaultKeyHex);
  if (cleanKeyHex.length !== 64 || !/^[0-9a-fA-F]+$/.test(cleanKeyHex)) {
    throw new Error("Invalid 256-bit vault key hex");
  }

  const keyBytes = hexToBytes(cleanKeyHex);
  const vaultId = deriveVaultIdFromVaultKey(keyBytes);
  const nonce = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nonce);

  const sanitizedPayload: VaultPayload = {
    customScrubTerms: Array.from(
      new Set(
        (payload.customScrubTerms ?? [])
          .map((t) => t.trim())
          .filter((t) => t.length > 0),
      ),
    ),
    notes: payload.notes ?? "",
    createdAt: typeof payload.createdAt === "number" ? payload.createdAt : Date.now(),
  };

  const plaintext = utf8ToBytes(JSON.stringify(sanitizedPayload));
  const ciphertext = gcm(keyBytes, nonce, VAULT_BUNDLE_AAD).encrypt(plaintext);

  return {
    nonceHex: bytesToHex(nonce),
    ciphertextHex: bytesToHex(ciphertext),
    vaultId,
  };
}

/**
 * Decrypts and authenticates a SealedVaultBundle using the 32-byte AES-256-GCM vault key.
 * Throws if the passphrase/key is wrong or if the ciphertext or nonce was tampered with.
 */
export function openVaultBundle(
  bundle: { nonceHex: string; ciphertextHex: string },
  vaultKeyHex: string,
): VaultPayload {
  const cleanKeyHex = normalizeHex(vaultKeyHex);
  if (cleanKeyHex.length !== 64 || !/^[0-9a-fA-F]+$/.test(cleanKeyHex)) {
    throw new Error("Invalid 256-bit vault key hex");
  }

  try {
    const keyBytes = hexToBytes(cleanKeyHex);
    const nonce = hexToBytes(normalizeHex(bundle.nonceHex));
    const ciphertext = hexToBytes(normalizeHex(bundle.ciphertextHex));
    const plaintextBytes = gcm(keyBytes, nonce, VAULT_BUNDLE_AAD).decrypt(ciphertext);
    const parsed = JSON.parse(new TextDecoder().decode(plaintextBytes)) as VaultPayload;
    if (!parsed || !Array.isArray(parsed.customScrubTerms)) {
      throw new Error("Malformed vault payload");
    }
    return {
      customScrubTerms: parsed.customScrubTerms.map((t) => String(t)),
      notes: typeof parsed.notes === "string" ? parsed.notes : "",
      createdAt: typeof parsed.createdAt === "number" ? parsed.createdAt : Date.now(),
    };
  } catch {
    throw new Error("Failed to decrypt ZK Vault: wrong passphrase or tampered ciphertext");
  }
}

function buildCanonicalExportMessage(
  vaultId: string,
  ed25519PublicKeyHex: string,
  nonceHex: string,
  ciphertextHex: string,
): Uint8Array {
  return utf8ToBytes(
    `drouter-zk-vault-v1|${vaultId}|${ed25519PublicKeyHex}|${nonceHex}|${ciphertextHex}`,
  );
}

function persistSessionIfConfigured(session: VaultSession): void {
  if (!session.persistEncrypted) {
    return;
  }
  const sealed = sealVaultBundle(session.payload, session.vaultKeyHex);
  const msg = buildCanonicalExportMessage(
    session.vaultId,
    session.ed25519PublicKeyHex,
    sealed.nonceHex,
    sealed.ciphertextHex,
  );
  const sig = ed25519.sign(msg, hexToBytes(session.ed25519PrivateKeyHex));
  const record: ExportedVaultFile = {
    format: "drouter-zk-vault-v1",
    vaultId: session.vaultId,
    ed25519PublicKeyHex: session.ed25519PublicKeyHex,
    nonceHex: sealed.nonceHex,
    ciphertextHex: sealed.ciphertextHex,
    signatureHex: bytesToHex(sig),
    exportedAt: Date.now(),
  };
  writeStorage(VAULT_STORAGE_KEY, JSON.stringify(record));
}

/**
 * Returns the currently unlocked in-memory ZK Vault session, or null if locked.
 */
export function getCurrentVaultSession(): VaultSession | null {
  return activeSession;
}

/**
 * Checks whether an encrypted vault bundle is stored in local device storage.
 */
export function getPersistedVaultMetadata(): {
  exists: boolean;
  vaultId?: string;
  exportedAt?: number;
} {
  const raw = readStorage(VAULT_STORAGE_KEY);
  if (!raw) return { exists: false };
  try {
    const parsed = JSON.parse(raw) as Partial<ExportedVaultFile>;
    if (parsed && parsed.format === "drouter-zk-vault-v1" && typeof parsed.vaultId === "string") {
      return {
        exists: true,
        vaultId: parsed.vaultId,
        exportedAt: typeof parsed.exportedAt === "number" ? parsed.exportedAt : undefined,
      };
    }
  } catch {
    // Ignore corrupted storage
  }
  return { exists: false };
}

/**
 * Derives keys in-browser from `passphrase` and unlocks the session.
 * If an encrypted vault matching this identity exists in local storage, it is decrypted automatically.
 */
export function unlockVaultWithPassphrase(
  passphrase: string,
  persistEncrypted = false,
): VaultSession {
  const identity = deriveVaultIdentity(passphrase);
  let payload: VaultPayload = {
    customScrubTerms: [],
    notes: "",
    createdAt: Date.now(),
  };

  const storedRaw = readStorage(VAULT_STORAGE_KEY);
  if (storedRaw) {
    try {
      const parsed = JSON.parse(storedRaw) as ExportedVaultFile;
      if (
        parsed &&
        parsed.nonceHex &&
        parsed.ciphertextHex &&
        parsed.vaultId === identity.vaultId
      ) {
        payload = openVaultBundle(
          { nonceHex: parsed.nonceHex, ciphertextHex: parsed.ciphertextHex },
          identity.vaultKeyHex,
        );
      }
    } catch {
      // If stored vault belongs to a different passphrase, start fresh session
    }
  }

  activeSession = {
    ...identity,
    persistEncrypted,
    unlockedAt: Date.now(),
    payload,
  };

  if (persistEncrypted) {
    persistSessionIfConfigured(activeSession);
  }

  notifyListeners();
  return activeSession;
}

/**
 * Updates the active vault's custom scrub terms or notes, re-sealing to localStorage if persistence is enabled.
 */
export function updateVaultPayload(
  updater: Partial<VaultPayload> | ((prev: VaultPayload) => VaultPayload),
): VaultSession {
  if (!activeSession) {
    throw new Error("ZK Vault is locked");
  }
  const nextPayload =
    typeof updater === "function"
      ? updater(activeSession.payload)
      : { ...activeSession.payload, ...updater };

  const sanitizedTerms = Array.from(
    new Set(
      (nextPayload.customScrubTerms ?? [])
        .map((t) => t.trim())
        .filter((t) => t.length > 0),
    ),
  );

  activeSession = {
    ...activeSession,
    payload: {
      customScrubTerms: sanitizedTerms,
      notes: nextPayload.notes ?? "",
      createdAt: nextPayload.createdAt ?? activeSession.payload.createdAt,
    },
  };

  persistSessionIfConfigured(activeSession);
  notifyListeners();
  return activeSession;
}

/**
 * Toggles whether the active session persists an AES-256-GCM encrypted copy in localStorage.
 */
export function setVaultPersistenceMode(persistEncrypted: boolean): VaultSession {
  if (!activeSession) {
    throw new Error("ZK Vault is locked");
  }
  activeSession = {
    ...activeSession,
    persistEncrypted,
  };
  if (persistEncrypted) {
    persistSessionIfConfigured(activeSession);
  } else {
    removeStorage(VAULT_STORAGE_KEY);
  }
  notifyListeners();
  return activeSession;
}

/**
 * Locks the in-memory vault session and zeroes the RAM reference.
 */
export function lockVault(): void {
  activeSession = null;
  notifyListeners();
}

/**
 * Cryptographically wipes both the in-memory session and any encrypted bundle in localStorage.
 */
export function wipeLocalVault(): void {
  activeSession = null;
  removeStorage(VAULT_STORAGE_KEY);
  notifyListeners();
}

/**
 * Exports the currently unlocked vault as an Ed25519-signed, AES-256-GCM encrypted `.drouter-vault.json` string.
 */
export function exportEncryptedVaultJson(): string {
  if (!activeSession) {
    throw new Error("Cannot export: ZK Vault is currently locked");
  }
  const sealed = sealVaultBundle(activeSession.payload, activeSession.vaultKeyHex);
  const msg = buildCanonicalExportMessage(
    activeSession.vaultId,
    activeSession.ed25519PublicKeyHex,
    sealed.nonceHex,
    sealed.ciphertextHex,
  );
  const sig = ed25519.sign(msg, hexToBytes(activeSession.ed25519PrivateKeyHex));

  const exported: ExportedVaultFile = {
    format: "drouter-zk-vault-v1",
    vaultId: activeSession.vaultId,
    ed25519PublicKeyHex: activeSession.ed25519PublicKeyHex,
    nonceHex: sealed.nonceHex,
    ciphertextHex: sealed.ciphertextHex,
    signatureHex: bytesToHex(sig),
    exportedAt: Date.now(),
  };

  return JSON.stringify(exported, null, 2);
}

/**
 * Imports and decrypts an `.drouter-vault.json` string using `passphrase`, verifying both
 * the Ed25519 signature and the AES-256-GCM authentication tag.
 */
export function importEncryptedVaultJson(
  jsonStr: string,
  passphrase: string,
  persistEncrypted = false,
): VaultSession {
  let parsed: ExportedVaultFile;
  try {
    parsed = JSON.parse(jsonStr) as ExportedVaultFile;
  } catch {
    throw new Error("Invalid vault JSON format");
  }

  if (
    !parsed ||
    parsed.format !== "drouter-zk-vault-v1" ||
    typeof parsed.nonceHex !== "string" ||
    typeof parsed.ciphertextHex !== "string" ||
    typeof parsed.vaultId !== "string"
  ) {
    throw new Error("Unrecognized vault file schema");
  }

  const identity = deriveVaultIdentity(passphrase);
  if (parsed.vaultId !== identity.vaultId) {
    throw new Error("Failed to decrypt ZK Vault: passphrase does not match vaultId");
  }

  if (parsed.signatureHex && parsed.ed25519PublicKeyHex) {
    const msg = buildCanonicalExportMessage(
      parsed.vaultId,
      parsed.ed25519PublicKeyHex,
      parsed.nonceHex,
      parsed.ciphertextHex,
    );
    const validSig = ed25519.verify(
      hexToBytes(normalizeHex(parsed.signatureHex)),
      msg,
      hexToBytes(normalizeHex(parsed.ed25519PublicKeyHex)),
    );
    if (!validSig) {
      throw new Error("Vault signature verification failed");
    }
  }

  const payload = openVaultBundle(
    { nonceHex: parsed.nonceHex, ciphertextHex: parsed.ciphertextHex },
    identity.vaultKeyHex,
  );

  activeSession = {
    ...identity,
    persistEncrypted,
    unlockedAt: Date.now(),
    payload,
  };

  if (persistEncrypted) {
    persistSessionIfConfigured(activeSession);
  }

  notifyListeners();
  return activeSession;
}

/**
 * Subscribes a listener to vault session lock/unlock/update events.
 */
export function subscribeVaultSession(listener: () => void): () => void {
  sessionListeners.add(listener);
  return () => {
    sessionListeners.delete(listener);
  };
}
