import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { BlindCreditToken, Hex } from "@/lib/types";
import {
  getCurrentVaultSession,
  openVaultBundle,
  sealVaultBundle,
} from "@/lib/auth/vault";
import {
  blindToken,
  formatCreditHeader,
  unblindSignature,
  verifyTokenSignature,
} from "./blind";
import { encodeAccessKey } from "./access-key";

export const CREDITS_STORAGE_KEY = "drouter.credits.v1";
const STORAGE_KEY = CREDITS_STORAGE_KEY;
export const PENDING_ACCESS_KEY_STORAGE_KEY = "drouter.credits.pending-access-key.v1";
const CREDITS_STORAGE_AAD = utf8ToBytes("drouter/v1/credits-wallet");

export interface PendingAccessKeyRecord {
  key: string;
  creditsMoved: number;
  tokenCount: number;
  createdAt: number;
}

let memoryStore: BlindCreditToken[] = [];
let pendingAccessKeyMemory: PendingAccessKeyRecord | null = null;
let ephemeralWalletKey: Uint8Array | null = null;

function getWalletStorageKey(): Uint8Array {
  const vault = getCurrentVaultSession();
  if (vault && vault.vaultKeyHex && /^[0-9a-fA-F]{64}$/.test(vault.vaultKeyHex)) {
    return hexToBytes(vault.vaultKeyHex);
  }
  if (!ephemeralWalletKey) {
    ephemeralWalletKey = new Uint8Array(32);
    globalThis.crypto.getRandomValues(ephemeralWalletKey);
  }
  return ephemeralWalletKey;
}

function readStorage(): BlindCreditToken[] {
  if (typeof window === "undefined" || !window.localStorage) {
    return [...memoryStore];
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    let list: unknown[] = [];
    if (parsed && typeof parsed === "object" && "nonceHex" in parsed && "ciphertextHex" in parsed) {
      const key = getWalletStorageKey();
      const nonce = hexToBytes(String((parsed as { nonceHex: string }).nonceHex));
      const ct = hexToBytes(String((parsed as { ciphertextHex: string }).ciphertextHex));
      const pt = gcm(key, nonce, CREDITS_STORAGE_AAD).decrypt(ct);
      list = JSON.parse(new TextDecoder().decode(pt));
    } else if (Array.isArray(parsed)) {
      list = parsed;
    }
    if (!Array.isArray(list)) return [];
    const valid = list.filter(
      (item): item is BlindCreditToken =>
        Boolean(
          item &&
            typeof (item as BlindCreditToken).token === "string" &&
            typeof (item as BlindCreditToken).signature === "string" &&
            typeof (item as BlindCreditToken).denomination === "number"
        )
    );
    memoryStore = [...valid];
    return valid;
  } catch {
    return [];
  }
}

function writeStorage(tokens: BlindCreditToken[]): void {
  if (typeof window !== "undefined" && window.localStorage) {
    const key = getWalletStorageKey();
    const nonce = new Uint8Array(12);
    globalThis.crypto.getRandomValues(nonce);
    const plaintext = utf8ToBytes(JSON.stringify(tokens));
    const ciphertext = gcm(key, nonce, CREDITS_STORAGE_AAD).encrypt(plaintext);
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        format: "drouter-credits-v1-gcm",
        nonceHex: bytesToHex(nonce),
        ciphertextHex: bytesToHex(ciphertext),
      })
    );
  }
  memoryStore = [...tokens];
}

function randomSecretHex(byteLength = 32): string {
  if (
    typeof globalThis.crypto === "undefined" ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new Error("CSPRNG unavailable: crypto.getRandomValues is required");
  }
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Computes `sha256(claimSecret)` as a 64-char hex string from a 32-byte hex `claimSecret`.
 */
export function hashClaimSecret(claimSecretHex: string): string {
  const cleaned = claimSecretHex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new Error("claimSecret must be a 32-byte (64-hex-char) secret");
  }
  return bytesToHex(sha256(hexToBytes(cleaned)));
}

/**
 * Generates a fresh 32-byte random `claimSecret` and its corresponding `claimHash = sha256(claimSecret)`.
 * Only `claimHash` is sent when requesting an invoice; `claimSecret` is kept in the browser until claiming.
 */
export function generateClaimSecret(): {
  claimSecret: string;
  claimHash: string;
} {
  const claimSecret = randomSecretHex(32);
  return {
    claimSecret,
    claimHash: hashClaimSecret(claimSecret),
  };
}

export function getStoredCredits(): BlindCreditToken[] {
  return readStorage();
}

export function storedCreditBalance(): number {
  return readStorage().reduce((sum, t) => sum + (t.denomination || 0), 0);
}

export function storeCreditTokens(tokens: BlindCreditToken[]): void {
  const existing = readStorage();
  writeStorage([...existing, ...tokens]);
}

export function clearStoredCredits(): void {
  memoryStore = [];
  pendingAccessKeyMemory = null;
  if (typeof window !== "undefined" && window.localStorage) {
    try {
      window.localStorage.removeItem(STORAGE_KEY);
      window.localStorage.removeItem(PENDING_ACCESS_KEY_STORAGE_KEY);
    } catch {
      // Ignore storage errors
    }
  }
}

/**
 * Interface I2: pops one unspent blind-signed credit token from storage and formats it
 * as the `x-drouter-credit` request header value, or returns null when the wallet is empty.
 */
export async function takeCreditHeader(): Promise<string | null> {
  const wallet = readStorage();
  if (wallet.length === 0) {
    return null;
  }
  const [token, ...rest] = wallet;
  writeStorage(rest);
  return formatCreditHeader(token);
}

export interface MoveTokensToAccessKeyResult {
  key: string;
  tokens: BlindCreditToken[];
  creditsMoved: number;
  remainingBalance: number;
}

export interface SelectCreditsFromWalletResult {
  selected: BlindCreditToken[];
  remaining: BlindCreditToken[];
  creditsMoved: number;
}

export function selectTokensForTargetCredits(
  wallet: readonly BlindCreditToken[],
  targetCredits: number,
): SelectCreditsFromWalletResult | null {
  if (!Number.isInteger(targetCredits) || targetCredits < 1) {
    return null;
  }

  // Pass 1: FIFO scan skipping tokens that would exceed targetCredits
  const selectedFifo: BlindCreditToken[] = [];
  const remainingFifo: BlindCreditToken[] = [];
  let sumFifo = 0;

  for (let i = 0; i < wallet.length; i++) {
    const tok = wallet[i];
    const denom = tok.denomination || 1;
    if (sumFifo + denom <= targetCredits && selectedFifo.length < 50) {
      selectedFifo.push(tok);
      sumFifo += denom;
    } else {
      remainingFifo.push(tok);
    }
  }

  if (sumFifo === targetCredits) {
    return {
      selected: selectedFifo,
      remaining: remainingFifo,
      creditsMoved: sumFifo,
    };
  }

  // Pass 2: Exact subset-sum DP (never exceeding targetCredits and at most 50 tokens)
  const dp = new Map<number, number[]>();
  dp.set(0, []);

  for (let i = 0; i < wallet.length; i++) {
    const denom = wallet[i].denomination || 1;
    if (denom > targetCredits) continue;
    const entries = Array.from(dp.entries());
    for (const [currentSum, indices] of entries) {
      const nextSum = currentSum + denom;
      if (nextSum <= targetCredits && indices.length + 1 <= 50 && !dp.has(nextSum)) {
        dp.set(nextSum, [...indices, i]);
      }
    }
    if (dp.has(targetCredits)) {
      break;
    }
  }

  const exactIndices = dp.get(targetCredits);
  if (!exactIndices) {
    return null;
  }

  const chosenSet = new Set<number>(exactIndices);
  const selected: BlindCreditToken[] = [];
  const remaining: BlindCreditToken[] = [];
  for (let i = 0; i < wallet.length; i++) {
    if (chosenSet.has(i)) {
      selected.push(wallet[i]);
    } else {
      remaining.push(wallet[i]);
    }
  }

  return {
    selected,
    remaining,
    creditsMoved: targetCredits,
  };
}

function writePendingAccessKey(record: PendingAccessKeyRecord): void {
  if (typeof window !== "undefined" && window.localStorage) {
    const vault = getCurrentVaultSession();
    if (vault && vault.vaultKeyHex && /^[0-9a-fA-F]{64}$/.test(vault.vaultKeyHex)) {
      const sealed = sealVaultBundle(
        {
          customScrubTerms: [],
          notes: JSON.stringify(record),
          createdAt: record.createdAt,
        },
        vault.vaultKeyHex,
      );
      window.localStorage.setItem(
        PENDING_ACCESS_KEY_STORAGE_KEY,
        JSON.stringify({
          format: "drouter-pending-access-key-v1-vault",
          ...sealed,
        }),
      );
    } else {
      const aesKey = getWalletStorageKey();
      const nonce = new Uint8Array(12);
      globalThis.crypto.getRandomValues(nonce);
      const plaintext = utf8ToBytes(JSON.stringify(record));
      const ciphertext = gcm(aesKey, nonce, CREDITS_STORAGE_AAD).encrypt(plaintext);
      window.localStorage.setItem(
        PENDING_ACCESS_KEY_STORAGE_KEY,
        JSON.stringify({
          format: "drouter-pending-access-key-v1-gcm",
          nonceHex: bytesToHex(nonce),
          ciphertextHex: bytesToHex(ciphertext),
        }),
      );
    }
  }
  pendingAccessKeyMemory = { ...record };
}

function parsePendingRecord(raw: unknown): PendingAccessKeyRecord | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.key !== "string" || !obj.key.startsWith("drk_")) return null;
  const creditsMoved =
    typeof obj.creditsMoved === "number" && Number.isFinite(obj.creditsMoved)
      ? obj.creditsMoved
      : 0;
  const tokenCount =
    typeof obj.tokenCount === "number" && Number.isFinite(obj.tokenCount)
      ? obj.tokenCount
      : 1;
  const createdAt =
    typeof obj.createdAt === "number" && Number.isFinite(obj.createdAt)
      ? obj.createdAt
      : Date.now();
  return {
    key: obj.key,
    creditsMoved,
    tokenCount,
    createdAt,
  };
}

export function readPendingAccessKey(): PendingAccessKeyRecord | null {
  if (typeof window !== "undefined" && window.localStorage) {
    try {
      const raw = window.localStorage.getItem(PENDING_ACCESS_KEY_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        if (
          parsed &&
          parsed.format === "drouter-pending-access-key-v1-vault" &&
          typeof parsed.nonceHex === "string" &&
          typeof parsed.ciphertextHex === "string"
        ) {
          const vault = getCurrentVaultSession();
          if (vault && vault.vaultKeyHex) {
            const payload = openVaultBundle(
              { nonceHex: parsed.nonceHex, ciphertextHex: parsed.ciphertextHex },
              vault.vaultKeyHex,
            );
            const record = parsePendingRecord(JSON.parse(payload.notes ?? "{}"));
            if (record) {
              pendingAccessKeyMemory = record;
              return { ...record };
            }
          }
        } else if (
          parsed &&
          parsed.format === "drouter-pending-access-key-v1-gcm" &&
          typeof parsed.nonceHex === "string" &&
          typeof parsed.ciphertextHex === "string"
        ) {
          const aesKey = getWalletStorageKey();
          const nonce = hexToBytes(parsed.nonceHex);
          const ct = hexToBytes(parsed.ciphertextHex);
          const pt = gcm(aesKey, nonce, CREDITS_STORAGE_AAD).decrypt(ct);
          const record = parsePendingRecord(
            JSON.parse(new TextDecoder().decode(pt)),
          );
          if (record) {
            pendingAccessKeyMemory = record;
            return { ...record };
          }
        }
      }
    } catch {
      // Fall back to session-only memory if storage entry belongs to another session
    }
  }
  return pendingAccessKeyMemory ? { ...pendingAccessKeyMemory } : null;
}

export function clearPendingAccessKey(): void {
  pendingAccessKeyMemory = null;
  if (typeof window === "undefined" || !window.localStorage) {
    return;
  }
  try {
    window.localStorage.removeItem(PENDING_ACCESS_KEY_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

/**
 * Moves `tokenCount` (1..50) tokens out of the browser wallet into a `drk_...` access key.
 * Crash-safe ordering: encodes and persists the pending key first, then removes the tokens from the wallet,
 * keeping the pending key recoverable until the user confirms they copied it.
 */
export function moveTokensToAccessKey(
  tokenCount: number,
  opts?: { onAfterKeyWritten?: (key: string) => void }
): MoveTokensToAccessKeyResult {
  if (!Number.isInteger(tokenCount) || tokenCount < 1 || tokenCount > 50) {
    throw new Error("tokenCount must be an integer between 1 and 50");
  }
  const wallet = readStorage();
  if (wallet.length < tokenCount) {
    throw new Error(
      `Not enough tokens in wallet: need ${tokenCount}, have ${wallet.length}`
    );
  }

  const selected = wallet.slice(0, tokenCount);
  const remaining = wallet.slice(tokenCount);
  const creditsMoved = selected.reduce((sum, t) => sum + (t.denomination || 0), 0);
  const remainingBalance = remaining.reduce((sum, t) => sum + (t.denomination || 0), 0);

  // 1. Encode and persist the pending access key BEFORE mutating the wallet
  const key = encodeAccessKey(selected);
  writePendingAccessKey({
    key,
    creditsMoved,
    tokenCount: selected.length,
    createdAt: Date.now(),
  });

  if (opts?.onAfterKeyWritten) {
    opts.onAfterKeyWritten(key);
  }

  // 2. Remove the moved tokens from the wallet (abort and roll back pending key if storage write fails)
  try {
    writeStorage(remaining);
  } catch (err) {
    clearPendingAccessKey();
    throw err;
  }

  return {
    key,
    tokens: selected,
    creditsMoved,
    remainingBalance,
  };
}

/**
 * Moves enough tokens from the browser wallet to cover `targetCredits` (e.g. 5, 10, or 20)
 * without exceeding `targetCredits` into a `drk_...` access key.
 * Crash-safe: persists the pending key first, then updates the wallet, keeping the pending key
 * until the user confirms they copied it.
 */
export function moveCreditsToAccessKey(
  targetCredits: number,
  opts?: { onAfterKeyWritten?: (key: string) => void }
): MoveTokensToAccessKeyResult {
  if (!Number.isInteger(targetCredits) || targetCredits < 1 || targetCredits > 1000) {
    throw new Error("targetCredits must be a positive integer");
  }
  const wallet = readStorage();
  const selection = selectTokensForTargetCredits(wallet, targetCredits);
  if (!selection) {
    const current = wallet.reduce((s, t) => s + (t.denomination || 0), 0);
    if (current >= targetCredits) {
      throw new Error(
        `Cannot select exactly ${targetCredits} credits without exceeding the requested amount from your current token denominations`
      );
    }
    throw new Error(
      `Not enough credits in wallet: need ${targetCredits}, have ${current}`
    );
  }

  const key = encodeAccessKey(selection.selected);
  writePendingAccessKey({
    key,
    creditsMoved: selection.creditsMoved,
    tokenCount: selection.selected.length,
    createdAt: Date.now(),
  });

  if (opts?.onAfterKeyWritten) {
    opts.onAfterKeyWritten(key);
  }

  try {
    writeStorage(selection.remaining);
  } catch (err) {
    clearPendingAccessKey();
    throw err;
  }

  const remainingBalance = selection.remaining.reduce(
    (sum, t) => sum + (t.denomination || 0),
    0
  );

  return {
    key,
    tokens: selection.selected,
    creditsMoved: selection.creditsMoved,
    remainingBalance,
  };
}

export interface CreditInvoiceClientHandle {
  invoiceId: string;
  depositAddress: Hex;
  amountUsdc: string;
  denomination: number;
  chainId: number;
  usdcContract: Hex;
  usdcDecimals: number;
  expiresAt: number;
  claimSecret: string;
  claimHash: string;
}

/**
 * Requests a one-time deposit address invoice (`POST /api/credits/invoice`) by sending ONLY `sha256(claimSecret)`.
 */
export async function requestCreditInvoice(
  baseUrl: string,
  denomination = 1,
  claimSecretOverride?: string
): Promise<CreditInvoiceClientHandle> {
  const prefix = baseUrl.replace(/\/$/, "");
  const claimSecret = claimSecretOverride
    ? claimSecretOverride.trim().toLowerCase().replace(/^0x/, "")
    : randomSecretHex(32);
  const claimHash = hashClaimSecret(claimSecret);

  const res = await fetch(`${prefix}/api/credits/invoice`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimHash, denomination }),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(
      (errBody as { error?: string }).error ||
        `Failed to create credit invoice (${res.status})`
    );
  }

  const data = (await res.json()) as {
    invoiceId: string;
    depositAddress: Hex;
    amountUsdc: string;
    denomination: number;
    chainId: number;
    usdcContract: Hex;
    usdcDecimals: number;
    expiresAt: number;
  };

  return {
    ...data,
    claimSecret,
    claimHash,
  };
}

/**
 * Claims blind-signed credits for a paid one-time deposit invoice (`POST /api/credits/claim`),
 * unblinds and verifies the RSA signatures, stores the tokens locally, and returns them.
 */
export async function claimPaidCredits(
  baseUrl: string,
  params: {
    invoiceId?: string;
    claimSecret: string;
    count?: number;
    denomination?: number;
  }
): Promise<BlindCreditToken[]> {
  const prefix = baseUrl.replace(/\/$/, "");
  const infoRes = await fetch(`${prefix}/api/credits`);
  if (!infoRes.ok) {
    throw new Error(`Failed to fetch credit issuer public key (${infoRes.status})`);
  }
  const pub = (await infoRes.json()) as {
    n: string;
    e: string;
    denominations: number[];
  };

  const count = params.count ?? 1;
  const denomination = params.denomination ?? 1;

  const pending = Array.from({ length: count }, () => {
    const tokenHex = randomSecretHex(32);
    const { blindedHex, rHex } = blindToken(tokenHex, denomination, pub);
    return { tokenHex, blindedHex, rHex };
  });

  const claimRes = await fetch(`${prefix}/api/credits/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...(params.invoiceId ? { invoiceId: params.invoiceId } : {}),
      claimSecret: params.claimSecret,
      blinded: pending.map((p) => p.blindedHex),
      denomination,
    }),
  });

  if (!claimRes.ok) {
    const errBody = await claimRes.json().catch(() => ({}));
    throw new Error(
      (errBody as { error?: string }).error ||
        `Failed to claim paid credits (${claimRes.status})`
    );
  }

  const signed = (await claimRes.json()) as {
    signatures: string[];
    denomination: number;
  };

  if (
    !Array.isArray(signed.signatures) ||
    signed.signatures.length !== pending.length
  ) {
    throw new Error("Issuer returned mismatched signature count");
  }

  const minted: BlindCreditToken[] = pending.map((item, idx) => {
    const signature = unblindSignature(signed.signatures[idx], item.rHex, pub);
    const creditToken: BlindCreditToken = {
      token: item.tokenHex,
      signature,
      denomination: signed.denomination ?? denomination,
    };
    if (!verifyTokenSignature(creditToken, pub)) {
      throw new Error("Unblinded RSA signature failed local verification");
    }
    return creditToken;
  });

  const existing = readStorage();
  writeStorage([...existing, ...minted]);
  return minted;
}

/**
 * Mints free daily-allowance blind credits via `POST /api/credits`.
 */
export async function mintCredits(
  baseUrl: string,
  count = 4,
  denomination = 1
): Promise<BlindCreditToken[]> {
  const prefix = baseUrl.replace(/\/$/, "");
  const infoRes = await fetch(`${prefix}/api/credits`);
  if (!infoRes.ok) {
    throw new Error(`Failed to fetch credit issuer public key (${infoRes.status})`);
  }
  const pub = (await infoRes.json()) as {
    n: string;
    e: string;
    denominations: number[];
  };

  const pending = Array.from({ length: count }, () => {
    const tokenHex = randomSecretHex(32);
    const { blindedHex, rHex } = blindToken(tokenHex, denomination, pub);
    return { tokenHex, blindedHex, rHex };
  });

  const signRes = await fetch(`${prefix}/api/credits`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      blinded: pending.map((p) => p.blindedHex),
      denomination,
    }),
  });

  if (!signRes.ok) {
    const errBody = await signRes.json().catch(() => ({}));
    throw new Error(
      (errBody as { error?: string }).error ||
        `Failed to mint blinded credits (${signRes.status})`
    );
  }

  const signed = (await signRes.json()) as {
    signatures: string[];
    denomination: number;
  };

  if (
    !Array.isArray(signed.signatures) ||
    signed.signatures.length !== pending.length
  ) {
    throw new Error("Issuer returned mismatched signature count");
  }

  const minted: BlindCreditToken[] = pending.map((item, idx) => {
    const signature = unblindSignature(signed.signatures[idx], item.rHex, pub);
    const creditToken: BlindCreditToken = {
      token: item.tokenHex,
      signature,
      denomination: signed.denomination ?? denomination,
    };
    if (!verifyTokenSignature(creditToken, pub)) {
      throw new Error("Unblinded RSA signature failed local verification");
    }
    return creditToken;
  });

  const existing = readStorage();
  writeStorage([...existing, ...minted]);
  return minted;
}

export async function spendOneCredit(
  baseUrl: string,
  nodeId?: string
): Promise<{
  ok: boolean;
  nullifier?: string;
  remaining: number;
  error?: string;
}> {
  const wallet = readStorage();
  if (wallet.length === 0) {
    return {
      ok: false,
      remaining: 0,
      error: "No credits available in local wallet",
    };
  }

  const [token, ...rest] = wallet;
  writeStorage(rest);
  const remainingAfterSpend = rest.reduce((sum, t) => sum + (t.denomination || 0), 0);

  const prefix = baseUrl.replace(/\/$/, "");
  let res: Response;
  try {
    res = await fetch(`${prefix}/api/credits/spend`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, nodeId }),
    });
  } catch (err) {
    writeStorage([token, ...rest]);
    const restoredBalance = [token, ...rest].reduce((sum, t) => sum + (t.denomination || 0), 0);
    return {
      ok: false,
      remaining: restoredBalance,
      error: err instanceof Error ? err.message : "Network error during credit spend",
    };
  }

  const data = (await res.json().catch(() => ({}))) as {
    ok?: boolean;
    nullifier?: string;
    error?: string;
  };

  if (!res.ok || !data.ok) {
    if (res.status >= 500) {
      writeStorage([token, ...rest]);
      const restoredBalance = [token, ...rest].reduce((sum, t) => sum + (t.denomination || 0), 0);
      return {
        ok: false,
        remaining: restoredBalance,
        error: data.error || `Spend failed with status ${res.status}`,
      };
    }
    return {
      ok: false,
      remaining: remainingAfterSpend,
      error: data.error || `Spend failed with status ${res.status}`,
    };
  }

  return {
    ok: true,
    nullifier: data.nullifier,
    remaining: remainingAfterSpend,
  };
}
