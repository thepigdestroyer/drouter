import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { BlindCreditToken } from "@/lib/types";
import { getCurrentVaultSession } from "@/lib/auth/vault";
import {
  blindToken,
  unblindSignature,
  verifyTokenSignature,
} from "./blind";

const STORAGE_KEY = "drouter.credits.v1";
const CREDITS_STORAGE_AAD = utf8ToBytes("drouter/v1/credits-wallet");

let memoryStore: BlindCreditToken[] = [];
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
    if (!raw) return [...memoryStore];
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
    return list.filter(
      (item): item is BlindCreditToken =>
        Boolean(
          item &&
            typeof (item as BlindCreditToken).token === "string" &&
            typeof (item as BlindCreditToken).signature === "string" &&
            typeof (item as BlindCreditToken).denomination === "number"
        )
    );
  } catch {
    return [...memoryStore];
  }
}

function writeStorage(tokens: BlindCreditToken[]): void {
  memoryStore = [...tokens];
  if (typeof window === "undefined" || !window.localStorage) {
    return;
  }
  try {
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
  } catch {
    // Ignore storage quota errors
  }
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

export function getStoredCredits(): BlindCreditToken[] {
  return readStorage();
}

export function storedCreditBalance(): number {
  return readStorage().reduce((sum, t) => sum + (t.denomination || 0), 0);
}

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
    // Network error before spend reached server: restore token to wallet
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
