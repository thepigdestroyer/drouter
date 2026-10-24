import { bytesToHex } from "@noble/hashes/utils.js";
import type { BlindCreditToken } from "@/lib/types";
import {
  blindToken,
  unblindSignature,
  verifyTokenSignature,
} from "./blind";

const STORAGE_KEY = "drouter.credits.v1";

let memoryStore: BlindCreditToken[] = [];

function readStorage(): BlindCreditToken[] {
  if (typeof window === "undefined" || !window.localStorage) {
    return [...memoryStore];
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is BlindCreditToken =>
        Boolean(
          item &&
            typeof item.token === "string" &&
            typeof item.signature === "string" &&
            typeof item.denomination === "number"
        )
    );
  } catch {
    return [];
  }
}

function writeStorage(tokens: BlindCreditToken[]): void {
  memoryStore = [...tokens];
  if (typeof window === "undefined" || !window.localStorage) {
    return;
  }
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
  } catch {
    // Ignore storage quota errors
  }
}

function randomSecretHex(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
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
  const remaining = rest.reduce((sum, t) => sum + (t.denomination || 0), 0);

  const prefix = baseUrl.replace(/\/$/, "");
  const res = await fetch(`${prefix}/api/credits/spend`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, nodeId }),
  });

  const data = (await res.json().catch(() => ({}))) as {
    ok?: boolean;
    nullifier?: string;
    error?: string;
  };

  if (!res.ok || !data.ok) {
    return {
      ok: false,
      remaining,
      error: data.error || `Spend failed with status ${res.status}`,
    };
  }

  return {
    ok: true,
    nullifier: data.nullifier,
    remaining,
  };
}
