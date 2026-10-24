import { decryptFrozenState, encryptFrozenState } from "./crypto";
import type { FreezeReceipt, FrozenSessionState } from "@/lib/types";

const STORAGE_KEY = "drouter.freeze.v1";

let memoryFallback: FreezeReceipt[] = [];

function hasLocalStorage(): boolean {
  try {
    return (
      typeof window !== "undefined" &&
      typeof window.localStorage !== "undefined" &&
      window.localStorage !== null &&
      typeof window.localStorage.getItem === "function"
    );
  } catch {
    return false;
  }
}

function readReceipts(): FreezeReceipt[] {
  if (hasLocalStorage()) {
    try {
      const raw = globalThis.localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed as FreezeReceipt[];
      }
      return [];
    } catch {
      return [];
    }
  }
  return [...memoryFallback];
}

function writeReceipts(receipts: FreezeReceipt[]): void {
  memoryFallback = [...receipts];
  if (hasLocalStorage()) {
    try {
      globalThis.localStorage.setItem(STORAGE_KEY, JSON.stringify(receipts));
    } catch {
      // Ignore quota/storage errors and rely on memoryFallback
    }
  }
}

/**
 * Lists all locally stored FreezeReceipts (containing client-held freezeSecretHex).
 */
export function listLocalFreezeReceipts(): FreezeReceipt[] {
  return readReceipts();
}

/**
 * Encrypts session state locally on the client, uploads ONLY the ciphertext bundle
 * (without freezeSecretHex or plaintext messages) to the server store, and saves
 * the FreezeReceipt locally.
 */
export async function freezeAndUpload(
  baseUrl: string,
  state: FrozenSessionState,
): Promise<FreezeReceipt & { byteLength: number }> {
  const bundle = encryptFrozenState(state);
  const prefix = baseUrl.replace(/\/+$/, "");

  const uploadPayload = {
    blobId: bundle.blobId,
    sessionIdHex: bundle.sessionIdHex,
    nonceHex: bundle.nonceHex,
    aadHex: bundle.aadHex,
    ciphertextHex: bundle.ciphertextHex,
    modelId: bundle.modelId,
    createdAt: bundle.createdAt,
  };

  const res = await fetch(`${prefix}/api/freeze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(uploadPayload),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(
      typeof errBody?.error === "string"
        ? errBody.error
        : `Freeze upload failed with status ${res.status}`,
    );
  }

  const data = (await res.json()) as {
    stored: boolean;
    blobId: string;
    byteLength: number;
  };

  const receipt: FreezeReceipt = {
    blobId: bundle.blobId,
    freezeSecretHex: bundle.freezeSecretHex,
    sessionIdHex: bundle.sessionIdHex,
    createdAt: bundle.createdAt,
  };

  const existing = readReceipts().filter((r) => r.blobId !== receipt.blobId);
  writeReceipts([receipt, ...existing]);

  return {
    ...receipt,
    byteLength:
      typeof data.byteLength === "number"
        ? data.byteLength
        : bundle.ciphertextHex.length / 2,
  };
}

/**
 * Downloads an encrypted session blob by blobId and decrypts it locally using
 * the client-held freezeSecretHex.
 */
export async function downloadAndResume(
  baseUrl: string,
  blobId: string,
  freezeSecretHex: string,
): Promise<FrozenSessionState> {
  const prefix = baseUrl.replace(/\/+$/, "");
  const res = await fetch(`${prefix}/api/freeze/${encodeURIComponent(blobId)}`, {
    method: "GET",
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch frozen blob ${blobId}: status ${res.status}`);
  }

  const bundle = (await res.json()) as {
    blobId: string;
    sessionIdHex: string;
    nonceHex: string;
    aadHex: string;
    ciphertextHex: string;
  };

  return decryptFrozenState(bundle, freezeSecretHex);
}

/**
 * Crypto-shreds a frozen session by permanently removing its freezeSecretHex
 * from local storage, rendering the server-side ciphertext unrecoverable.
 */
export function shredLocalFreezeSecret(blobId: string): { shredded: boolean } {
  const current = readReceipts();
  const next = current.filter((r) => r.blobId !== blobId);
  const shredded = next.length !== current.length;
  writeReceipts(next);
  return { shredded };
}
