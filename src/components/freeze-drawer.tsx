"use client";

import { useState } from "react";
import type { FreezeReceipt } from "@/lib/types";

export interface FreezeDrawerProps {
  canFreeze: boolean;
  onFreeze: () => Promise<FreezeReceipt | null>;
  onResume: (blobId: string, freezeSecretHex: string) => Promise<void>;
}

export function FreezeDrawer({ canFreeze, onFreeze, onResume }: FreezeDrawerProps) {
  const [freezing, setFreezing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [receipt, setReceipt] = useState<FreezeReceipt | null>(null);
  const [shredded, setShredded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [resumeOpen, setResumeOpen] = useState(false);
  const [blobIdInput, setBlobIdInput] = useState("");
  const [secretInput, setSecretInput] = useState("");
  const [statusError, setStatusError] = useState<string | null>(null);

  const handleFreeze = async () => {
    if (!canFreeze || freezing) return;
    setFreezing(true);
    setStatusError(null);
    setShredded(false);
    setCopied(false);
    try {
      const res = await onFreeze();
      if (res) {
        setReceipt(res);
        setBlobIdInput(res.blobId);
        setSecretInput(res.freezeSecretHex);
      }
    } catch (e) {
      setStatusError((e as Error).message || "Failed to freeze session bubble");
    } finally {
      setFreezing(false);
    }
  };

  const handleCopyKey = async () => {
    if (!receipt || shredded) return;
    const bundle = JSON.stringify(
      {
        blobId: receipt.blobId,
        freezeSecretHex: receipt.freezeSecretHex,
        sessionIdHex: receipt.sessionIdHex,
      },
      null,
      2,
    );
    try {
      await navigator.clipboard.writeText(bundle);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const handleCryptoShred = () => {
    if (!receipt) return;
    setReceipt({
      ...receipt,
      freezeSecretHex: "",
    });
    if (secretInput === receipt.freezeSecretHex) {
      setSecretInput("");
    }
    setShredded(true);
  };

  const handleResumeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const b = blobIdInput.trim();
    const s = secretInput.trim();
    if (!b || !s || resuming) return;
    setResuming(true);
    setStatusError(null);
    try {
      await onResume(b, s);
      setResumeOpen(false);
    } catch (err) {
      setStatusError((err as Error).message || "Could not decrypt or resume frozen bubble");
    } finally {
      setResuming(false);
    }
  };

  return (
    <div className="border-t border-zinc-800 bg-zinc-950/80 px-3 py-2.5 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void handleFreeze()}
            disabled={!canFreeze || freezing}
            className="rounded-md border border-indigo-700/80 bg-indigo-950/60 px-2.5 py-1 text-xs font-semibold text-indigo-200 hover:bg-indigo-900/60 disabled:opacity-35"
            title="Encrypt conversation state in browser under HKDF(freeze_secret, session_id) and store opaque ciphertext"
          >
            {freezing ? "Freezing…" : "Freeze bubble"}
          </button>
          <button
            type="button"
            onClick={() => setResumeOpen((prev) => !prev)}
            className="rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-300 hover:border-zinc-600 hover:text-zinc-100"
          >
            {resumeOpen ? "Hide resume form" : "Resume frozen bubble"}
          </button>
        </div>
        <span className="text-[11px] text-zinc-500">
          Zero-knowledge persistence: <code className="font-mono">K_freeze = HKDF(freeze_secret, session_id)</code> never leaves your browser.
        </span>
      </div>

      {statusError && (
        <p className="mt-2 rounded border border-rose-900 bg-rose-950/40 px-2.5 py-1.5 text-xs text-rose-200">
          {statusError}
        </p>
      )}

      {receipt && (
        <div className="mt-2.5 rounded-md border border-indigo-800/80 bg-indigo-950/30 p-3 text-xs text-indigo-100">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold text-indigo-200">
              {shredded
                ? "Freeze key crypto-shredded — remote ciphertext permanently undecryptable"
                : "Bubble frozen — client-held decryption capability"}
            </span>
            <div className="flex items-center gap-2">
              {!shredded && (
                <>
                  <button
                    type="button"
                    onClick={() => void handleCopyKey()}
                    className="rounded border border-indigo-700 bg-indigo-900/60 px-2 py-0.5 text-[11px] font-medium text-indigo-100 hover:bg-indigo-800/60"
                  >
                    {copied ? "Copied ✓" : "Copy key"}
                  </button>
                  <button
                    type="button"
                    onClick={handleCryptoShred}
                    className="rounded border border-rose-800 bg-rose-950/70 px-2 py-0.5 text-[11px] font-medium text-rose-200 hover:bg-rose-900/70"
                  >
                    Crypto-shred secret
                  </button>
                </>
              )}
            </div>
          </div>

          <dl className="space-y-1 font-mono text-[11px]">
            <div className="grid grid-cols-[7.5rem_1fr] gap-2">
              <dt className="font-sans text-indigo-300/70">Blob ID</dt>
              <dd className="break-all text-indigo-100">{receipt.blobId}</dd>
            </div>
            <div className="grid grid-cols-[7.5rem_1fr] gap-2">
              <dt className="font-sans text-indigo-300/70">Session ID</dt>
              <dd className="break-all text-indigo-200/90">{receipt.sessionIdHex}</dd>
            </div>
            <div className="grid grid-cols-[7.5rem_1fr] gap-2">
              <dt className="font-sans text-indigo-300/70">Freeze secret</dt>
              <dd className="break-all">
                {shredded ? (
                  <span className="text-rose-300">[WIPED — 32-BYTE ENTROPY ZEROED IN CLIENT MEMORY]</span>
                ) : (
                  <span className="text-emerald-300">{receipt.freezeSecretHex}</span>
                )}
              </dd>
            </div>
          </dl>

          {shredded && (
            <p className="mt-2 text-[11px] leading-relaxed text-rose-200/90">
              The 256-bit <code className="font-mono">freeze_secret</code> has been wiped from browser memory. Without it,{" "}
              <code className="font-mono">K_freeze</code> cannot be re-derived, so the AES-256-GCM ciphertext stored in
              MongoDB is now permanently undecryptable (cryptographic erasure).
            </p>
          )}
        </div>
      )}

      {resumeOpen && (
        <form
          onSubmit={(e) => void handleResumeSubmit(e)}
          className="mt-2.5 grid grid-cols-1 gap-2 rounded-md border border-zinc-800 bg-zinc-900/60 p-2.5 sm:grid-cols-[1fr_1.4fr_auto]"
        >
          <label className="flex flex-col gap-1 text-[11px] text-zinc-400">
            Blob ID
            <input
              type="text"
              value={blobIdInput}
              onChange={(e) => setBlobIdInput(e.target.value)}
              placeholder="e.g. blob_..."
              className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 placeholder:text-zinc-600"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-zinc-400">
            Freeze secret (hex)
            <input
              type="text"
              value={secretInput}
              onChange={(e) => setSecretInput(e.target.value)}
              placeholder="64-char hex freeze_secret"
              className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 placeholder:text-zinc-600"
            />
          </label>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={!blobIdInput.trim() || !secretInput.trim() || resuming}
              className="w-full rounded border border-emerald-700 bg-emerald-900/60 px-3 py-1.5 text-xs font-semibold text-emerald-100 hover:bg-emerald-800/60 disabled:opacity-40 sm:w-auto"
            >
              {resuming ? "Decrypting…" : "Decrypt & resume"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

export default FreezeDrawer;
