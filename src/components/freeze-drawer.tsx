"use client";

import { useState } from "react";
import type { FreezeReceipt } from "@/lib/types";

export interface FreezeDrawerProps {
  canFreeze: boolean;
  onFreeze: () => Promise<FreezeReceipt | null>;
  onResume: (blobId: string, freezeSecretHex: string) => Promise<void>;
}

export function FreezeDrawer({
  canFreeze,
  onFreeze,
  onResume,
}: FreezeDrawerProps) {
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
      setStatusError((e as Error).message || "Failed to freeze session");
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
      setStatusError(
        (err as Error).message || "Could not decrypt or resume frozen session",
      );
    } finally {
      setResuming(false);
    }
  };

  return (
    <div className="border-t border-rule pt-3 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void handleFreeze()}
            disabled={!canFreeze || freezing}
            className="ep-btn-ghost px-2.5 py-1 text-xs disabled:opacity-40"
            title="Encrypt conversation in browser and save opaque ciphertext"
          >
            {freezing ? "Freezing..." : "Freeze session"}
          </button>
          <button
            type="button"
            onClick={() => setResumeOpen((prev) => !prev)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {resumeOpen ? "Hide resume form" : "Resume frozen session"}
          </button>
        </div>
        <span className="text-[11px] text-ink-3">
          Freeze keys stay in your browser: <code className="font-mono">HKDF(freeze_secret, session_id)</code>
        </span>
      </div>

      {statusError && (
        <p className="mt-2 rounded border border-accent bg-accent-soft px-2.5 py-1.5 text-xs text-accent">
          {statusError}
        </p>
      )}

      {receipt && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              {shredded
                ? "Freeze key wiped. Stored ciphertext can no longer be decrypted."
                : "Session frozen. Save this key to resume later."}
            </span>
            {!shredded && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyKey()}
                  className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                >
                  {copied ? "Copied" : "Copy key"}
                </button>
                <button
                  type="button"
                  onClick={handleCryptoShred}
                  className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                >
                  Wipe key
                </button>
              </div>
            )}
          </div>

          <dl className="space-y-1 font-mono text-[11px]">
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[7.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Blob ID</dt>
              <dd className="break-all text-ink">{receipt.blobId}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[7.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Session ID</dt>
              <dd className="break-all text-ink-2">{receipt.sessionIdHex}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[7.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Freeze secret</dt>
              <dd className="break-all">
                {shredded ? (
                  <span className="text-accent">
                    [Wiped from browser memory]
                  </span>
                ) : (
                  <span className="text-ink">{receipt.freezeSecretHex}</span>
                )}
              </dd>
            </div>
          </dl>
        </div>
      )}

      {resumeOpen && (
        <form
          onSubmit={(e) => void handleResumeSubmit(e)}
          className="ep-inset mt-2.5 grid grid-cols-1 gap-2 p-3 sm:grid-cols-[1fr_1.4fr_auto]"
        >
          <label className="flex flex-col gap-1 text-[11px] text-ink-2">
            Blob ID
            <input
              type="text"
              value={blobIdInput}
              onChange={(e) => setBlobIdInput(e.target.value)}
              placeholder="blob_..."
              className="ep-input py-1 font-mono text-xs"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-ink-2">
            Freeze secret (hex)
            <input
              type="text"
              value={secretInput}
              onChange={(e) => setSecretInput(e.target.value)}
              placeholder="64-character hex secret"
              className="ep-input py-1 font-mono text-xs"
            />
          </label>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={!blobIdInput.trim() || !secretInput.trim() || resuming}
              className="ep-btn w-full py-1.5 text-xs sm:w-auto"
            >
              {resuming ? "Decrypting..." : "Decrypt & resume"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

export default FreezeDrawer;
