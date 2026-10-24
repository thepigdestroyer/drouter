"use client";

import { useCallback, useEffect, useState } from "react";
import {
  checkFrozenBlobStatus,
  destroyFrozenSession,
  formatResumeCode,
  listLocalFreezeReceipts,
  parseResumeCode,
  type StoredFreezeReceipt,
} from "@/lib/freeze/client";
import type { FreezeReceipt } from "@/lib/types";

export interface FreezeDrawerProps {
  canFreeze: boolean;
  onFreeze: () => Promise<FreezeReceipt | null>;
  onResume: (blobId: string, freezeSecretHex: string) => Promise<void>;
  baseUrl?: string;
}

export type FreezeDrawerState = "idle" | "frozen" | "resumable" | "destroyed" | "expired";

function formatUtcHour(epochSec?: number): string {
  if (!epochSec || !Number.isFinite(epochSec)) return "Coarse UTC hour";
  const sec = epochSec > 10_000_000_000 ? Math.floor(epochSec / 1000) : Math.floor(epochSec);
  const coarse = sec - (sec % 3600);
  try {
    return new Date(coarse * 1000).toISOString().slice(0, 13) + ":00 UTC";
  } catch {
    return "Coarse UTC hour";
  }
}

export function FreezeDrawer({
  canFreeze,
  onFreeze,
  onResume,
  baseUrl,
}: FreezeDrawerProps) {
  const [freezing, setFreezing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [destroying, setDestroying] = useState(false);
  const [checkingStatus, setCheckingStatus] = useState(false);

  const [drawerState, setDrawerState] = useState<FreezeDrawerState>("idle");
  const [activeReceipt, setActiveReceipt] = useState<StoredFreezeReceipt | null>(null);
  const [savedReceipts, setSavedReceipts] = useState<StoredFreezeReceipt[]>([]);
  const [destroyedInfo, setDestroyedInfo] = useState<{
    blobId: string;
    verifiedAbsent: boolean;
    localSecretWiped: boolean;
  } | null>(null);

  const [copiedCode, setCopiedCode] = useState(false);
  const [resumeOpen, setResumeOpen] = useState(false);
  const [resumeCodeInput, setResumeCodeInput] = useState("");
  const [blobIdInput, setBlobIdInput] = useState("");
  const [secretInput, setSecretInput] = useState("");
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusNote, setStatusNote] = useState<string | null>(null);

  const resolveOrigin = useCallback(() => {
    if (baseUrl) return baseUrl;
    if (typeof window !== "undefined" && window.location?.origin) {
      return window.location.origin;
    }
    return "";
  }, [baseUrl]);

  const refreshSavedFromStorage = useCallback(async () => {
    const list = listLocalFreezeReceipts();
    setSavedReceipts(list);
    if (list.length > 0) {
      const latest = list[0];
      setActiveReceipt(latest);
      setBlobIdInput(latest.blobId);
      setSecretInput(latest.freezeSecretHex);
      try {
        setResumeCodeInput(
          latest.resumeCode ||
            formatResumeCode({
              blobId: latest.blobId,
              freezeSecretHex: latest.freezeSecretHex,
              sessionIdHex: latest.sessionIdHex,
            }),
        );
      } catch {
        // Ignore formatting if secret was wiped
      }

      const origin = resolveOrigin();
      if (origin) {
        setCheckingStatus(true);
        try {
          const check = await checkFrozenBlobStatus(origin, latest.blobId, latest.expiresAt);
          if (check.status === "expired") {
            setDrawerState("expired");
          } else if (check.status === "destroyed") {
            setDrawerState("destroyed");
          } else {
            setDrawerState("resumable");
            setActiveReceipt((prev) =>
              prev
                ? {
                    ...prev,
                    expiresAt: check.expiresAt ?? prev.expiresAt,
                    byteLength: check.byteLength ?? prev.byteLength,
                    storageMode: check.storageMode ?? prev.storageMode,
                    persisted: check.persisted ?? prev.persisted,
                  }
                : prev,
            );
          }
        } finally {
          setCheckingStatus(false);
        }
      } else {
        setDrawerState("resumable");
      }
    }
  }, [resolveOrigin]);

  useEffect(() => {
    void refreshSavedFromStorage();
  }, [refreshSavedFromStorage]);

  const handleFreeze = async () => {
    if (!canFreeze || freezing) return;
    setFreezing(true);
    setStatusError(null);
    setStatusNote(null);
    setDestroyedInfo(null);
    setCopiedCode(false);
    try {
      const res = (await onFreeze()) as StoredFreezeReceipt | null;
      if (res) {
        const code =
          res.resumeCode ||
          formatResumeCode({
            blobId: res.blobId,
            freezeSecretHex: res.freezeSecretHex,
            sessionIdHex: res.sessionIdHex,
          });
        const enriched: StoredFreezeReceipt = {
          ...res,
          resumeCode: code,
        };
        setActiveReceipt(enriched);
        setSavedReceipts(listLocalFreezeReceipts());
        setBlobIdInput(enriched.blobId);
        setSecretInput(enriched.freezeSecretHex);
        setResumeCodeInput(code);
        setDrawerState("frozen");
        setStatusNote("Conversation encrypted in browser with AES-256-GCM. Plaintext never left your device.");
      }
    } catch (e) {
      setStatusError((e as Error).message || "Failed to freeze session");
    } finally {
      setFreezing(false);
    }
  };

  const handleCopyResumeCode = async () => {
    if (!activeReceipt || drawerState === "destroyed") return;
    let code = activeReceipt.resumeCode;
    if (!code) {
      try {
        code = formatResumeCode({
          blobId: activeReceipt.blobId,
          freezeSecretHex: activeReceipt.freezeSecretHex,
          sessionIdHex: activeReceipt.sessionIdHex,
        });
      } catch {
        return;
      }
    }
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    } catch {
      setCopiedCode(false);
    }
  };

  const handleDestroy = async (targetBlobId?: string) => {
    const blobId = (targetBlobId || activeReceipt?.blobId || blobIdInput).trim();
    if (!blobId || destroying) return;
    setDestroying(true);
    setStatusError(null);
    setStatusNote(null);
    try {
      const result = await destroyFrozenSession(resolveOrigin(), blobId);
      setDestroyedInfo({
        blobId: result.blobId,
        verifiedAbsent: result.verifiedAbsent,
        localSecretWiped: result.localSecretWiped,
      });
      if (activeReceipt && activeReceipt.blobId.toLowerCase() === result.blobId.toLowerCase()) {
        setActiveReceipt({
          ...activeReceipt,
          freezeSecretHex: "",
          resumeCode: "",
        });
      }
      if (blobIdInput.trim().toLowerCase() === result.blobId.toLowerCase()) {
        setSecretInput("");
        setResumeCodeInput("");
      }
      setSavedReceipts(listLocalFreezeReceipts());
      setDrawerState("destroyed");
    } catch (e) {
      setStatusError((e as Error).message || "Failed to destroy frozen session");
    } finally {
      setDestroying(false);
    }
  };

  const handleResumeCodeChange = (value: string) => {
    setResumeCodeInput(value);
    const trimmed = value.trim();
    if (!trimmed) return;
    try {
      const parsed = parseResumeCode(trimmed);
      setBlobIdInput(parsed.blobId);
      setSecretInput(parsed.freezeSecretHex);
      setStatusError(null);
    } catch {
      // Allow user to finish typing or use individual fields
    }
  };

  const handleSelectSavedReceipt = async (item: StoredFreezeReceipt) => {
    setActiveReceipt(item);
    setDestroyedInfo(null);
    setStatusError(null);
    setStatusNote(null);
    setBlobIdInput(item.blobId);
    setSecretInput(item.freezeSecretHex);
    try {
      setResumeCodeInput(
        item.resumeCode ||
          formatResumeCode({
            blobId: item.blobId,
            freezeSecretHex: item.freezeSecretHex,
            sessionIdHex: item.sessionIdHex,
          }),
      );
    } catch {
      setResumeCodeInput("");
    }
    const origin = resolveOrigin();
    if (origin) {
      setCheckingStatus(true);
      try {
        const check = await checkFrozenBlobStatus(origin, item.blobId, item.expiresAt);
        if (check.status === "expired") {
          setDrawerState("expired");
        } else if (check.status === "destroyed") {
          setDrawerState("destroyed");
        } else {
          setDrawerState("resumable");
        }
      } finally {
        setCheckingStatus(false);
      }
    } else {
      setDrawerState("resumable");
    }
  };

  const handleQuickResumeActive = async () => {
    if (!activeReceipt || !activeReceipt.freezeSecretHex || resuming) return;
    setResuming(true);
    setStatusError(null);
    setStatusNote(null);
    try {
      await onResume(activeReceipt.blobId, activeReceipt.freezeSecretHex);
      setDrawerState("resumable");
      setStatusNote("Session decrypted and resumed in browser.");
    } catch (err) {
      const msg = (err as Error).message || "Could not decrypt or resume frozen session";
      if (/expired/i.test(msg)) {
        setDrawerState("expired");
      } else if (/destroyed|404/i.test(msg)) {
        setDrawerState("destroyed");
      }
      setStatusError(msg);
    } finally {
      setResuming(false);
    }
  };

  const handleResumeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (resuming) return;

    let b = blobIdInput.trim();
    let s = secretInput.trim();

    if (resumeCodeInput.trim()) {
      try {
        const parsed = parseResumeCode(resumeCodeInput.trim());
        b = parsed.blobId;
        s = parsed.freezeSecretHex;
        setBlobIdInput(b);
        setSecretInput(s);
      } catch (err) {
        if (!b || !s) {
          setStatusError((err as Error).message || "Invalid resume code");
          return;
        }
      }
    }

    if (!b || !s) return;

    setResuming(true);
    setStatusError(null);
    setStatusNote(null);
    try {
      await onResume(b, s);
      setDrawerState("resumable");
      setResumeOpen(false);
      setStatusNote("Session decrypted and resumed in browser.");
    } catch (err) {
      const msg = (err as Error).message || "Could not decrypt or resume frozen session";
      if (/expired/i.test(msg)) {
        setDrawerState("expired");
      } else if (/destroyed|404/i.test(msg)) {
        setDrawerState("destroyed");
      }
      setStatusError(msg);
    } finally {
      setResuming(false);
    }
  };

  const currentResumeCode = (() => {
    if (!activeReceipt || !activeReceipt.freezeSecretHex) return "";
    if (activeReceipt.resumeCode) return activeReceipt.resumeCode;
    try {
      return formatResumeCode({
        blobId: activeReceipt.blobId,
        freezeSecretHex: activeReceipt.freezeSecretHex,
        sessionIdHex: activeReceipt.sessionIdHex,
      });
    } catch {
      return "";
    }
  })();

  return (
    <div className="border-t border-rule pt-3 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void handleFreeze()}
            disabled={!canFreeze || freezing}
            className="ep-btn-ghost px-2.5 py-1 text-xs disabled:opacity-40"
            title="Encrypt conversation in browser with AES-256-GCM and store only opaque ciphertext"
          >
            {freezing ? "Freezing..." : "Freeze session"}
          </button>
          <button
            type="button"
            onClick={() => setResumeOpen((prev) => !prev)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {resumeOpen ? "Hide resume form" : "Resume with code"}
          </button>
          {drawerState === "frozen" && <span className="ep-pass">Frozen</span>}
          {drawerState === "resumable" && (
            <span className="ep-pass">{checkingStatus ? "Checking..." : "Resumable"}</span>
          )}
          {drawerState === "destroyed" && <span className="ep-fail">Destroyed</span>}
          {drawerState === "expired" && <span className="ep-fail">Expired</span>}
        </div>
        <span className="text-[11px] text-ink-3">
          Client key: <code className="font-mono">HKDF-SHA384(freeze_secret, session_id)</code>
        </span>
      </div>

      {statusError && (
        <p className="mt-2 rounded border border-accent bg-accent-soft px-2.5 py-1.5 text-xs text-accent">
          {statusError}
        </p>
      )}

      {statusNote && !statusError && (
        <p className="mt-2 rounded border border-rule bg-paper-2 px-2.5 py-1.5 text-xs text-ink-2">
          {statusNote}
        </p>
      )}

      {savedReceipts.length > 1 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-3">
          <span className="ep-label">Saved keys in browser:</span>
          {savedReceipts.slice(0, 4).map((item) => (
            <button
              key={item.blobId}
              type="button"
              onClick={() => void handleSelectSavedReceipt(item)}
              className={`ep-muted-chip cursor-pointer hover:border-ink hover:text-ink ${
                activeReceipt?.blobId === item.blobId ? "border-ink text-ink" : ""
              }`}
            >
              {item.blobId.slice(0, 10)}
            </button>
          ))}
        </div>
      )}

      {(drawerState === "frozen" || drawerState === "resumable") && activeReceipt && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="font-medium text-ink">
                {drawerState === "frozen"
                  ? "Session frozen. Copy the resume code to restore on any device."
                  : "Encrypted session ready to resume from local browser storage."}
              </span>
              {activeReceipt.storageMode === "simulated-memory" && (
                <span className="ml-2 ep-muted-chip">Simulated ephemeral memory</span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => void handleQuickResumeActive()}
                disabled={resuming || !activeReceipt.freezeSecretHex}
                className="ep-btn px-2.5 py-1 text-[11px]"
              >
                {resuming ? "Decrypting..." : "Resume now"}
              </button>
              <button
                type="button"
                onClick={() => void handleCopyResumeCode()}
                className="ep-btn-ghost px-2 py-0.5 text-[11px]"
              >
                {copiedCode ? "Copied resume code" : "Copy resume code"}
              </button>
              <button
                type="button"
                onClick={() => void handleDestroy(activeReceipt.blobId)}
                disabled={destroying}
                className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                title="Delete server ciphertext and wipe local decryption key"
              >
                {destroying ? "Destroying..." : "Destroy"}
              </button>
            </div>
          </div>

          <dl className="space-y-1 font-mono text-[11px]">
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Blob ID</dt>
              <dd className="break-all text-ink">{activeReceipt.blobId}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Session ID</dt>
              <dd className="break-all text-ink-2">{activeReceipt.sessionIdHex}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Resume code</dt>
              <dd className="break-all text-ink">{currentResumeCode}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
              <dt className="font-sans text-ink-3">Coarse expiry</dt>
              <dd className="font-sans text-ink-2">
                {formatUtcHour(activeReceipt.expiresAt)} (MongoDB TTL auto-delete)
              </dd>
            </div>
          </dl>
        </div>
      )}

      {drawerState === "destroyed" && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              Frozen session destroyed. Local key wiped and server ciphertext deleted.
            </span>
            <span className="ep-fail">Crypto-shredded</span>
          </div>
          {destroyedInfo && (
            <dl className="mt-2 space-y-1 font-mono text-[11px]">
              <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                <dt className="font-sans text-ink-3">Blob ID</dt>
                <dd className="break-all text-ink-2">{destroyedInfo.blobId}</dd>
              </div>
              <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                <dt className="font-sans text-ink-3">Local key</dt>
                <dd className="font-sans text-ink">
                  {destroyedInfo.localSecretWiped
                    ? "Zeroed and removed from encrypted localStorage"
                    : "Not present in localStorage"}
                </dd>
              </div>
              <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                <dt className="font-sans text-ink-3">Server verification</dt>
                <dd className="font-sans text-ink">
                  {destroyedInfo.verifiedAbsent
                    ? "Verified absent (404 confirmed)"
                    : "Delete requested"}
                </dd>
              </div>
            </dl>
          )}
        </div>
      )}

      {drawerState === "expired" && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              Frozen blob has passed its coarse UTC expiry window and was purged by TTL.
            </span>
            {activeReceipt && (
              <button
                type="button"
                onClick={() => void handleDestroy(activeReceipt.blobId)}
                className="ep-btn-ghost px-2 py-0.5 text-[11px]"
              >
                Wipe local receipt
              </button>
            )}
          </div>
        </div>
      )}

      {resumeOpen && (
        <form
          onSubmit={(e) => void handleResumeSubmit(e)}
          className="ep-inset mt-2.5 space-y-2.5 p-3"
        >
          <label className="flex flex-col gap-1 text-[11px] text-ink-2">
            Resume code (paste across devices or page reloads)
            <input
              type="text"
              value={resumeCodeInput}
              onChange={(e) => handleResumeCodeChange(e.target.value)}
              placeholder="drouter-freeze-v1:<blobId>:<freezeSecretHex>"
              className="ep-input py-1 font-mono text-xs"
            />
          </label>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1.4fr_auto]">
            <label className="flex flex-col gap-1 text-[11px] text-ink-2">
              Blob ID
              <input
                type="text"
                value={blobIdInput}
                onChange={(e) => setBlobIdInput(e.target.value)}
                placeholder="32-character hex blobId"
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
            <div className="flex items-end gap-1.5">
              <button
                type="submit"
                disabled={
                  (!resumeCodeInput.trim() && (!blobIdInput.trim() || !secretInput.trim())) ||
                  resuming
                }
                className="ep-btn w-full py-1.5 text-xs sm:w-auto"
              >
                {resuming ? "Decrypting..." : "Decrypt & resume"}
              </button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}

export default FreezeDrawer;
