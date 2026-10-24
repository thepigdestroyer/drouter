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
import { TechDetails } from "@/components/ink/tech-details";

export interface FreezeDrawerProps {
  canFreeze: boolean;
  onFreeze: () => Promise<FreezeReceipt | null>;
  onResume: (blobId: string, freezeSecretHex: string) => Promise<void>;
  baseUrl?: string;
}

export type FreezeDrawerState =
  | "idle"
  | "frozen"
  | "resumable"
  | "destroyed"
  | "expired";

function formatUtcHour(epochSec?: number): string {
  if (!epochSec || !Number.isFinite(epochSec)) return "Within the next hour";
  const sec =
    epochSec > 10_000_000_000 ? Math.floor(epochSec / 1000) : Math.floor(epochSec);
  const coarse = sec - (sec % 3600);
  try {
    return new Date(coarse * 1000).toISOString().slice(0, 13) + ":00 UTC";
  } catch {
    return "Within the next hour";
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
  const [activeReceipt, setActiveReceipt] = useState<StoredFreezeReceipt | null>(
    null,
  );
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
          const check = await checkFrozenBlobStatus(
            origin,
            latest.blobId,
            latest.expiresAt,
          );
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
        setStatusNote(
          "Your chat is paused and locked on your device. Only your secret code can reopen it.",
        );
      }
    } catch (e) {
      setStatusError((e as Error).message || "Could not pause and lock this chat");
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
      if (
        activeReceipt &&
        activeReceipt.blobId.toLowerCase() === result.blobId.toLowerCase()
      ) {
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
      setStatusError((e as Error).message || "Could not delete saved chat");
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
        const check = await checkFrozenBlobStatus(
          origin,
          item.blobId,
          item.expiresAt,
        );
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
      setStatusNote("Chat unlocked and restored in your browser.");
    } catch (err) {
      const msg = (err as Error).message || "Could not unlock or restore this chat";
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
          setStatusError((err as Error).message || "Invalid recovery code");
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
      setStatusNote("Chat unlocked and restored in your browser.");
    } catch (err) {
      const msg = (err as Error).message || "Could not unlock or restore this chat";
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
            title="Lock your chat in your browser so you can come back to it later"
          >
            {freezing ? "Locking chat..." : "Pause and lock this chat"}
          </button>
          <button
            type="button"
            onClick={() => setResumeOpen((prev) => !prev)}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {resumeOpen ? "Hide recovery form" : "Pick up where you left off"}
          </button>
          {drawerState === "frozen" && (
            <span className="ep-pass">Paused and locked</span>
          )}
          {drawerState === "resumable" && (
            <span className="ep-pass">
              {checkingStatus ? "Checking..." : "Ready to continue"}
            </span>
          )}
          {drawerState === "destroyed" && (
            <span className="ep-fail">Permanently deleted</span>
          )}
          {drawerState === "expired" && <span className="ep-fail">Expired</span>}
        </div>
        <span className="text-[11px] text-ink-3">
          Locked on your device before saving
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
          <span className="ep-label">Saved chats on this browser:</span>
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

      {(drawerState === "frozen" || drawerState === "resumable") &&
        activeReceipt && (
          <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="font-medium text-ink">
                  {drawerState === "frozen"
                    ? "Chat paused and locked. Save your code to open it on another device."
                    : "A paused chat is saved on this browser and ready to reopen."}
                </span>
                {activeReceipt.storageMode === "simulated-memory" && (
                  <span className="ml-2 ep-muted-chip">Practice memory</span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void handleQuickResumeActive()}
                  disabled={resuming || !activeReceipt.freezeSecretHex}
                  className="ep-btn px-2.5 py-1 text-[11px]"
                >
                  {resuming
                    ? "Opening..."
                    : "Pick up where you left off"}
                </button>
                <button
                  type="button"
                  onClick={() => void handleCopyResumeCode()}
                  className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                >
                  {copiedCode ? "Copied code" : "Copy recovery code"}
                </button>
                <button
                  type="button"
                  onClick={() => void handleDestroy(activeReceipt.blobId)}
                  disabled={destroying}
                  className="ep-btn-ghost px-2 py-0.5 text-[11px]"
                  title="Delete saved chat and wipe your local key"
                >
                  {destroying ? "Deleting..." : "Delete forever"}
                </button>
              </div>
            </div>

            <TechDetails label="Show technical details">
              <dl className="mt-2 space-y-1 font-mono text-[11px]">
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Saved ID</dt>
                  <dd className="break-all text-ink">{activeReceipt.blobId}</dd>
                </div>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Session ID</dt>
                  <dd className="break-all text-ink-2">
                    {activeReceipt.sessionIdHex}
                  </dd>
                </div>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Recovery code</dt>
                  <dd className="break-all text-ink">{currentResumeCode}</dd>
                </div>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Auto-delete window</dt>
                  <dd className="font-sans text-ink-2">
                    {formatUtcHour(activeReceipt.expiresAt)}
                  </dd>
                </div>
              </dl>
            </TechDetails>
          </div>
        )}

      {drawerState === "destroyed" && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              Paused chat permanently deleted. Both the server copy and your
              local key have been wiped.
            </span>
            <span className="ep-fail">Deleted</span>
          </div>
          {destroyedInfo && (
            <TechDetails label="Show deletion details">
              <dl className="mt-2 space-y-1 font-mono text-[11px]">
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Saved ID</dt>
                  <dd className="break-all text-ink-2">{destroyedInfo.blobId}</dd>
                </div>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Browser key</dt>
                  <dd className="font-sans text-ink">
                    {destroyedInfo.localSecretWiped
                      ? "Wiped from browser storage"
                      : "Not stored on this browser"}
                  </dd>
                </div>
                <div className="grid grid-cols-1 gap-1 sm:grid-cols-[8.5rem_1fr] sm:gap-2">
                  <dt className="font-sans text-ink-3">Server check</dt>
                  <dd className="font-sans text-ink">
                    {destroyedInfo.verifiedAbsent
                      ? "Confirmed removed (404)"
                      : "Delete requested"}
                  </dd>
                </div>
              </dl>
            </TechDetails>
          )}
        </div>
      )}

      {drawerState === "expired" && (
        <div className="ep-inset mt-2.5 p-3 text-xs text-ink">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-ink">
              This paused chat has expired and was automatically removed.
            </span>
            {activeReceipt && (
              <button
                type="button"
                onClick={() => void handleDestroy(activeReceipt.blobId)}
                className="ep-btn-ghost px-2 py-0.5 text-[11px]"
              >
                Clear saved entry
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
            Recovery code (paste from another device or earlier chat)
            <input
              type="text"
              value={resumeCodeInput}
              onChange={(e) => handleResumeCodeChange(e.target.value)}
              placeholder="drouter-freeze-v1:<id>:<secret>"
              className="ep-input py-1 font-mono text-xs"
            />
          </label>
          <div className="flex items-center justify-between gap-2">
            <TechDetails label="Enter ID and secret key separately">
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="flex flex-col gap-1 text-[11px] text-ink-2">
                  Saved ID
                  <input
                    type="text"
                    value={blobIdInput}
                    onChange={(e) => setBlobIdInput(e.target.value)}
                    placeholder="32-character hex ID"
                    className="ep-input py-1 font-mono text-xs"
                  />
                </label>
                <label className="flex flex-col gap-1 text-[11px] text-ink-2">
                  Secret key
                  <input
                    type="text"
                    value={secretInput}
                    onChange={(e) => setSecretInput(e.target.value)}
                    placeholder="64-character hex secret"
                    className="ep-input py-1 font-mono text-xs"
                  />
                </label>
              </div>
            </TechDetails>
            <button
              type="submit"
              disabled={
                (!resumeCodeInput.trim() &&
                  (!blobIdInput.trim() || !secretInput.trim())) ||
                resuming
              }
              className="ep-btn shrink-0 py-1.5 text-xs"
            >
              {resuming ? "Opening..." : "Pick up where you left off"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

export default FreezeDrawer;
