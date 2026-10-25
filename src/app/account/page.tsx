"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { AuthGate } from "@/components/auth/auth-gate";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  VAULT_STORAGE_KEY,
  exportEncryptedVaultJson,
  getCurrentVaultSession,
  importEncryptedVaultJson,
  importEncryptedVaultWithActiveSession,
  lockVault,
  setVaultPersistenceMode,
  subscribeVaultSession,
  updateVaultPayload,
  wipeLocalVault,
  type VaultSession,
} from "@/lib/auth/vault";
import {
  CREDITS_STORAGE_KEY,
  PENDING_ACCESS_KEY_STORAGE_KEY,
  claimPaidCredits,
  clearPendingAccessKey,
  getStoredCredits,
  mintCredits,
  moveCreditsToAccessKey,
  readPendingAccessKey,
  requestCreditInvoice,
  storedCreditBalance,
  type CreditInvoiceClientHandle,
} from "@/lib/credits/client";
import {
  CHAT_GATEWAY_MODEL_IDS,
  buildCodingToolSnippets,
  filterChatCapableModelIds,
  type CodingToolId,
  type CodingToolMode,
} from "@/lib/gateway/harness-config";
import { preparePrompt } from "@/lib/pipeline";

function shortHex(hex: string, lead = 12, tail = 8): string {
  if (!hex || hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

const CODING_TOOL_TABS: ReadonlyArray<{ id: CodingToolId; label: string }> = [
  { id: "opencode", label: "OpenCode" },
  { id: "cursor", label: "Cursor" },
  { id: "continue", label: "Continue" },
  { id: "aider", label: "Aider" },
  { id: "typescript", label: "TypeScript SDK" },
  { id: "python", label: "Python SDK" },
  { id: "curl", label: "curl" },
];

const KEY_SIZE_OPTIONS = [5, 10, 20] as const;

export default function AccountPage() {
  const [session, setSession] = useState<VaultSession | null>(null);
  const [persistEncrypted, setPersistEncrypted] = useState<boolean>(true);
  const [newCustomTerm, setNewCustomTerm] = useState<string>("");
  const [vaultNotes, setVaultNotes] = useState<string>("");
  const [samplePrompt, setSamplePrompt] = useState<string>(
    "Sample message: review Fictional-Project-X and test@example.invalid before Friday.",
  );
  const [exportedJson, setExportedJson] = useState<string>("");
  const [importJsonText, setImportJsonText] = useState<string>("");
  const [importPassphrase, setImportPassphrase] = useState<string>("");
  const [statusBanner, setStatusBanner] = useState<{
    kind: "ok" | "err" | "info";
    text: string;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Coding tool access key & snippet state (all storage/network reads in effects or click handlers)
  const [walletBalance, setWalletBalance] = useState<number>(0);
  const [walletTokenCount, setWalletTokenCount] = useState<number>(0);
  const [selectedCreditsCount, setSelectedCreditsCount] = useState<5 | 10 | 20>(5);
  const [createdKeyInfo, setCreatedKeyInfo] = useState<{
    key: string;
    creditsMoved: number;
    tokenCount: number;
    uncopied: boolean;
  } | null>(null);
  const [mintingFree, setMintingFree] = useState<boolean>(false);
  const [showBuyPanel, setShowBuyPanel] = useState<boolean>(false);
  const [buyDenom, setBuyDenom] = useState<5 | 20>(5);
  const [activeInvoice, setActiveInvoice] = useState<CreditInvoiceClientHandle | null>(null);
  const [invoiceBusy, setInvoiceBusy] = useState<boolean>(false);
  const [codingMode, setCodingMode] = useState<CodingToolMode>("private");
  const [activeToolTab, setActiveToolTab] = useState<CodingToolId>("opencode");
  const [liveModelIds, setLiveModelIds] = useState<readonly string[]>(
    CHAT_GATEWAY_MODEL_IDS,
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    const syncWallet = () => {
      setWalletBalance(storedCreditBalance());
      setWalletTokenCount(getStoredCredits().length);
      const pending = readPendingAccessKey();
      if (pending) {
        setCreatedKeyInfo({
          key: pending.key,
          creditsMoved: pending.creditsMoved,
          tokenCount: pending.tokenCount,
          uncopied: true,
        });
      }
    };
    const sync = () => {
      const current = getCurrentVaultSession();
      setSession(current);
      if (current) {
        setPersistEncrypted(current.persistEncrypted);
        setVaultNotes(current.payload.notes ?? "");
      }
      syncWallet();
    };
    const handleStorage = (event: StorageEvent) => {
      if (
        !event.key ||
        event.key === CREDITS_STORAGE_KEY ||
        event.key === PENDING_ACCESS_KEY_STORAGE_KEY ||
        event.key === VAULT_STORAGE_KEY
      ) {
        syncWallet();
      }
    };
    sync();
    window.addEventListener("storage", handleStorage);
    const unsubVault = subscribeVaultSession(sync);
    return () => {
      window.removeEventListener("storage", handleStorage);
      unsubVault();
    };
  }, []);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (typeof fetch !== "function") return;
    let cancelled = false;
    fetch("/api/v1/models")
      .then(async (res) =>
        res.ok
          ? ((await res.json()) as { data?: Array<{ id?: string }> })
          : null,
      )
      .then((payload) => {
        if (cancelled) return;
        const rawIds = (payload?.data ?? [])
          .map((m) => (typeof m?.id === "string" ? m.id.trim() : ""))
          .filter((id) => id.length > 0);
        const chatIds = filterChatCapableModelIds(rawIds);
        if (chatIds.length > 0) {
          setLiveModelIds(chatIds);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshWalletState = () => {
    setWalletBalance(storedCreditBalance());
    setWalletTokenCount(getStoredCredits().length);
  };

  const triggerCopyFeedback = (id: string, text: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopiedId(id);
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopiedId(null);
      copyTimerRef.current = null;
    }, 1800);
  };

  const handleMintFreeCredits = async () => {
    if (mintingFree) return;
    setMintingFree(true);
    try {
      await mintCredits("", 5, 1);
      refreshWalletState();
      setStatusBanner({
        kind: "ok",
        text: "Added 5 free anonymous tokens to your browser wallet.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not add free credits right now. You can also buy credits below.",
      });
    } finally {
      setMintingFree(false);
    }
  };

  const handleRequestInvoice = async (denom: 5 | 20) => {
    if (invoiceBusy) return;
    setInvoiceBusy(true);
    try {
      const inv = await requestCreditInvoice("", denom);
      setActiveInvoice(inv);
      setStatusBanner({
        kind: "info",
        text: `Created one-time deposit address for ${inv.denomination} credits (${inv.amountUsdc} USDC).`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not create a deposit address right now.",
      });
    } finally {
      setInvoiceBusy(false);
    }
  };

  const handleClaimInvoice = async () => {
    if (!activeInvoice || invoiceBusy) return;
    setInvoiceBusy(true);
    try {
      const minted = await claimPaidCredits("", {
        invoiceId: activeInvoice.invoiceId,
        claimSecret: activeInvoice.claimSecret,
        count: activeInvoice.denomination,
        denomination: 1,
      });
      setActiveInvoice(null);
      setShowBuyPanel(false);
      refreshWalletState();
      setStatusBanner({
        kind: "ok",
        text: `Added ${minted.length} paid anonymous tokens to your browser wallet.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Payment not confirmed yet. Wait a moment and try again.",
      });
    } finally {
      setInvoiceBusy(false);
    }
  };

  const handleCreateAccessKey = () => {
    try {
      const moved = moveCreditsToAccessKey(selectedCreditsCount);
      setCreatedKeyInfo({
        key: moved.key,
        creditsMoved: moved.creditsMoved,
        tokenCount: moved.tokens.length,
        uncopied: true,
      });
      refreshWalletState();
      setStatusBanner({
        kind: "ok",
        text: `Created access key with ${moved.creditsMoved} credits and moved those tokens out of your browser wallet.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Not enough anonymous tokens in your wallet to create this key.",
      });
    }
  };

  const handleConfirmCopiedAccessKey = () => {
    clearPendingAccessKey();
    setCreatedKeyInfo((prev) => (prev ? { ...prev, uncopied: false } : null));
  };

  const codingSnippets = useMemo(
    () =>
      buildCodingToolSnippets({
        mode: codingMode,
        accessKey: createdKeyInfo?.key ?? null,
        modelIds: liveModelIds,
      }),
    [codingMode, createdKeyInfo?.key, liveModelIds],
  );

  const activeCustomTerms = session?.payload.customScrubTerms ?? [];

  const scrubPreview = useMemo(
    () =>
      preparePrompt(samplePrompt, {
        customTerms: activeCustomTerms,
      }),
    [samplePrompt, activeCustomTerms],
  );

  const signInMethodLabel =
    session?.authMethod === "passkey"
      ? "Fingerprint, face or device"
      : "6 secret words";

  const handleSignOut = () => {
    lockVault();
    setExportedJson("");
    setStatusBanner({
      kind: "info",
      text: "Signed out and cleared your active keys from browser memory.",
    });
  };

  const handleTogglePersistence = (nextPersist: boolean) => {
    setPersistEncrypted(nextPersist);
    if (session) {
      setVaultPersistenceMode(nextPersist);
      setStatusBanner({
        kind: "info",
        text: nextPersist
          ? "Locked settings are now saved on this device."
          : "Switched to temporary mode and removed saved settings from this device.",
      });
    }
  };

  const handleAddCustomTerm = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newCustomTerm.trim();
    if (!trimmed || !session) return;

    updateVaultPayload((prev) => ({
      ...prev,
      customScrubTerms: [...prev.customScrubTerms, trimmed],
    }));
    setNewCustomTerm("");
    setStatusBanner({
      kind: "ok",
      text: `Added "${trimmed}" to your words to always hide. We will replace it with a safe placeholder before your message leaves this device.`,
    });
  };

  const handleRemoveCustomTerm = (termToRemove: string) => {
    if (!session) return;
    updateVaultPayload((prev) => ({
      ...prev,
      customScrubTerms: prev.customScrubTerms.filter((t) => t !== termToRemove),
    }));
    setStatusBanner({
      kind: "info",
      text: `Removed "${termToRemove}" from your words to always hide.`,
    });
  };

  const handleSaveNotes = () => {
    if (!session) return;
    updateVaultPayload((prev) => ({
      ...prev,
      notes: vaultNotes,
    }));
    setStatusBanner({
      kind: "ok",
      text: "Saved your private notes in your account.",
    });
  };

  const handleExportVault = () => {
    try {
      const json = exportEncryptedVaultJson();
      setExportedJson(json);
      setStatusBanner({
        kind: "ok",
        text: "Prepared your locked backup file in browser memory.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Sign in first before exporting a backup.",
      });
    }
  };

  const handleDownloadExport = () => {
    if (!session && !exportedJson) return;
    try {
      const content = exportedJson || exportEncryptedVaultJson();
      if (!exportedJson) setExportedJson(content);
      const blob = new Blob([content], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${session?.vaultId ?? "deroute-account"}.drouter-vault.json`;
      a.click();
      URL.revokeObjectURL(url);
      setStatusBanner({
        kind: "ok",
        text: "Downloaded your locked backup file.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Sign in first before downloading a backup.",
      });
    }
  };

  const handleUploadVaultFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setImportJsonText(reader.result);
        setStatusBanner({
          kind: "info",
          text: `Loaded ${file.name} (${file.size} bytes). Click Restore backup below.`,
        });
      }
    };
    reader.onerror = () => {
      setStatusBanner({
        kind: "err",
        text: "Could not read the selected backup file.",
      });
    };
    reader.readAsText(file);
  };

  const handleImportVault = (e: React.FormEvent) => {
    e.preventDefault();
    if (!importJsonText.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Choose or paste a backup file first.",
      });
      return;
    }

    try {
      if (importPassphrase.trim()) {
        const restored = importEncryptedVaultJson(
          importJsonText,
          importPassphrase,
          persistEncrypted,
        );
        setImportPassphrase("");
        setStatusBanner({
          kind: "ok",
          text: `Restored backup for account ${restored.vaultId} (${restored.payload.customScrubTerms.length} hidden words restored).`,
        });
      } else {
        const restored = importEncryptedVaultWithActiveSession(
          importJsonText,
          persistEncrypted,
        );
        setStatusBanner({
          kind: "ok",
          text: `Restored backup for account ${restored.vaultId} (${restored.payload.customScrubTerms.length} hidden words restored).`,
        });
      }
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not restore backup. Check that the file matches your account or enter its 6 secret words.",
      });
    }
  };

  const handleWipeDeviceData = () => {
    wipeLocalVault();
    setExportedJson("");
    setVaultNotes("");
    setStatusBanner({
      kind: "ok",
      text: "Signed out and removed saved account data from this browser.",
    });
  };

  const walletIsShort = walletBalance < selectedCreditsCount;

  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden bg-paper text-ink">
      <SpecimenHeader activePath="/account" />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto w-full max-w-4xl flex-1 space-y-8 px-4 py-10 sm:px-6"
      >
        <AuthGate>
          <div className="space-y-8">
            {/* Hero */}
            <InkReveal>
              <section
                aria-labelledby="account-heading"
                className="space-y-3 border-b border-rule pb-6"
              >
                <div className="ep-label">Account settings</div>
                <h1 id="account-heading" className="ep-display text-3xl sm:text-4xl">
                  Your deRoute account
                </h1>
                <p className="max-w-[65ch] text-base leading-relaxed text-ink-2">
                  Choose words you always want hidden before anything leaves your device, get setup for your coding tool, save a backup file, or sign out.
                </p>

                {statusBanner && (
                  <div
                    role="status"
                    aria-live="polite"
                    className={`mt-3 rounded border px-3.5 py-2.5 text-xs font-mono ${
                      statusBanner.kind === "err"
                        ? "border-accent bg-accent-soft text-accent"
                        : "border-rule bg-paper-2 text-ink"
                    }`}
                  >
                    {statusBanner.text}
                  </div>
                )}
              </section>
            </InkReveal>

            {/* Sign-in Method & Sign Out */}
            {session && (
                <section
                  aria-labelledby="signin-method-heading"
                  className="ep-card space-y-4 p-5 sm:p-6"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="ep-label">Sign-in method in use</div>
                      <h2
                        id="signin-method-heading"
                        className="ep-display text-2xl"
                      >
                        {signInMethodLabel}
                      </h2>
                      <p className="font-mono text-xs text-ink-2">
                        Account ID: <strong className="text-ink">{session.vaultId}</strong>
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <span className="ep-pass">Signed in on this device</span>
                      <InkButton variant="ghost" onClick={handleSignOut}>
                        Sign out
                      </InkButton>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule pt-3 text-xs text-ink-2">
                    <span>
                      On this device:{" "}
                      <strong className="text-ink">
                        {persistEncrypted
                          ? "Locked copy saved on this device"
                          : "Temporary (clears when you close this tab)"}
                      </strong>
                    </span>
                    <div
                      className="flex items-center gap-2"
                      role="group"
                      aria-label="Device storage mode"
                    >
                      <button
                        type="button"
                        aria-pressed={!persistEncrypted}
                        onClick={() => handleTogglePersistence(false)}
                        className={
                          !persistEncrypted
                            ? "ep-btn text-xs py-1 px-2.5"
                            : "ep-btn-ghost text-xs py-1 px-2.5"
                        }
                      >
                        Temporary only
                      </button>
                      <button
                        type="button"
                        aria-pressed={persistEncrypted}
                        onClick={() => handleTogglePersistence(true)}
                        className={
                          persistEncrypted
                            ? "ep-btn text-xs py-1 px-2.5"
                            : "ep-btn-ghost text-xs py-1 px-2.5"
                        }
                      >
                        Save locked on device
                      </button>
                    </div>
                  </div>
                </section>
            )}

            {/* Words to always hide */}
              <section
                aria-labelledby="custom-scrub-heading"
                className="ep-card space-y-5 p-5 sm:p-6"
              >
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-rule pb-4">
                  <div className="space-y-1">
                    <div className="ep-label">Personal privacy list</div>
                    <h2 id="custom-scrub-heading" className="ep-display text-2xl">
                      Words to always hide
                    </h2>
                    <p className="max-w-[68ch] text-xs leading-relaxed text-ink-2">
                      We hide your personal details before anything leaves your device. Add names, project titles, or client words here and your browser will swap each one with a placeholder like{" "}
                      <code className="font-mono text-ink">[ENTITY_1]</code> before locking your message, then put the real word back when the reply arrives.
                    </p>
                  </div>
                  <span className="ep-pass">
                    {activeCustomTerms.length} hidden word
                    {activeCustomTerms.length === 1 ? "" : "s"}
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                  <div className="space-y-3">
                    <form onSubmit={handleAddCustomTerm} className="flex flex-col sm:flex-row gap-2">
                      <label htmlFor="custom-term-input" className="sr-only">
                        Add a word or phrase to always hide
                      </label>
                      <input
                        id="custom-term-input"
                        type="text"
                        value={newCustomTerm}
                        onChange={(e) => setNewCustomTerm(e.target.value)}
                        placeholder="Name, project, or private word..."
                        className="ep-input"
                      />
                      <InkButton
                        type="submit"
                        variant="primary"
                        disabled={!newCustomTerm.trim()}
                        className="shrink-0"
                      >
                        Add word
                      </InkButton>
                    </form>

                    {activeCustomTerms.length > 0 ? (
                      <div
                        className="flex flex-wrap gap-1.5"
                        aria-label="Words to always hide"
                      >
                        {activeCustomTerms.map((term, i) => (
                          <span key={term} className="ep-muted-chip text-ink">
                            <span>
                              {term} &rarr; [ENTITY_{i + 1}]
                            </span>
                            <button
                              type="button"
                              onClick={() => handleRemoveCustomTerm(term)}
                              className="ml-1 font-bold text-ink hover:text-accent"
                              aria-label={`Remove ${term}`}
                            >
                              &times;
                            </button>
                          </span>
                        ))}
                      </div>
                    ) : (
                      <div className="ep-inset p-3 text-xs text-ink-3">
                        No custom words saved yet. Add a word above (for example,{" "}
                        <code className="font-mono text-ink">Fictional-Project-X</code>) to hide it in every chat.
                      </div>
                    )}

                    <div className="space-y-1.5 border-t border-rule pt-3">
                      <label
                        htmlFor="vault-notes-input"
                        className="block font-mono text-xs text-ink-2"
                      >
                        Private notes (kept locked in your account)
                      </label>
                      <div className="flex gap-2">
                        <input
                          id="vault-notes-input"
                          type="text"
                          value={vaultNotes}
                          onChange={(e) => setVaultNotes(e.target.value)}
                          placeholder="Optional private notes..."
                          className="ep-input"
                        />
                        <button
                          type="button"
                          onClick={handleSaveNotes}
                          className="ep-btn-ghost shrink-0 text-xs"
                        >
                          Save notes
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="ep-inset space-y-2.5 p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="ep-label">
                        Live preview ({scrubPreview.report.redactions.length} hidden item
                        {scrubPreview.report.redactions.length === 1 ? "" : "s"})
                      </div>
                      <span className="ep-muted-chip">Stays on your device</span>
                    </div>
                    <label htmlFor="sample-prompt-textarea" className="sr-only">
                      Sample message to preview hidden words
                    </label>
                    <textarea
                      id="sample-prompt-textarea"
                      rows={2}
                      value={samplePrompt}
                      onChange={(e) => setSamplePrompt(e.target.value)}
                      className="ep-input font-mono text-xs"
                    />
                    <div className="break-words font-mono text-xs text-ink">
                      <span className="text-ink-3">What leaves your device: </span>
                      {scrubPreview.outboundText}
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-rule pt-2 font-mono text-[11px] text-ink-3">
                      <span>
                        Every message looks the same size from outside (
                        {scrubPreview.bucketBytes.toLocaleString()} B)
                      </span>
                    </div>
                  </div>
                </div>
              </section>

            {/* K4: Use deRoute from your coding tool */}
            <section
              aria-labelledby="coding-tool-heading"
              data-testid="coding-tool-section"
              className="ep-card space-y-6 p-5 sm:p-6"
            >
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-rule pb-4">
                <div className="space-y-1">
                  <div className="ep-label">Developer access</div>
                  <h2 id="coding-tool-heading" className="ep-display text-2xl">
                    Use deRoute from your coding tool
                  </h2>
                  <p className="max-w-[68ch] text-xs leading-relaxed text-ink-2">
                    Connect OpenCode, Cursor, Continue, Aider, or your own scripts to deRoute in three quick steps. Your browser packs anonymous tokens from your wallet into a key that our server never stores.
                  </p>
                </div>
                <span className="ep-pass" data-testid="wallet-balance-badge">
                  {walletBalance} credit{walletBalance === 1 ? "" : "s"} in wallet
                </span>
              </div>

              {/* Step 1: Create an access key */}
              <div className="space-y-3 border-b border-rule pb-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="ep-label">Step 1</div>
                    <h3 className="font-serif text-lg text-ink">
                      Create an access key
                    </h3>
                  </div>
                  <span className="font-mono text-xs text-ink-2">
                    {walletTokenCount} anonymous token{walletTokenCount === 1 ? "" : "s"} ready
                  </span>
                </div>

                <p className="text-xs text-ink-2">
                  Choose how many credits to move out of your browser wallet into a portable key. Moving tokens out of your wallet means this browser cannot spend the same token twice.
                </p>

                <div className="flex flex-wrap items-center gap-2">
                  <div
                    className="flex flex-wrap items-center gap-1.5"
                    role="group"
                    aria-label="Credits to include in access key"
                  >
                    {KEY_SIZE_OPTIONS.map((count) => (
                      <button
                        key={count}
                        type="button"
                        aria-pressed={selectedCreditsCount === count}
                        onClick={() => setSelectedCreditsCount(count)}
                        data-testid={`select-credits-${count}`}
                        className={
                          selectedCreditsCount === count
                            ? "ep-btn text-xs py-1.5 px-3"
                            : "ep-btn-ghost text-xs py-1.5 px-3"
                        }
                      >
                        {count} credits
                      </button>
                    ))}
                  </div>

                  <InkButton
                    type="button"
                    variant="primary"
                    disabled={walletIsShort}
                    onClick={handleCreateAccessKey}
                    data-testid="create-access-key-button"
                    className="text-xs"
                  >
                    Create access key ({selectedCreditsCount} credits)
                  </InkButton>
                </div>

                {walletIsShort && (
                  <div
                    data-testid="wallet-short-callout"
                    className="ep-inset flex flex-wrap items-center justify-between gap-3 p-3.5 text-xs"
                  >
                    <div className="space-y-0.5 text-ink-2">
                      <strong className="text-ink">
                        Your wallet has {walletBalance} credit{walletBalance === 1 ? "" : "s"}, and you selected {selectedCreditsCount}.
                      </strong>{" "}
                      Add 5 free credits from the daily allowance or buy more anonymous tokens.
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={handleMintFreeCredits}
                        disabled={mintingFree}
                        data-testid="add-5-free-button"
                        className="ep-btn text-xs py-1.5 px-3"
                      >
                        {mintingFree ? "Adding 5 free..." : "Add 5 free"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setShowBuyPanel((prev) => !prev)}
                        data-testid="toggle-buy-credits-button"
                        className="ep-btn-ghost text-xs py-1.5 px-3"
                      >
                        {showBuyPanel ? "Hide buy options" : "Buy credits"}
                      </button>
                    </div>
                  </div>
                )}

                {!walletIsShort && (
                  <div className="flex flex-wrap items-center gap-2 text-xs text-ink-3">
                    <span>Need more tokens in your wallet first?</span>
                    <button
                      type="button"
                      onClick={handleMintFreeCredits}
                      disabled={mintingFree}
                      data-testid="add-5-free-inline-button"
                      className="ep-btn-ghost text-xs py-1 px-2.5"
                    >
                      {mintingFree ? "Adding 5 free..." : "Add 5 free"}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowBuyPanel((prev) => !prev)}
                      className="ep-btn-ghost text-xs py-1 px-2.5"
                    >
                      {showBuyPanel ? "Hide buy options" : "Buy credits"}
                    </button>
                  </div>
                )}

                {showBuyPanel && (
                  <div className="ep-inset space-y-3 p-3.5 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <strong className="text-ink">
                        Buy prepaid anonymous tokens (one-time deposit address)
                      </strong>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => setBuyDenom(5)}
                          className={
                            buyDenom === 5
                              ? "ep-btn text-xs py-1 px-2.5"
                              : "ep-btn-ghost text-xs py-1 px-2.5"
                          }
                        >
                          5 credits (0.0005 USDC)
                        </button>
                        <button
                          type="button"
                          onClick={() => setBuyDenom(20)}
                          className={
                            buyDenom === 20
                              ? "ep-btn text-xs py-1 px-2.5"
                              : "ep-btn-ghost text-xs py-1 px-2.5"
                          }
                        >
                          20 credits (0.002 USDC)
                        </button>
                        <button
                          type="button"
                          disabled={invoiceBusy}
                          onClick={() => handleRequestInvoice(buyDenom)}
                          className="ep-btn text-xs py-1 px-2.5"
                        >
                          {invoiceBusy ? "Preparing..." : "Get deposit address"}
                        </button>
                      </div>
                    </div>

                    {activeInvoice && (
                      <div className="space-y-2 border-t border-rule pt-2 font-mono text-[11px] text-ink-2">
                        <div>
                          Send <strong className="text-ink">{activeInvoice.amountUsdc} USDC</strong> to{" "}
                          <code className="break-all text-ink">{activeInvoice.depositAddress}</code>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <button
                            type="button"
                            disabled={invoiceBusy}
                            onClick={handleClaimInvoice}
                            className="ep-btn text-xs py-1 px-2.5"
                          >
                            {invoiceBusy ? "Checking payment..." : "Claim paid credits"}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {createdKeyInfo && (
                  <div
                    data-testid="created-access-key-box"
                    className="ep-inset space-y-2.5 border-ink p-4"
                  >
                    {createdKeyInfo.uncopied && (
                      <div
                        data-testid="uncopied-access-key-banner"
                        className="rounded border border-accent bg-accent-soft px-3 py-2 text-xs text-ink flex flex-wrap items-center justify-between gap-2"
                      >
                        <span>
                          <strong>You have an uncopied access key.</strong> Copy and save it before closing this tab.
                        </span>
                        <button
                          type="button"
                          onClick={handleConfirmCopiedAccessKey}
                          data-testid="confirm-copied-access-key-button"
                          className="ep-btn-ghost text-xs py-1 px-2.5"
                        >
                          I have saved this key
                        </button>
                      </div>
                    )}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-xs font-medium text-ink">
                        Your new access key ({createdKeyInfo.creditsMoved} credits, shown once)
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          triggerCopyFeedback("access-key", createdKeyInfo.key);
                          handleConfirmCopiedAccessKey();
                        }}
                        data-testid="copy-access-key-button"
                        className="ep-btn text-xs py-1 px-3"
                      >
                        {copiedId === "access-key" ? "Copied key" : "Copy access key"}
                      </button>
                    </div>
                    <pre
                      data-testid="access-key-value"
                      className="overflow-x-auto rounded border border-rule bg-paper p-2.5 font-mono text-xs text-ink select-all"
                    >
                      {createdKeyInfo.key}
                    </pre>
                    <p className="text-xs text-accent font-medium">
                      Save this key now. It is shown once and is never stored on our server. Whoever holds this key can spend its credits.
                    </p>
                  </div>
                )}
              </div>

              {/* Step 2: Choose private (recommended) or hosted */}
              <div className="space-y-3 border-b border-rule pb-5">
                <div>
                  <div className="ep-label">Step 2</div>
                  <h3 className="font-serif text-lg text-ink">
                    Choose how your tool connects
                  </h3>
                </div>

                <div
                  className="grid grid-cols-1 gap-3 sm:grid-cols-2"
                  role="group"
                  aria-label="Connection privacy mode"
                >
                  <button
                    type="button"
                    aria-pressed={codingMode === "private"}
                    onClick={() => setCodingMode("private")}
                    data-testid="mode-private-button"
                    className={`text-left rounded border p-4 transition-colors ${
                      codingMode === "private"
                        ? "border-ink bg-paper-2"
                        : "border-rule bg-paper hover:bg-paper-2"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-serif text-base font-medium text-ink">
                        Private mode (recommended)
                      </span>
                      <span className="ep-pass">Local proxy</span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-ink-2">
                      Runs on your computer at{" "}
                      <code className="font-mono text-ink">http://127.0.0.1:4141/v1</code>.
                      Your computer hides personal details, checks the seal on the sealed computer, and locks every message before it leaves your machine.
                    </p>
                  </button>

                  <button
                    type="button"
                    aria-pressed={codingMode === "hosted"}
                    onClick={() => setCodingMode("hosted")}
                    data-testid="mode-hosted-button"
                    className={`text-left rounded border p-4 transition-colors ${
                      codingMode === "hosted"
                        ? "border-ink bg-paper-2"
                        : "border-rule bg-paper hover:bg-paper-2"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-serif text-base font-medium text-ink">
                        Hosted mode (convenient)
                      </span>
                      <span className="ep-muted-chip">Direct URL</span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-ink-2">
                      Connects straight to our server with no local download. In hosted mode our server filters your words before forwarding them to the sealed computer, so our server sees them. Use the local proxy if you do not want that.
                    </p>
                  </button>
                </div>

                {codingMode === "private" ? (
                  <div className="ep-inset space-y-2 p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-xs text-ink">
                        Start the single-file local proxy on your computer (Node 20 or later):
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          triggerCopyFeedback(
                            "proxy-cmd",
                            codingSnippets.proxyStartCommand,
                          )
                        }
                        className="ep-btn-ghost text-xs py-1 px-2.5"
                      >
                        {copiedId === "proxy-cmd" ? "Copied" : "Copy command"}
                      </button>
                    </div>
                    <pre className="overflow-x-auto rounded border border-rule bg-paper p-3 font-mono text-xs leading-relaxed text-ink">
                      <code>{codingSnippets.proxyStartCommand}</code>
                    </pre>
                  </div>
                ) : (
                  <div
                    data-testid="hosted-privacy-notice"
                    className="ep-inset border-accent bg-accent-soft p-3.5 text-xs text-ink"
                  >
                    <strong>Privacy note:</strong> In hosted mode our server filters your words before forwarding them to the sealed computer, so our server sees them. Use the local proxy if you do not want that.
                  </div>
                )}
              </div>

              {/* Step 3: Copy setup for the chosen tool */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="ep-label">Step 3</div>
                    <h3 className="font-serif text-lg text-ink">
                      Copy setup for your tool
                    </h3>
                  </div>
                  <span className="font-mono text-[11px] text-ink-3">
                    Live models: {liveModelIds.join(" · ")}
                  </span>
                </div>

                <div
                  role="tablist"
                  aria-label="Coding tools"
                  className="flex flex-wrap gap-1.5"
                >
                  {CODING_TOOL_TABS.map((tab) => {
                    const selected = activeToolTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        aria-selected={selected}
                        onClick={() => setActiveToolTab(tab.id)}
                        data-testid={`tool-tab-${tab.id}`}
                        className={
                          selected
                            ? "ep-btn text-xs py-1.5 px-3"
                            : "ep-btn-ghost text-xs py-1.5 px-3"
                        }
                      >
                        {tab.label}
                      </button>
                    );
                  })}
                </div>

                <div className="ep-inset overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule bg-paper px-3.5 py-2">
                    <span className="font-mono text-xs text-ink-2">
                      Endpoint: <strong className="text-ink">{codingSnippets.baseUrl}</strong>
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        triggerCopyFeedback(
                          `snippet-${activeToolTab}`,
                          codingSnippets.byTool[activeToolTab],
                        )
                      }
                      data-testid="copy-tool-snippet-button"
                      className="ep-btn-ghost text-xs py-1 px-2.5"
                    >
                      {copiedId === `snippet-${activeToolTab}`
                        ? "Copied snippet"
                        : "Copy snippet"}
                    </button>
                  </div>
                  <pre
                    data-testid="coding-tool-snippet-code"
                    className="overflow-x-auto p-3.5 font-mono text-xs leading-relaxed text-ink"
                  >
                    <code>{codingSnippets.byTool[activeToolTab]}</code>
                  </pre>
                </div>

                <TechDetails label="Show technical details for coding tool keys and proxy">
                  <div className="space-y-2 text-xs text-ink-2">
                    <p>
                      <strong className="text-ink">Key format (K1):</strong>{" "}
                      An access key is <code className="font-mono text-ink">drk_</code> followed by unpadded base64url of{" "}
                      <code className="font-mono text-ink">
                        canonicalJson(&#123; v: 1, origin: &quot;https://drouter-demo.vercel.app&quot;, tokens: [&#123; t, s, d &#125;, ...] &#125;)
                      </code>{" "}
                      containing 1 to 50 blind-signed RSA credit tokens.
                    </p>
                    <p>
                      <strong className="text-ink">Local proxy (K2):</strong>{" "}
                      <code className="font-mono text-ink">deroute-proxy.mjs</code> runs the mechanical PII filter with session-stable placeholders, verifies all seven attestation checks (AMD SEV-SNP / Intel TDX quote, VCEK certificate chain, Sigstore Rekor transparency log, and runtime measurement), seals each request with RFC 9180 HPKE through{" "}
                      <code className="font-mono text-ink">/api/relay/v1/</code>, attaches one{" "}
                      <code className="font-mono text-ink">x-drouter-credit</code> header per request, and records spent nullifiers in{" "}
                      <code className="font-mono text-ink">~/.config/deroute/spent.json</code>.
                    </p>
                    <p>
                      <strong className="text-ink">Hosted gateway (K3):</strong>{" "}
                      <code className="font-mono text-ink">POST /api/v1/chat/completions</code> accepts{" "}
                      <code className="font-mono text-ink">Authorization: Bearer drk_...</code>, spends the first token whose nullifier is unspent, and returns{" "}
                      <code className="font-mono text-ink">X-DRouter-Credits-Remaining</code>.
                    </p>
                  </div>
                </TechDetails>
              </div>
            </section>

            {/* Export & Import Backup */}
              <section
                aria-labelledby="backup-restore-heading"
                className="ep-card space-y-6 p-5 sm:p-6"
              >
                <div className="border-b border-rule pb-4">
                  <div className="ep-label">Backup and restore</div>
                  <h2
                    id="backup-restore-heading"
                    className="ep-display mt-0.5 text-2xl"
                  >
                    Export or import your backup
                  </h2>
                  <p className="mt-1 max-w-[68ch] text-xs text-ink-2">
                    Download a locked backup file of your hidden words and notes. Only your account can unlock it.
                  </p>
                </div>

                <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                  {/* Export */}
                  <div className="space-y-3">
                    <div className="ep-label">Export</div>
                    <h3 className="font-serif text-lg text-ink">
                      Save a backup file
                    </h3>
                    <p className="text-xs text-ink-2">
                      Download your hidden words and notes as a locked backup file to keep on your computer or move to another device.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <InkButton
                        variant="primary"
                        onClick={handleDownloadExport}
                        className="text-xs"
                      >
                        Download backup file
                      </InkButton>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-rule pt-3">
                      <span className="text-xs text-ink-2">
                        Sign out and clear saved data from this browser:
                      </span>
                      <button
                        type="button"
                        onClick={handleWipeDeviceData}
                        className="ep-btn-ghost text-xs"
                      >
                        Clear saved data
                      </button>
                    </div>
                  </div>

                  {/* Import */}
                  <form onSubmit={handleImportVault} className="space-y-3">
                    <div className="ep-label">Import</div>
                    <h3 className="font-serif text-lg text-ink">
                      Restore a backup file
                    </h3>
                    <p className="text-xs text-ink-2">
                      Choose a backup file you saved earlier. If it belongs to your signed-in account, click Restore backup right away. If it came from a 6-word account, enter those 6 words below.
                    </p>

                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".json,application/json"
                        onChange={handleUploadVaultFile}
                        className="sr-only"
                        id="import-vault-file-input"
                      />
                      <label
                        htmlFor="import-vault-file-input"
                        className="ep-btn-ghost cursor-pointer text-xs"
                      >
                        Choose backup file
                      </label>
                      {importJsonText.trim() && (
                        <span className="ep-muted-chip text-ink">
                          Backup loaded ({importJsonText.length.toLocaleString()} B)
                        </span>
                      )}
                    </div>

                    <div>
                      <label
                        htmlFor="import-vault-passphrase"
                        className="mb-1 block font-mono text-xs text-ink-2"
                      >
                        6 secret words (only if restoring from a 6-word backup)
                      </label>
                      <input
                        id="import-vault-passphrase"
                        type="text"
                        autoComplete="off"
                        spellCheck={false}
                        value={importPassphrase}
                        onChange={(e) => setImportPassphrase(e.target.value)}
                        placeholder="Leave blank to unlock with your signed-in account"
                        className="ep-input font-mono text-xs"
                      />
                    </div>

                    <InkButton type="submit" variant="primary" className="text-xs">
                      Restore backup
                    </InkButton>
                  </form>
                </div>

                <TechDetails label="Paste or inspect backup text manually">
                  <div className="grid grid-cols-1 gap-4 pt-1 lg:grid-cols-2">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-xs text-ink">
                          Inspect exported backup text
                        </span>
                        <button
                          type="button"
                          onClick={handleExportVault}
                          className="ep-btn-ghost text-xs"
                        >
                          Show backup file text
                        </button>
                      </div>
                      {exportedJson && (
                        <pre className="ep-inset max-h-40 overflow-auto p-3 font-mono text-[11px] text-ink-2">
                          {exportedJson}
                        </pre>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      <label
                        htmlFor="import-vault-json"
                        className="block font-mono text-xs text-ink"
                      >
                        Paste backup file text manually
                      </label>
                      <textarea
                        id="import-vault-json"
                        rows={3}
                        value={importJsonText}
                        onChange={(e) => setImportJsonText(e.target.value)}
                        placeholder='{"format": "drouter-zk-vault-v1", ...}'
                        className="ep-input font-mono text-xs"
                      />
                    </div>
                  </div>
                </TechDetails>

                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-rule pt-4 text-xs text-ink-2">
                  <span>Ready to send a private message?</span>
                  <Link href="/app" className="ep-link font-medium">
                    Go to Chat
                  </Link>
                </div>
              </section>

            {/* Technical Details */}
              <TechDetails label="Show technical details">
                <div className="space-y-2">
                  <p>
                    <strong className="text-ink">Account keys and local storage:</strong>{" "}
                    Your custom hidden words and notes are encrypted in your browser with AES-256-GCM (96-bit random nonce, authenticated additional data{" "}
                    <code className="font-mono text-ink">drouter/v1/zk-vault-bundle</code>) and signed with your derived Ed25519 key before being written to{" "}
                    <code className="font-mono text-ink">localStorage[&quot;{VAULT_STORAGE_KEY}&quot;]</code> or exported as{" "}
                    <code className="font-mono text-ink">.drouter-vault.json</code>.
                  </p>
                  {session && (
                    <p className="font-mono text-[11px] text-ink-2">
                      Ed25519 public key: {shortHex(session.ed25519PublicKeyHex, 14, 10)} · X25519 public key: {shortHex(session.x25519PublicKeyHex, 14, 10)}
                    </p>
                  )}
                </div>
              </TechDetails>
          </div>
        </AuthGate>
      </main>

      <SpecimenFooter />
    </div>
  );
}
