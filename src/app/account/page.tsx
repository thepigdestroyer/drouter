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
import { preparePrompt } from "@/lib/pipeline";

function shortHex(hex: string, lead = 12, tail = 8): string {
  if (!hex || hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

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

  useEffect(() => {
    const sync = () => {
      const current = getCurrentVaultSession();
      setSession(current);
      if (current) {
        setPersistEncrypted(current.persistEncrypted);
        setVaultNotes(current.payload.notes ?? "");
      }
    };
    sync();
    return subscribeVaultSession(sync);
  }, []);

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
                  Choose words you always want hidden before anything leaves your device, save a backup file, or sign out.
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
