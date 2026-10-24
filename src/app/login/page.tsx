"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  VAULT_STORAGE_KEY,
  deriveVaultIdentity,
  exportEncryptedVaultJson,
  generatePassphrase,
  getCurrentVaultSession,
  getPersistedVaultMetadata,
  importEncryptedVaultJson,
  lockVault,
  setVaultPersistenceMode,
  subscribeVaultSession,
  unlockVaultWithPassphrase,
  updateVaultPayload,
  wipeLocalVault,
  type VaultSession,
} from "@/lib/auth/vault";
import { preparePrompt } from "@/lib/pipeline";

function shortHex(hex: string, lead = 12, tail = 8): string {
  if (!hex || hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

export default function LoginPage() {
  const [session, setSession] = useState<VaultSession | null>(null);
  const [burnerPassphrase, setBurnerPassphrase] = useState<string>("");
  const [savedConfirmed, setSavedConfirmed] = useState<boolean>(false);
  const [existingPassphrase, setExistingPassphrase] = useState<string>("");
  const [persistEncrypted, setPersistEncrypted] = useState<boolean>(false);
  const [copiedBurner, setCopiedBurner] = useState<boolean>(false);
  const [newCustomTerm, setNewCustomTerm] = useState<string>("");
  const [vaultNotes, setVaultNotes] = useState<string>("");
  const [samplePrompt, setSamplePrompt] = useState<string>(
    "Synthetic test prompt: review Fictional-Project-X and test@example.invalid with token sk-test-synthetic0000.",
  );
  const [exportedJson, setExportedJson] = useState<string>("");
  const [importJsonText, setImportJsonText] = useState<string>("");
  const [importPassphrase, setImportPassphrase] = useState<string>("");
  const [statusBanner, setStatusBanner] = useState<{
    kind: "ok" | "err" | "info";
    text: string;
  } | null>(null);
  const [persistedMeta, setPersistedMeta] = useState<{
    exists: boolean;
    vaultId?: string;
    exportedAt?: number;
  }>({ exists: false });
  const [mounted, setMounted] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setMounted(true);
    setBurnerPassphrase(generatePassphrase(6));
    const sync = () => {
      const current = getCurrentVaultSession();
      setSession(current);
      if (current) {
        setPersistEncrypted(current.persistEncrypted);
        setVaultNotes(current.payload.notes ?? "");
      }
      setPersistedMeta(getPersistedVaultMetadata());
    };
    sync();
    return subscribeVaultSession(sync);
  }, []);

  const burnerPreview = useMemo(() => {
    if (!mounted || !burnerPassphrase.trim()) return null;
    try {
      return deriveVaultIdentity(burnerPassphrase);
    } catch {
      return null;
    }
  }, [burnerPassphrase, mounted]);

  const existingPreview = useMemo(() => {
    if (!existingPassphrase.trim()) return null;
    try {
      return deriveVaultIdentity(existingPassphrase);
    } catch {
      return null;
    }
  }, [existingPassphrase]);

  const activeCustomTerms = session?.payload.customScrubTerms ?? [];

  const scrubPreview = useMemo(
    () =>
      preparePrompt(samplePrompt, {
        customTerms: activeCustomTerms,
      }),
    [samplePrompt, activeCustomTerms],
  );

  const handleGenerateBurner = () => {
    const next = generatePassphrase(6);
    setBurnerPassphrase(next);
    setCopiedBurner(false);
    setSavedConfirmed(false);
    setStatusBanner({
      kind: "info",
      text: "Generated a fresh 6-word passphrase in your browser. Nothing was sent over the network.",
    });
  };

  const handleCopyBurner = async () => {
    if (!burnerPassphrase) return;
    try {
      await navigator.clipboard.writeText(burnerPassphrase);
      setCopiedBurner(true);
      setTimeout(() => setCopiedBurner(false), 2000);
    } catch {
      setStatusBanner({
        kind: "info",
        text: "Clipboard unavailable. Select and copy the 6 words directly.",
      });
    }
  };

  const handleCreateVault = () => {
    if (!savedConfirmed) {
      setStatusBanner({
        kind: "err",
        text: "Confirm that you saved your 6 words before creating the vault.",
      });
      return;
    }
    if (!burnerPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Generate a 6-word passphrase first.",
      });
      return;
    }
    try {
      const unlocked = unlockVaultWithPassphrase(burnerPassphrase, persistEncrypted);
      setStatusBanner({
        kind: "ok",
        text: `Unlocked passphrase vault ${unlocked.vaultId} locally. 0 bytes sent over the network.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Could not create passphrase vault",
      });
    }
  };

  const handleUnlockExisting = (e: React.FormEvent) => {
    e.preventDefault();
    if (!existingPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Enter your passphrase first.",
      });
      return;
    }
    try {
      const unlocked = unlockVaultWithPassphrase(existingPassphrase, persistEncrypted);
      setStatusBanner({
        kind: "ok",
        text: `Unlocked passphrase vault ${unlocked.vaultId} in your browser. 0 bytes sent over the network.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Failed to derive vault keys",
      });
    }
  };

  const handleLockVault = () => {
    lockVault();
    setExportedJson("");
    setStatusBanner({
      kind: "info",
      text: "Locked vault and zeroed keys in browser memory.",
    });
  };

  const handleTogglePersistence = (nextPersist: boolean) => {
    setPersistEncrypted(nextPersist);
    if (session) {
      setVaultPersistenceMode(nextPersist);
      setStatusBanner({
        kind: "info",
        text: nextPersist
          ? `Saved AES-256-GCM encrypted vault in localStorage under "${VAULT_STORAGE_KEY}".`
          : "Switched to RAM-only mode and removed the encrypted copy from localStorage.",
      });
    }
  };

  const handleAddCustomTerm = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newCustomTerm.trim();
    if (!trimmed) return;

    if (!session) {
      setStatusBanner({
        kind: "err",
        text: "Create or unlock a vault above before adding custom scrub terms.",
      });
      return;
    }

    const updated = updateVaultPayload((prev) => ({
      ...prev,
      customScrubTerms: [...prev.customScrubTerms, trimmed],
    }));
    setNewCustomTerm("");
    setStatusBanner({
      kind: "ok",
      text: `Added "${trimmed}" to vault ${updated.vaultId}. The chat console will replace it with an [ENTITY_N] placeholder before encryption.`,
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
      text: `Removed "${termToRemove}" from active custom scrub terms.`,
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
      text: "Updated encrypted notes in your local vault.",
    });
  };

  const handleExportVault = () => {
    try {
      const json = exportEncryptedVaultJson();
      setExportedJson(json);
      setStatusBanner({
        kind: "ok",
        text: "Prepared Ed25519-signed, AES-256-GCM encrypted .drouter-vault.json in browser memory.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Unlock a vault first before exporting.",
      });
    }
  };

  const handleDownloadExport = () => {
    if (!session && !exportedJson) return;
    try {
      const content = exportedJson || exportEncryptedVaultJson();
      if (!exportedJson) setExportedJson(content);
      triggerJsonDownload(content, session?.vaultId ?? "passphrase-vault");
      setStatusBanner({
        kind: "ok",
        text: "Downloaded encrypted .drouter-vault.json backup.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Unlock a vault first before downloading.",
      });
    }
  };

  function triggerJsonDownload(jsonContent: string, vaultId: string) {
    const blob = new Blob([jsonContent], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${vaultId}.drouter-vault.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const handleUploadVaultFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setImportJsonText(reader.result);
        setStatusBanner({
          kind: "info",
          text: `Loaded ${file.name} (${file.size} bytes). Enter its passphrase and click Verify & import vault.`,
        });
      }
    };
    reader.onerror = () => {
      setStatusBanner({
        kind: "err",
        text: "Could not read the selected vault file.",
      });
    };
    reader.readAsText(file);
  };

  const handleImportVault = (e: React.FormEvent) => {
    e.preventDefault();
    if (!importJsonText.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Paste or upload an encrypted .drouter-vault.json file first.",
      });
      return;
    }
    if (!importPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Enter the passphrase for the imported vault file.",
      });
      return;
    }
    try {
      const restored = importEncryptedVaultJson(
        importJsonText,
        importPassphrase,
        persistEncrypted,
      );
      setImportPassphrase("");
      setStatusBanner({
        kind: "ok",
        text: `Verified Ed25519 signature and unlocked ${restored.vaultId} (${restored.payload.customScrubTerms.length} custom scrub terms restored).`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not import vault file: wrong passphrase or tampered ciphertext.",
      });
    }
  };

  const handleCryptoWipe = () => {
    wipeLocalVault();
    setExportedJson("");
    setVaultNotes("");
    setStatusBanner({
      kind: "ok",
      text: "Wiped in-memory keys and removed saved vault data from this browser.",
    });
  };

  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink">
      <SpecimenHeader activePath="/login" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto w-full max-w-4xl flex-1 space-y-8 px-4 py-10 sm:px-6"
      >
        {/* Hero */}
        <section aria-labelledby="login-heading" className="space-y-3 border-b border-rule pb-6">
          <div className="ep-label">Passphrase vault</div>
          <h1 id="login-heading" className="ep-display text-3xl sm:text-4xl">
            Passphrase vault
          </h1>
          <p className="max-w-[65ch] text-base leading-relaxed text-ink-2">
            No account and no email. Your passphrase derives AES-256-GCM and Ed25519 keys inside your browser and never leaves this device.
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

        {/* Active Vault Banner (when unlocked) */}
        {session && (
          <section
            aria-label="Active passphrase vault"
            className="ep-card p-5 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="ep-label">Active Passphrase Vault</div>
                <div className="font-mono text-sm font-semibold text-ink">
                  {session.vaultId}
                </div>
                <div className="font-mono text-[11px] text-ink-3">
                  Ed25519 pubkey: {shortHex(session.ed25519PublicKeyHex, 12, 8)} · Custom scrub terms: {session.payload.customScrubTerms.length}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="ep-pass">Unlocked locally</span>
                <button
                  type="button"
                  onClick={handleLockVault}
                  className="ep-btn-ghost text-xs py-1.5 px-3"
                >
                  Lock vault
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule pt-3 text-xs text-ink-2">
              <span>
                Storage mode:{" "}
                <strong className="font-mono text-ink">
                  {persistEncrypted
                    ? "AES-256-GCM ciphertext in browser localStorage"
                    : "RAM only (clears when tab closes)"}
                </strong>
              </span>
              <div className="flex items-center gap-2" role="group" aria-label="Vault storage mode">
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
                  RAM only
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
                  Save encrypted on device
                </button>
              </div>
            </div>
          </section>
        )}

        {/* Two Clear Choices */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          {/* Choice 1: Create a new vault */}
          <section
            aria-labelledby="create-vault-heading"
            className="ep-card p-5 flex flex-col justify-between space-y-5"
          >
            <div className="space-y-3">
              <div className="ep-label">Option 1</div>
              <h2 id="create-vault-heading" className="ep-display text-2xl">
                Create a new vault
              </h2>
              <p className="text-xs leading-relaxed text-ink-2">
                Copy these six random words and save them in your password manager or on paper. They derive your local encryption keys inside your browser.
              </p>

              <div className="ep-inset p-3.5 space-y-2">
                <div className="ep-label">Your 6-word passphrase (generated on device)</div>
                <div
                  data-testid="generated-passphrase"
                  className="select-all font-mono text-sm font-semibold text-ink min-h-[1.25rem]"
                >
                  {mounted ? burnerPassphrase : "Generating in browser..."}
                </div>
                {burnerPreview && (
                  <div className="border-t border-rule pt-2 font-mono text-[11px] text-ink-3">
                    Derived Vault ID: <span className="text-ink">{burnerPreview.vaultId}</span>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyBurner()}
                  disabled={!mounted || !burnerPassphrase}
                  className="ep-btn-ghost text-xs"
                >
                  {copiedBurner ? "Copied" : "Copy 6 words"}
                </button>
                <button
                  type="button"
                  onClick={handleGenerateBurner}
                  disabled={!mounted}
                  className="ep-btn-ghost text-xs"
                >
                  Generate new words
                </button>
              </div>
            </div>

            <div className="space-y-3 border-t border-rule pt-4">
              <label className="flex cursor-pointer items-center gap-2 text-xs text-ink">
                <input
                  type="checkbox"
                  checked={savedConfirmed}
                  onChange={(e) => setSavedConfirmed(e.target.checked)}
                  className="h-4 w-4 accent-ink"
                />
                <span>I saved these 6 words in a safe place</span>
              </label>

              <button
                type="button"
                onClick={handleCreateVault}
                disabled={!savedConfirmed || !mounted}
                className="ep-btn-accent w-full"
              >
                Create a new vault
              </button>
            </div>
          </section>

          {/* Choice 2: Unlock with my passphrase */}
          <section
            aria-labelledby="unlock-vault-heading"
            className="ep-card p-5 flex flex-col justify-between space-y-5"
          >
            <form
              onSubmit={handleUnlockExisting}
              className="flex h-full flex-col justify-between space-y-5"
            >
              <div className="space-y-3">
                <div className="ep-label">Option 2</div>
                <h2 id="unlock-vault-heading" className="ep-display text-2xl">
                  Unlock with my passphrase
                </h2>
                <p className="text-xs leading-relaxed text-ink-2">
                  Enter your existing passphrase to derive your vault keys in browser memory. The same words always produce the same vault ID.
                </p>

                <div>
                  <label
                    htmlFor="existing-passphrase-input"
                    className="block font-mono text-xs text-ink-2 mb-1.5"
                  >
                    Passphrase
                  </label>
                  <input
                    id="existing-passphrase-input"
                    type="text"
                    autoComplete="off"
                    spellCheck={false}
                    value={existingPassphrase}
                    onChange={(e) => setExistingPassphrase(e.target.value)}
                    placeholder="Synthetic example: word1 word2 word3 word4 word5 word6"
                    className="ep-input font-mono"
                  />
                </div>

                <div className="ep-inset p-3 font-mono text-[11px] text-ink-2">
                  {existingPreview ? (
                    <div className="space-y-1">
                      <div>
                        Vault ID:{" "}
                        <span className="font-semibold text-ink">
                          {existingPreview.vaultId}
                        </span>
                      </div>
                      <div>
                        X25519 public key: {shortHex(existingPreview.x25519PublicKeyHex, 10, 8)}
                      </div>
                    </div>
                  ) : persistedMeta.exists ? (
                    <span>
                      Encrypted vault {persistedMeta.vaultId} is stored on this device. Enter its passphrase to decrypt.
                    </span>
                  ) : (
                    <span>
                      Type your passphrase above to preview its local vault ID.
                    </span>
                  )}
                </div>
              </div>

              <div className="border-t border-rule pt-4">
                <button type="submit" className="ep-btn w-full">
                  Unlock with my passphrase
                </button>
              </div>
            </form>
          </section>
        </div>

        {/* Custom Scrub Terms (I3 -> I1 pipeline) */}
        <section
          aria-labelledby="custom-scrub-heading"
          className="ep-card p-5 space-y-5"
        >
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-rule pb-4">
            <div className="space-y-1">
              <div className="ep-label">Local Scrubber Dictionary (Feeds Console)</div>
              <h2 id="custom-scrub-heading" className="ep-display text-2xl">
                Custom scrub terms
              </h2>
              <p className="max-w-[68ch] text-xs leading-relaxed text-ink-2">
                Terms saved in your unlocked vault automatically feed the chat console through the client prompt pipeline. Your browser replaces each term with <code className="font-mono text-ink">[ENTITY_N]</code> before HPKE encryption and restores it when the enclave replies.
              </p>
            </div>
            <span className={session ? "ep-pass" : "ep-muted-chip"}>
              {session
                ? `${activeCustomTerms.length} active term${activeCustomTerms.length === 1 ? "" : "s"}`
                : "Vault locked (0 active terms)"}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="space-y-3">
              <form onSubmit={handleAddCustomTerm} className="flex gap-2">
                <label htmlFor="custom-term-input" className="sr-only">
                  Add custom scrub term
                </label>
                <input
                  id="custom-term-input"
                  type="text"
                  value={newCustomTerm}
                  onChange={(e) => setNewCustomTerm(e.target.value)}
                  disabled={!session}
                  placeholder={
                    session
                      ? "Add project codename, client, or internal ID..."
                      : "Unlock a vault above to add custom scrub terms"
                  }
                  className="ep-input"
                />
                <button
                  type="submit"
                  disabled={!session || !newCustomTerm.trim()}
                  className="ep-btn shrink-0"
                >
                  Add term
                </button>
              </form>

              {session ? (
                activeCustomTerms.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5" aria-label="Saved custom scrub terms">
                    {activeCustomTerms.map((term, i) => (
                      <span key={term} className="ep-muted-chip text-ink">
                        <span>
                          {term} &rarr; [ENTITY_{i + 1}]
                        </span>
                        <button
                          type="button"
                          onClick={() => handleRemoveCustomTerm(term)}
                          className="ml-1 font-bold text-ink hover:text-accent"
                          aria-label={`Remove custom scrub term ${term}`}
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="ep-inset p-3 text-xs text-ink-3">
                    No custom scrub terms saved in this vault yet. Add a term above (for example, <code className="font-mono text-ink">Fictional-Project-X</code>) to test redaction.
                  </div>
                )
              ) : (
                <div className="ep-inset p-3 text-xs text-ink-3">
                  Vault is locked. Create or unlock a vault above to add custom scrub terms.
                </div>
              )}

              {session && (
                <div className="space-y-1.5 pt-2 border-t border-rule">
                  <label
                    htmlFor="vault-notes-input"
                    className="block font-mono text-xs text-ink-2"
                  >
                    Encrypted vault notes (AES-256-GCM sealed when persisted or exported)
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
              )}
            </div>

            <div className="ep-inset p-3.5 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="ep-label">
                  Synthetic Scrubber Preview ({scrubPreview.report.redactions.length} redaction
                  {scrubPreview.report.redactions.length === 1 ? "" : "s"})
                </div>
                <span className="ep-muted-chip">Synthetic test input</span>
              </div>
              <label htmlFor="sample-prompt-textarea" className="sr-only">
                Synthetic test prompt for scrubber preview
              </label>
              <textarea
                id="sample-prompt-textarea"
                rows={2}
                value={samplePrompt}
                onChange={(e) => setSamplePrompt(e.target.value)}
                className="ep-input font-mono text-xs"
              />
              <div className="font-mono text-xs text-ink break-words">
                <span className="text-ink-3">Outbound text: </span>
                {scrubPreview.outboundText}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-rule pt-2 font-mono text-[11px] text-ink-3">
                <span>
                  Padded frame: {scrubPreview.bucketBytes.toLocaleString()} B
                </span>
                <span>
                  Risk score: {scrubPreview.report.riskBefore} &rarr; {scrubPreview.report.riskAfter}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Export, Import, and Wipe */}
        <section
          aria-labelledby="backup-restore-heading"
          className="ep-card p-5 space-y-6"
        >
          <div className="border-b border-rule pb-4">
            <div className="ep-label">Portable Encrypted Backup</div>
            <h2 id="backup-restore-heading" className="ep-display text-2xl mt-0.5">
              Export, import, or wipe your vault
            </h2>
            <p className="max-w-[68ch] text-xs text-ink-2 mt-1">
              Exported files contain only AES-256-GCM ciphertext and an Ed25519 signature. Neither your passphrase nor plaintext terms are written to disk or localStorage.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Export */}
            <div className="space-y-3">
              <div className="ep-label">Export</div>
              <h3 className="font-serif text-lg text-ink">
                Export encrypted vault file
              </h3>
              <p className="text-xs text-ink-2">
                Download your custom scrub terms and notes as an AES-256-GCM encrypted, Ed25519-signed <code className="font-mono text-ink">.drouter-vault.json</code> file.
              </p>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={handleExportVault}
                  disabled={!session}
                  className="ep-btn-ghost text-xs"
                >
                  Show encrypted JSON
                </button>
                <button
                  type="button"
                  onClick={handleDownloadExport}
                  disabled={!session && !exportedJson}
                  className="ep-btn text-xs"
                >
                  Download .drouter-vault.json
                </button>
              </div>
              {exportedJson && (
                <pre className="ep-inset max-h-40 overflow-auto p-3 font-mono text-[11px] text-ink-2">
                  {exportedJson}
                </pre>
              )}

              <div className="border-t border-rule pt-3 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-ink-2">
                  Zero in-memory keys and clear browser storage:
                </span>
                <button
                  type="button"
                  onClick={handleCryptoWipe}
                  className="ep-btn-ghost text-xs"
                >
                  Wipe local vault
                </button>
              </div>
            </div>

            {/* Import */}
            <form onSubmit={handleImportVault} className="space-y-3">
              <div className="ep-label">Import</div>
              <h3 className="font-serif text-lg text-ink">
                Import encrypted vault file
              </h3>
              <p className="text-xs text-ink-2">
                Upload or paste an exported <code className="font-mono text-ink">.drouter-vault.json</code> bundle and enter its passphrase to verify the Ed25519 signature and decrypt.
              </p>

              <div className="flex items-center gap-2">
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
                  className="ep-btn-ghost text-xs cursor-pointer"
                >
                  Choose .drouter-vault.json file
                </label>
              </div>

              <div>
                <label
                  htmlFor="import-vault-json"
                  className="block font-mono text-xs text-ink-2 mb-1"
                >
                  Encrypted vault JSON
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

              <div>
                <label
                  htmlFor="import-vault-passphrase"
                  className="block font-mono text-xs text-ink-2 mb-1"
                >
                  Passphrase for imported backup
                </label>
                <input
                  id="import-vault-passphrase"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  value={importPassphrase}
                  onChange={(e) => setImportPassphrase(e.target.value)}
                  placeholder="Enter passphrase for this backup file"
                  className="ep-input font-mono text-xs"
                />
              </div>

              <button type="submit" className="ep-btn text-xs">
                Verify &amp; import vault
              </button>
            </form>
          </div>

          <div className="border-t border-rule pt-4 text-xs text-ink-3 flex flex-wrap items-center justify-between gap-2">
            <span>
              Key derivation: PBKDF2-HMAC-SHA-512 (210,000 rounds) + HKDF-SHA-384 (AES-256-GCM, Ed25519, X25519).
            </span>
            <Link href="/" className="ep-link">
              Return to console
            </Link>
          </div>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
