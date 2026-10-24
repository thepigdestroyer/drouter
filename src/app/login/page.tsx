"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
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

function shortHex(hex: string, lead = 12, tail = 8): string {
  if (!hex || hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}...${hex.slice(-tail)}`;
}

function previewCustomTermScrub(text: string, terms: string[]): {
  scrubbed: string;
  matches: { term: string; placeholder: string }[];
} {
  let scrubbed = text;
  const matches: { term: string; placeholder: string }[] = [];
  const sorted = [...terms]
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .sort((a, b) => b.length - a.length);

  sorted.forEach((term, idx) => {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "gi");
    if (regex.test(scrubbed)) {
      const placeholder = `[ENTITY_${idx + 1}]`;
      scrubbed = scrubbed.replace(regex, placeholder);
      matches.push({ term, placeholder });
    }
  });

  return { scrubbed, matches };
}

export default function LoginPage() {
  const [session, setSession] = useState<VaultSession | null>(null);
  const [burnerPassphrase, setBurnerPassphrase] = useState<string>(
    "argon cobalt velvet cipher obsidian quartz",
  );
  const [savedConfirmed, setSavedConfirmed] = useState<boolean>(false);
  const [existingPassphrase, setExistingPassphrase] = useState<string>("");
  const [persistEncrypted, setPersistEncrypted] = useState<boolean>(false);
  const [copiedBurner, setCopiedBurner] = useState<boolean>(false);
  const [newCustomTerm, setNewCustomTerm] = useState<string>("");
  const [vaultNotes, setVaultNotes] = useState<string>("");
  const [samplePrompt, setSamplePrompt] = useState<string>(
    "Summarize the Q4 merger architecture for Project Helios and patient record MRN-88412.",
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
    if (!mounted) return null;
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

  const activeCustomTerms = session?.payload.customScrubTerms ?? [
    "Project Helios",
    "MRN-88412",
  ];

  const scrubDemo = useMemo(
    () => previewCustomTermScrub(samplePrompt, activeCustomTerms),
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

  const handleTogglePersistence = (nextPersist: boolean) => {
    setPersistEncrypted(nextPersist);
    if (session) {
      setVaultPersistenceMode(nextPersist);
      setStatusBanner({
        kind: "info",
        text: nextPersist
          ? `Saved encrypted vault in localStorage under "${VAULT_STORAGE_KEY}".`
          : "Switched to RAM-only mode and cleared localStorage copy.",
      });
    }
  };

  const handleAddCustomTerm = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newCustomTerm.trim();
    if (!trimmed) return;

    if (!session) {
      unlockVaultWithPassphrase(burnerPassphrase, persistEncrypted);
    }
    const updated = updateVaultPayload((prev) => ({
      ...prev,
      customScrubTerms: [...prev.customScrubTerms, trimmed],
    }));
    setNewCustomTerm("");
    setStatusBanner({
      kind: "ok",
      text: `Added "${trimmed}" to vault ${updated.vaultId}.`,
    });
  };

  const handleRemoveCustomTerm = (termToRemove: string) => {
    if (!session) return;
    updateVaultPayload((prev) => ({
      ...prev,
      customScrubTerms: prev.customScrubTerms.filter((t) => t !== termToRemove),
    }));
  };

  const handleSaveNotes = () => {
    if (!session) return;
    updateVaultPayload((prev) => ({
      ...prev,
      notes: vaultNotes,
    }));
    setStatusBanner({
      kind: "ok",
      text: "Updated encrypted notes locally.",
    });
  };

  const handleExportVault = () => {
    try {
      const json = exportEncryptedVaultJson();
      setExportedJson(json);
      setStatusBanner({
        kind: "ok",
        text: "Prepared encrypted .drouter-vault.json in browser memory.",
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Unlock a vault first before exporting.",
      });
    }
  };

  const handleDownloadExport = () => {
    if (!exportedJson && session) {
      const fresh = exportEncryptedVaultJson();
      setExportedJson(fresh);
      triggerJsonDownload(fresh, session.vaultId);
      return;
    }
    if (exportedJson) {
      triggerJsonDownload(exportedJson, session?.vaultId ?? "passphrase-vault");
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

  const handleImportVault = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const restored = importEncryptedVaultJson(
        importJsonText,
        importPassphrase,
        persistEncrypted,
      );
      setStatusBanner({
        kind: "ok",
        text: `Verified signature and unlocked ${restored.vaultId} (${restored.payload.customScrubTerms.length} custom scrub terms restored).`,
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

      <main className="mx-auto w-full max-w-4xl flex-1 space-y-8 px-4 py-10 sm:px-6">
        {/* Hero */}
        <section className="space-y-3 border-b border-rule pb-6">
          <div className="ep-label">Passphrase vault</div>
          <h1 className="ep-display text-3xl sm:text-4xl">Passphrase vault</h1>
          <p className="max-w-[65ch] text-base leading-relaxed text-ink-2">
            No account and no email. Your passphrase never leaves this device.
          </p>

          {statusBanner && (
            <div
              role="status"
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
          <section className="ep-card p-5 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="ep-label">Active Passphrase Vault</div>
                <div className="font-mono text-sm font-semibold text-ink">
                  {session.vaultId}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="ep-pass">Unlocked locally</span>
                <button
                  type="button"
                  onClick={() => lockVault()}
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
                    ? "Encrypted in browser localStorage"
                    : "RAM only (clears when tab closes)"}
                </strong>
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleTogglePersistence(false)}
                  className={!persistEncrypted ? "ep-btn text-xs py-1 px-2.5" : "ep-btn-ghost text-xs py-1 px-2.5"}
                >
                  RAM only
                </button>
                <button
                  type="button"
                  onClick={() => handleTogglePersistence(true)}
                  className={persistEncrypted ? "ep-btn text-xs py-1 px-2.5" : "ep-btn-ghost text-xs py-1 px-2.5"}
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
          <section className="ep-card p-5 flex flex-col justify-between space-y-5">
            <div className="space-y-3">
              <div className="ep-label">Option 1</div>
              <h2 className="ep-display text-2xl">Create a new vault</h2>
              <p className="text-xs leading-relaxed text-ink-2">
                Copy these six random words and save them in your password manager or on paper. They derive your local encryption keys inside your browser.
              </p>

              <div className="ep-inset p-3.5 space-y-2">
                <div className="ep-label">Your 6-word passphrase</div>
                <div className="select-all font-mono text-sm font-semibold text-ink">
                  {burnerPassphrase}
                </div>
                {burnerPreview && (
                  <div className="border-t border-rule pt-2 font-mono text-[11px] text-ink-3">
                    Vault ID: <span className="text-ink">{burnerPreview.vaultId}</span>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyBurner()}
                  className="ep-btn-ghost text-xs"
                >
                  {copiedBurner ? "Copied" : "Copy 6 words"}
                </button>
                <button
                  type="button"
                  onClick={handleGenerateBurner}
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
                <span>I saved it in a safe place</span>
              </label>

              <button
                type="button"
                onClick={handleCreateVault}
                disabled={!savedConfirmed}
                className="ep-btn-accent w-full"
              >
                Create a new vault
              </button>
            </div>
          </section>

          {/* Choice 2: Unlock with my passphrase */}
          <section className="ep-card p-5 flex flex-col justify-between space-y-5">
            <form
              onSubmit={handleUnlockExisting}
              className="flex h-full flex-col justify-between space-y-5"
            >
              <div className="space-y-3">
                <div className="ep-label">Option 2</div>
                <h2 className="ep-display text-2xl">Unlock with my passphrase</h2>
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
                    value={existingPassphrase}
                    onChange={(e) => setExistingPassphrase(e.target.value)}
                    placeholder="e.g. orbit maple cable harvest velvet lunar"
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
                        Public key: {shortHex(existingPreview.x25519PublicKeyHex, 10, 8)}
                      </div>
                    </div>
                  ) : persistedMeta.exists ? (
                    <span>
                      Saved vault {persistedMeta.vaultId} found on this device. Enter its passphrase to decrypt.
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

        {/* More options: Custom scrub terms, Import/Export, Wipe */}
        <details className="ep-card p-5">
          <summary className="cursor-pointer font-serif text-lg text-ink">
            More options (custom scrub terms, export, import)
          </summary>

          <div className="mt-5 space-y-8 border-t border-rule pt-5">
            {/* Custom Scrub Terms */}
            <div className="space-y-4">
              <div>
                <div className="ep-label">Local Scrubber Dictionary</div>
                <h3 className="font-serif text-lg text-ink mt-0.5">
                  Custom scrub terms
                </h3>
                <p className="max-w-[68ch] text-xs text-ink-2">
                  Add project names, client names, or internal IDs. Your browser replaces them with placeholders like <code className="font-mono text-ink">[ENTITY_1]</code> before encrypting your prompt.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
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
                      placeholder="Add project name, client, or ID..."
                      className="ep-input"
                    />
                    <button type="submit" className="ep-btn shrink-0">
                      Add term
                    </button>
                  </form>

                  <div className="flex flex-wrap gap-1.5">
                    {activeCustomTerms.map((term, i) => (
                      <span key={term} className="ep-muted-chip">
                        <span>
                          {term} &rarr; [ENTITY_{i + 1}]
                        </span>
                        {session && (
                          <button
                            type="button"
                            onClick={() => handleRemoveCustomTerm(term)}
                            className="ml-1 font-bold text-ink hover:text-accent"
                            aria-label={`Remove ${term}`}
                          >
                            &times;
                          </button>
                        )}
                      </span>
                    ))}
                  </div>

                  {session && (
                    <div className="space-y-1.5 pt-2">
                      <label
                        htmlFor="vault-notes-input"
                        className="block font-mono text-xs text-ink-2"
                      >
                        Encrypted vault notes
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
                          Save
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="ep-inset p-3.5 space-y-2">
                  <div className="ep-label">
                    Scrubber preview ({scrubDemo.matches.length} matched)
                  </div>
                  <label htmlFor="sample-prompt-textarea" className="sr-only">
                    Sample prompt for scrubber preview
                  </label>
                  <textarea
                    id="sample-prompt-textarea"
                    rows={2}
                    value={samplePrompt}
                    onChange={(e) => setSamplePrompt(e.target.value)}
                    className="ep-input font-mono text-xs"
                  />
                  <div className="font-mono text-xs text-ink">
                    <span className="text-ink-3">Outbound text: </span>
                    {scrubDemo.scrubbed}
                  </div>
                </div>
              </div>
            </div>

            {/* Export & Import */}
            <div className="grid grid-cols-1 gap-6 border-t border-rule pt-6 lg:grid-cols-2">
              <div className="space-y-3">
                <div className="ep-label">Backup</div>
                <h3 className="font-serif text-lg text-ink">
                  Export encrypted vault file
                </h3>
                <p className="text-xs text-ink-2">
                  Download your custom terms and notes as an AES-256-GCM encrypted, Ed25519-signed <code className="font-mono text-ink">.drouter-vault.json</code> file.
                </p>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={handleExportVault}
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
                    Clear keys from memory and browser storage:
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

              <form onSubmit={handleImportVault} className="space-y-3">
                <div className="ep-label">Restore</div>
                <h3 className="font-serif text-lg text-ink">
                  Import encrypted vault file
                </h3>
                <p className="text-xs text-ink-2">
                  Paste an exported <code className="font-mono text-ink">.drouter-vault.json</code> bundle and enter its passphrase to verify and unlock.
                </p>
                <label htmlFor="import-vault-json" className="sr-only">
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
                <label htmlFor="import-vault-passphrase" className="sr-only">
                  Passphrase for imported vault
                </label>
                <input
                  id="import-vault-passphrase"
                  type="text"
                  value={importPassphrase}
                  onChange={(e) => setImportPassphrase(e.target.value)}
                  placeholder="Passphrase for this backup file"
                  className="ep-input font-mono text-xs"
                />
                <button type="submit" className="ep-btn text-xs">
                  Verify &amp; import vault
                </button>
              </form>
            </div>

            {/* Technical KDF note */}
            <div className="border-t border-rule pt-4 text-xs text-ink-3 flex flex-wrap items-center justify-between gap-2">
              <span>
                Key derivation: PBKDF2-HMAC-SHA-512 (210,000 rounds) + HKDF-SHA-384 (AES-256-GCM, Ed25519, X25519).
              </span>
              <Link href="/" className="ep-link">
                Return to console
              </Link>
            </div>
          </div>
        </details>
      </main>

      <SpecimenFooter />
    </div>
  );
}
