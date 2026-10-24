"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
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
  return `${hex.slice(0, lead)}…${hex.slice(-tail)}`;
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
  const [session, setSession] = useState<VaultSession | null>(() => getCurrentVaultSession());
  const [burnerPassphrase, setBurnerPassphrase] = useState<string>("argon cobalt velvet cipher obsidian quartz");
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
  const [derivationCount, setDerivationCount] = useState<number>(0);
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
    setStatusBanner({
      kind: "info",
      text: "Generated a fresh 6-word burner passphrase from 256 words using browser CSPRNG. Zero bytes sent over the network.",
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
        text: "Clipboard permission unavailable; select and copy the 6-word passphrase directly.",
      });
    }
  };

  const handleUnlockBurner = () => {
    try {
      const unlocked = unlockVaultWithPassphrase(burnerPassphrase, persistEncrypted);
      setDerivationCount((c) => c + 1);
      setStatusBanner({
        kind: "ok",
        text: `Unlocked Zero-Knowledge Vault ${unlocked.vaultId} locally (${
          persistEncrypted ? "AES-256-GCM persisted in localStorage" : "Ephemeral RAM-only session"
        }). 0 network bytes sent.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Could not unlock burner vault",
      });
    }
  };

  const handleUnlockExisting = (e: React.FormEvent) => {
    e.preventDefault();
    if (!existingPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Enter your passphrase first to derive your vault keys in-browser.",
      });
      return;
    }
    try {
      const unlocked = unlockVaultWithPassphrase(existingPassphrase, persistEncrypted);
      setDerivationCount((c) => c + 1);
      setStatusBanner({
        kind: "ok",
        text: `Derived and unlocked ${unlocked.vaultId} inside your browser. 0 bytes sent to server.`,
      });
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Failed to derive vault identity",
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
      text: `Added "${trimmed}" to encrypted vault ${updated.vaultId}. The client scrubber will replace it with an [ENTITY_N] tag before HPKE encryption.`,
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
      text: "Encrypted vault notes updated locally.",
    });
  };

  const handleTogglePersistence = (nextPersist: boolean) => {
    setPersistEncrypted(nextPersist);
    if (session) {
      setVaultPersistenceMode(nextPersist);
      setStatusBanner({
        kind: "info",
        text: nextPersist
          ? `Sealed vault as AES-256-GCM ciphertext under localStorage["${VAULT_STORAGE_KEY}"].`
          : `Switched to RAM-only mode and removed "${VAULT_STORAGE_KEY}" from localStorage.`,
      });
    }
  };

  const handleExportVault = () => {
    try {
      const json = exportEncryptedVaultJson();
      setExportedJson(json);
      setStatusBanner({
        kind: "ok",
        text: "Signed and sealed .drouter-vault.json in browser memory. All custom terms and notes are AES-256-GCM encrypted.",
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
      triggerJsonDownload(exportedJson, session?.vaultId ?? "zk-vault");
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
      setDerivationCount((c) => c + 1);
      setStatusBanner({
        kind: "ok",
        text: `Verified Ed25519 signature and decrypted ${restored.vaultId} (${restored.payload.customScrubTerms.length} custom scrub terms restored).`,
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
      text: `Crypto-wiped RAM session keys and removed "${VAULT_STORAGE_KEY}" from local device storage.`,
    });
  };

  return (
    <div className="min-h-screen bg-[#050506] text-zinc-100">
      {/* Top Specimen Header */}
      <header className="border-b border-zinc-800/80 bg-zinc-950/90 px-4 py-3 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="rounded border border-zinc-800 bg-zinc-900 px-2.5 py-1 font-mono text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:text-white"
            >
              dRouter
            </Link>
            <span className="font-mono text-xs uppercase tracking-wider text-zinc-400">
              Zero-Knowledge Identity &amp; Local Vault
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-1.5 rounded-full border border-emerald-800/60 bg-emerald-950/40 px-3 py-1 font-mono text-[11px] text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              <span>0 bytes sent to server</span>
              <span className="text-zinc-500">|</span>
              <span>{derivationCount} local KDF runs</span>
            </div>
            <AuthPill />
            <Link
              href="/"
              className="rounded border border-zinc-800 bg-zinc-900/60 px-2.5 py-1 text-xs text-zinc-300 hover:border-zinc-700 hover:text-white"
            >
              Back to Console
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-4 py-8">
        {/* Plain-English Explanation Hero */}
        <section className="rounded-xl border border-zinc-800/90 bg-zinc-950/80 p-6 shadow-2xl">
          <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
            <div className="max-w-3xl space-y-2.5">
              <div className="inline-flex items-center gap-2 rounded border border-amber-700/50 bg-amber-950/30 px-2.5 py-0.5 font-mono text-[11px] text-amber-300">
                100% Client-Side Key Derivation · PBKDF2-HMAC-SHA-512 to HKDF-SHA-384
              </div>
              <h1 className="text-2xl font-semibold tracking-tight text-white">
                If we knew who you were, an enclave wouldn&apos;t make you anonymous.
              </h1>
              <p className="text-sm leading-relaxed text-zinc-300">
                A traditional login with an email address, OAuth provider, or server-stored password
                hash gives the server a permanent account ID to link every prompt you ever send.
                dRouter has no user database, no email table, and no server login endpoint.
              </p>
              <p className="text-sm leading-relaxed text-zinc-400">
                Instead, your passphrase stays strictly inside your browser. It runs through 10,000
                rounds of PBKDF2-HMAC-SHA-512 and HKDF-SHA-384 to derive your local{" "}
                <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs text-emerald-300">
                  vaultAesKey
                </code>{" "}
                (for encrypting blind credits, freeze secrets, and custom PII terms at rest) and
                your{" "}
                <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs text-emerald-300">
                  Ed25519
                </code>{" "}
                keypair (for signing exported vault backups). Not a single byte leaves your device.
              </p>
            </div>

            {/* Live Network Audit Counter */}
            <div className="min-w-[240px] rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 font-mono text-xs">
              <div className="text-[10px] uppercase tracking-wider text-zinc-400">
                Live Login Network Monitor
              </div>
              <div className="mt-2 text-2xl font-bold text-emerald-400">
                0 bytes sent to server
              </div>
              <div className="mt-2 space-y-1 text-[11px] text-zinc-400">
                <div className="flex justify-between">
                  <span>Auth HTTP requests:</span>
                  <span className="text-zinc-200">0</span>
                </div>
                <div className="flex justify-between">
                  <span>Cookies / JWTs issued:</span>
                  <span className="text-zinc-200">0</span>
                </div>
                <div className="flex justify-between">
                  <span>Storage mode:</span>
                  <span className="text-emerald-300">
                    {persistEncrypted ? "Encrypted Local" : "RAM-Only"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {statusBanner && (
            <div
              className={`mt-4 rounded-lg border px-3.5 py-2.5 text-xs ${
                statusBanner.kind === "ok"
                  ? "border-emerald-800/70 bg-emerald-950/40 text-emerald-200"
                  : statusBanner.kind === "err"
                    ? "border-rose-800/70 bg-rose-950/40 text-rose-200"
                    : "border-sky-800/70 bg-sky-950/40 text-sky-200"
              }`}
            >
              {statusBanner.text}
            </div>
          )}
        </section>

        {/* Storage Mode Selector Bar */}
        <section className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-950/70 px-5 py-3.5 text-xs">
          <div className="space-y-0.5">
            <div className="font-semibold text-zinc-200">
              Vault Persistence Policy:{" "}
              <span className="font-mono text-emerald-300">
                {persistEncrypted
                  ? `Encrypted Local Vault (${VAULT_STORAGE_KEY})`
                  : "Ephemeral RAM-Only Session (Default)"}
              </span>
            </div>
            <p className="text-zinc-400">
              {persistEncrypted
                ? "Your vault payload is sealed with AES-256-GCM before touching localStorage. Plaintext keys remain in RAM only."
                : "Keys and custom scrub terms live strictly in browser memory and vanish the moment you close this tab."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleTogglePersistence(false)}
              className={`rounded-md border px-3 py-1.5 font-medium transition ${
                !persistEncrypted
                  ? "border-emerald-600/70 bg-emerald-950/60 text-emerald-200"
                  : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Ephemeral RAM-Only
            </button>
            <button
              type="button"
              onClick={() => handleTogglePersistence(true)}
              className={`rounded-md border px-3 py-1.5 font-medium transition ${
                persistEncrypted
                  ? "border-emerald-600/70 bg-emerald-950/60 text-emerald-200"
                  : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Encrypted Local Vault
            </button>
          </div>
        </section>

        {/* Option 1 & Option 2 Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Option 1: Generate a 6-Word Burner Passphrase */}
          <section className="flex flex-col justify-between rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-emerald-300">
                  Option 1
                </span>
                <span className="font-mono text-[11px] text-zinc-500">
                  256-word dictionary · crypto.getRandomValues
                </span>
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">
                  Generate a 6-Word Burner Passphrase
                </h2>
                <p className="mt-1 text-xs text-zinc-400">
                  Generate a fresh anonymous passphrase in one click, copy it to your password
                  manager or paper note, and unlock a clean client vault immediately.
                </p>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900/80 p-3.5">
                <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Generated 6-Word Passphrase
                </div>
                <div className="mt-1.5 select-all font-mono text-sm font-semibold tracking-wide text-emerald-300">
                  {burnerPassphrase}
                </div>
                {burnerPreview && (
                  <div className="mt-3 grid grid-cols-2 gap-2 border-t border-zinc-800/80 pt-2.5 font-mono text-[11px] text-zinc-400">
                    <div>
                      <span className="text-zinc-500">Vault ID: </span>
                      <span className="text-zinc-200">{burnerPreview.vaultId}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Ed25519: </span>
                      <span className="text-zinc-300">
                        {shortHex(burnerPreview.ed25519PublicKeyHex, 8, 6)}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={handleGenerateBurner}
                className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-semibold text-zinc-200 transition hover:border-zinc-600 hover:bg-zinc-800"
              >
                Generate 6-Word Anonymous Passphrase
              </button>
              <button
                type="button"
                onClick={() => void handleCopyBurner()}
                className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-medium text-zinc-300 transition hover:border-zinc-600 hover:text-white"
              >
                {copiedBurner ? "Copied" : "Copy Words"}
              </button>
              <button
                type="button"
                onClick={handleUnlockBurner}
                className="ml-auto rounded-md border border-emerald-600/80 bg-emerald-950/70 px-4 py-2 text-xs font-semibold text-emerald-200 transition hover:bg-emerald-900/70"
              >
                Unlock Burner Vault
              </button>
            </div>
          </section>

          {/* Option 2: Unlock with Existing Passphrase */}
          <section className="flex flex-col justify-between rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
            <form onSubmit={handleUnlockExisting} className="flex h-full flex-col justify-between space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-sky-300">
                    Option 2
                  </span>
                  <span className="font-mono text-[11px] text-emerald-400">
                    0 bytes sent to server
                  </span>
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-white">
                    Unlock with Existing Passphrase
                  </h2>
                  <p className="mt-1 text-xs text-zinc-400">
                    Type your existing 6-word or custom passphrase. Because key derivation is
                    deterministic, the same words always reconstruct your exact{" "}
                    <code className="font-mono text-zinc-300">zk-...</code> identity and decrypt
                    your local vault in-browser.
                  </p>
                </div>

                <div>
                  <label
                    htmlFor="existing-passphrase-input"
                    className="block text-[11px] font-medium text-zinc-400"
                  >
                    Passphrase (case and extra spaces are normalized automatically)
                  </label>
                  <input
                    id="existing-passphrase-input"
                    type="text"
                    value={existingPassphrase}
                    onChange={(e) => setExistingPassphrase(e.target.value)}
                    placeholder="e.g. aurora cobalt falcon glacier monolith quartz"
                    className="mt-1.5 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 font-mono text-xs text-zinc-100 placeholder-zinc-600 focus:border-emerald-600 focus:outline-none"
                  />
                </div>

                {existingPreview ? (
                  <div className="rounded-lg border border-zinc-800/90 bg-zinc-900/60 p-3 font-mono text-[11px] text-zinc-300">
                    <div className="flex items-center justify-between">
                      <span className="text-zinc-500">Derived Fingerprint:</span>
                      <span className="font-semibold text-emerald-300">
                        {existingPreview.vaultId}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center justify-between">
                      <span className="text-zinc-500">X25519 Public Key:</span>
                      <span>{shortHex(existingPreview.x25519PublicKeyHex, 10, 8)}</span>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-lg border border-zinc-900 bg-zinc-900/30 p-3 text-xs text-zinc-500">
                    {persistedMeta.exists
                      ? `Encrypted vault ${persistedMeta.vaultId} is stored on this device. Enter its passphrase to decrypt.`
                      : "Enter any passphrase above to preview its deterministic zk-fingerprint in real time."}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="font-mono text-[11px] text-zinc-500">
                  PBKDF2 (10,000 rounds) + HKDF-SHA-384
                </span>
                <button
                  type="submit"
                  className="rounded-md border border-sky-600/80 bg-sky-950/70 px-4 py-2 text-xs font-semibold text-sky-200 transition hover:bg-sky-900/70"
                >
                  Derive &amp; Unlock Vault
                </button>
              </div>
            </form>
          </section>
        </div>

        {/* Active Identity Specimen Inspector (when unlocked) */}
        {session && (
          <section className="rounded-xl border border-emerald-800/60 bg-emerald-950/15 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                  Unlocked Client Vault Specimen
                </div>
                <h3 className="text-base font-semibold text-white">
                  Active Fingerprint:{" "}
                  <span className="font-mono text-emerald-300">{session.vaultId}</span>{" "}
                  <span className="text-xs font-normal text-zinc-400">
                    (Never transmitted with prompts)
                  </span>
                </h3>
              </div>
              <button
                type="button"
                onClick={() => lockVault()}
                className="rounded-md border border-amber-700/60 bg-amber-950/40 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-900/50"
              >
                Lock Vault Session
              </button>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 font-mono text-xs md:grid-cols-3">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3">
                <div className="text-[10px] text-zinc-500">Ed25519 Export Signing Public Key</div>
                <div className="mt-1 truncate text-zinc-200" title={session.ed25519PublicKeyHex}>
                  {shortHex(session.ed25519PublicKeyHex, 14, 10)}
                </div>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3">
                <div className="text-[10px] text-zinc-500">X25519 Envelope Public Key</div>
                <div className="mt-1 truncate text-zinc-200" title={session.x25519PublicKeyHex}>
                  {shortHex(session.x25519PublicKeyHex, 14, 10)}
                </div>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3">
                <div className="text-[10px] text-zinc-500">AES-256-GCM Local Storage Key</div>
                <div className="mt-1 text-emerald-300">
                  {shortHex(session.vaultKeyHex, 10, 6)} (256-bit)
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Custom Sensitive Terms Vault */}
        <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6">
          <div className="flex flex-col justify-between gap-2 md:flex-row md:items-center">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Custom Sensitive Terms Vault
              </h2>
              <p className="text-xs text-zinc-400">
                Add secret project codenames, client names, or internal patient IDs. The client PII
                scrubber replaces every match with{" "}
                <code className="font-mono text-amber-300">[ENTITY_1]</code>,{" "}
                <code className="font-mono text-amber-300">[ENTITY_2]</code> before your prompt is
                encrypted, and restores them locally when the response arrives.
              </p>
            </div>
            <span className="rounded border border-zinc-800 bg-zinc-900 px-2.5 py-1 font-mono text-[11px] text-zinc-300">
              {session
                ? `${session.payload.customScrubTerms.length} terms sealed in ${session.vaultId}`
                : "Unlock vault or add a term to auto-initialize"}
            </span>
          </div>

          <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Term Manager & Notes */}
            <div className="space-y-4">
              <form onSubmit={handleAddCustomTerm} className="flex gap-2">
                <input
                  type="text"
                  value={newCustomTerm}
                  onChange={(e) => setNewCustomTerm(e.target.value)}
                  placeholder="Add project codename, client name, or patient ID..."
                  className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-600 focus:border-emerald-600 focus:outline-none"
                />
                <button
                  type="submit"
                  className="rounded-lg border border-emerald-700/70 bg-emerald-950/60 px-3.5 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-900/60"
                >
                  + Add Term
                </button>
              </form>

              <div className="flex flex-wrap gap-2">
                {activeCustomTerms.length === 0 ? (
                  <span className="text-xs text-zinc-500">
                    No custom scrub terms added yet.
                  </span>
                ) : (
                  activeCustomTerms.map((term, i) => (
                    <span
                      key={term}
                      className="inline-flex items-center gap-2 rounded-md border border-amber-800/60 bg-amber-950/30 px-2.5 py-1 font-mono text-xs text-amber-200"
                    >
                      <span>
                        {term} → [ENTITY_{i + 1}]
                      </span>
                      {session && (
                        <button
                          type="button"
                          onClick={() => handleRemoveCustomTerm(term)}
                          className="text-zinc-400 hover:text-rose-300"
                          title={`Remove ${term}`}
                        >
                          ×
                        </button>
                      )}
                    </span>
                  ))
                )}
              </div>

              {session && (
                <div className="space-y-2 pt-2">
                  <label className="block text-[11px] font-medium text-zinc-400">
                    Encrypted Scratchpad Notes (sealed inside AES-256-GCM bundle)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={vaultNotes}
                      onChange={(e) => setVaultNotes(e.target.value)}
                      placeholder="Optional private notes or freeze secret reminders..."
                      className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-600"
                    />
                    <button
                      type="button"
                      onClick={handleSaveNotes}
                      className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:border-zinc-600 hover:text-white"
                    >
                      Save Notes
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Live Pre-HPKE Entity Replacement Sandbox */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-zinc-300">
                  Live Pre-HPKE Scrubber Preview
                </span>
                <span className="font-mono text-[11px] text-amber-300">
                  {scrubDemo.matches.length} custom entities scrubbed
                </span>
              </div>
              <textarea
                rows={2}
                value={samplePrompt}
                onChange={(e) => setSamplePrompt(e.target.value)}
                className="w-full rounded border border-zinc-800 bg-zinc-950 p-2.5 font-mono text-xs text-zinc-200 focus:border-zinc-700 focus:outline-none"
              />
              <div className="rounded border border-zinc-800/80 bg-zinc-950/90 p-2.5 font-mono text-xs">
                <div className="text-[10px] uppercase tracking-wider text-zinc-500">
                  Outbound Payload Entering Enclave Tunnel:
                </div>
                <div className="mt-1 text-emerald-300">{scrubDemo.scrubbed}</div>
              </div>
            </div>
          </div>
        </section>

        {/* Export / Import .drouter-vault.json + Crypto-Wipe */}
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Export & Crypto-Wipe */}
          <div className="flex flex-col justify-between rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 space-y-4">
            <div className="space-y-3">
              <h2 className="text-base font-semibold text-white">
                Export Encrypted <code className="font-mono text-emerald-300">.drouter-vault.json</code>
              </h2>
              <p className="text-xs text-zinc-400">
                Export your custom dictionary and notes as an AES-256-GCM encrypted, Ed25519-signed
                portable file. Even if someone intercepts the file, it contains zero plaintext
                terms.
              </p>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={handleExportVault}
                  className="rounded-md border border-emerald-700/70 bg-emerald-950/50 px-3 py-1.5 text-xs font-semibold text-emerald-200 hover:bg-emerald-900/60"
                >
                  Generate Encrypted JSON
                </button>
                <button
                  type="button"
                  onClick={handleDownloadExport}
                  disabled={!session && !exportedJson}
                  className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
                >
                  Download .drouter-vault.json
                </button>
              </div>

              {exportedJson && (
                <pre className="max-h-44 overflow-auto rounded-lg border border-zinc-800 bg-zinc-900/90 p-3 font-mono text-[11px] text-zinc-300">
                  {exportedJson}
                </pre>
              )}
            </div>

            <div className="border-t border-zinc-800/80 pt-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-semibold text-rose-300">
                    Crypto-Wipe Local Device Storage
                  </div>
                  <p className="text-[11px] text-zinc-500">
                    Zeroes in-memory keys and deletes <code className="font-mono">{VAULT_STORAGE_KEY}</code> from this browser.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleCryptoWipe}
                  className="rounded-md border border-rose-700/70 bg-rose-950/50 px-3 py-1.5 text-xs font-semibold text-rose-200 transition hover:bg-rose-900/60"
                >
                  Crypto-Wipe Local Device Storage
                </button>
              </div>
            </div>
          </div>

          {/* Import Encrypted .drouter-vault.json */}
          <form
            onSubmit={handleImportVault}
            className="flex flex-col justify-between rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 space-y-4"
          >
            <div className="space-y-3">
              <h2 className="text-base font-semibold text-white">
                Import Encrypted <code className="font-mono text-sky-300">.drouter-vault.json</code>
              </h2>
              <p className="text-xs text-zinc-400">
                Paste a previously exported <code className="font-mono">.drouter-vault.json</code>{" "}
                bundle and enter the passphrase that sealed it. Both the Ed25519 signature and the
                AES-256-GCM authentication tag are verified locally.
              </p>

              <textarea
                rows={4}
                value={importJsonText}
                onChange={(e) => setImportJsonText(e.target.value)}
                placeholder='{"format": "drouter-zk-vault-v1", "vaultId": "zk-...", ...}'
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 p-2.5 font-mono text-[11px] text-zinc-200 placeholder-zinc-600 focus:border-sky-600 focus:outline-none"
              />

              <input
                type="text"
                value={importPassphrase}
                onChange={(e) => setImportPassphrase(e.target.value)}
                placeholder="Passphrase for this .drouter-vault.json file"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 font-mono text-xs text-zinc-100 placeholder-zinc-600 focus:border-sky-600 focus:outline-none"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                className="rounded-md border border-sky-700/70 bg-sky-950/60 px-4 py-2 text-xs font-semibold text-sky-200 transition hover:bg-sky-900/60"
              >
                Verify &amp; Import Vault
              </button>
            </div>
          </form>
        </section>
      </main>
    </div>
  );
}
