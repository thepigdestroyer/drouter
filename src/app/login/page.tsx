"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { sanitizeNextPath } from "@/components/auth/auth-gate";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  PasskeyPrfUnsupportedError,
  createPasskeyAccount,
  isPasskeyPrfSupported,
  signInWithPasskey,
} from "@/lib/auth/passkey";
import {
  deriveVaultIdentity,
  generatePassphrase,
  getCurrentVaultSession,
  getPersistedVaultMetadata,
  lockVault,
  subscribeVaultSession,
  unlockVaultWithPassphrase,
  type VaultSession,
} from "@/lib/auth/vault";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextPath = useMemo(
    () => sanitizeNextPath(searchParams?.get("next"), "/app"),
    [searchParams],
  );

  const [session, setSession] = useState<VaultSession | null>(null);
  const [prfSupported, setPrfSupported] = useState<boolean | null>(null);
  const [passkeyBusy, setPasskeyBusy] = useState<boolean>(false);
  const [burnerPassphrase, setBurnerPassphrase] = useState<string>("");
  const [savedConfirmed, setSavedConfirmed] = useState<boolean>(false);
  const [existingPassphrase, setExistingPassphrase] = useState<string>("");
  const [persistEncrypted, setPersistEncrypted] = useState<boolean>(true);
  const [copiedBurner, setCopiedBurner] = useState<boolean>(false);
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

    let active = true;
    void isPasskeyPrfSupported().then((supported) => {
      if (active) {
        setPrfSupported(supported);
      }
    });

    const sync = () => {
      const current = getCurrentVaultSession();
      setSession(current);
      if (current) {
        setPersistEncrypted(current.persistEncrypted);
      }
      setPersistedMeta(getPersistedVaultMetadata());
    };
    sync();
    const unsubscribe = subscribeVaultSession(sync);
    return () => {
      active = false;
      unsubscribe();
    };
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

  const handlePasskeySignIn = async () => {
    setPasskeyBusy(true);
    setStatusBanner(null);
    try {
      const unlocked = await signInWithPasskey();
      setStatusBanner({
        kind: "ok",
        text: `Signed in to account ${unlocked.vaultId} on your device.`,
      });
      router.push(nextPath);
    } catch (err) {
      if (err instanceof PasskeyPrfUnsupportedError) {
        setPrfSupported(false);
        setStatusBanner({
          kind: "info",
          text: "Your browser or device does not support fingerprint or face sign-in for private keys yet. Use the 6 secret words below instead.",
        });
      } else {
        setStatusBanner({
          kind: "err",
          text:
            err instanceof Error
              ? err.message
              : "Could not sign in with your device. Try again or use 6 secret words below.",
        });
      }
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handlePasskeyCreate = async () => {
    setPasskeyBusy(true);
    setStatusBanner(null);
    try {
      const created = await createPasskeyAccount();
      setStatusBanner({
        kind: "ok",
        text: `Created your deRoute account (${created.vaultId}) on this device.`,
      });
      router.push(nextPath);
    } catch (err) {
      if (err instanceof PasskeyPrfUnsupportedError) {
        setPrfSupported(false);
        setStatusBanner({
          kind: "info",
          text: "Your browser or device does not support fingerprint or face sign-in for private keys yet. Use the 6 secret words below instead.",
        });
      } else {
        setStatusBanner({
          kind: "err",
          text:
            err instanceof Error
              ? err.message
              : "Could not create a passkey on this device. Try again or use 6 secret words below.",
        });
      }
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handleGenerateBurner = () => {
    const next = generatePassphrase(6);
    setBurnerPassphrase(next);
    setCopiedBurner(false);
    setSavedConfirmed(false);
    setStatusBanner({
      kind: "info",
      text: "Created 6 fresh secret words in your browser. Nothing was sent over the network.",
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

  const handleCreateWithWords = () => {
    if (!savedConfirmed) {
      setStatusBanner({
        kind: "err",
        text: "Confirm that you saved your 6 words before creating your account.",
      });
      return;
    }
    if (!burnerPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Generate 6 secret words first.",
      });
      return;
    }
    try {
      const unlocked = unlockVaultWithPassphrase(
        burnerPassphrase,
        persistEncrypted,
      );
      setStatusBanner({
        kind: "ok",
        text: `Created account ${unlocked.vaultId} on your device.`,
      });
      router.push(nextPath);
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not create account from your 6 secret words.",
      });
    }
  };

  const handleUnlockExisting = (e: React.FormEvent) => {
    e.preventDefault();
    if (!existingPassphrase.trim()) {
      setStatusBanner({
        kind: "err",
        text: "Enter your 6 secret words first.",
      });
      return;
    }
    try {
      const unlocked = unlockVaultWithPassphrase(
        existingPassphrase,
        persistEncrypted,
      );
      setStatusBanner({
        kind: "ok",
        text: `Signed in to account ${unlocked.vaultId} on your device.`,
      });
      router.push(nextPath);
    } catch (err) {
      setStatusBanner({
        kind: "err",
        text:
          err instanceof Error
            ? err.message
            : "Could not unlock your account with those words.",
      });
    }
  };

  const handleSignOut = () => {
    lockVault();
    setStatusBanner({
      kind: "info",
      text: "Signed out and cleared your active keys from browser memory.",
    });
  };

  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto w-full max-w-4xl flex-1 space-y-8 px-4 py-10 sm:px-6"
    >
      {/* Hero */}
      <InkReveal>
        <section
          aria-labelledby="login-heading"
          className="space-y-3 border-b border-rule pb-6"
        >
          <div className="ep-label">Sign in</div>
          <h1 id="login-heading" className="ep-display text-3xl sm:text-4xl">
            Sign in to deRoute
          </h1>
          <p className="text-lg font-medium text-ink">
            No email. No password. We never learn who you are.
          </p>
          <p className="max-w-[65ch] text-sm leading-relaxed text-ink-2">
            Your account key is created and kept on your own device. Nothing about who you are is ever sent to our servers.
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

      {/* Active Account Banner (when already signed in) */}
        {session && (
          <section
            aria-label="Signed in account"
            className="ep-card space-y-4 p-5 sm:p-6"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="ep-label">Signed in</div>
                <div className="font-mono text-sm font-semibold text-ink">
                  Account {session.vaultId}
                </div>
                <p className="text-xs text-ink-2">
                  Signed in with:{" "}
                  <strong className="text-ink">
                    {session.authMethod === "passkey"
                      ? "Fingerprint, face or device"
                      : "6 secret words"}
                  </strong>
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <InkButton variant="accent" href={nextPath}>
                  Continue
                </InkButton>
                <InkButton variant="ghost" href="/account">
                  Account settings
                </InkButton>
                <InkButton
                  variant="ghost"
                  onClick={handleSignOut}
                >
                  Sign out
                </InkButton>
              </div>
            </div>
          </section>
        )}

        {/* Primary Option: Passkey */}
        <section
          aria-labelledby="passkey-heading"
          className="ep-card space-y-5 p-6 sm:p-7"
        >
          <div className="space-y-2">
            <div className="ep-label">Fastest way in</div>
            <h2 id="passkey-heading" className="ep-display text-2xl sm:text-3xl">
              Use your fingerprint, face or device
            </h2>
            <p className="max-w-[65ch] text-sm leading-relaxed text-ink-2">
              Your phone or computer unlocks your private account right here on your device. No typing needed and nothing is stored on our servers.
            </p>
          </div>

          {prfSupported === false && (
            <div
              role="note"
              data-testid="prf-unsupported-notice"
              className="rounded border border-rule bg-paper-2 p-4 text-xs leading-relaxed text-ink-2"
            >
              <strong className="font-medium text-ink">
                Fingerprint or face sign-in is not available in this browser yet.
              </strong>{" "}
              Your browser or device does not support private encryption keys for passkeys. Use the 6 secret words below to create or open your account instead.
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <InkButton
              variant="accent"
              onClick={() => void handlePasskeySignIn()}
              disabled={passkeyBusy || prfSupported === false}
            >
              Sign in with your fingerprint, face or device
            </InkButton>
            <InkButton
              variant="primary"
              onClick={() => void handlePasskeyCreate()}
              disabled={passkeyBusy || prfSupported === false}
            >
              Create a deRoute account
            </InkButton>
          </div>
        </section>

        {/* Fallback / Alternative: 6 Secret Words */}
        <section
          aria-labelledby="secret-words-heading"
          className="space-y-4"
        >
          <div className="space-y-1">
            <div className="ep-label">
              {prfSupported === false ? "Recommended on this browser" : "Works on every browser"}
            </div>
            <h2 id="secret-words-heading" className="ep-display text-2xl">
              {prfSupported === false
                ? "Sign in with 6 secret words"
                : "Or use 6 secret words"}
            </h2>
            <p className="max-w-[65ch] text-xs leading-relaxed text-ink-2">
              Write down 6 random words or save them in your password manager. Those 6 words unlock the exact same account on any browser.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            {/* Create with 6 secret words */}
            <div
              aria-labelledby="create-vault-heading"
              className="ep-card flex flex-col justify-between space-y-5 p-5"
            >
              <div className="space-y-3">
                <div className="ep-label">New 6-word account</div>
                <h3 id="create-vault-heading" className="ep-display text-xl">
                  Create with 6 secret words
                </h3>
                <p className="text-xs leading-relaxed text-ink-2">
                  Copy these 6 random words and keep them somewhere safe. They create your private keys inside your browser.
                </p>

                <div className="ep-inset space-y-2 p-3.5">
                  <div className="ep-label">Your 6 secret words (created on your device)</div>
                  <div
                    data-testid="generated-passphrase"
                    className="min-h-[1.25rem] select-all font-mono text-sm font-semibold text-ink"
                  >
                    {mounted ? burnerPassphrase : "Creating in browser..."}
                  </div>
                  {burnerPreview && (
                    <div className="border-t border-rule pt-2 font-mono text-[11px] text-ink-3">
                      Account ID: <span className="text-ink">{burnerPreview.vaultId}</span>
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
                    Get 6 new words
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

                <InkButton
                  variant="primary"
                  onClick={handleCreateWithWords}
                  disabled={!savedConfirmed || !mounted}
                  className="w-full"
                >
                  Create account with 6 words
                </InkButton>
              </div>
            </div>

            {/* Sign in with existing 6 secret words */}
            <div
              aria-labelledby="unlock-vault-heading"
              className="ep-card flex flex-col justify-between space-y-5 p-5"
            >
              <form
                onSubmit={handleUnlockExisting}
                className="flex h-full flex-col justify-between space-y-5"
              >
                <div className="space-y-3">
                  <div className="ep-label">Existing 6-word account</div>
                  <h3 id="unlock-vault-heading" className="ep-display text-xl">
                    Sign in with 6 secret words
                  </h3>
                  <p className="text-xs leading-relaxed text-ink-2">
                    Enter your 6 secret words to open your account. The same words always open the same account.
                  </p>

                  <div>
                    <label
                      htmlFor="existing-passphrase-input"
                      className="mb-1.5 block font-mono text-xs text-ink-2"
                    >
                      Your 6 secret words
                    </label>
                    <input
                      id="existing-passphrase-input"
                      type="text"
                      autoComplete="off"
                      spellCheck={false}
                      value={existingPassphrase}
                      onChange={(e) => setExistingPassphrase(e.target.value)}
                      placeholder="word1 word2 word3 word4 word5 word6"
                      className="ep-input font-mono"
                    />
                  </div>

                  <div className="ep-inset p-3 font-mono text-[11px] text-ink-2">
                    {existingPreview ? (
                      <div>
                        Account ID:{" "}
                        <span className="font-semibold text-ink">
                          {existingPreview.vaultId}
                        </span>
                      </div>
                    ) : persistedMeta.exists ? (
                      <span>
                        Locked account {persistedMeta.vaultId} is saved on this device.
                      </span>
                    ) : (
                      <span>
                        Type your 6 words above to preview your account ID.
                      </span>
                    )}
                  </div>

                  <label className="flex cursor-pointer items-center gap-2 text-xs text-ink-2">
                    <input
                      type="checkbox"
                      checked={persistEncrypted}
                      onChange={(e) => setPersistEncrypted(e.target.checked)}
                      className="h-4 w-4 accent-ink"
                    />
                    <span>Keep my locked settings saved on this device</span>
                  </label>
                </div>

                <div className="border-t border-rule pt-4">
                  <InkButton type="submit" variant="primary" className="w-full">
                    Sign in with 6 words
                  </InkButton>
                </div>
              </form>
            </div>
          </div>
        </section>

        {/* Account Settings shortcut + Technical Details */}
        <section className="space-y-4 border-t border-rule pt-6">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-2">
            <span>
              Want to manage words to always hide, export a backup, or sign out?
            </span>
            <Link href="/account" className="ep-link font-medium">
              Go to Account settings
            </Link>
          </div>

          <TechDetails label="Show technical details">
            <div className="space-y-2.5">
              <p>
                <strong className="text-ink">Client-side WebAuthn PRF passkeys:</strong>{" "}
                When you create or sign in with a passkey, your browser calls WebAuthn with the{" "}
                <code className="font-mono text-ink">prf</code> extension (
                <code className="font-mono text-ink">attestation: &quot;none&quot;</code>,{" "}
                <code className="font-mono text-ink">userVerification: &quot;required&quot;</code>,{" "}
                <code className="font-mono text-ink">residentKey: &quot;required&quot;</code>, a random 32-byte user handle, generic display name{" "}
                <code className="font-mono text-ink">&quot;deRoute account&quot;</code>, and{" "}
                <code className="font-mono text-ink">rpId</code> bound to the current hostname). The 32-byte PRF output is stretched in your browser with HKDF-SHA-384 into an Ed25519 signing keypair, an X25519 keypair, and an AES-256-GCM vault key. No credential ID, public key, or challenge is ever sent to a server.
              </p>
              <p>
                <strong className="text-ink">Passkey sync caveat:</strong>{" "}
                Apple iCloud Keychain and Google Password Manager sync passkeys end-to-end encrypted, so they cannot read your PRF secret or your messages, but they can see that a passkey exists for this site. If you do not want your device vendor to know you hold a passkey for this domain, use the 6 secret words option instead.
              </p>
              <p>
                <strong className="text-ink">6 secret words fallback:</strong>{" "}
                Draws 6 words from the 2,048-word BIP39 English wordlist (~66 bits of entropy) using{" "}
                <code className="font-mono text-ink">crypto.getRandomValues</code>, stretches them with 210,000 rounds of PBKDF2-HMAC-SHA-512, and derives the same Ed25519, X25519, and AES-256-GCM subkeys via HKDF-SHA-384.
              </p>
            </div>
          </TechDetails>
        </section>
    </main>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden bg-paper text-ink">
      <SpecimenHeader activePath="/login" />
      <Suspense
        fallback={
          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto w-full max-w-4xl flex-1 px-4 py-10 sm:px-6"
          >
            <div className="ep-card p-6 text-sm text-ink-2">
              Loading sign-in...
            </div>
          </main>
        }
      >
        <LoginContent />
      </Suspense>
      <SpecimenFooter />
    </div>
  );
}
