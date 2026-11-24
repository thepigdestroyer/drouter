"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { AuthGate } from "@/components/auth/auth-gate";
import { InkButton } from "@/components/ink/ink-button";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  getCurrentVaultSession,
  subscribeVaultSession,
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
const CODING_TOOL_TABS: ReadonlyArray<{ id: CodingToolId; label: string }> = [
  { id: "opencode", label: "OpenCode" },
  { id: "cline", label: "Cline / Roo Code" },
  { id: "continue", label: "Continue" },
  { id: "aider", label: "Aider" },
  { id: "typescript", label: "TypeScript SDK" },
  { id: "python", label: "Python SDK" },
  { id: "curl", label: "curl" },
];

const KEY_SIZE_OPTIONS = [1, 5] as const;

export default function ApiKeysPage() {
  const [recover, setRecover] = useState(false);
  const [statusBanner, setStatusBanner] = useState<{
    kind: "err" | "info" | "ok";
    text: string;
  } | null>(null);
  // Coding tool access key & snippet state (all storage/network reads in effects or click handlers)
  const [walletBalance, setWalletBalance] = useState<number>(0);
  const [walletTokenCount, setWalletTokenCount] = useState<number>(0);
  const [selectedCreditsCount, setSelectedCreditsCount] = useState<1 | 5>(5);
  const [createdKeyInfo, setCreatedKeyInfo] = useState<{
    key: string;
    creditsMoved: number;
    tokenCount: number;
    uncopied: boolean;
  } | null>(null);
  const [mintingFree, setMintingFree] = useState<boolean>(false);
  const [showBuyPanel, setShowBuyPanel] = useState<boolean>(false);
  const [buyDenom, setBuyDenom] = useState<5 | 20>(5);
  const [activeInvoice, setActiveInvoice] =
    useState<CreditInvoiceClientHandle | null>(null);
  const [invoiceBusy, setInvoiceBusy] = useState<boolean>(false);
  const [codingMode, setCodingMode] = useState<CodingToolMode>("hosted");
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
      const pending = getCurrentVaultSession() ? readPendingAccessKey() : null;
      if (pending) {
        setCreatedKeyInfo({
          key: pending.key,
          creditsMoved: pending.creditsMoved,
          tokenCount: pending.tokenCount,
          uncopied: true,
        });
      } else setCreatedKeyInfo(null);
    };
    const sync = () => {
      syncWallet();
      setStatusBanner(null);
      setRecover(false);
      setActiveInvoice(null);
    };
    const handleStorage = (event: StorageEvent) => {
      if (
        !event.key ||
        event.key === CREDITS_STORAGE_KEY ||
        event.key === PENDING_ACCESS_KEY_STORAGE_KEY
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

  const triggerCopyFeedback = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      setStatusBanner({
        kind: "err",
        text: "Clipboard unavailable. Select and copy the value manually.",
      });
      return;
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
      const moved = moveCreditsToAccessKey(selectedCreditsCount, {
        persistPending: recover,
      });
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
    setCreatedKeyInfo(null);
  };

  const codingSnippets = useMemo(
    () =>
      buildCodingToolSnippets({
        mode: codingMode,
        modelIds: liveModelIds,
      }),
    [codingMode, liveModelIds],
  );

  const walletIsShort = walletBalance < selectedCreditsCount;
  return (
    <div className="min-h-screen flex flex-col text-ink">
      <SpecimenHeader activePath="/api-keys" />
      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto w-full max-w-4xl flex-1 space-y-8 px-4 py-10 sm:px-6"
      >
        <header className="space-y-3 border-b border-rule pb-5">
          <p className="ep-label">Developer access / Chat Completions</p>
          <h1 className="ep-display text-3xl sm:text-5xl">Get an API key</h1>
          <p className="max-w-[65ch] text-ink-2">
            Use deRoute in your coding agent. Sign in, add credits, then move a
            few tokens into a key. Only the key goes in your client; your
            passkey or six secret words stay here.
          </p>
        </header>
        <section
          className="ep-card space-y-3 p-5"
          aria-label="Provider settings"
        >
          <h2 className="ep-display text-2xl">
            OpenAI-compatible provider settings
          </h2>
          {[
            ["Base URL", codingSnippets.baseUrl],
            ["Model ID", liveModelIds[0]],
          ].map(([label, value]) => (
            <div key={label} className="flex flex-wrap items-center gap-3">
              <strong>{label}</strong>
              <code className="break-all">{value}</code>
              <button
                className="ep-btn-ghost text-xs"
                onClick={() => triggerCopyFeedback(label, value)}
              >
                {copiedId === label ? "Copied" : `Copy ${label}`}
              </button>
            </div>
          ))}
          <p className="text-sm">
            Use a client with a custom base URL, model ID and API key field.
            Supports text, SSE streaming and function tools; your client runs
            the tools. No Responses API, images or embeddings.
          </p>
          <p className="text-sm">
            Direct HTTPS sends prompts and replies through deRoute in plaintext
            inside the gateway. For local filtering and encryption to the
            verified enclave, choose the local proxy below.
          </p>
        </section>
        {statusBanner && (
          <p role="status" className="ep-inset p-3 text-sm">
            {statusBanner.text}
          </p>
        )}
        <section className="ep-card space-y-4 p-5" aria-label="Key issuance">
          <AuthGate>
            <div className="ep-label">Wallet · {walletBalance} credits</div>
            {/* Step 1: Create your API key */}
            <div className="space-y-3 border-b border-rule pb-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="ep-label">Step 1</div>
                  <h3 className="font-serif text-lg text-ink">
                    Create your API key
                  </h3>
                </div>
                <span className="font-mono text-xs text-ink-2">
                  {walletTokenCount} anonymous token
                  {walletTokenCount === 1 ? "" : "s"} ready
                </span>
              </div>

              <p className="text-xs text-ink-2">
                Choose how many credits to move out of your browser wallet into
                a portable key. Each request spends one signed token. The free
                allowance adds five one-credit tokens to your encrypted browser
                wallet.
              </p>

              <label className="flex items-start gap-2 text-xs text-ink-2">
                <input
                  type="checkbox"
                  checked={recover}
                  onChange={(e) => setRecover(e.target.checked)}
                />
                Keep an encrypted recovery copy of the API key on this device
                until I confirm I saved it. Otherwise closing this tab loses the
                key.
              </label>
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
                      {count} {count === 1 ? "credit" : "credits"}
                    </button>
                  ))}
                </div>

                <InkButton
                  type="button"
                  variant="primary"
                  disabled={walletIsShort || Boolean(createdKeyInfo)}
                  onClick={handleCreateAccessKey}
                  data-testid="create-access-key-button"
                  className="text-xs"
                >
                  Create API key ({selectedCreditsCount} credits)
                </InkButton>
              </div>

              {walletIsShort && (
                <div
                  data-testid="wallet-short-callout"
                  className="ep-inset flex flex-wrap items-center justify-between gap-3 p-3.5 text-xs"
                >
                  <div className="space-y-0.5 text-ink-2">
                    <strong className="text-ink">
                      Your wallet has {walletBalance} credit
                      {walletBalance === 1 ? "" : "s"}, and you selected{" "}
                      {selectedCreditsCount}.
                    </strong>{" "}
                    Add 5 free credits from the daily allowance or buy more
                    anonymous tokens.
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
                      Buy tokens with Arc Testnet USDC (one-time deposit
                      address)
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
                        Send{" "}
                        <strong className="text-ink">
                          {activeInvoice.amountUsdc} USDC
                        </strong>{" "}
                        to{" "}
                        <code className="break-all text-ink">
                          {activeInvoice.depositAddress}
                        </code>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          disabled={invoiceBusy}
                          onClick={handleClaimInvoice}
                          className="ep-btn text-xs py-1 px-2.5"
                        >
                          {invoiceBusy
                            ? "Checking payment..."
                            : "Claim paid credits"}
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
                        <strong>You have an uncopied access key.</strong> Copy
                        and save it before closing this tab.
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
                      Your new access key ({createdKeyInfo.creditsMoved}{" "}
                      credits, shown once)
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        triggerCopyFeedback("access-key", createdKeyInfo.key);
                      }}
                      data-testid="copy-access-key-button"
                      className="ep-btn text-xs py-1 px-3"
                    >
                      {copiedId === "access-key"
                        ? "Copied key"
                        : "Copy access key"}
                    </button>
                  </div>
                  <pre
                    data-testid="access-key-value"
                    className="overflow-x-auto rounded border border-rule bg-paper p-2.5 font-mono text-xs text-ink select-all"
                  >
                    {createdKeyInfo.key}
                  </pre>
                  <p className="text-xs text-accent font-medium">
                    Save this key now. It is shown once and is never stored on
                    our server. Whoever holds this key can spend its credits.
                  </p>
                </div>
              )}
            </div>
          </AuthGate>
        </section>
        <section className="ep-card space-y-5 p-5" aria-label="Client setup">
          <h2 className="ep-display text-2xl">Connect your coding agent</h2>
          <p className="text-sm">
            For OpenCode v2, merge the snippet into opencode.jsonc. For
            Continue, set the named secret in Continue and merge its model
            entries into config.yaml. For Cline or Roo Code, use the provider
            settings shown. Only give your key to a client you trust.
          </p>
          <p className="text-sm">
            For terminal clients set DEROUTE_API_KEY in the client process
            environment. In Bash, run{" "}
            <code>read -rs DEROUTE_API_KEY; export DEROUTE_API_KEY</code>, then
            paste at the hidden prompt. Keep keys out of chat, shell history and
            version control.
          </p>
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
                  <code className="font-mono text-ink">
                    http://127.0.0.1:4141/v1
                  </code>
                  . Your computer hides personal details, checks the seal on the
                  sealed computer, and locks every message before it leaves your
                  machine.
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
                  Connects straight to our server with no local download. In
                  hosted mode our server filters your words before forwarding
                  them to the sealed computer, so our server sees them. Use the
                  local proxy if you do not want that.
                </p>
              </button>
            </div>

            {codingMode === "private" ? (
              <div className="ep-inset space-y-2 p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-xs text-ink">
                    Start the single-file local proxy on your computer (Node 20
                    or later):
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
                <strong>Privacy note:</strong> In hosted mode our server filters
                your words before forwarding them to the sealed computer, so our
                server sees them. Use the local proxy if you do not want that.
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
                Available models: {liveModelIds.join(" · ")}
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
                  Endpoint:{" "}
                  <strong className="text-ink">{codingSnippets.baseUrl}</strong>
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
          </div>
        </section>
        <section className="ep-inset space-y-2 p-5 text-sm">
          <h2 className="ep-display text-xl">Credits and limits</h2>
          <p>
            Keys are prepaid, cannot be topped up or revoked, and do not unlock
            your account. Anyone with a copy can spend the tokens. A request can
            spend a token even if the upstream model fails. Create a new key
            when the gateway returns 402.
          </p>
          <p>
            The free mint allowance refills at 10 credits per IP per day. Hosted
            inference shares a 40 requests/hour bucket. Rate limits return 429.
            Keep requests under 128 KiB, with at most 64 messages, 64 tools and
            16,384 output tokens. Shorten long agent sessions if you reach a
            limit.
          </p>
          <a className="ep-link" href="/api/v1/models">
            View the current model IDs
          </a>
        </section>
      </main>
      <SpecimenFooter />
    </div>
  );
}
