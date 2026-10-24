"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  buildTerminalSnippets,
  DEFAULT_LIVE_MODEL_IDS,
  PRODUCTION_BASE_URL,
  type TerminalTabId,
} from "@/components/inspector/terminal-snippets";
import {
  InkModal,
  TERMINAL_MODAL_PLAIN_SUMMARY,
} from "@/components/modal/ink-modal";

export interface TerminalModalProps {
  open: boolean;
  onClose: () => void;
  baseUrl?: string;
  defaultModel?: string;
}

export function TerminalModal({
  open,
  onClose,
  baseUrl = PRODUCTION_BASE_URL,
  defaultModel = "kimi-k3",
}: TerminalModalProps) {
  const [activeTab, setActiveTab] = useState<TerminalTabId>("opencode");
  const [copied, setCopied] = useState<string | null>(null);
  const [liveModelIds, setLiveModelIds] = useState<readonly string[]>(
    DEFAULT_LIVE_MODEL_IDS,
  );
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!open || typeof fetch !== "function") return;
    let cancelled = false;
    fetch("/v1/models")
      .then(async (res) =>
        res.ok
          ? ((await res.json()) as { data?: Array<{ id?: string }> })
          : null,
      )
      .then((payload) => {
        if (cancelled) return;
        const ids = (payload?.data ?? [])
          .map((m) => (typeof m?.id === "string" ? m.id.trim() : ""))
          .filter((id) => id.length > 0 && !id.toLowerCase().startsWith("sim-"));
        if (ids.length > 0) {
          setLiveModelIds(ids);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [open]);

  if (!open) return null;

  const snippets = buildTerminalSnippets(baseUrl, defaultModel, liveModelIds);

  const handleCopy = (key: string, text: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopied(key);
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopied(null);
      copyTimerRef.current = null;
    }, 1800);
  };

  const tabs: Array<{ id: TerminalTabId; label: string }> = [
    { id: "opencode", label: "1. OpenCode (opencode.json)" },
    { id: "proxy", label: "2. Local CLI Proxy" },
    { id: "env", label: "3. Claude Code / Cursor" },
    { id: "curl", label: "4. curl & CLI" },
    { id: "sdk", label: "5. Python / TS SDK" },
  ];

  const activeCode =
    activeTab === "opencode"
      ? `${snippets.opencodeConfig}\n\n${snippets.opencodeRemoteComment}`
      : activeTab === "proxy"
        ? snippets.proxySnippet
        : activeTab === "env"
          ? snippets.envSnippet
          : activeTab === "curl"
            ? snippets.curlSnippet
            : snippets.sdkSnippet;

  return (
    <InkModal<TerminalTabId>
      open={open}
      onClose={onClose}
      titleId="terminal-modal-title"
      eyebrow="CLI & IDE Integration"
      title="Use deRoute from Terminal, OpenCode, or Cursor"
      subtitle={
        <>
          Route your coding agent or scripts through sealed computers at{" "}
          <code className="font-mono text-ink">
            https://drouter-demo.vercel.app/v1
          </code>{" "}
          or via the local zero-trust HPKE CLI proxy.
        </>
      }
      tabs={tabs}
      activeTab={activeTab}
      onSelectTab={setActiveTab}
      tabListLabel="Terminal integration options"
      maxWidthClass="max-w-4xl"
      summaryText={TERMINAL_MODAL_PLAIN_SUMMARY}
    >
      <div className="ep-inset space-y-2 p-3.5 text-xs text-ink-2 sm:p-4">
        <div>
          <strong className="font-medium text-ink">
            API key &amp; anonymous tokens:
          </strong>{" "}
          OpenAI SDKs require a non-empty{" "}
          <code className="font-mono text-ink">apiKey</code> string, and deRoute
          accepts any value (for example{" "}
          <code className="font-mono text-ink">&quot;any-value&quot;</code>).
          Requests without an{" "}
          <code className="font-mono text-ink">x-drouter-credit</code> header
          use the per-IP free tier; attaching an optional{" "}
          <code className="font-mono text-ink">x-drouter-credit</code>{" "}
          blind-signed token spends an anonymous token instead.
        </div>
        <div>
          <strong className="font-medium text-ink">
            No npm CLI package:
          </strong>{" "}
          The zero-trust CLI runs directly from the repository (
          <code className="font-mono text-ink">
            git clone https://github.com/thepigdestroyer/drouter &amp;&amp; cd
            drouter &amp;&amp; npm ci &amp;&amp; node scripts/drouter-cli.mjs
            verify
          </code>
          ). It checks the AMD SEV-SNP hardware seal, hides personal details
          locally, and locks prompts with RFC 9180 HPKE on your machine.
        </div>
      </div>

      <div className="ep-inset overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule bg-paper px-3 py-2 sm:px-4">
          <span className="font-mono text-[11px] text-ink-3 break-words">
            Models: {liveModelIds.join(" · ")}
          </span>
          <button
            type="button"
            onClick={() => handleCopy(activeTab, activeCode)}
            className="ep-btn-ghost shrink-0 px-2.5 py-1 text-xs"
          >
            {copied === activeTab ? "Copied" : "Copy snippet"}
          </button>
        </div>
        <pre className="overflow-x-auto p-3 font-mono text-xs leading-relaxed text-ink sm:p-4">
          <code>{activeCode}</code>
        </pre>
      </div>
    </InkModal>
  );
}
