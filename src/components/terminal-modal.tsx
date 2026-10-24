"use client";

import React, { useState } from "react";
import {
  buildTerminalSnippets,
  PRODUCTION_BASE_URL,
  type TerminalTabId,
} from "@/components/inspector/terminal-snippets";

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

  if (!open) return null;

  const snippets = buildTerminalSnippets(baseUrl, defaultModel);

  const handleCopy = (key: string, text: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 1800);
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
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="terminal-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-2 sm:p-4"
    >
      <div className="ep-card flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden bg-paper text-ink">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-3 py-3 sm:px-5 sm:py-4">
          <div className="min-w-0">
            <div className="ep-label">CLI &amp; IDE Integration</div>
            <h2
              id="terminal-modal-title"
              className="ep-display mt-0.5 text-lg sm:text-2xl"
            >
              Use dRouter from Terminal, OpenCode, or Cursor
            </h2>
            <p className="mt-0.5 text-xs text-ink-2">
              Route your coding agent or scripts through attested enclaves at{" "}
              <code className="font-mono text-ink">
                https://drouter-demo.vercel.app/v1
              </code>{" "}
              or via the local zero-trust HPKE CLI proxy.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="ep-btn-ghost shrink-0 px-3 py-1 text-xs"
          >
            Close
          </button>
        </div>

        <div className="flex gap-1 overflow-x-auto border-b border-rule bg-paper px-2 pt-2 sm:px-4">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              className={`whitespace-nowrap border-b-2 px-2.5 py-2 text-xs font-medium transition-colors sm:px-3 ${
                activeTab === t.id
                  ? "border-ink bg-paper-2 text-ink"
                  : "border-transparent text-ink-3 hover:text-ink"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-3 sm:p-5">
          <div className="ep-inset p-3.5 text-xs text-ink-2 space-y-1.5">
            <div>
              <strong className="font-medium text-ink">
                API key &amp; blind credits:
              </strong>{" "}
              OpenAI SDKs require a non-empty <code className="font-mono text-ink">apiKey</code> string, and dRouter accepts any value (for example <code className="font-mono text-ink">&quot;any-value&quot;</code>). Requests without an <code className="font-mono text-ink">x-drouter-credit</code> header use the per-IP free tier; attaching an optional <code className="font-mono text-ink">x-drouter-credit</code> blind-signed token spends an unlinkable credit instead.
            </div>
            <div>
              <strong className="font-medium text-ink">
                No npm CLI package:
              </strong>{" "}
              The zero-trust CLI runs directly from the repository (<code className="font-mono text-ink">git clone https://github.com/thepigdestroyer/drouter &amp;&amp; cd drouter &amp;&amp; npm ci &amp;&amp; node scripts/drouter-cli.mjs verify</code>). It verifies the AMD SEV-SNP hardware quote, scrubs personal identifiers locally, and seals prompts with RFC 9180 HPKE on your machine.
            </div>
          </div>

          <div className="ep-inset overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule bg-paper px-3 py-2 sm:px-4">
              <span className="font-mono text-[11px] text-ink-3 break-words">
                Models: kimi-k3 · glm-5-3 · deepseek-v4-1-flash · gpt-oss-120b · llama3-3-70b · sim-echo-1
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
        </div>
      </div>
    </div>
  );
}
