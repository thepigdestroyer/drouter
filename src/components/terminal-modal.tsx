"use client";

import React, { useState } from "react";

export interface TerminalModalProps {
  open: boolean;
  onClose: () => void;
  baseUrl?: string;
  defaultModel?: string;
}

type TerminalTabId = "opencode" | "proxy" | "env" | "curl" | "sdk";

export function TerminalModal({
  open,
  onClose,
  baseUrl = "http://localhost:3000",
  defaultModel = "kimi-k3",
}: TerminalModalProps) {
  const [activeTab, setActiveTab] = useState<TerminalTabId>("opencode");
  const [copied, setCopied] = useState<string | null>(null);

  if (!open) return null;

  const cleanBase = baseUrl.replace(/\/$/, "");

  const handleCopy = (key: string, text: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 1800);
  };

  const opencodeConfig = `{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "drouter-confidential": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "dRouter Confidential TEE (Attested)",
      "options": {
        "baseURL": "http://127.0.0.1:4141/v1",
        "apiKey": "drouter-blind-credit-local"
      },
      "models": {
        "kimi-k3": {
          "name": "Kimi K3 (Intel TDX + NVIDIA CC GPUs, 262k context)"
        },
        "glm-5-3": {
          "name": "GLM-5.3 (AMD SEV-SNP + NVIDIA CC GPUs)"
        },
        "deepseek-v4-1-flash": {
          "name": "DeepSeek V4.1 Flash (Intel TDX + NVIDIA CC GPUs)"
        },
        "gpt-oss-120b": {
          "name": "GPT-OSS 120B (Intel TDX + NVIDIA CC GPU)"
        },
        "llama3-3-70b": {
          "name": "Llama 3.3 70B Instruct (Intel TDX + NVIDIA CC GPU)"
        }
      }
    }
  },
  "model": "drouter-confidential/${defaultModel}"
}`;

  const opencodeRemoteConfig = `// Or point directly at the hosted dRouter OpenAI-compatible gateway:
// "baseURL": "${cleanBase}/api/v1"`;

  const proxySnippet = `# Start the local zero-trust CLI proxy on port 4141.
# Hardware attestation verification, local PII scrubbing,
# and RFC 9180 HPKE encryption run on your machine before transit:
node scripts/drouter-cli.mjs proxy --port 4141

# Point any OpenAI-compatible coding agent at http://127.0.0.1:4141/v1`;

  const envSnippet = `# Local zero-trust proxy (recommended: verifies hardware & encrypts on your machine)
export OPENAI_BASE_URL="http://127.0.0.1:4141/v1"
export OPENAI_API_KEY="drouter-local-enclave"

# Or direct dRouter gateway endpoint (${cleanBase}/api/v1)
export OPENAI_BASE_URL="${cleanBase}/api/v1"
export OPENAI_API_KEY="drouter-attested"

# Model IDs: kimi-k3 | glm-5-3 | deepseek-v4-1-flash | gpt-oss-120b | llama3-3-70b`;

  const curlSnippet = `# 1. Verify all 7 hardware & cryptographic checks from your terminal:
node scripts/drouter-cli.mjs verify

# 2. Ask a confidential model from the CLI with local PII scrubbing & attestation:
node scripts/drouter-cli.mjs ask "Audit this Solidity vault for reentrancy" --model ${defaultModel}

# 3. Direct OpenAI-compatible curl:
curl -i -X POST "${cleanBase}/api/v1/chat/completions" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer drouter-attested" \\
  -d '{
    "model": "${defaultModel}",
    "messages": [
      { "role": "user", "content": "Reply with one short sentence." }
    ]
  }'`;

  const sdkSnippet = `// TypeScript / Node.js (OpenAI SDK)
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:4141/v1", // or "${cleanBase}/api/v1"
  apiKey: "drouter-attested",
});

const response = await client.chat.completions.create({
  model: "${defaultModel}",
  messages: [{ role: "user", content: "Summarize our private architecture." }],
});
console.log(response.choices[0]?.message?.content);

# ---------------------------------------------------------
# Python (openai >= 1.0)
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:4141/v1",  # or "${cleanBase}/api/v1"
    api_key="drouter-attested",
)

res = client.chat.completions.create(
    model="${defaultModel}",
    messages=[{"role": "user", "content": "Summarize our private architecture."}],
)
print(res.choices[0].message.content)`;

  const tabs: Array<{ id: TerminalTabId; label: string }> = [
    { id: "opencode", label: "1. OpenCode (opencode.json)" },
    { id: "proxy", label: "2. Local CLI Proxy" },
    { id: "env", label: "3. Claude Code / Cursor" },
    { id: "curl", label: "4. curl & CLI" },
    { id: "sdk", label: "5. Python / TS SDK" },
  ];

  const activeCode =
    activeTab === "opencode"
      ? `${opencodeConfig}\n\n${opencodeRemoteConfig}`
      : activeTab === "proxy"
        ? proxySnippet
        : activeTab === "env"
          ? envSnippet
          : activeTab === "curl"
            ? curlSnippet
            : sdkSnippet;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="terminal-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-3 sm:p-4"
    >
      <div className="ep-card flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden bg-paper text-ink">
        <div className="flex items-center justify-between gap-3 border-b border-rule bg-paper-2 px-5 py-4">
          <div>
            <div className="ep-label">CLI &amp; IDE Integration</div>
            <h2
              id="terminal-modal-title"
              className="ep-display mt-0.5 text-xl sm:text-2xl"
            >
              Use dRouter from Terminal, OpenCode, or Cursor
            </h2>
            <p className="mt-0.5 text-xs text-ink-2">
              Route your coding agent or terminal scripts through attested confidential enclaves.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="ep-btn-ghost px-3 py-1 text-xs"
          >
            Close
          </button>
        </div>

        <div className="flex gap-1 overflow-x-auto border-b border-rule bg-paper px-4 pt-2">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              className={`whitespace-nowrap border-b-2 px-3 py-2 text-xs font-medium transition-colors ${
                activeTab === t.id
                  ? "border-ink bg-paper-2 text-ink"
                  : "border-transparent text-ink-3 hover:text-ink"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {activeTab === "proxy" && (
            <div className="ep-inset p-3.5 text-xs text-ink-2">
              <strong className="font-medium text-ink">
                Recommended for coding agents:
              </strong>{" "}
              Running{" "}
              <code className="font-mono text-ink">
                node scripts/drouter-cli.mjs proxy --port 4141
              </code>{" "}
              verifies the hardware quote, scrubs personal identifiers, and seals prompts with HPKE locally on your machine.
            </div>
          )}

          <div className="ep-inset overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule bg-paper px-4 py-2">
              <span className="font-mono text-[11px] text-ink-3">
                Models: kimi-k3 · glm-5-3 · deepseek-v4-1-flash · gpt-oss-120b · llama3-3-70b
              </span>
              <button
                type="button"
                onClick={() => handleCopy(activeTab, activeCode)}
                className="ep-btn-ghost px-2.5 py-1 text-xs"
              >
                {copied === activeTab ? "Copied" : "Copy snippet"}
              </button>
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-ink">
              <code>{activeCode}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
