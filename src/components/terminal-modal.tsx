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
          "name": "Kimi K3 (Intel TDX + 8x B200/H200 CC)"
        },
        "glm-5-3": {
          "name": "GLM-5.3 (AMD SEV-SNP + 8x H200 CC)"
        },
        "deepseek-v4-1-flash": {
          "name": "DeepSeek V4.1 Flash (Confidential MoE)"
        },
        "gpt-oss-120b": {
          "name": "GPT-OSS 120B (Confidential TEE)"
        },
        "llama3-3-70b": {
          "name": "Llama 3.3 70B Instruct (Confidential TEE)"
        }
      }
    }
  },
  "model": "drouter-confidential/${defaultModel}"
}`;

  const opencodeRemoteConfig = `// Or point directly at the hosted dRouter OpenAI-compatible gateway:
// "baseURL": "${cleanBase}/api/v1"`;

  const proxySnippet = `# Start the local Zero-Trust CLI Proxy on port 4141
# 100% of AMD SEV-SNP / Intel TDX attestation verification, PII scrubbing,
# and RFC 9180 HPKE encryption happen locally on your machine before transit:
node scripts/drouter-cli.mjs proxy --port 4141

# Point any OpenAI-compatible coding agent at http://127.0.0.1:4141/v1`;

  const envSnippet = `# Local Zero-Trust Proxy (recommended — verifies silicon & encrypts on your Mac/Linux box)
export OPENAI_BASE_URL="http://127.0.0.1:4141/v1"
export OPENAI_API_KEY="drouter-local-enclave"

# Or direct dRouter Gateway endpoint (${cleanBase}/api/v1)
export OPENAI_BASE_URL="${cleanBase}/api/v1"
export OPENAI_API_KEY="drouter-attested"

# Run Claude Code / Codex / Aider / Cursor with attested confidential models:
# Model IDs: kimi-k3 | glm-5-3 | deepseek-v4-1-flash | gpt-oss-120b | llama3-3-70b`;

  const curlSnippet = `# 1. Verify all 7 hardware & cryptographic checks from your terminal:
node scripts/drouter-cli.mjs verify

# 2. Ask a confidential model from the CLI with local PII scrubbing & attestation:
node scripts/drouter-cli.mjs ask "Audit this Solidity vault for reentrancy" --model ${defaultModel}

# 3. Direct OpenAI-compatible curl (inspects X-DRouter-Attested & X-DRouter-Enclave-Fingerprint headers):
curl -i -X POST "${cleanBase}/api/v1/chat/completions" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer drouter-attested" \\
  -d '{
    "model": "${defaultModel}",
    "messages": [
      { "role": "user", "content": "Confirm you are running inside an attested confidential GPU bubble." }
    ]
  }'

# Response headers & body include:
# X-DRouter-Attested: true
# X-DRouter-Enclave-Fingerprint: 859dc53c31d4...
# "drouter_attestation": { "verified": true, "checksPassed": 7, ... }`;

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
    { id: "proxy", label: "2. Local Zero-Trust CLI Proxy" },
    { id: "env", label: "3. Claude Code / Codex / Cursor" },
    { id: "curl", label: "4. curl & Terminal CLI" },
    { id: "sdk", label: "5. Python / TypeScript SDK" },
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
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-3 sm:p-4 backdrop-blur-md"
    >
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-950 text-zinc-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 border-b border-zinc-800 bg-zinc-900/80 px-5 py-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-emerald-400">⌘</span>
              <h2
                id="terminal-modal-title"
                className="text-base sm:text-lg font-semibold text-white"
              >
                Use dRouter in Your Terminal, OpenCode, or IDE Harness
              </h2>
            </div>
            <p className="mt-0.5 text-xs text-zinc-400">
              Skip the web chatbox—route OpenCode, Claude Code, Codex, Cursor,
              or custom scripts through attested confidential GPUs.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 hover:text-white transition"
          >
            Close ✕
          </button>
        </div>

        {/* Tabs */}
        <div className="flex overflow-x-auto border-b border-zinc-800 bg-zinc-900/40 px-4 pt-2 gap-1.5">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              className={`whitespace-nowrap rounded-t-lg border-b-2 px-3.5 py-2 text-xs font-medium transition ${
                activeTab === t.id
                  ? "border-emerald-400 bg-zinc-900 text-emerald-300"
                  : "border-transparent text-zinc-400 hover:bg-zinc-900/50 hover:text-zinc-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {activeTab === "proxy" && (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5 text-xs text-zinc-200 leading-relaxed">
              <strong className="text-emerald-300">
                Recommended for Autonomous Coding Agents:
              </strong>{" "}
              Running{" "}
              <code className="font-mono text-emerald-300">
                node scripts/drouter-cli.mjs proxy --port 4141
              </code>{" "}
              performs AMD SEV-SNP / Intel TDX hardware verification, reversible
              PII scrubbing, and RFC 9180 HPKE encryption 100% locally on your
              machine so neither your IDE nor any relay ever transmits
              unverified plaintext.
            </div>
          )}

          <div className="relative rounded-xl border border-zinc-800 bg-zinc-900/80">
            <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
              <span className="font-mono text-[11px] text-zinc-400">
                Models: kimi-k3 · glm-5-3 · deepseek-v4-1-flash · gpt-oss-120b ·
                llama3-3-70b
              </span>
              <button
                type="button"
                onClick={() => handleCopy(activeTab, activeCode)}
                className="rounded-md border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/25 transition"
              >
                {copied === activeTab ? "Copied ✓" : "Copy Snippet"}
              </button>
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-zinc-200">
              <code>{activeCode}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
