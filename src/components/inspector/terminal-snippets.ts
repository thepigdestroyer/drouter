import {
  CHAT_GATEWAY_MODEL_IDS,
  filterChatCapableModelIds,
  isChatCapableGatewayModel,
} from "@/lib/gateway/harness-config";

export type TerminalTabId = "opencode" | "proxy" | "env" | "curl" | "sdk";

export interface TerminalSnippets {
  opencodeConfig: string;
  opencodeRemoteComment: string;
  proxySnippet: string;
  envSnippet: string;
  curlSnippet: string;
  sdkSnippet: string;
}

export const PRODUCTION_BASE_URL = "https://drouter-demo.vercel.app";
export const REPO_CLONE_URL = "https://github.com/thepigdestroyer/drouter";

export const DEFAULT_LIVE_MODEL_IDS = CHAT_GATEWAY_MODEL_IDS;

export function sanitizeLiveModelId(model?: string): string {
  const trimmed = (model || "").trim();
  if (!trimmed || !isChatCapableGatewayModel(trimmed)) {
    return "kimi-k3";
  }
  return trimmed;
}

export function normalizeBaseUrl(baseUrl?: string): string {
  const raw = (baseUrl || PRODUCTION_BASE_URL).trim().replace(/\/+$/, "");
  return raw || PRODUCTION_BASE_URL;
}

/**
 * Resolves the upstream HTTPS URL for `node scripts/drouter-cli.mjs`.
 * Because the Tinfoil SDK requires an HTTPS `attestationBundleURL`,
 * plain `http://localhost` origins automatically point the CLI upstream
 * at `https://drouter-demo.vercel.app`.
 */
export function resolveCliUpstreamUrl(baseUrl?: string): string {
  const clean = normalizeBaseUrl(baseUrl);
  if (clean.startsWith("https://")) {
    return clean;
  }
  return PRODUCTION_BASE_URL;
}

export function buildTerminalSnippets(
  baseUrl = PRODUCTION_BASE_URL,
  defaultModel = "kimi-k3",
  liveModelIds: readonly string[] = DEFAULT_LIVE_MODEL_IDS,
): TerminalSnippets {
  const cleanBase = normalizeBaseUrl(baseUrl);
  const resolvedModel = sanitizeLiveModelId(defaultModel);
  const modelList = filterChatCapableModelIds(liveModelIds);
  const gatewayV1 = `${cleanBase}/v1`;
  const prodV1 = `${PRODUCTION_BASE_URL}/v1`;
  const cliUpstream = resolveCliUpstreamUrl(cleanBase);
  const upstreamFlag =
    cliUpstream === PRODUCTION_BASE_URL ? "" : ` --upstream ${cliUpstream}`;

  const opencodeConfig = `{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "drouter-confidential": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "deRoute Confidential TEE (Attested)",
      "options": {
        "baseURL": "${prodV1}",
        "apiKey": "drk_YOUR_ACCESS_KEY"
      },
      "models": {
        "kimi-k3": {
          "name": "Kimi K3 (Intel TDX + NVIDIA CC GPUs, 262,144 context)"
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
        },
        "gemma4-31b": {
          "name": "Gemma 4 31B (AMD SEV-SNP / Intel TDX + NVIDIA CC GPUs)"
        }
      }
    }
  },
  "model": "drouter-confidential/${resolvedModel}"
}`;

  const opencodeRemoteComment = `// Recommended: create an access key (drk_...) on your Account page (${PRODUCTION_BASE_URL}/account)
// and run the local proxy: node deroute-proxy.mjs --key drk_...
// Then set "baseURL": "http://127.0.0.1:4141/v1" (or use "apiKey": "drk_YOUR_ACCESS_KEY" in hosted mode; any non-empty string falls back to the free tier).`;

  const proxySnippet = `# Recommended: create an access key (drk_...) on your Account page (${PRODUCTION_BASE_URL}/account)
# Download the single-file local proxy and verify its checksum:
curl -fsSLO ${PRODUCTION_BASE_URL}/downloads/deroute-proxy.mjs
curl -fsSLO ${PRODUCTION_BASE_URL}/downloads/deroute-proxy.mjs.sha256
shasum -a 256 -c deroute-proxy.mjs.sha256

# Start the local proxy on http://127.0.0.1:4141/v1 (or set DEROUTE_ACCESS_KEY=drk_...):
node deroute-proxy.mjs --key drk_YOUR_ACCESS_KEY

# Or build and run from source:
git clone ${REPO_CLONE_URL} && cd drouter && npm ci
node scripts/drouter-cli.mjs verify${upstreamFlag}
node scripts/drouter-cli.mjs proxy --port 4141${upstreamFlag}`;

  const envSnippet = `# Private mode (recommended): run "node deroute-proxy.mjs --key drk_..." from /account
export OPENAI_BASE_URL="http://127.0.0.1:4141/v1"
export OPENAI_API_KEY="deroute-local"

# Hosted mode (convenient, our server filters your words before forwarding):
export OPENAI_BASE_URL="${prodV1}"
export OPENAI_API_KEY="drk_YOUR_ACCESS_KEY" # or "any-value" for the per-network free tier

# Live Models (/v1/models): ${modelList.join(" | ")}`;

  const curlSnippet = `# 1. List attested enclave models:
curl ${prodV1}/models

# 2. Hosted mode with an access key from /account (Authorization: Bearer drk_...):
curl -sS -X POST "${prodV1}/chat/completions" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer drk_YOUR_ACCESS_KEY" \\
  -d '{
    "model": "${resolvedModel}",
    "messages": [
      { "role": "user", "content": "Reply with one short sentence." }
    ]
  }'

# 3. Verify all 7 checks and ask from the local zero-trust CLI:
git clone ${REPO_CLONE_URL} && cd drouter && npm ci && node scripts/drouter-cli.mjs verify${upstreamFlag}
node scripts/drouter-cli.mjs ask "Explain AMD SEV-SNP in one sentence." --model ${resolvedModel}${upstreamFlag}`;

  const sdkSnippet = `// TypeScript / Node.js (OpenAI SDK)
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${prodV1}", // or "${gatewayV1}" or "http://127.0.0.1:4141/v1" with node deroute-proxy.mjs --key drk_...
  apiKey: "drk_YOUR_ACCESS_KEY", // Create a drk_... key on /account; deRoute accepts any value for the free tier (x-drouter-credit header also supported)
});

const response = await client.chat.completions.create({
  model: "${resolvedModel}",
  messages: [{ role: "user", content: "Summarize how AMD SEV-SNP isolates guest memory." }],
});
console.log(response.choices[0]?.message?.content);

# ---------------------------------------------------------
# Python (openai >= 1.0)
from openai import OpenAI

client = OpenAI(
    base_url="${prodV1}",  # or "http://127.0.0.1:4141/v1"
    api_key="drk_YOUR_ACCESS_KEY",  # Create a drk_... key on /account; any non-empty string uses the free tier (x-drouter-credit header also supported)
)

res = client.chat.completions.create(
    model="${resolvedModel}",
    messages=[{"role": "user", "content": "Summarize how AMD SEV-SNP isolates guest memory."}],
)
print(res.choices[0].message.content)`;

  return {
    opencodeConfig,
    opencodeRemoteComment,
    proxySnippet,
    envSnippet,
    curlSnippet,
    sdkSnippet,
  };
}
