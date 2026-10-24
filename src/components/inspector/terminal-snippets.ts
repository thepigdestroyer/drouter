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
): TerminalSnippets {
  const cleanBase = normalizeBaseUrl(baseUrl);
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
      "name": "dRouter Confidential TEE (Attested)",
      "options": {
        "baseURL": "${prodV1}",
        "apiKey": "any-value"
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
        }
      }
    }
  },
  "model": "drouter-confidential/${defaultModel}"
}`;

  const opencodeRemoteComment = `// Or point at your local zero-trust HPKE proxy (after running scripts/drouter-cli.mjs proxy):
// "baseURL": "http://127.0.0.1:4141/v1"`;

  const proxySnippet = `# There is no npm package for the CLI. Clone the repo and run from source:
git clone ${REPO_CLONE_URL} && cd drouter && npm ci

# 1. Verify all 7 hardware & cryptographic checks (C1-C7):
node scripts/drouter-cli.mjs verify${upstreamFlag}

# 2. Start the local zero-trust HPKE proxy on port 4141:
node scripts/drouter-cli.mjs proxy --port 4141${upstreamFlag}

# Point any OpenAI-compatible client at http://127.0.0.1:4141/v1`;

  const envSnippet = `# Hosted OpenAI-compatible gateway (works immediately; any non-empty apiKey string is accepted)
export OPENAI_BASE_URL="${prodV1}"
export OPENAI_API_KEY="any-value"

# Or via the local zero-trust CLI proxy (verifies hardware quote & seals with HPKE on your machine)
export OPENAI_BASE_URL="http://127.0.0.1:4141/v1"
export OPENAI_API_KEY="any-value"

# Model IDs: kimi-k3 | glm-5-3 | deepseek-v4-1-flash | gpt-oss-120b | llama3-3-70b | sim-echo-1`;

  const curlSnippet = `# 1. List attested enclave models:
curl ${prodV1}/models

# 2. Direct OpenAI-compatible chat completion (any API key string works; x-drouter-credit is optional):
curl -sS -X POST "${prodV1}/chat/completions" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer any-value" \\
  -d '{
    "model": "${defaultModel}",
    "messages": [
      { "role": "user", "content": "Reply with one short sentence." }
    ]
  }'

# 3. Verify all 7 checks and ask from the local zero-trust CLI:
git clone ${REPO_CLONE_URL} && cd drouter && npm ci && node scripts/drouter-cli.mjs verify${upstreamFlag}
node scripts/drouter-cli.mjs ask "Explain AMD SEV-SNP in one sentence." --model ${defaultModel}${upstreamFlag}`;

  const sdkSnippet = `// TypeScript / Node.js (OpenAI SDK)
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${prodV1}", // or "${gatewayV1}" or "http://127.0.0.1:4141/v1"
  apiKey: "any-value", // OpenAI SDK requires a non-empty string; dRouter accepts any value (x-drouter-credit header optional)
});

const response = await client.chat.completions.create({
  model: "${defaultModel}",
  messages: [{ role: "user", content: "Summarize how AMD SEV-SNP isolates guest memory." }],
});
console.log(response.choices[0]?.message?.content);

# ---------------------------------------------------------
# Python (openai >= 1.0)
from openai import OpenAI

client = OpenAI(
    base_url="${prodV1}",  # or "http://127.0.0.1:4141/v1"
    api_key="any-value",  # Any non-empty string works; x-drouter-credit header is optional
)

res = client.chat.completions.create(
    model="${defaultModel}",
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
