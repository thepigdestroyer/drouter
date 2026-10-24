export interface GatewayModelSpec {
  id: string;
  label: string;
  provider: string;
  enclave_attested: boolean;
}

export const SUPPORTED_GATEWAY_MODELS: readonly GatewayModelSpec[] = [
  {
    id: "kimi-k3",
    label: "Kimi K3 (2.8T MoE)",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "glm-5-3",
    label: "GLM-5.3",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "deepseek-v4-1-flash",
    label: "DeepSeek V4.1 Flash",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "gpt-oss-120b",
    label: "GPT-OSS 120B",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "llama3-3-70b",
    label: "Llama 3.3 70B",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "gemma4-31b",
    label: "Gemma 4 31B",
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
  },
  {
    id: "sim-echo-1",
    label: "Simulated Enclave Echo (sim-1)",
    provider: "drouter-simulated-sev-snp",
    enclave_attested: true,
  },
] as const;

export const SUPPORTED_GATEWAY_MODEL_IDS = SUPPORTED_GATEWAY_MODELS.map((m) => m.id);

export interface HarnessConfigs {
  opencodeJson: string;
  curlCommand: string;
  openaiEnvExports: string;
  pythonSnippet: string;
  typescriptSnippet: string;
  localProxyCommand: string;
}

export function buildHarnessConfigs(baseUrl: string): HarnessConfigs {
  const cleanBase = (baseUrl || "https://drouter-demo.vercel.app").replace(/\/+$/, "");
  const gatewayUrl = `${cleanBase}/api/v1`;

  const opencodeConfig = {
    $schema: "https://opencode.ai/config.json",
    provider: {
      drouter: {
        npm: "@ai-sdk/openai-compatible",
        name: "dRouter Attested Enclave Gateway",
        options: {
          baseURL: gatewayUrl,
          apiKey: "drouter-anonymous",
        },
        models: {
          "kimi-k3": { name: "Kimi K3 (Attested Enclave)" },
          "glm-5-3": { name: "GLM-5.3 (Attested Enclave)" },
          "deepseek-v4-1-flash": { name: "DeepSeek V4.1 Flash (Attested Enclave)" },
          "gpt-oss-120b": { name: "GPT-OSS 120B (Attested Enclave)" },
          "llama3-3-70b": { name: "Llama 3.3 70B (Attested Enclave)" },
        },
      },
    },
    model: "drouter/kimi-k3",
  };

  const opencodeJson = JSON.stringify(opencodeConfig, null, 2);

  const curlCommand = `curl -sS ${gatewayUrl}/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer drouter-anonymous" -d '{"model":"kimi-k3","messages":[{"role":"user","content":"Verify enclave connectivity in one sentence."}]}'`;

  const openaiEnvExports = [
    `export OPENAI_BASE_URL="${gatewayUrl}"`,
    `export OPENAI_API_KEY="drouter-anonymous"`,
  ].join("\n");

  const pythonSnippet = [
    `from openai import OpenAI`,
    ``,
    `client = OpenAI(`,
    `    base_url="${gatewayUrl}",`,
    `    api_key="drouter-anonymous",`,
    `)`,
    `resp = client.chat.completions.create(`,
    `    model="kimi-k3",`,
    `    messages=[{"role": "user", "content": "Hello from dRouter enclave!"}],`,
    `)`,
    `print(resp.choices[0].message.content)`,
  ].join("\n");

  const typescriptSnippet = [
    `import OpenAI from "openai";`,
    ``,
    `const client = new OpenAI({`,
    `  baseURL: "${gatewayUrl}",`,
    `  apiKey: "drouter-anonymous",`,
    `});`,
    `const resp = await client.chat.completions.create({`,
    `  model: "kimi-k3",`,
    `  messages: [{ role: "user", content: "Hello from dRouter enclave!" }],`,
    `});`,
    `console.log(resp.choices[0]?.message?.content);`,
  ].join("\n");

  const localProxyCommand = `node scripts/drouter-cli.mjs proxy --port 4141 --upstream ${cleanBase}`;

  return {
    opencodeJson,
    curlCommand,
    openaiEnvExports,
    pythonSnippet,
    typescriptSnippet,
    localProxyCommand,
  };
}

export type NormalizedChatRole = "system" | "user" | "assistant";

export interface NormalizedChatMessage {
  role: NormalizedChatRole;
  content: string;
}

export type ParsedGatewayChatRequest =
  | {
      ok: true;
      model: string;
      messages: NormalizedChatMessage[];
      stream: boolean;
      temperature?: number;
      max_tokens?: number;
      scrubPii: boolean;
    }
  | {
      ok: false;
      error: string;
    };

function normalizeContent(raw: unknown): string | null {
  if (typeof raw === "string") {
    return raw;
  }
  if (Array.isArray(raw)) {
    const parts: string[] = [];
    for (const part of raw) {
      if (typeof part === "string") {
        parts.push(part);
      } else if (part && typeof part === "object") {
        const obj = part as Record<string, unknown>;
        if (typeof obj.text === "string") {
          parts.push(obj.text);
        } else if (typeof obj.content === "string") {
          parts.push(obj.content);
        } else if (typeof obj.input_text === "string") {
          parts.push(obj.input_text);
        }
      }
    }
    return parts.join("\n");
  }
  return null;
}

function normalizeRole(raw: unknown): NormalizedChatRole | null {
  if (raw === "system" || raw === "user" || raw === "assistant") {
    return raw;
  }
  if (raw === "developer") {
    return "system";
  }
  if (raw === "tool") {
    return "user";
  }
  return null;
}

export function parseGatewayChatRequest(body: unknown): ParsedGatewayChatRequest {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "Request body must be a JSON object" };
  }

  const record = body as Record<string, unknown>;
  const rawModel = typeof record.model === "string" && record.model.trim() ? record.model.trim() : "kimi-k3";
  const normalizedModel = rawModel.startsWith("drouter/") ? rawModel.slice("drouter/".length) : rawModel;

  const isSupported = SUPPORTED_GATEWAY_MODELS.some((m) => m.id === normalizedModel);
  if (!isSupported) {
    return {
      ok: false,
      error: `Unsupported model "${rawModel}". Supported models: ${SUPPORTED_GATEWAY_MODELS.map((m) => m.id).join(", ")}`,
    };
  }

  if (!Array.isArray(record.messages) || record.messages.length === 0) {
    return { ok: false, error: "messages must be a non-empty array" };
  }
  if (record.messages.length > 64) {
    return { ok: false, error: "messages cannot exceed 64 turns per request" };
  }

  const messages: NormalizedChatMessage[] = [];
  let totalContentChars = 0;
  for (let i = 0; i < record.messages.length; i += 1) {
    const item = record.messages[i];
    if (!item || typeof item !== "object") {
      return { ok: false, error: `messages[${i}] must be an object` };
    }
    const msg = item as Record<string, unknown>;
    const role = normalizeRole(msg.role);
    if (!role) {
      return {
        ok: false,
        error: `messages[${i}].role must be one of "system", "user", or "assistant"`,
      };
    }
    const content = normalizeContent(msg.content);
    if (content === null) {
      return {
        ok: false,
        error: `messages[${i}].content must be a string or an array of content parts`,
      };
    }
    if (content.length > 131_072) {
      return {
        ok: false,
        error: `messages[${i}].content exceeds maximum length (131072 characters)`,
      };
    }
    totalContentChars += content.length;
    if (totalContentChars > 262_144) {
      return {
        ok: false,
        error: "Total messages content exceeds maximum length (262144 characters)",
      };
    }
    messages.push({ role, content });
  }

  const stream = Boolean(record.stream ?? false);
  const scrubPii = Boolean(record.scrubPii ?? record.scrub_pii ?? false);

  let temperature: number | undefined;
  if (record.temperature !== undefined && record.temperature !== null) {
    if (
      typeof record.temperature !== "number" ||
      !Number.isFinite(record.temperature) ||
      record.temperature < 0 ||
      record.temperature > 2
    ) {
      return { ok: false, error: "temperature must be a finite number between 0 and 2" };
    }
    temperature = record.temperature;
  }

  let max_tokens: number | undefined;
  const rawMax = record.max_tokens ?? record.max_completion_tokens;
  if (rawMax !== undefined && rawMax !== null) {
    if (
      typeof rawMax !== "number" ||
      !Number.isInteger(rawMax) ||
      rawMax <= 0 ||
      rawMax > 16_384
    ) {
      return { ok: false, error: "max_tokens must be a positive integer up to 16384" };
    }
    max_tokens = rawMax;
  }

  return {
    ok: true,
    model: normalizedModel,
    messages,
    stream,
    ...(temperature !== undefined ? { temperature } : {}),
    ...(max_tokens !== undefined ? { max_tokens } : {}),
    scrubPii,
  };
}
