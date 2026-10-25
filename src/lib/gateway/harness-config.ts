export interface GatewayModelSpec {
  id: string;
  label: string;
  provider: string;
  enclave_attested: boolean;
  repo?: string;
  tag?: string;
  predicate?: string;
  healthy_hosts?: number;
  configured_hosts?: number;
  verified_hosts?: number;
  created?: number;
}

export const TINFOIL_PROXY_WELL_KNOWN_URL =
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";

/** Internal Tinfoil utility enclaves in the router proxy table that are not inference models. */
const NON_INFERENCE_TINFOIL_SERVICES = new Set<string>([
  "doc-upload",
  "pii-filter",
  "websearch",
]);

const KNOWN_MODEL_LABELS: Readonly<Record<string, string>> = {
  "kimi-k3": "Kimi K3 (2.8T MoE, 256K ctx)",
  "glm-5-3": "GLM-5.3",
  "deepseek-v4-1-flash": "DeepSeek V4.1 Flash",
  "gpt-oss-120b": "GPT-OSS 120B",
  "llama3-3-70b": "Llama 3.3 70B",
  "gemma4-31b": "Gemma 4 31B",
  "voxtral-small-24b": "Voxtral Small 24B",
  "voxtral-mini-4b-realtime": "Voxtral Mini 4B Realtime",
  "voxtral-tts": "Voxtral TTS",
  "qwen3-tts": "Qwen 3 TTS",
  "whisper-large-v3-turbo": "Whisper Large v3 Turbo",
  "nomic-embed-text": "Nomic Embed Text",
  "gpt-oss-safeguard-120b": "GPT-OSS Safeguard 120B",
  "decision-large": "Decision Large",
  "decision-medium": "Decision Medium",
  "decision-small": "Decision Small",
};

const PRIMARY_MODEL_ORDER: readonly string[] = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
  "gemma4-31b",
  "voxtral-small-24b",
];

/**
 * Production baseline of real Tinfoil enclave models.
 * Live requests to `/v1/models` and `/v1/verify` query `fetchLiveGatewayModels()` to read
 * Tinfoil's live `.well-known/tinfoil-proxy` enclave table directly.
 */
export const SUPPORTED_GATEWAY_MODELS: readonly GatewayModelSpec[] = [
  {
    id: "kimi-k3",
    label: KNOWN_MODEL_LABELS["kimi-k3"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-kimi-k3",
  },
  {
    id: "glm-5-3",
    label: KNOWN_MODEL_LABELS["glm-5-3"],
    provider: "tinfoil-sev-snp",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-glm5-3-nvfp4",
  },
  {
    id: "deepseek-v4-1-flash",
    label: KNOWN_MODEL_LABELS["deepseek-v4-1-flash"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-deepseek-v4-1-flash",
  },
  {
    id: "gpt-oss-120b",
    label: KNOWN_MODEL_LABELS["gpt-oss-120b"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-gpt-oss-120b",
  },
  {
    id: "llama3-3-70b",
    label: KNOWN_MODEL_LABELS["llama3-3-70b"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-llama3-3-70b",
  },
  {
    id: "gemma4-31b",
    label: KNOWN_MODEL_LABELS["gemma4-31b"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-gemma4-31b",
  },
  {
    id: "voxtral-small-24b",
    label: KNOWN_MODEL_LABELS["voxtral-small-24b"],
    provider: "tinfoil-tdx",
    enclave_attested: true,
    repo: "tinfoilsh/confidential-voxtral-small-24b",
  },
] as const;

export const SUPPORTED_GATEWAY_MODEL_IDS = SUPPORTED_GATEWAY_MODELS.map((m) => m.id);

interface LiveProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  } | null;
  enclaves?: Record<
    string,
    {
      hpke_key?: string;
      predicate?: string;
      tls_key_fp?: string;
    }
  >;
  verification?: {
    observed_at?: string;
    configured?: number;
    verified?: number;
    healthy?: number;
    unverified?: number;
  };
}

interface LiveProxyTableResponse {
  models?: Record<string, LiveProxyModelEntry>;
  observed_at?: string;
  updated?: string;
  version?: string;
}

const LIVE_MODEL_CACHE_TTL_MS = 60_000;
let cachedLiveModels: { models: GatewayModelSpec[]; fetchedAt: number } | null = null;
const dynamicLiveModelIds = new Set<string>(SUPPORTED_GATEWAY_MODEL_IDS);

for (const id of Object.keys(KNOWN_MODEL_LABELS)) {
  dynamicLiveModelIds.add(id);
}

export function resetGatewayModelsCache(): void {
  cachedLiveModels = null;
}

function formatModelLabel(id: string, tag?: string): string {
  const base =
    KNOWN_MODEL_LABELS[id] ??
    id
      .split("-")
      .map((part) => (part.length <= 3 ? part.toUpperCase() : part[0].toUpperCase() + part.slice(1)))
      .join(" ");
  return tag ? `${base} (${tag})` : base;
}

export function parseTinfoilProxyModelTable(
  table: LiveProxyTableResponse,
): GatewayModelSpec[] {
  const rawModels = table?.models;
  if (!rawModels || typeof rawModels !== "object") {
    return [...SUPPORTED_GATEWAY_MODELS];
  }

  const fallbackCreated = (() => {
    const ts = Date.parse(table.updated || table.observed_at || "");
    return Number.isFinite(ts) && ts > 0 ? Math.floor(ts / 1000) : 1792800000;
  })();

  const parsed: GatewayModelSpec[] = [];

  for (const [id, entry] of Object.entries(rawModels)) {
    if (!entry || typeof entry !== "object") continue;
    if (NON_INFERENCE_TINFOIL_SERVICES.has(id)) continue;

    const enclaves = entry.enclaves && typeof entry.enclaves === "object" ? entry.enclaves : {};
    const enclaveList = Object.values(enclaves);
    const configured = entry.verification?.configured ?? enclaveList.length;
    const verified = entry.verification?.verified ?? enclaveList.length;
    const healthy = entry.verification?.healthy ?? enclaveList.length;

    if (configured <= 0 || verified <= 0 || healthy <= 0 || enclaveList.length === 0) {
      continue;
    }

    const predicates = enclaveList
      .map((e) => e?.predicate ?? "")
      .filter((p) => typeof p === "string" && p.length > 0);
    const primaryPredicate =
      predicates[0] ?? entry.measurement?.type ?? "https://tinfoil.sh/predicate/tdx-guest/v2";
    const hasSevSnp = predicates.some((p) => p.includes("sev-snp"));
    const hasTdx = predicates.some((p) => p.includes("tdx"));
    const provider =
      hasSevSnp && hasTdx
        ? "tinfoil-sev-snp+tdx"
        : hasSevSnp
          ? "tinfoil-sev-snp"
          : "tinfoil-tdx";

    const observedMs = Date.parse(entry.verification?.observed_at || "");
    const created =
      Number.isFinite(observedMs) && observedMs > 0
        ? Math.floor(observedMs / 1000)
        : fallbackCreated;

    dynamicLiveModelIds.add(id);

    parsed.push({
      id,
      label: formatModelLabel(id, entry.tag),
      provider,
      enclave_attested: verified > 0 && healthy > 0,
      ...(entry.repo ? { repo: entry.repo } : {}),
      ...(entry.tag ? { tag: entry.tag } : {}),
      predicate: primaryPredicate,
      healthy_hosts: healthy,
      configured_hosts: configured,
      verified_hosts: verified,
      created,
    });
  }

  if (parsed.length === 0) {
    return [...SUPPORTED_GATEWAY_MODELS];
  }

  parsed.sort((a, b) => {
    const idxA = PRIMARY_MODEL_ORDER.indexOf(a.id);
    const idxB = PRIMARY_MODEL_ORDER.indexOf(b.id);
    if (idxA !== -1 && idxB !== -1) return idxA - idxB;
    if (idxA !== -1) return -1;
    if (idxB !== -1) return 1;
    return a.id.localeCompare(b.id);
  });

  return parsed;
}

/**
 * Fetches the live model enclave table from `https://inference.tinfoil.sh/.well-known/tinfoil-proxy`.
 * Uses a 60s in-memory cache and returns only real attested enclave models.
 */
export async function fetchLiveGatewayModels(opts?: {
  fetchImpl?: typeof fetch;
  forceRefresh?: boolean;
}): Promise<GatewayModelSpec[]> {
  const customFetch = opts?.fetchImpl;
  const now = Date.now();

  if (
    !customFetch &&
    !opts?.forceRefresh &&
    cachedLiveModels &&
    now - cachedLiveModels.fetchedAt < LIVE_MODEL_CACHE_TTL_MS
  ) {
    return [...cachedLiveModels.models];
  }

  const doFetch = customFetch ?? globalThis.fetch;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const res = await doFetch(TINFOIL_PROXY_WELL_KNOWN_URL, {
        signal: controller.signal,
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        const json = (await res.json()) as LiveProxyTableResponse;
        const live = parseTinfoilProxyModelTable(json);
        if (!customFetch) {
          cachedLiveModels = { models: live, fetchedAt: Date.now() };
        }
        return [...live];
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Fall back to last cached live table or baseline Tinfoil models on transient network error
  }

  return cachedLiveModels ? [...cachedLiveModels.models] : [...SUPPORTED_GATEWAY_MODELS];
}

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
        name: "deRoute Attested Enclave Gateway",
        options: {
          baseURL: gatewayUrl,
          // Any non-empty apiKey value works (the OpenAI SDK requires a string);
          // actual auth is the blind-signed x-drouter-credit header (with per-IP free-tier fallback).
          apiKey: "drouter-anonymous",
          _authNote:
            "any apiKey value works, auth is the blind credit header (x-drouter-credit) with per-IP free-tier fallback",
          headers: {
            "x-drouter-credit": "${DROUTER_CREDIT_TOKEN}",
          },
        },
        models: {
          "kimi-k3": { name: "Kimi K3 (Attested Enclave)" },
          "glm-5-3": { name: "GLM-5.3 (Attested Enclave)" },
          "deepseek-v4-1-flash": { name: "DeepSeek V4.1 Flash (Attested Enclave)" },
          "gpt-oss-120b": { name: "GPT-OSS 120B (Attested Enclave)" },
          "llama3-3-70b": { name: "Llama 3.3 70B (Attested Enclave)" },
          "gemma4-31b": { name: "Gemma 4 31B (Attested Enclave)" },
        },
      },
    },
    model: "drouter/kimi-k3",
  };

  const opencodeJson = JSON.stringify(opencodeConfig, null, 2);

  const curlCommand = [
    `# Note: any Bearer apiKey value works (required by OpenAI SDKs); auth is the blind credit header (x-drouter-credit)`,
    `curl -sS ${gatewayUrl}/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer drouter-anonymous" -H "x-drouter-credit: \${DROUTER_CREDIT_TOKEN:-}" -d '{"model":"kimi-k3","messages":[{"role":"user","content":"Verify enclave connectivity in one sentence."}]}'`,
  ].join("\n");

  const openaiEnvExports = [
    `# Any OPENAI_API_KEY value works; auth is the blind credit header (x-drouter-credit) or per-IP free tier`,
    `export OPENAI_BASE_URL="${gatewayUrl}"`,
    `export OPENAI_API_KEY="drouter-anonymous"`,
  ].join("\n");

  const pythonSnippet = [
    `from openai import OpenAI`,
    ``,
    `# Any api_key value works (OpenAI SDK requires a non-empty string);`,
    `# auth is the blind credit header (x-drouter-credit) with per-IP free-tier fallback.`,
    `client = OpenAI(`,
    `    base_url="${gatewayUrl}",`,
    `    api_key="drouter-anonymous",`,
    `)`,
    `resp = client.chat.completions.create(`,
    `    model="kimi-k3",`,
    `    messages=[{"role": "user", "content": "Hello from deRoute enclave!"}],`,
    `)`,
    `print(resp.choices[0].message.content)`,
  ].join("\n");

  const typescriptSnippet = [
    `import OpenAI from "openai";`,
    ``,
    `// Any apiKey value works (OpenAI SDK requires a non-empty string);`,
    `// auth is the blind credit header (x-drouter-credit) with per-IP free-tier fallback.`,
    `const client = new OpenAI({`,
    `  baseURL: "${gatewayUrl}",`,
    `  apiKey: "drouter-anonymous",`,
    `});`,
    `const resp = await client.chat.completions.create({`,
    `  model: "kimi-k3",`,
    `  messages: [{ role: "user", content: "Hello from deRoute enclave!" }],`,
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

export type CodingToolId =
  | "opencode"
  | "cursor"
  | "continue"
  | "aider"
  | "typescript"
  | "python"
  | "curl";

export type CodingToolMode = "private" | "hosted";

export const LOCAL_PROXY_BASE_URL = "http://127.0.0.1:4141/v1";
export const HOSTED_GATEWAY_BASE_URL = "https://drouter-demo.vercel.app/api/v1";

export interface CodingToolSnippets {
  mode: CodingToolMode;
  baseUrl: string;
  apiKeyPlaceholder: string;
  proxyStartCommand: string;
  byTool: Record<CodingToolId, string>;
}

/**
 * Builds copy-paste setup snippets for every supported coding tool (OpenCode, Cursor,
 * Continue, Aider, TypeScript OpenAI SDK, Python OpenAI SDK, curl) in either
 * Private mode (local proxy at http://127.0.0.1:4141/v1) or Hosted mode
 * (https://drouter-demo.vercel.app/api/v1 with Authorization: Bearer drk_...).
 */
export function buildCodingToolSnippets(opts?: {
  mode?: CodingToolMode;
  accessKey?: string | null;
  modelIds?: readonly string[];
  defaultModel?: string;
  hostedOrigin?: string;
}): CodingToolSnippets {
  const mode: CodingToolMode = opts?.mode ?? "private";
  const cleanOrigin = (opts?.hostedOrigin || "https://drouter-demo.vercel.app").replace(/\/+$/, "");
  const hostedBaseUrl = `${cleanOrigin}/api/v1`;
  const baseUrl = mode === "private" ? LOCAL_PROXY_BASE_URL : hostedBaseUrl;

  const keyOrPlaceholder =
    opts?.accessKey && opts.accessKey.trim().startsWith("drk_")
      ? opts.accessKey.trim()
      : "drk_YOUR_ACCESS_KEY";

  const apiKeyValue = mode === "private" ? "deroute-local" : keyOrPlaceholder;

  const rawModels =
    opts?.modelIds && opts.modelIds.length > 0
      ? opts.modelIds
      : SUPPORTED_GATEWAY_MODEL_IDS;
  const models = rawModels.filter((id) => id && !id.toLowerCase().startsWith("sim-"));
  const primaryModel =
    opts?.defaultModel && models.includes(opts.defaultModel)
      ? opts.defaultModel
      : models[0] ?? "kimi-k3";

  const opencodeModelsObj: Record<string, { name: string }> = {};
  for (const id of models) {
    opencodeModelsObj[id] = {
      name: `${KNOWN_MODEL_LABELS[id] ?? id} (deRoute)`,
    };
  }

  const opencodeConfig = {
    $schema: "https://opencode.ai/config.json",
    provider: {
      deroute: {
        npm: "@ai-sdk/openai-compatible",
        name:
          mode === "private"
            ? "deRoute (Local Private Proxy)"
            : "deRoute (Hosted Gateway)",
        options: {
          baseURL: baseUrl,
          apiKey: apiKeyValue,
        },
        models: opencodeModelsObj,
      },
    },
    model: `deroute/${primaryModel}`,
  };

  const proxyStartCommand = [
    `# 1. Download the single-file local proxy and its checksum:`,
    `curl -fsSLO ${cleanOrigin}/downloads/deroute-proxy.mjs`,
    `curl -fsSLO ${cleanOrigin}/downloads/deroute-proxy.mjs.sha256`,
    `shasum -a 256 -c deroute-proxy.mjs.sha256`,
    ``,
    `# 2. Start the local proxy on http://127.0.0.1:4141/v1 (requires Node 20+):`,
    `node deroute-proxy.mjs --key ${keyOrPlaceholder}`,
  ].join("\n");

  const opencodeSnippet = JSON.stringify(opencodeConfig, null, 2);

  const cursorSnippet = [
    `# Cursor -> Settings -> Models -> OpenAI API Key:`,
    `1. Turn on "Override OpenAI Base URL" and set it to:`,
    `   ${baseUrl}`,
    `2. Set "OpenAI API Key" to:`,
    `   ${apiKeyValue}`,
    `3. Add custom model IDs from GET /api/v1/models:`,
    `   ${models.join(", ")}`,
  ].join("\n");

  const continueModelsYaml = models
    .map(
      (id) =>
        `  - name: deRoute ${KNOWN_MODEL_LABELS[id] ?? id}\n    provider: openai\n    model: ${id}\n    apiBase: ${baseUrl}\n    apiKey: ${apiKeyValue}\n    roles:\n      - chat\n      - edit\n      - apply`,
    )
    .join("\n");

  const continueSnippet = [
    `# ~/.continue/config.yaml`,
    `name: deRoute Config`,
    `version: 1.0.0`,
    `schema: v1`,
    `models:`,
    continueModelsYaml,
  ].join("\n");

  const aiderSnippet = [
    `# Run Aider with --openai-api-base and --openai-api-key:`,
    `aider \\`,
    `  --openai-api-base "${baseUrl}" \\`,
    `  --openai-api-key "${apiKeyValue}" \\`,
    `  --model "openai/${primaryModel}"`,
    ``,
    `# Available models: ${models.map((m) => `openai/${m}`).join(", ")}`,
  ].join("\n");

  const typescriptSnippet = [
    `import OpenAI from "openai";`,
    ``,
    `const client = new OpenAI({`,
    `  baseURL: "${baseUrl}",`,
    `  apiKey: "${apiKeyValue}",`,
    `});`,
    ``,
    `const completion = await client.chat.completions.create({`,
    `  model: "${primaryModel}",`,
    `  messages: [{ role: "user", content: "Write a short unit test in TypeScript." }],`,
    `});`,
    ``,
    `console.log(completion.choices[0]?.message?.content);`,
  ].join("\n");

  const pythonSnippet = [
    `from openai import OpenAI`,
    ``,
    `client = OpenAI(`,
    `    base_url="${baseUrl}",`,
    `    api_key="${apiKeyValue}",`,
    `)`,
    ``,
    `completion = client.chat.completions.create(`,
    `    model="${primaryModel}",`,
    `    messages=[{"role": "user", "content": "Write a short unit test in Python."}],`,
    `)`,
    ``,
    `print(completion.choices[0].message.content)`,
  ].join("\n");

  const curlSnippet = [
    `# List live models:`,
    `curl -sS "${baseUrl}/models"`,
    ``,
    `# Send a chat completion request:`,
    `curl -sS -X POST "${baseUrl}/chat/completions" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -H "Authorization: Bearer ${apiKeyValue}" \\`,
    `  -d '{`,
    `    "model": "${primaryModel}",`,
    `    "messages": [`,
    `      { "role": "user", "content": "Reply with one short sentence." }`,
    `    ]`,
    `  }'`,
  ].join("\n");

  return {
    mode,
    baseUrl,
    apiKeyPlaceholder: apiKeyValue,
    proxyStartCommand,
    byTool: {
      opencode: opencodeSnippet,
      cursor: cursorSnippet,
      continue: continueSnippet,
      aider: aiderSnippet,
      typescript: typescriptSnippet,
      python: pythonSnippet,
      curl: curlSnippet,
    },
  };
}

export type NormalizedChatRole = "system" | "user" | "assistant" | "tool";

export interface NormalizedToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

export interface NormalizedChatMessage {
  role: NormalizedChatRole;
  content: string | null;
  name?: string;
  tool_call_id?: string;
  tool_calls?: NormalizedToolCall[];
}

export type ParsedGatewayChatRequest =
  | {
      ok: true;
      model: string;
      messages: NormalizedChatMessage[];
      stream: boolean;
      temperature?: number;
      max_tokens?: number;
      top_p?: number;
      stop?: string | string[];
      presence_penalty?: number;
      frequency_penalty?: number;
      seed?: number;
      tools?: Array<Record<string, unknown>>;
      tool_choice?: unknown;
      parallel_tool_calls?: boolean;
      response_format?: Record<string, unknown>;
      stream_options?: Record<string, unknown>;
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

function normalizeRole(
  raw: unknown,
  hasToolCallId: boolean,
): NormalizedChatRole | null {
  if (raw === "system" || raw === "user" || raw === "assistant") {
    return raw;
  }
  if (raw === "developer") {
    return "system";
  }
  if (raw === "tool" || raw === "function") {
    return hasToolCallId ? "tool" : "user";
  }
  return null;
}

function normalizeToolCalls(raw: unknown): NormalizedToolCall[] | undefined {
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  const out: NormalizedToolCall[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const tc = item as Record<string, unknown>;
    const fn =
      tc.function && typeof tc.function === "object"
        ? (tc.function as Record<string, unknown>)
        : null;
    if (!fn || typeof fn.name !== "string") continue;
    out.push({
      id: typeof tc.id === "string" && tc.id ? tc.id : `call_${out.length + 1}`,
      type: "function",
      function: {
        name: fn.name,
        arguments:
          typeof fn.arguments === "string"
            ? fn.arguments
            : JSON.stringify(fn.arguments ?? {}),
      },
    });
  }
  return out.length > 0 ? out : undefined;
}

export function parseGatewayChatRequest(
  body: unknown,
  opts?: {
    allowedModelIds?: Iterable<string>;
  },
): ParsedGatewayChatRequest {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "Request body must be a JSON object" };
  }

  const record = body as Record<string, unknown>;
  const rawModel =
    typeof record.model === "string" && record.model.trim()
      ? record.model.trim()
      : "kimi-k3";
  const normalizedModel = rawModel.startsWith("drouter/")
    ? rawModel.slice("drouter/".length)
    : rawModel;

  const allowedSet = opts?.allowedModelIds
    ? new Set(opts.allowedModelIds)
    : dynamicLiveModelIds;
  if (!allowedSet.has(normalizedModel)) {
    return {
      ok: false,
      error: `Unsupported model "${rawModel}". Supported models: ${[...allowedSet].join(", ")}`,
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
    const toolCallId =
      typeof msg.tool_call_id === "string" && msg.tool_call_id.trim()
        ? msg.tool_call_id.trim()
        : undefined;
    const role = normalizeRole(msg.role, Boolean(toolCallId));
    if (!role) {
      return {
        ok: false,
        error: `messages[${i}].role must be one of "system", "user", "assistant", or "tool"`,
      };
    }

    const toolCalls = role === "assistant" ? normalizeToolCalls(msg.tool_calls) : undefined;
    const content = normalizeContent(msg.content);

    if (content === null && !(role === "assistant" && toolCalls && toolCalls.length > 0)) {
      return {
        ok: false,
        error: `messages[${i}].content must be a string or an array of content parts`,
      };
    }

    const contentLen = content ? content.length : 0;
    if (contentLen > 131_072) {
      return {
        ok: false,
        error: `messages[${i}].content exceeds maximum length (131072 characters)`,
      };
    }
    totalContentChars += contentLen;
    if (totalContentChars > 262_144) {
      return {
        ok: false,
        error: "Total messages content exceeds maximum length (262144 characters)",
      };
    }

    const normalizedMsg: NormalizedChatMessage = {
      role,
      content,
    };
    if (typeof msg.name === "string" && msg.name.trim()) {
      normalizedMsg.name = msg.name.trim();
    }
    if (toolCallId) {
      normalizedMsg.tool_call_id = toolCallId;
    }
    if (toolCalls) {
      normalizedMsg.tool_calls = toolCalls;
    }
    messages.push(normalizedMsg);
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

  let top_p: number | undefined;
  if (record.top_p !== undefined && record.top_p !== null) {
    if (
      typeof record.top_p !== "number" ||
      !Number.isFinite(record.top_p) ||
      record.top_p < 0 ||
      record.top_p > 1
    ) {
      return { ok: false, error: "top_p must be a finite number between 0 and 1" };
    }
    top_p = record.top_p;
  }

  let stop: string | string[] | undefined;
  if (typeof record.stop === "string") {
    stop = record.stop;
  } else if (
    Array.isArray(record.stop) &&
    record.stop.length <= 4 &&
    record.stop.every((s) => typeof s === "string")
  ) {
    stop = record.stop as string[];
  }

  let presence_penalty: number | undefined;
  if (typeof record.presence_penalty === "number" && Number.isFinite(record.presence_penalty)) {
    presence_penalty = Math.max(-2, Math.min(2, record.presence_penalty));
  }

  let frequency_penalty: number | undefined;
  if (typeof record.frequency_penalty === "number" && Number.isFinite(record.frequency_penalty)) {
    frequency_penalty = Math.max(-2, Math.min(2, record.frequency_penalty));
  }

  let seed: number | undefined;
  if (typeof record.seed === "number" && Number.isInteger(record.seed)) {
    seed = record.seed;
  }

  let tools: Array<Record<string, unknown>> | undefined;
  if (Array.isArray(record.tools)) {
    if (record.tools.length > 64) {
      return { ok: false, error: "tools cannot exceed 64 tool definitions" };
    }
    tools = record.tools.filter(
      (t): t is Record<string, unknown> => Boolean(t && typeof t === "object" && !Array.isArray(t)),
    );
  }

  const tool_choice =
    record.tool_choice !== undefined && record.tool_choice !== null
      ? record.tool_choice
      : undefined;

  const parallel_tool_calls =
    typeof record.parallel_tool_calls === "boolean" ? record.parallel_tool_calls : undefined;

  const response_format =
    record.response_format &&
    typeof record.response_format === "object" &&
    !Array.isArray(record.response_format)
      ? (record.response_format as Record<string, unknown>)
      : undefined;

  const stream_options =
    record.stream_options &&
    typeof record.stream_options === "object" &&
    !Array.isArray(record.stream_options)
      ? (record.stream_options as Record<string, unknown>)
      : undefined;

  return {
    ok: true,
    model: normalizedModel,
    messages,
    stream,
    ...(temperature !== undefined ? { temperature } : {}),
    ...(max_tokens !== undefined ? { max_tokens } : {}),
    ...(top_p !== undefined ? { top_p } : {}),
    ...(stop !== undefined ? { stop } : {}),
    ...(presence_penalty !== undefined ? { presence_penalty } : {}),
    ...(frequency_penalty !== undefined ? { frequency_penalty } : {}),
    ...(seed !== undefined ? { seed } : {}),
    ...(tools !== undefined ? { tools } : {}),
    ...(tool_choice !== undefined ? { tool_choice } : {}),
    ...(parallel_tool_calls !== undefined ? { parallel_tool_calls } : {}),
    ...(response_format !== undefined ? { response_format } : {}),
    ...(stream_options !== undefined ? { stream_options } : {}),
    scrubPii,
  };
}
