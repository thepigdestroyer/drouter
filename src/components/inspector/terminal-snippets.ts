import {
  CHAT_GATEWAY_MODEL_IDS, buildCodingToolSnippets, GATEWAY_ORIGIN,
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

export const PRODUCTION_BASE_URL = GATEWAY_ORIGIN;
export const REPO_CLONE_URL = "https://github.com/thepigdestroyer/drouter";

export const DEFAULT_LIVE_MODEL_IDS = CHAT_GATEWAY_MODEL_IDS;

export function sanitizeLiveModelId(model?: string): string {
  const trimmed = (model || "").trim();
  if (!trimmed || !isChatCapableGatewayModel(trimmed)) {
    return "kimi-k3-1-pro";
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
 * at `https://deroute.is-an.ai`.
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
  defaultModel = "kimi-k3-1-pro",
  liveModelIds: readonly string[] = DEFAULT_LIVE_MODEL_IDS,
): TerminalSnippets {
  const cleanBase = normalizeBaseUrl(baseUrl);
  const resolvedModel = sanitizeLiveModelId(defaultModel);
  const modelList = filterChatCapableModelIds(liveModelIds);
  const cliUpstream = resolveCliUpstreamUrl(cleanBase);
  const upstreamFlag =
    cliUpstream === PRODUCTION_BASE_URL ? "" : ` --upstream ${cliUpstream}`;

  const setup = buildCodingToolSnippets({mode:"hosted", defaultModel: resolvedModel, modelIds: modelList});
  const opencodeConfig = setup.byTool.opencode;
  const opencodeRemoteComment = `// Get a key at ${PRODUCTION_BASE_URL}/api-keys and set DEROUTE_API_KEY for the OpenCode server.`;
  const proxySnippet = setup.proxyStartCommand;
  const envSnippet = `export OPENAI_BASE_URL="${setup.baseUrl}"\nexport OPENAI_API_KEY="\${DEROUTE_API_KEY:?Set your deRoute API key first}"\n# Models: ${modelList.join(" | ")}`;
  const curlSnippet = `${setup.byTool.curl}\n\n# Independent enclave verification:\ngit clone ${REPO_CLONE_URL} && cd drouter && npm ci && node scripts/drouter-cli.mjs verify${upstreamFlag}`;
  const sdkSnippet = `${setup.byTool.typescript}\n\n# Python\n${setup.byTool.python}`;

  return {
    opencodeConfig,
    opencodeRemoteComment,
    proxySnippet,
    envSnippet,
    curlSnippet,
    sdkSnippet,
  };
}
