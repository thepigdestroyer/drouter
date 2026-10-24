import { NextRequest, NextResponse, connection } from "next/server";
import {
  recordAgentVerificationReceipt,
  runAtlasHybridSearch,
} from "@/lib/atlas";
import {
  ARGON_COMPANION_MODELS,
  ARGON_TOOLKIT_MANIFEST,
  DEFAULT_TASK_PROMPT,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  DEMO_PERSONA,
  runArgonAutonomousWorkflow,
  validateArgonRequestConfig,
  type ArgonThinkingLevel,
  type AtlasHybridRunnerResult,
} from "@/lib/gemini";

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 20;
const ipHits = new Map<string, number[]>();

function checkGeminiPostRateLimit(ip: string): boolean {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  const recent = (ipHits.get(ip) ?? []).filter((t) => t > cutoff);
  if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
    ipHits.set(ip, recent);
    return false;
  }
  recent.push(now);
  ipHits.set(ip, recent);
  return true;
}

function getClientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return fwd || req.headers.get("x-real-ip")?.trim() || "127.0.0.1";
}

async function serverAtlasRunner(query: string): Promise<AtlasHybridRunnerResult> {
  const res = await runAtlasHybridSearch(query, { limit: 5 });
  const top = res.results[0];
  return {
    topDocId: top?.docId ?? "provider-tinfoil",
    topTitle: top?.title ?? "Tinfoil Confidential Inference Enclave",
    engines: res.engines,
    totalDocs: res.totalCorpusDocs,
    matchingReceiptsCount: res.matchingReceipts.length,
  };
}

async function serverReceiptRecorder(
  receipt: Parameters<typeof recordAgentVerificationReceipt>[0],
): Promise<void> {
  await recordAgentVerificationReceipt(receipt);
}

export async function GET() {
  await connection();

  const preVerifiedRun = await runArgonAutonomousWorkflow({
    taskPrompt: DEFAULT_TASK_PROMPT,
    thinkingLevel: "medium",
    background: true,
    injectFaultToTestSelfHealing: true,
    humanApprovedExternalAction: false,
    preferredEnclaveModel: "gemma4-31b",
    atlasRunner: serverAtlasRunner,
    receiptRecorder: serverReceiptRecorder,
  });

  const configValidation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: "medium",
    background: true,
    max_output_tokens: 131_072,
    max_context_tokens: 1_000_000,
    autonomousMultiStep: true,
  });

  return NextResponse.json({
    ok: true,
    mode: preVerifiedRun.mode,
    modelCalls: preVerifiedRun.modelCalls,
    track: "Google DeepMind Encode London Hackathon - Gemini 4 Argon Autonomous Agent",
    primaryModel: GEMINI_4_ARGON_MODEL_ID,
    companionModels: ARGON_COMPANION_MODELS,
    toolkitManifest: ARGON_TOOLKIT_MANIFEST,
    forbiddenLegacyParameters: FORBIDDEN_ARGON_PARAMETERS,
    persona: DEMO_PERSONA,
    configValidation,
    interactionsCreatePreview: preVerifiedRun.stages.stage4.interactionsPayload,
    sdkSnippets: preVerifiedRun.stages.stage4.sdkSnippets,
    autonomousRun: preVerifiedRun,
  });
}

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);
  if (!checkGeminiPostRateLimit(ip)) {
    return NextResponse.json(
      {
        ok: false,
        error: "RATE_LIMIT_EXCEEDED",
      },
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }

  let body: Record<string, unknown> = {};
  try {
    const parsed = (await request.json()) as unknown;
    if (parsed && typeof parsed === "object") {
      body = parsed as Record<string, unknown>;
    }
  } catch {
    body = {};
  }

  const thinkingLevelRaw =
    typeof body.thinkingLevel === "string"
      ? body.thinkingLevel
      : typeof body.thinking_level === "string"
        ? body.thinking_level
        : "medium";

  const validation = validateArgonRequestConfig({
    model:
      typeof body.model === "string" ? body.model : GEMINI_4_ARGON_MODEL_ID,
    thinking_level: thinkingLevelRaw,
    background:
      typeof body.background === "boolean" ? body.background : true,
    max_output_tokens:
      typeof body.maxOutputTokens === "number"
        ? body.maxOutputTokens
        : 131_072,
    thinking_budget: body.thinking_budget ?? body.thinkingBudget,
    temperature: body.temperature,
    top_p: body.top_p ?? body.topP,
    top_k: body.top_k ?? body.topK,
    cached_content: body.cached_content ?? body.cachedContent,
    autonomousMultiStep: true,
  });

  if (!validation.valid) {
    return NextResponse.json(
      {
        ok: false,
        error: "INVALID_GEMINI_4_ARGON_CONFIG",
        validation,
      },
      { status: 400 },
    );
  }

  const thinkingLevel = (validation.normalizedConfig?.thinking_level ??
    "medium") as ArgonThinkingLevel;

  const preferredEnclaveModel =
    body.preferredEnclaveModel === "kimi-k3" ? "kimi-k3" : "gemma4-31b";

  // Extract ephemeral per-request key without ever logging, persisting, or echoing it
  const ephemeralGeminiKey =
    typeof body.geminiApiKey === "string" && body.geminiApiKey.trim().length > 0
      ? body.geminiApiKey.trim()
      : undefined;

  const autonomousRun = await runArgonAutonomousWorkflow({
    taskPrompt:
      typeof body.taskPrompt === "string"
        ? body.taskPrompt
        : DEFAULT_TASK_PROMPT,
    thinkingLevel,
    background: validation.normalizedConfig?.background ?? true,
    injectFaultToTestSelfHealing: Boolean(body.injectFaultToTestSelfHealing),
    humanApprovedExternalAction: Boolean(body.humanApprovedExternalAction),
    preferredEnclaveModel,
    geminiApiKey: ephemeralGeminiKey,
    enableLiveEnclaveInference: true,
    atlasRunner: serverAtlasRunner,
    receiptRecorder: serverReceiptRecorder,
  });

  return NextResponse.json({
    ok: true,
    mode: autonomousRun.mode,
    modelCalls: autonomousRun.modelCalls,
    primaryModel: GEMINI_4_ARGON_MODEL_ID,
    companionModels: ARGON_COMPANION_MODELS,
    persona: DEMO_PERSONA,
    validation,
    interactionsCreatePayload: autonomousRun.stages.stage4.interactionsPayload,
    sdkSnippets: autonomousRun.stages.stage4.sdkSnippets,
    autonomousRun,
  });
}
