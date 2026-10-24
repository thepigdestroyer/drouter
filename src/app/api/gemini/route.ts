import { NextRequest, NextResponse, connection } from "next/server";
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
} from "@/lib/gemini";

export async function GET() {
  await connection();

  const preVerifiedRun = await runArgonAutonomousWorkflow({
    taskPrompt: DEFAULT_TASK_PROMPT,
    thinkingLevel: "high",
    background: true,
    injectFaultToTestSelfHealing: true,
    humanApprovedExternalAction: false,
    preferredEnclaveModel: "gemma4-31b",
  });

  const configValidation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: "high",
    background: true,
    max_output_tokens: 131_072,
    max_context_tokens: 1_000_000,
    autonomousMultiStep: true,
  });

  return NextResponse.json({
    ok: true,
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
        : "high";

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
    "high") as ArgonThinkingLevel;

  const preferredEnclaveModel =
    body.preferredEnclaveModel === "kimi-k3" ? "kimi-k3" : "gemma4-31b";

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
    geminiApiKey:
      typeof body.geminiApiKey === "string" ? body.geminiApiKey : undefined,
  });

  return NextResponse.json({
    ok: true,
    primaryModel: GEMINI_4_ARGON_MODEL_ID,
    companionModels: ARGON_COMPANION_MODELS,
    persona: DEMO_PERSONA,
    validation,
    interactionsCreatePayload: autonomousRun.stages.stage4.interactionsPayload,
    sdkSnippets: autonomousRun.stages.stage4.sdkSnippets,
    autonomousRun,
  });
}
