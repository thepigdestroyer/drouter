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
import { anchorReceipt, explorerTx } from "@/lib/arc/registry";
import { createGlobalBucketLimiter, createTokenBucketLimiter } from "@/lib/ratelimit";

// POST runs paid inference (Tinfoil, and Gemini when a key is configured).
const geminiPostIpLimiter = createTokenBucketLimiter({
  name: "gemini-post",
  capacity: 5,
  refillPerSec: 1 / 12,
});
const geminiPostGlobalLimiter = createGlobalBucketLimiter({
  name: "gemini-post-global",
  capacity: 60,
  refillPerSec: 60 / 3600,
});
// Human-approved Arc anchoring spends testnet USDC gas from the verifier wallet.
const arcAnchorGlobalLimiter = createGlobalBucketLimiter({
  name: "gemini-arc-anchor-global",
  capacity: 10,
  refillPerSec: 10 / 3600,
});

const MAX_TASK_PROMPT_CHARS = 32_768;

// GET is hit on every /argon page load, so it serves a cached simulated run
// and never records receipts.
const GET_CACHE_MS = 10 * 60_000;
let cachedGet: { atMs: number; body: unknown } | null = null;

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

  const nowMs = Date.now();
  if (cachedGet && nowMs - cachedGet.atMs < GET_CACHE_MS) {
    return NextResponse.json(cachedGet.body);
  }

  const preVerifiedRun = await runArgonAutonomousWorkflow({
    taskPrompt: DEFAULT_TASK_PROMPT,
    thinkingLevel: "medium",
    background: true,
    injectFaultToTestSelfHealing: true,
    humanApprovedExternalAction: false,
    preferredEnclaveModel: "gemma4-31b",
    atlasRunner: serverAtlasRunner,
  });

  const configValidation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: "medium",
    background: true,
    max_output_tokens: 131_072,
    max_context_tokens: 1_000_000,
    autonomousMultiStep: true,
  });

  const body = {
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
  };
  cachedGet = { atMs: nowMs, body };
  return NextResponse.json(body);
}

export async function POST(request: NextRequest) {
  const limited = geminiPostIpLimiter.check(request);
  if (limited) return limited;
  const globalCheck = geminiPostGlobalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return NextResponse.json(
      { ok: false, error: "RATE_LIMIT_EXCEEDED" },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  let body: Record<string, unknown> = {};
  try {
    const parsed = (await request.json()) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      body = parsed as Record<string, unknown>;
    }
  } catch {
    body = {};
  }

  if (typeof body.taskPrompt === "string" && body.taskPrompt.length > MAX_TASK_PROMPT_CHARS) {
    return NextResponse.json(
      { ok: false, error: "TASK_PROMPT_TOO_LONG", maxChars: MAX_TASK_PROMPT_CHARS },
      { status: 413 },
    );
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

  // The human approved the external action, so anchor the signed run digest on
  // Arc for real. Everything else in Stage 5 stays simulated and is labelled so.
  let arcAnchor:
    | { broadcast: true; txHash: string; explorerUrl: string; receiptHash: string }
    | { broadcast: false; reason: string }
    | undefined;
  if (Boolean(body.humanApprovedExternalAction)) {
    const receiptHash = `0x${autonomousRun.stages.stage6.forensicProofDigestHex}` as `0x${string}`;
    if (!/^0x[0-9a-f]{64}$/i.test(receiptHash)) {
      arcAnchor = { broadcast: false, reason: "Run digest is not a 32-byte hash." };
    } else if (!arcAnchorGlobalLimiter.consume(1).allowed) {
      arcAnchor = { broadcast: false, reason: "Hourly Arc anchoring quota reached. Try again later." };
    } else {
      const txHash = await anchorReceipt(receiptHash);
      arcAnchor = txHash
        ? { broadcast: true, txHash, explorerUrl: explorerTx(txHash), receiptHash }
        : { broadcast: false, reason: "Arc verifier wallet is not configured or the transaction failed." };
    }
  }

  return NextResponse.json({
    ok: true,
    mode: autonomousRun.mode,
    arcAnchor,
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
