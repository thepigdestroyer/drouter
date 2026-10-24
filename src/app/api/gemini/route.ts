import { NextRequest, NextResponse, connection } from "next/server";
import {
  recordAgentVerificationReceipt,
  runAtlasHybridSearch,
} from "@/lib/atlas";
import {
  ARGON_COMPANION_MODELS,
  ARGON_TOOLKIT_MANIFEST,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  DEFAULT_TASK_PROMPT,
  DEMO_PERSONA,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  HONEST_DATA_HANDLING_STATEMENT,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  redactForNonEnclaveBoundary,
  runArgonAutonomousWorkflow,
  ToolPolicyViolationError,
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
const MAX_EPHEMERAL_API_KEY_CHARS = 256;

// GET is hit on every /argon page load, so it serves a cached run
// without triggering paid inference calls and never records receipts.
const GET_CACHE_MS = 10 * 60_000;
let cachedGet: { atMs: number; body: unknown } | null = null;

async function serverAtlasRunner(query: string): Promise<AtlasHybridRunnerResult> {
  const redacted = await redactForNonEnclaveBoundary(query, {
    enableAttestedFilter: false,
  });
  const res = await runAtlasHybridSearch(redacted.text, { limit: 5 });
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
    enableLiveEnclaveInference: false,
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
    planner: preVerifiedRun.planner,
    dataSentToGoogle: DATA_SENT_TO_GOOGLE,
    dataHandling: HONEST_DATA_HANDLING_STATEMENT,
    taskDescriptor: preVerifiedRun.taskDescriptor,
    modelCalls: preVerifiedRun.modelCalls,
    track: "Google DeepMind Encode London Hackathon - Gemini 4 Argon Split-Knowledge Agent",
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

  if (
    typeof body.geminiApiKey === "string" &&
    body.geminiApiKey.length > MAX_EPHEMERAL_API_KEY_CHARS
  ) {
    return NextResponse.json(
      { ok: false, error: "INVALID_GEMINI_API_KEY" },
      { status: 400 },
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

  let autonomousRun;
  try {
    autonomousRun = await runArgonAutonomousWorkflow({
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
  } catch (err) {
    if (
      err instanceof ContentFreeEgressError ||
      err instanceof PrivacyInvariantViolationError
    ) {
      return NextResponse.json(
        {
          ok: false,
          error: "PRIVACY_INVARIANT_VIOLATION",
          message:
            "Outbound planner payload violated the content-free egress firewall; request aborted.",
        },
        { status: 422 },
      );
    }
    if (err instanceof ToolPolicyViolationError) {
      return NextResponse.json(
        {
          ok: false,
          error: "TOOL_POLICY_VIOLATION",
          message: "Planner tool call violated allowlist or argument schema.",
        },
        { status: 422 },
      );
    }
    if (err instanceof PlannerBudgetExceededError) {
      return NextResponse.json(
        {
          ok: false,
          error: "PLANNER_BUDGET_EXCEEDED",
          message: "Planner exceeded step or wall-clock budget.",
        },
        { status: 422 },
      );
    }
    throw err;
  }

  // Only when the human explicitly approved the external action do we anchor the
  // signed run digest on Circle Arc Testnet for real.
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
      const anchorAction = autonomousRun.stages.stage5.pendingActions.find(
        (a) => a.kind === "anchor_arc_receipt",
      );
      if (txHash && anchorAction) anchorAction.txHashHex = txHash;
    }
  }

  return NextResponse.json({
    ok: true,
    mode: autonomousRun.mode,
    planner: autonomousRun.planner,
    dataSentToGoogle: DATA_SENT_TO_GOOGLE,
    dataHandling: HONEST_DATA_HANDLING_STATEMENT,
    taskDescriptor: autonomousRun.taskDescriptor,
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
