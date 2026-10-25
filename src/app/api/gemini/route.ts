import { NextResponse, connection } from "next/server";
import {
  ALLOWED_PLANNER_TOOLS,
  ARGON_COMPANION_MODELS,
  ARGON_TOOLKIT_MANIFEST,
  buildInteractionsCreatePayload,
  buildTaskDescriptor,
  DATA_SENT_TO_GOOGLE,
  DEMO_PERSONA,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  generateInteractionsSdkSnippets,
  HONEST_DATA_HANDLING_STATEMENT,
  validateArgonRequestConfig,
} from "@/lib/gemini";

/**
 * Content-free metadata endpoint (`GET /api/gemini`).
 *
 * Wave 6 (W6-A): The old full-text `POST /api/gemini` path has been removed so the
 * server never receives task text. All private redaction, `TaskDescriptor` construction,
 * plan execution, corpus ranking, and Tinfoil enclave invocation run in the browser
 * (`src/lib/agent-client/`), and planning uses `POST /api/gemini/plan` (closed schema in,
 * closed plan out).
 */
export async function GET() {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next.js request store.
  }

  const taskDescriptor = buildTaskDescriptor({
    taskKind: "review",
    inputTokenEstimate: 64,
    redactionCounts: { SECRET: 1, EMAIL: 1, DIGITS: 2, TOTAL: 2 },
    verification: {
      mechanicalRedactionPassed: true,
      attestedPiiFilterVerified: false,
      bucketAligned4096: true,
    },
    allowedTools: ALLOWED_PLANNER_TOOLS,
  });

  const configValidation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: "medium",
    background: true,
    max_output_tokens: 131_072,
    max_context_tokens: 1_000_000,
    autonomousMultiStep: true,
  });

  const interactionsCreatePreview = buildInteractionsCreatePayload({
    taskDescriptor,
    thinkingLevel: "medium",
    background: true,
    maxOutputTokens: 131_072,
  });

  const sdkSnippets = generateInteractionsSdkSnippets(interactionsCreatePreview);

  return NextResponse.json(
    {
      ok: true,
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      dataHandling: HONEST_DATA_HANDLING_STATEMENT,
      taskDescriptor,
      track:
        "Google DeepMind Encode London Hackathon - Gemini 4 Argon Split-Knowledge Agent",
      primaryModel: GEMINI_4_ARGON_MODEL_ID,
      companionModels: ARGON_COMPANION_MODELS,
      toolkitManifest: ARGON_TOOLKIT_MANIFEST,
      forbiddenLegacyParameters: FORBIDDEN_ARGON_PARAMETERS,
      persona: DEMO_PERSONA,
      configValidation,
      interactionsCreatePreview,
      sdkSnippets,
    },
    {
      headers: { "Cache-Control": "no-store" },
    },
  );
}
