import { GoogleGenAI } from "@google/genai";
import { canonicalJson } from "./canonical.js";
import {
  ARGON_CONFIDENTIAL_TOOLS,
  assertContentFree,
  assertValidTaskDescriptor,
  assertValidToolCall,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  GEMINI_4_ARGON_MODEL_ID,
  MAX_PLANNER_STEPS,
  MAX_PLANNER_WALL_CLOCK_MS,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  sanitizeUntrustedModelOutput,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  TaskDescriptorValidationError,
  ToolPolicyViolationError,
} from "./firewall.js";
import { getKeyRing } from "./keys.js";
import { signGeminiEgressReceipt } from "./receipts.js";

async function withWallClockBudget(promise, startedAtMs, budgetMs) {
  const elapsed = Date.now() - startedAtMs;
  const remaining = budgetMs - elapsed;
  if (remaining <= 0) {
    throw new PlannerBudgetExceededError("wall_clock_timeout", budgetMs);
  }
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new PlannerBudgetExceededError("wall_clock_timeout", budgetMs));
        }, remaining);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/**
 * Builds the content-free `@google/genai` Interactions API request object for a validated `TaskDescriptor`
 * and verifies it passes `assertContentFree`.
 */
export function buildGeminiInteractionsRequest(descriptor) {
  const validated = assertValidTaskDescriptor(descriptor);
  const tools = ARGON_CONFIDENTIAL_TOOLS.filter((t) =>
    validated.allowedTools.includes(t.name),
  );

  const createRequest = {
    model: GEMINI_4_ARGON_MODEL_ID,
    background: true,
    system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
    generation_config: {
      thinking_level: "medium",
      max_output_tokens: 131_072,
    },
    input: [
      {
        type: "text",
        text: canonicalJson(validated),
      },
    ],
    tools,
  };

  assertContentFree(createRequest, "$.createRequest");
  return { validatedDescriptor: validated, createRequest };
}

/**
 * Executes `POST /agent/plan`:
 * 1. Validates the incoming `TaskDescriptor` strictly (enum fields, power-of-two bucketed token count,
 *    redaction counts capped at 5, `$INPUT` handle, no extra fields).
 * 2. Runs `assertContentFree` on the descriptor and on the outbound Gemini request.
 * 3. Canonicalises the exact outbound Gemini request bytes, computes SHA-256, and signs
 *    `{ sha256, epochHourSec, kind: "gemini-egress" }` with the attested `egress-signing` Ed25519 key.
 * 4. Calls `@google/genai` `client.interactions.create(...)` using `GEMINI_API_KEY`.
 *    If `GEMINI_API_KEY` is absent, returns `{ ok: false, planner: "unavailable", ... }` (never fakes output).
 * 5. Validates every returned tool call against the allowlist and strict JSON schemas.
 */
export async function planWithGemini({
  descriptor,
  apiKey,
  genaiClient,
  egressKeyPair,
  timestampSec,
  maxSteps = MAX_PLANNER_STEPS,
  wallClockBudgetMs = MAX_PLANNER_WALL_CLOCK_MS,
} = {}) {
  const { validatedDescriptor, createRequest } = buildGeminiInteractionsRequest(descriptor);
  const signingKey = egressKeyPair ?? getKeyRing()["egress-signing"];
  const egressReceipt = signGeminiEgressReceipt(createRequest, signingKey, timestampSec);

  const resolvedKey =
    (typeof apiKey === "string" ? apiKey.trim() : "") ||
    (typeof process.env.GEMINI_API_KEY === "string" ? process.env.GEMINI_API_KEY.trim() : "");

  if (!resolvedKey && !genaiClient) {
    return {
      ok: false,
      statusCode: 503,
      planner: "unavailable",
      error: "GEMINI_API_KEY is not configured in this enclave instance; planner is unavailable.",
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
      egressReceipt,
      egressReceipts: [egressReceipt],
    };
  }

  const client = genaiClient ?? new GoogleGenAI({ apiKey: resolvedKey });
  const effectiveMaxSteps = Math.min(
    MAX_PLANNER_STEPS,
    Math.max(1, Math.trunc(maxSteps || MAX_PLANNER_STEPS)),
  );
  const effectiveBudgetMs = Math.min(
    MAX_PLANNER_WALL_CLOCK_MS,
    Math.max(10, Math.trunc(wallClockBudgetMs || MAX_PLANNER_WALL_CLOCK_MS)),
  );

  const startedAt = Date.now();

  try {
    // Re-assert content-free firewall immediately prior to network transmission.
    assertContentFree(createRequest, "$.createRequest");

    const interaction = await withWallClockBudget(
      client.interactions.create(createRequest),
      startedAt,
      effectiveBudgetMs,
    );

    const rawSteps = Array.isArray(interaction?.steps) ? interaction.steps : [];
    const fnCalls = rawSteps.filter(
      (s) => s && s.type === "function_call" && typeof s.name === "string",
    );

    if (fnCalls.length > effectiveMaxSteps) {
      throw new PlannerBudgetExceededError("max_steps", effectiveMaxSteps);
    }

    const validatedSteps = [];
    for (let idx = 0; idx < fnCalls.length; idx++) {
      const call = fnCalls[idx];
      const toolName = call.name;
      const sanitizedArgs = assertValidToolCall(
        toolName,
        call.arguments ?? {},
        validatedDescriptor.allowedTools,
      );
      validatedSteps.push({
        step: idx + 1,
        id: typeof call.id === "string" && call.id.length <= 64 ? call.id : `call-${idx + 1}`,
        tool: toolName,
        arguments: sanitizedArgs,
      });
    }

    let rawOutputText = typeof interaction?.output_text === "string" ? interaction.output_text : "";
    if (!rawOutputText && rawSteps.length > 0) {
      for (const s of rawSteps) {
        if (s && s.type === "model_output" && Array.isArray(s.content)) {
          const text = s.content
            .map((c) => (typeof c?.text === "string" ? c.text : ""))
            .join("")
            .trim();
          if (text) {
            rawOutputText = text;
            break;
          }
        }
      }
    }

    const summary =
      sanitizeUntrustedModelOutput(rawOutputText) ||
      `Gemini 4 Argon control-plane plan verified (${validatedSteps.length} tool call(s) over content-free handles).`;

    return {
      ok: true,
      statusCode: 200,
      planner: GEMINI_4_ARGON_MODEL_ID,
      model: GEMINI_4_ARGON_MODEL_ID,
      interactionId: typeof interaction?.id === "string" ? interaction.id : undefined,
      status: typeof interaction?.status === "string" ? interaction.status : "completed",
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
      plan: {
        taskKind: validatedDescriptor.taskKind,
        inputHandle: "$INPUT",
        inputTokenEstimate: validatedDescriptor.inputTokenEstimate,
        steps: validatedSteps,
        toolCalls: validatedSteps.map((s) => ({
          id: s.id,
          name: s.tool,
          arguments: s.arguments,
        })),
        summary,
      },
      egressReceipt,
      egressReceipts: [egressReceipt],
    };
  } catch (err) {
    if (
      err instanceof TaskDescriptorValidationError ||
      err instanceof ContentFreeEgressError ||
      err instanceof PrivacyInvariantViolationError ||
      err instanceof ToolPolicyViolationError ||
      err instanceof PlannerBudgetExceededError
    ) {
      throw err;
    }

    const rawMsg = err instanceof Error ? err.message : "Gemini Interactions API call failed";
    const safeMsg = resolvedKey ? rawMsg.split(resolvedKey).join("[REDACTED_KEY]") : rawMsg;

    return {
      ok: false,
      statusCode: 503,
      planner: "unavailable",
      error: `Gemini Interactions API unavailable: ${safeMsg.replace(/[\u2013\u2014]/g, "-").slice(0, 180)}`,
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
      egressReceipt,
      egressReceipts: [egressReceipt],
    };
  }
}
