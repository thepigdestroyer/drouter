import { GoogleGenAI } from "@google/genai";
import { canonicalJson } from "./canonical.js";
import {
  ARGON_CONFIDENTIAL_TOOLS,
  assertContentFree,
  assertGoogleBoundMessage,
  assertValidTaskDescriptor,
  assertValidToolCall,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  GEMINI_4_ARGON_MODEL_ID,
  MAX_PLANNER_STEPS,
  MAX_PLANNER_WALL_CLOCK_MS,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  SAFE_CALL_ID_REGEX,
  sanitizeUntrustedModelOutput,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  TaskDescriptorValidationError,
  ToolPolicyViolationError,
} from "./firewall.js";
import { getKeyRing } from "./keys.js";
import { signGeminiEgressReceipt } from "./receipts.js";
import { getLoadedSecret, resolveSecretsSource } from "./secrets-gcp.js";

const ALLOWED_INTERACTION_STATUSES = new Set([
  "completed",
  "in_progress",
  "requires_action",
  "failed",
  "cancelled",
]);

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
  const bucketedIfComplete =
    descriptor &&
    typeof descriptor === "object" &&
    !Array.isArray(descriptor) &&
    descriptor.redactionCounts &&
    typeof descriptor.redactionCounts === "object" &&
    !Array.isArray(descriptor.redactionCounts)
      ? {
          ...descriptor,
          redactionCounts: Object.fromEntries(
            Object.entries(descriptor.redactionCounts).map(([k, v]) => [
              k,
              typeof v === "number" &&
              Number.isInteger(v) &&
              !Object.is(v, -0) &&
              v >= 0 &&
              v <= 5
                ? Math.min(2, v)
                : v,
            ]),
          ),
        }
      : descriptor;
  const validated = assertValidTaskDescriptor(bucketedIfComplete);
  const tools = ARGON_CONFIDENTIAL_TOOLS.filter((t) =>
    validated.allowedTools.includes(t.name),
  );

  const createRequest = {
    model: GEMINI_4_ARGON_MODEL_ID,
    // Google only allows background interactions when it may store them; we never let it store.
    background: false,
    store: false,
    system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
    generation_config: {
      thinking_level: "medium",
      // A plan is a few tool calls; Gemini 4 Argon allows at most 32,768 output tokens.
      max_output_tokens: 8_192,
    },
    input: [
      {
        type: "text",
        text: canonicalJson(validated),
      },
    ],
    tools,
  };

  assertGoogleBoundMessage("taskDescriptor", validated, "$.taskDescriptor");
  assertContentFree(validated, "$.taskDescriptor");
  assertGoogleBoundMessage("createRequest", createRequest, "$.createRequest");
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

  const secretsSource = resolveSecretsSource(process.env.CORE_SECRETS_SOURCE);
  const envFallbackKey =
    secretsSource === "gcp-secret-manager"
      ? ""
      : typeof process.env.GEMINI_API_KEY === "string"
        ? process.env.GEMINI_API_KEY.trim()
        : "";
  const resolvedKey =
    (typeof apiKey === "string" ? apiKey.trim() : "") ||
    (getLoadedSecret("GEMINI_API_KEY") ?? "") ||
    envFallbackKey;

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
  const abortController = new AbortController();

  try {
    // Re-assert closed schema gate and content-free firewall immediately prior to network transmission.
    assertGoogleBoundMessage("createRequest", createRequest, "$.createRequest");
    assertContentFree(createRequest, "$.createRequest");

    const requestOptions = {
      timeout_ms: effectiveBudgetMs,
      retries: { strategy: "none" },
      fetch_options: { signal: abortController.signal },
    };

    const interaction = await withWallClockBudget(
      client.interactions.create(createRequest, requestOptions),
      startedAt,
      effectiveBudgetMs,
    ).finally(() => abortController.abort());

    const rawSteps = Array.isArray(interaction?.steps) ? interaction.steps : [];
    const fnCalls = rawSteps.filter((s) => s && s.type === "function_call");

    if (fnCalls.length > effectiveMaxSteps) {
      throw new PlannerBudgetExceededError("max_steps", effectiveMaxSteps);
    }

    const validatedSteps = [];
    for (let idx = 0; idx < fnCalls.length; idx++) {
      const call = fnCalls[idx];
      const toolName = typeof call.name === "string" ? call.name : "";
      if (!toolName) {
        throw new ToolPolicyViolationError("<missing>", [
          "Function call step is missing tool name.",
        ]);
      }
      const sanitizedArgs = assertValidToolCall(
        toolName,
        call.arguments ?? {},
        validatedDescriptor.allowedTools,
      );
      const safeCallId =
        typeof call.id === "string" &&
        SAFE_CALL_ID_REGEX.test(call.id) &&
        !/\d{4,}/.test(call.id)
          ? call.id
          : `call-${idx + 1}`;
      const validatedToolCall = {
        id: safeCallId,
        type: "function_call",
        name: toolName,
        arguments: { ...sanitizedArgs },
      };
      assertGoogleBoundMessage(
        "toolCall",
        validatedToolCall,
        `$.toolCall(${toolName})`,
      );
      assertContentFree(validatedToolCall, `$.toolCall(${toolName})`);
      validatedSteps.push({
        step: idx + 1,
        id: validatedToolCall.id,
        tool: validatedToolCall.name,
        arguments: { ...validatedToolCall.arguments },
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

    const safeInteractionId =
      typeof interaction?.id === "string" &&
      SAFE_CALL_ID_REGEX.test(interaction.id) &&
      !/\d{4,}/.test(interaction.id)
        ? interaction.id
        : undefined;
    const safeStatus =
      typeof interaction?.status === "string" &&
      ALLOWED_INTERACTION_STATUSES.has(interaction.status)
        ? interaction.status
        : "completed";

    return {
      ok: true,
      statusCode: 200,
      planner: GEMINI_4_ARGON_MODEL_ID,
      model: GEMINI_4_ARGON_MODEL_ID,
      interactionId: safeInteractionId,
      status: safeStatus,
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
