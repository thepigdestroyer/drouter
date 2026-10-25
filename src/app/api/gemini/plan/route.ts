import { GoogleGenAI } from "@google/genai";
import { NextResponse } from "next/server";
import {
  assertClosedPlanSchema,
  assertNoDuplicateJsonKeys,
  buildGeminiCreateRequestFromDescriptor,
  extractEd25519RawPublicKeyHex,
  NEXT_SERVER_RECEIPT_LABEL,
  SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
  verifyEgressReceiptClient,
} from "@/lib/agent-client/plan-schema";
import {
  getCachedCoreAttestation,
  proxyCoreRequest,
  type CoreProxyResult,
} from "@/lib/core-proxy";
import {
  assertContentFree,
  assertGoogleBoundMessage,
  assertValidToolCall,
} from "@/lib/gemini/egress-schemas";
import {
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  GEMINI_4_ARGON_MODEL_ID,
  MAX_PLANNER_STEPS,
  MAX_PLANNER_WALL_CLOCK_MS,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  SAFE_CALL_ID_REGEX,
  sanitizeUntrustedModelOutput,
  ToolPolicyViolationError,
  type ClosedAgentPlan,
  type ClosedPlannerStep,
  type GeminiEgressReceipt,
  type GenAIInteractionsClientLike,
  type PlannerToolName,
} from "@/lib/gemini/shared";
import {
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
} from "@/lib/ratelimit";
import { canonicalJson } from "@/lib/transparency/log";
import { appendVerificationEventToLog } from "@/lib/transparency/store";

export const MAX_PLAN_REQUEST_BODY_BYTES = 16_384;

const ALLOWED_INTERACTION_STATUSES = new Set<string>([
  "completed",
  "in_progress",
  "requires_action",
  "failed",
  "cancelled",
]);

const planIpLimiter = createTokenBucketLimiter({
  name: "gemini-plan-ip",
  capacity: 15,
  refillPerSec: 1 / 4,
});

const planGlobalLimiter = createGlobalBucketLimiter({
  name: "gemini-plan-global",
  capacity: 120,
  refillPerSec: 120 / 3600,
});

type CorePlanHandlerOverride = (
  descriptorJson: string,
) => Promise<CoreProxyResult>;

const globalForGeminiPlan = globalThis as unknown as {
  __drouterTestCorePlanHandler?: CorePlanHandlerOverride | null;
  __drouterTestCoreAttestedEgressKey?: string | null;
  __drouterTestPlanGenAIClient?: GenAIInteractionsClientLike | null;
  __drouterTestPlanGeminiApiKey?: string | null;
};

/**
 * Test helper to override `/api/core/agent/plan` upstream proxy behavior in unit tests.
 */
export function setCorePlanHandlerForTests(
  fn: CorePlanHandlerOverride | null | undefined,
  attestedEgressPublicKeyHex?: string | null,
): void {
  globalForGeminiPlan.__drouterTestCorePlanHandler = fn ?? null;
  globalForGeminiPlan.__drouterTestCoreAttestedEgressKey =
    attestedEgressPublicKeyHex ?? null;
}

/**
 * Test helper to inject a mock `@google/genai` client for Next-server planning unit tests.
 */
export function setPlanGenAIClientForTests(
  client: GenAIInteractionsClientLike | null | undefined,
  apiKeyOverride?: string | null,
): void {
  globalForGeminiPlan.__drouterTestPlanGenAIClient = client ?? null;
  globalForGeminiPlan.__drouterTestPlanGeminiApiKey = apiKeyOverride ?? null;
}

async function withWallClockBudget<T>(
  promise: Promise<T>,
  startedAtMs: number,
  budgetMs: number,
): Promise<T> {
  const elapsed = Date.now() - startedAtMs;
  const remaining = budgetMs - elapsed;
  if (remaining <= 0) {
    throw new PlannerBudgetExceededError("wall_clock_timeout", budgetMs);
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
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

async function readBoundedPlanBody(
  request: Request,
  maxBytes = MAX_PLAN_REQUEST_BODY_BYTES,
): Promise<
  | { ok: true; parsed: unknown }
  | { ok: false; status: 400 | 413; error: string; message: string }
> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isFinite(declared) || declared < 0) {
      return {
        ok: false,
        status: 400,
        error: "invalid_content_length",
        message: "Invalid Content-Length header.",
      };
    }
    if (declared > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: "payload_too_large",
        message: `Request body exceeds maximum size of ${maxBytes} bytes.`,
      };
    }
  }

  if (!request.body) {
    return {
      ok: false,
      status: 400,
      error: "empty_body",
      message: "POST /api/gemini/plan requires a JSON TaskDescriptor body.",
    };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          return {
            ok: false,
            status: 413,
            error: "payload_too_large",
            message: `Request body exceeds maximum size of ${maxBytes} bytes.`,
          };
        }
        chunks.push(value);
      }
    }
  } catch {
    return {
      ok: false,
      status: 400,
      error: "body_read_failed",
      message: "Failed to read request body.",
    };
  }

  if (total === 0) {
    return {
      ok: false,
      status: 400,
      error: "empty_body",
      message: "POST /api/gemini/plan requires a non-empty JSON TaskDescriptor body.",
    };
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  const rawText = new TextDecoder("utf-8", { fatal: true }).decode(combined);
  try {
    const parsed = JSON.parse(rawText) as unknown;
    assertNoDuplicateJsonKeys(rawText);
    return { ok: true, parsed };
  } catch {
    return {
      ok: false,
      status: 400,
      error: "invalid_json",
      message: "Request body must be valid JSON without duplicate keys.",
    };
  }
}

export async function POST(request: Request) {
  const limited = planIpLimiter.check(request);
  if (limited) return limited;

  const globalCheck = planGlobalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return NextResponse.json(
      { ok: false, error: "rate_limit_exceeded" },
      {
        status: 429,
        headers: {
          "Retry-After": String(globalCheck.retryAfterSec),
          "Cache-Control": "no-store",
        },
      },
    );
  }

  const rawUrl = request.url || "http://localhost/api/gemini/plan";
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl, "http://localhost");
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid_url", message: "Malformed request URL." },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  if (rawUrl.includes("?") || parsedUrl.search.length > 0) {
    return NextResponse.json(
      {
        ok: false,
        error: "query_parameters_forbidden",
        message: "Query parameters are not permitted on POST /api/gemini/plan.",
      },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  const bodyRes = await readBoundedPlanBody(request);
  if (!bodyRes.ok) {
    return NextResponse.json(
      {
        ok: false,
        error: bodyRes.error,
        message: bodyRes.message,
      },
      { status: bodyRes.status, headers: { "Cache-Control": "no-store" } },
    );
  }

  let built: ReturnType<typeof buildGeminiCreateRequestFromDescriptor>;
  try {
    built = buildGeminiCreateRequestFromDescriptor(bodyRes.parsed);
  } catch (err) {
    return NextResponse.json(
      {
        ok: false,
        error: "invalid_task_descriptor",
        message:
          err instanceof Error
            ? err.message
            : "Request body failed closed TaskDescriptor schema validation.",
      },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  const { validatedDescriptor, createRequest, canonicalRequest, requestSha256 } =
    built;
  const descriptorJson = canonicalJson(validatedDescriptor);

  // =========================================================================
  // 1. Prefer `/api/core/agent/plan` (Google Confidential Space) when available
  // =========================================================================
  try {
    const coreHandler = globalForGeminiPlan.__drouterTestCorePlanHandler;
    const coreRes: CoreProxyResult = coreHandler
      ? await coreHandler(descriptorJson)
      : await proxyCoreRequest(
          new Request("http://localhost/api/core/agent/plan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: descriptorJson,
          }),
          ["agent", "plan"],
        );

    if (coreRes.status === 200) {
      const coreData = JSON.parse(coreRes.body) as Record<string, unknown>;
      if (coreData && coreData.ok === true && coreData.plan && coreData.egressReceipt) {
        const validatedPlan = assertClosedPlanSchema(
          coreData.plan,
          validatedDescriptor.allowedTools,
          "$.corePlan",
        );

        const rawCoreReceipt = coreData.egressReceipt as Record<string, unknown>;
        const candidateReceipt = {
          ...rawCoreReceipt,
          signer: "sealed-google-computer" as const,
          signerLabel: SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
          keyId: "egress-signing" as const,
        };
        const attestedCoreEgressKey = extractEd25519RawPublicKeyHex(
          getCachedCoreAttestation()?.keys.egress ??
            globalForGeminiPlan.__drouterTestCoreAttestedEgressKey ??
            "",
        );
        const verifiedReceiptRes = verifyEgressReceiptClient(
          candidateReceipt,
          attestedCoreEgressKey || undefined,
          validatedDescriptor,
        );
        if (
          !verifiedReceiptRes.ok ||
          !verifiedReceiptRes.receipt ||
          verifiedReceiptRes.receipt.sha256 !== requestSha256 ||
          verifiedReceiptRes.receipt.canonicalRequest !== canonicalRequest
        ) {
          return NextResponse.json(
            {
              ok: false,
              error: "invalid_core_egress_receipt",
              message: verifiedReceiptRes.detail,
            },
            { status: 502, headers: { "Cache-Control": "no-store" } },
          );
        }

        const logEntry = await appendVerificationEventToLog({
          kind: "verification_event",
          nodeId: "tinfoil-router",
          nodeKind: "tinfoil",
          ok: true,
          measurement: verifiedReceiptRes.receipt.sha256,
          evidenceHash: verifiedReceiptRes.receipt.sha256,
          anchorOnArc: false,
        });

        const egressReceipt: GeminiEgressReceipt = {
          ...verifiedReceiptRes.receipt,
          signer: "sealed-google-computer",
          signerLabel: SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
          keyId: "egress-signing",
          transparencyLog: {
            leafIndex: logEntry.event.index,
            leafHash: logEntry.event.leafHash,
            treeSize: logEntry.signedTreeHead.treeSize,
            rootHash: logEntry.signedTreeHead.rootHash,
            auditPath: logEntry.inclusionProof.auditPath,
            operatorPublicKey: logEntry.signedTreeHead.operatorPublicKey,
            treeHeadSignature: logEntry.signedTreeHead.signature,
          },
        };

        return NextResponse.json(
          {
            ok: true,
            planner: GEMINI_4_ARGON_MODEL_ID,
            plannerSource: "sealed-google-computer",
            model: GEMINI_4_ARGON_MODEL_ID,
            interactionId:
              typeof coreData.interactionId === "string" &&
              SAFE_CALL_ID_REGEX.test(coreData.interactionId)
                ? coreData.interactionId
                : undefined,
            status:
              typeof coreData.status === "string" &&
              ALLOWED_INTERACTION_STATUSES.has(coreData.status)
                ? coreData.status
                : "completed",
            dataSentToGoogle: DATA_SENT_TO_GOOGLE,
            egressFirewallVerified: true,
            plan: validatedPlan,
            egressReceipt,
            egressReceipts: [egressReceipt],
          },
          { status: 200, headers: { "Cache-Control": "no-store" } },
        );
      }
    } else if (coreRes.status === 422 || coreRes.status === 504) {
      const errData = JSON.parse(coreRes.body) as Record<string, unknown>;
      return NextResponse.json(errData, {
        status: coreRes.status,
        headers: { "Cache-Control": "no-store" },
      });
    }
  } catch (err) {
    if (
      err instanceof ContentFreeEgressError ||
      err instanceof PrivacyInvariantViolationError ||
      err instanceof ToolPolicyViolationError
    ) {
      return NextResponse.json(
        {
          ok: false,
          error: "tool_policy_violation",
          message: err.message,
        },
        { status: 422, headers: { "Cache-Control": "no-store" } },
      );
    }
    // If `/api/core/agent/plan` is unreachable or not deployed, fall through to Next server check
  }

  // =========================================================================
  // 2. Else Gemini on the Next server when `GEMINI_API_KEY` is set
  // =========================================================================
  const injectedClient = globalForGeminiPlan.__drouterTestPlanGenAIClient;
  const resolvedKey =
    (globalForGeminiPlan.__drouterTestPlanGeminiApiKey !== undefined &&
    globalForGeminiPlan.__drouterTestPlanGeminiApiKey !== null
      ? globalForGeminiPlan.__drouterTestPlanGeminiApiKey.trim()
      : typeof process !== "undefined"
        ? process.env?.GEMINI_API_KEY?.trim() ?? ""
        : "") || "";

  if (!resolvedKey && !injectedClient) {
    // 3. Honest "planner unavailable" state (never a fake plan)
    return NextResponse.json(
      {
        ok: false,
        planner: "unavailable",
        plannerSource: "unavailable",
        error: "planner_unavailable",
        unavailableReason: "no_key",
        attemptedLiveCall: false,
        message:
          "Gemini planner is unavailable because neither deroute-core nor GEMINI_API_KEY is configured.",
        dataSentToGoogle: "none (planner unavailable)",
        egressFirewallVerified: true,
        plan: null,
        egressReceipt: null,
      },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const client: GenAIInteractionsClientLike =
    injectedClient ??
    (new GoogleGenAI({
      apiKey: resolvedKey,
    }) as unknown as GenAIInteractionsClientLike);

  const startedAt = Date.now();
  const abortController = new AbortController();

  try {
    assertGoogleBoundMessage("createRequest", createRequest, "$.createRequest");
    assertContentFree(createRequest, "$.createRequest");

    const requestOptions = {
      timeout_ms: MAX_PLANNER_WALL_CLOCK_MS,
      retries: { strategy: "none" },
      fetch_options: { signal: abortController.signal },
    };

    const interaction = await withWallClockBudget(
      client.interactions.create(createRequest, requestOptions),
      startedAt,
      MAX_PLANNER_WALL_CLOCK_MS,
    ).finally(() => abortController.abort());

    const rawSteps = Array.isArray(interaction?.steps) ? interaction.steps : [];
    const fnCalls = rawSteps.filter((s) => s && s.type === "function_call");

    if (fnCalls.length === 0) {
      throw new ToolPolicyViolationError("<empty_plan>", [
        "Planner returned zero tool call steps; at least one tool step is required.",
      ]);
    }

    if (fnCalls.length > MAX_PLANNER_STEPS) {
      throw new PlannerBudgetExceededError("max_steps", MAX_PLANNER_STEPS);
    }

    const validatedSteps: ClosedPlannerStep[] = [];
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
        type: "function_call" as const,
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
        tool: validatedToolCall.name as PlannerToolName,
        arguments: { ...validatedToolCall.arguments },
      });
    }

    let rawOutputText =
      typeof interaction?.output_text === "string" ? interaction.output_text : "";
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

    const candidatePlan: ClosedAgentPlan = {
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
    };

    const validatedPlan = assertClosedPlanSchema(
      candidatePlan,
      validatedDescriptor.allowedTools,
      "$.plan",
    );

    const logEntry = await appendVerificationEventToLog({
      kind: "verification_event",
      nodeId: "tinfoil-router",
      nodeKind: "tinfoil",
      ok: true,
      measurement: requestSha256,
      evidenceHash: requestSha256,
      anchorOnArc: false,
    });

    const egressReceipt: GeminiEgressReceipt = {
      canonicalRequest,
      sha256: requestSha256,
      epochHourSec: logEntry.signedTreeHead.timestampSec,
      kind: "gemini-egress",
      signer: "next-server",
      signerLabel: NEXT_SERVER_RECEIPT_LABEL,
      signature: logEntry.signedTreeHead.signature,
      publicKey: logEntry.signedTreeHead.operatorPublicKey,
      keyId: "operator-tree-head",
      transparencyLog: {
        leafIndex: logEntry.event.index,
        leafHash: logEntry.event.leafHash,
        treeSize: logEntry.signedTreeHead.treeSize,
        rootHash: logEntry.signedTreeHead.rootHash,
        auditPath: logEntry.inclusionProof.auditPath,
        operatorPublicKey: logEntry.signedTreeHead.operatorPublicKey,
        treeHeadSignature: logEntry.signedTreeHead.signature,
      },
    };

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

    return NextResponse.json(
      {
        ok: true,
        planner: GEMINI_4_ARGON_MODEL_ID,
        plannerSource: "next-server",
        model: GEMINI_4_ARGON_MODEL_ID,
        interactionId: safeInteractionId,
        status: safeStatus,
        dataSentToGoogle: DATA_SENT_TO_GOOGLE,
        egressFirewallVerified: true,
        plan: validatedPlan,
        egressReceipt,
        egressReceipts: [egressReceipt],
      },
      { status: 200, headers: { "Cache-Control": "no-store" } },
    );
  } catch (err) {
    if (
      err instanceof ContentFreeEgressError ||
      err instanceof PrivacyInvariantViolationError
    ) {
      return NextResponse.json(
        {
          ok: false,
          error: "content_free_violation",
          message: err.message,
        },
        { status: 400, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (err instanceof ToolPolicyViolationError) {
      return NextResponse.json(
        {
          ok: false,
          error: "tool_policy_violation",
          toolName: err.toolName,
          message: err.message,
          details: err.validationErrors,
        },
        { status: 422, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (err instanceof PlannerBudgetExceededError) {
      return NextResponse.json(
        {
          ok: false,
          error: "planner_budget_exceeded",
          kind: err.kind,
          message: err.message,
        },
        { status: 504, headers: { "Cache-Control": "no-store" } },
      );
    }

    const rawMsg =
      err instanceof Error ? err.message : "Gemini Interactions API call failed";
    const safeMsg = resolvedKey
      ? rawMsg.split(resolvedKey).join("[REDACTED_KEY]")
      : rawMsg;

    return NextResponse.json(
      {
        ok: false,
        planner: "unavailable",
        plannerSource: "unavailable",
        error: "gemini_call_failed",
        unavailableReason: "gemini_call_failed",
        attemptedLiveCall: true,
        message: `The Gemini call failed: ${safeMsg.replace(/[\u2013\u2014]/g, "-").slice(0, 180)}`,
        dataSentToGoogle: "none (planner unavailable)",
        egressFirewallVerified: true,
        plan: null,
        egressReceipt: null,
      },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}
