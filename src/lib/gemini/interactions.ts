/**
 * Google DeepMind Gemini 4 Argon (`gemini-4-argon`) Split-Knowledge Control Plane,
 * Content-Free Egress Firewall (`assertContentFree`), Strict Tool Schema Validator,
 * Step/Time Budget Enforcer, and Attested Tinfoil Enclave Planner Loop (`src/lib/gemini/interactions.ts`).
 *
 * Architectural guarantee (D1 & D2):
 * - Gemini is a control plane only. It never receives user content, enclave output text,
 *   search queries, or anything derived from user text other than numbers, booleans,
 *   allowlisted enums, fixed-format SHA-256 hashes, and opaque handles (`$INPUT`, `$RESULT_<n>`).
 * - Every outbound request to Google Gemini passes through `assertContentFree(value)`.
 * - Every tool call is validated against a strict function allowlist and JSON schema.
 * - Step count and wall-clock time budgets are strictly enforced.
 * - Model output is untrusted data, never executed, and never authoritative for gates.
 */

import { estimateTokens } from "@/lib/privacy/padding";
import { canonicalJson } from "@/lib/transparency/log";
import {
  assertAnyToolResultSchema,
  assertFunctionResultStepSchema,
  assertGeminiCreateRequestSchema,
  assertGeminiFollowUpRequestSchema,
  assertGoogleBoundMessage,
  assertInteractionsCreatePayloadSchema,
  assertTaskDescriptorSchema,
  assertToolCallArgumentsSchema,
  assertToolCallSchema,
  assertToolResultSchema,
  type GoogleBoundMessageKind,
} from "./egress-schemas";
import {
  ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED,
  ALLOWED_ATLAS_CATEGORIES,
  ALLOWED_ATLAS_TOPICS,
  ALLOWED_HANDLE_KEYS,
  ALLOWED_HASH_KEYS,
  ALLOWED_PLANNER_TOOLS,
  ALLOWED_REDACTION_COUNT_KEYS,
  ALLOWED_VERIFICATION_KEYS,
  ARGON_COMPANION_MODELS,
  ARGON_CONFIDENTIAL_TOOLS,
  ARGON_LONG_DECODE_THRESHOLD_TOKENS,
  ARGON_MAX_UNIFIED_CONTEXT_TOKENS,
  ARGON_TOOLKIT_MANIFEST,
  bucketScrubRedactionCount,
  CLOSED_CALL_ID_REGEX,
  classifyTaskKind,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  DIGEST_HANDLE_REGEX,
  DOC_HANDLE_REGEX,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  HANDLE_KEY_TO_REGEX,
  INPUT_LITERAL_HANDLE_REGEX,
  INPUT_OR_RESULT_HANDLE_REGEX,
  isPowerOfTwo,
  isPowerOfTwoInRange,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  MAX_HANDLE_INDEX,
  MAX_PLANNER_STEPS,
  MAX_PLANNER_WALL_CLOCK_MS,
  MAX_PLAINTEXT_LEAK_COUNT,
  MAX_REDACTION_COUNT_PER_KIND,
  MAX_TOKEN_BUCKET,
  MEASUREMENT_HANDLE_REGEX,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  RECEIPT_HANDLE_REGEX,
  RESULT_HANDLE_REGEX,
  ROUTER_HANDLE_REGEX,
  roundUpToPowerOfTwo,
  SAFE_CALL_ID_REGEX,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  TINFOIL_KIMI_K3_MAX_CONTEXT_TOKENS,
  ToolPolicyViolationError,
  VALID_TASK_KINDS,
  VALID_THINKING_LEVELS,
  type AllowedAtlasCategory,
  type AllowedAtlasTopic,
  type ArgonInteractionToolDeclaration,
  type ArgonModelCallRecord,
  type ArgonPlannerDescriptor,
  type ArgonThinkingLevel,
  type ArgonToolExecutor,
  type ArgonToolkitModelSpec,
  type ForbiddenArgonParameter,
  type GenAIInteractionsClientLike,
  type InteractionsCreatePayload,
  type LiveGeminiCallResult,
  type LookupTopic,
  type OpenAICompatibleToolDefinition,
  type PlannerToolName,
  type TaskDescriptor,
  type TaskKind,
  type TinfoilChatCompletionResponse,
  type TinfoilPlannerCallResult,
  type TinfoilPlannerClientLike,
  type TinfoilToolCall,
} from "./shared";

export {
  ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED,
  ALLOWED_ATLAS_CATEGORIES,
  ALLOWED_ATLAS_TOPICS,
  ALLOWED_HANDLE_KEYS,
  ALLOWED_HASH_KEYS,
  ALLOWED_PLANNER_TOOLS,
  ALLOWED_REDACTION_COUNT_KEYS,
  ALLOWED_VERIFICATION_KEYS,
  ARGON_COMPANION_MODELS,
  ARGON_CONFIDENTIAL_TOOLS,
  ARGON_LONG_DECODE_THRESHOLD_TOKENS,
  ARGON_MAX_UNIFIED_CONTEXT_TOKENS,
  ARGON_TOOLKIT_MANIFEST,
  assertAnyToolResultSchema,
  assertFunctionResultStepSchema,
  assertGeminiCreateRequestSchema,
  assertGeminiFollowUpRequestSchema,
  assertGoogleBoundMessage,
  assertInteractionsCreatePayloadSchema,
  assertTaskDescriptorSchema,
  assertToolCallArgumentsSchema,
  assertToolCallSchema,
  assertToolResultSchema,
  bucketScrubRedactionCount,
  CLOSED_CALL_ID_REGEX,
  classifyTaskKind,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  DIGEST_HANDLE_REGEX,
  DOC_HANDLE_REGEX,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  HANDLE_KEY_TO_REGEX,
  INPUT_LITERAL_HANDLE_REGEX,
  INPUT_OR_RESULT_HANDLE_REGEX,
  isPowerOfTwo,
  isPowerOfTwoInRange,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  MAX_HANDLE_INDEX,
  MAX_PLANNER_STEPS,
  MAX_PLANNER_WALL_CLOCK_MS,
  MAX_PLAINTEXT_LEAK_COUNT,
  MAX_REDACTION_COUNT_PER_KIND,
  MAX_TOKEN_BUCKET,
  MEASUREMENT_HANDLE_REGEX,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  RECEIPT_HANDLE_REGEX,
  RESULT_HANDLE_REGEX,
  ROUTER_HANDLE_REGEX,
  roundUpToPowerOfTwo,
  SAFE_CALL_ID_REGEX,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  TINFOIL_KIMI_K3_MAX_CONTEXT_TOKENS,
  ToolPolicyViolationError,
  VALID_TASK_KINDS,
  VALID_THINKING_LEVELS,
  type AllowedAtlasCategory,
  type AllowedAtlasTopic,
  type ArgonInteractionToolDeclaration,
  type ArgonModelCallRecord,
  type ArgonPlannerDescriptor,
  type ArgonThinkingLevel,
  type ArgonToolExecutor,
  type ArgonToolkitModelSpec,
  type ForbiddenArgonParameter,
  type GenAIInteractionsClientLike,
  type GoogleBoundMessageKind,
  type InteractionsCreatePayload,
  type LiveGeminiCallResult,
  type LookupTopic,
  type OpenAICompatibleToolDefinition,
  type PlannerToolName,
  type TaskDescriptor,
  type TaskKind,
  type TinfoilChatCompletionResponse,
  type TinfoilPlannerCallResult,
  type TinfoilPlannerClientLike,
  type TinfoilToolCall,
};

const FORBIDDEN_ALIAS_MAP: Record<string, ForbiddenArgonParameter> = {
  thinking_budget: "thinking_budget",
  thinkingBudget: "thinking_budget",
  temperature: "temperature",
  top_p: "top_p",
  topP: "top_p",
  top_k: "top_k",
  topK: "top_k",
  cached_content: "cached_content",
  cachedContent: "cached_content",
};

const OPAQUE_HANDLE_REGEX =
  /^(?:\$INPUT|\$(?:RESULT|DOC|RECEIPT|DIGEST|ROUTER|MEASUREMENT)_(?:[1-9]|1[0-6]))$/;
const SHORT_HEX_REGEX = /^0x(?:[0-9a-f]{2}){1,7}$/;
const FIXED_SHA256_HEX_REGEX = /^0x[0-9a-f]{64}$/;

export const ALLOWED_NUMERIC_KEYS: ReadonlySet<string> = new Set<string>([
  "inputTokenEstimate",
  "max_output_tokens",
  "max_context_tokens",
  "max_tokens",
  "bucketQuantumBytes",
  "bucketBytes",
  "redactionCount",
  "mechanicalRedactionCount",
  "attestedRedactionCount",
  "plaintextLeakCount",
  "checksPassed",
  "checksTotal",
  "totalDocs",
  "matchingReceiptsCount",
  "outputTokenEstimate",
  ...ALLOWED_REDACTION_COUNT_KEYS,
]);

export const ALLOWED_BOOLEAN_KEYS: ReadonlySet<string> = new Set<string>([
  "background",
  "store",
  "humanApproved",
  "passed",
  "selfHealed",
  "failedOver",
  "attested",
  "requiresHumanApproval",
  "stateChangedOnChain",
  "applyAttestedFilter",
  ...ALLOWED_VERIFICATION_KEYS,
]);

export const ALLOWED_ARRAY_KEYS: ReadonlySet<string> = new Set<string>([
  "input",
  "tools",
  "allowedTools",
  "required",
  "enum",
  "messages",
  "tool_calls",
]);

const ALLOWED_STRING_ARRAY_KEYS: ReadonlySet<string> = new Set<string>([
  "allowedTools",
  "required",
  "enum",
]);

const ALLOWED_JSON_STRING_KEYS: ReadonlySet<string> = new Set<string>([
  "text",
  "content",
  "result",
  "arguments",
]);

const ALLOWED_OBJECT_ONLY_KEYS: ReadonlySet<string> = new Set<string>([
  "taskDescriptor",
  "redactionCounts",
  "verification",
  "generation_config",
  "subagent_routing",
  "metadata",
  "parameters",
  "properties",
  "arguments",
]);

const ALLOWED_INTERACTION_STATUSES: ReadonlySet<string> = new Set<string>([
  "completed",
  "in_progress",
  "requires_action",
  "failed",
  "cancelled",
]);

const ALLOWED_STATIC_SCHEMA_DESCRIPTIONS = new Set<string>([
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ...ARGON_CONFIDENTIAL_TOOLS.flatMap((t) => [
    t.description,
    ...Object.values(t.parameters.properties).map((p) => p.description),
  ]),
]);

export const ALLOWED_CONTENT_FREE_ENUMS: ReadonlySet<string> = new Set<string>([
  // Model & SDK identifiers
  GEMINI_4_ARGON_MODEL_ID,
  ARGON_COMPANION_MODELS.sandboxAgent,
  ARGON_COMPANION_MODELS.parallelSubagentFast,
  ARGON_COMPANION_MODELS.parallelSubagentLite,
  ARGON_COMPANION_MODELS.deepResearch,
  ARGON_COMPANION_MODELS.realtimeVoice,
  ARGON_COMPANION_MODELS.voiceTts,
  ARGON_COMPANION_MODELS.confidentialOpenCloud,
  ARGON_COMPANION_MODELS.confidentialOnDevice,
  ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
  ARGON_COMPANION_MODELS.tinfoilEnclaveKimi,
  "pii-filter",
  "@google/genai>=2.31.0",
  "client.interactions.create",
  "redacted_clinical_scientist_persona",
  "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves",
  DATA_SENT_TO_GOOGLE,

  // Thinking levels & config enums
  "low",
  "medium",
  "high",
  "enabled",

  // Task kinds
  ...VALID_TASK_KINDS,

  // Roles & step types
  "user",
  "system",
  "assistant",
  "tool",
  "text",
  "function",
  "function_call",
  "function_result",
  "model_output",
  "auto",
  "none",

  // Schema types
  "OBJECT",
  "STRING",
  "INTEGER",
  "BOOLEAN",
  "NUMBER",
  "ARRAY",
  "object",
  "string",
  "integer",
  "boolean",
  "number",
  "array",

  // Tool names
  ...ALLOWED_PLANNER_TOOLS,

  // Tool argument & result status enums
  "tinfoil",
  ...ALLOWED_ATLAS_TOPICS,
  ...ALLOWED_ATLAS_CATEGORIES,
  ...LOOKUP_TOPICS,
  "allowed",
  "denied",
  "anchor_receipt",
  "ok",
  "verified",
  "completed",
  "failed",
  "blocked_pending_human",
  "ready_for_anchor",
  "anchored",
  "dispatched_over_hpke_ehbp",
  "paused_awaiting_human",
  "executed_with_human_approval",
  "executed",
  "atlas",
  "app-fallback",
  "$rankFusion",
  "rank_fusion",
  "app-rrf",
  "app_rrf",
]);

export const ALLOWED_CONTENT_FREE_KEYS: ReadonlySet<string> = new Set<string>([
  // Top-level Interactions API & OpenAI planner keys
  "model",
  "thinking_level",
  "background",
  "store",
  "max_output_tokens",
  "max_context_tokens",
  "implicit_caching",
  "generation_config",
  "system_instruction",
  "input",
  "tools",
  "subagent_routing",
  "metadata",
  "taskDescriptor",
  "previous_interaction_id",
  "role",
  "content",
  "type",
  "text",
  "name",
  "description",
  "parameters",
  "properties",
  "required",
  "enum",
  "id",
  "call_id",
  "tool_call_id",
  "arguments",
  "result",
  "messages",
  "tool_choice",
  "max_tokens",
  "function",
  "tool_calls",

  // Subagent routing & metadata keys
  "sandbox_verifier",
  "fast_swarm",
  "quorum_checker",
  "deep_research",
  "on_device_filter",
  "attested_enclave_model",
  "tinfoil_enclave_target",
  "voice_briefing",
  "live_voice_gate",
  "sdk_target",
  "api_surface",
  "persona",
  "enclave_protocol",
  "data_sent_to_google",

  // TaskDescriptor keys
  "taskKind",
  "inputHandle",
  "inputTokenEstimate",
  "redactionCounts",
  "verification",
  "allowedTools",

  // Allowed redactionCounts category keys
  "SECRET",
  "EMAIL",
  "PHONE",
  "IP",
  "ACCT",
  "ENTITY",
  "NAME",
  "DIGITS",
  "ENTROPY",
  "URL",
  "ADDRESS",
  "DATE",
  "CUSTOM",
  "SYMMETRY",
  "ATTESTED_PII",
  "TOTAL",

  // Allowed verification boolean keys
  "mechanicalRedactionPassed",
  "attestedPiiFilterVerified",
  "bucketAligned4096",
  "routerSevSnpVerified",
  "enclaveTdxGpuVerified",
  "hpkeKeyBound",
  "sigstoreManifestVerified",
  "arcRegistryVerified",

  // Allowed tool argument & result keys
  "bucketQuantumBytes",
  "applyAttestedFilter",
  "providerId",
  "enclaveModel",
  "topic",
  "category",
  "actionKind",
  "resultHandle",
  "outputHandle",
  "docHandle",
  "topDocHandle",
  "receiptHandle",
  "digestHandle",
  "contentHandle",
  "outputDigestHandle",
  "routerHandle",
  "enclaveMeasurementHandle",
  "humanApproved",
  "status",
  "passed",
  "redactionCount",
  "mechanicalRedactionCount",
  "attestedRedactionCount",
  "bucketBytes",
  "plaintextLeakCount",
  "contentSha256",
  "checksPassed",
  "checksTotal",
  "selfHealed",
  "failedOver",
  "routerDigestHex",
  "enclaveMeasurementHex",
  "vectorEngine",
  "textEngine",
  "fusionEngine",
  "totalDocs",
  "matchingReceiptsCount",
  "topDocSha256",
  "outputTokenEstimate",
  "outputSha256",
  "attested",
  "requiresHumanApproval",
  "stateChangedOnChain",
  "receiptSha256",
]);

const ALLOWED_REQUIRED_PARAM_NAMES = new Set<string>([
  "inputHandle",
  "bucketQuantumBytes",
  "providerId",
  "enclaveModel",
  "topic",
  "category",
  "taskKind",
  "actionKind",
  "resultHandle",
  "humanApproved",
]);

export const ALLOWED_OBJECT_KEYS: ReadonlySet<string> = new Set<string>([
  "taskDescriptor",
  "redactionCounts",
  "verification",
  "generation_config",
  "subagent_routing",
  "metadata",
  "parameters",
  "properties",
  "arguments",
  "result",
  "function",
  // Object-array element contexts
  "input",
  "tools",
  "messages",
  "tool_calls",
]);

const GOOGLE_BOUND_PATH_PREFIXES = [
  "$.createRequest",
  "$.followUpRequest",
  "$.functionResult",
  "$.toolResult",
  "$.tinfoilToolResult",
  "$.payload",
  "$.interactionsPayload",
  "$.outboundGeminiRequest",
  "$.canonicalRequest",
  "$.taskDescriptor",
  "$.mockedGeminiReceived",
  "$.googleBound",
] as const;

function isStrictGoogleBoundPath(path: string, insideJsonString: boolean): boolean {
  if (insideJsonString) {
    return true;
  }
  for (let i = 0; i < GOOGLE_BOUND_PATH_PREFIXES.length; i++) {
    if (path.startsWith(GOOGLE_BOUND_PATH_PREFIXES[i])) {
      return true;
    }
  }
  return false;
}

const ALLOWED_SUBAGENT_ROUTING_KEYS = new Set<string>([
  "sandbox_verifier",
  "fast_swarm",
  "quorum_checker",
  "deep_research",
  "on_device_filter",
  "attested_enclave_model",
  "tinfoil_enclave_target",
  "voice_briefing",
  "live_voice_gate",
]);

const ALLOWED_METADATA_KEYS = new Set<string>([
  "sdk_target",
  "api_surface",
  "persona",
  "enclave_protocol",
  "data_sent_to_google",
]);

const ALLOWED_GENERATION_CONFIG_KEYS = new Set<string>([
  "thinking_level",
  "max_output_tokens",
]);

const HIGH_RANGE_NUMERIC_KEYS = new Set<string>([
  "inputTokenEstimate",
  "outputTokenEstimate",
  "max_output_tokens",
  "max_context_tokens",
  "max_tokens",
  "bucketQuantumBytes",
  "bucketBytes",
]);

function hasAsciiRunOrCount(byteValues: readonly number[]): boolean {
  let consecutivePrintableAscii = 0;
  let maxConsecutivePrintableAscii = 0;
  let totalPrintableLettersOrSpaces = 0;
  let totalPrintableAscii = 0;
  for (let i = 0; i < byteValues.length; i++) {
    const byteVal = byteValues[i];
    if (byteVal >= 0x20 && byteVal <= 0x7e) {
      consecutivePrintableAscii += 1;
      if (consecutivePrintableAscii > maxConsecutivePrintableAscii) {
        maxConsecutivePrintableAscii = consecutivePrintableAscii;
      }
      totalPrintableAscii += 1;
      if (
        byteVal === 0x20 ||
        (byteVal >= 0x41 && byteVal <= 0x5a) ||
        (byteVal >= 0x61 && byteVal <= 0x7a)
      ) {
        totalPrintableLettersOrSpaces += 1;
      }
      if (consecutivePrintableAscii >= 8) {
        return true;
      }
    } else {
      consecutivePrintableAscii = 0;
    }
  }
  if (byteValues.length > 0 && byteValues.length < 16) {
    return (
      maxConsecutivePrintableAscii >= 2 ||
      totalPrintableLettersOrSpaces >= 2 ||
      totalPrintableAscii >= 3
    );
  }
  return totalPrintableLettersOrSpaces >= 18 || totalPrintableAscii >= 20;
}

export function hasSmuggledAsciiInHex(hexWithoutPrefix: string): boolean {
  if (
    typeof hexWithoutPrefix !== "string" ||
    hexWithoutPrefix.length < 2 ||
    hexWithoutPrefix.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(hexWithoutPrefix)
  ) {
    return true;
  }
  // Reject all-decimal digit strings disguised with a 0x prefix
  if (/^\d+$/.test(hexWithoutPrefix)) {
    return true;
  }
  // Reject trivial repeating sequences (e.g., 0000000000000000 or 1234123412341234)
  if (
    /^([0-9a-f]{1,4})\1{15,}$/.test(hexWithoutPrefix) ||
    (hexWithoutPrefix.length <= 14 && /^([0-9a-f]{1,2})\1{2,}$/.test(hexWithoutPrefix))
  ) {
    return true;
  }
  const bytes: number[] = [];
  const freq = new Map<number, number>();
  let maxFreq = 0;
  for (let i = 0; i < hexWithoutPrefix.length; i += 2) {
    const byteVal = parseInt(hexWithoutPrefix.slice(i, i + 2), 16);
    bytes.push(byteVal);
    const count = (freq.get(byteVal) ?? 0) + 1;
    freq.set(byteVal, count);
    if (count > maxFreq) {
      maxFreq = count;
    }
  }
  if (bytes.length >= 16) {
    if (freq.size < 12 || maxFreq >= 6) {
      return true;
    }
  } else if (bytes.length >= 4) {
    if (freq.size < Math.ceil(bytes.length * 0.75) || maxFreq >= 3) {
      return true;
    }
  }
  if (hasAsciiRunOrCount(bytes)) {
    return true;
  }
  const strippedNulls = bytes.filter((b) => b !== 0x00 && b !== 0xff);
  if (hasAsciiRunOrCount(strippedNulls)) {
    return true;
  }
  if (bytes.length < 16) {
    const strippedControls = bytes.filter(
      (b) => b > 0x1f && b !== 0x7f && b !== 0xff,
    );
    if (hasAsciiRunOrCount(strippedControls)) {
      return true;
    }
  }
  let consecutiveHighBitText = 0;
  let totalHighBitLettersOrSpaces = 0;
  let consecutiveLow7Text = 0;
  let totalLow7Text = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    const low7 = b & 0x7f;
    const isLetterOrSpace =
      low7 === 0x20 ||
      (low7 >= 0x41 && low7 <= 0x5a) ||
      (low7 >= 0x61 && low7 <= 0x7a);
    const isDigitOrCommonPunct =
      (low7 >= 0x30 && low7 <= 0x39) ||
      low7 === 0x2d ||
      low7 === 0x5f ||
      low7 === 0x2e;
    if (isLetterOrSpace || isDigitOrCommonPunct) {
      consecutiveLow7Text += 1;
      totalLow7Text += 1;
      if (consecutiveLow7Text >= (bytes.length < 16 ? 2 : 16)) {
        return true;
      }
      if ((b & 0x80) !== 0) {
        consecutiveHighBitText += 1;
        if (isLetterOrSpace) {
          totalHighBitLettersOrSpaces += 1;
        }
        if (consecutiveHighBitText >= (bytes.length < 16 ? 2 : 8)) {
          return true;
        }
      } else {
        consecutiveHighBitText = 0;
      }
    } else {
      consecutiveHighBitText = 0;
      consecutiveLow7Text = 0;
    }
  }
  if (bytes.length < 16) {
    return (
      totalHighBitLettersOrSpaces >= 3 ||
      totalLow7Text >= Math.max(3, Math.ceil(bytes.length * 0.7))
    );
  }
  return totalHighBitLettersOrSpaces >= 16 || totalLow7Text >= 28;
}

export function isContentFreeString(
  value: string,
  keyContext?: string,
  strictGoogleBound = false,
): boolean {
  if (typeof value !== "string" || value.length === 0 || !keyContext) {
    return false;
  }
  if (
    ALLOWED_NUMERIC_KEYS.has(keyContext) ||
    ALLOWED_BOOLEAN_KEYS.has(keyContext) ||
    ALLOWED_OBJECT_ONLY_KEYS.has(keyContext) ||
    (ALLOWED_ARRAY_KEYS.has(keyContext) && !ALLOWED_STRING_ARRAY_KEYS.has(keyContext))
  ) {
    return false;
  }
  if (ALLOWED_HASH_KEYS.has(keyContext)) {
    if (SHORT_HEX_REGEX.test(value) && value.length <= MAX_GOOGLE_BOUND_HEX_LENGTH) {
      return !hasSmuggledAsciiInHex(value.slice(2));
    }
    if (
      !strictGoogleBound &&
      ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED &&
      FIXED_SHA256_HEX_REGEX.test(value)
    ) {
      return !hasSmuggledAsciiInHex(value.slice(2));
    }
    return false;
  }
  if (keyContext === "required") {
    return ALLOWED_REQUIRED_PARAM_NAMES.has(value);
  }
  if (keyContext === "allowedTools") {
    return (ALLOWED_PLANNER_TOOLS as readonly string[]).includes(value);
  }
  if (
    keyContext === "id" ||
    keyContext === "call_id" ||
    keyContext === "tool_call_id" ||
    keyContext === "previous_interaction_id"
  ) {
    return SAFE_CALL_ID_REGEX.test(value) && !/\d{4,}/.test(value);
  }
  if (keyContext === "system_instruction" || keyContext === "description") {
    return ALLOWED_STATIC_SCHEMA_DESCRIPTIONS.has(value);
  }
  if (ALLOWED_HANDLE_KEYS.has(keyContext)) {
    return HANDLE_KEY_TO_REGEX[keyContext]?.test(value) ?? false;
  }
  if (/^(?:0x)?[0-9a-fA-F]{15,}$/.test(value) && value.length > MAX_GOOGLE_BOUND_HEX_LENGTH) {
    return false;
  }
  return ALLOWED_CONTENT_FREE_ENUMS.has(value);
}

export type DigestHandlePrefix =
  | "DOC"
  | "RECEIPT"
  | "DIGEST"
  | "ROUTER"
  | "MEASUREMENT";

export interface DigestHandleMapState {
  byHandle: Record<string, string>;
  byDigest: Map<string, string>;
  counters: Record<DigestHandlePrefix, number>;
}

const HASH_KEY_TO_HANDLE_SPEC: Record<
  string,
  { handleKey: string; prefix: DigestHandlePrefix }
> = {
  topDocSha256: { handleKey: "topDocHandle", prefix: "DOC" },
  receiptSha256: { handleKey: "receiptHandle", prefix: "RECEIPT" },
  contentSha256: { handleKey: "contentHandle", prefix: "DIGEST" },
  outputSha256: { handleKey: "outputDigestHandle", prefix: "DIGEST" },
  routerDigestHex: { handleKey: "routerHandle", prefix: "ROUTER" },
  enclaveMeasurementHex: {
    handleKey: "enclaveMeasurementHandle",
    prefix: "MEASUREMENT",
  },
};

export function createDigestHandleMapState(): DigestHandleMapState {
  return {
    byHandle: {},
    byDigest: new Map<string, string>(),
    counters: {
      DOC: 0,
      RECEIPT: 0,
      DIGEST: 0,
      ROUTER: 0,
      MEASUREMENT: 0,
    },
  };
}

/**
 * Replaces any hex digest fields (`contentSha256`, `routerDigestHex`, `enclaveMeasurementHex`,
 * `topDocSha256`, `outputSha256`, `receiptSha256`) in a tool result object with opaque handles
 * (`$DOC_<n>`, `$RECEIPT_<n>`, `$DIGEST_<n>`, `$ROUTER_<n>`, `$MEASUREMENT_<n>`) before the
 * tool result is serialized into a Google-bound request, keeping the real hashes only in
 * `state.byHandle` on the server side.
 */
export function replaceDigestsWithOpaqueHandles(
  rawResult: Record<string, unknown>,
  state: DigestHandleMapState = createDigestHandleMapState(),
): Record<string, unknown> {
  if (!isPlainObject(rawResult)) {
    throw new ContentFreeEgressError(String(rawResult), "$");
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.getOwnPropertyNames(rawResult)) {
    const desc = Object.getOwnPropertyDescriptor(rawResult, key);
    if (!desc || !("value" in desc) || desc.enumerable !== true) {
      throw new ContentFreeEgressError(key, `$.${key}`);
    }
    const value = desc.value;
    if (value === undefined) {
      throw new ContentFreeEgressError("undefined", `$.${key}`);
    }
    const spec = HASH_KEY_TO_HANDLE_SPEC[key];
    if (spec) {
      if (typeof value !== "string") {
        throw new ContentFreeEgressError(String(value), `$.${key}`);
      }
      const handleRegex = HANDLE_KEY_TO_REGEX[spec.handleKey];
      if (Object.prototype.hasOwnProperty.call(rawResult, spec.handleKey)) {
        const existingHandle = rawResult[spec.handleKey];
        if (
          typeof existingHandle !== "string" ||
          !handleRegex ||
          !handleRegex.test(existingHandle)
        ) {
          throw new ContentFreeEgressError(
            String(existingHandle),
            `$.${spec.handleKey}`,
          );
        }
      }
      if (handleRegex && handleRegex.test(value)) {
        out[spec.handleKey] = value;
        continue;
      }
      const isValidDigestHex =
        (FIXED_SHA256_HEX_REGEX.test(value) || SHORT_HEX_REGEX.test(value)) &&
        !hasSmuggledAsciiInHex(value.slice(2));
      if (!isValidDigestHex) {
        throw new ContentFreeEgressError(value, `$.${key}`);
      }
      const cacheKey = `${spec.prefix}:${value}`;
      let handle = state.byDigest.get(cacheKey);
      if (!handle) {
        const currentCount = state.counters[spec.prefix] ?? 0;
        if (currentCount >= MAX_HANDLE_INDEX) {
          throw new ContentFreeEgressError(
            "<handle_table_exhausted>",
            `$.${key}`,
          );
        }
        const nextIdx = currentCount + 1;
        state.counters[spec.prefix] = nextIdx;
        handle = `$${spec.prefix}_${nextIdx}`;
        state.byDigest.set(cacheKey, handle);
        state.byHandle[handle] = value;
      }
      out[spec.handleKey] = handle;
      continue;
    }
    out[key] = value;
  }
  return out;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.prototype.toString.call(value) !== "[object Object]"
  ) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Egress firewall (D1): recursively inspects any outbound value before it leaves
 * for Google Gemini. Rejects any string not in the strict allowlist of opaque
 * handles (`$INPUT`, `$RESULT_<n>`, `$DOC_<n>`, `$RECEIPT_<n>`, etc.) or allowlisted
 * enum literals, rejects any hex string > 16 characters in Google-bound payloads,
 * and rejects any unallowlisted object keys, numbers, arrays, or JSON-smuggled content.
 */
export function assertContentFree(
  value: unknown,
  path = "$",
  keyContext?: string,
  depth = 0,
  insideJsonString = false,
  isJsonRoot = false,
): void {
  if (depth > 8) {
    throw new ContentFreeEgressError("<max_depth_exceeded>", path);
  }
  if (depth === 0) {
    if (!isPlainObject(value)) {
      throw new ContentFreeEgressError(String(value), path);
    }
  }
  if (value === null || value === undefined) {
    throw new ContentFreeEgressError(String(value), path);
  }
  const valueType = typeof value;
  if (valueType === "boolean") {
    if (!keyContext || !ALLOWED_BOOLEAN_KEYS.has(keyContext)) {
      throw new ContentFreeEgressError(String(value), path);
    }
    return;
  }
  if (valueType === "number") {
    const num = value as number;
    if (
      !keyContext ||
      !ALLOWED_NUMERIC_KEYS.has(keyContext) ||
      !Number.isInteger(num) ||
      Object.is(num, -0) ||
      num < 0 ||
      num > MAX_TOKEN_BUCKET
    ) {
      throw new ContentFreeEgressError(String(value), path);
    }
    if (ALLOWED_REDACTION_COUNT_KEYS.has(keyContext)) {
      if (num > MAX_REDACTION_COUNT_PER_KIND) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "plaintextLeakCount") {
      if (num > MAX_PLAINTEXT_LEAK_COUNT) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (
      keyContext === "bucketQuantumBytes" ||
      keyContext === "bucketBytes"
    ) {
      if (!isPowerOfTwoInRange(num, 512, 65_536)) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "checksPassed") {
      if (num > 16) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "checksTotal") {
      if (num < 1 || num > 16) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (
      keyContext === "redactionCount" ||
      keyContext === "mechanicalRedactionCount" ||
      keyContext === "attestedRedactionCount"
    ) {
      if (num !== 0 && !isPowerOfTwoInRange(num, 1, 64)) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (
      keyContext === "totalDocs" ||
      keyContext === "matchingReceiptsCount"
    ) {
      if (num > 64) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "max_tokens") {
      if (num < 1 || num > 4096) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "max_output_tokens") {
      if (!isPowerOfTwoInRange(num, 1024, 131_072)) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (keyContext === "max_context_tokens") {
      if (
        num !== ARGON_MAX_UNIFIED_CONTEXT_TOKENS &&
        !isPowerOfTwoInRange(num, 1024, MAX_TOKEN_BUCKET)
      ) {
        throw new ContentFreeEgressError(String(value), path);
      }
    } else if (
      keyContext === "inputTokenEstimate" ||
      keyContext === "outputTokenEstimate"
    ) {
      if (!isPowerOfTwoInRange(num, 1, MAX_TOKEN_BUCKET)) {
        throw new ContentFreeEgressError(String(value), path);
      }
    }
    return;
  }
  if (valueType === "string") {
    const str = value as string;
    if (str.length === 0 || str.trim().length === 0) {
      throw new ContentFreeEgressError("<empty_string>", path);
    }
    if (str.startsWith("{") || str.startsWith("[")) {
      if (
        insideJsonString ||
        !keyContext ||
        !ALLOWED_JSON_STRING_KEYS.has(keyContext) ||
        !str.startsWith("{") ||
        !str.endsWith("}")
      ) {
        throw new ContentFreeEgressError(str, path);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(str);
      } catch {
        throw new ContentFreeEgressError(str, path);
      }
      if (!isPlainObject(parsed)) {
        throw new ContentFreeEgressError(str, path);
      }
      let canonical: string;
      try {
        canonical = canonicalJson(parsed);
      } catch {
        throw new ContentFreeEgressError(str, path);
      }
      if (canonical !== str) {
        throw new ContentFreeEgressError(str, path);
      }
      assertContentFree(parsed, `${path}(json)`, undefined, depth + 1, true, true);
      return;
    }
    const strictGoogleBound = isStrictGoogleBoundPath(path, insideJsonString);
    if (!isContentFreeString(str, keyContext, strictGoogleBound)) {
      throw new ContentFreeEgressError(str, path);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (
      !keyContext ||
      !ALLOWED_ARRAY_KEYS.has(keyContext) ||
      value.length === 0 ||
      value.length > 32
    ) {
      throw new ContentFreeEgressError("<disallowed_array>", path);
    }
    if (keyContext === "allowedTools") {
      if (
        value.length > ALLOWED_PLANNER_TOOLS.length ||
        new Set(value).size !== value.length
      ) {
        throw new ContentFreeEgressError("<invalid_allowedTools>", path);
      }
      let lastCanonicalIdx = -1;
      for (let i = 0; i < value.length; i++) {
        const idx = (ALLOWED_PLANNER_TOOLS as readonly string[]).indexOf(
          String(value[i]),
        );
        if (idx === -1 || idx <= lastCanonicalIdx) {
          throw new ContentFreeEgressError(String(value[i]), `${path}[${i}]`);
        }
        lastCanonicalIdx = idx;
      }
    } else if (keyContext === "required") {
      if (
        !path.endsWith(".parameters.required") ||
        value.length > ALLOWED_REQUIRED_PARAM_NAMES.size ||
        new Set(value).size !== value.length
      ) {
        throw new ContentFreeEgressError("<invalid_required>", path);
      }
    } else if (keyContext === "enum") {
      if (
        !/\.properties\.[A-Za-z0-9_]+\.enum$/.test(path) ||
        value.length > 32 ||
        new Set(value).size !== value.length
      ) {
        throw new ContentFreeEgressError("<invalid_enum>", path);
      }
    } else if (keyContext === "tools") {
      if (depth !== 1 || value.length > ALLOWED_PLANNER_TOOLS.length) {
        throw new ContentFreeEgressError("<invalid_tools>", path);
      }
    } else if (keyContext === "input" || keyContext === "messages") {
      if (depth !== 1 || value.length > 16) {
        throw new ContentFreeEgressError("<invalid_input_array>", path);
      }
    } else if (keyContext === "tool_calls") {
      if (!path.endsWith(".tool_calls") || value.length > MAX_PLANNER_STEPS) {
        throw new ContentFreeEgressError("<invalid_tool_calls>", path);
      }
    }
    const expectsStringElements = ALLOWED_STRING_ARRAY_KEYS.has(keyContext);
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (expectsStringElements) {
        if (typeof item !== "string") {
          throw new ContentFreeEgressError(String(item), `${path}[${i}]`);
        }
      } else if (!isPlainObject(item)) {
        throw new ContentFreeEgressError(String(item), `${path}[${i}]`);
      }
      assertContentFree(
        item,
        `${path}[${i}]`,
        keyContext,
        depth + 1,
        insideJsonString,
        false,
      );
    }
    return;
  }
  if (isPlainObject(value)) {
    const isToolPropertySchemaDef =
      typeof keyContext === "string" &&
      ALLOWED_REQUIRED_PARAM_NAMES.has(keyContext) &&
      path.endsWith(`.properties.${keyContext}`);
    if (
      depth > 0 &&
      !isJsonRoot &&
      !isToolPropertySchemaDef &&
      (!keyContext || !ALLOWED_OBJECT_KEYS.has(keyContext))
    ) {
      throw new ContentFreeEgressError("<disallowed_object>", path);
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new ContentFreeEgressError("<symbol_property>", path);
    }
    if (typeof (value as { toJSON?: unknown }).toJSON === "function") {
      throw new ContentFreeEgressError("<custom_toJSON>", path);
    }
    const ownKeys = Object.getOwnPropertyNames(value);
    if (ownKeys.length === 0) {
      throw new ContentFreeEgressError("<empty_object>", path);
    }
    if (ownKeys.length > 64) {
      throw new ContentFreeEgressError("<too_many_keys>", path);
    }
    let numericKeyCount = 0;
    let highRangeNumericCount = 0;
    let hasInputEstimate = false;
    let hasOutputEstimate = false;
    for (const k of ownKeys) {
      if (
        k === "__proto__" ||
        k === "constructor" ||
        k === "prototype" ||
        !ALLOWED_CONTENT_FREE_KEYS.has(k)
      ) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (keyContext === "redactionCounts" && !ALLOWED_REDACTION_COUNT_KEYS.has(k)) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (keyContext === "verification" && !ALLOWED_VERIFICATION_KEYS.has(k)) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (
        keyContext === "generation_config" &&
        !ALLOWED_GENERATION_CONFIG_KEYS.has(k)
      ) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (
        keyContext === "subagent_routing" &&
        !ALLOWED_SUBAGENT_ROUTING_KEYS.has(k)
      ) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (keyContext === "metadata" && !ALLOWED_METADATA_KEYS.has(k)) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      const desc = Object.getOwnPropertyDescriptor(value, k);
      if (!desc || !("value" in desc) || desc.enumerable !== true) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (desc.value === undefined) {
        throw new ContentFreeEgressError("undefined", `${path}.${k}`);
      }
      if (typeof desc.value === "number") {
        numericKeyCount += 1;
        if (HIGH_RANGE_NUMERIC_KEYS.has(k)) {
          highRangeNumericCount += 1;
        }
        if (k === "inputTokenEstimate") hasInputEstimate = true;
        if (k === "outputTokenEstimate") hasOutputEstimate = true;
        if (keyContext !== "redactionCounts" && numericKeyCount > 5) {
          throw new ContentFreeEgressError("<too_many_numeric_keys>", path);
        }
        if (
          highRangeNumericCount > 2 ||
          (hasInputEstimate && hasOutputEstimate)
        ) {
          throw new ContentFreeEgressError(
            "<incompatible_numeric_keys>",
            path,
          );
        }
      }
      assertContentFree(
        desc.value,
        `${path}.${k}`,
        k,
        depth + 1,
        insideJsonString,
        false,
      );
    }
    return;
  }
  throw new ContentFreeEgressError(String(value), path);
}

/**
 * Enforces the deRoute Privacy Invariant: neither Google nor Tinfoil planner calls
 * may receive raw PII or unredacted secrets. Inspects the serialized outbound payload
 * and throws `PrivacyInvariantViolationError` if any original placeholder value or
 * unmasked sensitive token (>= 4 chars) is present.
 */
export function assertOutboundPrivacyInvariant(
  outboundPayload: unknown,
  sensitiveOriginals: readonly string[],
): void {
  const rawSerialized =
    typeof outboundPayload === "string"
      ? outboundPayload
      : JSON.stringify(outboundPayload ?? {});
  const serialized = rawSerialized.normalize("NFKC");
  const lowerSerialized = serialized.toLowerCase();

  for (const rawOrig of sensitiveOriginals) {
    const cleaned = (rawOrig || "").normalize("NFKC").trim();
    if (cleaned.length < 4) continue;
    if (serialized.includes(cleaned) || lowerSerialized.includes(cleaned.toLowerCase())) {
      throw new PrivacyInvariantViolationError(cleaned);
    }
  }
}

export interface ToolArgumentFieldSchema {
  type: "STRING" | "INTEGER" | "BOOLEAN";
  required?: boolean;
  isHandle?: boolean;
  enum?: readonly string[];
  min?: number;
  max?: number;
}

export const TOOL_ARGUMENT_SCHEMAS: Record<
  PlannerToolName,
  Record<string, ToolArgumentFieldSchema>
> = {
  scrub_and_symmetry_mask: {
    inputHandle: { type: "STRING", required: true, isHandle: true },
    bucketQuantumBytes: {
      type: "INTEGER",
      required: true,
      min: 512,
      max: 65536,
    },
  },
  verify_two_hop_enclave_and_quorum: {
    providerId: { type: "STRING", required: true, enum: ["tinfoil"] },
    enclaveModel: {
      type: "STRING",
      required: true,
      enum: ["gemma4-31b", "kimi-k3"],
    },
  },
  search_atlas_hybrid_kb: {
    topic: {
      type: "STRING",
      required: true,
      enum: [...ALLOWED_ATLAS_TOPICS, ...LOOKUP_TOPICS],
    },
    inputHandle: { type: "STRING", required: false, isHandle: true },
    category: {
      type: "STRING",
      required: false,
      enum: ALLOWED_ATLAS_CATEGORIES,
    },
  },
  invoke_attested_enclave: {
    inputHandle: { type: "STRING", required: true, isHandle: true },
    enclaveModel: {
      type: "STRING",
      required: true,
      enum: ["gemma4-31b", "kimi-k3"],
    },
    taskKind: { type: "STRING", required: false, enum: VALID_TASK_KINDS },
  },
  anchor_arc_settlement_with_human_gate: {
    actionKind: { type: "STRING", required: true, enum: ["anchor_receipt"] },
    resultHandle: { type: "STRING", required: false, isHandle: true },
    humanApproved: { type: "BOOLEAN", required: true },
  },
};

export interface ToolCallValidationResult {
  valid: boolean;
  errors: string[];
  sanitizedArgs?: Record<string, unknown>;
}

/**
 * Validates a planner tool call against the strict tool allowlist and JSON argument schema.
 * Rejects unknown tools, unexpected properties, wrong types, non-handle strings, or free text.
 */
export function validateToolCallArguments(
  toolName: string,
  args: unknown,
): ToolCallValidationResult {
  if (!(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(toolName)) {
    return {
      valid: false,
      errors: [`Tool '${String(toolName)}' is not in ALLOWED_PLANNER_TOOLS.`],
    };
  }

  if (
    !args ||
    typeof args !== "object" ||
    Array.isArray(args) ||
    Object.prototype.toString.call(args) !== "[object Object]"
  ) {
    return {
      valid: false,
      errors: [`Arguments for '${toolName}' must be a non-null plain object.`],
    };
  }

  const schema = TOOL_ARGUMENT_SCHEMAS[toolName as PlannerToolName];
  const rawObj = args as Record<string, unknown>;
  const errors: string[] = [];
  const sanitizedArgs: Record<string, unknown> = {};

  for (const key of Object.keys(rawObj)) {
    if (!Object.prototype.hasOwnProperty.call(schema, key)) {
      errors.push(`Unexpected argument '${key}' on tool '${toolName}'.`);
    }
  }

  for (const [field, spec] of Object.entries(schema)) {
    const val = rawObj[field];
    if (val === undefined) {
      if (spec.required) {
        errors.push(`Missing required argument '${field}' on tool '${toolName}'.`);
      }
      continue;
    }

    if (spec.type === "STRING") {
      if (typeof val !== "string") {
        errors.push(`Argument '${field}' on '${toolName}' must be a string.`);
        continue;
      }
      if (spec.isHandle && !INPUT_OR_RESULT_HANDLE_REGEX.test(val)) {
        errors.push(
          `Argument '${field}' on '${toolName}' must be an opaque handle ($INPUT or $RESULT_1..$RESULT_16), got '${val.slice(0, 24)}'.`,
        );
        continue;
      }
      if (spec.enum && !spec.enum.includes(val)) {
        errors.push(
          `Argument '${field}' on '${toolName}' must be one of [${spec.enum.join(", ")}], got '${val.slice(0, 24)}'.`,
        );
        continue;
      }
      sanitizedArgs[field] = val;
    } else if (spec.type === "INTEGER") {
      if (typeof val !== "number" || !Number.isInteger(val)) {
        errors.push(`Argument '${field}' on '${toolName}' must be an integer.`);
        continue;
      }
      if (spec.min !== undefined && val < spec.min) {
        errors.push(`Argument '${field}' on '${toolName}' must be >= ${spec.min}.`);
        continue;
      }
      if (spec.max !== undefined && val > spec.max) {
        errors.push(`Argument '${field}' on '${toolName}' must be <= ${spec.max}.`);
        continue;
      }
      if (
        field === "bucketQuantumBytes" &&
        !isPowerOfTwoInRange(val, 512, 65_536)
      ) {
        errors.push(
          `Argument '${field}' on '${toolName}' must be a power-of-two byte bucket between 512 and 65536.`,
        );
        continue;
      }
      sanitizedArgs[field] = val;
    } else if (spec.type === "BOOLEAN") {
      if (typeof val !== "boolean") {
        errors.push(`Argument '${field}' on '${toolName}' must be a boolean.`);
        continue;
      }
      sanitizedArgs[field] = val;
    }
  }

  if (errors.length === 0) {
    try {
      assertGoogleBoundMessage(
        `toolCall:${toolName}`,
        args,
        `$.toolCall(${toolName})`,
      );
      assertGoogleBoundMessage(
        `toolCall:${toolName}`,
        sanitizedArgs,
        `$.toolCall(${toolName})`,
      );
      assertContentFree(args, `$.toolCall(${toolName})`);
      assertContentFree(sanitizedArgs, `$.toolCall(${toolName})`);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : "Failed content-free check.");
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    ...(errors.length === 0 ? { sanitizedArgs } : {}),
  };
}

export function assertValidToolCall(
  toolName: string,
  args: unknown,
  allowedToolsSubset?: readonly string[],
): Record<string, unknown> {
  const res = validateToolCallArguments(toolName, args);
  if (!res.valid || !res.sanitizedArgs) {
    throw new ToolPolicyViolationError(toolName, res.errors);
  }
  if (
    Array.isArray(allowedToolsSubset) &&
    !allowedToolsSubset.includes(toolName)
  ) {
    throw new ToolPolicyViolationError(toolName, [
      `Tool '${toolName}' is not permitted by this descriptor's allowedTools list.`,
    ]);
  }
  return res.sanitizedArgs;
}

/**
 * Sanitizes untrusted model text output so it can never inject HTML/scripts,
 * control characters, or em dashes, and caps length. Model output is never executed
 * and never used to compute pass/fail verification gates.
 */
export function sanitizeUntrustedModelOutput(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/<[^>]*>/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 512);
}

export interface ArgonRequestConfigInput {
  model?: string;
  thinking_level?: ArgonThinkingLevel | string;
  thinkingLevel?: ArgonThinkingLevel | string;
  background?: boolean;
  max_output_tokens?: number;
  maxOutputTokens?: number;
  max_context_tokens?: number;
  maxContextTokens?: number;
  autonomousMultiStep?: boolean;
  thinking_budget?: unknown;
  thinkingBudget?: unknown;
  temperature?: unknown;
  top_p?: unknown;
  topP?: unknown;
  top_k?: unknown;
  topK?: unknown;
  cached_content?: unknown;
  cachedContent?: unknown;
  [key: string]: unknown;
}

export interface ValidatedArgonConfig {
  model: typeof GEMINI_4_ARGON_MODEL_ID;
  thinking_level: ArgonThinkingLevel;
  background: boolean;
  max_output_tokens: number;
  max_context_tokens: number;
  implicit_caching: "enabled";
}

export interface ArgonValidationResult {
  valid: boolean;
  ok: boolean;
  errors: string[];
  rejectedParameters: ForbiddenArgonParameter[];
  normalizedConfig?: ValidatedArgonConfig;
}

/**
 * Validates a candidate Gemini 4 Argon request configuration:
 * 1. Model must be "gemini-4-argon" (defaults to "gemini-4-argon" if omitted).
 * 2. Requires a valid `thinking_level` ("low" | "medium" | "high", defaults to "medium").
 * 3. Rejects `thinking_budget`, `temperature`, `top_p`, `top_k`, and `cached_content`.
 * 4. Automatically enables `background: true` when `max_output_tokens > 65536`
 *    or when `autonomousMultiStep` / `background` is requested.
 */
export function validateArgonRequestConfig(
  input: ArgonRequestConfigInput,
): ArgonValidationResult {
  const errors: string[] = [];
  const rejectedSet = new Set<ForbiddenArgonParameter>();

  if (!input || typeof input !== "object") {
    return {
      valid: false,
      ok: false,
      errors: ["Request configuration must be a non-null object."],
      rejectedParameters: [],
    };
  }

  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined && key in FORBIDDEN_ALIAS_MAP) {
      const canonical = FORBIDDEN_ALIAS_MAP[key];
      rejectedSet.add(canonical);
    }
  }

  if (rejectedSet.has("thinking_budget")) {
    errors.push(
      "Parameter 'thinking_budget' is deprecated and rejected in gemini-4-argon. Use 'thinking_level' ('low' | 'medium' | 'high') instead.",
    );
  }
  if (rejectedSet.has("temperature")) {
    errors.push(
      "Parameter 'temperature' is rejected in gemini-4-argon. Sampling is managed dynamically by the Argon reasoning scheduler.",
    );
  }
  if (rejectedSet.has("top_p")) {
    errors.push(
      "Parameter 'top_p' is rejected in gemini-4-argon. Sampling is managed dynamically by the Argon reasoning scheduler.",
    );
  }
  if (rejectedSet.has("top_k")) {
    errors.push(
      "Parameter 'top_k' is rejected in gemini-4-argon. Sampling is managed dynamically by the Argon reasoning scheduler.",
    );
  }
  if (rejectedSet.has("cached_content")) {
    errors.push(
      "Parameter 'cached_content' is rejected in gemini-4-argon. Implicit prefix caching is automatic across the 1,000,000-token unified context window.",
    );
  }

  const model = input.model ?? GEMINI_4_ARGON_MODEL_ID;
  if (model !== GEMINI_4_ARGON_MODEL_ID) {
    errors.push(
      `Invalid primary model '${String(model)}'. Expected '${GEMINI_4_ARGON_MODEL_ID}'.`,
    );
  }

  const rawThinkingLevel = input.thinking_level ?? input.thinkingLevel ?? "medium";
  if (
    typeof rawThinkingLevel !== "string" ||
    !(VALID_THINKING_LEVELS as readonly string[]).includes(rawThinkingLevel)
  ) {
    errors.push(
      `Invalid thinking_level '${String(rawThinkingLevel)}'. Must be one of: 'low', 'medium', 'high'.`,
    );
  }

  const rawMaxOutput =
    input.max_output_tokens ?? input.maxOutputTokens ?? 131_072;
  if (
    typeof rawMaxOutput !== "number" ||
    !Number.isFinite(rawMaxOutput) ||
    rawMaxOutput < 1 ||
    rawMaxOutput > ARGON_MAX_UNIFIED_CONTEXT_TOKENS
  ) {
    errors.push(
      `Invalid max_output_tokens '${String(rawMaxOutput)}'. Must be between 1 and ${ARGON_MAX_UNIFIED_CONTEXT_TOKENS}.`,
    );
  }

  const rawMaxContext =
    input.max_context_tokens ??
    input.maxContextTokens ??
    ARGON_MAX_UNIFIED_CONTEXT_TOKENS;
  if (
    typeof rawMaxContext !== "number" ||
    !Number.isFinite(rawMaxContext) ||
    rawMaxContext < 1024 ||
    rawMaxContext > ARGON_MAX_UNIFIED_CONTEXT_TOKENS
  ) {
    errors.push(
      `Invalid max_context_tokens '${String(rawMaxContext)}'. Must be between 1024 and ${ARGON_MAX_UNIFIED_CONTEXT_TOKENS}.`,
    );
  }

  const rejectedParameters = Array.from(rejectedSet);
  if (errors.length > 0) {
    return {
      valid: false,
      ok: false,
      errors,
      rejectedParameters,
    };
  }

  const thinking_level = rawThinkingLevel as ArgonThinkingLevel;
  const max_output_tokens = Math.trunc(rawMaxOutput);
  const max_context_tokens = Math.trunc(rawMaxContext);

  const requiresBackground =
    Boolean(input.background) ||
    Boolean(input.autonomousMultiStep) ||
    max_output_tokens > ARGON_LONG_DECODE_THRESHOLD_TOKENS;

  return {
    valid: true,
    ok: true,
    errors: [],
    rejectedParameters: [],
    normalizedConfig: {
      model: GEMINI_4_ARGON_MODEL_ID,
      thinking_level,
      background: requiresBackground,
      max_output_tokens,
      max_context_tokens,
      implicit_caching: "enabled",
    },
  };
}

/**
 * Strips any forbidden legacy sampling/caching parameters from an incoming object
 * and returns both the sanitized config and the list of stripped parameter names.
 */
export function sanitizeToArgonConfig(
  raw: Record<string, unknown>,
): {
  config: ValidatedArgonConfig;
  strippedFields: ForbiddenArgonParameter[];
} {
  const strippedSet = new Set<ForbiddenArgonParameter>();
  const cleaned: ArgonRequestConfigInput = {};

  for (const [k, v] of Object.entries(raw)) {
    if (k in FORBIDDEN_ALIAS_MAP && v !== undefined) {
      strippedSet.add(FORBIDDEN_ALIAS_MAP[k]);
      continue;
    }
    cleaned[k] = v;
  }

  const validated = validateArgonRequestConfig({
    ...cleaned,
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level:
      typeof cleaned.thinking_level === "string" &&
      (VALID_THINKING_LEVELS as readonly string[]).includes(cleaned.thinking_level)
        ? (cleaned.thinking_level as ArgonThinkingLevel)
        : "medium",
    autonomousMultiStep: true,
  });

  if (!validated.normalizedConfig) {
    throw new Error(validated.errors.join(" "));
  }

  return {
    config: validated.normalizedConfig,
    strippedFields: Array.from(strippedSet),
  };
}

/**
 * Converts `ARGON_CONFIDENTIAL_TOOLS` into OpenAI-compatible function tool declarations
 * for Tinfoil's attested enclave models (`kimi-k3` and `gemma4-31b`).
 */
export function buildTinfoilOpenAITools(
  tools: readonly ArgonInteractionToolDeclaration[] = ARGON_CONFIDENTIAL_TOOLS,
): OpenAICompatibleToolDefinition[] {
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description,
      parameters: {
        type: "object",
        properties: Object.fromEntries(
          Object.entries(t.parameters.properties).map(([key, prop]) => [
            key,
            {
              type: prop.type.toLowerCase(),
              description: prop.description,
              ...(prop.enum ? { enum: prop.enum } : {}),
            },
          ]),
        ),
        required: [...t.parameters.required],
      },
    },
  }));
}

export function buildTaskDescriptor(params: {
  taskKind?: TaskKind;
  rawTextForClassification?: string;
  inputTokenEstimate?: number;
  redactionCounts?: Record<string, number>;
  verification?: Record<string, boolean>;
  allowedTools?: readonly string[];
}): TaskDescriptor {
  const taskKind: TaskKind =
    params.taskKind ?? classifyTaskKind(params.rawTextForClassification ?? "");
  const inputTokenEstimate = roundUpToPowerOfTwo(
    params.inputTokenEstimate ??
      estimateTokens(params.rawTextForClassification ?? "task"),
  );

  const sanitizedRedactionCounts: Record<string, number> = {};
  for (const [k, v] of Object.entries(params.redactionCounts ?? { TOTAL: 0 })) {
    if (ALLOWED_REDACTION_COUNT_KEYS.has(k) && typeof v === "number" && Number.isFinite(v)) {
      sanitizedRedactionCounts[k] = Math.min(
        MAX_REDACTION_COUNT_PER_KIND,
        Math.max(0, Math.trunc(v)),
      );
    }
  }
  if (Object.keys(sanitizedRedactionCounts).length === 0) {
    sanitizedRedactionCounts.TOTAL = 0;
  }

  const sanitizedVerification: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(
    params.verification ?? { mechanicalRedactionPassed: true },
  )) {
    if (ALLOWED_VERIFICATION_KEYS.has(k) && typeof v === "boolean") {
      sanitizedVerification[k] = v;
    }
  }
  if (Object.keys(sanitizedVerification).length === 0) {
    sanitizedVerification.mechanicalRedactionPassed = true;
  }

  const requestedTools = params.allowedTools ?? ALLOWED_PLANNER_TOOLS;
  const allowedTools = ALLOWED_PLANNER_TOOLS.filter((t) =>
    (requestedTools as readonly string[]).includes(t),
  );

  const descriptor: TaskDescriptor = {
    taskKind,
    inputHandle: "$INPUT",
    inputTokenEstimate,
    redactionCounts: sanitizedRedactionCounts,
    verification: sanitizedVerification,
    allowedTools: allowedTools.length > 0 ? [...allowedTools] : [...ALLOWED_PLANNER_TOOLS],
  };

  assertGoogleBoundMessage("taskDescriptor", descriptor, "$.taskDescriptor");
  assertContentFree(descriptor, "$.taskDescriptor");
  return descriptor;
}

export function buildInteractionsCreatePayload(params: {
  taskDescriptor?: TaskDescriptor;
  scrubbedPrompt?: string;
  thinkingLevel?: ArgonThinkingLevel;
  background?: boolean;
  maxOutputTokens?: number;
  persona?: string;
}): InteractionsCreatePayload {
  const validation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: params.thinkingLevel ?? "medium",
    background: params.background ?? true,
    max_output_tokens: params.maxOutputTokens ?? 131_072,
    max_context_tokens: ARGON_MAX_UNIFIED_CONTEXT_TOKENS,
    autonomousMultiStep: true,
  });

  if (!validation.valid || !validation.normalizedConfig) {
    throw new Error(
      `Invalid Gemini 4 Argon configuration: ${validation.errors.join("; ")}`,
    );
  }

  const cfg = validation.normalizedConfig;
  const descriptor =
    params.taskDescriptor ??
    buildTaskDescriptor({
      rawTextForClassification: params.scrubbedPrompt ?? "",
    });

  assertGoogleBoundMessage("taskDescriptor", descriptor, "$.taskDescriptor");
  assertContentFree(descriptor, "$.taskDescriptor");

  const payload: InteractionsCreatePayload = {
    model: cfg.model,
    thinking_level: cfg.thinking_level,
    background: cfg.background,
    max_output_tokens: cfg.max_output_tokens,
    max_context_tokens: cfg.max_context_tokens,
    implicit_caching: cfg.implicit_caching,
    generation_config: {
      thinking_level: cfg.thinking_level,
      max_output_tokens: cfg.max_output_tokens,
    },
    system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
    taskDescriptor: descriptor,
    input: [
      {
        role: "user",
        content: canonicalJson(descriptor),
      },
    ],
    tools: ARGON_CONFIDENTIAL_TOOLS,
    subagent_routing: {
      sandbox_verifier: ARGON_COMPANION_MODELS.sandboxAgent,
      fast_swarm: ARGON_COMPANION_MODELS.parallelSubagentFast,
      quorum_checker: ARGON_COMPANION_MODELS.parallelSubagentLite,
      deep_research: ARGON_COMPANION_MODELS.deepResearch,
      on_device_filter: ARGON_COMPANION_MODELS.confidentialOnDevice,
      attested_enclave_model: ARGON_COMPANION_MODELS.confidentialOpenCloud,
      tinfoil_enclave_target: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
      voice_briefing: ARGON_COMPANION_MODELS.voiceTts,
      live_voice_gate: ARGON_COMPANION_MODELS.realtimeVoice,
    },
    metadata: {
      sdk_target: "@google/genai>=2.31.0",
      api_surface: "client.interactions.create",
      persona: "redacted_clinical_scientist_persona",
      enclave_protocol:
        "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves",
      data_sent_to_google: DATA_SENT_TO_GOOGLE,
    },
  };

  assertGoogleBoundMessage("interactionsPayload", payload, "$.payload");
  assertContentFree(payload, "$.payload");
  return payload;
}

export function generateInteractionsSdkSnippets(
  payload: InteractionsCreatePayload,
): {
  typescript: string;
  python: string;
} {
  const typescript = [
    `import { GoogleGenAI } from "@google/genai"; // v2.31.0`,
    ``,
    `const client = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });`,
    ``,
    `// Official Gemini 4 Argon Split-Knowledge Interactions API call`,
    `// Only a content-free TaskDescriptor ($INPUT handle, counts, booleans, enums) is sent.`,
    `// Note: thinking_budget, temperature, top_p, top_k, and cached_content are omitted`,
    `// because gemini-4-argon enforces thinking_level and automatic implicit caching.`,
    `const taskDescriptor = ${JSON.stringify(payload.taskDescriptor, null, 2)};`,
    `const interaction = await client.interactions.create({`,
    `  model: "${payload.model}",`,
    `  background: ${String(payload.background)},`,
    `  generation_config: {`,
    `    thinking_level: "${payload.thinking_level}",`,
    `    max_output_tokens: ${payload.max_output_tokens},`,
    `  },`,
    `  system_instruction: ${JSON.stringify(payload.system_instruction)},`,
    `  input: [{ type: "text", text: JSON.stringify(taskDescriptor) }],`,
    `  tools: ${JSON.stringify(payload.tools, null, 2)},`,
    `});`,
    ``,
    `console.log(interaction.id, interaction.status);`,
  ].join("\n");

  const python = [
    `import json`,
    `from google import genai  # google-genai >= 1.40.0`,
    ``,
    `client = genai.Client()`,
    ``,
    `# Official Gemini 4 Argon Split-Knowledge Interactions API call (content-free TaskDescriptor only)`,
    `task_descriptor = json.loads(${JSON.stringify(JSON.stringify(payload.taskDescriptor))})`,
    `interaction = client.interactions.create(`,
    `    model="${payload.model}",`,
    `    background=${payload.background ? "True" : "False"},`,
    `    generation_config={`,
    `        "thinking_level": "${payload.thinking_level}",`,
    `        "max_output_tokens": ${payload.max_output_tokens},`,
    `    },`,
    `    system_instruction=${JSON.stringify(payload.system_instruction)},`,
    `    input=[{"type": "text", "text": json.dumps(task_descriptor)}],`,
    `)`,
    `print(interaction.id, interaction.status)`,
  ].join("\n");

  return { typescript, python };
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

/**
 * Calls `@google/genai` (`new GoogleGenAI({ apiKey }).interactions.create(...)`)
 * over a content-free `TaskDescriptor` and executes a multi-turn function-calling loop.
 *
 * Security guarantees (D1 & D2):
 * 1. Runs `assertContentFree` and `assertOutboundPrivacyInvariant` on every outbound request.
 * 2. Validates every tool call with `assertValidToolCall` (strict allowlist + JSON schema).
 * 3. Enforces `maxSteps` (<= `MAX_PLANNER_STEPS`) and `wallClockBudgetMs` (<= `MAX_PLANNER_WALL_CLOCK_MS`).
 * 4. Treats model output as untrusted data and never executes or trusts it for gates.
 * 5. Refuses to run with ambient keys in browser environments.
 */
export async function callGeminiInteractionsEndpoint(params: {
  payload: InteractionsCreatePayload;
  apiKey?: string;
  sensitiveOriginals?: readonly string[];
  toolExecutor?: ArgonToolExecutor;
  genaiClient?: GenAIInteractionsClientLike;
  maxSteps?: number;
  wallClockBudgetMs?: number;
}): Promise<LiveGeminiCallResult> {
  const sensitiveOriginals = params.sensitiveOriginals ?? [];

  // Enforce both Privacy Invariant, Closed Schema Gate, and Content-Free Egress Firewall before checking key or calling Google
  assertOutboundPrivacyInvariant(params.payload, sensitiveOriginals);
  assertGoogleBoundMessage("interactionsPayload", params.payload, "$.payload");
  assertContentFree(params.payload, "$.payload");

  if (typeof window !== "undefined" && !params.genaiClient) {
    return {
      attemptedLiveCall: false,
      liveEndpointReached: false,
      sdkMethod: "client.interactions.create",
      fallbackReason:
        "Browser execution blocked: Gemini API key may only be used on the server.",
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
    };
  }

  const resolvedKey =
    params.apiKey?.trim() ||
    (typeof process !== "undefined" ? process.env?.GEMINI_API_KEY?.trim() : "") ||
    "";

  if (!resolvedKey && !params.genaiClient) {
    return {
      attemptedLiveCall: false,
      liveEndpointReached: false,
      sdkMethod: "client.interactions.create",
      fallbackReason:
        "No GEMINI_API_KEY configured; planner routed to attested Tinfoil enclave model.",
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
    };
  }

  const client: GenAIInteractionsClientLike =
    params.genaiClient ??
    (await (async () => {
      const { GoogleGenAI } = await import("@google/genai");
      return new GoogleGenAI({
        apiKey: resolvedKey,
      }) as unknown as GenAIInteractionsClientLike;
    })());

  const maxSteps = Math.min(
    MAX_PLANNER_STEPS,
    Math.max(1, Math.trunc(params.maxSteps ?? MAX_PLANNER_STEPS)),
  );
  const wallClockBudgetMs = Math.min(
    MAX_PLANNER_WALL_CLOCK_MS,
    Math.max(10, Math.trunc(params.wallClockBudgetMs ?? MAX_PLANNER_WALL_CLOCK_MS)),
  );

  const startedAt = Date.now();
  const toolCallsExecuted: string[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  try {
    const createRequest: Record<string, unknown> = {
      model: params.payload.model,
      background: params.payload.background,
      store: false,
      system_instruction: params.payload.system_instruction,
      generation_config: {
        thinking_level: params.payload.thinking_level,
        max_output_tokens: params.payload.max_output_tokens,
      },
      input: [
        {
          type: "text",
          text: params.payload.input[0]?.content ?? "",
        },
      ],
      tools: params.payload.tools,
    };

    assertOutboundPrivacyInvariant(createRequest, sensitiveOriginals);
    assertGoogleBoundMessage("createRequest", createRequest, "$.createRequest");
    assertContentFree(createRequest, "$.createRequest");

    const createAbortController = new AbortController();
    const createRequestOptions = {
      timeout_ms: wallClockBudgetMs,
      retries: { strategy: "none" },
      fetch_options: { signal: createAbortController.signal },
    };

    let interaction = await withWallClockBudget(
      client.interactions.create(createRequest, createRequestOptions),
      startedAt,
      wallClockBudgetMs,
    ).finally(() => createAbortController.abort());

    if (typeof interaction.usage?.total_input_tokens === "number") {
      totalInputTokens += interaction.usage.total_input_tokens;
    }
    if (typeof interaction.usage?.total_output_tokens === "number") {
      totalOutputTokens += interaction.usage.total_output_tokens;
    }

    let stepCount = 0;
    let turn = 0;
    const digestHandleState = createDigestHandleMapState();
    while (params.toolExecutor && Array.isArray(interaction.steps)) {
      const fnCalls = interaction.steps.filter(
        (s) => s && s.type === "function_call",
      );
      if (fnCalls.length === 0) break;

      if (turn >= maxSteps || stepCount + fnCalls.length > maxSteps) {
        throw new PlannerBudgetExceededError("max_steps", maxSteps);
      }

      const fnResults: Array<Record<string, unknown>> = [];
      for (let idx = 0; idx < fnCalls.length; idx++) {
        const call = fnCalls[idx];
        const name = typeof call.name === "string" ? call.name : "";
        if (!name) {
          throw new ToolPolicyViolationError("<missing>", [
            "Function call step is missing tool name.",
          ]);
        }
        const validatedArgs = assertValidToolCall(
          name,
          call.arguments ?? {},
          params.payload.taskDescriptor.allowedTools,
        );
        const safeCallId =
          typeof call.id === "string" &&
          SAFE_CALL_ID_REGEX.test(call.id) &&
          !/\d{4,}/.test(call.id)
            ? call.id
            : `call-${turn + 1}-${idx + 1}`;
        assertGoogleBoundMessage(
          "toolCall",
          {
            id: safeCallId,
            type: "function_call",
            name,
            arguments: validatedArgs,
          },
          `$.toolCall(${name})`,
        );
        stepCount += 1;
        toolCallsExecuted.push(name);

        const rawResultObj = await withWallClockBudget(
          params.toolExecutor(name, validatedArgs),
          startedAt,
          wallClockBudgetMs,
        );

        assertOutboundPrivacyInvariant(rawResultObj, sensitiveOriginals);
        const resultObj = replaceDigestsWithOpaqueHandles(
          rawResultObj,
          digestHandleState,
        );
        assertOutboundPrivacyInvariant(resultObj, sensitiveOriginals);
        assertGoogleBoundMessage(
          `toolResult:${name}`,
          resultObj,
          `$.toolResult(${name})`,
        );
        assertContentFree(resultObj, `$.toolResult(${name})`);

        const resultStep: Record<string, unknown> = {
          type: "function_result",
          call_id: safeCallId,
          name,
          result: canonicalJson(resultObj),
        };
        assertOutboundPrivacyInvariant(resultStep, sensitiveOriginals);
        assertGoogleBoundMessage(
          "functionResult",
          resultStep,
          `$.functionResult(${name})`,
        );
        assertContentFree(resultStep, `$.functionResult(${name})`);
        fnResults.push(resultStep);
      }

      const safePrevId =
        typeof interaction.id === "string" &&
        SAFE_CALL_ID_REGEX.test(interaction.id) &&
        !/\d{4,}/.test(interaction.id)
          ? interaction.id
          : `inter-argon-turn-${turn + 1}`;

      const followUpRequest: Record<string, unknown> = {
        model: params.payload.model,
        background: params.payload.background,
        store: false,
        previous_interaction_id: safePrevId,
        generation_config: {
          thinking_level: params.payload.thinking_level,
          max_output_tokens: params.payload.max_output_tokens,
        },
        input: fnResults,
        tools: params.payload.tools,
      };

      assertOutboundPrivacyInvariant(followUpRequest, sensitiveOriginals);
      assertGoogleBoundMessage(
        "followUpRequest",
        followUpRequest,
        `$.followUpRequest(${turn + 1})`,
      );
      assertContentFree(followUpRequest, `$.followUpRequest(${turn + 1})`);

      const followUpAbortController = new AbortController();
      const followUpOptions = {
        timeout_ms: Math.max(10, wallClockBudgetMs - (Date.now() - startedAt)),
        retries: { strategy: "none" },
        fetch_options: { signal: followUpAbortController.signal },
      };

      interaction = await withWallClockBudget(
        client.interactions.create(followUpRequest, followUpOptions),
        startedAt,
        wallClockBudgetMs,
      ).finally(() => followUpAbortController.abort());

      if (typeof interaction.usage?.total_input_tokens === "number") {
        totalInputTokens += interaction.usage.total_input_tokens;
      }
      if (typeof interaction.usage?.total_output_tokens === "number") {
        totalOutputTokens += interaction.usage.total_output_tokens;
      }
      turn += 1;
    }

    const latencyMs = Math.max(1, Date.now() - startedAt);
    let rawOutputText = interaction.output_text;
    if (!rawOutputText && Array.isArray(interaction.steps)) {
      for (const s of interaction.steps) {
        if (s.type === "model_output" && Array.isArray(s.content)) {
          const txt = s.content
            .map((c) => (typeof c.text === "string" ? c.text : ""))
            .join("")
            .trim();
          if (txt) {
            rawOutputText = txt;
            break;
          }
        }
      }
    }

    const safeTelemetrySummary = sanitizeUntrustedModelOutput(rawOutputText);
    const safeInteractionId =
      typeof interaction.id === "string" &&
      SAFE_CALL_ID_REGEX.test(interaction.id) &&
      !/\d{4,}/.test(interaction.id)
        ? interaction.id
        : undefined;
    const safeInteractionStatus =
      typeof interaction.status === "string" &&
      ALLOWED_INTERACTION_STATUSES.has(interaction.status)
        ? interaction.status
        : "completed";

    return {
      attemptedLiveCall: true,
      liveEndpointReached: true,
      sdkMethod: "client.interactions.create",
      interactionId: safeInteractionId,
      interactionStatus: safeInteractionStatus,
      toolCallsExecuted,
      ...(Object.keys(digestHandleState.byHandle).length > 0
        ? { resolvedDigestHandles: { ...digestHandleState.byHandle } }
        : {}),
      liveSummaryText:
        safeTelemetrySummary ||
        `Gemini 4 Argon control-plane interaction completed (${toolCallsExecuted.length} tool call(s) executed over content-free handles).`,
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
      modelCallRecord: {
        model: params.payload.model,
        purpose: "Split-knowledge control-plane planner (content-free TaskDescriptor only)",
        ok: true,
        latencyMs,
        ...(totalInputTokens > 0 ? { inputTokens: totalInputTokens } : {}),
        ...(totalOutputTokens > 0 ? { outputTokens: totalOutputTokens } : {}),
      },
    };
  } catch (err) {
    if (
      err instanceof PrivacyInvariantViolationError ||
      err instanceof ContentFreeEgressError ||
      err instanceof ToolPolicyViolationError ||
      err instanceof PlannerBudgetExceededError
    ) {
      throw err;
    }
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const rawMsg = err instanceof Error ? err.message : "SDK error";
    const safeMsg = resolvedKey ? rawMsg.split(resolvedKey).join("[REDACTED_KEY]") : rawMsg;

    return {
      attemptedLiveCall: true,
      liveEndpointReached: false,
      sdkMethod: "client.interactions.create",
      toolCallsExecuted,
      fallbackReason: `Gemini Interactions SDK call failed (${safeMsg.slice(0, 180)}); falling back to Tinfoil enclave planner.`,
      dataSentToGoogle: DATA_SENT_TO_GOOGLE,
      egressFirewallVerified: true,
      modelCallRecord: {
        model: params.payload.model,
        purpose: "Split-knowledge control-plane planner (content-free TaskDescriptor only)",
        ok: false,
        latencyMs,
        error: safeMsg.slice(0, 180),
      },
    };
  }
}

/**
 * Executes the autonomous tool-calling planner and enclave execution loop using an
 * attested Tinfoil enclave model (`kimi-k3` or `gemma4-31b`) via OpenAI-compatible
 * tool calls on the `tinfoil` SDK.
 *
 * Goes through the exact same tool allowlist, argument validation (`assertValidToolCall`),
 * handle plumbing, and step/time budgets as the Gemini planner.
 */
export async function callTinfoilPlannerToolLoop(params: {
  model: "gemma4-31b" | "kimi-k3";
  taskDescriptor?: TaskDescriptor;
  scrubbedPrompt: string;
  systemInstruction?: string;
  apiKey?: string;
  sensitiveOriginals?: readonly string[];
  toolExecutor?: ArgonToolExecutor;
  tinfoilClient?: TinfoilPlannerClientLike;
  enableNetworkCall?: boolean;
  maxTurns?: number;
  maxSteps?: number;
  wallClockBudgetMs?: number;
}): Promise<TinfoilPlannerCallResult> {
  const sensitiveOriginals = params.sensitiveOriginals ?? [];
  const systemInstruction =
    params.systemInstruction ??
    "You are the autonomous confidential security and routing planner for deRoute running inside an attested Tinfoil enclave. " +
      "Never output unredacted personal details or secrets, and never use em dashes. " +
      "Plan over the TaskDescriptor using the handle-based verification tools ($INPUT, $RESULT_1) and provide a concise verification summary repeating the masked identifiers.";

  // Enforce Privacy Invariant before checking credentials or making any SDK call
  assertOutboundPrivacyInvariant(params.scrubbedPrompt, sensitiveOriginals);
  assertOutboundPrivacyInvariant(systemInstruction, sensitiveOriginals);
  if (params.taskDescriptor) {
    assertGoogleBoundMessage(
      "taskDescriptor",
      params.taskDescriptor,
      "$.tinfoilTaskDescriptor",
    );
    assertContentFree(params.taskDescriptor, "$.tinfoilTaskDescriptor");
  }

  const resolvedKey =
    params.apiKey?.trim() ||
    (typeof process !== "undefined" ? process.env?.TINFOIL_API_KEY?.trim() : "") ||
    "";

  const canCallLive =
    Boolean(params.tinfoilClient) ||
    (Boolean(params.enableNetworkCall) &&
      typeof window === "undefined" &&
      Boolean(resolvedKey));

  if (!canCallLive) {
    return {
      attemptedLiveCall: false,
      liveEndpointReached: false,
      sdkMethod: "tinfoil.chat.completions.create",
      model: params.model,
      toolCallsExecuted: [],
      fallbackReason:
        "Tinfoil enclave network inference skipped (no TINFOIL_API_KEY configured or offline test mode).",
    };
  }

  const maxSteps = Math.min(
    MAX_PLANNER_STEPS,
    Math.max(1, Math.trunc(params.maxSteps ?? MAX_PLANNER_STEPS)),
  );
  const wallClockBudgetMs = Math.min(
    MAX_PLANNER_WALL_CLOCK_MS,
    Math.max(10, Math.trunc(params.wallClockBudgetMs ?? MAX_PLANNER_WALL_CLOCK_MS)),
  );

  const startedAt = Date.now();
  const toolCallsExecuted: string[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  try {
    let client: TinfoilPlannerClientLike;
    if (params.tinfoilClient) {
      client = params.tinfoilClient;
    } else {
      const { TinfoilAI } = await import("tinfoil");
      client = new TinfoilAI({
        apiKey: resolvedKey,
      }) as unknown as TinfoilPlannerClientLike;
    }

    if (typeof client.ready === "function") {
      await withWallClockBudget(client.ready(), startedAt, wallClockBudgetMs);
    }

    const openAiTools = buildTinfoilOpenAITools(ARGON_CONFIDENTIAL_TOOLS);
    const userContent = params.taskDescriptor
      ? `TaskDescriptor: ${JSON.stringify(params.taskDescriptor)}\n\nEnclave Handle ($INPUT): ${params.scrubbedPrompt}`
      : params.scrubbedPrompt;
    assertOutboundPrivacyInvariant(userContent, sensitiveOriginals);

    const messages: Array<Record<string, unknown>> = [
      { role: "system", content: systemInstruction },
      { role: "user", content: userContent },
    ];

    const maxTurns = Math.min(
      maxSteps,
      params.maxTurns ?? (params.tinfoilClient ? 4 : 2),
    );
    let stepCount = 0;
    let completionId: string | undefined;
    let finalText = "";

    for (let turn = 0; turn < maxTurns; turn++) {
      const reqPayload: Record<string, unknown> = {
        model: params.model,
        messages: [...messages],
        tools: openAiTools,
        tool_choice: "auto",
        max_tokens: 280,
      };
      assertOutboundPrivacyInvariant(reqPayload, sensitiveOriginals);

      let response: TinfoilChatCompletionResponse;
      try {
        response = await withWallClockBudget(
          client.chat.completions.create(reqPayload, {
            headers: { "X-Tinfoil-Model": params.model },
          }),
          startedAt,
          wallClockBudgetMs,
        );
      } catch (toolCallErr) {
        if (
          toolCallErr instanceof PrivacyInvariantViolationError ||
          toolCallErr instanceof ToolPolicyViolationError ||
          toolCallErr instanceof PlannerBudgetExceededError
        ) {
          throw toolCallErr;
        }
        if (turn === 0) {
          const plainReq: Record<string, unknown> = {
            model: params.model,
            messages: [...messages],
            max_tokens: 240,
          };
          assertOutboundPrivacyInvariant(plainReq, sensitiveOriginals);
          response = await withWallClockBudget(
            client.chat.completions.create(plainReq, {
              headers: { "X-Tinfoil-Model": params.model },
            }),
            startedAt,
            wallClockBudgetMs,
          );
        } else {
          throw toolCallErr;
        }
      }

      if (response.id) {
        completionId = response.id;
      }
      if (typeof response.usage?.prompt_tokens === "number") {
        totalInputTokens += response.usage.prompt_tokens;
      }
      if (typeof response.usage?.completion_tokens === "number") {
        totalOutputTokens += response.usage.completion_tokens;
      }

      const msg = response.choices?.[0]?.message;
      const toolCalls = Array.isArray(msg?.tool_calls) ? msg.tool_calls : [];

      if (typeof msg?.content === "string" && msg.content.trim().length > 0) {
        finalText = sanitizeUntrustedModelOutput(msg.content);
      }

      if (toolCalls.length === 0 || !params.toolExecutor) {
        break;
      }

      if (stepCount + toolCalls.length > maxSteps) {
        throw new PlannerBudgetExceededError("max_steps", maxSteps);
      }

      const validatedToolCallsForTurn: Array<{
        safeTcId: string;
        fnName: string;
        validatedArgs: Record<string, unknown>;
        sanitizedToolCall: {
          id: string;
          type: "function";
          function: { name: string; arguments: string };
        };
      }> = [];

      for (let idx = 0; idx < toolCalls.length; idx++) {
        const tc = toolCalls[idx];
        const fnName =
          tc && typeof tc === "object" && typeof tc.function?.name === "string"
            ? tc.function.name.trim()
            : "";
        if (!fnName) {
          throw new ToolPolicyViolationError("<missing>", [
            "Tool call is missing function.name.",
          ]);
        }
        let parsedArgs: Record<string, unknown>;
        if (
          typeof tc.function?.arguments !== "string" ||
          !tc.function.arguments.trim()
        ) {
          throw new ToolPolicyViolationError(fnName, [
            "Tool arguments must be a non-empty JSON object string.",
          ]);
        }
        try {
          const parsed = JSON.parse(tc.function.arguments) as unknown;
          if (!isPlainObject(parsed)) {
            throw new Error("not a plain object");
          }
          parsedArgs = parsed;
        } catch {
          throw new ToolPolicyViolationError(fnName, [
            "Tool arguments must be a valid JSON object.",
          ]);
        }
        assertOutboundPrivacyInvariant(parsedArgs, sensitiveOriginals);
        const validatedArgs = assertValidToolCall(
          fnName,
          parsedArgs,
          params.taskDescriptor?.allowedTools,
        );
        const safeTcId =
          typeof tc.id === "string" &&
          SAFE_CALL_ID_REGEX.test(tc.id) &&
          !/\d{4,}/.test(tc.id)
            ? tc.id
            : `tc-${turn + 1}-${idx + 1}`;
        const sanitizedToolCall = {
          id: safeTcId,
          type: "function" as const,
          function: {
            name: fnName,
            arguments: canonicalJson(validatedArgs),
          },
        };
        assertGoogleBoundMessage(
          "toolCall",
          sanitizedToolCall,
          `$.tinfoilToolCall(${fnName})`,
        );
        assertContentFree(sanitizedToolCall, `$.tinfoilToolCall(${fnName})`);
        validatedToolCallsForTurn.push({
          safeTcId,
          fnName,
          validatedArgs,
          sanitizedToolCall,
        });
      }

      messages.push({
        role: "assistant",
        content: finalText || null,
        tool_calls: validatedToolCallsForTurn.map((v) => v.sanitizedToolCall),
      });

      const digestHandleState = createDigestHandleMapState();
      for (const {
        safeTcId,
        fnName,
        validatedArgs,
      } of validatedToolCallsForTurn) {
        stepCount += 1;
        toolCallsExecuted.push(fnName);

        const rawToolResult = await withWallClockBudget(
          params.toolExecutor(fnName, validatedArgs),
          startedAt,
          wallClockBudgetMs,
        );
        assertOutboundPrivacyInvariant(rawToolResult, sensitiveOriginals);
        const toolResult = replaceDigestsWithOpaqueHandles(
          rawToolResult,
          digestHandleState,
        );
        assertOutboundPrivacyInvariant(toolResult, sensitiveOriginals);
        assertGoogleBoundMessage(
          `tinfoilToolResult:${fnName}`,
          toolResult,
          `$.tinfoilToolResult(${fnName})`,
        );
        assertContentFree(toolResult, `$.tinfoilToolResult(${fnName})`);

        const toolMsg: Record<string, unknown> = {
          role: "tool",
          tool_call_id: safeTcId,
          name: fnName,
          content: canonicalJson(toolResult),
        };
        assertOutboundPrivacyInvariant(toolMsg, sensitiveOriginals);
        messages.push(toolMsg);
      }
    }

    const latencyMs = Math.max(1, Date.now() - startedAt);
    return {
      attemptedLiveCall: true,
      liveEndpointReached: true,
      sdkMethod: "tinfoil.chat.completions.create",
      model: params.model,
      completionId,
      toolCallsExecuted,
      finalText:
        finalText ||
        `Tinfoil enclave planner (${params.model}) executed ${toolCallsExecuted.length} tool call(s) over RFC 9180 HPKE.`,
      modelCallRecord: {
        model: params.model,
        purpose: `Autonomous Tinfoil enclave planner & content execution (${params.model} over RFC 9180 HPKE)`,
        ok: true,
        latencyMs,
        ...(totalInputTokens > 0 ? { inputTokens: totalInputTokens } : {}),
        ...(totalOutputTokens > 0 ? { outputTokens: totalOutputTokens } : {}),
      },
    };
  } catch (err) {
    if (
      err instanceof PrivacyInvariantViolationError ||
      err instanceof ContentFreeEgressError ||
      err instanceof ToolPolicyViolationError ||
      err instanceof PlannerBudgetExceededError
    ) {
      throw err;
    }
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const rawMsg = err instanceof Error ? err.message : "Tinfoil planner error";
    const safeMsg = resolvedKey ? rawMsg.split(resolvedKey).join("[REDACTED_KEY]") : rawMsg;

    return {
      attemptedLiveCall: true,
      liveEndpointReached: false,
      sdkMethod: "tinfoil.chat.completions.create",
      model: params.model,
      toolCallsExecuted,
      fallbackReason: `Tinfoil planner SDK call failed (${safeMsg.slice(0, 180)}).`,
      modelCallRecord: {
        model: params.model,
        purpose: `Autonomous Tinfoil enclave planner & content execution (${params.model})`,
        ok: false,
        latencyMs,
        error: safeMsg.slice(0, 180),
      },
    };
  }
}

/**
 * Deprecated companion subagent helper kept only for backward-compatible exports.
 * Enforces `assertContentFree` on any input so free text can never reach Google.
 */
export async function callCompanionSubagentInteraction(params: {
  model:
    | typeof ARGON_COMPANION_MODELS.parallelSubagentFast
    | typeof ARGON_COMPANION_MODELS.parallelSubagentLite;
  purpose: string;
  scrubbedInput: string;
  apiKey?: string;
  sensitiveOriginals?: readonly string[];
  genaiClient?: GenAIInteractionsClientLike;
}): Promise<{
  liveReached: boolean;
  summaryText?: string;
  modelCallRecord?: ArgonModelCallRecord;
}> {
  const sensitiveOriginals = params.sensitiveOriginals ?? [];
  assertOutboundPrivacyInvariant(params.scrubbedInput, sensitiveOriginals);
  assertContentFree(params.scrubbedInput, "$.companionSubagent.scrubbedInput");
  return { liveReached: false };
}
