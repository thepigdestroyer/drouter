/**
 * Split-Knowledge Control-Plane Egress Firewall (`assertContentFree`),
 * TaskDescriptor Validator with Power-of-Two Bucketing & Redaction Capping (A3),
 * Closed Lookup Vocabulary (`LOOKUP_TOPICS`, E1), and Strict Tool Schema Validator.
 *
 * Ported from `src/lib/gemini/interactions.ts` for `deroute-core` (no cross-boundary imports).
 */

import { canonicalJson } from "./canonical.js";

export const GEMINI_4_ARGON_MODEL_ID = "gemini-4-argon";
export const DATA_SENT_TO_GOOGLE = "content-free task descriptor only";

export const VALID_THINKING_LEVELS = ["low", "medium", "high"];

export const VALID_TASK_KINDS = [
  "summarize",
  "analyze",
  "draft",
  "review",
  "question",
];

export const ALLOWED_PLANNER_TOOLS = [
  "scrub_and_symmetry_mask",
  "verify_two_hop_enclave_and_quorum",
  "search_atlas_hybrid_kb",
  "invoke_attested_enclave",
  "anchor_arc_settlement_with_human_gate",
];

export const ALLOWED_ATLAS_TOPICS = [
  "tinfoil_enclave",
  "sev_snp_router",
  "tdx_gpu_cc",
  "hpke_ehbp",
  "arc_registry",
  "blind_credits",
  "pii_redaction",
];

export const ALLOWED_ATLAS_CATEGORIES = [
  "provider",
  "advisory",
  "architecture",
  "all",
];

/**
 * Closed lookup vocabulary (Wave 6 Decision E1.1 & E1.4).
 * `assertContentFree` permits these exact topic identifiers as enum literals.
 */
export const LOOKUP_TOPICS = [
  "provider:tinfoil",
  "provider:phala-redpill",
  "provider:near-ai-cloud",
  "provider:venice-ai",
  "provider:prem-ai",
  "provider:ppq-ai",
  "provider:confidential-ai",
  "provider:chutes-bittensor",
  "provider:privatemode-cosmian",
  "provider:nanogpt",
  "hardware:intel-tdx",
  "hardware:amd-sev-snp",
  "hardware:nvidia-cc",
  "attack:memory-bus",
  "attack:side-channel",
  "attack:voltage-glitching",
  "crypto:hpke",
  "crypto:blind-signatures",
  "crypto:pqc-ml-kem",
  "policy:data-retention",
  "policy:sigstore-rekor",
  "policy:arc-settlement",
];

export const ALLOWED_REDACTION_COUNT_KEYS = new Set([
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
]);

export const ALLOWED_VERIFICATION_KEYS = new Set([
  "mechanicalRedactionPassed",
  "attestedPiiFilterVerified",
  "bucketAligned4096",
  "routerSevSnpVerified",
  "enclaveTdxGpuVerified",
  "hpkeKeyBound",
  "sigstoreManifestVerified",
  "arcRegistryVerified",
]);

export const MAX_REDACTION_COUNT_PER_KIND = 5;
export const MAX_TOKEN_BUCKET = 1_048_576;
export const MAX_PLANNER_STEPS = 5;
export const MAX_PLANNER_WALL_CLOCK_MS = 20_000;

export const SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION =
  "SPLIT_KNOWLEDGE_CONTROL_PLANE_V1: Plan over the content-free TaskDescriptor using only opaque handles ($INPUT, $RESULT_n) and allowlisted enums. Never request or emit user text.";

export const ARGON_CONFIDENTIAL_TOOLS = [
  {
    type: "function",
    name: "scrub_and_symmetry_mask",
    description:
      "Runs mechanical redaction, attested enclave PII filtering, symmetry masking, and RFC 8259 bucket padding on an opaque input handle.",
    parameters: {
      type: "OBJECT",
      properties: {
        inputHandle: {
          type: "STRING",
          description: "Opaque input handle ($INPUT or $RESULT_n).",
        },
        bucketQuantumBytes: {
          type: "INTEGER",
          description: "Byte padding quantum in bytes.",
        },
      },
      required: ["inputHandle", "bucketQuantumBytes"],
    },
  },
  {
    type: "function",
    name: "verify_two_hop_enclave_and_quorum",
    description:
      "Verifies live Tinfoil two-hop hardware attestation (AMD SEV-SNP router and Intel TDX with NVIDIA Confidential Computing GPUs), Sigstore Rekor release digest, and Circle Arc registry admission.",
    parameters: {
      type: "OBJECT",
      properties: {
        providerId: {
          type: "STRING",
          description: "Target confidential compute provider identifier (tinfoil).",
          enum: ["tinfoil"],
        },
        enclaveModel: {
          type: "STRING",
          description: "Target attested enclave model identifier (gemma4-31b or kimi-k3).",
          enum: ["gemma4-31b", "kimi-k3"],
        },
      },
      required: ["providerId", "enclaveModel"],
    },
  },
  {
    type: "function",
    name: "search_atlas_hybrid_kb",
    description:
      "Executes MongoDB Atlas Hybrid Search ($rankFusion combining $vectorSearch and $search) over confidential compute intelligence using a content-free topic enum or server-resolved handle.",
    parameters: {
      type: "OBJECT",
      properties: {
        topic: {
          type: "STRING",
          description:
            "Content-free technical topic enum (tinfoil_enclave, sev_snp_router, tdx_gpu_cc, hpke_ehbp, arc_registry, blind_credits, pii_redaction).",
          enum: [...ALLOWED_ATLAS_TOPICS, ...LOOKUP_TOPICS],
        },
        inputHandle: {
          type: "STRING",
          description:
            "Optional opaque handle ($INPUT or $RESULT_n) resolved on the server after mechanical redaction.",
        },
        category: {
          type: "STRING",
          description: "Optional category filter (provider, advisory, architecture, all).",
          enum: ALLOWED_ATLAS_CATEGORIES,
        },
      },
      required: ["topic"],
    },
  },
  {
    type: "function",
    name: "invoke_attested_enclave",
    description:
      "Dispatches the server-resolved handle to the verified Tinfoil confidential enclave (gemma4-31b or kimi-k3) over RFC 9180 HPKE Encrypted HTTP Body and stores the enclave output in a new server handle.",
    parameters: {
      type: "OBJECT",
      properties: {
        inputHandle: {
          type: "STRING",
          description: "Opaque handle ($INPUT or $RESULT_n) resolved server-side for enclave execution.",
        },
        enclaveModel: {
          type: "STRING",
          description: "Attested Tinfoil enclave model identifier (gemma4-31b or kimi-k3).",
          enum: ["gemma4-31b", "kimi-k3"],
        },
        taskKind: {
          type: "STRING",
          description: "Task kind enum (summarize, analyze, draft, review, question).",
          enum: VALID_TASK_KINDS,
        },
      },
      required: ["inputHandle", "enclaveModel"],
    },
  },
  {
    type: "function",
    name: "anchor_arc_settlement_with_human_gate",
    description:
      "Requests anchoring the verified execution receipt hash on Circle Arc Testnet (chainId 5042002) subject to mandatory server-enforced human approval.",
    parameters: {
      type: "OBJECT",
      properties: {
        actionKind: {
          type: "STRING",
          description: "Settlement action kind (anchor_receipt).",
          enum: ["anchor_receipt"],
        },
        resultHandle: {
          type: "STRING",
          description:
            "Optional opaque result handle ($INPUT or $RESULT_n) whose receipt hash will be anchored.",
        },
        humanApproved: {
          type: "BOOLEAN",
          description: "Whether human approval was requested (enforced independently by server state).",
        },
      },
      required: ["actionKind", "humanApproved"],
    },
  },
];

export class PrivacyInvariantViolationError extends Error {
  constructor(leakedToken, messageOverride) {
    super(
      messageOverride ??
        `PRIVACY_INVARIANT_VIOLATION: Outbound planner payload contained unredacted or non-allowlisted value (${String(leakedToken).slice(0, 12)}***). Call aborted before network transmission.`,
    );
    this.name = "PrivacyInvariantViolationError";
    this.leakedToken = leakedToken;
  }
}

export class ContentFreeEgressError extends PrivacyInvariantViolationError {
  constructor(rejectedValue, path = "$") {
    super(
      rejectedValue,
      `CONTENT_FREE_EGRESS_VIOLATION at ${path}: Outbound Gemini payload contained non-allowlisted string or content (${String(rejectedValue).slice(0, 16)}***). Only opaque handles, fixed SHA-256 hashes, booleans, numbers, and allowlisted enums may leave the enclave to Google.`,
    );
    this.name = "ContentFreeEgressError";
    this.path = path;
  }
}

export class TaskDescriptorValidationError extends Error {
  constructor(errors) {
    super(`INVALID_TASK_DESCRIPTOR: ${errors.join("; ")}`);
    this.name = "TaskDescriptorValidationError";
    this.errors = errors;
  }
}

export class ToolPolicyViolationError extends Error {
  constructor(toolName, validationErrors) {
    super(`TOOL_POLICY_VIOLATION (${toolName}): ${validationErrors.join("; ")}`);
    this.name = "ToolPolicyViolationError";
    this.toolName = toolName;
    this.validationErrors = validationErrors;
  }
}

export class PlannerBudgetExceededError extends Error {
  constructor(kind, limit) {
    super(
      kind === "max_steps"
        ? `PLANNER_BUDGET_EXCEEDED: Planner exceeded maximum step budget (${limit} steps).`
        : `PLANNER_BUDGET_EXCEEDED: Planner exceeded wall-clock budget (${limit} ms).`,
    );
    this.name = "PlannerBudgetExceededError";
    this.kind = kind;
    this.limit = limit;
  }
}

const OPAQUE_HANDLE_REGEX =
  /^(?:\$INPUT|\$(?:RESULT|DOC|RECEIPT|DIGEST|ROUTER|MEASUREMENT)_(?:[1-9]|[1-5]\d|6[0-4]))$/;
const SHORT_HEX_REGEX = /^0x(?:[0-9a-f]{2}){1,7}$/;
const FIXED_SHA256_HEX_REGEX = /^0x[0-9a-f]{64}$/;
export const MAX_GOOGLE_BOUND_HEX_LENGTH = 16;

/**
 * Compatibility flag allowing legacy 64-char SHA-256 digests ONLY on unmigrated local
 * `orchestrator.ts` `toolExecutor` outputs (`path === "$"` or `$.toolExecutor.result(...)`
 * when `insideJsonString === false`) until the controller applies the orchestrator diff.
 * Google-bound payloads (`createRequest`, `followUpRequest`, `functionResult`, `toolResult`,
 * `payload`, `interactionsPayload`, `outboundGeminiRequest`, `canonicalRequest`, `taskDescriptor`,
 * and all JSON-encoded strings `insideJsonString === true`) unconditionally reject any hex > 16 chars.
 */
export const ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED = false;

export const SAFE_CALL_ID_REGEX =
  /^(?:call|tc|inter)-(?:[1-9]\d{0,2}|turn-[1-9]\d{0,1}|argon-turn-[1-9]|(?:[1-9]-)?(?:scrub_and_symmetry_mask|verify_two_hop_enclave_and_quorum|search_atlas_hybrid_kb|invoke_attested_enclave|anchor_arc_settlement_with_human_gate)|[1-9]-[1-9]\d{0,1})$/;

export const ALLOWED_HANDLE_KEYS = new Set([
  "inputHandle",
  "outputHandle",
  "resultHandle",
  "docHandle",
  "topDocHandle",
  "receiptHandle",
  "digestHandle",
  "contentHandle",
  "outputDigestHandle",
  "routerHandle",
  "enclaveMeasurementHandle",
]);

export const ALLOWED_HASH_KEYS = new Set([
  "contentSha256",
  "routerDigestHex",
  "enclaveMeasurementHex",
  "topDocSha256",
  "outputSha256",
  "receiptSha256",
]);

export const ALLOWED_NUMERIC_KEYS = new Set([
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

export const ALLOWED_BOOLEAN_KEYS = new Set([
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

export const ALLOWED_ARRAY_KEYS = new Set([
  "input",
  "tools",
  "allowedTools",
  "required",
  "enum",
  "messages",
  "tool_calls",
]);

const ALLOWED_STRING_ARRAY_KEYS = new Set([
  "allowedTools",
  "required",
  "enum",
]);

const ALLOWED_JSON_STRING_KEYS = new Set([
  "text",
  "content",
  "result",
]);

const ALLOWED_OBJECT_ONLY_KEYS = new Set([
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

const ALLOWED_STATIC_SCHEMA_DESCRIPTIONS = new Set([
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ...ARGON_CONFIDENTIAL_TOOLS.flatMap((t) => [
    t.description,
    ...Object.values(t.parameters.properties).map((p) => p.description),
  ]),
]);

export const ALLOWED_CONTENT_FREE_ENUMS = new Set([
  // Model & SDK identifiers
  GEMINI_4_ARGON_MODEL_ID,
  "antigravity-preview-09-2026",
  "gemini-3.8-flash",
  "gemini-3.5-flash-lite",
  "deep-research-preview-04-2026",
  "gemini-3.8-live",
  "gemini-3.8-flash-tts",
  "gemma-4-31b-it",
  "gemma-4-e4b",
  "gemma4-31b",
  "kimi-k3",
  "pii-filter",
  "@google/genai>=2.31.0",
  "client.interactions.create",
  "redacted_clinical_scientist_persona",
  "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves",
  DATA_SENT_TO_GOOGLE,

  // Thinking levels & config enums
  ...VALID_THINKING_LEVELS,
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

  // Tool argument & result status enums + closed lookup vocabulary
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

export const ALLOWED_CONTENT_FREE_KEYS = new Set([
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
  ...ALLOWED_REDACTION_COUNT_KEYS,

  // Allowed verification boolean keys
  ...ALLOWED_VERIFICATION_KEYS,

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

const ALLOWED_REQUIRED_PARAM_NAMES = new Set([
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

export const ALLOWED_OBJECT_KEYS = new Set([
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
];

function isStrictGoogleBoundPath(path, insideJsonString) {
  if (insideJsonString) {
    return true;
  }
  if (typeof path !== "string") {
    return false;
  }
  for (let i = 0; i < GOOGLE_BOUND_PATH_PREFIXES.length; i++) {
    if (path.startsWith(GOOGLE_BOUND_PATH_PREFIXES[i])) {
      return true;
    }
  }
  return false;
}

function hasAsciiRunOrCount(byteValues) {
  let consecutivePrintableAscii = 0;
  let totalPrintableLettersOrSpaces = 0;
  let totalPrintableAscii = 0;
  for (let i = 0; i < byteValues.length; i++) {
    const byteVal = byteValues[i];
    if (byteVal >= 0x20 && byteVal <= 0x7e) {
      consecutivePrintableAscii += 1;
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
      consecutivePrintableAscii >= 4 ||
      totalPrintableLettersOrSpaces >= 4 ||
      totalPrintableAscii >= Math.max(3, Math.ceil(byteValues.length * 0.7))
    );
  }
  return totalPrintableLettersOrSpaces >= 18 || totalPrintableAscii >= 20;
}

export function hasSmuggledAsciiInHex(hexWithoutPrefix) {
  if (
    typeof hexWithoutPrefix !== "string" ||
    hexWithoutPrefix.length < 2 ||
    hexWithoutPrefix.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(hexWithoutPrefix)
  ) {
    return true;
  }
  if (/^\d+$/.test(hexWithoutPrefix)) {
    return true;
  }
  if (
    /^([0-9a-f]{1,4})\1{15,}$/.test(hexWithoutPrefix) ||
    (hexWithoutPrefix.length <= 14 && /^([0-9a-f]{1,2})\1{2,}$/.test(hexWithoutPrefix))
  ) {
    return true;
  }
  const bytes = [];
  const freq = new Map();
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
      if (consecutiveLow7Text >= (bytes.length < 16 ? 4 : 16)) {
        return true;
      }
      if ((b & 0x80) !== 0) {
        consecutiveHighBitText += 1;
        if (isLetterOrSpace) {
          totalHighBitLettersOrSpaces += 1;
        }
        if (consecutiveHighBitText >= (bytes.length < 16 ? 4 : 8)) {
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
      totalHighBitLettersOrSpaces >= 4 ||
      totalLow7Text >= Math.max(3, Math.ceil(bytes.length * 0.7))
    );
  }
  return totalHighBitLettersOrSpaces >= 16 || totalLow7Text >= 28;
}

export function isContentFreeString(value, keyContext, strictGoogleBound = false) {
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
    return OPAQUE_HANDLE_REGEX.test(value);
  }
  if (/^(?:0x)?[0-9a-fA-F]{15,}$/.test(value) && value.length > MAX_GOOGLE_BOUND_HEX_LENGTH) {
    return false;
  }
  if (OPAQUE_HANDLE_REGEX.test(value)) {
    return true;
  }
  return ALLOWED_CONTENT_FREE_ENUMS.has(value);
}

const HASH_KEY_TO_HANDLE_SPEC = {
  topDocSha256: { handleKey: "topDocHandle", prefix: "DOC" },
  receiptSha256: { handleKey: "receiptHandle", prefix: "RECEIPT" },
  contentSha256: { handleKey: "contentHandle", prefix: "DIGEST" },
  outputSha256: { handleKey: "outputDigestHandle", prefix: "DIGEST" },
  routerDigestHex: { handleKey: "routerHandle", prefix: "ROUTER" },
  enclaveMeasurementHex: { handleKey: "enclaveMeasurementHandle", prefix: "MEASUREMENT" },
};

export function createDigestHandleMapState() {
  return {
    byHandle: {},
    byDigest: new Map(),
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
  rawResult,
  state = createDigestHandleMapState(),
) {
  if (!isPlainObject(rawResult)) {
    return rawResult;
  }
  const out = {};
  for (const [key, value] of Object.entries(rawResult)) {
    const spec = HASH_KEY_TO_HANDLE_SPEC[key];
    if (spec && typeof value === "string") {
      if (OPAQUE_HANDLE_REGEX.test(value)) {
        out[spec.handleKey] = value;
        continue;
      }
      const cacheKey = `${spec.prefix}:${value}`;
      let handle = state.byDigest.get(cacheKey);
      if (!handle) {
        const nextIdx = Math.min(64, (state.counters[spec.prefix] ?? 0) + 1);
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

function isPlainObject(value) {
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
  value,
  path = "$",
  keyContext,
  depth = 0,
  insideJsonString = false,
  isJsonRoot = false,
) {
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
    if (
      !keyContext ||
      !ALLOWED_NUMERIC_KEYS.has(keyContext) ||
      !Number.isInteger(value) ||
      Object.is(value, -0) ||
      value < 0 ||
      value > MAX_TOKEN_BUCKET
    ) {
      throw new ContentFreeEgressError(String(value), path);
    }
    if (
      ALLOWED_REDACTION_COUNT_KEYS.has(keyContext) &&
      value > MAX_REDACTION_COUNT_PER_KIND
    ) {
      throw new ContentFreeEgressError(String(value), path);
    }
    return;
  }
  if (valueType === "string") {
    if (value.length === 0 || value.trim().length === 0) {
      throw new ContentFreeEgressError("<empty_string>", path);
    }
    if (value.startsWith("{") || value.startsWith("[")) {
      if (
        insideJsonString ||
        !keyContext ||
        !ALLOWED_JSON_STRING_KEYS.has(keyContext) ||
        !value.startsWith("{") ||
        !value.endsWith("}")
      ) {
        throw new ContentFreeEgressError(value, path);
      }
      let parsed;
      try {
        parsed = JSON.parse(value);
      } catch {
        throw new ContentFreeEgressError(value, path);
      }
      if (!isPlainObject(parsed)) {
        throw new ContentFreeEgressError(value, path);
      }
      let canonical;
      try {
        canonical = canonicalJson(parsed);
      } catch {
        throw new ContentFreeEgressError(value, path);
      }
      if (canonical !== value) {
        throw new ContentFreeEgressError(value, path);
      }
      assertContentFree(parsed, `${path}(json)`, undefined, depth + 1, true, true);
      return;
    }
    const strictGoogleBound = isStrictGoogleBoundPath(path, insideJsonString);
    if (!isContentFreeString(value, keyContext, strictGoogleBound)) {
      throw new ContentFreeEgressError(value, path);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (
      !keyContext ||
      !ALLOWED_ARRAY_KEYS.has(keyContext) ||
      value.length > 32
    ) {
      throw new ContentFreeEgressError("<disallowed_array>", path);
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
      Boolean(keyContext) &&
      ALLOWED_REQUIRED_PARAM_NAMES.has(keyContext) &&
      typeof path === "string" &&
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
    if (typeof value.toJSON === "function") {
      throw new ContentFreeEgressError("<custom_toJSON>", path);
    }
    const ownKeys = Object.getOwnPropertyNames(value);
    if (ownKeys.length > 64) {
      throw new ContentFreeEgressError("<too_many_keys>", path);
    }
    for (const k of ownKeys) {
      if (
        k === "__proto__" ||
        k === "constructor" ||
        k === "prototype" ||
        !ALLOWED_CONTENT_FREE_KEYS.has(k)
      ) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      const desc = Object.getOwnPropertyDescriptor(value, k);
      if (!desc || !("value" in desc) || desc.enumerable !== true) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (desc.value === undefined) {
        continue;
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
 * Checks whether an integer `n` is a positive power of two (1, 2, 4, 8, ..., 1048576).
 */
export function isPowerOfTwo(n) {
  return Number.isInteger(n) && n >= 1 && n <= MAX_TOKEN_BUCKET && (n & (n - 1)) === 0;
}

/**
 * Rounds any positive number up to the next power-of-two bucket in [1, MAX_TOKEN_BUCKET] (Wave 6 A3).
 */
export function roundUpToPowerOfTwo(n) {
  const clamped = Math.max(1, Math.min(MAX_TOKEN_BUCKET, Math.ceil(Number(n) || 1)));
  let bucket = 1;
  while (bucket < clamped && bucket < MAX_TOKEN_BUCKET) {
    bucket *= 2;
  }
  return bucket;
}

/**
 * Normalizes a raw descriptor into a bucketed `TaskDescriptor` (Wave 6 Amendment A3):
 * - `inputTokenEstimate` rounded up to a power-of-two bucket
 * - `redactionCounts` capped at 5 per kind (`0..5`)
 */
export function bucketTaskDescriptor(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TaskDescriptorValidationError(["TaskDescriptor must be a non-null plain object."]);
  }
  const taskKind = VALID_TASK_KINDS.includes(raw.taskKind) ? raw.taskKind : "analyze";
  const inputTokenEstimate = roundUpToPowerOfTwo(raw.inputTokenEstimate ?? 1024);

  const redactionCounts = {};
  if (raw.redactionCounts && typeof raw.redactionCounts === "object") {
    for (const [k, v] of Object.entries(raw.redactionCounts)) {
      if (ALLOWED_REDACTION_COUNT_KEYS.has(k) && typeof v === "number" && Number.isFinite(v)) {
        redactionCounts[k] = Math.min(MAX_REDACTION_COUNT_PER_KIND, Math.max(0, Math.trunc(v)));
      }
    }
  }
  if (Object.keys(redactionCounts).length === 0) {
    redactionCounts.TOTAL = 0;
  }

  const verification = {};
  if (raw.verification && typeof raw.verification === "object") {
    for (const [k, v] of Object.entries(raw.verification)) {
      if (ALLOWED_VERIFICATION_KEYS.has(k) && typeof v === "boolean") {
        verification[k] = v;
      }
    }
  }
  if (Object.keys(verification).length === 0) {
    verification.mechanicalRedactionPassed = true;
  }

  const allowedTools = Array.isArray(raw.allowedTools)
    ? ALLOWED_PLANNER_TOOLS.filter((t) => raw.allowedTools.includes(t))
    : [...ALLOWED_PLANNER_TOOLS];

  return {
    taskKind,
    inputHandle: "$INPUT",
    inputTokenEstimate,
    redactionCounts,
    verification,
    allowedTools: allowedTools.length > 0 ? allowedTools : [...ALLOWED_PLANNER_TOOLS],
  };
}

function previewToken(v) {
  return String(v).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 32);
}

const REQUIRED_DESCRIPTOR_KEYS = [
  "taskKind",
  "inputHandle",
  "inputTokenEstimate",
  "redactionCounts",
  "verification",
  "allowedTools",
];
const ALLOWED_DESCRIPTOR_KEY_SET = new Set(REQUIRED_DESCRIPTOR_KEYS);

/**
 * Strictly validates an incoming `TaskDescriptor` for `POST /agent/plan`:
 * - Only accepts the exact 6 `TaskDescriptor` fields (or `{ taskDescriptor }` wrapper with no other keys)
 * - `taskKind` must be in `VALID_TASK_KINDS`
 * - `inputHandle` must be `"$INPUT"`
 * - `inputTokenEstimate` must be an integer power of two in `[1, 1048576]` (A3 bucketing)
 * - `redactionCounts` keys must be in `ALLOWED_REDACTION_COUNT_KEYS` and values integers in `0..5` (A3 cap)
 * - `verification` keys must be in `ALLOWED_VERIFICATION_KEYS` and values booleans
 * - `allowedTools` must be a non-empty array of unique tool names from `ALLOWED_PLANNER_TOOLS`
 * - Passes `assertContentFree`
 */
export function validateTaskDescriptor(input) {
  if (!isPlainObject(input)) {
    return {
      valid: false,
      errors: ["Request body must be a non-null plain JSON object."],
    };
  }

  // Unwrap `{ taskDescriptor: { ... } }` if that is the only key on the outer object.
  let candidate = input;
  const outerKeys = Object.getOwnPropertyNames(input);
  if (outerKeys.includes("taskDescriptor")) {
    if (outerKeys.length !== 1) {
      return {
        valid: false,
        errors: [
          `Unexpected outer fields alongside 'taskDescriptor': ${outerKeys
            .filter((k) => k !== "taskDescriptor")
            .slice(0, 8)
            .map(previewToken)
            .join(", ")}.`,
        ],
      };
    }
    candidate = input.taskDescriptor;
    if (!isPlainObject(candidate)) {
      return {
        valid: false,
        errors: ["'taskDescriptor' must be a non-null plain JSON object."],
      };
    }
  }

  const errors = [];
  const candidateKeys = Object.getOwnPropertyNames(candidate);

  for (const key of candidateKeys) {
    if (!ALLOWED_DESCRIPTOR_KEY_SET.has(key)) {
      errors.push(`Unexpected field '${previewToken(key)}' on TaskDescriptor.`);
    }
  }
  for (const reqKey of REQUIRED_DESCRIPTOR_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(candidate, reqKey)) {
      errors.push(`Missing required field '${reqKey}' on TaskDescriptor.`);
    }
  }

  if (!VALID_TASK_KINDS.includes(candidate.taskKind)) {
    errors.push(
      `Invalid taskKind '${previewToken(candidate.taskKind)}'. Must be one of: ${VALID_TASK_KINDS.join(", ")}.`,
    );
  }

  if (candidate.inputHandle !== "$INPUT") {
    errors.push(
      `Invalid inputHandle '${previewToken(candidate.inputHandle)}'. Must be the literal handle '$INPUT'.`,
    );
  }

  if (!isPowerOfTwo(candidate.inputTokenEstimate)) {
    errors.push(
      `Invalid inputTokenEstimate '${previewToken(candidate.inputTokenEstimate)}'. Must be a power-of-two integer bucket between 1 and ${MAX_TOKEN_BUCKET}.`,
    );
  }

  if (!isPlainObject(candidate.redactionCounts)) {
    errors.push("'redactionCounts' must be a non-null plain object.");
  } else {
    const rcEntries = Object.entries(candidate.redactionCounts);
    if (rcEntries.length === 0) {
      errors.push("'redactionCounts' must contain at least one redaction category count.");
    }
    for (const [k, v] of rcEntries) {
      if (!ALLOWED_REDACTION_COUNT_KEYS.has(k)) {
        errors.push(`Invalid redactionCounts key '${previewToken(k)}'.`);
      }
      if (
        typeof v !== "number" ||
        !Number.isInteger(v) ||
        v < 0 ||
        v > MAX_REDACTION_COUNT_PER_KIND
      ) {
        errors.push(
          `Invalid redactionCounts['${previewToken(k)}'] = ${previewToken(v)}. Must be an integer capped in 0..${MAX_REDACTION_COUNT_PER_KIND}.`,
        );
      }
    }
  }

  if (!isPlainObject(candidate.verification)) {
    errors.push("'verification' must be a non-null plain object.");
  } else {
    const verEntries = Object.entries(candidate.verification);
    if (verEntries.length === 0) {
      errors.push("'verification' must contain at least one boolean verification flag.");
    }
    for (const [k, v] of verEntries) {
      if (!ALLOWED_VERIFICATION_KEYS.has(k)) {
        errors.push(`Invalid verification key '${previewToken(k)}'.`);
      }
      if (typeof v !== "boolean") {
        errors.push(`Invalid verification['${previewToken(k)}']: must be a boolean.`);
      }
    }
  }

  if (!Array.isArray(candidate.allowedTools) || candidate.allowedTools.length === 0) {
    errors.push("'allowedTools' must be a non-empty array of allowed planner tools.");
  } else {
    const seen = new Set();
    for (const tool of candidate.allowedTools) {
      if (typeof tool !== "string" || !ALLOWED_PLANNER_TOOLS.includes(tool)) {
        errors.push(`Invalid tool '${previewToken(tool)}' in allowedTools.`);
      } else if (seen.has(tool)) {
        errors.push(`Duplicate tool '${previewToken(tool)}' in allowedTools.`);
      } else {
        seen.add(tool);
      }
    }
  }

  if (errors.length === 0) {
    try {
      assertContentFree(candidate, "$.taskDescriptor");
    } catch (err) {
      errors.push(err instanceof Error ? err.message : "Failed assertContentFree.");
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    errors: [],
    descriptor: {
      taskKind: candidate.taskKind,
      inputHandle: "$INPUT",
      inputTokenEstimate: candidate.inputTokenEstimate,
      redactionCounts: { ...candidate.redactionCounts },
      verification: { ...candidate.verification },
      allowedTools: ALLOWED_PLANNER_TOOLS.filter((t) => candidate.allowedTools.includes(t)),
    },
  };
}

export function assertValidTaskDescriptor(input) {
  const res = validateTaskDescriptor(input);
  if (!res.valid || !res.descriptor) {
    throw new TaskDescriptorValidationError(res.errors);
  }
  return res.descriptor;
}

export const TOOL_ARGUMENT_SCHEMAS = {
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

export function validateToolCallArguments(toolName, args) {
  if (!ALLOWED_PLANNER_TOOLS.includes(toolName)) {
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

  const schema = TOOL_ARGUMENT_SCHEMAS[toolName];
  const errors = [];
  const sanitizedArgs = {};

  for (const key of Object.keys(args)) {
    if (!Object.prototype.hasOwnProperty.call(schema, key)) {
      errors.push(`Unexpected argument '${key}' on tool '${toolName}'.`);
    }
  }

  for (const [field, spec] of Object.entries(schema)) {
    const val = args[field];
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
      if (spec.isHandle && !OPAQUE_HANDLE_REGEX.test(val)) {
        errors.push(
          `Argument '${field}' on '${toolName}' must be an opaque handle ($INPUT or $RESULT_1..$RESULT_64), got '${val.slice(0, 24)}'.`,
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

export function assertValidToolCall(toolName, args, allowedToolsSubset) {
  const res = validateToolCallArguments(toolName, args);
  if (!res.valid || !res.sanitizedArgs) {
    throw new ToolPolicyViolationError(toolName, res.errors);
  }
  if (Array.isArray(allowedToolsSubset) && !allowedToolsSubset.includes(toolName)) {
    throw new ToolPolicyViolationError(toolName, [
      `Tool '${toolName}' is not permitted by this descriptor's allowedTools list.`,
    ]);
  }
  return res.sanitizedArgs;
}

export function sanitizeUntrustedModelOutput(raw) {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/<[^>]*>/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 512);
}
