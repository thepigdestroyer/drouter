/**
 * Closed-Schema Egress Gate (`src/lib/gemini/egress-schemas.ts`).
 *
 * Replaces open-ended "inspect anything" validation as the primary gate with an
 * exact, closed schema validator per Google-bound message type:
 * - Exact key sets on every object (rejects any extra or missing keys, non-plain
 *   prototypes, symbol keys, non-enumerable properties, getters/setters, custom `toJSON`,
 *   or `undefined` values).
 * - Per-field primitive types, literal constants, and closed enum sets.
 * - Tight per-field integer bounds and power-of-two bucketing (`inputTokenEstimate`,
 *   `outputTokenEstimate`, `bucketQuantumBytes`, `bucketBytes`, `max_output_tokens`).
 * - Per-key handle grammars with `n <= 16` (`$INPUT` or `$RESULT_1..16` only on
 *   input/result handles, `$DOC_1..16` only on `topDocHandle`/`docHandle`,
 *   `$RECEIPT_1..16` only on `receiptHandle`, `$DIGEST_1..16` only on
 *   `contentHandle`/`outputDigestHandle`/`digestHandle`, `$ROUTER_1..16` only on
 *   `routerHandle`, `$MEASUREMENT_1..16` only on `enclaveMeasurementHandle`).
 * - Array length caps and element uniqueness (`allowedTools`, `tools`, `input`).
 * - Deep equality against our own constants for `model`, `system_instruction`,
 *   `ARGON_CONFIDENTIAL_TOOLS`, `subagent_routing`, and `metadata`.
 */

import { canonicalJson } from "@/lib/transparency/log";
import {
  ALLOWED_ATLAS_CATEGORIES,
  ALLOWED_ATLAS_TOPICS,
  ALLOWED_PLANNER_TOOLS,
  ALLOWED_REDACTION_COUNT_KEYS,
  ALLOWED_VERIFICATION_KEYS,
  ARGON_COMPANION_MODELS,
  ARGON_CONFIDENTIAL_TOOLS,
  ARGON_MAX_UNIFIED_CONTEXT_TOKENS,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  GEMINI_4_ARGON_MODEL_ID,
  LOOKUP_TOPICS,
  MAX_PLANNER_STEPS,
  MAX_REDACTION_COUNT_PER_KIND,
  MAX_TOKEN_BUCKET,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  VALID_TASK_KINDS,
  VALID_THINKING_LEVELS,
  type ArgonInteractionToolDeclaration,
  type InteractionsCreatePayload,
  type PlannerToolName,
  type TaskDescriptor,
} from "./interactions";

export const MAX_HANDLE_INDEX = 16;

export const INPUT_LITERAL_HANDLE_REGEX = /^\$INPUT$/;
export const INPUT_OR_RESULT_HANDLE_REGEX =
  /^(?:\$INPUT|\$RESULT_(?:[1-9]|1[0-6]))$/;
export const RESULT_HANDLE_REGEX = /^\$RESULT_(?:[1-9]|1[0-6])$/;
export const DOC_HANDLE_REGEX = /^\$DOC_(?:[1-9]|1[0-6])$/;
export const RECEIPT_HANDLE_REGEX = /^\$RECEIPT_(?:[1-9]|1[0-6])$/;
export const DIGEST_HANDLE_REGEX = /^\$DIGEST_(?:[1-9]|1[0-6])$/;
export const ROUTER_HANDLE_REGEX = /^\$ROUTER_(?:[1-9]|1[0-6])$/;
export const MEASUREMENT_HANDLE_REGEX = /^\$MEASUREMENT_(?:[1-9]|1[0-6])$/;

export const HANDLE_KEY_TO_REGEX: Readonly<Record<string, RegExp>> = {
  inputHandle: INPUT_OR_RESULT_HANDLE_REGEX,
  outputHandle: RESULT_HANDLE_REGEX,
  resultHandle: INPUT_OR_RESULT_HANDLE_REGEX,
  docHandle: DOC_HANDLE_REGEX,
  topDocHandle: DOC_HANDLE_REGEX,
  receiptHandle: RECEIPT_HANDLE_REGEX,
  digestHandle: DIGEST_HANDLE_REGEX,
  contentHandle: DIGEST_HANDLE_REGEX,
  outputDigestHandle: DIGEST_HANDLE_REGEX,
  routerHandle: ROUTER_HANDLE_REGEX,
  enclaveMeasurementHandle: MEASUREMENT_HANDLE_REGEX,
};

export const CLOSED_CALL_ID_REGEX =
  /^(?:call|tc|inter)-(?:[1-9]|1[0-6]|turn-(?:[1-9]|1[0-6])|argon-turn-(?:[1-9]|1[0-6])|(?:(?:[1-9]|1[0-6])-)?(?:scrub_and_symmetry_mask|verify_two_hop_enclave_and_quorum|search_atlas_hybrid_kb|invoke_attested_enclave|anchor_arc_settlement_with_human_gate)|(?:[1-9]|1[0-6])-(?:[1-9]|1[0-6]))$/;

const EXPECTED_SUBAGENT_ROUTING: Readonly<Record<string, string>> = {
  sandbox_verifier: ARGON_COMPANION_MODELS.sandboxAgent,
  fast_swarm: ARGON_COMPANION_MODELS.parallelSubagentFast,
  quorum_checker: ARGON_COMPANION_MODELS.parallelSubagentLite,
  deep_research: ARGON_COMPANION_MODELS.deepResearch,
  on_device_filter: ARGON_COMPANION_MODELS.confidentialOnDevice,
  attested_enclave_model: ARGON_COMPANION_MODELS.confidentialOpenCloud,
  tinfoil_enclave_target: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
  voice_briefing: ARGON_COMPANION_MODELS.voiceTts,
  live_voice_gate: ARGON_COMPANION_MODELS.realtimeVoice,
};

const EXPECTED_METADATA: Readonly<Record<string, string>> = {
  sdk_target: "@google/genai>=2.31.0",
  api_surface: "client.interactions.create",
  persona: "redacted_clinical_scientist_persona",
  enclave_protocol:
    "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves",
  data_sent_to_google: DATA_SENT_TO_GOOGLE,
};

const ALLOWED_SEARCH_TOPICS_SET: ReadonlySet<string> = new Set<string>([
  ...ALLOWED_ATLAS_TOPICS,
  ...LOOKUP_TOPICS,
]);

const ALLOWED_ATLAS_CATEGORIES_SET: ReadonlySet<string> = new Set<string>(
  ALLOWED_ATLAS_CATEGORIES,
);

const VALID_TASK_KINDS_SET: ReadonlySet<string> = new Set<string>(
  VALID_TASK_KINDS,
);

const VALID_THINKING_LEVELS_SET: ReadonlySet<string> = new Set<string>(
  VALID_THINKING_LEVELS,
);

export function isPowerOfTwoInRange(
  value: unknown,
  min: number,
  max: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    !Object.is(value, -0) &&
    value >= min &&
    value <= max &&
    (value & (value - 1)) === 0
  );
}

function boundedInteger(
  value: unknown,
  min: number,
  max: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    !Object.is(value, -0) &&
    value >= min &&
    value <= max
  );
}

function assertStrictPlainObject(
  value: unknown,
  path: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.prototype.toString.call(value) !== "[object Object]"
  ) {
    throw new ContentFreeEgressError(String(value), path);
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new ContentFreeEgressError("<non_plain_prototype>", path);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new ContentFreeEgressError("<symbol_property>", path);
  }
  const rec = value as Record<string, unknown>;
  if (typeof rec.toJSON === "function") {
    throw new ContentFreeEgressError("<custom_toJSON>", path);
  }
  const ownKeys = Object.getOwnPropertyNames(rec);
  if (ownKeys.length === 0) {
    throw new ContentFreeEgressError("<empty_object>", path);
  }
  for (const k of ownKeys) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
    const desc = Object.getOwnPropertyDescriptor(rec, k);
    if (!desc || !("value" in desc) || desc.enumerable !== true) {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
    if (desc.value === undefined) {
      throw new ContentFreeEgressError("undefined", `${path}.${k}`);
    }
  }
  return rec;
}

function assertExactKeys(
  obj: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  path: string,
): void {
  const allowed = new Set<string>([...requiredKeys, ...optionalKeys]);
  const ownKeys = Object.getOwnPropertyNames(obj);
  for (const k of ownKeys) {
    if (!allowed.has(k)) {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
  }
  for (const req of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(obj, req)) {
      throw new ContentFreeEgressError(`<missing:${req}>`, `${path}.${req}`);
    }
  }
}

function assertDeepEqualConstant(
  actual: unknown,
  expected: unknown,
  path: string,
): void {
  if (actual === expected) {
    return;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) {
      throw new ContentFreeEgressError("<array_mismatch>", path);
    }
    for (let i = 0; i < expected.length; i++) {
      assertDeepEqualConstant(actual[i], expected[i], `${path}[${i}]`);
    }
    return;
  }
  if (expected && typeof expected === "object") {
    const actualObj = assertStrictPlainObject(actual, path);
    const expectedObj = expected as Record<string, unknown>;
    const expectedKeys = Object.keys(expectedObj);
    assertExactKeys(actualObj, expectedKeys, [], path);
    for (const k of expectedKeys) {
      assertDeepEqualConstant(actualObj[k], expectedObj[k], `${path}.${k}`);
    }
    return;
  }
  throw new ContentFreeEgressError(String(actual), path);
}

function assertValidToolsArray(
  toolsValue: unknown,
  expectedToolNames: readonly string[],
  path: string,
): void {
  if (
    !Array.isArray(toolsValue) ||
    toolsValue.length === 0 ||
    toolsValue.length > ALLOWED_PLANNER_TOOLS.length
  ) {
    throw new ContentFreeEgressError("<invalid_tools_array>", path);
  }
  const expectedDecls: ArgonInteractionToolDeclaration[] =
    ARGON_CONFIDENTIAL_TOOLS.filter((t) => expectedToolNames.includes(t.name));
  if (toolsValue.length !== expectedDecls.length) {
    throw new ContentFreeEgressError("<tools_length_mismatch>", path);
  }
  for (let i = 0; i < expectedDecls.length; i++) {
    assertDeepEqualConstant(toolsValue[i], expectedDecls[i], `${path}[${i}]`);
  }
}

function assertGenerationConfig(
  value: unknown,
  path: string,
): { thinking_level: string; max_output_tokens: number } {
  const obj = assertStrictPlainObject(value, path);
  assertExactKeys(obj, ["thinking_level", "max_output_tokens"], [], path);
  const thinkingLevel = obj.thinking_level;
  if (
    typeof thinkingLevel !== "string" ||
    !VALID_THINKING_LEVELS_SET.has(thinkingLevel)
  ) {
    throw new ContentFreeEgressError(
      String(thinkingLevel),
      `${path}.thinking_level`,
    );
  }
  const maxOutputTokens = obj.max_output_tokens;
  if (!isPowerOfTwoInRange(maxOutputTokens, 1024, 131_072)) {
    throw new ContentFreeEgressError(
      String(maxOutputTokens),
      `${path}.max_output_tokens`,
    );
  }
  return {
    thinking_level: thinkingLevel,
    max_output_tokens: maxOutputTokens,
  };
}

/**
 * 1. Closed schema validator for `TaskDescriptor`.
 */
export function assertTaskDescriptorSchema(
  payload: unknown,
  path = "$.taskDescriptor",
): TaskDescriptor {
  const obj = assertStrictPlainObject(payload, path);
  assertExactKeys(
    obj,
    [
      "taskKind",
      "inputHandle",
      "inputTokenEstimate",
      "redactionCounts",
      "verification",
      "allowedTools",
    ],
    [],
    path,
  );

  if (
    typeof obj.taskKind !== "string" ||
    !VALID_TASK_KINDS_SET.has(obj.taskKind)
  ) {
    throw new ContentFreeEgressError(String(obj.taskKind), `${path}.taskKind`);
  }

  if (
    typeof obj.inputHandle !== "string" ||
    !INPUT_LITERAL_HANDLE_REGEX.test(obj.inputHandle)
  ) {
    throw new ContentFreeEgressError(
      String(obj.inputHandle),
      `${path}.inputHandle`,
    );
  }

  if (!isPowerOfTwoInRange(obj.inputTokenEstimate, 1, MAX_TOKEN_BUCKET)) {
    throw new ContentFreeEgressError(
      String(obj.inputTokenEstimate),
      `${path}.inputTokenEstimate`,
    );
  }

  const rcObj = assertStrictPlainObject(
    obj.redactionCounts,
    `${path}.redactionCounts`,
  );
  const rcKeys = Object.getOwnPropertyNames(rcObj);
  if (rcKeys.length > ALLOWED_REDACTION_COUNT_KEYS.size) {
    throw new ContentFreeEgressError(
      "<too_many_redaction_keys>",
      `${path}.redactionCounts`,
    );
  }
  for (const k of rcKeys) {
    if (!ALLOWED_REDACTION_COUNT_KEYS.has(k)) {
      throw new ContentFreeEgressError(k, `${path}.redactionCounts.${k}`);
    }
    if (!boundedInteger(rcObj[k], 0, MAX_REDACTION_COUNT_PER_KIND)) {
      throw new ContentFreeEgressError(
        String(rcObj[k]),
        `${path}.redactionCounts.${k}`,
      );
    }
  }

  const verObj = assertStrictPlainObject(
    obj.verification,
    `${path}.verification`,
  );
  const verKeys = Object.getOwnPropertyNames(verObj);
  if (verKeys.length > ALLOWED_VERIFICATION_KEYS.size) {
    throw new ContentFreeEgressError(
      "<too_many_verification_keys>",
      `${path}.verification`,
    );
  }
  for (const k of verKeys) {
    if (!ALLOWED_VERIFICATION_KEYS.has(k)) {
      throw new ContentFreeEgressError(k, `${path}.verification.${k}`);
    }
    if (typeof verObj[k] !== "boolean") {
      throw new ContentFreeEgressError(
        String(verObj[k]),
        `${path}.verification.${k}`,
      );
    }
  }

  const tools = obj.allowedTools;
  if (
    !Array.isArray(tools) ||
    tools.length === 0 ||
    tools.length > ALLOWED_PLANNER_TOOLS.length
  ) {
    throw new ContentFreeEgressError(
      "<invalid_allowedTools>",
      `${path}.allowedTools`,
    );
  }
  const seenTools = new Set<string>();
  let lastCanonicalIdx = -1;
  for (let i = 0; i < tools.length; i++) {
    const t = tools[i];
    if (typeof t !== "string") {
      throw new ContentFreeEgressError(
        String(t),
        `${path}.allowedTools[${i}]`,
      );
    }
    const canonicalIdx = (ALLOWED_PLANNER_TOOLS as readonly string[]).indexOf(t);
    if (canonicalIdx === -1 || seenTools.has(t) || canonicalIdx <= lastCanonicalIdx) {
      throw new ContentFreeEgressError(t, `${path}.allowedTools[${i}]`);
    }
    seenTools.add(t);
    lastCanonicalIdx = canonicalIdx;
  }

  return obj as unknown as TaskDescriptor;
}

/**
 * 2. Closed schema validator for `InteractionsCreatePayload`.
 */
export function assertInteractionsCreatePayloadSchema(
  payload: unknown,
  path = "$.interactionsPayload",
): InteractionsCreatePayload {
  const obj = assertStrictPlainObject(payload, path);
  assertExactKeys(
    obj,
    [
      "model",
      "thinking_level",
      "background",
      "max_output_tokens",
      "max_context_tokens",
      "implicit_caching",
      "generation_config",
      "system_instruction",
      "taskDescriptor",
      "input",
      "tools",
      "subagent_routing",
      "metadata",
    ],
    [],
    path,
  );

  if (obj.model !== GEMINI_4_ARGON_MODEL_ID) {
    throw new ContentFreeEgressError(String(obj.model), `${path}.model`);
  }
  if (
    typeof obj.thinking_level !== "string" ||
    !VALID_THINKING_LEVELS_SET.has(obj.thinking_level)
  ) {
    throw new ContentFreeEgressError(
      String(obj.thinking_level),
      `${path}.thinking_level`,
    );
  }
  if (typeof obj.background !== "boolean") {
    throw new ContentFreeEgressError(
      String(obj.background),
      `${path}.background`,
    );
  }
  if (!isPowerOfTwoInRange(obj.max_output_tokens, 1024, 131_072)) {
    throw new ContentFreeEgressError(
      String(obj.max_output_tokens),
      `${path}.max_output_tokens`,
    );
  }
  if (obj.max_context_tokens !== ARGON_MAX_UNIFIED_CONTEXT_TOKENS) {
    throw new ContentFreeEgressError(
      String(obj.max_context_tokens),
      `${path}.max_context_tokens`,
    );
  }
  if (obj.implicit_caching !== "enabled") {
    throw new ContentFreeEgressError(
      String(obj.implicit_caching),
      `${path}.implicit_caching`,
    );
  }

  const genCfg = assertGenerationConfig(
    obj.generation_config,
    `${path}.generation_config`,
  );
  if (
    genCfg.thinking_level !== obj.thinking_level ||
    genCfg.max_output_tokens !== obj.max_output_tokens
  ) {
    throw new ContentFreeEgressError(
      "<generation_config_mismatch>",
      `${path}.generation_config`,
    );
  }

  if (obj.system_instruction !== SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION) {
    throw new ContentFreeEgressError(
      String(obj.system_instruction),
      `${path}.system_instruction`,
    );
  }

  const descriptor = assertTaskDescriptorSchema(
    obj.taskDescriptor,
    `${path}.taskDescriptor`,
  );

  if (!Array.isArray(obj.input) || obj.input.length !== 1) {
    throw new ContentFreeEgressError("<invalid_input>", `${path}.input`);
  }
  const inputItem = assertStrictPlainObject(obj.input[0], `${path}.input[0]`);
  assertExactKeys(inputItem, ["role", "content"], [], `${path}.input[0]`);
  if (inputItem.role !== "user") {
    throw new ContentFreeEgressError(
      String(inputItem.role),
      `${path}.input[0].role`,
    );
  }
  const expectedCanonicalDescriptor = canonicalJson(descriptor);
  if (inputItem.content !== expectedCanonicalDescriptor) {
    throw new ContentFreeEgressError(
      String(inputItem.content),
      `${path}.input[0].content`,
    );
  }

  assertValidToolsArray(obj.tools, ALLOWED_PLANNER_TOOLS, `${path}.tools`);
  assertDeepEqualConstant(
    obj.subagent_routing,
    EXPECTED_SUBAGENT_ROUTING,
    `${path}.subagent_routing`,
  );
  assertDeepEqualConstant(
    obj.metadata,
    EXPECTED_METADATA,
    `${path}.metadata`,
  );

  return obj as unknown as InteractionsCreatePayload;
}

/**
 * 3. Closed schema validator for `createRequest` (`client.interactions.create` initial turn).
 */
export function assertGeminiCreateRequestSchema(
  payload: unknown,
  path = "$.createRequest",
): void {
  const obj = assertStrictPlainObject(payload, path);
  assertExactKeys(
    obj,
    [
      "model",
      "background",
      "store",
      "system_instruction",
      "generation_config",
      "input",
      "tools",
    ],
    [],
    path,
  );

  if (obj.model !== GEMINI_4_ARGON_MODEL_ID) {
    throw new ContentFreeEgressError(String(obj.model), `${path}.model`);
  }
  if (typeof obj.background !== "boolean") {
    throw new ContentFreeEgressError(
      String(obj.background),
      `${path}.background`,
    );
  }
  if (obj.store !== false) {
    throw new ContentFreeEgressError(String(obj.store), `${path}.store`);
  }
  if (obj.system_instruction !== SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION) {
    throw new ContentFreeEgressError(
      String(obj.system_instruction),
      `${path}.system_instruction`,
    );
  }

  assertGenerationConfig(obj.generation_config, `${path}.generation_config`);

  if (!Array.isArray(obj.input) || obj.input.length !== 1) {
    throw new ContentFreeEgressError("<invalid_input>", `${path}.input`);
  }
  const inputItem = assertStrictPlainObject(obj.input[0], `${path}.input[0]`);
  assertExactKeys(inputItem, ["type", "text"], [], `${path}.input[0]`);
  if (inputItem.type !== "text") {
    throw new ContentFreeEgressError(
      String(inputItem.type),
      `${path}.input[0].type`,
    );
  }
  if (typeof inputItem.text !== "string") {
    throw new ContentFreeEgressError(
      String(inputItem.text),
      `${path}.input[0].text`,
    );
  }
  let parsedText: unknown;
  try {
    parsedText = JSON.parse(inputItem.text);
  } catch {
    throw new ContentFreeEgressError(inputItem.text, `${path}.input[0].text`);
  }
  const descriptor = assertTaskDescriptorSchema(
    parsedText,
    `${path}.input[0].text(json)`,
  );
  if (canonicalJson(descriptor) !== inputItem.text) {
    throw new ContentFreeEgressError(inputItem.text, `${path}.input[0].text`);
  }

  // `tools` must match either the full ARGON_CONFIDENTIAL_TOOLS list or the exact canonical subset in descriptor.allowedTools
  const toolsList = obj.tools;
  if (!Array.isArray(toolsList)) {
    throw new ContentFreeEgressError("<invalid_tools>", `${path}.tools`);
  }
  const expectedSubset =
    toolsList.length === ARGON_CONFIDENTIAL_TOOLS.length
      ? ALLOWED_PLANNER_TOOLS
      : descriptor.allowedTools;
  assertValidToolsArray(toolsList, expectedSubset, `${path}.tools`);
}

/**
 * 4. Closed schema validator for tool call arguments per `PlannerToolName`.
 */
export function assertToolCallArgumentsSchema(
  toolName: string,
  args: unknown,
  path = `$.toolCall(${toolName})`,
): Record<string, unknown> {
  if (!(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(toolName)) {
    throw new ContentFreeEgressError(String(toolName), path);
  }
  const obj = assertStrictPlainObject(args, path);

  switch (toolName as PlannerToolName) {
    case "scrub_and_symmetry_mask": {
      assertExactKeys(
        obj,
        ["inputHandle", "bucketQuantumBytes"],
        [],
        path,
      );
      if (
        typeof obj.inputHandle !== "string" ||
        !INPUT_OR_RESULT_HANDLE_REGEX.test(obj.inputHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.inputHandle),
          `${path}.inputHandle`,
        );
      }
      if (!isPowerOfTwoInRange(obj.bucketQuantumBytes, 512, 65_536)) {
        throw new ContentFreeEgressError(
          String(obj.bucketQuantumBytes),
          `${path}.bucketQuantumBytes`,
        );
      }
      return {
        inputHandle: obj.inputHandle,
        bucketQuantumBytes: obj.bucketQuantumBytes,
      };
    }

    case "verify_two_hop_enclave_and_quorum": {
      assertExactKeys(obj, ["providerId", "enclaveModel"], [], path);
      if (obj.providerId !== "tinfoil") {
        throw new ContentFreeEgressError(
          String(obj.providerId),
          `${path}.providerId`,
        );
      }
      if (obj.enclaveModel !== "gemma4-31b" && obj.enclaveModel !== "kimi-k3") {
        throw new ContentFreeEgressError(
          String(obj.enclaveModel),
          `${path}.enclaveModel`,
        );
      }
      return {
        providerId: obj.providerId,
        enclaveModel: obj.enclaveModel,
      };
    }

    case "search_atlas_hybrid_kb": {
      assertExactKeys(
        obj,
        ["topic"],
        ["inputHandle", "category"],
        path,
      );
      if (
        typeof obj.topic !== "string" ||
        !ALLOWED_SEARCH_TOPICS_SET.has(obj.topic)
      ) {
        throw new ContentFreeEgressError(String(obj.topic), `${path}.topic`);
      }
      const out: Record<string, unknown> = { topic: obj.topic };
      if (Object.prototype.hasOwnProperty.call(obj, "inputHandle")) {
        if (
          typeof obj.inputHandle !== "string" ||
          !INPUT_OR_RESULT_HANDLE_REGEX.test(obj.inputHandle)
        ) {
          throw new ContentFreeEgressError(
            String(obj.inputHandle),
            `${path}.inputHandle`,
          );
        }
        out.inputHandle = obj.inputHandle;
      }
      if (Object.prototype.hasOwnProperty.call(obj, "category")) {
        if (
          typeof obj.category !== "string" ||
          !ALLOWED_ATLAS_CATEGORIES_SET.has(obj.category)
        ) {
          throw new ContentFreeEgressError(
            String(obj.category),
            `${path}.category`,
          );
        }
        out.category = obj.category;
      }
      return out;
    }

    case "invoke_attested_enclave": {
      assertExactKeys(
        obj,
        ["inputHandle", "enclaveModel"],
        ["taskKind"],
        path,
      );
      if (
        typeof obj.inputHandle !== "string" ||
        !INPUT_OR_RESULT_HANDLE_REGEX.test(obj.inputHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.inputHandle),
          `${path}.inputHandle`,
        );
      }
      if (obj.enclaveModel !== "gemma4-31b" && obj.enclaveModel !== "kimi-k3") {
        throw new ContentFreeEgressError(
          String(obj.enclaveModel),
          `${path}.enclaveModel`,
        );
      }
      const out: Record<string, unknown> = {
        inputHandle: obj.inputHandle,
        enclaveModel: obj.enclaveModel,
      };
      if (Object.prototype.hasOwnProperty.call(obj, "taskKind")) {
        if (
          typeof obj.taskKind !== "string" ||
          !VALID_TASK_KINDS_SET.has(obj.taskKind)
        ) {
          throw new ContentFreeEgressError(
            String(obj.taskKind),
            `${path}.taskKind`,
          );
        }
        out.taskKind = obj.taskKind;
      }
      return out;
    }

    case "anchor_arc_settlement_with_human_gate": {
      assertExactKeys(
        obj,
        ["actionKind", "humanApproved"],
        ["resultHandle"],
        path,
      );
      if (obj.actionKind !== "anchor_receipt") {
        throw new ContentFreeEgressError(
          String(obj.actionKind),
          `${path}.actionKind`,
        );
      }
      if (typeof obj.humanApproved !== "boolean") {
        throw new ContentFreeEgressError(
          String(obj.humanApproved),
          `${path}.humanApproved`,
        );
      }
      const out: Record<string, unknown> = {
        actionKind: obj.actionKind,
        humanApproved: obj.humanApproved,
      };
      if (Object.prototype.hasOwnProperty.call(obj, "resultHandle")) {
        if (
          typeof obj.resultHandle !== "string" ||
          !INPUT_OR_RESULT_HANDLE_REGEX.test(obj.resultHandle)
        ) {
          throw new ContentFreeEgressError(
            String(obj.resultHandle),
            `${path}.resultHandle`,
          );
        }
        out.resultHandle = obj.resultHandle;
      }
      return out;
    }
  }
}

/**
 * Closed schema validator for a complete tool call object (Gemini `function_call` step or OpenAI `tool_call`).
 */
export function assertToolCallSchema(
  payload: unknown,
  path = "$.toolCall",
): { id: string; name: PlannerToolName; arguments: Record<string, unknown> } {
  const obj = assertStrictPlainObject(payload, path);

  if (Object.prototype.hasOwnProperty.call(obj, "function")) {
    assertExactKeys(obj, ["id", "type", "function"], [], path);
    if (typeof obj.id !== "string" || !CLOSED_CALL_ID_REGEX.test(obj.id)) {
      throw new ContentFreeEgressError(String(obj.id), `${path}.id`);
    }
    if (obj.type !== "function") {
      throw new ContentFreeEgressError(String(obj.type), `${path}.type`);
    }
    const fnObj = assertStrictPlainObject(obj.function, `${path}.function`);
    assertExactKeys(fnObj, ["name", "arguments"], [], `${path}.function`);
    if (
      typeof fnObj.name !== "string" ||
      !(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(fnObj.name)
    ) {
      throw new ContentFreeEgressError(
        String(fnObj.name),
        `${path}.function.name`,
      );
    }
    let parsedArgs: unknown = fnObj.arguments;
    if (typeof fnObj.arguments === "string") {
      try {
        parsedArgs = JSON.parse(fnObj.arguments);
      } catch {
        throw new ContentFreeEgressError(
          fnObj.arguments,
          `${path}.function.arguments`,
        );
      }
      const validated = assertToolCallArgumentsSchema(
        fnObj.name,
        parsedArgs,
        `${path}.function.arguments`,
      );
      if (canonicalJson(validated) !== fnObj.arguments) {
        throw new ContentFreeEgressError(
          fnObj.arguments,
          `${path}.function.arguments`,
        );
      }
      return {
        id: obj.id,
        name: fnObj.name as PlannerToolName,
        arguments: validated,
      };
    }
    const validated = assertToolCallArgumentsSchema(
      fnObj.name,
      parsedArgs,
      `${path}.function.arguments`,
    );
    return {
      id: obj.id,
      name: fnObj.name as PlannerToolName,
      arguments: validated,
    };
  }

  assertExactKeys(obj, ["id", "name", "arguments"], ["type"], path);
  if (
    Object.prototype.hasOwnProperty.call(obj, "type") &&
    obj.type !== "function_call"
  ) {
    throw new ContentFreeEgressError(String(obj.type), `${path}.type`);
  }
  if (typeof obj.id !== "string" || !CLOSED_CALL_ID_REGEX.test(obj.id)) {
    throw new ContentFreeEgressError(String(obj.id), `${path}.id`);
  }
  if (
    typeof obj.name !== "string" ||
    !(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(obj.name)
  ) {
    throw new ContentFreeEgressError(String(obj.name), `${path}.name`);
  }
  const validated = assertToolCallArgumentsSchema(
    obj.name,
    obj.arguments,
    `${path}.arguments`,
  );
  return {
    id: obj.id,
    name: obj.name as PlannerToolName,
    arguments: validated,
  };
}

/**
 * 5. Closed schema validator for each of the 5 tool result shapes.
 */
export function assertToolResultSchema(
  toolName: string,
  payload: unknown,
  path = `$.toolResult(${toolName})`,
): void {
  if (!(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(toolName)) {
    throw new ContentFreeEgressError(String(toolName), path);
  }
  const obj = assertStrictPlainObject(payload, path);

  switch (toolName as PlannerToolName) {
    case "scrub_and_symmetry_mask": {
      assertExactKeys(
        obj,
        [
          "status",
          "passed",
          "outputHandle",
          "redactionCount",
          "mechanicalRedactionCount",
          "attestedRedactionCount",
          "bucketBytes",
          "plaintextLeakCount",
          "contentHandle",
        ],
        [],
        path,
      );
      if (obj.status !== "ok" && obj.status !== "failed") {
        throw new ContentFreeEgressError(String(obj.status), `${path}.status`);
      }
      if (typeof obj.passed !== "boolean") {
        throw new ContentFreeEgressError(String(obj.passed), `${path}.passed`);
      }
      if (
        typeof obj.outputHandle !== "string" ||
        !RESULT_HANDLE_REGEX.test(obj.outputHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.outputHandle),
          `${path}.outputHandle`,
        );
      }
      if (!boundedInteger(obj.redactionCount, 0, 64)) {
        throw new ContentFreeEgressError(
          String(obj.redactionCount),
          `${path}.redactionCount`,
        );
      }
      if (!boundedInteger(obj.mechanicalRedactionCount, 0, 64)) {
        throw new ContentFreeEgressError(
          String(obj.mechanicalRedactionCount),
          `${path}.mechanicalRedactionCount`,
        );
      }
      if (!boundedInteger(obj.attestedRedactionCount, 0, 64)) {
        throw new ContentFreeEgressError(
          String(obj.attestedRedactionCount),
          `${path}.attestedRedactionCount`,
        );
      }
      if (!isPowerOfTwoInRange(obj.bucketBytes, 512, 65_536)) {
        throw new ContentFreeEgressError(
          String(obj.bucketBytes),
          `${path}.bucketBytes`,
        );
      }
      if (!boundedInteger(obj.plaintextLeakCount, 0, MAX_REDACTION_COUNT_PER_KIND)) {
        throw new ContentFreeEgressError(
          String(obj.plaintextLeakCount),
          `${path}.plaintextLeakCount`,
        );
      }
      if (
        typeof obj.contentHandle !== "string" ||
        !DIGEST_HANDLE_REGEX.test(obj.contentHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.contentHandle),
          `${path}.contentHandle`,
        );
      }
      return;
    }

    case "verify_two_hop_enclave_and_quorum": {
      assertExactKeys(
        obj,
        [
          "status",
          "passed",
          "providerId",
          "enclaveModel",
          "checksPassed",
          "checksTotal",
          "routerHandle",
          "enclaveMeasurementHandle",
        ],
        ["selfHealed", "failedOver"],
        path,
      );
      if (obj.status !== "verified" && obj.status !== "failed") {
        throw new ContentFreeEgressError(String(obj.status), `${path}.status`);
      }
      if (typeof obj.passed !== "boolean") {
        throw new ContentFreeEgressError(String(obj.passed), `${path}.passed`);
      }
      if (obj.providerId !== "tinfoil") {
        throw new ContentFreeEgressError(
          String(obj.providerId),
          `${path}.providerId`,
        );
      }
      if (obj.enclaveModel !== "gemma4-31b" && obj.enclaveModel !== "kimi-k3") {
        throw new ContentFreeEgressError(
          String(obj.enclaveModel),
          `${path}.enclaveModel`,
        );
      }
      if (!boundedInteger(obj.checksPassed, 0, 16)) {
        throw new ContentFreeEgressError(
          String(obj.checksPassed),
          `${path}.checksPassed`,
        );
      }
      if (!boundedInteger(obj.checksTotal, 1, 16)) {
        throw new ContentFreeEgressError(
          String(obj.checksTotal),
          `${path}.checksTotal`,
        );
      }
      if (
        typeof obj.routerHandle !== "string" ||
        !ROUTER_HANDLE_REGEX.test(obj.routerHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.routerHandle),
          `${path}.routerHandle`,
        );
      }
      if (
        typeof obj.enclaveMeasurementHandle !== "string" ||
        !MEASUREMENT_HANDLE_REGEX.test(obj.enclaveMeasurementHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.enclaveMeasurementHandle),
          `${path}.enclaveMeasurementHandle`,
        );
      }
      if (
        Object.prototype.hasOwnProperty.call(obj, "selfHealed") &&
        typeof obj.selfHealed !== "boolean"
      ) {
        throw new ContentFreeEgressError(
          String(obj.selfHealed),
          `${path}.selfHealed`,
        );
      }
      if (
        Object.prototype.hasOwnProperty.call(obj, "failedOver") &&
        typeof obj.failedOver !== "boolean"
      ) {
        throw new ContentFreeEgressError(
          String(obj.failedOver),
          `${path}.failedOver`,
        );
      }
      return;
    }

    case "search_atlas_hybrid_kb": {
      assertExactKeys(
        obj,
        [
          "status",
          "outputHandle",
          "vectorEngine",
          "textEngine",
          "fusionEngine",
          "totalDocs",
          "matchingReceiptsCount",
          "topDocHandle",
        ],
        [],
        path,
      );
      if (obj.status !== "ok" && obj.status !== "failed") {
        throw new ContentFreeEgressError(String(obj.status), `${path}.status`);
      }
      if (
        typeof obj.outputHandle !== "string" ||
        !RESULT_HANDLE_REGEX.test(obj.outputHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.outputHandle),
          `${path}.outputHandle`,
        );
      }
      if (obj.vectorEngine !== "atlas" && obj.vectorEngine !== "app-fallback") {
        throw new ContentFreeEgressError(
          String(obj.vectorEngine),
          `${path}.vectorEngine`,
        );
      }
      if (obj.textEngine !== "atlas" && obj.textEngine !== "app-fallback") {
        throw new ContentFreeEgressError(
          String(obj.textEngine),
          `${path}.textEngine`,
        );
      }
      if (
        obj.fusionEngine !== "$rankFusion" &&
        obj.fusionEngine !== "rank_fusion" &&
        obj.fusionEngine !== "app-rrf" &&
        obj.fusionEngine !== "app_rrf"
      ) {
        throw new ContentFreeEgressError(
          String(obj.fusionEngine),
          `${path}.fusionEngine`,
        );
      }
      if (!boundedInteger(obj.totalDocs, 0, 64)) {
        throw new ContentFreeEgressError(
          String(obj.totalDocs),
          `${path}.totalDocs`,
        );
      }
      if (!boundedInteger(obj.matchingReceiptsCount, 0, 64)) {
        throw new ContentFreeEgressError(
          String(obj.matchingReceiptsCount),
          `${path}.matchingReceiptsCount`,
        );
      }
      if (
        typeof obj.topDocHandle !== "string" ||
        !DOC_HANDLE_REGEX.test(obj.topDocHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.topDocHandle),
          `${path}.topDocHandle`,
        );
      }
      return;
    }

    case "invoke_attested_enclave": {
      assertExactKeys(
        obj,
        [
          "status",
          "outputHandle",
          "enclaveModel",
          "outputTokenEstimate",
          "outputDigestHandle",
          "attested",
        ],
        [],
        path,
      );
      if (obj.status !== "completed" && obj.status !== "failed") {
        throw new ContentFreeEgressError(String(obj.status), `${path}.status`);
      }
      if (
        typeof obj.outputHandle !== "string" ||
        !RESULT_HANDLE_REGEX.test(obj.outputHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.outputHandle),
          `${path}.outputHandle`,
        );
      }
      if (obj.enclaveModel !== "gemma4-31b" && obj.enclaveModel !== "kimi-k3") {
        throw new ContentFreeEgressError(
          String(obj.enclaveModel),
          `${path}.enclaveModel`,
        );
      }
      if (!isPowerOfTwoInRange(obj.outputTokenEstimate, 1, MAX_TOKEN_BUCKET)) {
        throw new ContentFreeEgressError(
          String(obj.outputTokenEstimate),
          `${path}.outputTokenEstimate`,
        );
      }
      if (
        typeof obj.outputDigestHandle !== "string" ||
        !DIGEST_HANDLE_REGEX.test(obj.outputDigestHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.outputDigestHandle),
          `${path}.outputDigestHandle`,
        );
      }
      if (typeof obj.attested !== "boolean") {
        throw new ContentFreeEgressError(
          String(obj.attested),
          `${path}.attested`,
        );
      }
      return;
    }

    case "anchor_arc_settlement_with_human_gate": {
      assertExactKeys(
        obj,
        [
          "status",
          "requiresHumanApproval",
          "humanApproved",
          "stateChangedOnChain",
          "receiptHandle",
        ],
        [],
        path,
      );
      if (
        obj.status !== "executed" &&
        obj.status !== "blocked_pending_human" &&
        obj.status !== "ready_for_anchor" &&
        obj.status !== "anchored" &&
        obj.status !== "failed"
      ) {
        throw new ContentFreeEgressError(String(obj.status), `${path}.status`);
      }
      if (typeof obj.requiresHumanApproval !== "boolean") {
        throw new ContentFreeEgressError(
          String(obj.requiresHumanApproval),
          `${path}.requiresHumanApproval`,
        );
      }
      if (typeof obj.humanApproved !== "boolean") {
        throw new ContentFreeEgressError(
          String(obj.humanApproved),
          `${path}.humanApproved`,
        );
      }
      if (typeof obj.stateChangedOnChain !== "boolean") {
        throw new ContentFreeEgressError(
          String(obj.stateChangedOnChain),
          `${path}.stateChangedOnChain`,
        );
      }
      if (
        typeof obj.receiptHandle !== "string" ||
        !RECEIPT_HANDLE_REGEX.test(obj.receiptHandle)
      ) {
        throw new ContentFreeEgressError(
          String(obj.receiptHandle),
          `${path}.receiptHandle`,
        );
      }
      return;
    }
  }
}

export function assertAnyToolResultSchema(
  payload: unknown,
  path = "$.toolResult",
): PlannerToolName {
  const obj = assertStrictPlainObject(payload, path);
  for (const toolName of ALLOWED_PLANNER_TOOLS) {
    try {
      assertToolResultSchema(toolName, obj, path);
      return toolName;
    } catch {
      // Try next closed tool result schema
    }
  }
  throw new ContentFreeEgressError("<unmatched_tool_result_schema>", path);
}

/**
 * 6. Closed schema validator for `function_result` step (`FunctionResultStep`).
 */
export function assertFunctionResultStepSchema(
  payload: unknown,
  path = "$.functionResult",
): { call_id: string; name: PlannerToolName } {
  const obj = assertStrictPlainObject(payload, path);
  assertExactKeys(obj, ["type", "call_id", "name", "result"], [], path);

  if (obj.type !== "function_result") {
    throw new ContentFreeEgressError(String(obj.type), `${path}.type`);
  }
  if (typeof obj.call_id !== "string" || !CLOSED_CALL_ID_REGEX.test(obj.call_id)) {
    throw new ContentFreeEgressError(String(obj.call_id), `${path}.call_id`);
  }
  if (
    typeof obj.name !== "string" ||
    !(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(obj.name)
  ) {
    throw new ContentFreeEgressError(String(obj.name), `${path}.name`);
  }
  if (typeof obj.result !== "string") {
    throw new ContentFreeEgressError(String(obj.result), `${path}.result`);
  }
  let parsedResult: unknown;
  try {
    parsedResult = JSON.parse(obj.result);
  } catch {
    throw new ContentFreeEgressError(obj.result, `${path}.result`);
  }
  assertToolResultSchema(obj.name, parsedResult, `${path}.result(json)`);
  if (canonicalJson(parsedResult) !== obj.result) {
    throw new ContentFreeEgressError(obj.result, `${path}.result`);
  }
  return {
    call_id: obj.call_id,
    name: obj.name as PlannerToolName,
  };
}

/**
 * 7. Closed schema validator for `followUpRequest` (`client.interactions.create` on follow-up turns).
 */
export function assertGeminiFollowUpRequestSchema(
  payload: unknown,
  path = "$.followUpRequest",
): void {
  const obj = assertStrictPlainObject(payload, path);
  assertExactKeys(
    obj,
    [
      "model",
      "background",
      "store",
      "previous_interaction_id",
      "generation_config",
      "input",
      "tools",
    ],
    [],
    path,
  );

  if (obj.model !== GEMINI_4_ARGON_MODEL_ID) {
    throw new ContentFreeEgressError(String(obj.model), `${path}.model`);
  }
  if (typeof obj.background !== "boolean") {
    throw new ContentFreeEgressError(
      String(obj.background),
      `${path}.background`,
    );
  }
  if (obj.store !== false) {
    throw new ContentFreeEgressError(String(obj.store), `${path}.store`);
  }
  if (
    typeof obj.previous_interaction_id !== "string" ||
    !CLOSED_CALL_ID_REGEX.test(obj.previous_interaction_id)
  ) {
    throw new ContentFreeEgressError(
      String(obj.previous_interaction_id),
      `${path}.previous_interaction_id`,
    );
  }

  assertGenerationConfig(obj.generation_config, `${path}.generation_config`);

  if (
    !Array.isArray(obj.input) ||
    obj.input.length === 0 ||
    obj.input.length > MAX_PLANNER_STEPS
  ) {
    throw new ContentFreeEgressError("<invalid_followup_input>", `${path}.input`);
  }
  const seenCallIds = new Set<string>();
  for (let i = 0; i < obj.input.length; i++) {
    const step = assertFunctionResultStepSchema(
      obj.input[i],
      `${path}.input[${i}]`,
    );
    if (seenCallIds.has(step.call_id)) {
      throw new ContentFreeEgressError(
        step.call_id,
        `${path}.input[${i}].call_id`,
      );
    }
    seenCallIds.add(step.call_id);
  }

  const toolsList = obj.tools;
  if (
    !Array.isArray(toolsList) ||
    toolsList.length === 0 ||
    toolsList.length > ALLOWED_PLANNER_TOOLS.length
  ) {
    throw new ContentFreeEgressError("<invalid_tools>", `${path}.tools`);
  }
  const toolNames = toolsList.map((t) =>
    t && typeof t === "object" ? String((t as { name?: unknown }).name ?? "") : "",
  );
  const canonicalExpectedNames = ALLOWED_PLANNER_TOOLS.filter((name) =>
    toolNames.includes(name),
  );
  assertValidToolsArray(toolsList, canonicalExpectedNames, `${path}.tools`);
}

export type GoogleBoundMessageKind =
  | "taskDescriptor"
  | "TaskDescriptor"
  | "interactionsPayload"
  | "payload"
  | "InteractionsCreatePayload"
  | "createRequest"
  | "GeminiCreateRequest"
  | "toolCall"
  | "PlannerToolCall"
  | `toolCall:${PlannerToolName}`
  | "toolResult"
  | "tinfoilToolResult"
  | "PlannerToolResult"
  | `toolResult:${PlannerToolName}`
  | `tinfoilToolResult:${PlannerToolName}`
  | "functionResult"
  | "FunctionResultStep"
  | "followUpRequest"
  | "GeminiFollowUpRequest";

/**
 * Primary Closed-Schema Egress Gate (`assertGoogleBoundMessage`).
 * Throws `ContentFreeEgressError` on any mismatch against the exact schema for `kind`.
 */
export function assertGoogleBoundMessage(
  kind: GoogleBoundMessageKind | string,
  payload: unknown,
  path?: string,
): void {
  if (kind === "taskDescriptor" || kind === "TaskDescriptor") {
    assertTaskDescriptorSchema(payload, path ?? "$.taskDescriptor");
    return;
  }
  if (
    kind === "interactionsPayload" ||
    kind === "payload" ||
    kind === "InteractionsCreatePayload"
  ) {
    assertInteractionsCreatePayloadSchema(
      payload,
      path ?? "$.interactionsPayload",
    );
    return;
  }
  if (kind === "createRequest" || kind === "GeminiCreateRequest") {
    assertGeminiCreateRequestSchema(payload, path ?? "$.createRequest");
    return;
  }
  if (kind === "toolCall" || kind === "PlannerToolCall") {
    assertToolCallSchema(payload, path ?? "$.toolCall");
    return;
  }
  if (kind.startsWith("toolCall:")) {
    const toolName = kind.slice("toolCall:".length);
    assertToolCallArgumentsSchema(
      toolName,
      payload,
      path ?? `$.toolCall(${toolName})`,
    );
    return;
  }
  if (
    kind === "toolResult" ||
    kind === "tinfoilToolResult" ||
    kind === "PlannerToolResult"
  ) {
    assertAnyToolResultSchema(payload, path ?? `$.${kind}`);
    return;
  }
  if (kind.startsWith("toolResult:") || kind.startsWith("tinfoilToolResult:")) {
    const colonIdx = kind.indexOf(":");
    const prefix = kind.slice(0, colonIdx);
    const toolName = kind.slice(colonIdx + 1);
    assertToolResultSchema(
      toolName,
      payload,
      path ?? `$.${prefix}(${toolName})`,
    );
    return;
  }
  if (kind === "functionResult" || kind === "FunctionResultStep") {
    assertFunctionResultStepSchema(payload, path ?? "$.functionResult");
    return;
  }
  if (kind === "followUpRequest" || kind === "GeminiFollowUpRequest") {
    assertGeminiFollowUpRequestSchema(payload, path ?? "$.followUpRequest");
    return;
  }
  throw new ContentFreeEgressError(
    `<unknown_schema_kind:${String(kind)}>`,
    path ?? "$",
  );
}
