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

import { estimateTokens } from "@/lib/privacy/padding";
import { canonicalJson } from "@/lib/transparency/log";
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
  ARGON_MAX_UNIFIED_CONTEXT_TOKENS,
  CLOSED_CALL_ID_REGEX,
  classifyTaskKind,
  ContentFreeEgressError,
  DATA_SENT_TO_GOOGLE,
  DIGEST_HANDLE_REGEX,
  DOC_HANDLE_REGEX,
  GEMINI_4_ARGON_MODEL_ID,
  HANDLE_KEY_TO_REGEX,
  INPUT_LITERAL_HANDLE_REGEX,
  INPUT_OR_RESULT_HANDLE_REGEX,
  isPowerOfTwoInRange,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  MAX_HANDLE_INDEX,
  MAX_PLANNER_STEPS,
  MAX_PLAINTEXT_LEAK_COUNT,
  MAX_REDACTION_COUNT_PER_KIND,
  MAX_TOKEN_BUCKET,
  MEASUREMENT_HANDLE_REGEX,
  RECEIPT_HANDLE_REGEX,
  RESULT_HANDLE_REGEX,
  ROUTER_HANDLE_REGEX,
  roundUpToPowerOfTwo,
  SAFE_CALL_ID_REGEX,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ToolPolicyViolationError,
  VALID_TASK_KINDS,
  VALID_THINKING_LEVELS,
  validateArgonRequestConfig,
  type ArgonInteractionToolDeclaration,
  type ArgonThinkingLevel,
  type InteractionsCreatePayload,
  type PlannerToolName,
  type TaskDescriptor,
  type TaskKind,
} from "./shared";

export {
  CLOSED_CALL_ID_REGEX,
  DIGEST_HANDLE_REGEX,
  DOC_HANDLE_REGEX,
  HANDLE_KEY_TO_REGEX,
  INPUT_LITERAL_HANDLE_REGEX,
  INPUT_OR_RESULT_HANDLE_REGEX,
  isPowerOfTwoInRange,
  MAX_HANDLE_INDEX,
  MEASUREMENT_HANDLE_REGEX,
  RECEIPT_HANDLE_REGEX,
  RESULT_HANDLE_REGEX,
  ROUTER_HANDLE_REGEX,
};

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

export function isScrubCountPowerOfTwoBucket(value: unknown): value is number {
  return value === 0 || isPowerOfTwoInRange(value, 1, 64);
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
  expectedToolNames?: readonly string[],
  path = "$.tools",
): void {
  if (
    !Array.isArray(toolsValue) ||
    toolsValue.length === 0 ||
    toolsValue.length > ALLOWED_PLANNER_TOOLS.length
  ) {
    throw new ContentFreeEgressError("<invalid_tools_array>", path);
  }
  const seenNames = new Set<string>();
  let lastCanonicalIdx = -1;
  for (let i = 0; i < toolsValue.length; i++) {
    const item = assertStrictPlainObject(toolsValue[i], `${path}[${i}]`);
    const name = item.name;
    if (typeof name !== "string") {
      throw new ContentFreeEgressError(String(name), `${path}[${i}].name`);
    }
    const canonicalIdx = (ALLOWED_PLANNER_TOOLS as readonly string[]).indexOf(
      name,
    );
    if (
      canonicalIdx === -1 ||
      seenNames.has(name) ||
      canonicalIdx <= lastCanonicalIdx
    ) {
      throw new ContentFreeEgressError(name, `${path}[${i}].name`);
    }
    seenNames.add(name);
    lastCanonicalIdx = canonicalIdx;
    assertDeepEqualConstant(
      item,
      ARGON_CONFIDENTIAL_TOOLS[canonicalIdx],
      `${path}[${i}]`,
    );
  }
  if (expectedToolNames !== undefined) {
    const expectedDecls: ArgonInteractionToolDeclaration[] =
      ARGON_CONFIDENTIAL_TOOLS.filter((t) => expectedToolNames.includes(t.name));
    if (toolsValue.length !== expectedDecls.length) {
      throw new ContentFreeEgressError("<tools_length_mismatch>", path);
    }
    for (let i = 0; i < expectedDecls.length; i++) {
      assertDeepEqualConstant(toolsValue[i], expectedDecls[i], `${path}[${i}]`);
    }
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
      throw new ContentFreeEgressError(String(t), `${path}.allowedTools[${i}]`);
    }
    const canonicalIdx = (ALLOWED_PLANNER_TOOLS as readonly string[]).indexOf(
      t,
    );
    if (
      canonicalIdx === -1 ||
      seenTools.has(t) ||
      canonicalIdx <= lastCanonicalIdx
    ) {
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

  assertValidToolsArray(obj.tools, undefined, `${path}.tools`);
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

  // `tools` must be a non-empty canonical subset of ARGON_CONFIDENTIAL_TOOLS
  assertValidToolsArray(obj.tools, undefined, `${path}.tools`);
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
      assertExactKeys(obj, ["inputHandle", "bucketQuantumBytes"], [], path);
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
      assertExactKeys(obj, ["topic"], ["inputHandle", "category"], path);
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
      assertExactKeys(obj, ["inputHandle", "enclaveModel"], ["taskKind"], path);
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
      if (!isScrubCountPowerOfTwoBucket(obj.redactionCount)) {
        throw new ContentFreeEgressError(
          String(obj.redactionCount),
          `${path}.redactionCount`,
        );
      }
      if (!isScrubCountPowerOfTwoBucket(obj.mechanicalRedactionCount)) {
        throw new ContentFreeEgressError(
          String(obj.mechanicalRedactionCount),
          `${path}.mechanicalRedactionCount`,
        );
      }
      if (!isScrubCountPowerOfTwoBucket(obj.attestedRedactionCount)) {
        throw new ContentFreeEgressError(
          String(obj.attestedRedactionCount),
          `${path}.attestedRedactionCount`,
        );
      }
      if (
        obj.redactionCount !==
        Math.min(64, obj.mechanicalRedactionCount + obj.attestedRedactionCount)
      ) {
        throw new ContentFreeEgressError(
          String(obj.redactionCount),
          `${path}.redactionCount`,
        );
      }
      if (!isPowerOfTwoInRange(obj.bucketBytes, 512, 65_536)) {
        throw new ContentFreeEgressError(
          String(obj.bucketBytes),
          `${path}.bucketBytes`,
        );
      }
      if (
        !boundedInteger(obj.plaintextLeakCount, 0, MAX_PLAINTEXT_LEAK_COUNT)
      ) {
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
  if (
    typeof obj.call_id !== "string" ||
    !CLOSED_CALL_ID_REGEX.test(obj.call_id)
  ) {
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
    throw new ContentFreeEgressError(
      "<invalid_followup_input>",
      `${path}.input`,
    );
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
    t && typeof t === "object"
      ? String((t as { name?: unknown }).name ?? "")
      : "",
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

const ALLOWED_STATIC_SCHEMA_DESCRIPTIONS = new Set<string>([
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ...ARGON_CONFIDENTIAL_TOOLS.flatMap((t) => [
    t.description,
    ...Object.values(t.parameters.properties).map((p) => p.description),
  ]),
]);

export const ALLOWED_CONTENT_FREE_ENUMS: ReadonlySet<string> = new Set<string>([
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
  "low",
  "medium",
  "high",
  "enabled",
  ...VALID_TASK_KINDS,
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
  ...ALLOWED_PLANNER_TOOLS,
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
  "taskKind",
  "inputHandle",
  "inputTokenEstimate",
  "redactionCounts",
  "verification",
  "allowedTools",
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
  "mechanicalRedactionPassed",
  "attestedPiiFilterVerified",
  "bucketAligned4096",
  "routerSevSnpVerified",
  "enclaveTdxGpuVerified",
  "hpkeKeyBound",
  "sigstoreManifestVerified",
  "arcRegistryVerified",
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

function isStrictGoogleBoundPath(
  path: string,
  insideJsonString: boolean,
): boolean {
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
  if (/^\d+$/.test(hexWithoutPrefix)) {
    return true;
  }
  if (
    /^([0-9a-f]{1,4})\1{15,}$/.test(hexWithoutPrefix) ||
    (hexWithoutPrefix.length <= 14 &&
      /^([0-9a-f]{1,2})\1{2,}$/.test(hexWithoutPrefix))
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
    (ALLOWED_ARRAY_KEYS.has(keyContext) &&
      !ALLOWED_STRING_ARRAY_KEYS.has(keyContext))
  ) {
    return false;
  }
  if (ALLOWED_HASH_KEYS.has(keyContext)) {
    if (
      SHORT_HEX_REGEX.test(value) &&
      value.length <= MAX_GOOGLE_BOUND_HEX_LENGTH
    ) {
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
  if (
    /^(?:0x)?[0-9a-fA-F]{15,}$/.test(value) &&
    value.length > MAX_GOOGLE_BOUND_HEX_LENGTH
  ) {
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
      assertContentFree(
        parsed,
        `${path}(json)`,
        undefined,
        depth + 1,
        true,
        true,
      );
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
      if (
        keyContext === "redactionCounts" &&
        !ALLOWED_REDACTION_COUNT_KEYS.has(k)
      ) {
        throw new ContentFreeEgressError(k, `${path}.${k}`);
      }
      if (
        keyContext === "verification" &&
        !ALLOWED_VERIFICATION_KEYS.has(k)
      ) {
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
        errors.push(
          `Missing required argument '${field}' on tool '${toolName}'.`,
        );
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
        errors.push(
          `Argument '${field}' on '${toolName}' must be >= ${spec.min}.`,
        );
        continue;
      }
      if (spec.max !== undefined && val > spec.max) {
        errors.push(
          `Argument '${field}' on '${toolName}' must be <= ${spec.max}.`,
        );
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
      errors.push(
        err instanceof Error ? err.message : "Failed content-free check.",
      );
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
    if (
      ALLOWED_REDACTION_COUNT_KEYS.has(k) &&
      typeof v === "number" &&
      Number.isFinite(v)
    ) {
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
    allowedTools:
      allowedTools.length > 0 ? [...allowedTools] : [...ALLOWED_PLANNER_TOOLS],
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
