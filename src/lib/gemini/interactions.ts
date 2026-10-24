/**
 * Google DeepMind Gemini 4 Argon (`gemini-4-argon`) Interactions API Contract,
 * Tinfoil Enclave OpenAI-Compatible Planner Loop, Privacy Invariant Guard, and
 * Companion Toolkit Registry (`src/lib/gemini/interactions.ts`).
 *
 * Uses the official `@google/genai` SDK (`new GoogleGenAI({ apiKey })` and
 * `client.interactions.create(...)`) when `GEMINI_API_KEY` is present, and
 * falls back to an attested Tinfoil enclave model (`kimi-k3` or `gemma4-31b`)
 * via the `tinfoil` SDK (`tinfoilClient.chat.completions.create(...)` with
 * OpenAI-compatible tool calls) when no Gemini key is configured.
 */

import { GoogleGenAI } from "@google/genai";

export const GEMINI_4_ARGON_MODEL_ID = "gemini-4-argon" as const;

export const ARGON_COMPANION_MODELS = {
  orchestrator: "gemini-4-argon",
  sandboxAgent: "antigravity-preview-09-2026",
  parallelSubagentFast: "gemini-3.8-flash",
  parallelSubagentLite: "gemini-3.5-flash-lite",
  deepResearch: "deep-research-preview-04-2026",
  realtimeVoice: "gemini-3.8-live",
  voiceTts: "gemini-3.8-flash-tts",
  confidentialOpenCloud: "gemma-4-31b-it",
  confidentialOnDevice: "gemma-4-e4b",
  tinfoilEnclaveGemma: "gemma4-31b",
  tinfoilEnclaveKimi: "kimi-k3",
} as const;

export type ArgonThinkingLevel = "low" | "medium" | "high";

export const VALID_THINKING_LEVELS: readonly ArgonThinkingLevel[] = [
  "low",
  "medium",
  "high",
] as const;

export const FORBIDDEN_ARGON_PARAMETERS = [
  "thinking_budget",
  "temperature",
  "top_p",
  "top_k",
  "cached_content",
] as const;

export type ForbiddenArgonParameter = (typeof FORBIDDEN_ARGON_PARAMETERS)[number];

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

export const ARGON_LONG_DECODE_THRESHOLD_TOKENS = 65_536;
export const ARGON_MAX_UNIFIED_CONTEXT_TOKENS = 1_000_000;
export const TINFOIL_KIMI_K3_MAX_CONTEXT_TOKENS = 262_144;

export interface ArgonPlannerDescriptor {
  provider: "gemini" | "tinfoil";
  model: string;
}

export interface ArgonModelCallRecord {
  model: string;
  purpose: string;
  ok: boolean;
  latencyMs: number;
  inputTokens?: number;
  outputTokens?: number;
  error?: string;
}

export interface ArgonToolkitModelSpec {
  id: string;
  role: string;
  stageUsed: string;
  statusInDemo: "used-when-key-set" | "live-enclave" | "not-used";
  trustBoundary: "on-device-local" | "attested-tee-enclave" | "gemini-interactions-cloud";
  description: string;
  tinfoilEnclaveAlias?: string;
}

export const ARGON_TOOLKIT_MANIFEST: readonly ArgonToolkitModelSpec[] = [
  {
    id: GEMINI_4_ARGON_MODEL_ID,
    role: "Primary 1M-Context Autonomous Reasoning and Tool-Calling Orchestrator",
    stageUsed: "Stage 4 (Autonomous Tool Loop and Synthesis when GEMINI_API_KEY is provided)",
    statusInDemo: "used-when-key-set",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Invoked via @google/genai client.interactions.create with generation_config.thinking_level and background execution over scrubbed and symmetry-masked text. When GEMINI_API_KEY is absent, planning falls back to an attested Tinfoil model.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentFast,
    role: "Parallel Subagent for Attestation and Atlas Hybrid Search Summarization",
    stageUsed: "Stage 2 (Parallel Subagent Summary when GEMINI_API_KEY is provided; skipped without key)",
    statusInDemo: "used-when-key-set",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Called in parallel via client.interactions.create when GEMINI_API_KEY is present to summarize MongoDB Atlas Hybrid Search ($rankFusion) and Tinfoil 2-hop attestation results.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentLite,
    role: "Parallel Subagent for Quorum and Policy Verification Summarization",
    stageUsed: "Stage 2 (Parallel Subagent Summary when GEMINI_API_KEY is provided; skipped without key)",
    statusInDemo: "used-when-key-set",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Called in parallel via client.interactions.create when GEMINI_API_KEY is present to summarize 5-of-7 Ed25519 hardware verifier quorum and Circle Arc registry readiness.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOpenCloud,
    role: "Open-Weight Confidential Enclave Planner and Inference Model (Tinfoil Live Attested)",
    stageUsed: "Stage 4 (Attested Tinfoil Enclave Planner and Inference via gemma4-31b or kimi-k3)",
    statusInDemo: "live-enclave",
    trustBoundary: "attested-tee-enclave",
    tinfoilEnclaveAlias: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
    description:
      "Maps to Tinfoil's live attested gemma4-31b and kimi-k3 enclaves (Intel TDX + NVIDIA CC GPUs, max-model-len 262,144 tokens on kimi-k3) routed via router-0.tinfoil.sh (AMD SEV-SNP).",
  },
  {
    id: ARGON_COMPANION_MODELS.sandboxAgent,
    role: "Not used in this demo (VMPL0 1,344-state and V1/V6 memory-bus checks run in deterministic local TypeScript)",
    stageUsed: "not used (Stage 3 uses local TypeScript verifiers)",
    statusInDemo: "not-used",
    trustBoundary: "attested-tee-enclave",
    description:
      "Not used in this demo. Stage 3 runs deterministic local TypeScript formal checks (verifyMonitorPolicyExhaustive across 1,344 states and runMemoryBusAndPopAudit).",
  },
  {
    id: ARGON_COMPANION_MODELS.deepResearch,
    role: "Not used in this demo (CVE and provider advisories are queried from MongoDB Atlas enclave_intelligence)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used in this demo. Hardware advisories (TEE.fail, DDRop, Cipherleaks, VoltPillager) are retrieved from MongoDB Atlas Hybrid Search.",
  },
  {
    id: ARGON_COMPANION_MODELS.realtimeVoice,
    role: "Not used in this demo (Human-in-the-Loop approval gate is controlled via HTTP/UI)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used in this demo. Stage 5 Human-in-the-Loop control is enforced deterministically in server code.",
  },
  {
    id: ARGON_COMPANION_MODELS.voiceTts,
    role: "Not used in this demo (Stage 6 produces a text briefing and Ed25519-signed forensic digest)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used in this demo. Stage 6 generates a text readout and signs the canonical SHA-256 forensic digest with Ed25519 locally.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOnDevice,
    role: "Not used in this demo (Stage 1 PII scrubbing and symmetry masking run in deterministic local TypeScript)",
    stageUsed: "not used (Stage 1 uses local prompt pipeline and symmetry transform)",
    statusInDemo: "not-used",
    trustBoundary: "on-device-local",
    description:
      "Not used in this demo. Stage 1 runs deterministic local regex scrubbing (src/lib/pipeline and src/lib/privacy) and homomorphic symmetry masking (src/lib/symmetry).",
  },
] as const;

export class PrivacyInvariantViolationError extends Error {
  readonly leakedToken: string;

  constructor(leakedToken: string) {
    super(
      `PRIVACY_INVARIANT_VIOLATION: Outbound planner payload contained unredacted sensitive value (${leakedToken.slice(0, 4)}***). Call aborted before network transmission.`,
    );
    this.name = "PrivacyInvariantViolationError";
    this.leakedToken = leakedToken;
  }
}

/**
 * Enforces the dRouter Privacy Invariant: neither Google nor Tinfoil planner calls
 * may receive raw PII or unredacted secrets. Inspects the serialized outbound payload
 * and throws `PrivacyInvariantViolationError` if any original placeholder value or
 * unmasked sensitive token (>= 4 chars) is present.
 */
export function assertOutboundPrivacyInvariant(
  outboundPayload: unknown,
  sensitiveOriginals: readonly string[],
): void {
  const serialized =
    typeof outboundPayload === "string"
      ? outboundPayload
      : JSON.stringify(outboundPayload ?? {});
  const lowerSerialized = serialized.toLowerCase();

  for (const rawOrig of sensitiveOriginals) {
    const cleaned = (rawOrig || "").trim();
    if (cleaned.length < 4) continue;
    if (serialized.includes(cleaned) || lowerSerialized.includes(cleaned.toLowerCase())) {
      throw new PrivacyInvariantViolationError(cleaned);
    }
  }
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

export interface ArgonInteractionToolDeclaration {
  type: "function";
  name: string;
  description: string;
  parameters: {
    type: "OBJECT";
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

export const ARGON_CONFIDENTIAL_TOOLS: readonly ArgonInteractionToolDeclaration[] = [
  {
    type: "function",
    name: "scrub_and_symmetry_mask",
    description:
      "Runs local PII/secret scrubbing, PAPILLON generalization, and homomorphic symmetry masking f(T(x)) = T(f(x)) with 4096-byte RFC 8259 bucket padding.",
    parameters: {
      type: "OBJECT",
      properties: {
        rawPayload: {
          type: "STRING",
          description: "Already-scrubbed prompt context to verify and pad locally.",
        },
        bucketQuantumBytes: {
          type: "INTEGER",
          description: "Byte padding quantum (4096).",
        },
      },
      required: ["rawPayload", "bucketQuantumBytes"],
    },
  },
  {
    type: "function",
    name: "verify_two_hop_enclave_and_quorum",
    description:
      "Fetches and verifies live Tinfoil attestation (router-0.tinfoil.sh AMD SEV-SNP report + Intel TDX and NVIDIA CC GPU model enclave) and 5-of-7 Ed25519 verifier quorum.",
    parameters: {
      type: "OBJECT",
      properties: {
        providerId: {
          type: "STRING",
          description: "Target confidential compute provider ID (e.g., tinfoil).",
        },
        enclaveModel: {
          type: "STRING",
          description: "Target attested model ID (gemma4-31b or kimi-k3).",
        },
      },
      required: ["providerId", "enclaveModel"],
    },
  },
  {
    type: "function",
    name: "search_atlas_hybrid_kb",
    description:
      "Executes MongoDB Atlas Hybrid Search ($rankFusion combining $vectorSearch and $search) over enclave_intelligence and past agent_verification_receipts.",
    parameters: {
      type: "OBJECT",
      properties: {
        query: {
          type: "STRING",
          description: "Scrubbed technical search query for confidential enclaves and advisories.",
        },
        category: {
          type: "STRING",
          description: "Optional category filter (provider, advisory, architecture, all).",
        },
      },
      required: ["query"],
    },
  },
  {
    type: "function",
    name: "run_antigravity_vmpl0_and_memory_audit",
    description:
      "Exhaustively checks all 1,344 VMPL0 exit policy states (I1-I5) and V1/V6 DDR5 memory-bus Shannon entropy in an isolated sandbox.",
    parameters: {
      type: "OBJECT",
      properties: {
        candidateNodeId: {
          type: "STRING",
          description: "Candidate enclave node ID under test.",
        },
        autoPatchOnFailure: {
          type: "BOOLEAN",
          description: "Whether to fail over and re-verify on an attested node if a fault is found.",
        },
      },
      required: ["candidateNodeId", "autoPatchOnFailure"],
    },
  },
  {
    type: "function",
    name: "invoke_attested_enclave",
    description:
      "Dispatches the scrubbed and symmetry-masked prompt to the verified Tinfoil confidential enclave (gemma4-31b or kimi-k3) over RFC 9180 HPKE Encrypted HTTP Body.",
    parameters: {
      type: "OBJECT",
      properties: {
        enclaveModel: {
          type: "STRING",
          description: "Attested Tinfoil enclave model ID (gemma4-31b or kimi-k3).",
        },
        maskedPrompt: {
          type: "STRING",
          description: "Scrubbed and symmetry-masked prompt text.",
        },
      },
      required: ["enclaveModel", "maskedPrompt"],
    },
  },
  {
    type: "function",
    name: "anchor_arc_settlement_with_human_gate",
    description:
      "Prepares or submits a verified execution receipt to Circle Arc Testnet (chainId 5042002, registry 0xbc8085c2b6fe6e0db05f169925c0b841828f4481) only when humanApproved is true.",
    parameters: {
      type: "OBJECT",
      properties: {
        actionKind: {
          type: "STRING",
          description: "anchor_receipt | slash_faulty_node",
        },
        humanApproved: {
          type: "BOOLEAN",
          description: "Explicit confirmation from the human user before state change.",
        },
      },
      required: ["actionKind", "humanApproved"],
    },
  },
] as const;

export interface OpenAICompatibleToolDefinition {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, { type: string; description: string }>;
      required: string[];
    };
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
            },
          ]),
        ),
        required: [...t.parameters.required],
      },
    },
  }));
}

export interface InteractionsCreatePayload {
  model: typeof GEMINI_4_ARGON_MODEL_ID;
  thinking_level: ArgonThinkingLevel;
  background: boolean;
  max_output_tokens: number;
  max_context_tokens: number;
  implicit_caching: "enabled";
  generation_config: {
    thinking_level: ArgonThinkingLevel;
    max_output_tokens: number;
  };
  system_instruction: string;
  input: Array<{
    role: "user" | "system";
    content: string;
  }>;
  tools: readonly ArgonInteractionToolDeclaration[];
  subagent_routing: {
    sandbox_verifier: typeof ARGON_COMPANION_MODELS.sandboxAgent;
    fast_swarm: typeof ARGON_COMPANION_MODELS.parallelSubagentFast;
    quorum_checker: typeof ARGON_COMPANION_MODELS.parallelSubagentLite;
    deep_research: typeof ARGON_COMPANION_MODELS.deepResearch;
    on_device_filter: typeof ARGON_COMPANION_MODELS.confidentialOnDevice;
    attested_enclave_model: typeof ARGON_COMPANION_MODELS.confidentialOpenCloud;
    tinfoil_enclave_target: typeof ARGON_COMPANION_MODELS.tinfoilEnclaveGemma;
    voice_briefing: typeof ARGON_COMPANION_MODELS.voiceTts;
    live_voice_gate: typeof ARGON_COMPANION_MODELS.realtimeVoice;
  };
  metadata: {
    sdk_target: "@google/genai>=2.31.0";
    api_surface: "client.interactions.create";
    persona: string;
    enclave_protocol: "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves";
  };
}

export function buildInteractionsCreatePayload(params: {
  scrubbedPrompt: string;
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
  const persona =
    params.persona ??
    "Dana Reyes (Clinical data scientist, Oncology Trial Unit; fictional example persona)";

  return {
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
    system_instruction:
      "You are the Gemini 4 Argon Confidential Security and Routing Orchestrator for dRouter. " +
      "Never accept unredacted secrets or raw patient identifiers outside the local trust boundary. " +
      "Use the provided tools to verify live Tinfoil attestation (router-0.tinfoil.sh AMD SEV-SNP + Intel TDX / NVIDIA CC GPU model enclaves), query MongoDB Atlas Hybrid Search ($rankFusion), verify all 1,344 VMPL0 exit policy states, and dispatch scrubbed inference to the attested enclave. " +
      "Require explicit Human-in-the-Loop confirmation before anchoring receipts on Circle Arc.",
    input: [
      {
        role: "user",
        content: params.scrubbedPrompt,
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
      persona,
      enclave_protocol:
        "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves",
    },
  };
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
    `// Official Gemini 4 Argon Interactions API call`,
    `// Note: thinking_budget, temperature, top_p, top_k, and cached_content are omitted`,
    `// because gemini-4-argon enforces thinking_level and automatic implicit caching.`,
    `const interaction = await client.interactions.create({`,
    `  model: "${payload.model}",`,
    `  background: ${String(payload.background)},`,
    `  generation_config: {`,
    `    thinking_level: "${payload.thinking_level}",`,
    `    max_output_tokens: ${payload.max_output_tokens},`,
    `  },`,
    `  system_instruction: ${JSON.stringify(payload.system_instruction)},`,
    `  input: [{ type: "text", text: ${JSON.stringify(payload.input[0]?.content ?? "")} }],`,
    `  tools: ${JSON.stringify(payload.tools, null, 2)},`,
    `});`,
    ``,
    `console.log(interaction.id, interaction.status, interaction.output_text);`,
  ].join("\n");

  const python = [
    `from google import genai  # google-genai >= 1.40.0`,
    ``,
    `client = genai.Client()`,
    ``,
    `# Official Gemini 4 Argon Interactions API call`,
    `interaction = client.interactions.create(`,
    `    model="${payload.model}",`,
    `    background=${payload.background ? "True" : "False"},`,
    `    generation_config={`,
    `        "thinking_level": "${payload.thinking_level}",`,
    `        "max_output_tokens": ${payload.max_output_tokens},`,
    `    },`,
    `    system_instruction=${JSON.stringify(payload.system_instruction)},`,
    `    input=[{"type": "text", "text": ${JSON.stringify(payload.input[0]?.content ?? "")}}],`,
    `)`,
    `print(interaction.id, interaction.status)`,
  ].join("\n");

  return { typescript, python };
}

export interface LiveGeminiCallResult {
  attemptedLiveCall: boolean;
  liveEndpointReached: boolean;
  sdkMethod: "client.interactions.create";
  interactionId?: string;
  interactionStatus?: string;
  toolCallsExecuted?: string[];
  liveSummaryText?: string;
  fallbackReason?: string;
  modelCallRecord?: ArgonModelCallRecord;
}

export interface GenAIInteractionsClientLike {
  interactions: {
    create(params: Record<string, unknown>): Promise<{
      id?: string;
      status?: string;
      output_text?: string;
      steps?: Array<{
        type: string;
        id?: string;
        name?: string;
        arguments?: Record<string, unknown>;
        content?: Array<{ type?: string; text?: string }>;
      }>;
      usage?: {
        total_input_tokens?: number;
        total_output_tokens?: number;
      };
    }>;
  };
}

export interface TinfoilToolCall {
  id: string;
  type?: string;
  function: {
    name: string;
    arguments: string;
  };
}

export interface TinfoilChatCompletionResponse {
  id?: string;
  choices?: Array<{
    message?: {
      role?: string;
      content?: string | null;
      tool_calls?: TinfoilToolCall[];
    };
    finish_reason?: string | null;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

export interface TinfoilPlannerClientLike {
  ready?(): Promise<void>;
  getVerificationDocument?(): Promise<unknown>;
  chat: {
    completions: {
      create(
        params: Record<string, unknown>,
        options?: Record<string, unknown>,
      ): Promise<TinfoilChatCompletionResponse>;
    };
  };
}

export interface TinfoilPlannerCallResult {
  attemptedLiveCall: boolean;
  liveEndpointReached: boolean;
  sdkMethod: "tinfoil.chat.completions.create";
  model: "gemma4-31b" | "kimi-k3";
  completionId?: string;
  toolCallsExecuted: string[];
  finalText?: string;
  fallbackReason?: string;
  modelCallRecord?: ArgonModelCallRecord;
}

export type ArgonToolExecutor = (
  toolName: string,
  args: Record<string, unknown>,
) => Promise<Record<string, unknown>>;

/**
 * Calls `@google/genai` (`new GoogleGenAI({ apiKey }).interactions.create(...)`)
 * and executes a multi-turn function-calling loop when a key or mock client is provided.
 * Strictly enforces `assertOutboundPrivacyInvariant` before every SDK call.
 */
export async function callGeminiInteractionsEndpoint(params: {
  payload: InteractionsCreatePayload;
  apiKey?: string;
  sensitiveOriginals?: readonly string[];
  toolExecutor?: ArgonToolExecutor;
  genaiClient?: GenAIInteractionsClientLike;
}): Promise<LiveGeminiCallResult> {
  const sensitiveOriginals = params.sensitiveOriginals ?? [];

  // Enforce the Privacy Invariant on the payload before checking key or calling Google
  assertOutboundPrivacyInvariant(params.payload.input, sensitiveOriginals);
  assertOutboundPrivacyInvariant(params.payload.system_instruction, sensitiveOriginals);

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
    };
  }

  const client: GenAIInteractionsClientLike =
    params.genaiClient ??
    (new GoogleGenAI({ apiKey: resolvedKey }) as unknown as GenAIInteractionsClientLike);

  const startedAt = Date.now();
  const toolCallsExecuted: string[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  try {
    const createRequest: Record<string, unknown> = {
      model: params.payload.model,
      background: params.payload.background,
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

    let interaction = await client.interactions.create(createRequest);
    if (typeof interaction.usage?.total_input_tokens === "number") {
      totalInputTokens += interaction.usage.total_input_tokens;
    }
    if (typeof interaction.usage?.total_output_tokens === "number") {
      totalOutputTokens += interaction.usage.total_output_tokens;
    }

    // Multi-turn tool-calling loop (up to 4 turns) when model emits function_call steps
    let turn = 0;
    while (turn < 4 && params.toolExecutor && Array.isArray(interaction.steps)) {
      const fnCalls = interaction.steps.filter(
        (s) => s && s.type === "function_call" && typeof s.name === "string",
      );
      if (fnCalls.length === 0) break;

      const fnResults: Array<Record<string, unknown>> = [];
      for (const call of fnCalls) {
        const name = call.name as string;
        const callId = call.id || `call-${turn}-${name}`;
        toolCallsExecuted.push(name);
        const resultObj = await params.toolExecutor(name, call.arguments ?? {});
        const resultStep = {
          type: "function_result",
          call_id: callId,
          name,
          result: JSON.stringify(resultObj),
        };
        assertOutboundPrivacyInvariant(resultStep, sensitiveOriginals);
        fnResults.push(resultStep);
      }

      const followUpRequest: Record<string, unknown> = {
        model: params.payload.model,
        background: params.payload.background,
        previous_interaction_id: interaction.id,
        generation_config: {
          thinking_level: params.payload.thinking_level,
          max_output_tokens: params.payload.max_output_tokens,
        },
        input: fnResults,
        tools: params.payload.tools,
      };

      assertOutboundPrivacyInvariant(followUpRequest, sensitiveOriginals);
      interaction = await client.interactions.create(followUpRequest);

      if (typeof interaction.usage?.total_input_tokens === "number") {
        totalInputTokens += interaction.usage.total_input_tokens;
      }
      if (typeof interaction.usage?.total_output_tokens === "number") {
        totalOutputTokens += interaction.usage.total_output_tokens;
      }
      turn += 1;
    }

    const latencyMs = Math.max(1, Date.now() - startedAt);
    let outputText = interaction.output_text;
    if (!outputText && Array.isArray(interaction.steps)) {
      for (const s of interaction.steps) {
        if (s.type === "model_output" && Array.isArray(s.content)) {
          const txt = s.content
            .map((c) => (typeof c.text === "string" ? c.text : ""))
            .join("")
            .trim();
          if (txt) {
            outputText = txt;
            break;
          }
        }
      }
    }

    return {
      attemptedLiveCall: true,
      liveEndpointReached: true,
      sdkMethod: "client.interactions.create",
      interactionId: interaction.id,
      interactionStatus: interaction.status ?? "completed",
      toolCallsExecuted,
      liveSummaryText:
        outputText ||
        `Gemini 4 Argon interaction ${interaction.id ?? "live"} completed (${toolCallsExecuted.length} tool call(s) executed).`,
      modelCallRecord: {
        model: params.payload.model,
        purpose: "Primary autonomous routing & tool-calling orchestrator (Stage 4)",
        ok: true,
        latencyMs,
        ...(totalInputTokens > 0 ? { inputTokens: totalInputTokens } : {}),
        ...(totalOutputTokens > 0 ? { outputTokens: totalOutputTokens } : {}),
      },
    };
  } catch (err) {
    if (err instanceof PrivacyInvariantViolationError) {
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
      fallbackReason: `Gemini Interactions SDK call failed (${safeMsg.slice(0, 180)}); falling back to Tinfoil planner.`,
      modelCallRecord: {
        model: params.payload.model,
        purpose: "Primary autonomous routing & tool-calling orchestrator (Stage 4)",
        ok: false,
        latencyMs,
        error: safeMsg.slice(0, 180),
      },
    };
  }
}

/**
 * Executes the autonomous tool-calling planner loop using an attested Tinfoil enclave
 * model (`kimi-k3` or `gemma4-31b`) via OpenAI-compatible tool calls on the `tinfoil` SDK.
 * Strictly enforces `assertOutboundPrivacyInvariant` on every outbound prompt and tool result.
 */
export async function callTinfoilPlannerToolLoop(params: {
  model: "gemma4-31b" | "kimi-k3";
  scrubbedPrompt: string;
  systemInstruction?: string;
  apiKey?: string;
  sensitiveOriginals?: readonly string[];
  toolExecutor?: ArgonToolExecutor;
  tinfoilClient?: TinfoilPlannerClientLike;
  enableNetworkCall?: boolean;
  maxTurns?: number;
}): Promise<TinfoilPlannerCallResult> {
  const sensitiveOriginals = params.sensitiveOriginals ?? [];
  const systemInstruction =
    params.systemInstruction ??
    "You are the autonomous confidential security and routing planner for dRouter running inside an attested Tinfoil enclave. " +
      "Never output unredacted PII or secrets, and never use em dashes. " +
      "Use the provided verification tools to audit the scrubbed request and provide a concise verification summary repeating the masked identifiers.";

  // Enforce Privacy Invariant before checking credentials or making any SDK call
  assertOutboundPrivacyInvariant(params.scrubbedPrompt, sensitiveOriginals);
  assertOutboundPrivacyInvariant(systemInstruction, sensitiveOriginals);

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
        "Tinfoil enclave network inference skipped (cached GET or no TINFOIL_API_KEY enabled).",
    };
  }

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
      await client.ready();
    }

    const openAiTools = buildTinfoilOpenAITools(ARGON_CONFIDENTIAL_TOOLS);
    const messages: Array<Record<string, unknown>> = [
      { role: "system", content: systemInstruction },
      { role: "user", content: params.scrubbedPrompt },
    ];

    const maxTurns = params.maxTurns ?? (params.tinfoilClient ? 4 : 2);
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
        response = await client.chat.completions.create(reqPayload, {
          headers: { "X-Tinfoil-Model": params.model },
        });
      } catch (toolCallErr) {
        if (toolCallErr instanceof PrivacyInvariantViolationError) {
          throw toolCallErr;
        }
        // If the target enclave container does not accept tool definitions on turn 0,
        // fall back to a standard completion call on the same attested enclave.
        if (turn === 0) {
          const plainReq: Record<string, unknown> = {
            model: params.model,
            messages: [...messages],
            max_tokens: 240,
          };
          assertOutboundPrivacyInvariant(plainReq, sensitiveOriginals);
          response = await client.chat.completions.create(plainReq, {
            headers: { "X-Tinfoil-Model": params.model },
          });
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
        finalText = msg.content.trim();
      }

      if (toolCalls.length === 0 || !params.toolExecutor) {
        break;
      }

      messages.push({
        role: "assistant",
        content: msg?.content ?? null,
        tool_calls: toolCalls,
      });

      for (const tc of toolCalls) {
        const fnName = tc.function?.name;
        if (!fnName) continue;
        let parsedArgs: Record<string, unknown> = {};
        if (typeof tc.function?.arguments === "string" && tc.function.arguments.trim()) {
          try {
            const parsed = JSON.parse(tc.function.arguments) as unknown;
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              parsedArgs = parsed as Record<string, unknown>;
            }
          } catch {
            parsedArgs = {};
          }
        }
        assertOutboundPrivacyInvariant(parsedArgs, sensitiveOriginals);
        toolCallsExecuted.push(fnName);
        const toolResult = await params.toolExecutor(fnName, parsedArgs);
        const toolMsg: Record<string, unknown> = {
          role: "tool",
          tool_call_id: tc.id || `call-${turn}-${fnName}`,
          name: fnName,
          content: JSON.stringify(toolResult),
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
        purpose: `Autonomous Tinfoil enclave planner & tool loop (${params.model} over RFC 9180 HPKE)`,
        ok: true,
        latencyMs,
        ...(totalInputTokens > 0 ? { inputTokens: totalInputTokens } : {}),
        ...(totalOutputTokens > 0 ? { outputTokens: totalOutputTokens } : {}),
      },
    };
  } catch (err) {
    if (err instanceof PrivacyInvariantViolationError) {
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
        purpose: `Autonomous Tinfoil enclave planner & tool loop (${params.model})`,
        ok: false,
        latencyMs,
        error: safeMsg.slice(0, 180),
      },
    };
  }
}

/**
 * Invokes a companion subagent (`gemini-3.8-flash` or `gemini-3.5-flash-lite`) via
 * `client.interactions.create` when a Gemini API key or mock client is available.
 * Enforces `assertOutboundPrivacyInvariant` before calling the SDK.
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

  const resolvedKey =
    params.apiKey?.trim() ||
    (typeof process !== "undefined" ? process.env?.GEMINI_API_KEY?.trim() : "") ||
    "";

  if (!resolvedKey && !params.genaiClient) {
    return { liveReached: false };
  }

  const client: GenAIInteractionsClientLike =
    params.genaiClient ??
    (new GoogleGenAI({ apiKey: resolvedKey }) as unknown as GenAIInteractionsClientLike);

  const startedAt = Date.now();
  try {
    const req: Record<string, unknown> = {
      model: params.model,
      background: false,
      generation_config: {
        thinking_level: "low",
        max_output_tokens: 256,
      },
      system_instruction:
        "Summarize the confidential compute verification artifact concisely in one plain sentence without em dashes.",
      input: [{ type: "text", text: params.scrubbedInput }],
    };
    assertOutboundPrivacyInvariant(req, sensitiveOriginals);

    const interaction = await client.interactions.create(req);
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const text = interaction.output_text?.trim();

    return {
      liveReached: true,
      summaryText: text,
      modelCallRecord: {
        model: params.model,
        purpose: params.purpose,
        ok: true,
        latencyMs,
        ...(typeof interaction.usage?.total_input_tokens === "number"
          ? { inputTokens: interaction.usage.total_input_tokens }
          : {}),
        ...(typeof interaction.usage?.total_output_tokens === "number"
          ? { outputTokens: interaction.usage.total_output_tokens }
          : {}),
      },
    };
  } catch (err) {
    if (err instanceof PrivacyInvariantViolationError) {
      throw err;
    }
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const rawMsg = err instanceof Error ? err.message : "Subagent SDK error";
    const safeMsg = resolvedKey ? rawMsg.split(resolvedKey).join("[REDACTED_KEY]") : rawMsg;

    return {
      liveReached: false,
      modelCallRecord: {
        model: params.model,
        purpose: params.purpose,
        ok: false,
        latencyMs,
        error: safeMsg.slice(0, 160),
      },
    };
  }
}
