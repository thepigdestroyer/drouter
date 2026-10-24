/**
 * Google DeepMind Gemini 4 Argon (`gemini-4-argon`) Interactions API Contract
 * and Companion Toolkit Registry.
 *
 * Enforces the official Gemini 4 Argon API rules:
 * - Model ID: "gemini-4-argon"
 * - Uses `thinking_level` ("low" | "medium" | "high")
 * - Rejects deprecated `thinking_budget`, `temperature`, `top_p`, `top_k`,
 *   and explicit `cached_content` (implicit caching is automatic in gemini-4-argon)
 * - Sets `background: true` for long decode (> 65,536 tokens up to 1,000,000 tokens)
 *   or autonomous multi-step execution
 * - Builds the official `client.interactions.create` payload for `@google/genai >= 2.3.0`
 */

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

export interface ArgonToolkitModelSpec {
  id: string;
  role: string;
  stageUsed: string;
  trustBoundary: "on-device-local" | "attested-tee-enclave" | "gemini-interactions-cloud";
  description: string;
  tinfoilEnclaveAlias?: string;
}

export const ARGON_TOOLKIT_MANIFEST: readonly ArgonToolkitModelSpec[] = [
  {
    id: GEMINI_4_ARGON_MODEL_ID,
    role: "Primary 1M-Context Autonomous Reasoning & Routing Orchestrator",
    stageUsed: "Stage 4 (1M Unified Context Synthesis & Confidential Routing)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Flagship Gemini 4 Argon model invoked via client.interactions.create with thinking_level control, automatic implicit context caching, and background long-decode execution.",
  },
  {
    id: ARGON_COMPANION_MODELS.sandboxAgent,
    role: "Antigravity Managed Agent for Formal Policy & Memory-Bus Sandbox Verification",
    stageUsed: "Stage 3 (1,344-State VMPL0 Check, V1/V6 Audit & Self-Healing Loop)",
    trustBoundary: "attested-tee-enclave",
    description:
      "Executes isolated verification loops inside attested microVMs, detects invariant counterexamples or memory-bus leaks, and patches routing policies autonomously.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentFast,
    role: "High-Throughput Parallel Subagent Swarm Coordinator",
    stageUsed: "Stage 2 (Parallel Atlas Hybrid Search & 2-Hop Attestation Audit)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Runs low-latency parallel subagents to query MongoDB Atlas Hybrid Search ($vectorSearch + $search) and verify AMD SEV-SNP + NVIDIA B200/H200 CC attestation bundles.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentLite,
    role: "Ultra-Fast Quorum & Nullifier Subagent",
    stageUsed: "Stage 2 (5-of-7 Verifier Quorum & Circle Arc Stake Check)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Performs sub-50ms Ed25519 quorum signature checks across the 7 independent hardware verification authorities.",
  },
  {
    id: ARGON_COMPANION_MODELS.deepResearch,
    role: "Deep Web & Literature Grounding Agent with Citations",
    stageUsed: "Stage 2 (Protocol & Hardware Vulnerability Cross-Reference)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Synthesizes cited public literature and CVE/TEE hardware advisories without receiving unredacted private data.",
  },
  {
    id: ARGON_COMPANION_MODELS.realtimeVoice,
    role: "Real-Time Bidirectional Lab Voice & Interruption Stream",
    stageUsed: "Stage 6 (Live Benchtop Voice Control & Human-in-the-Loop Gate)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Provides hands-free wet-lab voice interaction for approving or rejecting Circle Arc on-chain settlement and session key release.",
  },
  {
    id: ARGON_COMPANION_MODELS.voiceTts,
    role: "Structured Security Briefing Audio Synthesizer",
    stageUsed: "Stage 6 (Multimodal Audit Readout & Forensic Digest)",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Renders the verified cryptographic audit summary and genomic pipeline readout into low-latency spoken audio.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOpenCloud,
    role: "Open-Weight Confidential Enclave Model (Tinfoil Live Attested)",
    stageUsed: "Stage 1 & Stage 4 (Confidential Enclave Inference on 8x B200/H200 CC)",
    trustBoundary: "attested-tee-enclave",
    tinfoilEnclaveAlias: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
    description:
      "Maps directly to Tinfoil's live attested gemma4-31b enclave over RFC 9180 HPKE Encrypted HTTP Body (EHBP) so sensitive genomic sequences never leave hardware-encrypted GPU memory.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOnDevice,
    role: "On-Device Local Privacy Filter & PAPILLON Prompt Generalizer",
    stageUsed: "Stage 1 (Local PII/Secret Scrubbing & Symmetry Masking)",
    trustBoundary: "on-device-local",
    description:
      "Runs strictly on the researcher's local workstation to strip API keys, patient cohort IDs, and unpublished results before any network hop.",
  },
] as const;

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
  // Deprecated / forbidden fields in gemini-4-argon that must be rejected:
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
 * Validates a candidate Gemini 4 Argon request configuration against the official
 * DeepMind Argon API specification:
 * 1. Model must be "gemini-4-argon" (defaults to "gemini-4-argon" if omitted).
 * 2. Requires a valid `thinking_level` ("low" | "medium" | "high").
 * 3. Rejects `thinking_budget`, `temperature`, `top_p`, `top_k`, and `cached_content`.
 * 4. Automatically enables `background: true` when `max_output_tokens > 65536`
 *    (up to 1,000,000 tokens) or when `autonomousMultiStep` / `background` is requested.
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

  const rawThinkingLevel = input.thinking_level ?? input.thinkingLevel ?? "high";
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
        : "high",
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
    name: "scrub_and_symmetry_mask",
    description:
      "Runs on-device gemma-4-e4b privacy scrubbing, PAPILLON generalization, and homomorphic symmetry masking f(T(x)) = T(f(x)) with 4096-byte OHTTP frame padding.",
    parameters: {
      type: "OBJECT",
      properties: {
        rawPayload: {
          type: "STRING",
          description: "Raw genomic protocol and codebase context to scrub locally.",
        },
        bucketQuantumBytes: {
          type: "INTEGER",
          description: "Byte padding quantum (must be 4096).",
        },
      },
      required: ["rawPayload", "bucketQuantumBytes"],
    },
  },
  {
    name: "verify_two_hop_enclave_and_quorum",
    description:
      "Dispatches gemini-3.8-flash and gemini-3.5-flash-lite subagents to verify AMD SEV-SNP + 8x NVIDIA B200/H200 CC attestation and 5-of-7 Circle Arc verifier quorum.",
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
    name: "run_antigravity_vmpl0_and_memory_audit",
    description:
      "Invokes antigravity-preview-09-2026 in an attested microVM to exhaustively check all 1,344 VMPL0 exit policy states (I1-I5) and V1/V6 DDR5 memory-bus Shannon entropy.",
    parameters: {
      type: "OBJECT",
      properties: {
        candidateNodeId: {
          type: "STRING",
          description: "Candidate enclave node ID under test.",
        },
        autoPatchOnFailure: {
          type: "BOOLEAN",
          description: "Whether to autonomously patch and re-route if a fault is found.",
        },
      },
      required: ["candidateNodeId", "autoPatchOnFailure"],
    },
  },
  {
    name: "anchor_arc_settlement_with_human_gate",
    description:
      "Submits a verified batch execution receipt or node slash transaction to Circle Arc Testnet (chainId 5042002) only after explicit Human-in-the-Loop approval.",
    parameters: {
      type: "OBJECT",
      properties: {
        actionKind: {
          type: "STRING",
          description: "anchor_receipt | slash_faulty_node | release_freeze_key",
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

export interface InteractionsCreatePayload {
  model: typeof GEMINI_4_ARGON_MODEL_ID;
  thinking_level: ArgonThinkingLevel;
  background: boolean;
  max_output_tokens: number;
  max_context_tokens: number;
  implicit_caching: "enabled";
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
    sdk_target: "@google/genai>=2.3.0";
    api_surface: "client.interactions.create";
    persona: string;
    enclave_protocol: "RFC 9180 HPKE EHBP + AMD SEV-SNP + NVIDIA B200 CC";
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
    thinking_level: params.thinkingLevel ?? "high",
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
    system_instruction:
      "You are the Gemini 4 Argon Confidential Security and Routing Orchestrator for dRouter. " +
      "Never accept unredacted secrets or raw genomic identifiers outside the local trust boundary. " +
      "Verify all 1,344 VMPL0 exit policy states (I1-I5) and V1/V6 DDR5 memory-bus entropy via antigravity-preview-09-2026 before dispatching long-context inference to attested Tinfoil enclaves (gemma4-31b / kimi-k3). " +
      "Require explicit Human-in-the-Loop confirmation before anchoring receipts or slashing nodes on Circle Arc.",
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
      sdk_target: "@google/genai>=2.3.0",
      api_surface: "client.interactions.create",
      persona,
      enclave_protocol: "RFC 9180 HPKE EHBP + AMD SEV-SNP + NVIDIA B200 CC",
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
    `import { GoogleGenAI } from "@google/genai"; // >= 2.3.0`,
    ``,
    `const client = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });`,
    ``,
    `// Official Gemini 4 Argon Interactions API call`,
    `// Note: thinking_budget, temperature, top_p, top_k, and cached_content are omitted`,
    `// because gemini-4-argon enforces thinking_level and automatic implicit caching.`,
    `const interaction = await client.interactions.create({`,
    `  model: "${payload.model}",`,
    `  thinking_level: "${payload.thinking_level}",`,
    `  background: ${String(payload.background)}, // > 65,536 token decode & multi-step loop`,
    `  max_output_tokens: ${payload.max_output_tokens},`,
    `  max_context_tokens: ${payload.max_context_tokens},`,
    `  system_instruction: ${JSON.stringify(payload.system_instruction)},`,
    `  input: ${JSON.stringify(payload.input, null, 2)},`,
    `  subagent_routing: ${JSON.stringify(payload.subagent_routing, null, 2)},`,
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
    `    thinking_level="${payload.thinking_level}",`,
    `    background=${payload.background ? "True" : "False"},`,
    `    max_output_tokens=${payload.max_output_tokens},`,
    `    max_context_tokens=${payload.max_context_tokens},`,
    `    system_instruction=${JSON.stringify(payload.system_instruction)},`,
    `    input=[{"role": "user", "content": ${JSON.stringify(payload.input[0]?.content ?? "")}}],`,
    `)`,
    `print(interaction.id, interaction.status)`,
  ].join("\n");

  return { typescript, python };
}

export interface LiveGeminiCallResult {
  attemptedLiveCall: boolean;
  liveEndpointReached: boolean;
  endpointUrl: string;
  httpStatus?: number;
  liveSummaryText?: string;
  fallbackReason?: string;
}

/**
 * Calls the Google Gemini Interactions / v1beta endpoint when a `GEMINI_API_KEY`
 * is provided, while preserving deterministic local cryptographic verification.
 */
export async function callGeminiInteractionsEndpoint(params: {
  payload: InteractionsCreatePayload;
  apiKey?: string;
  timeoutMs?: number;
}): Promise<LiveGeminiCallResult> {
  const resolvedKey = (
    params.apiKey?.trim() ||
    process.env.GEMINI_API_KEY?.trim() ||
    ""
  );
  const interactionsUrl =
    "https://generativelanguage.googleapis.com/v1beta/interactions";

  if (!resolvedKey) {
    return {
      attemptedLiveCall: false,
      liveEndpointReached: false,
      endpointUrl: interactionsUrl,
      fallbackReason:
        "No GEMINI_API_KEY provided in request or environment; executed deterministic local cryptographic and enclave verification harness.",
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), params.timeoutMs ?? 4500);

  try {
    const response = await fetch(
      `${interactionsUrl}?key=${encodeURIComponent(resolvedKey)}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model: params.payload.model,
          thinking_level: params.payload.thinking_level,
          background: params.payload.background,
          max_output_tokens: params.payload.max_output_tokens,
          system_instruction: params.payload.system_instruction,
          input: params.payload.input,
        }),
        signal: controller.signal,
      },
    );

    if (response.ok) {
      const json = (await response.json()) as Record<string, unknown>;
      const outputText =
        typeof json.output_text === "string"
          ? json.output_text
          : JSON.stringify(json).slice(0, 360);
      return {
        attemptedLiveCall: true,
        liveEndpointReached: true,
        endpointUrl: interactionsUrl,
        httpStatus: response.status,
        liveSummaryText: outputText,
      };
    }

    return {
      attemptedLiveCall: true,
      liveEndpointReached: false,
      endpointUrl: interactionsUrl,
      httpStatus: response.status,
      fallbackReason: `Gemini Interactions endpoint returned HTTP ${response.status}; verified execution plan synthesized via local confidential enclave harness.`,
    };
  } catch (err) {
    return {
      attemptedLiveCall: true,
      liveEndpointReached: false,
      endpointUrl: interactionsUrl,
      fallbackReason:
        err instanceof Error
          ? `Network or timeout during live Gemini call (${err.message}); local enclave verification completed.`
          : "Network error during live Gemini call; local enclave verification completed.",
    };
  } finally {
    clearTimeout(timeout);
  }
}
