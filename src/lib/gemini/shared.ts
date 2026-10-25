/**
 * Client-safe shared constants, types, error classes, and pure helpers for
 * Gemini 4 Argon (`src/lib/gemini/shared.ts`).
 *
 * Contains zero SDK imports (`@google/genai` is never imported here).
 */

export const GEMINI_4_ARGON_MODEL_ID = "gemini-4-argon" as const;

export const DATA_SENT_TO_GOOGLE = "content-free task descriptor only" as const;

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

export type TaskKind = "summarize" | "analyze" | "draft" | "review" | "question";

export const VALID_TASK_KINDS: readonly TaskKind[] = [
  "summarize",
  "analyze",
  "draft",
  "review",
  "question",
] as const;

export const ALLOWED_PLANNER_TOOLS = [
  "scrub_and_symmetry_mask",
  "verify_two_hop_enclave_and_quorum",
  "search_atlas_hybrid_kb",
  "invoke_attested_enclave",
  "anchor_arc_settlement_with_human_gate",
] as const;

export type PlannerToolName = (typeof ALLOWED_PLANNER_TOOLS)[number];

export const ALLOWED_ATLAS_TOPICS = [
  "tinfoil_enclave",
  "sev_snp_router",
  "tdx_gpu_cc",
  "hpke_ehbp",
  "arc_registry",
  "blind_credits",
  "pii_redaction",
] as const;

export type AllowedAtlasTopic = (typeof ALLOWED_ATLAS_TOPICS)[number];

export const ALLOWED_ATLAS_CATEGORIES = [
  "provider",
  "advisory",
  "architecture",
  "all",
] as const;

export type AllowedAtlasCategory = (typeof ALLOWED_ATLAS_CATEGORIES)[number];

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
] as const;

export type LookupTopic = (typeof LOOKUP_TOPICS)[number];

export const MAX_PLANNER_STEPS = 5;
export const MAX_PLANNER_WALL_CLOCK_MS = 20_000;

export interface TaskDescriptor {
  taskKind: TaskKind;
  inputHandle: "$INPUT";
  inputTokenEstimate: number;
  redactionCounts: Record<string, number>;
  verification: Record<string, boolean>;
  allowedTools: string[];
}

/**
 * Deterministically classifies a user prompt into a content-free `TaskKind` enum
 * locally without invoking any external model.
 */
export function classifyTaskKind(rawText: string): TaskKind {
  const lower = (rawText || "").toLowerCase();
  if (
    /\b(?:review|audit|inspect|compliance|agreement)\b/.test(lower) &&
    !/\bsummarize\s+the\s+main\b/.test(lower)
  ) {
    return "review";
  }
  if (/\b(?:summarize|summary|briefing|tldr|overview)\b/.test(lower)) {
    return "summarize";
  }
  if (/\b(?:draft|write|compose|prepare\s+a\s+draft)\b/.test(lower)) {
    return "draft";
  }
  if (
    lower.trim().endsWith("?") ||
    /^(?:what|how|why|when|where|who|which|can\s+you\s+explain)\b/.test(
      lower.trim(),
    )
  ) {
    return "question";
  }
  if (/\b(?:review|audit|check)\b/.test(lower)) {
    return "review";
  }
  return "analyze";
}

export const FORBIDDEN_ARGON_PARAMETERS = [
  "thinking_budget",
  "temperature",
  "top_p",
  "top_k",
  "cached_content",
] as const;

export type ForbiddenArgonParameter =
  (typeof FORBIDDEN_ARGON_PARAMETERS)[number];

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
  trustBoundary:
    | "on-device-local"
    | "attested-tee-enclave"
    | "gemini-interactions-cloud";
  description: string;
  tinfoilEnclaveAlias?: string;
}

export const ARGON_TOOLKIT_MANIFEST: readonly ArgonToolkitModelSpec[] = [
  {
    id: GEMINI_4_ARGON_MODEL_ID,
    role: "Split-Knowledge Control-Plane Planner (receives content-free TaskDescriptor only)",
    stageUsed:
      "Stage 4 (Control-Plane Tool Loop when GEMINI_API_KEY is provided)",
    statusInDemo: "used-when-key-set",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Invoked via @google/genai client.interactions.create over a content-free TaskDescriptor ($INPUT handle, counts, booleans, enums). Never receives user text, enclave output text, or search queries.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOpenCloud,
    role: "Open-Weight Confidential Enclave Planner and Inference Model (Tinfoil Live Attested)",
    stageUsed:
      "Stage 4 (Attested Tinfoil Enclave Planner and Content Execution via gemma4-31b or kimi-k3)",
    statusInDemo: "live-enclave",
    trustBoundary: "attested-tee-enclave",
    tinfoilEnclaveAlias: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
    description:
      "Maps to Tinfoil's live attested gemma4-31b and kimi-k3 enclaves (Intel TDX + NVIDIA CC GPUs) routed via router-0.tinfoil.sh (AMD SEV-SNP). Executes all content work on server-resolved handles.",
  },
  {
    id: "pii-filter",
    role: "Attested Enclave Second-Pass PII Redaction Model (Tinfoil Live Attested)",
    stageUsed:
      "Stage 1 (Attested PII Filter after deterministic mechanicalRedact)",
    statusInDemo: "live-enclave",
    trustBoundary: "attested-tee-enclave",
    description:
      "Runs inside a sealed Tinfoil enclave after deterministic mechanicalRedact before any derived text leaves the enclave boundary.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentFast,
    role: "Not used for user text (Atlas Hybrid Search runs deterministically on server)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used for content summarization so zero search queries or document titles ever reach Google.",
  },
  {
    id: ARGON_COMPANION_MODELS.parallelSubagentLite,
    role: "Not used for user text (C1-C7 attestation verification runs deterministically in TypeScript)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used for attestation text summarization; C1-C7 checks are computed deterministically by code.",
  },
  {
    id: ARGON_COMPANION_MODELS.sandboxAgent,
    role: "Not used in this demo (enclave attestation and failover checks run in deterministic TypeScript)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "attested-tee-enclave",
    description:
      "Not used in this demo. Stage 3 verifies live Tinfoil model enclave measurements and failover in TypeScript.",
  },
  {
    id: ARGON_COMPANION_MODELS.deepResearch,
    role: "Not used in this demo (advisories are queried from MongoDB Atlas enclave_intelligence)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Not used in this demo. Hardware advisories are retrieved from MongoDB Atlas Hybrid Search.",
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
    role: "Not used in this demo (Stage 1 runs deterministic mechanicalRedact and symmetry masking)",
    stageUsed: "not used",
    statusInDemo: "not-used",
    trustBoundary: "on-device-local",
    description:
      "Not used in this demo. Stage 1 runs deterministic mechanicalRedact (src/lib/privacy/mechanical), attestedPiiFilter (src/lib/privacy/attested-filter), and symmetry masking.",
  },
] as const;

export class PrivacyInvariantViolationError extends Error {
  readonly leakedToken: string;

  constructor(leakedToken: string, messageOverride?: string) {
    super(
      messageOverride ??
        `PRIVACY_INVARIANT_VIOLATION: Outbound planner payload contained unredacted or non-allowlisted value (${String(leakedToken).slice(0, 12)}***). Call aborted before network transmission.`,
    );
    this.name = "PrivacyInvariantViolationError";
    this.leakedToken = leakedToken;
  }
}

export class ContentFreeEgressError extends PrivacyInvariantViolationError {
  readonly path: string;

  constructor(rejectedValue: string, path = "$") {
    super(
      rejectedValue,
      `CONTENT_FREE_EGRESS_VIOLATION at ${path}: Outbound Gemini payload contained non-allowlisted string or content (${String(rejectedValue).slice(0, 16)}***). Only opaque handles, fixed SHA-256 hashes, booleans, numbers, and allowlisted enums may leave the server to Google.`,
    );
    this.name = "ContentFreeEgressError";
    this.path = path;
  }
}

export class ToolPolicyViolationError extends Error {
  readonly toolName: string;
  readonly validationErrors: string[];

  constructor(toolName: string, validationErrors: string[]) {
    super(
      `TOOL_POLICY_VIOLATION (${toolName}): ${validationErrors.join("; ")}`,
    );
    this.name = "ToolPolicyViolationError";
    this.toolName = toolName;
    this.validationErrors = validationErrors;
  }
}

export class PlannerBudgetExceededError extends Error {
  readonly kind: "max_steps" | "wall_clock_timeout";
  readonly limit: number;

  constructor(kind: "max_steps" | "wall_clock_timeout", limit: number) {
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

export const SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION =
  "SPLIT_KNOWLEDGE_CONTROL_PLANE_V1: Plan over the content-free TaskDescriptor using only opaque handles ($INPUT, $RESULT_n) and allowlisted enums. Never request or emit user text." as const;

export interface ArgonInteractionToolDeclaration {
  type: "function";
  name: PlannerToolName;
  description: string;
  parameters: {
    type: "OBJECT";
    properties: Record<
      string,
      {
        type: "STRING" | "INTEGER" | "BOOLEAN";
        description: string;
        enum?: readonly string[];
      }
    >;
    required: string[];
  };
}

export const ARGON_CONFIDENTIAL_TOOLS: readonly ArgonInteractionToolDeclaration[] =
  [
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
            description:
              "Target confidential compute provider identifier (tinfoil).",
            enum: ["tinfoil"],
          },
          enclaveModel: {
            type: "STRING",
            description:
              "Target attested enclave model identifier (gemma4-31b or kimi-k3).",
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
            description:
              "Optional category filter (provider, advisory, architecture, all).",
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
            description:
              "Opaque handle ($INPUT or $RESULT_n) resolved server-side for enclave execution.",
          },
          enclaveModel: {
            type: "STRING",
            description:
              "Attested Tinfoil enclave model identifier (gemma4-31b or kimi-k3).",
            enum: ["gemma4-31b", "kimi-k3"],
          },
          taskKind: {
            type: "STRING",
            description:
              "Task kind enum (summarize, analyze, draft, review, question).",
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
            description:
              "Whether human approval was requested (enforced independently by server state).",
          },
        },
        required: ["actionKind", "humanApproved"],
      },
    },
  ] as const;

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

export const SAFE_CALL_ID_REGEX = CLOSED_CALL_ID_REGEX;

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

export const MAX_GOOGLE_BOUND_HEX_LENGTH = 16;
export const ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED = false;

export const MAX_REDACTION_COUNT_PER_KIND = 2;
export const MAX_PLAINTEXT_LEAK_COUNT = 5;
export const MAX_TOKEN_BUCKET = 1_048_576;

export function isPowerOfTwo(n: unknown): n is number {
  return isPowerOfTwoInRange(n, 1, MAX_TOKEN_BUCKET);
}

export function roundUpToPowerOfTwo(n: number): number {
  const clamped = Math.max(
    1,
    Math.min(MAX_TOKEN_BUCKET, Math.ceil(Number(n) || 1)),
  );
  let bucket = 1;
  while (bucket < clamped && bucket < MAX_TOKEN_BUCKET) {
    bucket *= 2;
  }
  return bucket;
}

export function bucketScrubRedactionCount(n: number): number {
  const intVal = Math.max(0, Math.min(64, Math.ceil(Number(n) || 0)));
  if (intVal === 0) return 0;
  let bucket = 1;
  while (bucket < intVal && bucket < 64) {
    bucket *= 2;
  }
  return bucket;
}

export const ALLOWED_REDACTION_COUNT_KEYS: ReadonlySet<string> =
  new Set<string>([
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

export const ALLOWED_VERIFICATION_KEYS: ReadonlySet<string> = new Set<string>([
  "mechanicalRedactionPassed",
  "attestedPiiFilterVerified",
  "bucketAligned4096",
  "routerSevSnpVerified",
  "enclaveTdxGpuVerified",
  "hpkeKeyBound",
  "sigstoreManifestVerified",
  "arcRegistryVerified",
]);

export const ALLOWED_HANDLE_KEYS: ReadonlySet<string> = new Set<string>([
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

export const ALLOWED_HASH_KEYS: ReadonlySet<string> = new Set<string>([
  "contentSha256",
  "routerDigestHex",
  "enclaveMeasurementHex",
  "topDocSha256",
  "outputSha256",
  "receiptSha256",
]);

export interface OpenAICompatibleToolDefinition {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<
        string,
        { type: string; description: string; enum?: readonly string[] }
      >;
      required: string[];
    };
  };
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
  system_instruction: typeof SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION;
  taskDescriptor: TaskDescriptor;
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
    persona: "redacted_clinical_scientist_persona";
    enclave_protocol: "RFC 9180 HPKE EHBP + AMD SEV-SNP Router + Intel TDX / NVIDIA CC GPU Enclaves";
    data_sent_to_google: typeof DATA_SENT_TO_GOOGLE;
  };
}

export interface LiveGeminiCallResult {
  attemptedLiveCall: boolean;
  liveEndpointReached: boolean;
  sdkMethod: "client.interactions.create";
  interactionId?: string;
  interactionStatus?: string;
  toolCallsExecuted?: string[];
  resolvedDigestHandles?: Record<string, string>;
  liveSummaryText?: string;
  fallbackReason?: string;
  modelCallRecord?: ArgonModelCallRecord;
  dataSentToGoogle: typeof DATA_SENT_TO_GOOGLE | "none (planner unavailable)";
  egressFirewallVerified: boolean;
}

export interface GenAIInteractionsClientLike {
  interactions: {
    create(
      params: Record<string, unknown>,
      options?: Record<string, unknown>,
    ): Promise<{
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
