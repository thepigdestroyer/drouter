/**
 * Client-safe shared constants, types, error classes, and pure helpers for
 * Gemini 4 Argon (`src/lib/gemini/shared.ts`).
 *
 * Contains zero SDK imports (`@google/genai` is never imported here).
 */

import type { AppliedMask } from "@/lib/symmetry/homomorphism";
import type { AuditStep } from "@/lib/transparency/log";

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

  const rawThinkingLevel =
    input.thinking_level ?? input.thinkingLevel ?? "medium";
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
    if (
      serialized.includes(cleaned) ||
      lowerSerialized.includes(cleaned.toLowerCase())
    ) {
      throw new PrivacyInvariantViolationError(cleaned);
    }
  }
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

export interface MechanicalRedactionItem {
  kind: string;
  placeholder: string;
}

export interface MechanicalRedactResult {
  text: string;
  redactions: MechanicalRedactionItem[];
  restore(s: string): string;
}

export type MechanicalRedactFn = (
  text: string,
  opts?: { customTerms?: string[] },
) => MechanicalRedactResult;

export interface DataHandlingStatement {
  dataSentToGoogle: typeof DATA_SENT_TO_GOOGLE;
  googleCanSee: readonly string[];
  googleCannotSee: readonly string[];
  enclaveCanSee: string;
}

export const HONEST_DATA_HANDLING_STATEMENT: DataHandlingStatement = {
  dataSentToGoogle: DATA_SENT_TO_GOOGLE,
  googleCanSee: [
    "content-free TaskDescriptor (taskKind, $INPUT handle, inputTokenEstimate, redactionCounts, verification booleans, allowedTools)",
    "content-free tool arguments and results (opaque handles, status enums, integer counts, booleans)",
    "server or Confidential Space egress IP and server Gemini API key",
  ],
  googleCannotSee: [
    "user prompt text or any free-text substrings",
    "redacted or unredacted personal details, names, emails, secrets, or numbers in strings",
    "enclave completion text or intermediate reasoning over content",
    "Atlas search queries or knowledge base document text",
    "client IP address or browser headers",
  ],
  enclaveCanSee:
    "Mechanically redacted and symmetry-masked prompt inside attested Tinfoil enclave (AMD SEV-SNP router + Intel TDX / NVIDIA CC GPU enclave) over RFC 9180 HPKE directly from the browser.",
};

export const MAX_ALWAYS_HIDE_TERMS = 64;
export const MAX_ALWAYS_HIDE_TERM_CHARS = 128;

/**
 * Validates, NFKC-normalises, trims, drops empty/single-char strings, deduplicates
 * case-insensitively, and caps count and length of user-configured `alwaysHide` terms.
 */
export function sanitizeAlwaysHideTerms(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (out.length >= MAX_ALWAYS_HIDE_TERMS) break;
    if (typeof item !== "string") continue;
    const normalized = item
      .normalize("NFKC")
      .trim()
      .slice(0, MAX_ALWAYS_HIDE_TERM_CHARS)
      .trim();
    if (normalized.length < 2) continue;
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(normalized);
  }
  return out;
}

export interface NamedUserPersona {
  name: string;
  role: string;
  institution: string;
  assayProtocol: string;
  contextWindowScale: string;
  confidentialityMandate: string;
}

export const DEMO_PERSONA: NamedUserPersona = {
  name: "Example: a fictional hospital data scientist",
  role: "Example: a fictional hospital data scientist (clinical trial statistics)",
  institution: "Example: a fictional hospital data scientist",
  assayProtocol:
    "Phase II trial survival analysis: protocol, de-identified case notes, and R analysis code",
  contextWindowScale:
    "Up to 1,000,000 tokens in Gemini 4 Argon control plane (content-free TaskDescriptor only); 262,144 tokens max context in Tinfoil Kimi K3 enclave",
  confidentialityMandate:
    "Run a multi-step AI analysis and code review without exposing patient identifiers, unpublished trial results, or API credentials to any cloud provider.",
};

export const DEFAULT_TASK_PROMPT =
  "Review our ONC-2041 survival study pipeline for group COHORT-2026-08-14 " +
  "(grant budget £125,000.00, contact dana.reyes@example.org, test key sk-test-4f9a2c7e1b8d6a3f5e0c). " +
  "Summarize the main findings in plain words without sharing any private names or keys.";

export interface GeminiEgressReceipt {
  /** Exact canonical JSON string sent to Google Gemini (`client.interactions.create`). */
  canonicalRequest: string;
  /** Lowercase 64-char SHA-256 hex digest of `canonicalRequest`. */
  sha256: string;
  /** Coarsened UTC hour timestamp in seconds (divisible by 3600). */
  epochHourSec: number;
  kind: "gemini-egress";
  /** Who produced and signed/recorded this receipt. */
  signer: "sealed-google-computer" | "next-server";
  /** Honest human-readable label for who signed/recorded the receipt. */
  signerLabel: string;
  /** Ed25519 signature hex (either from the sealed computer's `egress-signing` key or the server's `operator-tree-head` key). */
  signature: string;
  /** Ed25519 public key hex corresponding to `signature`. */
  publicKey: string;
  /** Optional RFC 8410 SPKI public key hex when signed by `deroute-core`. */
  spkiPublicKey?: string;
  /** Key identifier (`"egress-signing"` for sealed computer, `"operator-tree-head"` for Next server). */
  keyId: "egress-signing" | "operator-tree-head";
  /** Transparency log inclusion details when appended to the server's RFC 6962 log. */
  transparencyLog?: {
    leafIndex: number;
    leafHash: string;
    treeSize: number;
    rootHash: string;
    auditPath: AuditStep[];
    operatorPublicKey: string;
    treeHeadSignature: string;
  };
}

export interface ClosedPlannerStep {
  step: number;
  id: string;
  tool: PlannerToolName;
  arguments: Record<string, unknown>;
}

export interface ClosedAgentPlan {
  taskKind: TaskKind;
  inputHandle: "$INPUT";
  inputTokenEstimate: number;
  steps: ClosedPlannerStep[];
  toolCalls: Array<{
    id: string;
    name: PlannerToolName;
    arguments: Record<string, unknown>;
  }>;
  summary: string;
}

export interface Stage1PrivacyFilterResult {
  stageNumber: 1;
  stageName: "On-Device Privacy Filter & Symmetry Masking";
  modelsUsed: string[];
  passed: boolean;
  verificationSignal: {
    plaintextLeakCount: number;
    bucketBytes: number;
    bucketAligned4096: boolean;
    symmetryHomomorphismVerified: boolean;
    formula: "plaintextLeakCount === 0 && bucketBytes % 4096 === 0";
  };
  redactionCount: number;
  mechanicalRedactionCount: number;
  redactionCounts: Record<string, number>;
  attestedFilter: {
    model: string;
    verified: boolean;
    redactionCount: number;
    fallbackToMechanicalOnly: boolean;
    note: string;
  };
  placeholders: Record<string, string>;
  appliedSymmetryMasks: AppliedMask[];
  papillonGeneralizedPrompt: string;
  homomorphicEquation: string;
}

export interface SubagentTaskTrace {
  subagentId: string;
  model: string;
  task: string;
  latencyMs: number;
  passed: boolean;
  artifactSummary: string;
}

export interface SevenCheckStatus {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface Stage2SubagentSwarmResult {
  stageNumber: 2;
  stageName: "Live 2-Hop Hardware Attestation, Atlas Hybrid Search & Registry Verification";
  modelsUsed: string[];
  passed: boolean;
  verificationSignal: {
    allSevenChecksPassed: boolean;
    checksPassed: number;
    checksTotal: number;
    formula: "allSevenChecksPassed === true";
  };
  subagents: SubagentTaskTrace[];
  sevenChecks: SevenCheckStatus[];
  selectedEnclaveProvider: string;
  selectedEnclaveModel: string;
  selectedEnclaveHost: string;
  routerHost: string;
}

export interface SandboxAttemptRecord {
  attemptNumber: number;
  candidateNodeId: string;
  candidateModelId?: "gemma4-31b" | "kimi-k3";
  enclaveAttestationVerified: boolean;
  verifiedHosts: number;
  configuredHosts: number;
  unverifiedHosts: number;
  measurementRegisterCount: number;
  dmVerityRootHashPresent: boolean;
  releaseDigestMatched: boolean;
  failedInvariants: string[];
  plaintextLeakMatches: number;
  passed: boolean;
  remediationApplied?: string;
}

export interface Stage3SandboxVerificationResult {
  stageNumber: 3;
  stageName: "Live Tinfoil Enclave Measurement Verification & Automatic Model Failover";
  modelsUsed: string[];
  passed: boolean;
  failedOver: boolean;
  attempts: SandboxAttemptRecord[];
  sandboxReceipt: {
    sandboxId: string;
    imageMeasurementHex: string;
    rtmr3Hex: string;
  };
  verificationSignal: {
    enclaveAttestationVerified: boolean;
    verifiedHosts: number;
    configuredHosts: number;
    unverifiedHosts: number;
    measurementRegisterCount: number;
    dmVerityRootHashPresent: boolean;
    releaseDigestMatched: boolean;
    formula:
      "enclaveAttestationVerified === true && verifiedHosts > 0 && unverifiedHosts === 0 && measurementRegisterCount > 0 && dmVerityRootHashPresent === true && releaseDigestMatched === true";
  };
}

export interface Stage4ArgonSynthesisResult {
  stageNumber: 4;
  stageName: "Gemini 4 Argon Split-Knowledge Control Plane & Attested Enclave Execution";
  modelsUsed: string[];
  passed: boolean;
  planner: ArgonPlannerDescriptor;
  plannerStatus?: "ok" | "unavailable";
  plan?: ClosedAgentPlan | null;
  egressReceipt?: GeminiEgressReceipt | null;
  canonicalBytesSentToGoogle?: string | null;
  thinkingLevel: ArgonThinkingLevel;
  background: boolean;
  unifiedContextTokens: number;
  enclaveMaxContextTokens: number;
  routedEnclaveModel: "gemma4-31b" | "kimi-k3";
  routedEnclaveHost: string;
  taskDescriptor: TaskDescriptor;
  dataSentToGoogle: typeof DATA_SENT_TO_GOOGLE | "none (planner unavailable)";
  resolvedHandles: Record<
    string,
    { tokenEstimate: number; sha256Hex: string }
  >;
  interactionsPayload: InteractionsCreatePayload;
  sdkSnippets: {
    typescript: string;
    python: string;
  };
  liveGeminiCall: LiveGeminiCallResult;
  enclaveCompletionMasked: string;
  restoredClientOutput: string;
  verificationSignal: {
    argonConfigValid: boolean;
    privacyInvariantVerified: boolean;
    contentFreeEgressVerified: boolean;
    homomorphicRestoreVerified: boolean;
    enclaveModelAttested: boolean;
    formula:
      "argonConfigValid === true && homomorphicRestoreVerified === true && enclaveModelAttested === true";
  };
}

export interface Stage5HumanInTheLoopResult {
  stageNumber: 5;
  stageName: "Human-in-the-Loop Control Gate (Circle Arc Settlement)";
  passed: boolean;
  requiresHumanApproval: true;
  approvedByHuman: boolean;
  externalActionStatus: "paused_awaiting_human" | "executed_with_human_approval";
  stateChangedOnChain: boolean;
  pendingActions: Array<{
    actionId: string;
    kind: "anchor_arc_receipt";
    description: string;
    gasToken: "USDC (Circle Arc Testnet 5042002)";
    status: "blocked_pending_human" | "executed";
    txHashHex?: string;
  }>;
  verificationSignal: {
    requiresHumanApproval: true;
    approvedByHuman: boolean;
    unauthorizedStateChangePrevented: boolean;
    formula:
      "requiresHumanApproval === true && (approvedByHuman ? stateChangedOnChain === true : stateChangedOnChain === false)";
  };
}

export interface Stage6MultimodalReadoutResult {
  stageNumber: 6;
  stageName: "Verification Briefing & Ed25519 Signed Forensic Digest";
  modelsUsed: string[];
  passed: boolean;
  voiceTranscript: string;
  audioPcmFrameMetadata: {
    sampleRateHz: 24000;
    channels: 1;
    durationSeconds: number;
    voiceProfile: "text-readout-only";
  };
  forensicProofDigestHex: string;
  ed25519SignatureHex: string;
  signerPublicKeyHex: string;
  verificationSignal: {
    briefingGenerated: boolean;
    proofDigestValid: boolean;
    signatureVerified: boolean;
    formula:
      "briefingGenerated === true && proofDigestHex.length === 64 && signatureVerified === true";
  };
}

export interface ArgonAutonomousRunResult {
  runId: string;
  timestampIso: string;
  mode: "live" | "tinfoil-planner" | "planner-unavailable";
  planner: ArgonPlannerDescriptor;
  plannerStatus?: "ok" | "unavailable";
  plan?: ClosedAgentPlan | null;
  egressReceipt?: GeminiEgressReceipt | null;
  canonicalBytesSentToGoogle?: string | null;
  dataSentToGoogle: typeof DATA_SENT_TO_GOOGLE | "none (planner unavailable)";
  dataHandling: DataHandlingStatement;
  taskDescriptor: TaskDescriptor;
  modelCalls: ArgonModelCallRecord[];
  persona: NamedUserPersona;
  overallPassed: boolean;
  humanGateState: "paused_awaiting_human" | "executed_with_human_approval";
  stages: {
    stage1: Stage1PrivacyFilterResult;
    stage2: Stage2SubagentSwarmResult;
    stage3: Stage3SandboxVerificationResult;
    stage4: Stage4ArgonSynthesisResult;
    stage5: Stage5HumanInTheLoopResult;
    stage6: Stage6MultimodalReadoutResult;
  };
}

const UNRESTORED_PLACEHOLDER_RE =
  /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\d+\]|<PRIVATE_[A-Z0-9_]+>/i;

function escapeRegExpLiteral(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countCaseInsensitiveOccurrences(haystack: string, needle: string): number {
  if (!haystack || !needle) return 0;
  const re = new RegExp(escapeRegExpLiteral(needle), "gi");
  let count = 0;
  while (re.exec(haystack) !== null) {
    count += 1;
  }
  return count;
}

/**
 * Verifies that a restored output string:
 * 1. Contains no leftover mechanical placeholders (`[KIND_N]`, case-insensitive) or symmetry surrogates.
 * 2. Restores every occurrence of repeated placeholders and symmetry masks present in `maskedText`.
 * 3. Evaluates overlapping restored originals longest-first (consuming matched spans so a longer
 *    term like "Halden & Moss LLP" cannot falsely satisfy a shorter overlapping term like "Moss").
 * 4. Handles case differences and NFKC Unicode normalization cleanly.
 */
export function verifyRedactionAndSymmetryRestore(params: {
  rawPrompt: string;
  maskedText: string;
  restoredText: string;
  placeholders: Record<string, string>;
  appliedSymmetryMasks?: readonly AppliedMask[];
}): boolean {
  const {
    rawPrompt,
    maskedText,
    restoredText,
    placeholders,
    appliedSymmetryMasks = [],
  } = params;
  if (!maskedText || !restoredText) return false;

  const normRawPrompt = rawPrompt.normalize("NFKC");
  const normMasked = maskedText.normalize("NFKC");
  const normRestored = restoredText.normalize("NFKC");
  const lowerRawPrompt = normRawPrompt.toLowerCase();
  const lowerRestored = normRestored.toLowerCase();

  if (UNRESTORED_PLACEHOLDER_RE.test(normRestored)) {
    return false;
  }

  for (const placeholder of Object.keys(placeholders)) {
    const normPlaceholder = placeholder.normalize("NFKC");
    if (
      normPlaceholder &&
      lowerRestored.includes(normPlaceholder.toLowerCase())
    ) {
      return false;
    }
  }

  for (const mask of appliedSymmetryMasks) {
    const normMask = mask.masked.normalize("NFKC");
    const normOrig = mask.original.normalize("NFKC");
    if (
      normMask &&
      normMask.toLowerCase() !== normOrig.toLowerCase() &&
      !lowerRawPrompt.includes(normMask.toLowerCase()) &&
      lowerRestored.includes(normMask.toLowerCase())
    ) {
      return false;
    }
  }

  const expectedCounts = new Map<string, number>();
  const addExpected = (orig: string, count: number) => {
    if (count <= 0) return;
    const key = orig.normalize("NFKC").toLowerCase();
    if (!key) return;
    expectedCounts.set(key, (expectedCounts.get(key) ?? 0) + count);
  };

  for (const [placeholder, original] of Object.entries(placeholders)) {
    const normPlaceholder = placeholder.normalize("NFKC");
    const occ = countCaseInsensitiveOccurrences(normMasked, normPlaceholder);
    if (occ > 0) {
      addExpected(original, occ);
    }
  }

  const masksByLowerMasked = new Map<
    string,
    { masked: string; originals: string[] }
  >();
  for (const mask of appliedSymmetryMasks) {
    const normMask = mask.masked.normalize("NFKC");
    const normOrig = mask.original.normalize("NFKC");
    if (!normMask || !normOrig) continue;
    const lowerMask = normMask.toLowerCase();
    const existing = masksByLowerMasked.get(lowerMask);
    if (existing) {
      existing.originals.push(normOrig);
    } else {
      masksByLowerMasked.set(lowerMask, {
        masked: normMask,
        originals: [normOrig],
      });
    }
  }

  let workingMaskedLower = normMasked.toLowerCase();
  const sortedMaskGroups = Array.from(masksByLowerMasked.values()).sort(
    (a, b) => b.masked.length - a.masked.length,
  );
  for (const group of sortedMaskGroups) {
    const re = new RegExp(escapeRegExpLiteral(group.masked.toLowerCase()), "gi");
    let matchIdx = 0;
    workingMaskedLower = workingMaskedLower.replace(re, (m) => {
      const origForOccurrence =
        group.originals[Math.min(matchIdx, group.originals.length - 1)];
      matchIdx += 1;
      addExpected(origForOccurrence, 1);
      return "\u0000".repeat(m.length);
    });
  }

  let workingRestoredLower = lowerRestored;
  const sortedExpected = Array.from(expectedCounts.entries()).sort(
    (a, b) => b[0].length - a[0].length,
  );

  for (const [lowerOrig, requiredCount] of sortedExpected) {
    if (requiredCount <= 0) continue;
    const re = new RegExp(escapeRegExpLiteral(lowerOrig), "g");
    let foundCount = 0;
    workingRestoredLower = workingRestoredLower.replace(re, (m) => {
      if (foundCount < requiredCount) {
        foundCount += 1;
        return "\u0000".repeat(m.length);
      }
      return m;
    });
    if (foundCount < requiredCount) {
      return false;
    }
  }

  return true;
}
