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

import { GoogleGenAI } from "@google/genai";
import { estimateTokens } from "@/lib/privacy/padding";
import { canonicalJson } from "@/lib/transparency/log";

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
    /^(?:what|how|why|when|where|who|which|can\s+you\s+explain)\b/.test(lower.trim())
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
    role: "Split-Knowledge Control-Plane Planner (receives content-free TaskDescriptor only)",
    stageUsed: "Stage 4 (Control-Plane Tool Loop when GEMINI_API_KEY is provided)",
    statusInDemo: "used-when-key-set",
    trustBoundary: "gemini-interactions-cloud",
    description:
      "Invoked via @google/genai client.interactions.create over a content-free TaskDescriptor ($INPUT handle, counts, booleans, enums). Never receives user text, enclave output text, or search queries.",
  },
  {
    id: ARGON_COMPANION_MODELS.confidentialOpenCloud,
    role: "Open-Weight Confidential Enclave Planner and Inference Model (Tinfoil Live Attested)",
    stageUsed: "Stage 4 (Attested Tinfoil Enclave Planner and Content Execution via gemma4-31b or kimi-k3)",
    statusInDemo: "live-enclave",
    trustBoundary: "attested-tee-enclave",
    tinfoilEnclaveAlias: ARGON_COMPANION_MODELS.tinfoilEnclaveGemma,
    description:
      "Maps to Tinfoil's live attested gemma4-31b and kimi-k3 enclaves (Intel TDX + NVIDIA CC GPUs) routed via router-0.tinfoil.sh (AMD SEV-SNP). Executes all content work on server-resolved handles.",
  },
  {
    id: "pii-filter",
    role: "Attested Enclave Second-Pass PII Redaction Model (Tinfoil Live Attested)",
    stageUsed: "Stage 1 (Attested PII Filter after deterministic mechanicalRedact)",
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

export const ARGON_CONFIDENTIAL_TOOLS: readonly ArgonInteractionToolDeclaration[] = [
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
          enum: ALLOWED_ATLAS_TOPICS,
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
] as const;

const OPAQUE_HANDLE_REGEX = /^(?:\$INPUT|\$RESULT_(?:[1-9]|[1-5]\d|6[0-4]))$/;
const FIXED_SHA256_HEX_REGEX = /^0x[0-9a-f]{64}$/;
export const SAFE_CALL_ID_REGEX =
  /^(?:call|tc|inter)-(?:[1-9]\d{0,2}|turn-[1-9]\d{0,1}|argon-turn-[1-9]|(?:[1-9]-)?(?:scrub_and_symmetry_mask|verify_two_hop_enclave_and_quorum|search_atlas_hybrid_kb|invoke_attested_enclave|anchor_arc_settlement_with_human_gate)|[1-9]-[1-9]\d{0,1})$/;

export const MAX_REDACTION_COUNT_PER_KIND = 5;
export const MAX_TOKEN_BUCKET = 1_048_576;

export const ALLOWED_REDACTION_COUNT_KEYS: ReadonlySet<string> = new Set<string>([
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

export const ALLOWED_HASH_KEYS: ReadonlySet<string> = new Set<string>([
  "contentSha256",
  "routerDigestHex",
  "enclaveMeasurementHex",
  "topDocSha256",
  "outputSha256",
  "receiptSha256",
]);

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
]);

const ALLOWED_INTERACTION_STATUSES: ReadonlySet<string> = new Set<string>([
  "completed",
  "in_progress",
  "requires_action",
  "failed",
  "cancelled",
]);

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

function hasAsciiRunOrCount(byteValues: readonly number[]): boolean {
  let consecutivePrintableAscii = 0;
  let totalPrintableLettersOrSpaces = 0;
  for (let i = 0; i < byteValues.length; i++) {
    const byteVal = byteValues[i];
    if (byteVal >= 0x20 && byteVal <= 0x7e) {
      consecutivePrintableAscii += 1;
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
  return totalPrintableLettersOrSpaces >= 18;
}

function hasSmuggledAsciiInHex(hexWithoutPrefix: string): boolean {
  // Reject 64-digit decimal number strings disguised with a 0x prefix
  if (/^\d{64}$/.test(hexWithoutPrefix)) {
    return true;
  }
  // Reject trivial repeating sequences (e.g., 0000000000000000 or 1234123412341234)
  if (/^([0-9a-f]{1,4})\1{15,}$/.test(hexWithoutPrefix)) {
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
  if (freq.size < 12 || maxFreq >= 6) {
    return true;
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
    if ((b & 0x80) !== 0 && (isLetterOrSpace || isDigitOrCommonPunct)) {
      consecutiveHighBitText += 1;
      if (isLetterOrSpace) {
        totalHighBitLettersOrSpaces += 1;
      }
      if (consecutiveHighBitText >= 8) {
        return true;
      }
    } else {
      consecutiveHighBitText = 0;
    }
  }
  return totalHighBitLettersOrSpaces >= 16;
}

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

export function isContentFreeString(value: string, keyContext?: string): boolean {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  if (OPAQUE_HANDLE_REGEX.test(value)) {
    return true;
  }
  if (FIXED_SHA256_HEX_REGEX.test(value)) {
    if (!keyContext || !ALLOWED_HASH_KEYS.has(keyContext)) {
      return false;
    }
    return !hasSmuggledAsciiInHex(value.slice(2));
  }
  if (
    keyContext === "required" &&
    ALLOWED_REQUIRED_PARAM_NAMES.has(value)
  ) {
    return true;
  }
  if (
    (keyContext === "id" ||
      keyContext === "call_id" ||
      keyContext === "tool_call_id" ||
      keyContext === "previous_interaction_id") &&
    SAFE_CALL_ID_REGEX.test(value) &&
    !/\d{4,}/.test(value)
  ) {
    return true;
  }
  if (
    (keyContext === "system_instruction" || keyContext === "description") &&
    ALLOWED_STATIC_SCHEMA_DESCRIPTIONS.has(value)
  ) {
    return true;
  }
  return ALLOWED_CONTENT_FREE_ENUMS.has(value);
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
 * handles (`$INPUT`, `$RESULT_<n>`), verified 32-byte lowercase SHA-256 hex hashes
 * under allowlisted hash keys, or allowlisted enum literals, and rejects any
 * unallowlisted object keys, numbers, arrays, or JSON-smuggled content.
 */
export function assertContentFree(
  value: unknown,
  path = "$",
  keyContext?: string,
  depth = 0,
  insideJsonString = false,
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
    if (
      ALLOWED_REDACTION_COUNT_KEYS.has(keyContext) &&
      num > MAX_REDACTION_COUNT_PER_KIND
    ) {
      throw new ContentFreeEgressError(String(value), path);
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
      assertContentFree(parsed, `${path}(json)`, undefined, depth + 1, true);
      return;
    }
    if (!isContentFreeString(str, keyContext)) {
      throw new ContentFreeEgressError(str, path);
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
      );
    }
    return;
  }
  if (isPlainObject(value)) {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new ContentFreeEgressError("<symbol_property>", path);
    }
    if (typeof (value as { toJSON?: unknown }).toJSON === "function") {
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
    topic: { type: "STRING", required: true, enum: ALLOWED_ATLAS_TOPICS },
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

export function assertValidToolCall(
  toolName: string,
  args: unknown,
): Record<string, unknown> {
  const res = validateToolCallArguments(toolName, args);
  if (!res.valid || !res.sanitizedArgs) {
    throw new ToolPolicyViolationError(toolName, res.errors);
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
  const inputTokenEstimate = Math.min(
    MAX_TOKEN_BUCKET,
    Math.max(
      1,
      Math.trunc(
        params.inputTokenEstimate ??
          estimateTokens(params.rawTextForClassification ?? "task"),
      ),
    ),
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
  dataSentToGoogle: typeof DATA_SENT_TO_GOOGLE;
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

  // Enforce both Privacy Invariant and Content-Free Egress Firewall before checking key or calling Google
  assertOutboundPrivacyInvariant(params.payload, sensitiveOriginals);
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
    (new GoogleGenAI({ apiKey: resolvedKey }) as unknown as GenAIInteractionsClientLike);

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
    while (params.toolExecutor && Array.isArray(interaction.steps)) {
      const fnCalls = interaction.steps.filter(
        (s) => s && s.type === "function_call" && typeof s.name === "string",
      );
      if (fnCalls.length === 0) break;

      if (turn >= maxSteps || stepCount + fnCalls.length > maxSteps) {
        throw new PlannerBudgetExceededError("max_steps", maxSteps);
      }

      const fnResults: Array<Record<string, unknown>> = [];
      for (let idx = 0; idx < fnCalls.length; idx++) {
        const call = fnCalls[idx];
        const name = call.name as string;
        const validatedArgs = assertValidToolCall(name, call.arguments ?? {});
        stepCount += 1;
        toolCallsExecuted.push(name);

        const resultObj = await withWallClockBudget(
          params.toolExecutor(name, validatedArgs),
          startedAt,
          wallClockBudgetMs,
        );

        assertOutboundPrivacyInvariant(resultObj, sensitiveOriginals);
        assertContentFree(resultObj, `$.toolResult(${name})`);

        const safeCallId =
          typeof call.id === "string" &&
          SAFE_CALL_ID_REGEX.test(call.id) &&
          !/\d{4,}/.test(call.id)
            ? call.id
            : `call-${turn + 1}-${idx + 1}`;
        const resultStep: Record<string, unknown> = {
          type: "function_result",
          call_id: safeCallId,
          name,
          result: canonicalJson(resultObj),
        };
        assertOutboundPrivacyInvariant(resultStep, sensitiveOriginals);
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
            throw new ToolPolicyViolationError(fnName, [
              "Tool arguments must be valid JSON object.",
            ]);
          }
        }
        assertOutboundPrivacyInvariant(parsedArgs, sensitiveOriginals);
        const validatedArgs = assertValidToolCall(fnName, parsedArgs);
        stepCount += 1;
        toolCallsExecuted.push(fnName);

        const toolResult = await withWallClockBudget(
          params.toolExecutor(fnName, validatedArgs),
          startedAt,
          wallClockBudgetMs,
        );
        assertOutboundPrivacyInvariant(toolResult, sensitiveOriginals);
        assertContentFree(toolResult, `$.tinfoilToolResult(${fnName})`);

        const toolMsg: Record<string, unknown> = {
          role: "tool",
          tool_call_id: tc.id || `call-${turn + 1}-${fnName}`,
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
