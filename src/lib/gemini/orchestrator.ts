/**
 * Gemini 4 Argon (`gemini-4-argon`) Split-Knowledge Control Plane Types,
 * Data-Handling Statement, and Pure Client/Server Verification Helpers
 * (`src/lib/gemini/orchestrator.ts`).
 *
 * Wave 6 architecture (W6-A):
 * - All private redaction, symmetry masking, `TaskDescriptor` construction, plan
 *   execution, whole-corpus ranking, Tinfoil enclave invocation (`openTinfoilSession`),
 *   and name restoration run in the user's browser (`src/lib/agent-client/`).
 * - The server never receives task text. The old server-side full-text workflow has
 *   been removed.
 */

import type { AppliedMask } from "@/lib/symmetry/homomorphism";
import type {
  ModelEnclaveAttestation,
  RouterSnpHardwareReport,
} from "@/lib/tinfoil/deep-inspect";
import {
  DATA_SENT_TO_GOOGLE,
  GEMINI_4_ARGON_MODEL_ID,
  type ArgonModelCallRecord,
  type ArgonPlannerDescriptor,
  type ArgonThinkingLevel,
  type GenAIInteractionsClientLike,
  type InteractionsCreatePayload,
  type LiveGeminiCallResult,
  type PlannerToolName,
  type TaskDescriptor,
  type TaskKind,
  type TinfoilPlannerCallResult,
  type TinfoilPlannerClientLike,
} from "./interactions";

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

export interface AttestedPiiFilterResult {
  text: string;
  redactionCount: number;
  model: string;
  verified: boolean;
}

export type AttestedPiiFilterFn = (
  text: string,
) => Promise<AttestedPiiFilterResult>;

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
  tinfoilPlannerCall?: TinfoilPlannerCallResult;
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

export interface AtlasHybridRunnerResult {
  topDocId: string;
  topTitle: string;
  engines: {
    vectorSearch: "atlas" | "app-fallback";
    textSearch: "atlas" | "app-fallback";
    fusion: "$rankFusion" | "app-rrf";
    embedding: string;
  };
  totalDocs: number;
  matchingReceiptsCount: number;
}

export interface LiveTinfoilAttestationResult {
  routerHost: string;
  routerReleaseDigest: string;
  routerPredicate: string;
  routerSnpReport?: RouterSnpHardwareReport;
  modelAttestation: ModelEnclaveAttestation;
  fetchedLive: boolean;
}

export interface ArgonOrchestratorOptions {
  taskPrompt?: string;
  alwaysHide?: string[];
  thinkingLevel?: ArgonThinkingLevel;
  background?: boolean;
  humanApprovedExternalAction?: boolean;
  preferredEnclaveModel?: "gemma4-31b" | "kimi-k3";
  geminiApiKey?: string;
  tinfoilApiKey?: string;
  genaiClient?: GenAIInteractionsClientLike;
  tinfoilClient?: TinfoilPlannerClientLike;
  enableLiveEnclaveInference?: boolean;
  maxSteps?: number;
  wallClockBudgetMs?: number;
  mechanicalRedactor?: MechanicalRedactFn;
  attestedFilterRunner?: AttestedPiiFilterFn;
  symmetryOptions?: {
    dateShiftDays?: number;
    numericScaleFactor?: number;
    customEntities?: Record<string, string>;
  };
  attestationFetcher?: (
    enclaveModel: "gemma4-31b" | "kimi-k3",
  ) => Promise<LiveTinfoilAttestationResult>;
  atlasRunner?: (query: string) => Promise<AtlasHybridRunnerResult>;
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

export { GEMINI_4_ARGON_MODEL_ID };
