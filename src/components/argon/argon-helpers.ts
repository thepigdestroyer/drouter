import { GEMINI_4_ARGON_MODEL_ID } from "@/lib/gemini/shared";
import type {
  ArgonAutonomousRunResult,
  DataHandlingStatement,
  GeminiEgressReceipt,
} from "@/lib/gemini/orchestrator";
import {
  findForbiddenPlainTerms,
  FORBIDDEN_PLAIN_VIEW_TERMS,
  formatPlainAtlasResult,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolveEffectiveAtlasQuery,
  sanitizeJargonToPlainWords,
  type PlainDocOverride,
} from "@/lib/plain-copy";

export {
  findForbiddenPlainTerms,
  FORBIDDEN_PLAIN_VIEW_TERMS,
  formatPlainAtlasResult,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolveEffectiveAtlasQuery,
  sanitizeJargonToPlainWords,
  type PlainDocOverride,
};

export const AGENT_INTRO_SENTENCE =
  "Give it a private task. It hides your personal details, checks the sealed computer, does the work, and asks you before it records anything in public." as const;

export const APPROVAL_CARD_QUESTION =
  "Allow the agent to record a receipt in the public receipt book?" as const;

export const WHAT_GOOGLE_RECEIVED_PROMPT =
  "Gemini planned the steps without seeing your words. What Google received:" as const;

export interface ExampleAgentTask {
  id: string;
  label: string;
  description: string;
  prompt: string;
}

export const EXAMPLE_AGENT_TASKS: readonly ExampleAgentTask[] = [
  {
    id: "study-notes",
    label: "Example: a fictional hospital data scientist",
    description:
      "Hides emails, dates, budgets, group codes, and secret keys before checking the study.",
    prompt:
      "Review our ONC-2041 survival study pipeline for group COHORT-2026-08-14 (grant budget £125,000.00, contact dana.reyes@example.org, test key sk-test-4f9a2c7e1b8d6a3f5e0c). Summarize the main findings in plain words without sharing any private names or keys.",
  },
  {
    id: "research-agreement",
    label: "Example: a private legal agreement review",
    description:
      "Hides names, firm names, phone numbers, emails, dates, and secret keys before reviewing the draft.",
    prompt:
      "Review our draft acquisition agreement for Priya Natarajan at Halden & Moss LLP dated 2026-05-10 (budget £125,000.00, contact priya.natarajan@example.org, phone +44 7911 123456, test key sk-test-4f9a2c7e1b8d6a3f5e0c). List any missing safety rules in plain words before we sign.",
  },
] as const;

export const DEFAULT_PLAIN_TASK_PROMPT = EXAMPLE_AGENT_TASKS[0].prompt;

export interface ArgonPlannerInfo {
  provider: string;
  model: string;
}

export type ArcAnchorResult =
  | {
      broadcast: true;
      txHash: string;
      explorerUrl: string;
      receiptHash: string;
    }
  | { broadcast: false; reason: string };

/**
 * Honest plain-language planner line:
 * - "Planner unavailable (no Gemini key is set)" when planner is unavailable
 * - "Planned by Gemini 4 Argon" when Gemini 4 Argon did the planning
 * - "Planned by <model> because the Gemini call failed" when a Gemini call was attempted and failed
 * - "Planned by <model> because no Gemini key is set" when no Gemini key was configured
 */
export function resolvePlannerModeBadgeText(params: {
  planner?: ArgonPlannerInfo | null;
  plannerStatus?: "ok" | "unavailable";
  mode?: string;
  liveGeminiReached?: boolean;
  attemptedLiveCall?: boolean;
  enclaveModel?: string;
}): string {
  const {
    planner,
    plannerStatus,
    mode,
    liveGeminiReached,
    attemptedLiveCall = false,
    enclaveModel,
  } = params;

  if (
    plannerStatus === "unavailable" ||
    mode === "planner-unavailable" ||
    planner?.model === "unavailable" ||
    planner?.provider === "unavailable"
  ) {
    if (attemptedLiveCall) {
      return "Planner unavailable (the Gemini call failed)";
    }
    return "Planner unavailable (no Gemini key is set)";
  }

  if (planner && typeof planner.model === "string" && planner.model.trim()) {
    const provider = (planner.provider ?? "").toLowerCase();
    const model = planner.model.trim();
    if (
      provider.includes("google") ||
      provider.includes("gemini") ||
      provider.includes("confidential-space") ||
      model === GEMINI_4_ARGON_MODEL_ID
    ) {
      return "Planned by Gemini 4 Argon";
    }
    if (attemptedLiveCall && !liveGeminiReached) {
      return `Planned by ${model} because the Gemini call failed`;
    }
    return `Planned by ${model} because no Gemini key is set`;
  }

  if (mode === "live" || liveGeminiReached) {
    return "Planned by Gemini 4 Argon";
  }

  const fallbackModel = enclaveModel?.trim() || "gemma4-31b";
  if (attemptedLiveCall && !liveGeminiReached) {
    return `Planned by ${fallbackModel} because the Gemini call failed`;
  }
  return `Planned by ${fallbackModel} because no Gemini key is set`;
}

export function resolvePlannerSubtitleText(params: {
  isLiveGeminiBadge: boolean;
  plannerUnavailable?: boolean;
  attemptedLiveCall?: boolean;
  liveGeminiReached?: boolean;
  isInitialPreview?: boolean;
  failureReason?: string;
}): string {
  const {
    isLiveGeminiBadge,
    plannerUnavailable = false,
    attemptedLiveCall = false,
    liveGeminiReached = false,
    isInitialPreview = false,
    failureReason,
  } = params;

  if (plannerUnavailable) {
    if (attemptedLiveCall) {
      const cleanedReason = failureReason
        ? sanitizeJargonToPlainWords(
            failureReason
              .replace(/\bAIza[0-9A-Za-z_-]{10,}\b/g, "[hidden key]")
              .replace(/\bsk-[0-9A-Za-z_-]{8,}\b/g, "[hidden key]")
              .replace(/\bghp_[0-9A-Za-z_-]{8,}\b/g, "[hidden key]"),
          )
        : "";
      const reasonClause = cleanedReason ? ` (${cleanedReason})` : "";
      return `We tried to reach Gemini 4 Argon with the configured key, but the Gemini call failed${reasonClause}. No fake plan is ever generated.`;
    }
    return "Our server has no Gemini key set right now and the sealed Google planner is not connected, so the Gemini planner is unavailable. No fake plan is ever generated.";
  }

  if (isLiveGeminiBadge) {
    return "Gemini planned the steps without seeing your words. The sealed computer did the content work after your device hid your personal details.";
  }

  if (attemptedLiveCall && !liveGeminiReached) {
    const cleanedReason = failureReason
      ? sanitizeJargonToPlainWords(
          failureReason
            .replace(/\bAIza[0-9A-Za-z_-]{10,}\b/g, "[hidden key]")
            .replace(/\bsk-[0-9A-Za-z_-]{8,}\b/g, "[hidden key]")
            .replace(/\bghp_[0-9A-Za-z_-]{8,}\b/g, "[hidden key]"),
        )
      : "";
    const reasonClause = cleanedReason ? ` (${cleanedReason})` : "";
    return `We tried to reach Gemini 4 Argon with the provided key, but the Gemini call failed${reasonClause}, so a sealed computer model planned the steps instead.`;
  }

  if (isInitialPreview) {
    return "This initial preview was prepared on your device so no paid call ran on page load. Click Run below to execute your task in the browser.";
  }

  return "Our server has no Gemini key set right now, so a sealed computer model planned the steps instead.";
}

export interface FormattedEgressReceiptDisplay {
  hasReceipt: boolean;
  signer: "sealed-google-computer" | "next-server" | "none";
  signerHeading: string;
  canonicalBytes: string;
  sha256Hex: string;
  signatureHex: string;
  publicKeyHex: string;
  keyId: string;
  epochHourSec: number | null;
  transparencySummary: string | null;
}

/**
 * Formats a `GeminiEgressReceipt` for honest display inside `TechDetails`,
 * distinguishing receipts signed by the sealed Google computer (`egress-signing`)
 * from receipts recorded by our server (`operator-tree-head` transparency log).
 */
export function formatEgressReceiptDisplay(
  receipt: GeminiEgressReceipt | null | undefined,
): FormattedEgressReceiptDisplay {
  if (!receipt) {
    return {
      hasReceipt: false,
      signer: "none",
      signerHeading: "No request was sent to Google (planner unavailable)",
      canonicalBytes: "",
      sha256Hex: "",
      signatureHex: "",
      publicKeyHex: "",
      keyId: "",
      epochHourSec: null,
      transparencySummary: null,
    };
  }

  const tLog = receipt.transparencyLog;
  const transparencySummary = tLog
    ? `leaf #${tLog.leafIndex} (leafHash=0x${tLog.leafHash}, treeSize=${tLog.treeSize}, rootHash=0x${tLog.rootHash})`
    : null;

  if (receipt.signer === "sealed-google-computer") {
    return {
      hasReceipt: true,
      signer: "sealed-google-computer",
      signerHeading:
        "Signed by the sealed Google computer (Google Confidential Space egress-signing key)",
      canonicalBytes: receipt.canonicalRequest,
      sha256Hex: receipt.sha256,
      signatureHex: receipt.signature,
      publicKeyHex: receipt.publicKey,
      keyId: receipt.keyId || "egress-signing",
      epochHourSec: receipt.epochHourSec,
      transparencySummary,
    };
  }

  return {
    hasReceipt: true,
    signer: "next-server",
    signerHeading:
      "Recorded by our server (sha256 appended to transparency log, signed by operator tree-head key)",
    canonicalBytes: receipt.canonicalRequest,
    sha256Hex: receipt.sha256,
    signatureHex: receipt.signature,
    publicKeyHex: receipt.publicKey,
    keyId: receipt.keyId || "operator-tree-head",
    epochHourSec: receipt.epochHourSec,
    transparencySummary,
  };
}

const REDACTION_CATEGORY_LABELS: Readonly<
  Record<string, { singular: string; plural: string }>
> = {
  EMAIL: { singular: "email", plural: "emails" },
  SECRET: { singular: "secret key", plural: "secret keys" },
  PHONE: { singular: "phone number", plural: "phone numbers" },
  DATE: { singular: "date", plural: "dates" },
  DIGITS: { singular: "number", plural: "numbers" },
  NAME: { singular: "name", plural: "names" },
  ADDRESS: { singular: "address", plural: "addresses" },
  URL: { singular: "web link", plural: "web links" },
  IP: { singular: "network address", plural: "network addresses" },
  ACCT: { singular: "account number", plural: "account numbers" },
  ENTITY: { singular: "private term", plural: "private terms" },
  ENTROPY: { singular: "random code", plural: "random codes" },
  SYMMETRY: { singular: "shifted code", plural: "shifted codes" },
  ATTESTED_PII: {
    singular: "extra sealed-computer match",
    plural: "extra sealed-computer matches",
  },
};

export function formatPlainRedactionCounts(
  redactionCounts?: Record<string, number> | null,
): string {
  if (!redactionCounts) return "";
  const parts: string[] = [];
  for (const [rawKey, count] of Object.entries(redactionCounts)) {
    const key = rawKey.toUpperCase();
    if (key === "TOTAL" || typeof count !== "number" || count <= 0) {
      continue;
    }
    const label = REDACTION_CATEGORY_LABELS[key] ?? {
      singular: "detail",
      plural: "details",
    };
    parts.push(`${count} ${count === 1 ? label.singular : label.plural}`);
  }
  return parts.join(", ");
}

export function formatPlainStage1Summary(
  stage1: ArgonAutonomousRunResult["stages"]["stage1"],
): string {
  const secondCheckYesNo = stage1.attestedFilter?.verified ? "yes" : "no";
  const breakdown = formatPlainRedactionCounts(stage1.redactionCounts);
  const breakdownClause = breakdown ? ` (${breakdown})` : "";
  const secondCheckSentence = stage1.attestedFilter?.verified
    ? `The second check inside a sealed computer removed ${stage1.attestedFilter.redactionCount} extra items.`
    : "The on-device check handled all hiding before anything left your device.";

  return `${stage1.redactionCount} personal details hidden; second check inside a sealed computer: ${secondCheckYesNo}${breakdownClause}. ${secondCheckSentence} Every message looks the same size from outside.`;
}

export const DEVICE_PREPARATION_PLAIN_SENTENCE =
  "Your task is prepared on your device, and only a short description without your words goes to our server." as const;

export interface PlainDataHandlingView {
  headline: string;
  devicePreparationSentence: string;
  sentToGooglePlain: string;
  googleCanSeePlain: string[];
  googleCannotSeePlain: string[];
  sealedComputerCanSeePlain: string;
}

export function formatPlainDataHandling(
  dataHandling?: DataHandlingStatement | null,
): PlainDataHandlingView {
  const sentRaw =
    dataHandling?.dataSentToGoogle ?? "content-free task descriptor only";
  const sentToGooglePlain =
    sentRaw === "content-free task descriptor only"
      ? "only a short task description prepared on your device, with none of your words (sent to our server to ask Gemini for a plan)"
      : sanitizeJargonToPlainWords(sentRaw);
  return {
    headline: WHAT_GOOGLE_RECEIVED_PROMPT,
    devicePreparationSentence: DEVICE_PREPARATION_PLAIN_SENTENCE,
    sentToGooglePlain,
    googleCanSeePlain: [
      "Task kind (such as review or summarize), estimated word count, count of hidden details, and whether each safety check passed",
      "Tool step status codes, item counts, and numbered placeholders with zero user words",
      "Server network address and server Gemini key",
    ],
    googleCannotSeePlain: [
      "Your prompt words or any sentence you typed",
      "Names, emails, phone numbers, dates, budgets, or secret keys",
      "The answer written by the sealed computer",
      "Your knowledge search questions or your browser address",
    ],
    sealedComputerCanSeePlain:
      "Your task after your device hides personal details, locked so only the sealed computer can open it.",
  };
}

/**
 * Formats the restored client output into a clean, jargon-free plain text result
 * while preserving the restored personal details (names, dates, budgets, emails).
 */
export function formatPlainRestoredOutput(
  rawRestoredOutput: string,
  isLiveRun = true,
): string {
  if (!rawRestoredOutput) return "";
  const prefix = isLiveRun
    ? "Answer from the sealed computer (with your real details put back on your device): "
    : "Restored output on your device: ";

  let cleaned = rawRestoredOutput;
  cleaned = cleaned.replace(/^\[Live Attested Enclave\s+[^\]]*\]\s*/i, prefix);
  cleaned = cleaned.replace(/^\[Simulated Enclave Output\s+[^\]]*\]\s*/i, prefix);
  cleaned = cleaned.replace(
    /\bover\s+server-resolved\s+handle\s+\$INPUT\s*/gi,
    "",
  );
  cleaned = cleaned.replace(/\s*\bVerification Summary\b[\s\S]*$/i, "");

  return sanitizeJargonToPlainWords(cleaned);
}

export interface PlainTimelineStep {
  id:
    | "hiding-details"
    | "checking-seal"
    | "thinking"
    | "waiting-for-you"
    | "done";
  stepNumber: 1 | 2 | 3 | 4 | 5;
  title:
    | "Hiding your details"
    | "Checking the seal"
    | "Thinking"
    | "Waiting for you"
    | "Done";
  passed: boolean;
  statusText: string;
  plainResult: string;
}

export function buildPlainTimelineSteps(params: {
  run: ArgonAutonomousRunResult;
  plannerBadgeText: string;
  arcAnchor?: ArcAnchorResult | null;
  userDeclinedApproval?: boolean;
  hasLiveModelCalls?: boolean;
}): PlainTimelineStep[] {
  const {
    run,
    plannerBadgeText,
    arcAnchor,
    userDeclinedApproval = false,
    hasLiveModelCalls = false,
  } = params;
  const { stage1, stage2, stage3, stage4, stage5, stage6 } = run.stages;
  const isLiveRun =
    Boolean(stage4.liveGeminiCall.liveEndpointReached) || hasLiveModelCalls;
  const isPlannerUnavailable =
    run.mode === "planner-unavailable" ||
    run.plannerStatus === "unavailable" ||
    stage4.plannerStatus === "unavailable";

  // Step 1: Hiding your details
  const step1Passed = stage1.passed;
  const step1Result = step1Passed
    ? formatPlainStage1Summary(stage1)
    : "We found a personal detail that was not hidden, so we stopped before anything left your device.";

  // Step 2: Checking the seal (Stage 2 + Stage 3)
  const checksPassed = stage2.verificationSignal.checksPassed;
  const checksTotal = stage2.verificationSignal.checksTotal;
  const step2Passed = stage2.passed && stage3.passed;
  const firstAttempt = stage3.attempts[0];
  const secondAttempt = stage3.attempts[1];
  const firstModelLabel =
    firstAttempt?.candidateModelId ??
    firstAttempt?.candidateNodeId ??
    "first model";
  const secondModelLabel =
    secondAttempt?.candidateModelId ??
    secondAttempt?.candidateNodeId ??
    "alternate model";
  const selectedModelLabel =
    stage2.selectedEnclaveModel ||
    secondAttempt?.candidateModelId ||
    firstAttempt?.candidateModelId ||
    "sealed computer";
  const firstMissingSeparateRecord = Boolean(
    firstAttempt?.failedInvariants?.includes(
      "ModelEnclaveRecordMissingFromMatrix",
    ),
  );
  const step2Result = !step2Passed
    ? firstMissingSeparateRecord
      ? `No separate seal record was found for ${firstModelLabel} (${checksPassed} of ${checksTotal} safety checks passed), so we refused to send your task without a verified seal.`
      : `The seal check for ${selectedModelLabel} failed (${checksPassed} of ${checksTotal} safety checks passed), so we refused to send your task to that computer.`
    : stage3.failedOver && firstAttempt && secondAttempt
      ? firstMissingSeparateRecord
        ? `No separate seal record was published for the first sealed computer (${firstModelLabel}), so we switched to an alternate sealed computer (${secondModelLabel}) whose seal check passed (${checksPassed} of ${checksTotal} safety checks passed).`
        : `The seal check on the first sealed computer (${firstModelLabel}) failed, so we switched to an alternate sealed computer (${secondModelLabel}) whose seal check passed (${checksPassed} of ${checksTotal} safety checks passed).`
      : `We checked the seal for ${selectedModelLabel} is intact (${checksPassed} of ${checksTotal} safety checks passed) and confirmed the sealed computer software matches the public software log.`;

  // Step 3: Thinking (Stage 4)
  const step3Passed = stage4.passed;
  const plannedByGemini = plannerBadgeText === "Planned by Gemini 4 Argon";
  const plannerPrivacyNote = plannedByGemini
    ? "Gemini planned the steps without seeing your words."
    : "The sealed computer planned the steps itself, so your words never left it.";
  const noAnswerReturned =
    stage4.restoredClientOutput ===
      "The sealed computer did not return an answer" ||
    stage4.enclaveCompletionMasked ===
      "The sealed computer did not return an answer";
  const runKindNote = `${plannerPrivacyNote} The sealed computer finished the work and your device put your real names, dates, and numbers back in place.`;
  const step3Result = isPlannerUnavailable
    ? stage4.liveGeminiCall.attemptedLiveCall
      ? `${plannerBadgeText}. We tried to reach Gemini 4 Argon, but the Gemini call failed, so no fake plan was generated.`
      : `${plannerBadgeText}. The Gemini planner is unavailable right now, so no fake plan was generated.`
    : step3Passed
      ? `${plannerBadgeText}. ${runKindNote}`
      : noAnswerReturned
        ? `${plannerBadgeText}. The sealed computer did not return an answer.`
        : `${plannerBadgeText}. The thinking step could not finish all safety checks.`;

  // Step 4: Waiting for you (Stage 5) - only offered when the run completed successfully
  const runCompletedWork =
    !isPlannerUnavailable &&
    stage1.passed &&
    stage2.passed &&
    stage3.passed &&
    stage4.passed;
  const isGatePending =
    stage5.externalActionStatus === "paused_awaiting_human" ||
    !stage5.approvedByHuman;
  let step4Passed = false;
  let step4StatusText: string;
  let step4Result: string;

  if (!runCompletedWork) {
    step4Passed = false;
    step4StatusText = "Not needed";
    step4Result = isPlannerUnavailable
      ? "Skipped because the Gemini planner could not run the task."
      : "Skipped because the task did not finish.";
  } else if (isGatePending) {
    if (userDeclinedApproval) {
      step4StatusText = "Not recorded";
      step4Result =
        "You chose Not now. Nothing was written to the public receipt book.";
    } else {
      step4StatusText = "Waiting for you";
      step4Result =
        "Paused until you decide below whether to record a receipt in the public receipt book.";
    }
  } else if (arcAnchor?.broadcast) {
    step4Passed = stage5.passed;
    step4StatusText = "Recorded";
    step4Result =
      "You allowed it. A receipt was recorded in the public receipt book.";
  } else {
    step4Passed = stage5.passed;
    step4StatusText = "Allowed";
    const plainReason = arcAnchor?.reason
      ? sanitizeJargonToPlainWords(arcAnchor.reason)
      : "live wallet not configured on this server";
    step4Result = `You allowed it. The public receipt book was not updated on the live network (${plainReason}).`;
  }

  // Step 5: Done (Stage 6)
  const step5Passed = stage6.passed && stage4.passed;
  const plainAnswer = formatPlainRestoredOutput(
    stage4.restoredClientOutput,
    isLiveRun,
  );
  const step5Result = isPlannerUnavailable
    ? "The Gemini planner is unavailable right now, so there is no final result to sign."
    : step5Passed
      ? `${plainAnswer} Your result is signed with a tamper-proof seal so you can verify it anytime.`
      : noAnswerReturned
        ? "The sealed computer did not return an answer, so there is no final result to sign."
        : "The final summary could not be signed.";

  return [
    {
      id: "hiding-details",
      stepNumber: 1,
      title: "Hiding your details",
      passed: step1Passed,
      statusText: step1Passed ? "Complete" : "Stopped",
      plainResult: step1Result,
    },
    {
      id: "checking-seal",
      stepNumber: 2,
      title: "Checking the seal",
      passed: step2Passed,
      statusText: step2Passed ? "Seal intact" : "Failed",
      plainResult: step2Result,
    },
    {
      id: "thinking",
      stepNumber: 3,
      title: "Thinking",
      passed: step3Passed,
      statusText: isPlannerUnavailable
        ? "Unavailable"
        : step3Passed
          ? "Complete"
          : "Failed",
      plainResult: step3Result,
    },
    {
      id: "waiting-for-you",
      stepNumber: 4,
      title: "Waiting for you",
      passed: step4Passed,
      statusText: step4StatusText,
      plainResult: step4Result,
    },
    {
      id: "done",
      stepNumber: 5,
      title: "Done",
      passed: step5Passed,
      statusText: step5Passed ? "Ready" : "Failed",
      plainResult: step5Result,
    },
  ];
}

/**
 * Formats a clean JSON representation of `ArgonAutonomousRunResult` for expert
 * inspection.
 */
export function formatCleanRunJsonForDisplay(
  run: ArgonAutonomousRunResult,
): Record<string, unknown> {
  const { stage1, stage2, stage3, stage4, stage5, stage6 } = run.stages;

  return {
    runId: run.runId,
    timestampIso: run.timestampIso,
    mode: run.mode,
    planner: run.planner,
    plannerStatus: run.plannerStatus,
    plan: run.plan ?? null,
    egressReceipt: run.egressReceipt ?? null,
    canonicalBytesSentToGoogle: run.canonicalBytesSentToGoogle ?? null,
    dataSentToGoogle: run.dataSentToGoogle,
    dataHandling: run.dataHandling,
    taskDescriptor: run.taskDescriptor,
    modelCalls: run.modelCalls,
    overallPassed: run.overallPassed,
    humanGateState: run.humanGateState,
    stages: {
      stage1,
      stage2: {
        stageNumber: stage2.stageNumber,
        stageName: stage2.stageName,
        modelsUsed: stage2.modelsUsed,
        passed: stage2.passed,
        verificationSignal: {
          allSevenChecksPassed: stage2.verificationSignal.allSevenChecksPassed,
          checksPassed: stage2.verificationSignal.checksPassed,
          checksTotal: stage2.verificationSignal.checksTotal,
          formula: stage2.verificationSignal.formula,
        },
        subagents: stage2.subagents,
        sevenChecks: stage2.sevenChecks,
        selectedEnclaveProvider: stage2.selectedEnclaveProvider,
        selectedEnclaveModel: stage2.selectedEnclaveModel,
        selectedEnclaveHost: stage2.selectedEnclaveHost,
        routerHost: stage2.routerHost,
      },
      stage3: {
        stageNumber: stage3.stageNumber,
        stageName: stage3.stageName,
        modelsUsed: stage3.modelsUsed,
        passed: stage3.passed,
        failedOver: stage3.failedOver,
        attempts: stage3.attempts.map((att) => ({
          attemptNumber: att.attemptNumber,
          candidateNodeId: att.candidateNodeId,
          candidateModelId: att.candidateModelId,
          enclaveAttestationVerified: att.enclaveAttestationVerified,
          verifiedHosts: att.verifiedHosts,
          configuredHosts: att.configuredHosts,
          unverifiedHosts: att.unverifiedHosts,
          measurementRegisterCount: att.measurementRegisterCount,
          dmVerityRootHashPresent: att.dmVerityRootHashPresent,
          releaseDigestMatched: att.releaseDigestMatched,
          failedInvariants: att.failedInvariants,
          plaintextLeakMatches: att.plaintextLeakMatches,
          passed: att.passed,
          remediationApplied: att.remediationApplied,
        })),
        enclaveMeasurementReceipt: {
          enclaveHost: stage3.sandboxReceipt.sandboxId,
          dmVerityRootHashHex: stage3.sandboxReceipt.imageMeasurementHex,
          rtmrMeasurementHex: stage3.sandboxReceipt.rtmr3Hex,
        },
        verificationSignal: {
          enclaveAttestationVerified:
            stage3.verificationSignal.enclaveAttestationVerified,
          verifiedHosts: stage3.verificationSignal.verifiedHosts,
          configuredHosts: stage3.verificationSignal.configuredHosts,
          unverifiedHosts: stage3.verificationSignal.unverifiedHosts,
          measurementRegisterCount:
            stage3.verificationSignal.measurementRegisterCount,
          dmVerityRootHashPresent:
            stage3.verificationSignal.dmVerityRootHashPresent,
          releaseDigestMatched: stage3.verificationSignal.releaseDigestMatched,
          formula: stage3.verificationSignal.formula,
        },
      },
      stage4,
      stage5,
      stage6,
    },
  };
}
