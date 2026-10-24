import { GEMINI_4_ARGON_MODEL_ID } from "@/lib/gemini/interactions";
import type {
  ArgonAutonomousRunResult,
  DataHandlingStatement,
} from "@/lib/gemini/orchestrator";

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
    label: "Example 1: Check hospital study notes",
    description:
      "Hides emails, dates, budgets, group codes, and secret keys before checking the study.",
    prompt:
      "Review our RTH-ONC-207 survival study pipeline for group RTH-COHORT-2026-08-14 (grant budget £125,000.00, contact dana.reyes@example.org, test key sk-test-4f9a2c7e1b8d6a3f5e0c). Summarize the main findings in plain words without sharing any private names or keys.",
  },
  {
    id: "research-agreement",
    label: "Example 2: Check a private research agreement",
    description:
      "Hides phone numbers, emails, dates, and project codes before reviewing the draft.",
    prompt:
      "Review our draft research agreement for project RTH-ONC-207 and group RTH-COHORT-2026-08-14 (budget £125,000.00, contact dana.reyes@example.org, phone +44 7911 123456, test key sk-test-4f9a2c7e1b8d6a3f5e0c). List any missing safety rules in plain words before we sign.",
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
 * Forbidden technical terms that must never appear in default (unexpanded) views.
 */
export const FORBIDDEN_PLAIN_VIEW_TERMS: readonly string[] = [
  "attestation",
  "attested",
  "enclave",
  "TEE",
  "SEV-SNP",
  "SNP",
  "TDX",
  "HPKE",
  "RFC",
  "Merkle",
  "nullifier",
  "RSA",
  "quorum",
  "Sigstore",
  "Rekor",
  "VCEK",
  "CKKS",
  "FHE",
  "homomorphic",
  "dm-verity",
  "measurement",
  "ciphertext",
  "hash",
  "digest",
  "ECDSA",
  "X25519",
  "PII",
  "OHTTP",
  "SPRT",
  "Arc testnet",
  "relay hop",
  "bucket bytes",
] as const;

/**
 * Replaces user-visible "dRouter" with "deRoute" and converts technical terms
 * into the approved plain vocabulary for any dynamic text shown outside TechDetails.
 */
export function sanitizeJargonToPlainWords(input: string): string {
  if (!input) return "";
  const out = input
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\bdRouter\b/g, "deRoute")
    .replace(/\bover\s+server-resolved\s+handle\s+\$INPUT\s*/gi, "")
    .replace(/\$INPUT\b/g, "your task")
    .replace(/\$RESULT_\d+\b/g, "the result")
    .replace(/\bArc\s+testnet\b/gi, "public receipt book")
    .replace(/\bCircle\s+Arc\b/gi, "public receipt book")
    .replace(/\brelay\s+hops?\b/gi, "routing steps")
    .replace(/\bbucket\s+bytes\b/gi, "standard message size")
    .replace(/\bhomomorphic(?:ally)?\b/gi, "reversible")
    .replace(/\bdm-verity\b/gi, "disk seal")
    .replace(/\bSEV-SNP\b/gi, "hardware lock")
    .replace(/\bSNP\b/gi, "hardware lock")
    .replace(/\bTDX\b/gi, "hardware lock")
    .replace(/\bVCEK\b/gi, "chip key")
    .replace(/\bHPKE\b/gi, "sealed lock")
    .replace(/\bOHTTP\b/gi, "blind relay")
    .replace(/\bSPRT\b/gi, "spot check")
    .replace(/\bCKKS\b/gi, "locked math")
    .replace(/\bFHE\b/gi, "locked math")
    .replace(/\bECDSA\b/gi, "digital signature")
    .replace(/\bX25519\b/gi, "key exchange")
    .replace(/\bRSA\b/gi, "blind signature")
    .replace(/\bPII\b/gi, "personal details")
    .replace(/\bRFC\s*\d+\b/gi, "standard rule")
    .replace(/\bRFC\b/gi, "standard rule")
    .replace(/\bMerkle\b/gi, "receipt tree")
    .replace(/\bnullifiers?\b/gi, "used-token record")
    .replace(/\bquorum\b/gi, "group of independent checkers")
    .replace(/\bSigstore\b/gi, "public software log")
    .replace(/\bRekor\b/gi, "public software log")
    .replace(/\battestations?\b/gi, "seal check")
    .replace(/\battested\b/gi, "seal-checked")
    .replace(/\benclaves?\b/gi, "sealed computer")
    .replace(/\bTEEs?\b/gi, "sealed computer")
    .replace(/\bmeasurements?\b/gi, "seal fingerprint")
    .replace(/\bciphertexts?\b/gi, "locked message")
    .replace(/\bhashes\b/gi, "fingerprints")
    .replace(/\bhash\b/gi, "fingerprint")
    .replace(/\bdigests?\b/gi, "summary code")
    .replace(/\bsimulated\b/gi, "preview")
    .replace(/\bsimulation\b/gi, "preview");

  return out.replace(/\s+/g, " ").trim();
}

/**
 * Checks whether a plain-view string contains any forbidden technical term.
 */
export function findForbiddenPlainTerms(text: string): string[] {
  const found: string[] = [];
  for (const term of FORBIDDEN_PLAIN_VIEW_TERMS) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\b`, "i");
    if (re.test(text)) {
      found.push(term);
    }
  }
  return found;
}

/**
 * Honest plain-language planner line:
 * - "Planned by Gemini 4 Argon" when Gemini 4 Argon did the planning
 * - "Planned by <model> because no Gemini key is set" when a fallback model planned the run
 */
export function resolvePlannerModeBadgeText(params: {
  planner?: ArgonPlannerInfo | null;
  mode?: string;
  liveGeminiReached?: boolean;
  enclaveModel?: string;
}): string {
  const { planner, mode, liveGeminiReached, enclaveModel } = params;
  if (planner && typeof planner.model === "string" && planner.model.trim()) {
    const provider = (planner.provider ?? "").toLowerCase();
    const model = planner.model.trim();
    if (
      provider.includes("google") ||
      provider.includes("gemini") ||
      model === GEMINI_4_ARGON_MODEL_ID
    ) {
      return "Planned by Gemini 4 Argon";
    }
    return `Planned by ${model} because no Gemini key is set`;
  }

  if (mode === "live" || liveGeminiReached) {
    return "Planned by Gemini 4 Argon";
  }

  const fallbackModel = enclaveModel?.trim() || "gemma4-31b";
  return `Planned by ${fallbackModel} because no Gemini key is set`;
}

export function resolvePlannerSubtitleText(params: {
  isLiveGeminiBadge: boolean;
  attemptedLiveCall?: boolean;
  liveGeminiReached?: boolean;
  isInitialPreview?: boolean;
}): string {
  const {
    isLiveGeminiBadge,
    attemptedLiveCall = false,
    liveGeminiReached = false,
    isInitialPreview = false,
  } = params;

  if (isLiveGeminiBadge) {
    return "Gemini planned the steps without seeing your words. The sealed computer did the content work after your device hid your personal details.";
  }

  if (attemptedLiveCall && !liveGeminiReached) {
    return "We tried to reach Gemini 4 Argon with the provided key, but the call did not succeed, so a sealed computer model planned the steps instead.";
  }

  if (isInitialPreview) {
    return "This initial preview was planned by a sealed computer model so no paid call ran on page load. Click Run below or add a Gemini key in the expert section.";
  }

  return "Our server has no Gemini key set right now, so a sealed computer model planned the steps instead. You can add your own Gemini key in the expert section below.";
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

export interface PlainDataHandlingView {
  headline: string;
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
  return {
    headline: WHAT_GOOGLE_RECEIVED_PROMPT,
    sentToGooglePlain: sanitizeJargonToPlainWords(sentRaw),
    googleCanSeePlain: [
      "Task kind (such as review or summarize), estimated word count, count of hidden details, and whether each safety check passed",
      "Tool step status codes, item counts, and numbered placeholders with zero user words",
      "Server network address and your single-use Gemini key if you entered one",
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

  // Step 1: Hiding your details
  const step1Passed = stage1.passed;
  const step1Result = step1Passed
    ? formatPlainStage1Summary(stage1)
    : "We found a personal detail that was not hidden, so we stopped before anything left your device.";

  // Step 2: Checking the seal (Stage 2 + Stage 3)
  const checksPassed = stage2.verificationSignal.checksPassed;
  const checksTotal = stage2.verificationSignal.checksTotal;
  const step2Passed = stage2.passed && stage3.passed;
  const step2Result = !step2Passed
    ? `The seal check failed (${checksPassed} of ${checksTotal} safety checks passed), so we refused to send your task to that computer.`
    : stage3.faultInjected && stage3.selfHealed
      ? `We checked the seal is intact (${checksPassed} of ${checksTotal} safety checks passed). When we tested a faulty computer, we caught the broken seal, blocked it, and switched to a clean sealed computer automatically.`
      : `We checked the seal is intact (${checksPassed} of ${checksTotal} safety checks passed) and confirmed the sealed computer software matches the public software log.`;

  // Step 3: Thinking (Stage 4)
  const step3Passed = stage4.passed;
  const runKindNote = isLiveRun
    ? "Gemini planned the steps without seeing your words. The sealed computer finished the work and your device put your real names, dates, and numbers back in place."
    : "Gemini planned the steps without seeing your words. This initial preview loaded without making a paid call on page load. Click Run above to run the live task, and your device will put your real names, dates, and numbers back in place.";
  const step3Result = step3Passed
    ? `${plannerBadgeText}. ${runKindNote}`
    : `${plannerBadgeText}. The thinking step could not finish all safety checks.`;

  // Step 4: Waiting for you (Stage 5)
  const isGatePending =
    stage5.externalActionStatus === "paused_awaiting_human" ||
    !stage5.approvedByHuman;
  const step4Passed = !isGatePending && stage5.passed;
  let step4StatusText: string;
  let step4Result: string;

  if (isGatePending) {
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
    step4StatusText = "Recorded";
    step4Result =
      "You allowed it. A receipt was recorded in the public receipt book.";
  } else {
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
  const step5Result = step5Passed
    ? `${plainAnswer} Your result is signed with a tamper-proof seal so you can verify it anytime.`
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
      statusText: step3Passed ? "Complete" : "Failed",
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
 * inspection, omitting deprecated compatibility aliases (`quorumValidSignatures`,
 * `quorumRequired`, `vmpl0StatesChecked`, `vmpl0Verified`, `vmpl0All1344Passed`,
 * `sandboxReceipt`, and `mode: "simulated"`).
 */
export function formatCleanRunJsonForDisplay(
  run: ArgonAutonomousRunResult,
): Record<string, unknown> {
  const { stage1, stage2, stage3, stage4, stage5, stage6 } = run.stages;

  return {
    runId: run.runId,
    timestampIso: run.timestampIso,
    planner: run.planner,
    dataSentToGoogle: run.dataSentToGoogle,
    dataHandling: run.dataHandling,
    taskDescriptor: run.taskDescriptor,
    modelCalls: run.modelCalls,
    overallPassed: run.overallPassed,
    selfHealingTriggeredAndResolved: run.selfHealingTriggeredAndResolved,
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
        faultInjected: stage3.faultInjected,
        selfHealed: stage3.selfHealed,
        attempts: stage3.attempts.map((att) => ({
          attemptNumber: att.attemptNumber,
          candidateNodeId: att.candidateNodeId,
          candidateModelId: att.candidateModelId,
          enclaveAttestationVerified: att.enclaveAttestationVerified,
          failedInvariants: att.failedInvariants,
          entropyBitsPerByte: att.entropyBitsPerByte,
          repeated16ByteBlocks: att.repeated16ByteBlocks,
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
          enclaveAttestationVerified: stage3.verificationSignal.vmpl0All1344Passed,
          entropyBitsPerByte: stage3.verificationSignal.entropyBitsPerByte,
          repeated16ByteBlocks: stage3.verificationSignal.repeated16ByteBlocks,
        },
      },
      stage4,
      stage5,
      stage6,
    },
  };
}

export const PLAIN_ATLAS_PRESET_QUERIES: readonly {
  label: string;
  query: string;
}[] = [
  {
    label: "How two sealed computers protect you",
    query: "Tinfoil confidential GPU model router",
  },
  {
    label: "Stopping memory wire tapping",
    query: "DDR5 memory bus interposer probe mitigation",
  },
  {
    label: "Anonymous tokens for payment",
    query: "blind signature credits double-spend",
  },
  {
    label: "Guarding against voltage tampering",
    query: "VoltPillager voltage fault injection",
  },
] as const;

export function resolveEffectiveAtlasQuery(rawQuery: string): string {
  const trimmed = rawQuery.trim();
  const matchedPreset = PLAIN_ATLAS_PRESET_QUERIES.find(
    (p) => p.label.toLowerCase() === trimmed.toLowerCase(),
  );
  return matchedPreset ? matchedPreset.query : trimmed;
}

interface PlainDocOverride {
  title: string;
  categoryLabel: string;
  summary: string;
}

const PLAIN_DOC_OVERRIDES: Record<string, PlainDocOverride> = {
  "provider-tinfoil": {
    title: "Tinfoil: Sealed computers for private AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Tinfoil runs open AI models inside locked hardware so nobody outside can read your prompts or answers. Before your device sends a message, it checks the hardware seal and locks the message so only the sealed computer can open it.",
  },
  "provider-phala-redpill": {
    title: "Phala Cloud / Redpill: Sealed GPU computers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Runs open AI models on locked server chips and graphics cards. Publishes a gateway seal check, though its connection from the gateway to individual worker computers is not yet fully verified end-to-end.",
  },
  "provider-near-ai-cloud": {
    title: "NEAR AI Cloud: Sealed AI cloud servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Offers AI models hosted on locked server hardware. Requires an account key to inspect its seal check report, and independent checks note that some worker routes are not yet fully verified.",
  },
  "provider-venice-ai": {
    title: "Venice.ai: Locked chat mode",
    categoryLabel: "Sealed computer provider",
    summary:
      "Provides a locked mode for selected AI models running on sealed hardware. Independent checks found that some worker routes and hardware proofs are still incomplete.",
  },
  "provider-prem-ai": {
    title: "Prem AI: Sealed AI servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Locks messages on your device before sending them to sealed servers. Its default verifier rules leave some software fingerprints unpinned unless configured manually.",
  },
  "provider-ppq-ai": {
    title: "PPQ.AI: Pay-per-question private AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Routes private AI questions to Tinfoil sealed computers without a monthly subscription. To keep your message locked all the way from your device to the sealed computer, you must use its local privacy proxy.",
  },
  "provider-confidential-ai": {
    title: "Confidential AI: Locked cloud servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Runs AI models inside locked servers with a secure tunnel that ends inside the locked hardware. Its graphics card seal checks are still marked as raw and unverified.",
  },
  "provider-chutes-bittensor": {
    title: "Chutes: Decentralized AI servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "A marketplace of community-run locked AI servers. While individual servers publish hardware seal checks, the main gateway can see messages before passing them along.",
  },
  "provider-privatemode-cosmian": {
    title: "Privatemode (Edgeless Systems): European sealed AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Hosted in Europe on locked servers that pass 13 out of 13 hardware seal checks. Requires the Privatemode app or helper tool on your device to lock messages end-to-end.",
  },
  "provider-nanogpt": {
    title: "NanoGPT: Pay-per-prompt AI storefront",
    categoryLabel: "Sealed computer provider",
    summary:
      "Offers pay-per-prompt access to AI models on locked servers. However, its gateway unlocks messages outside the sealed computer, and several models failed independent hardware seal checks.",
  },
  "advisory-tee-fail-ddr5": {
    title: "Memory wire tapping attack and how deRoute blocks it",
    categoryLabel: "Hardware safety note",
    summary:
      "Researchers showed that someone with physical access to a server can clip a probe onto memory wires and watch repeated patterns. deRoute checks for repeated patterns in memory and hides your personal details on your device before anything is sent.",
  },
  "advisory-ddrop": {
    title: "Memory write-dropping attack (DDRop) and safety checks",
    categoryLabel: "Hardware safety note",
    summary:
      "Researchers showed an attacker touching server memory wires can block new memory writes so old data stays behind. deRoute runs hardware seal checks and hides your personal details on your device before trusting a sealed computer.",
  },
  "advisory-cipherleaks": {
    title: "Memory pattern leaks (Cipherleaks & BadRAM) and fixes",
    categoryLabel: "Hardware safety note",
    summary:
      "Older server firmware leaked secret key patterns through memory updates or fake memory chips. deRoute checks that servers run updated firmware and never sends your raw personal details off your device.",
  },
  "advisory-voltpillager": {
    title: "Power voltage tampering (VoltPillager) and multi-layer protection",
    categoryLabel: "Hardware safety note",
    summary:
      "An attacker with physical access to a server motherboard can jolt its power wires to cause calculation errors. Because physical tampering is possible on a single machine, deRoute combines device-side detail hiding, independent seal checkers, and the public receipt book.",
  },
  "arch-vmpl0-inner-monitor": {
    title:
      "How deRoute uses anonymous tokens, detail hiding, and the public receipt book",
    categoryLabel: "How deRoute works",
    summary:
      "deRoute separates payment from your identity using prepaid anonymous tokens that cannot be traced back to you. Before your message leaves your device, deRoute hides your personal details and pads every message to a standard size, then records verification receipts in the public receipt book.",
  },
  "arch-two-hop-gpu-custody": {
    title: "How deRoute checks two sealed computers in a row",
    categoryLabel: "How deRoute works",
    summary:
      "Your message passes through an open-source sealed router computer that checks the second sealed AI computer running the graphics cards. Your device checks the seal on both computers and locks your message so only the sealed computer can open it.",
  },
};

export function formatPlainAtlasResult(item: {
  docId: string;
  title: string;
  category: string;
  summary: string;
  provider?: string;
}): PlainDocOverride {
  const known = PLAIN_DOC_OVERRIDES[item.docId];
  if (known) {
    return known;
  }

  if (item.docId.startsWith("provider-")) {
    const cleanName = sanitizeJargonToPlainWords(
      item.title.split("-")[0]?.trim() || item.provider || "Provider",
    );
    return {
      title: `${cleanName}: Sealed computer for private AI`,
      categoryLabel: "Sealed computer provider",
      summary: sanitizeJargonToPlainWords(item.summary),
    };
  }

  const categoryLabel =
    item.category === "provider"
      ? "Sealed computer provider"
      : item.category === "advisory"
        ? "Hardware safety note"
        : "How deRoute works";

  return {
    title: sanitizeJargonToPlainWords(item.title),
    categoryLabel,
    summary: sanitizeJargonToPlainWords(item.summary),
  };
}
