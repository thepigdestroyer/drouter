import { GEMINI_4_ARGON_MODEL_ID } from "@/lib/gemini/interactions";
import type { ArgonAutonomousRunResult } from "@/lib/gemini/orchestrator";

export const AGENT_INTRO_SENTENCE =
  "Give it a private task. It hides your personal details, checks the sealed computer, does the work, and asks you before it records anything in public." as const;

export const APPROVAL_CARD_QUESTION =
  "Allow the agent to record a receipt in the public receipt book?" as const;

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
  let out = input
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\bdRouter\b/g, "deRoute")
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
    .replace(/\bdigests?\b/gi, "summary code");

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
 * Honest plain-language planner line (Requirement 4):
 * - "Planned by Gemini 4 Argon" when Gemini 4 Argon did the planning
 * - "Planned by <model> because no Gemini key is set" when a fallback model planned the run
 */
export function resolvePlannerModeBadgeText(params: {
  planner?: ArgonPlannerInfo | null;
  mode?: "live" | "simulated";
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

/**
 * Formats the restored client output into a clean, jargon-free plain text result
 * while preserving the restored personal details (names, dates, budgets, emails).
 */
export function formatPlainRestoredOutput(rawRestoredOutput: string): string {
  if (!rawRestoredOutput) return "";
  let cleaned = rawRestoredOutput;

  cleaned = cleaned.replace(
    /^\[Live Attested Enclave\s+[^\]]*\]\s*/i,
    "Live answer from the sealed computer (with your real details put back on your device): ",
  );
  cleaned = cleaned.replace(
    /^\[Simulated Enclave Output\s+[^\]]*\]\s*/i,
    "Practice answer (your real details were put back on your device): ",
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

  // Step 1: Hiding your details
  const step1Passed = stage1.passed;
  const step1Result = step1Passed
    ? `We hid ${stage1.redactionCount} personal details on your device (such as names, emails, dates, budgets, and secret keys) and made your message a standard size so nobody watching the network can guess what is inside.`
    : "We found a personal detail that was not hidden, so we stopped before anything left your device.";

  // Step 2: Checking the seal (Stage 2 + Stage 3)
  const step2Passed = stage2.passed && stage3.passed;
  const step2Result = !step2Passed
    ? "The seal check failed, so we refused to send your task to that computer."
    : stage3.faultInjected && stage3.selfHealed
      ? `We checked the seal is intact with ${stage2.verificationSignal.quorumValidSignatures} of 7 independent checkers. During a practice fault test, we spotted a tampered computer, blocked it, and switched to a clean sealed computer automatically.`
      : `We checked the seal is intact with ${stage2.verificationSignal.quorumValidSignatures} of 7 independent checkers and confirmed the sealed computer follows all 1,344 safety rules.`;

  // Step 3: Thinking (Stage 4)
  const step3Passed = stage4.passed;
  const runKindNote =
    run.mode === "live" || hasLiveModelCalls
      ? "The sealed computer finished the work and your device put your real names, dates, and numbers back in place."
      : "This initial preview used a practice response so no paid call ran on page load. Click Run above to run the live task, and your device will put your real names, dates, and numbers back in place.";
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
      : "practice mode only";
    step4Result = `You allowed it. The public receipt book was not updated on the live network (${plainReason}).`;
  }

  // Step 5: Done (Stage 6)
  const step5Passed = stage6.passed && stage4.passed;
  const plainAnswer = formatPlainRestoredOutput(stage4.restoredClientOutput);
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
      "Researchers showed an attacker touching server memory wires can block new memory writes so old data stays behind. deRoute checks all 1,344 safety rules and requires multiple independent checkers before trusting a sealed computer.",
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
    title: "How deRoute uses anonymous tokens, detail hiding, and the public receipt book",
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
