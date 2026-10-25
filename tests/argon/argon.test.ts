import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ATLAS_SEED_DOCS, runAtlasHybridSearch } from "@/lib/atlas";
import {
  HONEST_DATA_HANDLING_STATEMENT,
  runArgonAutonomousWorkflow,
} from "@/lib/gemini";
import {
  AGENT_INTRO_SENTENCE,
  APPROVAL_CARD_QUESTION,
  buildPlainTimelineSteps,
  DEFAULT_PLAIN_TASK_PROMPT,
  EXAMPLE_AGENT_TASKS,
  findForbiddenPlainTerms,
  formatCleanRunJsonForDisplay,
  formatPlainAtlasResult,
  formatPlainDataHandling,
  formatPlainRedactionCounts,
  formatPlainRestoredOutput,
  formatPlainStage1Summary,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolveEffectiveAtlasQuery,
  resolvePlannerModeBadgeText,
  resolvePlannerSubtitleText,
  sanitizeJargonToPlainWords,
  WHAT_GOOGLE_RECEIVED_PROMPT,
} from "@/components/argon/argon-helpers";

describe("deRoute wave 4/5 Argon & Atlas plain-language helpers", () => {
  it("uses exact required intro sentence, approval question, Google descriptor heading, and 2 plain example tasks with zero forbidden terms", () => {
    expect(AGENT_INTRO_SENTENCE).toBe(
      "Give it a private task. It hides your personal details, checks the sealed computer, does the work, and asks you before it records anything in public.",
    );
    expect(APPROVAL_CARD_QUESTION).toBe(
      "Allow the agent to record a receipt in the public receipt book?",
    );
    expect(WHAT_GOOGLE_RECEIVED_PROMPT).toBe(
      "Gemini planned the steps without seeing your words. What Google received:",
    );
    expect(EXAMPLE_AGENT_TASKS).toHaveLength(2);
    expect(DEFAULT_PLAIN_TASK_PROMPT).toBe(EXAMPLE_AGENT_TASKS[0].prompt);

    const dataHandlingView = formatPlainDataHandling(
      HONEST_DATA_HANDLING_STATEMENT,
    );

    for (const str of [
      AGENT_INTRO_SENTENCE,
      APPROVAL_CARD_QUESTION,
      WHAT_GOOGLE_RECEIVED_PROMPT,
      dataHandlingView.headline,
      dataHandlingView.sentToGooglePlain,
      dataHandlingView.sealedComputerCanSeePlain,
      ...dataHandlingView.googleCanSeePlain,
      ...dataHandlingView.googleCannotSeePlain,
      ...EXAMPLE_AGENT_TASKS.flatMap((t) => [t.label, t.description, t.prompt]),
    ]) {
      expect(findForbiddenPlainTerms(str)).toEqual([]);
      expect(str).not.toContain("dRouter");
      expect(str).not.toMatch(/[\u2013\u2014]/);
      expect(str.toLowerCase()).not.toContain("simulat");
      expect(str.toLowerCase()).not.toContain("practice");
    }
  });

  it("formats honest planner line and subtitle for Gemini 4 Argon, failed user key, initial preview, and fallback models", () => {
    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "gemini", model: "gemini-4-argon" },
        mode: "live",
      }),
    ).toBe("Planned by Gemini 4 Argon");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "tinfoil", model: "gemma4-31b" },
      }),
    ).toBe("Planned by gemma4-31b because no Gemini key is set");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "tinfoil", model: "kimi-k3" },
        mode: "tinfoil-planner",
      }),
    ).toBe("Planned by kimi-k3 because no Gemini key is set");

    const liveSub = resolvePlannerSubtitleText({
      isLiveGeminiBadge: true,
      attemptedLiveCall: true,
      liveGeminiReached: true,
    });
    expect(liveSub).toContain(
      "Gemini planned the steps without seeing your words.",
    );
    expect(findForbiddenPlainTerms(liveSub)).toEqual([]);

    const failedKeySub = resolvePlannerSubtitleText({
      isLiveGeminiBadge: false,
      attemptedLiveCall: true,
      liveGeminiReached: false,
    });
    expect(failedKeySub).toContain("provided key");
    expect(findForbiddenPlainTerms(failedKeySub)).toEqual([]);

    const previewSub = resolvePlannerSubtitleText({
      isLiveGeminiBadge: false,
      attemptedLiveCall: false,
      liveGeminiReached: false,
      isInitialPreview: true,
    });
    expect(previewSub).toContain("initial preview");
    expect(findForbiddenPlainTerms(previewSub)).toEqual([]);
  });

  it("shows stage1.redactionCounts and attestedFilter in plain words ('N personal details hidden; second check inside a sealed computer: yes/no')", async () => {
    const runNoAttested = await runArgonAutonomousWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      enableLiveEnclaveInference: false,
    });

    const summaryNo = formatPlainStage1Summary(runNoAttested.stages.stage1);
    expect(summaryNo).toContain(
      `${runNoAttested.stages.stage1.redactionCount} personal details hidden; second check inside a sealed computer: no`,
    );
    expect(findForbiddenPlainTerms(summaryNo)).toEqual([]);

    const runWithAttested = await runArgonAutonomousWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      enableLiveEnclaveInference: true,
      attestedFilterRunner: async (text) => ({
        text,
        redactionCount: 2,
        model: "pii-filter",
        verified: true,
      }),
    });

    const summaryYes = formatPlainStage1Summary(runWithAttested.stages.stage1);
    expect(summaryYes).toContain(
      `${runWithAttested.stages.stage1.redactionCount} personal details hidden; second check inside a sealed computer: yes`,
    );
    expect(findForbiddenPlainTerms(summaryYes)).toEqual([]);

    const countsStr = formatPlainRedactionCounts(
      runWithAttested.stages.stage1.redactionCounts,
    );
    expect(countsStr).toContain("email");
    expect(countsStr).toContain("secret key");
    expect(findForbiddenPlainTerms(countsStr)).toEqual([]);
  });

  it("builds 5 plain timeline steps using checksPassed/checksTotal with zero forbidden jargon words and passes Stage 1 & Stage 4 with both example tasks", async () => {
    for (const task of EXAMPLE_AGENT_TASKS) {
      const run = await runArgonAutonomousWorkflow({
        taskPrompt: task.prompt,
        thinkingLevel: "medium",
        background: true,
        injectFaultToTestSelfHealing: true,
        humanApprovedExternalAction: false,
        preferredEnclaveModel: "gemma4-31b",
        enableLiveEnclaveInference: false,
      });

      expect(run.mode).toBe("tinfoil-planner");
      expect(run.overallPassed).toBe(true);
      expect(run.stages.stage1.redactionCount).toBeGreaterThanOrEqual(5);
      expect(
        run.stages.stage4.verificationSignal.homomorphicRestoreVerified,
      ).toBe(true);

      const plannerBadgeText = resolvePlannerModeBadgeText({
        planner: run.planner,
      });

      const steps = buildPlainTimelineSteps({
        run,
        plannerBadgeText,
        arcAnchor: null,
      });

      expect(steps.map((s) => s.title)).toEqual([
        "Hiding your details",
        "Checking the seal",
        "Thinking",
        "Waiting for you",
        "Done",
      ]);

      expect(steps[0].passed).toBe(true);
      expect(steps[0].plainResult).toContain(
        `${run.stages.stage1.redactionCount} personal details hidden; second check inside a sealed computer: no`,
      );
      expect(steps[1].passed).toBe(true);
      expect(steps[1].plainResult).toContain(
        `${run.stages.stage2.verificationSignal.checksPassed} of ${run.stages.stage2.verificationSignal.checksTotal} safety checks passed`,
      );
      expect(steps[2].passed).toBe(true);
      // Without a Gemini key the sealed computer plans, so the note must not credit Gemini.
      expect(steps[2].plainResult).toContain(
        steps[2].plainResult.startsWith("Planned by Gemini 4 Argon")
          ? "Gemini planned the steps without seeing your words."
          : "The sealed computer planned the steps itself, so your words never left it.",
      );
      expect(steps[3].passed).toBe(false);
      expect(steps[4].passed).toBe(true);
      expect(steps[4].plainResult).not.toContain("$INPUT");

      for (const step of steps) {
        expect(findForbiddenPlainTerms(step.title)).toEqual([]);
        expect(findForbiddenPlainTerms(step.statusText)).toEqual([]);
        expect(findForbiddenPlainTerms(step.plainResult)).toEqual([]);
        expect(step.plainResult).not.toContain("dRouter");
        expect(step.plainResult).not.toMatch(/[\u2013\u2014]/);
        expect(step.plainResult.toLowerCase()).not.toContain("simulat");
        expect(step.plainResult.toLowerCase()).not.toContain("practice");
      }

      const plainRestored = formatPlainRestoredOutput(
        run.stages.stage4.restoredClientOutput,
        false,
      );
      expect(findForbiddenPlainTerms(plainRestored)).toEqual([]);
      expect(plainRestored).toContain("Riverside Teaching Hospital");
      expect(plainRestored).not.toContain("$INPUT");
      expect(plainRestored.toLowerCase()).not.toContain("simulat");
      expect(plainRestored.toLowerCase()).not.toContain("practice");

      const cleanJson = JSON.stringify(formatCleanRunJsonForDisplay(run));
      expect(cleanJson).not.toContain("quorumValidSignatures");
      expect(cleanJson).not.toContain("vmpl0StatesChecked");
      expect(cleanJson).not.toContain("vmpl0All1344Passed");
      expect(cleanJson).not.toContain("sandboxReceipt");
      expect(cleanJson).not.toContain('"simulated"');
    }
  });

  it("translates all 16 Atlas seed docs and preset queries into plain words with zero forbidden terms", async () => {
    for (const preset of PLAIN_ATLAS_PRESET_QUERIES) {
      expect(findForbiddenPlainTerms(preset.label)).toEqual([]);
      expect(findForbiddenPlainTerms(preset.query)).toEqual([]);
      expect(resolveEffectiveAtlasQuery(preset.label)).toBe(preset.query);
      const res = await runAtlasHybridSearch(preset.query, { limit: 4 });
      expect(res.results.length).toBeGreaterThan(0);
    }

    for (const doc of ATLAS_SEED_DOCS) {
      const plain = formatPlainAtlasResult(doc);
      expect(findForbiddenPlainTerms(plain.title)).toEqual([]);
      expect(findForbiddenPlainTerms(plain.categoryLabel)).toEqual([]);
      expect(findForbiddenPlainTerms(plain.summary)).toEqual([]);
      expect(plain.title).not.toContain("dRouter");
      expect(plain.summary).not.toContain("dRouter");
      expect(plain.summary).not.toMatch(/[\u2013\u2014]/);
      expect(plain.summary).not.toContain("1,344");
    }

    const dynamic = sanitizeJargonToPlainWords(
      "dRouter verifies AMD SEV-SNP and Intel TDX enclave attestation with HPKE RFC 9180, RSA nullifiers, Sigstore Rekor, dm-verity measurement, ciphertext digest, and Arc testnet.",
    );
    expect(findForbiddenPlainTerms(dynamic)).toEqual([]);
    expect(dynamic).toContain("deRoute");
    expect(dynamic).not.toContain("dRouter");
  });

  it("handles Allow (broadcast and fallback) and Not now states in buildPlainTimelineSteps with zero forbidden terms", async () => {
    const approvedRun = await runArgonAutonomousWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[1].prompt,
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: false,
      humanApprovedExternalAction: true,
      preferredEnclaveModel: "kimi-k3",
      enableLiveEnclaveInference: false,
    });

    const stepsBroadcast = buildPlainTimelineSteps({
      run: approvedRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      arcAnchor: {
        broadcast: true,
        txHash: `0x${"ab".repeat(32)}`,
        explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
        receiptHash: `0x${"cd".repeat(32)}`,
      },
      hasLiveModelCalls: true,
    });

    expect(stepsBroadcast[3].title).toBe("Waiting for you");
    expect(stepsBroadcast[3].passed).toBe(true);
    expect(stepsBroadcast[3].statusText).toBe("Recorded");
    expect(stepsBroadcast[3].plainResult).toContain(
      "A receipt was recorded in the public receipt book.",
    );

    for (const s of stepsBroadcast) {
      expect(findForbiddenPlainTerms(s.plainResult)).toEqual([]);
      expect(findForbiddenPlainTerms(s.statusText)).toEqual([]);
    }

    const stepsSkippedBroadcast = buildPlainTimelineSteps({
      run: approvedRun,
      plannerBadgeText: "Planned by kimi-k3 because no Gemini key is set",
      arcAnchor: {
        broadcast: false,
        reason: "Run digest is not a 32-byte hash on Arc testnet.",
      },
    });

    expect(stepsSkippedBroadcast[3].passed).toBe(true);
    expect(
      findForbiddenPlainTerms(stepsSkippedBroadcast[3].plainResult),
    ).toEqual([]);

    const pendingRun = await runArgonAutonomousWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      humanApprovedExternalAction: false,
      enableLiveEnclaveInference: false,
    });

    const stepsNotNow = buildPlainTimelineSteps({
      run: pendingRun,
      plannerBadgeText: "Planned by gemma4-31b because no Gemini key is set",
      userDeclinedApproval: true,
    });

    expect(stepsNotNow[3].passed).toBe(false);
    expect(stepsNotNow[3].statusText).toBe("Not recorded");
    expect(stepsNotNow[3].plainResult).toContain("Not now");
    expect(findForbiddenPlainTerms(stepsNotNow[3].plainResult)).toEqual([]);
  });

  it("ensures unexpanded JSX outside TechDetails in src/app/argon/page.tsx and src/components/atlas-explorer.tsx contains zero forbidden jargon, dRouter, or simulated items", () => {
    const repoRoot = path.resolve(__dirname, "../..");
    const filesToCheck = [
      "src/app/argon/page.tsx",
      "src/components/atlas-explorer.tsx",
    ];

    for (const relPath of filesToCheck) {
      const fullSource = fs.readFileSync(path.join(repoRoot, relPath), "utf8");

      // Ensure removed items and preview backdoor do not exist anywhere in page/component source
      expect(fullSource).not.toContain("slash_faulty_node");
      expect(fullSource).not.toContain("pipelineReport");
      expect(fullSource).not.toContain("quorumValidSignatures");
      expect(fullSource).not.toContain("vmpl0StatesChecked");
      expect(fullSource).not.toContain("memory-bus");
      expect(fullSource).not.toContain("unlockVaultWithKeyMaterial");
      expect(fullSource.toLowerCase()).not.toContain("simulat");
      expect(fullSource.toLowerCase()).not.toContain("practice");

      // Remove TechDetails blocks (<TechDetails ...>...</TechDetails>)
      const withoutTechDetails = fullSource.replace(
        /<TechDetails[\s\S]*?<\/TechDetails>/g,
        "",
      );

      // Extract visible text between JSX tags (>...<)
      const jsxTextNodes = Array.from(
        withoutTechDetails.matchAll(/>([^<>{}]+)</g),
      )
        .map((m) => m[1].trim())
        .filter((t) => t.length > 0);

      for (const textNode of jsxTextNodes) {
        expect(findForbiddenPlainTerms(textNode)).toEqual([]);
        expect(textNode).not.toContain("dRouter");
        expect(textNode).not.toMatch(/[\u2013\u2014]/);
      }
    }
  });
});
