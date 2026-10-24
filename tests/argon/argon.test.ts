import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ATLAS_SEED_DOCS, runAtlasHybridSearch } from "@/lib/atlas";
import { runArgonAutonomousWorkflow } from "@/lib/gemini";
import {
  AGENT_INTRO_SENTENCE,
  APPROVAL_CARD_QUESTION,
  buildPlainTimelineSteps,
  DEFAULT_PLAIN_TASK_PROMPT,
  EXAMPLE_AGENT_TASKS,
  findForbiddenPlainTerms,
  formatPlainAtlasResult,
  formatPlainRestoredOutput,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolvePlannerModeBadgeText,
  sanitizeJargonToPlainWords,
} from "@/components/argon/argon-helpers";

describe("deRoute wave 4 Argon & Atlas plain-language helpers", () => {
  it("uses exact required intro sentence, approval question, and 2 plain example tasks with zero forbidden terms", () => {
    expect(AGENT_INTRO_SENTENCE).toBe(
      "Give it a private task. It hides your personal details, checks the sealed computer, does the work, and asks you before it records anything in public.",
    );
    expect(APPROVAL_CARD_QUESTION).toBe(
      "Allow the agent to record a receipt in the public receipt book?",
    );
    expect(EXAMPLE_AGENT_TASKS).toHaveLength(2);
    expect(DEFAULT_PLAIN_TASK_PROMPT).toBe(EXAMPLE_AGENT_TASKS[0].prompt);

    for (const str of [
      AGENT_INTRO_SENTENCE,
      APPROVAL_CARD_QUESTION,
      ...EXAMPLE_AGENT_TASKS.flatMap((t) => [t.label, t.description, t.prompt]),
    ]) {
      expect(findForbiddenPlainTerms(str)).toEqual([]);
      expect(str).not.toContain("dRouter");
      expect(str).not.toMatch(/[\u2013\u2014]/);
    }
  });

  it("formats honest planner line for Gemini 4 Argon and fallback models", () => {
    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "gemini", model: "gemini-4-argon" },
        mode: "live",
      }),
    ).toBe("Planned by Gemini 4 Argon");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "tinfoil", model: "gemma4-31b" },
        mode: "simulated",
      }),
    ).toBe("Planned by gemma4-31b because no Gemini key is set");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "tinfoil", model: "kimi-k3" },
        mode: "simulated",
      }),
    ).toBe("Planned by kimi-k3 because no Gemini key is set");
  });

  it("builds 5 plain timeline steps with zero forbidden jargon words and passes Stage 1 & Stage 4 with both example tasks", async () => {
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

      expect(run.overallPassed).toBe(true);
      expect(run.stages.stage1.redactionCount).toBeGreaterThanOrEqual(5);
      expect(
        run.stages.stage4.verificationSignal.homomorphicRestoreVerified,
      ).toBe(true);

      const plannerBadgeText = resolvePlannerModeBadgeText({
        planner: run.planner,
        mode: run.mode,
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
      expect(steps[1].passed).toBe(true);
      expect(steps[2].passed).toBe(true);
      expect(steps[3].passed).toBe(false); // Waiting for human approval
      expect(steps[4].passed).toBe(true);

      for (const step of steps) {
        expect(findForbiddenPlainTerms(step.title)).toEqual([]);
        expect(findForbiddenPlainTerms(step.statusText)).toEqual([]);
        expect(findForbiddenPlainTerms(step.plainResult)).toEqual([]);
        expect(step.plainResult).not.toContain("dRouter");
        expect(step.plainResult).not.toMatch(/[\u2013\u2014]/);
      }

      const plainRestored = formatPlainRestoredOutput(
        run.stages.stage4.restoredClientOutput,
      );
      expect(findForbiddenPlainTerms(plainRestored)).toEqual([]);
      expect(plainRestored).toContain("Riverside Teaching Hospital");
    }
  });

  it("translates all 16 Atlas seed docs and preset queries into plain words with zero forbidden terms", async () => {
    for (const preset of PLAIN_ATLAS_PRESET_QUERIES) {
      expect(findForbiddenPlainTerms(preset.label)).toEqual([]);
      expect(findForbiddenPlainTerms(preset.query)).toEqual([]);
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
    }

    // Dynamic fallback sanitization
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
    expect(findForbiddenPlainTerms(stepsSkippedBroadcast[3].plainResult)).toEqual(
      [],
    );

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

  it("ensures unexpanded JSX outside TechDetails in src/app/argon/page.tsx and src/components/atlas-explorer.tsx contains zero forbidden jargon or dRouter", () => {
    const repoRoot = path.resolve(__dirname, "../..");
    const filesToCheck = [
      "src/app/argon/page.tsx",
      "src/components/atlas-explorer.tsx",
    ];

    for (const relPath of filesToCheck) {
      const fullSource = fs.readFileSync(path.join(repoRoot, relPath), "utf8");
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
