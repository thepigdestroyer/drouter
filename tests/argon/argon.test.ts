import fs from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { ATLAS_SEED_DOCS, runAtlasHybridSearch } from "@/lib/atlas";
import {
  HONEST_DATA_HANDLING_STATEMENT,
  runArgonAutonomousWorkflow,
  type TinfoilPlannerClientLike,
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

const BANNED_SCRIPTED_STRINGS = [
  "Riverside",
  "Northvale",
  "ASSAY-774",
  "quarantined",
  "self-heal",
  "faulty computer",
] as const;

function buildMockHealthyAttestation(
  enclaveModel: "gemma4-31b" | "kimi-k3",
) {
  const isKimi = enclaveModel === "kimi-k3";
  const repo = isKimi
    ? "tinfoilsh/confidential-kimi-k3"
    : "tinfoilsh/confidential-gemma4-31b";
  const tag = isKimi ? "v0.0.15" : "v0.0.12";
  const host = isKimi
    ? "kimi-k3-inf14.tinfoil.containers.tinfoil.dev"
    : "gemma4-31b-inf10.tinfoil.containers.tinfoil.dev";
  const dmVerityRootHash = isKimi
    ? "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c"
    : "8b4029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f1a";
  const register0 = `${dmVerityRootHash}980bb51973cdf396404412ebb7c1a7b7`;

  return {
    routerHost: "router-0.tinfoil.sh",
    routerReleaseDigest:
      "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    routerPredicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    fetchedLive: true,
    modelAttestation: {
      modelId: enclaveModel,
      repo,
      tag,
      hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
      tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)" as const,
      configuredHosts: 1,
      verifiedHosts: 1,
      healthyHosts: 1,
      unverifiedHosts: 0,
      enclaveHosts: [
        {
          host,
          hpkeKey:
            "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
          predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
          tlsKeyFp:
            "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
          codeTag: tag,
        },
      ],
      measurementRegisters: [register0],
      vmShape: { cpus: 32, memoryMb: 262144, gpus: 8, disks: 1 },
      dmVerityRootHash,
      kernelHash:
        "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff",
      initrdHash:
        "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e7",
      containerImageDigest: `sha256:${dmVerityRootHash}`,
      weightRepoCommit: `${repo}@${tag}`,
      weightMpkHash: dmVerityRootHash,
      ccGpuFlagsVerified: true,
      releaseUrl: `https://github.com/${repo}/releases/tag/${tag}`,
      sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityRootHash}`,
    },
  };
}

function createEchoPlaceholderTinfoilClient(
  prefixText = "Completed private analysis.",
): TinfoilPlannerClientLike {
  return {
    ready: vi.fn(async () => {}),
    chat: {
      completions: {
        create: vi.fn(async (params: Record<string, unknown>) => {
          const messages = Array.isArray(params.messages)
            ? (params.messages as Array<{ role?: string; content?: string }>)
            : [];
          const userContent =
            messages.find((m) => m.role === "user")?.content ?? "";
          const placeholderMatches = Array.from(
            new Set(
              userContent.match(
                /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\d+\]/g,
              ) ?? [],
            ),
          );
          return {
            id: "chatcmpl-mock-enclave",
            choices: [
              {
                finish_reason: "stop",
                message: {
                  role: "assistant",
                  content: `${prefixText} Verified items: ${placeholderMatches.join(", ")}.`,
                },
              },
            ],
            usage: { prompt_tokens: 120, completion_tokens: 32 },
          };
        }),
      },
    },
  };
}

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
      attestationFetcher: async (m) => buildMockHealthyAttestation(m),
      tinfoilClient: createEchoPlaceholderTinfoilClient(),
    });

    const summaryNo = formatPlainStage1Summary(runNoAttested.stages.stage1);
    expect(summaryNo).toContain(
      `${runNoAttested.stages.stage1.redactionCount} personal details hidden; second check inside a sealed computer: no`,
    );
    expect(findForbiddenPlainTerms(summaryNo)).toEqual([]);

    const runWithAttested = await runArgonAutonomousWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      enableLiveEnclaveInference: true,
      attestationFetcher: async (m) => buildMockHealthyAttestation(m),
      tinfoilClient: createEchoPlaceholderTinfoilClient(),
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

  it("builds 5 plain timeline steps using checksPassed/checksTotal with zero forbidden jargon words and passes all stages for arbitrary tasks", async () => {
    const arbitraryTasks = [
      {
        prompt:
          "Draft a legal memo for Priya Natarajan at Halden & Moss LLP regarding the 2026-05-10 acquisition ($250,000.00, contact priya.natarajan@haldenmoss.example, key sk-live-9a8b7c6d5e4f3a2b1c0d).",
        alwaysHide: ["Halden & Moss LLP"],
        expectedRestored: ["Priya Natarajan", "Halden & Moss LLP", "priya.natarajan@haldenmoss.example"],
      },
      {
        prompt:
          "Review our authentication middleware configured by dev-sec@acme-corp.example using API key sk-proj-8f7e6d5c4b3a2918273645 and token ghp_1234567890abcdefghijklmnopqrstuvwx on 2026-11-01.",
        alwaysHide: [],
        expectedRestored: ["dev-sec@acme-corp.example", "sk-proj-8f7e6d5c4b3a2918273645"],
      },
    ];

    for (const task of arbitraryTasks) {
      const run = await runArgonAutonomousWorkflow({
        taskPrompt: task.prompt,
        alwaysHide: task.alwaysHide,
        thinkingLevel: "medium",
        background: true,
        humanApprovedExternalAction: false,
        preferredEnclaveModel: "gemma4-31b",
        attestationFetcher: async (m) => buildMockHealthyAttestation(m),
        tinfoilClient: createEchoPlaceholderTinfoilClient("Completed review."),
      });

      expect(run.mode).toBe("tinfoil-planner");
      expect(run.overallPassed).toBe(true);
      expect(run.stages.stage1.redactionCount).toBeGreaterThanOrEqual(3);
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
      for (const expStr of task.expectedRestored) {
        expect(plainRestored).toContain(expStr);
      }
      expect(plainRestored).not.toContain("$INPUT");
      expect(plainRestored.toLowerCase()).not.toContain("simulat");
      expect(plainRestored.toLowerCase()).not.toContain("practice");

      const cleanJson = JSON.stringify(formatCleanRunJsonForDisplay(run));
      expect(cleanJson).not.toContain("quorumValidSignatures");
      expect(cleanJson).not.toContain("vmpl0StatesChecked");
      expect(cleanJson).not.toContain("vmpl0All1344Passed");
      expect(cleanJson).not.toContain("sandboxReceipt");
      expect(cleanJson).not.toContain('"simulated"');
      expect(cleanJson).not.toContain("faultInjected");
      expect(cleanJson).not.toContain("selfHealed");
      expect(cleanJson).not.toContain("selfHealingTriggeredAndResolved");
      expect(cleanJson).not.toContain("entropyBitsPerByte");
      expect(cleanJson).not.toContain("repeated16ByteBlocks");
      expect(cleanJson).not.toContain("postPopAllZero");
      expect(cleanJson).not.toContain("zeroizedOnDestroy");

      for (const banned of BANNED_SCRIPTED_STRINGS) {
        expect(cleanJson.toLowerCase()).not.toContain(banned.toLowerCase());
      }
    }
  });

  it("handles model returning nothing and real node verification failover honestly in buildPlainTimelineSteps", async () => {
    // 1. Model returns nothing -> Stage 4 fails honestly with "The sealed computer did not return an answer"
    const noAnswerRun = await runArgonAutonomousWorkflow({
      taskPrompt:
        "Review code for dev@acme.example with key sk-live-9f8e7d6c5b4a3210fedcba98.",
      enableLiveEnclaveInference: false,
      attestationFetcher: async (m) => buildMockHealthyAttestation(m),
    });

    expect(noAnswerRun.stages.stage4.passed).toBe(false);
    expect(noAnswerRun.stages.stage4.restoredClientOutput).toBe(
      "The sealed computer did not return an answer",
    );
    expect(noAnswerRun.overallPassed).toBe(false);

    const noAnswerSteps = buildPlainTimelineSteps({
      run: noAnswerRun,
      plannerBadgeText: "Planned by gemma4-31b because no Gemini key is set",
      arcAnchor: null,
    });
    expect(noAnswerSteps[2].passed).toBe(false);
    expect(noAnswerSteps[2].plainResult).toContain(
      "The sealed computer did not return an answer",
    );
    expect(noAnswerSteps[4].passed).toBe(false);
    expect(noAnswerSteps[4].plainResult).toContain(
      "The sealed computer did not return an answer",
    );

    // 2. Selected node fails real verification -> honest failover message
    const failoverRun = await runArgonAutonomousWorkflow({
      taskPrompt:
        "Draft a legal memo for Priya Natarajan at Halden & Moss LLP.",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      attestationFetcher: async (model) => {
        if (model === "gemma4-31b") {
          const broken = buildMockHealthyAttestation("gemma4-31b");
          return {
            ...broken,
            modelAttestation: {
              ...broken.modelAttestation,
              verifiedHosts: 0,
              unverifiedHosts: 1,
              ccGpuFlagsVerified: false,
              dmVerityRootHash: "",
              measurementRegisters: [],
            },
          };
        }
        return buildMockHealthyAttestation("kimi-k3");
      },
      tinfoilClient: createEchoPlaceholderTinfoilClient("Completed on backup."),
    });

    expect(failoverRun.stages.stage3.failedOver).toBe(true);
    expect(failoverRun.overallPassed).toBe(true);

    const failoverSteps = buildPlainTimelineSteps({
      run: failoverRun,
      plannerBadgeText: "Planned by kimi-k3 because no Gemini key is set",
      arcAnchor: null,
    });
    expect(failoverSteps[1].passed).toBe(true);
    expect(failoverSteps[1].plainResult).toContain(
      "The seal check on the first sealed computer (gemma4-31b) failed, so we switched to an alternate sealed computer (kimi-k3) whose seal check passed",
    );
    expect(findForbiddenPlainTerms(failoverSteps[1].plainResult)).toEqual([]);

    for (const banned of BANNED_SCRIPTED_STRINGS) {
      expect(failoverSteps[1].plainResult.toLowerCase()).not.toContain(
        banned.toLowerCase(),
      );
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
      humanApprovedExternalAction: true,
      preferredEnclaveModel: "kimi-k3",
      attestationFetcher: async (m) => buildMockHealthyAttestation(m),
      tinfoilClient: createEchoPlaceholderTinfoilClient(),
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
      attestationFetcher: async (m) => buildMockHealthyAttestation(m),
      tinfoilClient: createEchoPlaceholderTinfoilClient(),
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

  it("ensures unexpanded JSX outside TechDetails and page/helper copy contain zero forbidden jargon, dRouter, simulated items, or scripted hospital/fault terms", () => {
    const repoRoot = path.resolve(__dirname, "../..");
    const filesToCheck = [
      "src/app/argon/page.tsx",
      "src/components/argon/argon-helpers.ts",
      "src/components/atlas-explorer.tsx",
    ];

    for (const relPath of filesToCheck) {
      const fullSource = fs.readFileSync(path.join(repoRoot, relPath), "utf8");

      // Ensure removed items and scripted terms do not exist anywhere in page/helper source
      expect(fullSource).not.toContain("slash_faulty_node");
      expect(fullSource).not.toContain("pipelineReport");
      expect(fullSource).not.toContain("quorumValidSignatures");
      expect(fullSource).not.toContain("vmpl0StatesChecked");
      expect(fullSource).not.toContain("memory-bus");
      expect(fullSource).not.toContain("unlockVaultWithKeyMaterial");
      for (const banned of BANNED_SCRIPTED_STRINGS) {
        expect(fullSource.toLowerCase()).not.toContain(banned.toLowerCase());
      }

      if (relPath.endsWith(".tsx")) {
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
    }
  });
});
