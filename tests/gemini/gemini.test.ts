import { describe, expect, it } from "vitest";
import {
  ARGON_COMPANION_MODELS,
  ARGON_TOOLKIT_MANIFEST,
  buildInteractionsCreatePayload,
  GEMINI_4_ARGON_MODEL_ID,
  generateInteractionsSdkSnippets,
  DEMO_PERSONA,
  runArgonAutonomousWorkflow,
  sanitizeToArgonConfig,
  validateArgonRequestConfig,
} from "@/lib/gemini";

describe("Gemini 4 Argon API Contract & Validator (interactions.ts)", () => {
  it("accepts valid gemini-4-argon configs with thinking_level and background: true", () => {
    const validHigh = validateArgonRequestConfig({
      model: "gemini-4-argon",
      thinking_level: "high",
      background: true,
      max_output_tokens: 131_072,
      max_context_tokens: 1_000_000,
    });

    expect(validHigh.valid).toBe(true);
    expect(validHigh.ok).toBe(true);
    expect(validHigh.errors).toEqual([]);
    expect(validHigh.normalizedConfig).toEqual({
      model: "gemini-4-argon",
      thinking_level: "high",
      background: true,
      max_output_tokens: 131_072,
      max_context_tokens: 1_000_000,
      implicit_caching: "enabled",
    });

    // Long decode (> 65,536 tokens) automatically forces background: true
    const autoBackground = validateArgonRequestConfig({
      model: "gemini-4-argon",
      thinking_level: "medium",
      max_output_tokens: 100_000,
    });
    expect(autoBackground.valid).toBe(true);
    expect(autoBackground.normalizedConfig?.background).toBe(true);
  });

  it("rejects any config containing thinking_budget, temperature, top_p, top_k, or cached_content", () => {
    const forbiddenFields = [
      { key: "thinking_budget", val: 8192 },
      { key: "temperature", val: 0.7 },
      { key: "top_p", val: 0.9 },
      { key: "top_k", val: 40 },
      { key: "cached_content", val: "cachedContents/abc-123" },
    ] as const;

    for (const item of forbiddenFields) {
      const res = validateArgonRequestConfig({
        model: "gemini-4-argon",
        thinking_level: "high",
        background: true,
        [item.key]: item.val,
      });
      expect(res.valid).toBe(false);
      expect(res.rejectedParameters).toContain(item.key);
      expect(res.errors.some((e) => e.includes(item.key))).toBe(true);
    }

    // Also test all 5 forbidden parameters passed simultaneously
    const combined = validateArgonRequestConfig({
      model: "gemini-4-argon",
      thinking_level: "high",
      thinking_budget: 4096,
      temperature: 0.2,
      top_p: 0.95,
      top_k: 20,
      cached_content: "cachedContents/xyz",
    });
    expect(combined.valid).toBe(false);
    expect(combined.rejectedParameters).toEqual([
      "thinking_budget",
      "temperature",
      "top_p",
      "top_k",
      "cached_content",
    ]);
  });

  it("strips forbidden legacy parameters via sanitizeToArgonConfig and builds client.interactions.create payload", () => {
    const sanitized = sanitizeToArgonConfig({
      thinking_level: "high",
      temperature: 0.5,
      thinking_budget: 2048,
      cached_content: "cachedContents/old",
    });

    expect(sanitized.config.model).toBe(GEMINI_4_ARGON_MODEL_ID);
    expect(sanitized.config.thinking_level).toBe("high");
    expect(sanitized.config.background).toBe(true);
    expect(sanitized.strippedFields).toEqual([
      "temperature",
      "thinking_budget",
      "cached_content",
    ]);

    const payload = buildInteractionsCreatePayload({
      scrubbedPrompt: "Audit ASSAY-774 inside attested B200 enclave.",
      thinkingLevel: "high",
      background: true,
    });

    expect(payload.model).toBe("gemini-4-argon");
    expect(payload.thinking_level).toBe("high");
    expect(payload.background).toBe(true);
    expect(payload.subagent_routing.sandbox_verifier).toBe(
      "antigravity-preview-09-2026",
    );
    expect(payload.subagent_routing.fast_swarm).toBe("gemini-3.8-flash");
    expect(payload.subagent_routing.quorum_checker).toBe(
      "gemini-3.5-flash-lite",
    );
    expect(payload.subagent_routing.deep_research).toBe(
      "deep-research-preview-04-2026",
    );
    expect(payload.subagent_routing.live_voice_gate).toBe("gemini-3.8-live");
    expect(payload.subagent_routing.voice_briefing).toBe(
      "gemini-3.8-flash-tts",
    );
    expect(payload.subagent_routing.attested_enclave_model).toBe(
      "gemma-4-31b-it",
    );
    expect(payload.subagent_routing.on_device_filter).toBe("gemma-4-e4b");
    expect(payload.subagent_routing.tinfoil_enclave_target).toBe("gemma4-31b");

    const snippets = generateInteractionsSdkSnippets(payload);
    expect(snippets.typescript).toContain("client.interactions.create");
    expect(snippets.python).toContain("client.interactions.create");
    expect(ARGON_TOOLKIT_MANIFEST.length).toBeGreaterThanOrEqual(8);
    expect(ARGON_COMPANION_MODELS.orchestrator).toBe("gemini-4-argon");
  });
});

describe("Autonomous 6-Stage Orchestrator, Self-Healing & Human-in-the-Loop Gate (orchestrator.ts)", () => {
  it("runs all 6 stages for the demo persona, detects an injected fault, self-heals by re-routing, and passes all verification signals", async () => {
    const result = await runArgonAutonomousWorkflow({
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: true,
      humanApprovedExternalAction: false,
      preferredEnclaveModel: "gemma4-31b",
    });

    expect(result.persona.name).toBe(DEMO_PERSONA.name);
    expect(result.persona.institution).toBe(DEMO_PERSONA.institution);
    expect(result.overallPassed).toBe(true);
    expect(result.selfHealingTriggeredAndResolved).toBe(true);

    // Stage 1: On-Device Privacy Filter
    const { stage1, stage2, stage3, stage4, stage5, stage6 } = result.stages;
    expect(stage1.passed).toBe(true);
    expect(stage1.verificationSignal.plaintextLeakCount).toBe(0);
    expect(stage1.verificationSignal.bucketBytes % 4096).toBe(0);
    expect(stage1.verificationSignal.symmetryHomomorphismVerified).toBe(true);
    expect(stage1.papillonGeneralizedPrompt).not.toContain(
      "sk-test-4f9a2c7e1b8d6a3f5e0c",
    );
    expect(stage1.papillonGeneralizedPrompt).not.toContain(
      "dana.reyes@example.org",
    );

    // Stage 2: Parallel Subagent Swarm
    expect(stage2.passed).toBe(true);
    expect(stage2.verificationSignal.allSevenChecksPassed).toBe(true);
    expect(stage2.sevenChecks).toHaveLength(7);
    expect(stage2.subagents).toHaveLength(3);

    // Stage 3: Antigravity Sandbox Verification Loop with Fault Injection & Self-Healing
    expect(stage3.passed).toBe(true);
    expect(stage3.faultInjected).toBe(true);
    expect(stage3.selfHealed).toBe(true);
    expect(stage3.attempts).toHaveLength(2);
    expect(stage3.attempts[0].passed).toBe(false);
    expect(stage3.attempts[0].candidateNodeId).toBe("node-bad-ecb-leak-01");
    expect(stage3.attempts[0].failedInvariants).toContain("I1_NoPlaintextEgress");
    expect(stage3.attempts[0].repeated16ByteBlocks).toBeGreaterThan(0);

    expect(stage3.attempts[1].passed).toBe(true);
    expect(stage3.attempts[1].candidateNodeId).toBe("tinfoil-b200-cc-prime-02");
    expect(stage3.verificationSignal.vmpl0All1344Passed).toBe(true);
    expect(stage3.verificationSignal.entropyBitsPerByte).toBeGreaterThan(7.5);
    expect(stage3.verificationSignal.repeated16ByteBlocks).toBe(0);

    // Stage 4: Gemini 4 Argon 1M-Context Synthesis & Homomorphic Restoration
    expect(stage4.passed).toBe(true);
    expect(stage4.verificationSignal.argonConfigValid).toBe(true);
    expect(stage4.verificationSignal.homomorphicRestoreVerified).toBe(true);
    expect(stage4.restoredClientOutput).toContain("Riverside Teaching Hospital");
    expect(stage4.restoredClientOutput).toContain("RTH-ONC-207");

    // Stage 5: Human-in-the-Loop Gate (blocked when humanApprovedExternalAction: false)
    expect(stage5.passed).toBe(true);
    expect(stage5.requiresHumanApproval).toBe(true);
    expect(stage5.approvedByHuman).toBe(false);
    expect(stage5.stateChangedOnChain).toBe(false);
    expect(stage5.externalActionStatus).toBe("paused_awaiting_human");
    expect(
      stage5.pendingActions.every((a) => a.status === "blocked_pending_human"),
    ).toBe(true);

    // Stage 6: Multimodal Voice Briefing & Signed Forensic Digest
    expect(stage6.passed).toBe(true);
    expect(stage6.forensicProofDigestHex).toHaveLength(64);
    expect(stage6.verificationSignal.signatureVerified).toBe(true);
  });

  it("permits Circle Arc external state changes when humanApprovedExternalAction is true", async () => {
    const approvedRun = await runArgonAutonomousWorkflow({
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: true,
      humanApprovedExternalAction: true,
      preferredEnclaveModel: "kimi-k3",
    });

    expect(approvedRun.overallPassed).toBe(true);
    expect(approvedRun.humanGateState).toBe("executed_with_human_approval");
    expect(approvedRun.stages.stage5.approvedByHuman).toBe(true);
    expect(approvedRun.stages.stage5.stateChangedOnChain).toBe(true);
    expect(
      approvedRun.stages.stage5.pendingActions.every(
        (a) => a.status === "executed" && typeof a.txHashHex === "string",
      ),
    ).toBe(true);
  });
});
