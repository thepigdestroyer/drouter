import { describe, expect, it, vi } from "vitest";
import {
  ARGON_COMPANION_MODELS,
  ARGON_TOOLKIT_MANIFEST,
  assertOutboundPrivacyInvariant,
  buildInteractionsCreatePayload,
  buildTinfoilOpenAITools,
  callGeminiInteractionsEndpoint,
  callTinfoilPlannerToolLoop,
  GEMINI_4_ARGON_MODEL_ID,
  generateInteractionsSdkSnippets,
  DEMO_PERSONA,
  PrivacyInvariantViolationError,
  runArgonAutonomousWorkflow,
  sanitizeToArgonConfig,
  validateArgonRequestConfig,
  type GenAIInteractionsClientLike,
  type TinfoilPlannerClientLike,
} from "@/lib/gemini";

describe("Gemini 4 Argon API Contract, OpenAI Tool Schema & Privacy Guard (interactions.ts)", () => {
  it("accepts valid gemini-4-argon configs, defaults thinking_level to medium, and forces background: true for long decode", () => {
    const validDefault = validateArgonRequestConfig({
      model: "gemini-4-argon",
      max_output_tokens: 131_072,
      max_context_tokens: 1_000_000,
    });

    expect(validDefault.valid).toBe(true);
    expect(validDefault.ok).toBe(true);
    expect(validDefault.errors).toEqual([]);
    expect(validDefault.normalizedConfig).toEqual({
      model: "gemini-4-argon",
      thinking_level: "medium",
      background: true,
      max_output_tokens: 131_072,
      max_context_tokens: 1_000_000,
      implicit_caching: "enabled",
    });

    const validHigh = validateArgonRequestConfig({
      model: "gemini-4-argon",
      thinking_level: "high",
      background: true,
      max_output_tokens: 131_072,
      max_context_tokens: 1_000_000,
    });
    expect(validHigh.valid).toBe(true);
    expect(validHigh.normalizedConfig?.thinking_level).toBe("high");
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

  it("strips forbidden legacy parameters via sanitizeToArgonConfig, builds OpenAI tool schemas for Tinfoil, and builds client.interactions.create payload", () => {
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
      scrubbedPrompt: "Audit ASSAY-774 inside attested enclave.",
      thinkingLevel: "high",
      background: true,
    });

    expect(payload.model).toBe("gemini-4-argon");
    expect(payload.thinking_level).toBe("high");
    expect(payload.generation_config.thinking_level).toBe("high");
    expect(payload.background).toBe(true);
    expect(payload.tools.every((t) => t.type === "function")).toBe(true);

    const openAiTools = buildTinfoilOpenAITools(payload.tools);
    expect(openAiTools).toHaveLength(payload.tools.length);
    expect(openAiTools[0].type).toBe("function");
    expect(openAiTools[0].function.parameters.type).toBe("object");

    const snippets = generateInteractionsSdkSnippets(payload);
    expect(snippets.typescript).toContain("client.interactions.create");
    expect(snippets.python).toContain("client.interactions.create");

    const notUsedModels = ARGON_TOOLKIT_MANIFEST.filter((m) => m.statusInDemo === "not-used");
    expect(notUsedModels.length).toBeGreaterThanOrEqual(4);
    expect(ARGON_COMPANION_MODELS.orchestrator).toBe("gemini-4-argon");
  });

  it("enforces the Privacy Invariant and aborts both Google and Tinfoil planner SDK calls if any unredacted PII or secret is present", async () => {
    const originals = [
      "sk-test-4f9a2c7e1b8d6a3f5e0c",
      "dana.reyes@example.org",
      "Riverside Teaching Hospital",
    ];

    expect(() =>
      assertOutboundPrivacyInvariant(
        { input: " Safe scrubbed text [SECRET_1] [EMAIL_1] Northvale Institute " },
        originals,
      ),
    ).not.toThrow();

    expect(() =>
      assertOutboundPrivacyInvariant(
        { input: "Leaked credential sk-test-4f9a2c7e1b8d6a3f5e0c in prompt" },
        originals,
      ),
    ).toThrow(PrivacyInvariantViolationError);

    const spyGeminiCreate = vi.fn();
    const mockGeminiClient: GenAIInteractionsClientLike = {
      interactions: { create: spyGeminiCreate },
    };

    const leakyPayload = buildInteractionsCreatePayload({
      scrubbedPrompt: "Contains dana.reyes@example.org by mistake",
      thinkingLevel: "medium",
    });

    await expect(
      callGeminiInteractionsEndpoint({
        payload: leakyPayload,
        sensitiveOriginals: originals,
        genaiClient: mockGeminiClient,
      }),
    ).rejects.toThrow(PrivacyInvariantViolationError);
    expect(spyGeminiCreate).not.toHaveBeenCalled();

    const spyTinfoilCreate = vi.fn();
    const mockTinfoilClient: TinfoilPlannerClientLike = {
      chat: { completions: { create: spyTinfoilCreate } },
    };

    await expect(
      callTinfoilPlannerToolLoop({
        model: "kimi-k3",
        scrubbedPrompt: "Leaked Riverside Teaching Hospital in Tinfoil planner prompt",
        sensitiveOriginals: originals,
        tinfoilClient: mockTinfoilClient,
      }),
    ).rejects.toThrow(PrivacyInvariantViolationError);
    expect(spyTinfoilCreate).not.toHaveBeenCalled();
  });
});

describe("Autonomous 6-Stage Orchestrator: Live Attestation, Real Fault Re-Route, Tinfoil Planner Fallback & Mocked SDKs (orchestrator.ts)", () => {
  it("fetches live Tinfoil attestation, fails a real check on fault injection for gemma4-31b, re-routes to kimi-k3, and blocks unapproved external actions", async () => {
    const result = await runArgonAutonomousWorkflow({
      taskPrompt:
        "Audit our RTH-ONC-207 survival analysis pipeline for cohort RTH-COHORT-2026-08-14 " +
        "(grant budget £125,000.00, contact dana.reyes@example.org, phone +44 7911 123456, SSN 123-45-6789, credential sk-test-4f9a2c7e1b8d6a3f5e0c).",
      thinkingLevel: "medium",
      background: true,
      injectFaultToTestSelfHealing: true,
      humanApprovedExternalAction: false,
      preferredEnclaveModel: "gemma4-31b",
      enableLiveEnclaveInference: false,
    });

    expect(result.mode).toBe("simulated");
    // Because fault was injected on gemma4-31b, self-healing re-routed to kimi-k3
    expect(result.planner).toEqual({
      provider: "tinfoil",
      model: "kimi-k3",
    });
    expect(result.modelCalls).toEqual([]);
    expect(result.persona.name).toBe(DEMO_PERSONA.name);
    expect(result.overallPassed).toBe(true);
    expect(result.selfHealingTriggeredAndResolved).toBe(true);

    // Stage 1: On-Device Privacy Filter & Prompt Pipeline
    const { stage1, stage2, stage3, stage4, stage5, stage6 } = result.stages;
    expect(stage1.passed).toBe(true);
    expect(stage1.verificationSignal.plaintextLeakCount).toBe(0);
    expect(stage1.verificationSignal.bucketBytes % 4096).toBe(0);
    expect(stage1.verificationSignal.symmetryHomomorphismVerified).toBe(true);
    expect(stage1.papillonGeneralizedPrompt).not.toContain("sk-test-4f9a2c7e1b8d6a3f5e0c");
    expect(stage1.papillonGeneralizedPrompt).not.toContain("dana.reyes@example.org");
    expect(stage1.papillonGeneralizedPrompt).not.toContain("+44 7911 123456");
    expect(stage1.papillonGeneralizedPrompt).not.toContain("123-45-6789");
    expect(stage1.papillonGeneralizedPrompt).not.toContain("Riverside Teaching Hospital");

    // Stage 2: Parallel Subagent Swarm with real live Tinfoil enclave hostnames
    expect(stage2.passed).toBe(true);
    expect(stage2.verificationSignal.allSevenChecksPassed).toBe(true);
    expect(stage2.routerHost).toBe("router-0.tinfoil.sh");
    expect(stage2.selectedEnclaveModel).toBe("gemma4-31b");
    expect(stage2.selectedEnclaveHost).toContain("gemma4-31b");

    // Stage 3: Fault injection tampers gemma4-31b, real checks fail, and self-healing re-routes to kimi-k3 and re-verifies
    expect(stage3.passed).toBe(true);
    expect(stage3.faultInjected).toBe(true);
    expect(stage3.selfHealed).toBe(true);
    expect(stage3.attempts).toHaveLength(2);
    expect(stage3.attempts[0].passed).toBe(false);
    expect(stage3.attempts[0].candidateModelId).toBe("gemma4-31b");
    expect(stage3.attempts[0].candidateNodeId).toContain("gemma4-31b");
    expect(stage3.attempts[0].enclaveAttestationVerified).toBe(false);
    expect(stage3.attempts[0].vmpl0Verified).toBe(false);
    expect(stage3.attempts[0].failedInvariants).toContain("I1_NoPlaintextEgress");
    expect(stage3.attempts[0].failedInvariants).toContain("C5_ConfidentialGpuFlagsTampered");
    expect(stage3.attempts[0].failedInvariants).toContain("C7_DmVerityMeasurementTampered");

    expect(stage3.attempts[1].passed).toBe(true);
    expect(stage3.attempts[1].candidateModelId).toBe("kimi-k3");
    expect(stage3.attempts[1].candidateNodeId).toContain("kimi-k3");
    expect(stage3.attempts[1].enclaveAttestationVerified).toBe(true);
    expect(stage3.verificationSignal.vmpl0All1344Passed).toBe(true);
    expect(stage3.verificationSignal.entropyBitsPerByte).toBeGreaterThan(7.5);
    expect(stage3.verificationSignal.repeated16ByteBlocks).toBe(0);

    // Stage 4: Re-routed to kimi-k3 & local homomorphic restoration verified
    expect(stage4.passed).toBe(true);
    expect(stage4.planner).toEqual({ provider: "tinfoil", model: "kimi-k3" });
    expect(stage4.routedEnclaveModel).toBe("kimi-k3");
    expect(stage4.routedEnclaveHost).toContain("kimi-k3");
    expect(stage4.enclaveMaxContextTokens).toBe(262_144);
    expect(stage4.restoredClientOutput).toContain("Riverside Teaching Hospital");
    expect(stage4.restoredClientOutput).toContain("Oncology Trial Unit");
    expect(stage4.restoredClientOutput).toContain("RTH-ONC-207");

    // Stage 5: Human-in-the-Loop Gate blocks external state change
    expect(stage5.passed).toBe(true);
    expect(stage5.requiresHumanApproval).toBe(true);
    expect(stage5.approvedByHuman).toBe(false);
    expect(stage5.stateChangedOnChain).toBe(false);
    expect(stage5.externalActionStatus).toBe("paused_awaiting_human");
    expect(
      stage5.pendingActions.every((a) => a.status === "blocked_pending_human"),
    ).toBe(true);

    // Stage 6: Signed Forensic Digest & computed duration
    expect(stage6.passed).toBe(true);
    expect(stage6.voiceTranscript).toContain("Simulated Mode");
    expect(stage6.forensicProofDigestHex).toHaveLength(64);
    expect(stage6.verificationSignal.signatureVerified).toBe(true);
  });

  it("uses the attested Tinfoil model as autonomous planner in an OpenAI-compatible tool-calling loop when no GEMINI_API_KEY is present", async () => {
    const tinfoilCalls: Array<Record<string, unknown>> = [];
    let turn = 0;

    const mockTinfoilClient: TinfoilPlannerClientLike = {
      ready: vi.fn(async () => {}),
      chat: {
        completions: {
          create: vi.fn(async (params: Record<string, unknown>) => {
            tinfoilCalls.push(params);
            const serialized = JSON.stringify(params);
            // Assert zero raw PII ever reaches Tinfoil planner calls
            expect(serialized).not.toContain("sk-test-4f9a2c7e1b8d6a3f5e0c");
            expect(serialized).not.toContain("dana.reyes@example.org");
            expect(serialized).not.toContain("Riverside Teaching Hospital");
            expect(serialized).not.toContain("RTH-ONC-207");

            turn += 1;
            if (turn === 1) {
              return {
                id: "chatcmpl-tinfoil-turn-1",
                choices: [
                  {
                    finish_reason: "tool_calls",
                    message: {
                      role: "assistant",
                      content: null,
                      tool_calls: [
                        {
                          id: "tc-1",
                          type: "function",
                          function: {
                            name: "scrub_and_symmetry_mask",
                            arguments: JSON.stringify({
                              rawPayload: "scrubbed",
                              bucketQuantumBytes: 4096,
                            }),
                          },
                        },
                        {
                          id: "tc-2",
                          type: "function",
                          function: {
                            name: "verify_two_hop_enclave_and_quorum",
                            arguments: JSON.stringify({
                              providerId: "tinfoil",
                              enclaveModel: "gemma4-31b",
                            }),
                          },
                        },
                        {
                          id: "tc-3",
                          type: "function",
                          function: {
                            name: "search_atlas_hybrid_kb",
                            arguments: JSON.stringify({
                              query: "Tinfoil confidential GPU enclave",
                            }),
                          },
                        },
                        {
                          id: "tc-4",
                          type: "function",
                          function: {
                            name: "run_antigravity_vmpl0_and_memory_audit",
                            arguments: JSON.stringify({
                              candidateNodeId: "gemma4-31b-inf10-0.tinfoil.containers.tinfoil.dev",
                              autoPatchOnFailure: true,
                            }),
                          },
                        },
                        {
                          id: "tc-5",
                          type: "function",
                          function: {
                            name: "anchor_arc_settlement_with_human_gate",
                            arguments: JSON.stringify({
                              actionKind: "anchor_receipt",
                              humanApproved: false,
                            }),
                          },
                        },
                      ],
                    },
                  },
                ],
                usage: { prompt_tokens: 180, completion_tokens: 72 },
              };
            }

            return {
              id: "chatcmpl-tinfoil-turn-2",
              choices: [
                {
                  finish_reason: "stop",
                  message: {
                    role: "assistant",
                    content:
                      "Survival analysis pipeline audit completed for ASSAY-774 at Atlas Cellular Unit, Northvale Institute with all 5 verification tools passing.",
                  },
                },
              ],
              usage: { prompt_tokens: 310, completion_tokens: 36 },
            };
          }),
        },
      },
    };

    const run = await runArgonAutonomousWorkflow({
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: false,
      humanApprovedExternalAction: false,
      preferredEnclaveModel: "gemma4-31b",
      tinfoilClient: mockTinfoilClient,
    });

    // Backward-compatible mode stays "simulated" when Gemini is not called, while planner is Tinfoil
    expect(run.mode).toBe("simulated");
    expect(run.planner).toEqual({
      provider: "tinfoil",
      model: "gemma4-31b",
    });
    expect(run.overallPassed).toBe(true);
    expect(run.modelCalls).toHaveLength(1);
    expect(run.modelCalls[0].model).toBe("gemma4-31b");
    expect(run.modelCalls[0].ok).toBe(true);
    expect(run.stages.stage4.tinfoilPlannerCall?.toolCallsExecuted).toEqual([
      "scrub_and_symmetry_mask",
      "verify_two_hop_enclave_and_quorum",
      "search_atlas_hybrid_kb",
      "run_antigravity_vmpl0_and_memory_audit",
      "anchor_arc_settlement_with_human_gate",
    ]);
    expect(run.stages.stage4.enclaveCompletionMasked).toContain("Live Attested Enclave gemma4-31b");
    expect(run.stages.stage4.restoredClientOutput).toContain("Riverside Teaching Hospital");
    expect(run.stages.stage4.restoredClientOutput).toContain("Oncology Trial Unit");
    expect(run.stages.stage4.restoredClientOutput).toContain("RTH-ONC-207");
    expect(tinfoilCalls).toHaveLength(2);
  });

  it("executes a real multi-turn tool-calling loop with mocked @google/genai client.interactions.create and human approval without leaking any PII", async () => {
    const recordedCalls: Array<Record<string, unknown>> = [];
    let argonTurn = 0;

    const mockGenaiClient: GenAIInteractionsClientLike = {
      interactions: {
        create: vi.fn(async (params: Record<string, unknown>) => {
          recordedCalls.push(params);
          const serialized = JSON.stringify(params);
          // Assert zero PII ever reaches Google SDK
          expect(serialized).not.toContain("sk-test-4f9a2c7e1b8d6a3f5e0c");
          expect(serialized).not.toContain("dana.reyes@example.org");
          expect(serialized).not.toContain("Riverside Teaching Hospital");
          expect(serialized).not.toContain("RTH-ONC-207");

          if (params.model === "gemini-3.8-flash" || params.model === "gemini-3.5-flash-lite") {
            return {
              id: `inter-sub-${String(params.model)}`,
              status: "completed",
              output_text: `Verified subagent summary from ${String(params.model)}.`,
              usage: { total_input_tokens: 48, total_output_tokens: 18 },
            };
          }

          argonTurn += 1;
          if (argonTurn === 1) {
            return {
              id: "inter-argon-turn-1",
              status: "requires_action",
              steps: [
                {
                  type: "function_call",
                  id: "call-1",
                  name: "scrub_and_symmetry_mask",
                  arguments: { rawPayload: "scrubbed", bucketQuantumBytes: 4096 },
                },
                {
                  type: "function_call",
                  id: "call-2",
                  name: "verify_two_hop_enclave_and_quorum",
                  arguments: { providerId: "tinfoil", enclaveModel: "kimi-k3" },
                },
                {
                  type: "function_call",
                  id: "call-3",
                  name: "search_atlas_hybrid_kb",
                  arguments: { query: "Tinfoil Kimi K3 confidential GPU enclave" },
                },
                {
                  type: "function_call",
                  id: "call-4",
                  name: "run_antigravity_vmpl0_and_memory_audit",
                  arguments: {
                    candidateNodeId: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
                    autoPatchOnFailure: true,
                  },
                },
                {
                  type: "function_call",
                  id: "call-5",
                  name: "anchor_arc_settlement_with_human_gate",
                  arguments: { actionKind: "anchor_receipt", humanApproved: true },
                },
              ],
              usage: { total_input_tokens: 210, total_output_tokens: 95 },
            };
          }

          return {
            id: "inter-argon-turn-2",
            status: "completed",
            output_text:
              "All 5 confidential tools executed and verified; human approval confirmed for Circle Arc settlement.",
            usage: { total_input_tokens: 340, total_output_tokens: 64 },
          };
        }),
      },
    };

    const liveRun = await runArgonAutonomousWorkflow({
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: true,
      humanApprovedExternalAction: true,
      preferredEnclaveModel: "kimi-k3",
      genaiClient: mockGenaiClient,
    });

    expect(liveRun.mode).toBe("live");
    expect(liveRun.planner).toEqual({
      provider: "gemini",
      model: "gemini-4-argon",
    });
    expect(liveRun.overallPassed).toBe(true);
    // Because preferredEnclaveModel was kimi-k3 and fault was injected, it re-routed to gemma4-31b
    expect(liveRun.stages.stage4.routedEnclaveModel).toBe("gemma4-31b");
    expect(liveRun.modelCalls).toHaveLength(3);
    expect(liveRun.modelCalls.map((m) => m.model).sort()).toEqual([
      "gemini-3.5-flash-lite",
      "gemini-3.8-flash",
      "gemini-4-argon",
    ]);
    expect(liveRun.stages.stage4.liveGeminiCall.toolCallsExecuted).toEqual([
      "scrub_and_symmetry_mask",
      "verify_two_hop_enclave_and_quorum",
      "search_atlas_hybrid_kb",
      "run_antigravity_vmpl0_and_memory_audit",
      "anchor_arc_settlement_with_human_gate",
    ]);
    expect(liveRun.humanGateState).toBe("executed_with_human_approval");
    expect(liveRun.stages.stage5.approvedByHuman).toBe(true);
    expect(liveRun.stages.stage5.stateChangedOnChain).toBe(true);
    expect(recordedCalls.length).toBe(4);
  });
});
