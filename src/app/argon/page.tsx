"use client";

import React, { useEffect, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
import { AtlasExplorer } from "@/components/atlas-explorer";
import {
  ExhibitSection,
  SpecimenFooter,
  SpecimenHeader,
} from "@/components/specimen-chrome";
import {
  ARGON_TOOLKIT_MANIFEST,
  DEFAULT_TASK_PROMPT,
  DEMO_PERSONA,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  runArgonAutonomousWorkflow,
  validateArgonRequestConfig,
  type ArgonAutonomousRunResult,
  type ArgonThinkingLevel,
  type ArgonValidationResult,
} from "@/lib/gemini";

interface ModelCallRecord {
  model: string;
  purpose: string;
  ok: boolean;
  latencyMs: number;
  inputTokens?: number;
  outputTokens?: number;
  error?: string;
}

interface GeminiRouteResponse {
  ok?: boolean;
  mode?: "live" | "simulated";
  modelCalls?: ModelCallRecord[];
  autonomousRun?: ArgonAutonomousRunResult;
  arcAnchor?: ArcAnchorResult;
}

type ArcAnchorResult =
  | { broadcast: true; txHash: string; explorerUrl: string; receiptHash: string }
  | { broadcast: false; reason: string };

function buildFallbackModelCalls(
  run: ArgonAutonomousRunResult,
  mode: "live" | "simulated",
): ModelCallRecord[] {
  const liveCall = run.stages.stage4.liveGeminiCall;
  const rows: ModelCallRecord[] = [
    {
      model: GEMINI_4_ARGON_MODEL_ID,
      purpose:
        mode === "live"
          ? "Primary reasoning orchestrator (live API)"
          : "Primary reasoning orchestrator (simulated)",
      ok: mode === "live" ? liveCall.liveEndpointReached : true,
      latencyMs: 12,
      error:
        liveCall.attemptedLiveCall && !liveCall.liveEndpointReached
          ? liveCall.fallbackReason
          : undefined,
    },
    {
      model: run.stages.stage1.modelsUsed.join(", "),
      purpose: "Stage 1 local PII scrub and symmetry masking (simulated)",
      ok: run.stages.stage1.passed,
      latencyMs: 6,
    },
  ];

  for (const sub of run.stages.stage2.subagents) {
    rows.push({
      model: sub.model,
      purpose: `${sub.task} (simulated)`,
      ok: sub.passed,
      latencyMs: sub.latencyMs,
    });
  }

  rows.push({
    model: run.stages.stage3.modelsUsed.join(", "),
    purpose: "Stage 3 sandbox policy and bus entropy check (simulated)",
    ok: run.stages.stage3.passed,
    latencyMs: 28,
  });

  rows.push({
    model: run.stages.stage4.routedEnclaveModel,
    purpose: "Stage 4 confidential enclave completion (simulated)",
    ok: run.stages.stage4.passed,
    latencyMs: 42,
  });

  return rows;
}

export default function ArgonShowcasePage() {
  const [taskPrompt, setTaskPrompt] = useState<string>(DEFAULT_TASK_PROMPT);
  const [thinkingLevel, setThinkingLevel] = useState<ArgonThinkingLevel>("high");
  const [backgroundDecode, setBackgroundDecode] = useState<boolean>(true);
  const [enclaveModel, setEnclaveModel] = useState<"gemma4-31b" | "kimi-k3">(
    "gemma4-31b",
  );
  const [injectFault, setInjectFault] = useState<boolean>(true);
  const [humanApproved, setHumanApproved] = useState<boolean>(false);
  const [geminiApiKey, setGeminiApiKey] = useState<string>("");
  const [sdkTab, setSdkTab] = useState<"typescript" | "python" | "payload">(
    "typescript",
  );
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runResult, setRunResult] = useState<ArgonAutonomousRunResult | null>(
    null,
  );
  const [apiMode, setApiMode] = useState<"live" | "simulated">("simulated");
  const [arcAnchor, setArcAnchor] = useState<ArcAnchorResult | null>(null);
  const [apiModelCalls, setApiModelCalls] = useState<ModelCallRecord[] | null>(
    null,
  );
  const [legacyTestResult, setLegacyTestResult] =
    useState<ArgonValidationResult | null>(null);

  useEffect(() => {
    let active = true;
    fetch("/api/gemini")
      .then((res) => (res.ok ? (res.json() as Promise<GeminiRouteResponse>) : null))
      .then(async (data) => {
        if (!active) return;
        if (data?.autonomousRun) {
          setRunResult(data.autonomousRun);
          const resolvedMode =
            data.mode ??
            (data.autonomousRun.stages.stage4.liveGeminiCall.liveEndpointReached
              ? "live"
              : "simulated");
          setApiMode(resolvedMode);
          setApiModelCalls(data.modelCalls ?? null);
          return;
        }
        const fallback = await runArgonAutonomousWorkflow({
          taskPrompt: DEFAULT_TASK_PROMPT,
          thinkingLevel: "high",
          background: true,
          injectFaultToTestSelfHealing: true,
          humanApprovedExternalAction: false,
          preferredEnclaveModel: "gemma4-31b",
        });
        if (active) {
          setRunResult(fallback);
          setApiMode("simulated");
        }
      })
      .catch(async () => {
        const fallback = await runArgonAutonomousWorkflow({
          taskPrompt: DEFAULT_TASK_PROMPT,
          thinkingLevel: "high",
          background: true,
          injectFaultToTestSelfHealing: true,
          humanApprovedExternalAction: false,
          preferredEnclaveModel: "gemma4-31b",
        });
        if (active) {
          setRunResult(fallback);
          setApiMode("simulated");
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleExecuteWorkflow(overrideApproval?: boolean) {
    setIsRunning(true);
    const effectiveApproval =
      overrideApproval !== undefined ? overrideApproval : humanApproved;
    if (overrideApproval !== undefined) {
      setHumanApproved(overrideApproval);
    }

    try {
      const response = await fetch("/api/gemini", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          taskPrompt,
          thinkingLevel,
          background: backgroundDecode,
          injectFaultToTestSelfHealing: injectFault,
          humanApprovedExternalAction: effectiveApproval,
          preferredEnclaveModel: enclaveModel,
          geminiApiKey: geminiApiKey.trim() || undefined,
        }),
      });
      if (response.ok) {
        const data = (await response.json()) as GeminiRouteResponse;
        if (data.autonomousRun) {
          setRunResult(data.autonomousRun);
          const resolvedMode =
            data.mode ??
            (data.autonomousRun.stages.stage4.liveGeminiCall.liveEndpointReached
              ? "live"
              : "simulated");
          setApiMode(resolvedMode);
          setApiModelCalls(data.modelCalls ?? null);
          setArcAnchor(data.arcAnchor ?? null);
          setIsRunning(false);
          return;
        }
      }
    } catch {
      // Fall back to client execution if offline
    }

    const fallbackRun = await runArgonAutonomousWorkflow({
      taskPrompt,
      thinkingLevel,
      background: backgroundDecode,
      injectFaultToTestSelfHealing: injectFault,
      humanApprovedExternalAction: effectiveApproval,
      preferredEnclaveModel: enclaveModel,
      geminiApiKey: geminiApiKey.trim() || undefined,
    });
    setRunResult(fallbackRun);
    setApiMode(
      fallbackRun.stages.stage4.liveGeminiCall.liveEndpointReached
        ? "live"
        : "simulated",
    );
    setApiModelCalls(null);
    setIsRunning(false);
  }

  function handleTestForbiddenParams() {
    const res = validateArgonRequestConfig({
      model: GEMINI_4_ARGON_MODEL_ID,
      thinking_level: thinkingLevel,
      thinking_budget: 16384,
      temperature: 0.7,
      top_p: 0.95,
      top_k: 40,
      cached_content: "cachedContents/legacy-session-123",
    });
    setLegacyTestResult(res);
  }

  const activeConfigValidation = validateArgonRequestConfig({
    model: GEMINI_4_ARGON_MODEL_ID,
    thinking_level: thinkingLevel,
    background: backgroundDecode,
    max_output_tokens: 131_072,
    max_context_tokens: 1_000_000,
    autonomousMultiStep: true,
  });

  const modelCallsList = runResult
    ? (apiModelCalls ?? buildFallbackModelCalls(runResult, apiMode))
    : [];

  const isGatePending =
    runResult?.stages.stage5.externalActionStatus === "paused_awaiting_human";

  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/argon" rightSlot={<AuthPill />} />

      <main className="flex-1 w-full min-w-0">
        <div className="mx-auto w-full max-w-5xl px-4 pt-10 pb-4 sm:px-6 space-y-10">
        {/* 1. Intro & Mode Badge */}
        <header className="space-y-5 border-b border-rule pb-8">
          <div className="ep-label">Gemini 4 Argon agent</div>
          <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
            Confidential research agent with hardware checks and human approval
          </h1>
          <p className="max-w-[70ch] text-base sm:text-lg text-ink-2 leading-relaxed">
            This agent scrubs private identifiers on your device, verifies a
            confidential hardware enclave, routes your task, and pauses before any
            on-chain action until a human approves.
          </p>

          {/* Large Mode Badge */}
          <div className="ep-card p-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              {apiMode === "live" ? (
                <span className="inline-flex items-center rounded-full bg-ink text-paper px-3.5 py-1 font-mono text-xs font-medium tracking-wider uppercase">
                  Live: gemini-4-argon
                </span>
              ) : (
                <span className="inline-flex items-center rounded-full border border-ink text-ink px-3.5 py-1 font-mono text-xs font-medium tracking-wider uppercase">
                  Simulated: no Gemini API key
                </span>
              )}
            </div>
            <p className="text-xs text-ink-2 max-w-[56ch]">
              {apiMode === "live"
                ? "Connected to Google's live Interactions API with local privacy scrubbing and enclave verification."
                : "No GEMINI_API_KEY is configured in production today, so the agent runs in deterministic simulated mode unless you supply a key below."}
            </p>
          </div>

          {/* 2. Persona Card (Example user: Dana Reyes) */}
          <div className="ep-inset p-4 sm:p-5 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="ep-label">Example user</span>
              <span className="ep-muted-chip">Fictional persona</span>
            </div>
            <div className="font-serif text-lg font-medium text-ink">
              {DEMO_PERSONA.name}
            </div>
            <div className="text-xs font-mono text-ink-2">
              {DEMO_PERSONA.role} / {DEMO_PERSONA.institution}
            </div>
            <p className="max-w-[70ch] text-xs sm:text-sm text-ink-2 leading-relaxed">
              <strong className="text-ink font-medium">Task:</strong>{" "}
              {DEMO_PERSONA.assayProtocol}.{" "}
              <strong className="text-ink font-medium">Goal:</strong>{" "}
              {DEMO_PERSONA.confidentialityMandate}
            </p>
          </div>
        </header>

        {/* 3. Task Input & Controls */}
        <section aria-label="Agent controls" className="ep-card p-5 sm:p-6 space-y-5">
          <div className="space-y-2">
            <label htmlFor="argon-task-prompt" className="ep-label block">
              Task prompt (scrubbed locally in Stage 1 before leaving your device)
            </label>
            <textarea
              id="argon-task-prompt"
              rows={4}
              value={taskPrompt}
              onChange={(e) => setTaskPrompt(e.target.value)}
              className="ep-input font-mono text-xs sm:text-sm leading-relaxed"
            />
          </div>

          {/* Controls row */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {/* Thinking level */}
            <div className="space-y-1.5">
              <span className="ep-label block">Thinking level</span>
              <div className="flex gap-1.5" role="group" aria-label="Thinking level">
                {(["low", "medium", "high"] as const).map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setThinkingLevel(lvl)}
                    className={
                      thinkingLevel === lvl
                        ? "ep-btn flex-1 py-1.5 px-2.5 text-xs font-mono uppercase cursor-pointer"
                        : "ep-btn-ghost flex-1 py-1.5 px-2.5 text-xs font-mono uppercase cursor-pointer"
                    }
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            {/* Simulate a compromised node */}
            <div className="space-y-1.5">
              <span className="ep-label block">Simulate a compromised node</span>
              <button
                type="button"
                role="switch"
                aria-checked={injectFault}
                onClick={() => setInjectFault((prev) => !prev)}
                className={
                  injectFault
                    ? "ep-btn w-full py-1.5 px-3 text-xs font-mono cursor-pointer"
                    : "ep-btn-ghost w-full py-1.5 px-3 text-xs font-mono cursor-pointer"
                }
              >
                {injectFault ? "On: inject faulty node" : "Off: clean path"}
              </button>
            </div>

            {/* Enclave model */}
            <div className="space-y-1.5">
              <span className="ep-label block">Enclave model</span>
              <div className="flex gap-1.5" role="group" aria-label="Enclave model">
                {(["gemma4-31b", "kimi-k3"] as const).map((mdl) => (
                  <button
                    key={mdl}
                    type="button"
                    onClick={() => setEnclaveModel(mdl)}
                    className={
                      enclaveModel === mdl
                        ? "ep-btn flex-1 py-1.5 px-2 text-xs font-mono cursor-pointer"
                        : "ep-btn-ghost flex-1 py-1.5 px-2 text-xs font-mono cursor-pointer"
                    }
                  >
                    {mdl}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <p className="text-xs text-ink-3">
            Note: Gemini 4 Argon supports a 1,000,000-token context window. On
            Tinfoil, router-0.tinfoil.sh attests with AMD SEV-SNP, and the Kimi K3
            enclave runs on Intel TDX plus NVIDIA confidential GPUs with a
            262,144-token max context length.
          </p>

          {/* Optional Gemini API key */}
          <details className="ep-inset p-3.5 text-xs">
            <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
              Use your own Gemini key (optional)
            </summary>
            <div className="mt-3 space-y-2">
              <label htmlFor="gemini-api-key-input" className="block text-ink-2">
                Sent to our server for one call. Never stored or logged.
              </label>
              <input
                id="gemini-api-key-input"
                type="password"
                placeholder="AIzaSy..."
                value={geminiApiKey}
                onChange={(e) => setGeminiApiKey(e.target.value)}
                className="ep-input font-mono text-xs"
              />
            </div>
          </details>

          {/* Primary Run button */}
          <div className="pt-1">
            <button
              type="button"
              disabled={isRunning}
              onClick={() => void handleExecuteWorkflow()}
              className="ep-btn w-full sm:w-auto px-6 py-2.5 text-sm cursor-pointer"
            >
              {isRunning ? "Running agent..." : "Run agent"}
            </button>
          </div>
        </section>

        {/* 4. Vertical Timeline of Stages */}
        {runResult ? (
          <section aria-label="Agent execution stages" className="space-y-6">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule pb-3">
              <div>
                <div className="ep-label">Execution trace</div>
                <h2 className="font-serif text-2xl text-ink">
                  Six verification stages
                </h2>
              </div>
              <span className="ep-mono">Run ID: {runResult.runId}</span>
            </div>

            <ol className="relative border-l border-rule-2 ml-3 pl-6 space-y-6">
              {/* Stage 1 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 1: On-device privacy scrub and masking
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: {runResult.stages.stage1.modelsUsed.join(", ")} (Simulated local scrubber)
                    </div>
                  </div>
                  <span
                    className={
                      runResult.stages.stage1.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {runResult.stages.stage1.passed ? "Pass" : "Fail"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  Scrubbed {runResult.stages.stage1.redactionCount} sensitive items
                  (email, API key, cohort ID, grant amount, date) and padded the
                  frame to{" "}
                  {runResult.stages.stage1.verificationSignal.bucketBytes.toLocaleString()}{" "}
                  bytes with {runResult.stages.stage1.verificationSignal.plaintextLeakCount}{" "}
                  plaintext leaks.
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-2 text-ink-2">
                    <div>
                      <span className="text-ink font-medium">
                        Outbound masked prompt:
                      </span>{" "}
                      {runResult.stages.stage1.papillonGeneralizedPrompt}
                    </div>
                    <div>
                      <span className="text-ink font-medium">Formula:</span>{" "}
                      {runResult.stages.stage1.verificationSignal.formula}
                    </div>
                  </div>
                </details>
              </li>

              {/* Stage 2 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 2: Parallel enclave discovery and quorum check
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: {runResult.stages.stage2.modelsUsed.join(", ")} (Simulated subagents)
                    </div>
                  </div>
                  <span
                    className={
                      runResult.stages.stage2.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {runResult.stages.stage2.passed ? "Pass" : "Fail"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  Matched provider {runResult.stages.stage2.selectedEnclaveProvider}{" "}
                  for {runResult.stages.stage2.selectedEnclaveModel} and verified{" "}
                  {runResult.stages.stage2.verificationSignal.quorumValidSignatures} of{" "}
                  7 verifier signatures.
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-2 text-ink-2">
                    {runResult.stages.stage2.subagents.map((sub) => (
                      <div key={sub.subagentId}>
                        <span className="text-ink font-medium">{sub.model}</span> (
                        {sub.latencyMs} ms): {sub.artifactSummary}
                      </div>
                    ))}
                  </div>
                </details>
              </li>

              {/* Stage 3 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 3: Monitor policy and memory-bus check
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: {runResult.stages.stage3.modelsUsed.join(", ")} (Simulated sandbox)
                    </div>
                  </div>
                  <span
                    className={
                      runResult.stages.stage3.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {runResult.stages.stage3.passed
                      ? runResult.stages.stage3.selfHealed
                        ? "Pass (recovered)"
                        : "Pass"
                      : "Fail"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  {runResult.stages.stage3.faultInjected
                    ? `Caught injected plaintext leak and 15 repeated 16-byte blocks on ${runResult.stages.stage3.attempts[0]?.candidateNodeId}, blocked the node, and failed over to a clean node.`
                    : `Verified 1,344 policy states and measured ${runResult.stages.stage3.verificationSignal.entropyBitsPerByte} bits/byte ciphertext entropy with 0 repeated 16-byte blocks.`}
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-2 text-ink-2">
                    {runResult.stages.stage3.attempts.map((att) => (
                      <div
                        key={att.attemptNumber}
                        className="border-b border-rule last:border-b-0 pb-2 last:pb-0"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-ink font-medium">
                            Attempt #{att.attemptNumber}: {att.candidateNodeId}
                          </span>
                          <span className={att.passed ? "ep-pass" : "ep-muted-chip"}>
                            {att.passed ? "Verified" : "Fault caught"}
                          </span>
                        </div>
                        <div className="mt-1">
                          States checked: {att.vmpl0StatesChecked} | Entropy:{" "}
                          {att.entropyBitsPerByte} bits/byte | Repeated 16B
                          blocks: {att.repeated16ByteBlocks}
                        </div>
                        {att.remediationApplied && (
                          <div className="mt-1 text-ink">
                            Remediation: {att.remediationApplied}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </details>
              </li>

              {/* Stage 4 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 4: Gemini 4 Argon synthesis and enclave routing
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: {GEMINI_4_ARGON_MODEL_ID} -&gt;{" "}
                      {runResult.stages.stage4.routedEnclaveModel}
                    </div>
                  </div>
                  <span
                    className={
                      runResult.stages.stage4.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {runResult.stages.stage4.passed ? "Pass" : "Fail"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  Validated Argon config (thinking_level=&quot;
                  {runResult.stages.stage4.thinkingLevel}&quot;, background=
                  {String(runResult.stages.stage4.background)}) and restored
                  original local placeholders on the enclave response.
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-2 text-ink-2">
                    <div>
                      <span className="text-ink font-medium">
                        Masked enclave output:
                      </span>{" "}
                      {runResult.stages.stage4.enclaveCompletionMasked}
                    </div>
                    <div>
                      <span className="text-ink font-medium">
                        Gemini call note:
                      </span>{" "}
                      {runResult.stages.stage4.liveGeminiCall.liveSummaryText ??
                        runResult.stages.stage4.liveGeminiCall.fallbackReason ??
                        "Simulated locally"}
                    </div>
                  </div>
                </details>
              </li>

              {/* Stage 5 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 5: Human approval gate for on-chain actions
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: Human-in-the-loop policy gate (Circle Arc Testnet 5042002)
                    </div>
                  </div>
                  <span className={isGatePending ? "ep-fail" : "ep-pass"}>
                    {isGatePending ? "Waiting for human" : "Approved"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  {isGatePending
                    ? `Paused: holding ${runResult.stages.stage5.pendingActions.length} external Circle Arc action(s) until you explicitly approve below.`
                    : `Human approved: ${runResult.stages.stage5.pendingActions.length} Circle Arc action(s) recorded (Simulated tx hash).`}
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-1.5 text-ink-2">
                    <div>
                      Arc Testnet registry: 0xbc8085c2b6fe6e0db05f169925c0b841828f4481 (chain 5042002)
                    </div>
                    {runResult.stages.stage5.pendingActions.map((act) => (
                      <div key={act.actionId}>
                        {act.kind} ({act.status}): {act.description}
                        {act.txHashHex ? ` | Tx: ${act.txHashHex}` : ""}
                      </div>
                    ))}
                  </div>
                </details>
              </li>

              {/* Stage 6 */}
              <li className="relative space-y-2">
                <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full bg-ink border-2 border-paper" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <h3 className="font-serif text-lg font-medium text-ink">
                      Stage 6: Signed audit digest and briefing
                    </h3>
                    <div className="font-mono text-xs text-ink-3">
                      Model: {runResult.stages.stage6.modelsUsed.join(", ")} (Simulated briefing)
                    </div>
                  </div>
                  <span
                    className={
                      runResult.stages.stage6.passed ? "ep-pass" : "ep-fail"
                    }
                  >
                    {runResult.stages.stage6.passed ? "Pass" : "Fail"}
                  </span>
                </div>
                <p className="max-w-[70ch] text-sm text-ink-2">
                  Signed SHA-256 run digest{" "}
                  <code className="font-mono text-xs">
                    0x{runResult.stages.stage6.forensicProofDigestHex.slice(0, 16)}...
                  </code>{" "}
                  with Ed25519.
                </p>
                <details className="text-xs text-ink-3">
                  <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                    Show details
                  </summary>
                  <div className="mt-2 ep-inset p-3 font-mono text-xs space-y-2 text-ink-2">
                    <div className="font-sans text-ink">
                      &ldquo;{runResult.stages.stage6.voiceTranscript}&rdquo;
                    </div>
                    <div className="break-all">
                      Ed25519 signature: 0x{runResult.stages.stage6.ed25519SignatureHex}
                    </div>
                  </div>
                </details>
              </li>
            </ol>
          </section>
        ) : (
          <div className="ep-card p-6 font-mono text-xs text-ink-2">
            Loading agent trace...
          </div>
        )}

        {/* 5. Human Approval Gate Blocking Card */}
        {runResult && (
          <section
            aria-label="Human approval gate"
            className={`ep-card p-5 sm:p-6 space-y-4 ${
              isGatePending ? "border-accent bg-accent-soft/40" : ""
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="ep-label">Human-in-the-loop gate</div>
                <h2 className="font-serif text-xl sm:text-2xl text-ink">
                  {isGatePending
                    ? "Action required: approve or reject external on-chain actions"
                    : "External actions approved by human"}
                </h2>
              </div>
              <span className={isGatePending ? "ep-fail" : "ep-pass"}>
                {isGatePending ? "Pending approval" : "Approved"}
              </span>
            </div>

            <p className="max-w-[70ch] text-sm text-ink-2">
              The agent cannot anchor receipts or submit slash reports to Circle
              Arc Testnet (registry{" "}
              <code className="font-mono text-xs break-all">
                0xbc8085c2b6fe6e0db05f169925c0b841828f4481
              </code>
              , chain 5042002) without your confirmation.
            </p>

            <ul className="space-y-2 text-xs">
              {runResult.stages.stage5.pendingActions.map((act) => (
                <li key={act.actionId} className="ep-inset p-3 space-y-1">
                  <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                    <span className="text-ink font-medium">{act.kind}</span>
                    <span className="text-ink-3">{act.status}</span>
                  </div>
                  <p className="text-ink-2">{act.description}</p>
                  {act.kind === "anchor_arc_receipt" && arcAnchor?.broadcast ? (
                    <div className="font-mono text-[11px] text-ink-2 break-all">
                      Anchored on Arc testnet:{" "}
                      <a
                        href={arcAnchor.explorerUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link"
                      >
                        {arcAnchor.txHash}
                      </a>
                    </div>
                  ) : act.kind === "anchor_arc_receipt" && arcAnchor && !arcAnchor.broadcast ? (
                    <div className="font-mono text-[11px] text-ink-2">
                      Not anchored: {arcAnchor.reason}
                    </div>
                  ) : (
                    act.txHashHex && (
                      <div className="font-mono text-[11px] text-ink-2 break-all">
                        Simulated Arc tx (not broadcast): {act.txHashHex}
                      </div>
                    )
                  )}
                </li>
              ))}
            </ul>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="button"
                disabled={isRunning}
                onClick={() => void handleExecuteWorkflow(true)}
                className="ep-btn cursor-pointer"
              >
                Approve
              </button>
              <button
                type="button"
                disabled={isRunning}
                onClick={() => void handleExecuteWorkflow(false)}
                className="ep-btn-ghost cursor-pointer"
              >
                Reject
              </button>
            </div>
          </section>
        )}

        {/* 6. Final Locally Restored Answer */}
        {runResult && (
          <section
            aria-label="Final locally restored answer"
            className="ep-card p-5 sm:p-6 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="ep-label">Final answer</div>
                <h2 className="font-serif text-xl sm:text-2xl text-ink">
                  Locally restored output
                </h2>
              </div>
              <span className="ep-pass">Placeholders restored on device</span>
            </div>
            <p className="text-xs text-ink-3">
              The enclave returned a masked completion using shifted dates,
              scaled numbers, and placeholders. Your device restored the real
              names and figures locally:
            </p>
            <div className="ep-inset p-4 font-mono text-xs sm:text-sm leading-relaxed text-ink">
              {runResult.stages.stage4.restoredClientOutput}
            </div>
          </section>
        )}

        {/* 7. Compact modelCalls Table */}
        {runResult && (
          <section
            aria-label="Model calls"
            className="ep-card p-5 sm:p-6 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="ep-label">Model telemetry</div>
                <h2 className="font-serif text-xl text-ink">
                  Model calls in this run
                </h2>
              </div>
              <span className="ep-muted-chip">Mode: {apiMode}</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-rule font-mono text-[11px] uppercase text-ink-3">
                    <th className="py-2 pr-3">Model</th>
                    <th className="py-2 pr-3">Purpose</th>
                    <th className="py-2 pr-3">Status</th>
                    <th className="py-2 text-right">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rule font-mono text-xs">
                  {modelCallsList.map((call, idx) => (
                    <tr key={`${call.model}-${idx}`}>
                      <td className="py-2.5 pr-3 text-ink font-medium">
                        {call.model}
                      </td>
                      <td className="py-2.5 pr-3 font-sans text-ink-2">
                        {call.purpose}
                        {call.error ? (
                          <span className="block font-mono text-[11px] text-ink-3">
                            {call.error}
                          </span>
                        ) : null}
                      </td>
                      <td className="py-2.5 pr-3">
                        <span className={call.ok ? "ep-pass" : "ep-fail"}>
                          {call.ok ? "ok" : "error"}
                        </span>
                      </td>
                      <td className="py-2.5 text-right text-ink-2">
                        {call.latencyMs} ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* 8. Developer Details (Collapsed) */}
        <section aria-label="Developer details">
          <details className="ep-card p-5 sm:p-6">
            <summary className="cursor-pointer font-serif text-lg font-medium text-ink select-none">
              Developer details (SDK snippet, parameter rules, and raw JSON)
            </summary>

            <div className="mt-5 space-y-6 border-t border-rule pt-5">
              {/* Interactions SDK snippet */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="ep-label">
                    @google/genai client.interactions.create
                  </div>
                  <div className="flex gap-1.5">
                    {(["typescript", "python", "payload"] as const).map(
                      (tab) => (
                        <button
                          key={tab}
                          type="button"
                          onClick={() => setSdkTab(tab)}
                          className={
                            sdkTab === tab
                              ? "ep-btn py-1 px-2.5 text-xs font-mono uppercase cursor-pointer"
                              : "ep-btn-ghost py-1 px-2.5 text-xs font-mono uppercase cursor-pointer"
                          }
                        >
                          {tab}
                        </button>
                      ),
                    )}
                  </div>
                </div>

                <pre className="ep-inset p-4 overflow-x-auto font-mono text-xs leading-relaxed text-ink">
                  {runResult
                    ? sdkTab === "typescript"
                      ? runResult.stages.stage4.sdkSnippets.typescript
                      : sdkTab === "python"
                        ? runResult.stages.stage4.sdkSnippets.python
                        : JSON.stringify(
                            runResult.stages.stage4.interactionsPayload,
                            null,
                            2,
                          )
                    : "Loading snippet..."}
                </pre>
              </div>

              {/* Argon rule compliance list */}
              <div className="space-y-3">
                <div className="ep-label">Argon parameter validator</div>
                <ul className="ep-inset p-4 space-y-1.5 font-mono text-xs text-ink-2">
                  <li>
                    model: &quot;{activeConfigValidation.normalizedConfig?.model}
                    &quot;
                  </li>
                  <li>
                    thinking_level: &quot;
                    {activeConfigValidation.normalizedConfig?.thinking_level}&quot;
                  </li>
                  <li>
                    background:{" "}
                    {String(activeConfigValidation.normalizedConfig?.background)}
                  </li>
                  <li>implicit_caching: &quot;enabled&quot;</li>
                  <li>
                    Rejected legacy parameters:{" "}
                    {FORBIDDEN_ARGON_PARAMETERS.join(", ")}
                  </li>
                </ul>

                <button
                  type="button"
                  onClick={handleTestForbiddenParams}
                  className="ep-btn-ghost text-xs font-mono cursor-pointer"
                >
                  Test validator with forbidden legacy parameters
                </button>

                {legacyTestResult && (
                  <div className="ep-inset p-3.5 font-mono text-xs text-ink-2 space-y-1">
                    <div className="text-ink font-medium">
                      Valid: {String(legacyTestResult.valid)} | Rejected:{" "}
                      {legacyTestResult.rejectedParameters.join(", ")}
                    </div>
                    <ul className="list-disc pl-4 space-y-0.5">
                      {legacyTestResult.errors.map((err, idx) => (
                        <li key={idx}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Companion toolkit */}
              <div className="space-y-2">
                <div className="ep-label">Model manifest</div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {ARGON_TOOLKIT_MANIFEST.map((item) => (
                    <div
                      key={item.id}
                      className="ep-inset p-3 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-ink font-medium">{item.id}</span>
                        <span className="text-ink-3">{item.trustBoundary}</span>
                      </div>
                      <p className="text-ink-2">{item.role}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw JSON */}
              {runResult && (
                <div className="space-y-2">
                  <div className="ep-label">Raw run JSON</div>
                  <pre className="ep-inset p-4 max-h-80 overflow-auto font-mono text-[11px] text-ink-2">
                    {JSON.stringify(runResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </details>
        </section>

        </div>

        {/* 9. Knowledge search (MongoDB Atlas) */}
        <ExhibitSection
          tag="Retrieval tool"
          title="Knowledge search (MongoDB Atlas)"
          subtitle="Agent retrieval tool for confidential provider specifications and hardware advisories."
        >
          <AtlasExplorer />
        </ExhibitSection>
      </main>

      <SpecimenFooter />
    </div>
  );
}
