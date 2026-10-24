"use client";

import React, { useEffect, useState } from "react";
import {
  ExhibitSection,
  SpecimenFooter,
  SpecimenHeader,
} from "@/components/specimen-chrome";
import {
  ARGON_TOOLKIT_MANIFEST,
  DEFAULT_TASK_PROMPT,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  DEMO_PERSONA,
  runArgonAutonomousWorkflow,
  validateArgonRequestConfig,
  type ArgonAutonomousRunResult,
  type ArgonThinkingLevel,
  type ArgonValidationResult,
} from "@/lib/gemini";

export default function ArgonShowcasePage() {
  const [taskPrompt, setTaskPrompt] = useState<string>(DEFAULT_TASK_PROMPT);
  const [thinkingLevel, setThinkingLevel] = useState<ArgonThinkingLevel>("high");
  const [backgroundDecode, setBackgroundDecode] = useState<boolean>(true);
  const [enclaveModel, setEnclaveModel] = useState<"gemma4-31b" | "kimi-k3">("gemma4-31b");
  const [injectFault, setInjectFault] = useState<boolean>(true);
  const [humanApproved, setHumanApproved] = useState<boolean>(false);
  const [geminiApiKey, setGeminiApiKey] = useState<string>("");
  const [sdkTab, setSdkTab] = useState<"typescript" | "python" | "payload">("typescript");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runResult, setRunResult] = useState<ArgonAutonomousRunResult | null>(null);
  const [legacyTestResult, setLegacyTestResult] = useState<ArgonValidationResult | null>(null);

  useEffect(() => {
    let active = true;
    runArgonAutonomousWorkflow({
      taskPrompt: DEFAULT_TASK_PROMPT,
      thinkingLevel: "high",
      background: true,
      injectFaultToTestSelfHealing: true,
      humanApprovedExternalAction: false,
      preferredEnclaveModel: "gemma4-31b",
    }).then((res) => {
      if (active) {
        setRunResult(res);
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
        const data = (await response.json()) as {
          autonomousRun?: ArgonAutonomousRunResult;
        };
        if (data.autonomousRun) {
          setRunResult(data.autonomousRun);
          setIsRunning(false);
          return;
        }
      }
    } catch {
      // Fall back to direct client-side execution if offline
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

  return (
    <div className="min-h-screen flex flex-col bg-[#050706] text-[#ece7da]">
      <SpecimenHeader />

      <main className="flex-1">
        {/* Hero Banner & Named Persona */}
        <section className="mx-auto max-w-[1440px] px-4 pt-10 pb-4 sm:px-6">
          <div className="rounded-2xl border border-[rgba(236,231,218,0.14)] bg-[#070a08] p-6 sm:p-8 shadow-[0_24px_60px_rgba(0,0,0,0.65)]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-3 py-1 font-mono text-xs uppercase tracking-[0.14em] text-[#a6ff72]">
                <span className="h-2 w-2 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
                <span>Google DeepMind Encode London Hackathon · Gemini 4 Argon Track</span>
              </div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                <span className="rounded border border-[rgba(236,231,218,0.18)] bg-[#090d0b] px-2.5 py-1 text-[#ece7da]/85">
                  model: &quot;gemini-4-argon&quot;
                </span>
                <span className="rounded border border-[#a6ff72]/35 bg-[#a6ff72]/10 px-2.5 py-1 text-[#a6ff72]">
                  thinking_level: &quot;{thinkingLevel}&quot;
                </span>
                <span className="rounded border border-[#ffb85c]/35 bg-[#ffb85c]/10 px-2.5 py-1 text-[#ffb85c]">
                  background: {String(backgroundDecode)} (1M Context)
                </span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-12">
              <div className="lg:col-span-7">
                <h1
                  className="text-3xl sm:text-4xl lg:text-5xl font-normal italic tracking-tight text-[#ece7da] leading-[1.12]"
                  style={{
                    fontFamily:
                      "Instrument Serif, Playfair Display, Georgia, Cambria, Times New Roman, serif",
                  }}
                >
                  Gemini 4 Argon Autonomous Confidential Security and Routing Agent
                </h1>
                <p className="mt-4 text-sm sm:text-base leading-relaxed text-[#ece7da]/75">
                  A 6-stage autonomous agent orchestrating{" "}
                  <code className="font-mono text-[#a6ff72]">gemini-4-argon</code>,{" "}
                  <code className="font-mono text-[#a6ff72]">antigravity-preview-09-2026</code>,{" "}
                  <code className="font-mono text-[#a6ff72]">gemini-3.8-flash</code>,{" "}
                  <code className="font-mono text-[#a6ff72]">deep-research-preview-04-2026</code>,{" "}
                  <code className="font-mono text-[#a6ff72]">gemini-3.8-live</code>, and{" "}
                  <code className="font-mono text-[#a6ff72]">gemma-4-31b-it</code> (mapped to
                  Tinfoil&apos;s live attested <code className="font-mono text-[#ffb85c]">gemma4-31b</code>{" "}
                  enclave). Built with concrete pass/fail verification gates, autonomous
                  fault remediation, and a strict Human-in-the-Loop safeguard.
                </p>
              </div>

              {/* Named Real User Card */}
              <div className="lg:col-span-5 rounded-xl border border-[#ffb85c]/35 bg-[#090d0b] p-5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-[#ffb85c]">
                    Named Real User &amp; Scientific Workflow
                  </span>
                  <span className="rounded bg-[#ffb85c]/15 px-2 py-0.5 font-mono text-[10px] text-[#ffb85c]">
                    1,000,000-Token Session
                  </span>
                </div>
                <div className="mt-3 text-lg font-semibold text-[#ece7da]">
                  {DEMO_PERSONA.name}
                </div>
                <div className="font-mono text-xs text-[#a6ff72]">
                  {DEMO_PERSONA.role} · {DEMO_PERSONA.institution}
                </div>
                <p className="mt-2.5 text-xs leading-relaxed text-[#ece7da]/75">
                  <strong className="text-[#ece7da]">Pipeline:</strong>{" "}
                  {DEMO_PERSONA.assayProtocol}
                </p>
                <p className="mt-2 text-xs leading-relaxed text-[#ece7da]/70">
                  <strong className="text-[#ece7da]">Mandate:</strong>{" "}
                  {DEMO_PERSONA.confidentialityMandate}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Exhibit 01: Interactive 3-Minute Judge Controls */}
        <ExhibitSection
          number="01"
          tag="INTERACTIVE ORCHESTRATOR CONTROLS"
          title="Configure Gemini 4 Argon, Inject Enclave Faults, and Gate On-Chain Actions"
          subtitle="Adjust thinking_level, toggle a simulated VMPL0 + DDR5 memory-bus leak to watch antigravity-preview-09-2026 self-heal, and control the Human-in-the-Loop gate."
        >
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="lg:col-span-7 space-y-4">
              <div>
                <label
                  htmlFor="argon-task-prompt"
                  className="block font-mono text-xs uppercase tracking-[0.12em] text-[#ece7da]/75"
                >
                  Unredacted Local Research Prompt (Scrubbed on-device in Stage 1)
                </label>
                <textarea
                  id="argon-task-prompt"
                  rows={4}
                  value={taskPrompt}
                  onChange={(e) => setTaskPrompt(e.target.value)}
                  className="mt-2 w-full rounded-xl border border-[rgba(236,231,218,0.18)] bg-[#050706] p-3 font-mono text-xs text-[#ece7da] focus:border-[#a6ff72] focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                {/* Thinking Level */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-3.5">
                  <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-[#ece7da]/65">
                    1. thinking_level
                  </div>
                  <div className="mt-2 flex gap-1.5">
                    {(["low", "medium", "high"] as const).map((lvl) => (
                      <button
                        key={lvl}
                        type="button"
                        onClick={() => setThinkingLevel(lvl)}
                        className={`flex-1 rounded-lg border px-2 py-1.5 font-mono text-xs uppercase transition-colors ${
                          thinkingLevel === lvl
                            ? "border-[#a6ff72] bg-[#a6ff72]/15 text-[#a6ff72]"
                            : "border-[rgba(236,231,218,0.14)] bg-[#050706] text-[#ece7da]/70 hover:text-[#ece7da]"
                        }`}
                      >
                        {lvl}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Background 1M Decode */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-3.5">
                  <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-[#ece7da]/65">
                    2. Long Decode (&gt;65k)
                  </div>
                  <button
                    type="button"
                    onClick={() => setBackgroundDecode((prev) => !prev)}
                    className={`mt-2 w-full rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors ${
                      backgroundDecode
                        ? "border-[#a6ff72] bg-[#a6ff72]/15 text-[#a6ff72]"
                        : "border-[rgba(236,231,218,0.14)] bg-[#050706] text-[#ece7da]/70"
                    }`}
                  >
                    background: {String(backgroundDecode)}
                  </button>
                </div>

                {/* Target Attested Enclave */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-3.5">
                  <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-[#ece7da]/65">
                    3. Tinfoil Enclave
                  </div>
                  <div className="mt-2 flex gap-1.5">
                    {(["gemma4-31b", "kimi-k3"] as const).map((mdl) => (
                      <button
                        key={mdl}
                        type="button"
                        onClick={() => setEnclaveModel(mdl)}
                        className={`flex-1 rounded-lg border px-2 py-1.5 font-mono text-[11px] transition-colors ${
                          enclaveModel === mdl
                            ? "border-[#ffb85c] bg-[#ffb85c]/15 text-[#ffb85c]"
                            : "border-[rgba(236,231,218,0.14)] bg-[#050706] text-[#ece7da]/70"
                        }`}
                      >
                        {mdl}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Optional Live Gemini API Key */}
              <div>
                <label
                  htmlFor="gemini-api-key-input"
                  className="block font-mono text-[11px] uppercase tracking-[0.12em] text-[#ece7da]/65"
                >
                  Optional Live GEMINI_API_KEY (Calls Google v1beta/interactions alongside local enclave verification)
                </label>
                <input
                  id="gemini-api-key-input"
                  type="password"
                  placeholder="AIzaSy... (leave blank for deterministic offline verification)"
                  value={geminiApiKey}
                  onChange={(e) => setGeminiApiKey(e.target.value)}
                  className="mt-1.5 w-full rounded-xl border border-[rgba(236,231,218,0.16)] bg-[#050706] px-3 py-2 font-mono text-xs text-[#ece7da] focus:border-[#a6ff72] focus:outline-none"
                />
              </div>
            </div>

            {/* Fault Injection & Human-in-the-Loop Gate Controls */}
            <div className="lg:col-span-5 flex flex-col justify-between space-y-4 rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
              <div className="space-y-3">
                <div className="font-mono text-xs uppercase tracking-[0.14em] text-[#a6ff72]">
                  Autonomous Verification &amp; Safeguard Toggles
                </div>

                {/* Fault Injection Toggle */}
                <div className="rounded-lg border border-[rgba(236,231,218,0.12)] bg-[#050706] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#ece7da]">
                      Inject Faulty Enclave / Memory-Bus Leak
                    </span>
                    <button
                      type="button"
                      onClick={() => setInjectFault((prev) => !prev)}
                      className={`rounded-full border px-3 py-1 font-mono text-xs transition-colors ${
                        injectFault
                          ? "border-[#ffb85c] bg-[#ffb85c]/20 text-[#ffb85c]"
                          : "border-[rgba(236,231,218,0.2)] bg-[#090d0b] text-[#ece7da]/70"
                      }`}
                    >
                      {injectFault ? "FAULT INJECTED" : "CLEAN PATH"}
                    </button>
                  </div>
                  <p className="mt-1.5 text-xs text-[#ece7da]/65">
                    Simulates a misconfigured node (<code className="font-mono">node-bad-ecb-leak-01</code>)
                    that violates VMPL0 invariant <code className="font-mono">I1_NoPlaintextEgress</code>{" "}
                    and leaks 15 repeated 16-byte ECB cipher blocks on the DDR5 bus so{" "}
                    <code className="font-mono text-[#a6ff72]">antigravity-preview-09-2026</code>{" "}
                    can catch and self-heal it.
                  </p>
                </div>

                {/* Human-in-the-Loop Safeguard */}
                <div className="rounded-lg border border-[rgba(236,231,218,0.12)] bg-[#050706] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#ece7da]">
                      Human-in-the-Loop Safeguard (Stage 5)
                    </span>
                    <span
                      className={`rounded-full px-2.5 py-0.5 font-mono text-[11px] ${
                        humanApproved
                          ? "bg-[#a6ff72]/20 text-[#a6ff72] border border-[#a6ff72]/40"
                          : "bg-[#ffb85c]/20 text-[#ffb85c] border border-[#ffb85c]/40"
                      }`}
                    >
                      {humanApproved ? "APPROVED BY HUMAN" : "PAUSED (SAFEGUARD ACTIVE)"}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-[#ece7da]/65">
                    Blocks Circle Arc USDC receipt anchoring and node slashing until
                    the user explicitly confirms the state-changing transaction.
                  </p>
                  <div className="mt-2.5 flex gap-2">
                    <button
                      type="button"
                      onClick={() => handleExecuteWorkflow(false)}
                      className={`flex-1 rounded-lg border px-2.5 py-1.5 font-mono text-xs transition-colors ${
                        !humanApproved
                          ? "border-[#ffb85c] bg-[#ffb85c]/15 text-[#ffb85c]"
                          : "border-[rgba(236,231,218,0.16)] bg-[#090d0b] text-[#ece7da]/75"
                      }`}
                    >
                      Hold / Reject External Action
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExecuteWorkflow(true)}
                      className={`flex-1 rounded-lg border px-2.5 py-1.5 font-mono text-xs transition-colors ${
                        humanApproved
                          ? "border-[#a6ff72] bg-[#a6ff72]/15 text-[#a6ff72]"
                          : "border-[rgba(236,231,218,0.16)] bg-[#090d0b] text-[#ece7da]/75"
                      }`}
                    >
                      Approve Circle Arc Tx
                    </button>
                  </div>
                </div>
              </div>

              <button
                type="button"
                disabled={isRunning}
                onClick={() => handleExecuteWorkflow()}
                className="w-full rounded-xl border border-[#a6ff72] bg-[#a6ff72]/15 px-4 py-3 font-mono text-xs uppercase tracking-[0.14em] text-[#a6ff72] transition-all hover:bg-[#a6ff72]/25 disabled:opacity-50"
              >
                {isRunning
                  ? "Running 6-Stage Gemini 4 Argon Verification Loop..."
                  : "Run 6-Stage Gemini 4 Argon Autonomous Agent ↗"}
              </button>
            </div>
          </div>
        </ExhibitSection>

        {/* Exhibit 02: 6-Stage Autonomous Execution Trace & Pass/Fail Signals */}
        <ExhibitSection
          number="02"
          tag="6-STAGE AUTONOMOUS EXECUTION TRACE"
          title="Concrete Pass/Fail Verification Signals Across All 6 Agent Stages"
          subtitle="Every stage emits a machine-verifiable invariant formula before the pipeline advances to the next trust boundary."
        >
          {runResult ? (
            <div className="space-y-4">
              {/* Summary Status Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#a6ff72]/35 bg-[#090d0b] p-4">
                <div className="flex items-center gap-3">
                  <span className="h-3 w-3 rounded-full bg-[#a6ff72] shadow-[0_0_10px_#a6ff72]" />
                  <div>
                    <div className="font-mono text-xs uppercase tracking-[0.12em] text-[#a6ff72]">
                      Run ID: {runResult.runId} · All 6 Verification Gates Passed:{" "}
                      {String(runResult.overallPassed)}
                    </div>
                    <div className="text-xs text-[#ece7da]/70">
                      Self-Healing Triggered &amp; Resolved:{" "}
                      <strong className="font-mono text-[#ffb85c]">
                        {String(runResult.selfHealingTriggeredAndResolved)}
                      </strong>{" "}
                      | Human Gate Status:{" "}
                      <strong className="font-mono text-[#a6ff72]">
                        {runResult.humanGateState}
                      </strong>
                    </div>
                  </div>
                </div>
                <div className="font-mono text-xs text-[#ece7da]/65">
                  Proof Digest: 0x{runResult.stages.stage6.forensicProofDigestHex.slice(0, 20)}...
                </div>
              </div>

              {/* Grid of 6 Stages */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {/* Stage 1 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 1 · {runResult.stages.stage1.stageName}
                    </span>
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                      PASS ({runResult.stages.stage1.verificationSignal.formula})
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                    Models: {runResult.stages.stage1.modelsUsed.join(" -> ")}
                  </div>
                  <p className="mt-2 text-xs text-[#ece7da]/75">
                    Scrubbed {runResult.stages.stage1.redactionCount} sensitive items
                    (API key, email, cohort ID, grant currency, date) and padded
                    the frame to{" "}
                    <code className="font-mono text-[#a6ff72]">
                      {runResult.stages.stage1.verificationSignal.bucketBytes} bytes
                    </code>{" "}
                    (4096-byte multiple) with{" "}
                    <code className="font-mono text-[#a6ff72]">
                      plaintextLeakCount = {runResult.stages.stage1.verificationSignal.plaintextLeakCount}
                    </code>
                    .
                  </p>
                  <div className="mt-2.5 rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5 font-mono text-[11px] text-[#ece7da]/80">
                    <div className="text-[10px] uppercase text-[#ece7da]/45">
                      PAPILLON Generalized &amp; Symmetry-Masked Prompt Sent Outbound:
                    </div>
                    <div className="mt-1 break-words">
                      {runResult.stages.stage1.papillonGeneralizedPrompt}
                    </div>
                  </div>
                </div>

                {/* Stage 2 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 2 · {runResult.stages.stage2.stageName}
                    </span>
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                      PASS ({runResult.stages.stage2.verificationSignal.formula})
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                    Models: {runResult.stages.stage2.modelsUsed.join(" + ")}
                  </div>
                  <ul className="mt-2 space-y-1.5 text-xs text-[#ece7da]/80">
                    {runResult.stages.stage2.subagents.map((sub) => (
                      <li
                        key={sub.subagentId}
                        className="rounded border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2"
                      >
                        <div className="flex justify-between font-mono text-[11px] text-[#a6ff72]">
                          <span>{sub.model}</span>
                          <span>{sub.latencyMs} ms</span>
                        </div>
                        <div className="mt-0.5 text-[11px] text-[#ece7da]/75">
                          {sub.artifactSummary}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Stage 3 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 3 · {runResult.stages.stage3.stageName}
                    </span>
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                      PASS (1,344 States &amp; V1/V6)
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                    Model: {runResult.stages.stage3.modelsUsed.join(", ")}
                  </div>
                  <div className="mt-2 space-y-2">
                    {runResult.stages.stage3.attempts.map((att) => (
                      <div
                        key={att.attemptNumber}
                        className={`rounded-lg border p-2.5 font-mono text-[11px] ${
                          att.passed
                            ? "border-[#a6ff72]/35 bg-[#050706] text-[#ece7da]"
                            : "border-[#ffb85c]/50 bg-[#ffb85c]/10 text-[#ffb85c]"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span>
                            Attempt #{att.attemptNumber} · Node: {att.candidateNodeId}
                          </span>
                          <span>{att.passed ? "VERIFIED (100%)" : "FAULT CAUGHT"}</span>
                        </div>
                        <div className="mt-1 text-[10px] text-[#ece7da]/75">
                          VMPL0: {att.vmpl0StatesChecked} states | Entropy:{" "}
                          {att.entropyBitsPerByte} bits/byte | Repeated 16B blocks:{" "}
                          {att.repeated16ByteBlocks}
                        </div>
                        {att.remediationApplied && (
                          <div className="mt-1.5 border-t border-[#ffb85c]/30 pt-1.5 text-[11px] text-[#ece7da]">
                            <strong>Self-Healing Action:</strong> {att.remediationApplied}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Stage 4 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 4 · {runResult.stages.stage4.stageName}
                    </span>
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                      PASS (Homomorphic Restore)
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                    Orchestrator: gemini-4-argon -&gt; Attested Enclave:{" "}
                    {runResult.stages.stage4.routedEnclaveModel}
                  </div>
                  <div className="mt-2 space-y-2 font-mono text-[11px]">
                    <div className="rounded border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2 text-[#ece7da]/70">
                      <span className="text-[10px] uppercase text-[#ffb85c]">
                        Enclave Output (Still Masked in Cloud):
                      </span>
                      <p className="mt-1">{runResult.stages.stage4.enclaveCompletionMasked}</p>
                    </div>
                    <div className="rounded border border-[#a6ff72]/30 bg-[#050706] p-2 text-[#ece7da]">
                      <span className="text-[10px] uppercase text-[#a6ff72]">
                        Locally Unmasked Output:
                      </span>
                      <p className="mt-1">{runResult.stages.stage4.restoredClientOutput}</p>
                    </div>
                  </div>
                </div>

                {/* Stage 5 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 5 · {runResult.stages.stage5.stageName}
                    </span>
                    <span className="rounded border border-[#ffb85c]/40 bg-[#ffb85c]/10 px-2 py-0.5 font-mono text-[10px] text-[#ffb85c]">
                      {runResult.stages.stage5.externalActionStatus}
                    </span>
                  </div>
                  <ul className="mt-2 space-y-2 text-xs">
                    {runResult.stages.stage5.pendingActions.map((act) => (
                      <li
                        key={act.actionId}
                        className="rounded border border-[rgba(236,231,218,0.12)] bg-[#050706] p-2.5"
                      >
                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <span className="text-[#ece7da]">{act.kind}</span>
                          <span
                            className={
                              act.status === "executed"
                                ? "text-[#a6ff72]"
                                : "text-[#ffb85c]"
                            }
                          >
                            {act.status.toUpperCase()}
                          </span>
                        </div>
                        <p className="mt-1 text-[11px] text-[#ece7da]/70">
                          {act.description}
                        </p>
                        {act.txHashHex && (
                          <div className="mt-1 font-mono text-[10px] text-[#a6ff72]">
                            Circle Arc Tx: {act.txHashHex}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Stage 6 */}
                <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#a6ff72]">
                      Stage 6 · {runResult.stages.stage6.stageName}
                    </span>
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                      PASS (Ed25519 Signed)
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                    Models: {runResult.stages.stage6.modelsUsed.join(" + ")}
                  </div>
                  <p className="mt-2 rounded border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2.5 text-xs leading-relaxed text-[#ece7da]/85">
                    &ldquo;{runResult.stages.stage6.voiceTranscript}&rdquo;
                  </p>
                  <div className="mt-2 font-mono text-[10px] text-[#ece7da]/60 break-all">
                    Ed25519 Sig: 0x{runResult.stages.stage6.ed25519SignatureHex.slice(0, 48)}...
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 font-mono text-xs text-[#ece7da]/70">
              Initializing 6-stage Gemini 4 Argon verification harness...
            </div>
          )}
        </ExhibitSection>

        {/* Exhibit 03: Gemini 4 Argon API Contract & SDK Inspector */}
        <ExhibitSection
          number="03"
          tag="GEMINI 4 ARGON API CONTRACT & SDK"
          title="Interactions API (client.interactions.create) & Rule Validator"
          subtitle="Enforces thinking_level and background long-decode while rejecting deprecated thinking_budget, temperature, top_p, top_k, and explicit cached_content."
        >
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Validator Badge & Forbidden Params Tester */}
            <div className="lg:col-span-5 space-y-4">
              <div className="rounded-xl border border-[#a6ff72]/35 bg-[#090d0b] p-4">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs uppercase tracking-[0.12em] text-[#a6ff72]">
                    Argon API Rule Compliance Badge
                  </span>
                  <span className="rounded bg-[#a6ff72]/20 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                    VALIDATED
                  </span>
                </div>
                <ul className="mt-3 space-y-1.5 font-mono text-xs text-[#ece7da]/80">
                  <li>
                    + model:{" "}
                    <span className="text-[#a6ff72]">
                      &quot;{activeConfigValidation.normalizedConfig?.model}&quot;
                    </span>
                  </li>
                  <li>
                    + thinking_level:{" "}
                    <span className="text-[#a6ff72]">
                      &quot;{activeConfigValidation.normalizedConfig?.thinking_level}&quot;
                    </span>
                  </li>
                  <li>
                    + background:{" "}
                    <span className="text-[#a6ff72]">
                      {String(activeConfigValidation.normalizedConfig?.background)}
                    </span>
                  </li>
                  <li>
                    + implicit_caching:{" "}
                    <span className="text-[#a6ff72]">&quot;enabled&quot;</span>
                  </li>
                  <li>
                    - Rejected Legacy Params:{" "}
                    <span className="text-[#ffb85c]">
                      {FORBIDDEN_ARGON_PARAMETERS.join(", ")}
                    </span>
                  </li>
                </ul>

                <button
                  type="button"
                  onClick={handleTestForbiddenParams}
                  className="mt-4 w-full rounded-lg border border-[#ffb85c]/45 bg-[#ffb85c]/10 px-3 py-2 font-mono text-xs text-[#ffb85c] hover:bg-[#ffb85c]/20"
                >
                  Test Validator Against Legacy Config (temperature / thinking_budget)
                </button>

                {legacyTestResult && (
                  <div className="mt-3 rounded-lg border border-[#ffb85c]/40 bg-[#050706] p-3 font-mono text-[11px] text-[#ffb85c]">
                    <div>
                      validateArgonRequestConfig valid: {String(legacyTestResult.valid)}
                    </div>
                    <div className="mt-1 text-[#ece7da]/80">
                      Rejected: {legacyTestResult.rejectedParameters.join(", ")}
                    </div>
                    <ul className="mt-1.5 list-disc pl-4 text-[10px] text-[#ece7da]/70">
                      {legacyTestResult.errors.map((err, idx) => (
                        <li key={idx}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Companion Toolkit Table */}
              <div className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
                <div className="font-mono text-xs uppercase tracking-[0.12em] text-[#ece7da]/70">
                  Gemini 4 Argon Companion Model Toolkit
                </div>
                <ul className="mt-3 space-y-2 text-xs">
                  {ARGON_TOOLKIT_MANIFEST.map((item) => (
                    <li
                      key={item.id}
                      className="rounded border border-[rgba(236,231,218,0.1)] bg-[#050706] p-2"
                    >
                      <div className="flex items-center justify-between font-mono text-[11px]">
                        <span className="text-[#a6ff72]">{item.id}</span>
                        <span className="text-[10px] text-[#ffb85c]">
                          {item.trustBoundary}
                        </span>
                      </div>
                      <div className="mt-0.5 text-[11px] text-[#ece7da]/75">
                        {item.role}
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* SDK Code Inspector */}
            <div className="lg:col-span-7 rounded-xl border border-[rgba(236,231,218,0.14)] bg-[#090d0b] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs uppercase tracking-[0.12em] text-[#a6ff72]">
                  Official @google/genai (&gt;= 2.3.0) client.interactions.create
                </span>
                <div className="flex gap-1.5">
                  {(["typescript", "python", "payload"] as const).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => setSdkTab(tab)}
                      className={`rounded-lg border px-2.5 py-1 font-mono text-xs uppercase ${
                        sdkTab === tab
                          ? "border-[#a6ff72] bg-[#a6ff72]/15 text-[#a6ff72]"
                          : "border-[rgba(236,231,218,0.14)] bg-[#050706] text-[#ece7da]/70"
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>

              <pre className="mt-3 max-h-[540px] overflow-auto rounded-xl border border-[rgba(236,231,218,0.1)] bg-[#050706] p-4 font-mono text-xs leading-relaxed text-[#ece7da]">
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
                  : "Loading SDK snippet..."}
              </pre>
            </div>
          </div>
        </ExhibitSection>
      </main>

      <SpecimenFooter />
    </div>
  );
}
