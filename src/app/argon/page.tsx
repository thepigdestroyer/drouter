"use client";

import React, { useCallback, useEffect, useState } from "react";
import { AuthGate } from "@/components/auth/auth-gate";
import { AuthPill } from "@/components/auth-pill";
import { AtlasExplorer } from "@/components/atlas-explorer";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import {
  ExhibitSection,
  SpecimenFooter,
  SpecimenHeader,
} from "@/components/specimen-chrome";
import {
  AGENT_INTRO_SENTENCE,
  APPROVAL_CARD_QUESTION,
  buildPlainTimelineSteps,
  DEFAULT_PLAIN_TASK_PROMPT,
  EXAMPLE_AGENT_TASKS,
  formatCleanRunJsonForDisplay,
  formatPlainDataHandling,
  resolvePlannerModeBadgeText,
  resolvePlannerSubtitleText,
  sanitizeJargonToPlainWords,
  WHAT_GOOGLE_RECEIVED_PROMPT,
  type ArcAnchorResult,
  type ArgonPlannerInfo,
} from "@/components/argon/argon-helpers";
import {
  ARGON_TOOLKIT_MANIFEST,
  FORBIDDEN_ARGON_PARAMETERS,
  GEMINI_4_ARGON_MODEL_ID,
  validateArgonRequestConfig,
  type ArgonThinkingLevel,
  type ArgonValidationResult,
  type TaskDescriptor,
} from "@/lib/gemini/interactions";
import type {
  ArgonAutonomousRunResult,
  DataHandlingStatement,
} from "@/lib/gemini/orchestrator";

export { resolvePlannerModeBadgeText, type ArgonPlannerInfo };

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
  error?: string;
  message?: string;
  mode?: string;
  planner?: ArgonPlannerInfo;
  dataSentToGoogle?: string;
  dataHandling?: DataHandlingStatement;
  taskDescriptor?: TaskDescriptor;
  modelCalls?: ModelCallRecord[];
  autonomousRun?: ArgonAutonomousRunResult & {
    planner?: ArgonPlannerInfo;
  };
  arcAnchor?: ArcAnchorResult;
  validation?: ArgonValidationResult;
}

const PUBLIC_RECEIPT_BOOK_URL =
  "https://testnet.arcscan.app/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481";

function InkCheckIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="h-3.5 w-3.5 shrink-0 stroke-current"
      fill="none"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M3.2 8.4L6.5 11.6L12.8 4.6" />
    </svg>
  );
}

function OrangeCrossIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="h-3.5 w-3.5 shrink-0 stroke-current"
      fill="none"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M4.2 4.2L11.8 11.8M11.8 4.2L4.2 11.8" />
    </svg>
  );
}

function ArgonAuthenticatedView() {
  const [taskPrompt, setTaskPrompt] = useState<string>(
    DEFAULT_PLAIN_TASK_PROMPT,
  );
  const [thinkingLevel, setThinkingLevel] =
    useState<ArgonThinkingLevel>("high");
  const [backgroundDecode] = useState<boolean>(true);
  const [enclaveModel, setEnclaveModel] = useState<"gemma4-31b" | "kimi-k3">(
    "gemma4-31b",
  );
  const [injectFault, setInjectFault] = useState<boolean>(true);
  const [humanApproved, setHumanApproved] = useState<boolean>(false);
  const [userDeclinedApproval, setUserDeclinedApproval] =
    useState<boolean>(false);
  const [geminiApiKey, setGeminiApiKey] = useState<string>("");
  const [sdkTab, setSdkTab] = useState<"typescript" | "python" | "payload">(
    "typescript",
  );
  const [isInitialLoading, setIsInitialLoading] = useState<boolean>(true);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [lastActionKind, setLastActionKind] = useState<"get" | "post">("get");
  const [lastApprovalOverride, setLastApprovalOverride] = useState<
    boolean | undefined
  >(undefined);
  const [runResult, setRunResult] = useState<ArgonAutonomousRunResult | null>(
    null,
  );
  const [plannerInfo, setPlannerInfo] = useState<ArgonPlannerInfo | null>(null);
  const [arcAnchor, setArcAnchor] = useState<ArcAnchorResult | null>(null);
  const [apiModelCalls, setApiModelCalls] = useState<ModelCallRecord[]>([]);
  const [legacyTestResult, setLegacyTestResult] =
    useState<ArgonValidationResult | null>(null);

  const loadInitialRun = useCallback(async () => {
    setIsInitialLoading(true);
    setApiError(null);
    setLastActionKind("get");
    try {
      const res = await fetch("/api/gemini");
      const data = (await res
        .json()
        .catch(() => null)) as GeminiRouteResponse | null;
      if (!res.ok || !data || data.ok === false || !data.autonomousRun) {
        const errMsg =
          data?.message ||
          data?.error ||
          `Could not load the initial agent state (HTTP ${res.status}).`;
        setApiError(errMsg);
        return;
      }

      const run = data.autonomousRun;
      setRunResult(run);
      setPlannerInfo(data.planner ?? run.planner ?? null);
      setApiModelCalls(Array.isArray(data.modelCalls) ? data.modelCalls : []);
      setArcAnchor(data.arcAnchor ?? null);
      setHumanApproved(Boolean(run.stages.stage5.approvedByHuman));
      setUserDeclinedApproval(false);
    } catch (err) {
      setApiError(
        err instanceof Error
          ? err.message
          : "Network error while loading the agent.",
      );
    } finally {
      setIsInitialLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadInitialRun();
  }, [loadInitialRun]);

  async function handleExecuteWorkflow(overrideApproval?: boolean) {
    setIsRunning(true);
    setApiError(null);
    setLastActionKind("post");
    setLastApprovalOverride(overrideApproval);

    const effectiveApproval =
      overrideApproval !== undefined ? overrideApproval : humanApproved;

    // Clear previous runResult when starting a new Run so a failed POST never leaves stale results visible
    if (overrideApproval !== true) {
      setRunResult(null);
      setArcAnchor(null);
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

      const data = (await response
        .json()
        .catch(() => null)) as GeminiRouteResponse | null;

      if (
        !response.ok ||
        !data ||
        data.ok === false ||
        !data.autonomousRun
      ) {
        const validationErrors = data?.validation?.errors?.join(" ");
        const errMsg =
          validationErrors ||
          data?.message ||
          data?.error ||
          `Agent run failed with HTTP ${response.status}.`;
        setRunResult(null);
        setApiError(errMsg);
        return;
      }

      const run = data.autonomousRun;
      setRunResult(run);
      setPlannerInfo(data.planner ?? run.planner ?? null);
      setApiModelCalls(Array.isArray(data.modelCalls) ? data.modelCalls : []);
      setArcAnchor(data.arcAnchor ?? null);
      setHumanApproved(effectiveApproval);
      setUserDeclinedApproval(false);
    } catch (err) {
      setRunResult(null);
      setApiError(
        err instanceof Error
          ? err.message
          : "Network error while running the agent.",
      );
    } finally {
      setIsRunning(false);
    }
  }

  function handleNotNowClick() {
    setUserDeclinedApproval(true);
    setHumanApproved(false);
  }

  function handleRetry() {
    if (lastActionKind === "post") {
      void handleExecuteWorkflow(lastApprovalOverride);
    } else {
      void loadInitialRun();
    }
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

  const liveGeminiReached = Boolean(
    runResult?.stages.stage4.liveGeminiCall.liveEndpointReached,
  );
  const attemptedLiveGemini = Boolean(
    runResult?.stages.stage4.liveGeminiCall.attemptedLiveCall,
  );
  const hasLiveModelCalls = apiModelCalls.some((c) => c.ok);
  const isInitialPreview = lastActionKind === "get" && !hasLiveModelCalls;

  const plannerBadgeText = resolvePlannerModeBadgeText({
    planner: plannerInfo,
    mode: runResult?.mode ?? (liveGeminiReached ? "live" : "tinfoil-planner"),
    liveGeminiReached,
    enclaveModel:
      runResult?.stages.stage4.routedEnclaveModel ?? enclaveModel,
  });
  const isLiveGeminiBadge = plannerBadgeText === "Planned by Gemini 4 Argon";

  const plannerSubtitle = resolvePlannerSubtitleText({
    isLiveGeminiBadge,
    attemptedLiveCall: attemptedLiveGemini,
    liveGeminiReached,
    isInitialPreview,
  });

  const isGatePending =
    runResult?.stages.stage5.externalActionStatus === "paused_awaiting_human" ||
    !runResult?.stages.stage5.approvedByHuman;

  const timelineSteps = runResult
    ? buildPlainTimelineSteps({
        run: runResult,
        plannerBadgeText,
        arcAnchor,
        userDeclinedApproval,
        hasLiveModelCalls,
      })
    : [];

  const plainDataHandling = formatPlainDataHandling(runResult?.dataHandling);
  const activeTaskDescriptor =
    runResult?.taskDescriptor ?? runResult?.stages.stage4.taskDescriptor;

  return (
    <>
      <div className="mx-auto w-full max-w-5xl px-4 pt-10 pb-4 sm:px-6 space-y-10">
        {/* 1. Top Intro & Split-Knowledge / Data-Handling Card */}
        <InkReveal className="[&[data-ink-reveal=pending]]:!opacity-100 [&[data-ink-reveal=pending]]:![clip-path:none]">
          <header className="space-y-5 border-b border-rule pb-8">
            <div className="ep-label">deRoute private agent</div>
            <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
              Private AI agent
            </h1>
            <p
              data-testid="argon-intro-sentence"
              className="max-w-[70ch] text-base sm:text-lg text-ink-2 leading-relaxed"
            >
              {AGENT_INTRO_SENTENCE}
            </p>

            {/* Honest Planner & Data-Handling Card */}
            <div className="ep-card p-4 sm:p-5 space-y-4 min-w-0">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between min-w-0">
                <div className="flex items-center gap-3 min-w-0">
                  <span
                    data-testid="argon-mode-badge"
                    className={
                      isLiveGeminiBadge
                        ? "inline-flex items-center rounded-2xl sm:rounded-full bg-ink text-paper px-3.5 py-1.5 font-mono text-xs font-medium tracking-wide max-w-full whitespace-normal break-words"
                        : "inline-flex items-center rounded-2xl sm:rounded-full border border-ink text-ink px-3.5 py-1.5 font-mono text-xs font-medium tracking-wide max-w-full whitespace-normal break-words"
                    }
                  >
                    {plannerBadgeText}
                  </span>
                </div>
                <p className="text-xs text-ink-2 max-w-[58ch]">
                  {plannerSubtitle}
                </p>
              </div>

              {/* Plain Split-Knowledge & Data-Handling Summary */}
              <div className="border-t border-rule pt-3.5 space-y-3">
                <p
                  data-testid="argon-what-google-received"
                  className="text-sm font-medium text-ink"
                >
                  {WHAT_GOOGLE_RECEIVED_PROMPT}{" "}
                  <span className="font-normal text-ink-2">
                    {plainDataHandling.sentToGooglePlain}.
                  </span>
                </p>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs text-ink-2">
                  <div className="ep-inset p-3 space-y-1">
                    <div className="font-mono font-medium text-ink">
                      What Google can see
                    </div>
                    <ul className="list-disc pl-4 space-y-0.5">
                      {plainDataHandling.googleCanSeePlain.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="ep-inset p-3 space-y-1">
                    <div className="font-mono font-medium text-ink">
                      What Google never sees
                    </div>
                    <ul className="list-disc pl-4 space-y-0.5">
                      {plainDataHandling.googleCannotSeePlain.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="ep-inset p-3 space-y-1">
                    <div className="font-mono font-medium text-ink">
                      What the sealed computer sees
                    </div>
                    <p>{plainDataHandling.sealedComputerCanSeePlain}</p>
                  </div>
                </div>

                {activeTaskDescriptor && (
                  <TechDetails label="Show technical details">
                    <div className="space-y-3 font-mono text-xs text-ink-2">
                      <div>
                        <span className="text-ink font-medium">
                          dataSentToGoogle:
                        </span>{" "}
                        {runResult?.dataSentToGoogle ??
                          "content-free task descriptor only"}
                      </div>
                      <div className="space-y-1">
                        <div className="text-ink font-medium">
                          Content-free TaskDescriptor sent to planner:
                        </div>
                        <pre className="ep-inset p-3 overflow-x-auto text-[11px] text-ink">
                          {JSON.stringify(activeTaskDescriptor, null, 2)}
                        </pre>
                      </div>
                      {runResult?.dataHandling && (
                        <div className="space-y-1">
                          <div className="text-ink font-medium">
                            Raw dataHandling statement:
                          </div>
                          <pre className="ep-inset p-3 overflow-x-auto text-[11px] text-ink-2">
                            {JSON.stringify(runResult.dataHandling, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  </TechDetails>
                )}
              </div>
            </div>
          </header>
        </InkReveal>

        {/* Big Task Box with 2 Example Tasks and 1 Run InkButton */}
        <InkReveal className="[&[data-ink-reveal=pending]]:!opacity-100 [&[data-ink-reveal=pending]]:![clip-path:none]">
          <section
            aria-label="Give the agent a task"
            className="ep-card p-5 sm:p-6 space-y-5"
          >
            <div className="space-y-2">
              <label
                htmlFor="argon-task-prompt"
                className="font-serif text-lg font-medium text-ink block"
              >
                Your private task
              </label>
              <p className="text-xs sm:text-sm text-ink-2">
                Your device hides names, emails, dates, amounts, and secret
                keys before anything is sent.
              </p>
              <textarea
                id="argon-task-prompt"
                rows={4}
                value={taskPrompt}
                onChange={(e) => {
                  setTaskPrompt(e.target.value);
                  setHumanApproved(false);
                  setUserDeclinedApproval(false);
                }}
                className="ep-input text-sm leading-relaxed"
              />
            </div>

            {/* 2 Example Tasks in plain words */}
            <div className="space-y-2">
              <span className="ep-label block">Or try an example task:</span>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {EXAMPLE_AGENT_TASKS.map((ex) => {
                  const isSelected = taskPrompt.trim() === ex.prompt.trim();
                  return (
                    <button
                      key={ex.id}
                      type="button"
                      aria-pressed={isSelected}
                      onClick={() => {
                        setTaskPrompt(ex.prompt);
                        setHumanApproved(false);
                        setUserDeclinedApproval(false);
                      }}
                      className={`text-left rounded border p-3.5 transition-colors cursor-pointer ${
                        isSelected
                          ? "border-ink bg-paper-2"
                          : "border-rule bg-paper hover:border-ink hover:bg-paper-2/60"
                      }`}
                    >
                      <div className="font-serif text-sm font-medium text-ink">
                        {ex.label}
                      </div>
                      <p className="mt-1 text-xs text-ink-2">
                        {ex.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Single Run InkButton */}
            <div className="pt-1">
              <InkButton
                type="button"
                variant="primary"
                disabled={isRunning || isInitialLoading}
                onClick={() => {
                  setHumanApproved(false);
                  setUserDeclinedApproval(false);
                  void handleExecuteWorkflow(false);
                }}
                className="w-full sm:w-auto px-7 py-2.5 text-sm cursor-pointer"
              >
                {isRunning && lastApprovalOverride !== true
                  ? "Running..."
                  : "Run"}
              </InkButton>
            </div>
          </section>
        </InkReveal>

        {/* Error Banner with Retry */}
        {apiError && (
          <section
            role="alert"
            aria-label="Agent error"
            className="ep-card border-accent bg-accent-soft/40 p-5 sm:p-6 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="space-y-0.5">
                <div className="ep-label">Problem running task</div>
                <h2 className="font-serif text-xl text-ink">
                  Could not complete agent request
                </h2>
              </div>
              <span className="ep-fail">
                <OrangeCrossIcon />
                <span>Error</span>
              </span>
            </div>
            <p className="text-sm text-ink-2 break-words">
              {sanitizeJargonToPlainWords(apiError)}
            </p>
            <TechDetails label="Show technical details">
              <p className="font-mono text-xs text-ink-2 break-words">
                {apiError}
              </p>
            </TechDetails>
            <div>
              <InkButton
                type="button"
                variant="ghost"
                disabled={isRunning || isInitialLoading}
                onClick={handleRetry}
                className="text-xs cursor-pointer"
              >
                Try again
              </InkButton>
            </div>
          </section>
        )}

        {/* 2. Friendly Vertical Ink Timeline of Plain Steps */}
        <InkReveal className="[&[data-ink-reveal=pending]]:!opacity-100 [&[data-ink-reveal=pending]]:![clip-path:none]">
          {runResult ? (
            <section
              aria-label="Agent progress timeline"
              aria-live="polite"
              className="space-y-6"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule pb-3 min-w-0">
                <div>
                  <div className="ep-label">Progress</div>
                  <h2 className="font-serif text-2xl text-ink">
                    How your task was handled
                  </h2>
                </div>
                <span className="ep-muted-chip max-w-full whitespace-normal break-words text-left">
                  {plannerBadgeText}
                </span>
              </div>

              <ol className="relative border-l-2 border-ink/25 ml-3 pl-6 space-y-6">
                {timelineSteps.map((step) => (
                  <li key={step.id} className="relative space-y-2.5">
                    <span
                      aria-hidden="true"
                      className={`absolute -left-[33px] top-1 flex h-4 w-4 items-center justify-center rounded-full border-2 border-paper ${
                        step.passed ? "bg-ink" : "bg-accent"
                      }`}
                    />

                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="font-serif text-lg sm:text-xl font-medium text-ink">
                        {step.stepNumber}. {step.title}
                      </h3>
                      <span className={step.passed ? "ep-pass" : "ep-fail"}>
                        {step.passed ? (
                          <InkCheckIcon />
                        ) : (
                          <OrangeCrossIcon />
                        )}
                        <span>{step.statusText}</span>
                      </span>
                    </div>

                    <p className="max-w-[70ch] text-sm text-ink-2 leading-relaxed">
                      {step.plainResult}
                    </p>

                    {/* Per-step TechDetails */}
                    {step.id === "hiding-details" && (
                      <TechDetails label="Show technical details">
                        <div className="space-y-2 font-mono text-xs text-ink-2">
                          <div>
                            <span className="text-ink font-medium">
                              Models / modules:
                            </span>{" "}
                            {runResult.stages.stage1.modelsUsed.join(", ")}
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Total redactions:
                            </span>{" "}
                            {runResult.stages.stage1.redactionCount} |{" "}
                            <span className="text-ink font-medium">
                              Mechanical (D3):
                            </span>{" "}
                            {runResult.stages.stage1.mechanicalRedactionCount} |{" "}
                            <span className="text-ink font-medium">
                              Bucket size:
                            </span>{" "}
                            {runResult.stages.stage1.verificationSignal.bucketBytes.toLocaleString()}{" "}
                            bytes |{" "}
                            <span className="text-ink font-medium">
                              Plaintext leaks:
                            </span>{" "}
                            {
                              runResult.stages.stage1.verificationSignal
                                .plaintextLeakCount
                            }
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Redaction counts by category:
                            </span>{" "}
                            {JSON.stringify(
                              runResult.stages.stage1.redactionCounts,
                            )}
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Attested filter (D4):
                            </span>{" "}
                            model={runResult.stages.stage1.attestedFilter.model}
                            , verified=
                            {String(
                              runResult.stages.stage1.attestedFilter.verified,
                            )}
                            , redactionCount=
                            {
                              runResult.stages.stage1.attestedFilter
                                .redactionCount
                            }
                            , fallbackToMechanicalOnly=
                            {String(
                              runResult.stages.stage1.attestedFilter
                                .fallbackToMechanicalOnly,
                            )}{" "}
                            ({runResult.stages.stage1.attestedFilter.note})
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Outbound masked prompt:
                            </span>{" "}
                            {
                              runResult.stages.stage1
                                .papillonGeneralizedPrompt
                            }
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Homomorphic equation:
                            </span>{" "}
                            {runResult.stages.stage1.homomorphicEquation}
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Verification formula:
                            </span>{" "}
                            {
                              runResult.stages.stage1.verificationSignal
                                .formula
                            }
                          </div>
                        </div>
                      </TechDetails>
                    )}

                    {step.id === "checking-seal" && (
                      <TechDetails label="Show technical details">
                        <div className="space-y-3 font-mono text-xs text-ink-2">
                          <div>
                            <span className="text-ink font-medium">
                              Verification checks passed:
                            </span>{" "}
                            {
                              runResult.stages.stage2.verificationSignal
                                .checksPassed
                            }{" "}
                            /{" "}
                            {
                              runResult.stages.stage2.verificationSignal
                                .checksTotal
                            }
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Router &amp; enclave target:
                            </span>{" "}
                            {runResult.stages.stage2.routerHost} -&gt;{" "}
                            {runResult.stages.stage2.selectedEnclaveHost} (
                            {runResult.stages.stage2.selectedEnclaveModel})
                          </div>
                          <div className="space-y-1">
                            <div className="text-ink font-medium">
                              7-check hardware &amp; registry verification:
                            </div>
                            {runResult.stages.stage2.sevenChecks.map((chk) => (
                              <div key={chk.id}>
                                [{chk.passed ? "PASS" : "FAIL"}] {chk.label} -{" "}
                                {chk.detail}
                              </div>
                            ))}
                          </div>
                          <div className="space-y-1">
                            <div className="text-ink font-medium">
                              Verifier subagent traces:
                            </div>
                            {runResult.stages.stage2.subagents.map((sub) => (
                              <div key={sub.subagentId}>
                                {sub.model} ({sub.latencyMs} ms):{" "}
                                {sub.artifactSummary}
                              </div>
                            ))}
                          </div>
                          <div className="space-y-1">
                            <div className="text-ink font-medium">
                              Enclave verification &amp; failover attempts:
                            </div>
                            {runResult.stages.stage3.attempts.map((att) => (
                              <div
                                key={att.attemptNumber}
                                className="border-t border-rule pt-1.5"
                              >
                                <div>
                                  Attempt #{att.attemptNumber}:{" "}
                                  {att.candidateNodeId} (
                                  {att.candidateModelId ?? "enclave"} -{" "}
                                  {att.passed ? "Verified" : "Fault caught"})
                                </div>
                                <div>
                                  Enclave attestation verified:{" "}
                                  {String(att.enclaveAttestationVerified)} |
                                  Stream entropy: {att.entropyBitsPerByte}{" "}
                                  bits/byte | Repeated 16B blocks:{" "}
                                  {att.repeated16ByteBlocks}
                                </div>
                                {att.remediationApplied && (
                                  <div className="text-ink">
                                    Remediation: {att.remediationApplied}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Active enclave measurement:
                            </span>{" "}
                            {runResult.stages.stage3.sandboxReceipt.sandboxId} |
                            dm-verity root 0x
                            {runResult.stages.stage3.sandboxReceipt.imageMeasurementHex.slice(
                              0,
                              16,
                            )}
                            ... | RTMR 0x
                            {runResult.stages.stage3.sandboxReceipt.rtmr3Hex.slice(
                              0,
                              16,
                            )}
                            ...
                          </div>
                        </div>
                      </TechDetails>
                    )}

                    {step.id === "thinking" && (
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-ink">
                          {WHAT_GOOGLE_RECEIVED_PROMPT}
                        </p>
                        <TechDetails label="Show technical details">
                          <div className="space-y-2 font-mono text-xs text-ink-2">
                            <div>
                              <span className="text-ink font-medium">
                                dataSentToGoogle:
                              </span>{" "}
                              {runResult.stages.stage4.dataSentToGoogle}
                            </div>
                            <div className="space-y-1">
                              <div className="text-ink font-medium">
                                Content-free TaskDescriptor:
                              </div>
                              <pre className="ep-inset p-3 overflow-x-auto text-[11px] text-ink">
                                {JSON.stringify(
                                  runResult.stages.stage4.taskDescriptor,
                                  null,
                                  2,
                                )}
                              </pre>
                            </div>
                            <div className="space-y-1">
                              <div className="text-ink font-medium">
                                Server-resolved opaque handles:
                              </div>
                              <pre className="ep-inset p-3 overflow-x-auto text-[11px] text-ink-2">
                                {JSON.stringify(
                                  runResult.stages.stage4.resolvedHandles,
                                  null,
                                  2,
                                )}
                              </pre>
                            </div>
                            <div>
                              <span className="text-ink font-medium">
                                Planner:
                              </span>{" "}
                              {runResult.stages.stage4.planner.provider}:
                              {runResult.stages.stage4.planner.model} |{" "}
                              <span className="text-ink font-medium">
                                Routed enclave:
                              </span>{" "}
                              {runResult.stages.stage4.routedEnclaveModel} (
                              {runResult.stages.stage4.routedEnclaveHost})
                            </div>
                            <div>
                              <span className="text-ink font-medium">
                                Config:
                              </span>{" "}
                              thinking_level=&quot;
                              {runResult.stages.stage4.thinkingLevel}&quot;,
                              background=
                              {String(runResult.stages.stage4.background)},
                              contentFreeEgressVerified=
                              {String(
                                runResult.stages.stage4.verificationSignal
                                  .contentFreeEgressVerified,
                              )}
                            </div>
                            <div>
                              <span className="text-ink font-medium">
                                Masked enclave output:
                              </span>{" "}
                              {
                                runResult.stages.stage4
                                  .enclaveCompletionMasked
                              }
                            </div>
                            <div>
                              <span className="text-ink font-medium">
                                Restored client output:
                              </span>{" "}
                              {runResult.stages.stage4.restoredClientOutput}
                            </div>
                            <div>
                              <span className="text-ink font-medium">
                                Planner call note:
                              </span>{" "}
                              {runResult.stages.stage4.liveGeminiCall
                                .liveSummaryText ??
                                runResult.stages.stage4.liveGeminiCall
                                  .fallbackReason ??
                                "No live Gemini call"}
                            </div>
                          </div>
                        </TechDetails>
                      </div>
                    )}

                    {step.id === "waiting-for-you" && (
                      <TechDetails label="Show technical details">
                        <div className="space-y-1.5 font-mono text-xs text-ink-2">
                          <div>
                            <span className="text-ink font-medium">
                              Gate status:
                            </span>{" "}
                            {runResult.stages.stage5.externalActionStatus}
                          </div>
                          <div>
                            <span className="text-ink font-medium">
                              Circle Arc Testnet registry:
                            </span>{" "}
                            0xbc8085c2b6fe6e0db05f169925c0b841828f4481 (chain
                            5042002)
                          </div>
                          {runResult.stages.stage5.pendingActions.map((act) => {
                            const isRealBroadcast =
                              act.kind === "anchor_arc_receipt" &&
                              arcAnchor?.broadcast === true;
                            return (
                              <div key={act.actionId}>
                                {act.kind} ({act.status}): {act.description}
                                {isRealBroadcast ? (
                                  <>
                                    {" "}
                                    | Broadcast tx:{" "}
                                    <a
                                      href={arcAnchor.explorerUrl}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="ep-link"
                                    >
                                      {arcAnchor.txHash}
                                    </a>
                                  </>
                                ) : (
                                  " | Not broadcast on-chain"
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </TechDetails>
                    )}

                    {step.id === "done" && (
                      <TechDetails label="Show technical details">
                        <div className="space-y-2 font-mono text-xs text-ink-2">
                          <div>
                            <span className="text-ink font-medium">
                              Run ID:
                            </span>{" "}
                            {runResult.runId}
                          </div>
                          <div className="break-all">
                            <span className="text-ink font-medium">
                              SHA-256 run digest:
                            </span>{" "}
                            0x
                            {runResult.stages.stage6.forensicProofDigestHex}
                          </div>
                          <div className="break-all">
                            <span className="text-ink font-medium">
                              Ed25519 signature:
                            </span>{" "}
                            0x
                            {runResult.stages.stage6.ed25519SignatureHex}
                          </div>
                          <div className="break-all">
                            <span className="text-ink font-medium">
                              Signer public key:
                            </span>{" "}
                            0x
                            {runResult.stages.stage6.signerPublicKeyHex}
                          </div>
                          <div className="font-sans text-xs text-ink-2">
                            {runResult.stages.stage6.voiceTranscript}
                          </div>
                        </div>
                      </TechDetails>
                    )}
                  </li>
                ))}
              </ol>
            </section>
          ) : isInitialLoading ? (
            <div className="ep-card p-6 text-sm text-ink-2">
              Loading your private agent...
            </div>
          ) : null}
        </InkReveal>

        {/* 3. Clear Approval Card */}
        <InkReveal className="[&[data-ink-reveal=pending]]:!opacity-100 [&[data-ink-reveal=pending]]:![clip-path:none]">
          {runResult && (
            <section
              aria-label="Public receipt approval"
              aria-live="polite"
              data-testid="argon-approval-card"
              className={`ep-card p-5 sm:p-6 space-y-4 ${
                isGatePending && !userDeclinedApproval
                  ? "border-accent bg-accent-soft/40"
                  : ""
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="ep-label">Your choice</div>
                  <h2 className="font-serif text-xl sm:text-2xl text-ink">
                    {APPROVAL_CARD_QUESTION}
                  </h2>
                </div>
                <span className={isGatePending ? "ep-fail" : "ep-pass"}>
                  {isGatePending ? <OrangeCrossIcon /> : <InkCheckIcon />}
                  <span>
                    {isGatePending
                      ? userDeclinedApproval
                        ? "Not now"
                        : "Waiting for you"
                      : "Allowed"}
                  </span>
                </span>
              </div>

              <p className="max-w-[70ch] text-sm text-ink-2">
                A receipt proves that the safety checks passed without sharing
                your task or personal details. Nothing is written in public
                unless you click Allow.
              </p>

              {/* Confirmation after Allow */}
              {!isGatePending && (
                <div
                  data-testid="argon-receipt-confirmation"
                  className="ep-inset p-4 space-y-2 text-sm text-ink"
                >
                  {arcAnchor?.broadcast ? (
                    <p>
                      Confirmed: your receipt was recorded in the public receipt
                      book.{" "}
                      <a
                        href={arcAnchor.explorerUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link font-medium"
                      >
                        See the receipt
                      </a>
                    </p>
                  ) : (
                    <p>
                      You allowed the receipt, but it was not recorded on the
                      live network (
                      {arcAnchor?.reason
                        ? sanitizeJargonToPlainWords(arcAnchor.reason)
                        : "live wallet not configured on this server"}
                      ).{" "}
                      <a
                        href={PUBLIC_RECEIPT_BOOK_URL}
                        target="_blank"
                        rel="noreferrer"
                        className="ep-link font-medium"
                      >
                        View the public receipt book
                      </a>
                    </p>
                  )}
                </div>
              )}

              {/* Plain confirmation when user clicks Not now */}
              {isGatePending && userDeclinedApproval && (
                <div className="ep-inset p-3.5 text-sm text-ink-2">
                  Okay, we did not record anything in the public receipt book.
                  You can click Allow anytime if you change your mind.
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3 pt-1">
                <InkButton
                  type="button"
                  variant={
                    isGatePending && !userDeclinedApproval
                      ? "accent"
                      : "primary"
                  }
                  disabled={isRunning || isInitialLoading || !isGatePending}
                  onClick={() => void handleExecuteWorkflow(true)}
                  className="cursor-pointer"
                >
                  {isRunning && lastApprovalOverride === true
                    ? "Recording..."
                    : isGatePending
                      ? "Allow"
                      : "Allowed"}
                </InkButton>
                <InkButton
                  type="button"
                  variant="ghost"
                  disabled={isRunning || isInitialLoading || !isGatePending}
                  onClick={handleNotNowClick}
                  className="cursor-pointer"
                >
                  Not now
                </InkButton>
              </div>

              <TechDetails label="Show technical details">
                <div className="space-y-1.5 font-mono text-xs text-ink-2">
                  <div>
                    Registry contract:
                    0xbc8085c2b6fe6e0db05f169925c0b841828f4481 (Circle Arc
                    Testnet, chainId 5042002)
                  </div>
                  {arcAnchor?.broadcast ? (
                    <div className="break-all">
                      Transaction hash: {arcAnchor.txHash} | Receipt hash:{" "}
                      {arcAnchor.receiptHash}
                    </div>
                  ) : arcAnchor ? (
                    <div>Broadcast status: {arcAnchor.reason}</div>
                  ) : (
                    <div>Broadcast status: waiting for human approval</div>
                  )}
                </div>
              </TechDetails>
            </section>
          )}
        </InkReveal>

        {/* 4. For Experts Section (All settings, model calls, SDK code, validator, raw JSON) */}
        <InkReveal className="[&[data-ink-reveal=pending]]:!opacity-100 [&[data-ink-reveal=pending]]:![clip-path:none]">
          <section aria-label="For experts">
            <TechDetails
              label="For experts"
              summary="Settings, SDK code, and raw data"
            >
              <div className="space-y-6">
                {/* Expert run controls */}
                <div className="space-y-4">
                  <div className="ep-label">
                    Expert agent settings (used on next Run)
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    {/* Thinking level */}
                    <div className="space-y-1.5">
                      <span className="ep-label block">Thinking level</span>
                      <div
                        className="flex gap-1.5"
                        role="group"
                        aria-label="Thinking level"
                      >
                        {(["low", "medium", "high"] as const).map((lvl) => (
                          <button
                            key={lvl}
                            type="button"
                            aria-pressed={thinkingLevel === lvl}
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

                    {/* Automatic failover test */}
                    <div className="space-y-1.5">
                      <span className="ep-label block">
                        Test automatic failover
                      </span>
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
                        {injectFault
                          ? "On: test failover to backup model"
                          : "Off: primary model only"}
                      </button>
                    </div>

                    {/* Enclave model */}
                    <div className="space-y-1.5">
                      <span className="ep-label block">Enclave model</span>
                      <div
                        className="flex gap-1.5"
                        role="group"
                        aria-label="Enclave model"
                      >
                        {(["gemma4-31b", "kimi-k3"] as const).map((mdl) => (
                          <button
                            key={mdl}
                            type="button"
                            aria-pressed={enclaveModel === mdl}
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

                  {/* Optional Gemini API key */}
                  <div className="ep-inset p-3.5 space-y-2">
                    <label
                      htmlFor="gemini-api-key-input"
                      className="block font-mono text-xs text-ink"
                    >
                      Use your own Gemini API key (optional, sent for one call
                      and never stored)
                    </label>
                    <input
                      id="gemini-api-key-input"
                      type="password"
                      autoComplete="off"
                      placeholder="AIzaSy..."
                      value={geminiApiKey}
                      onChange={(e) => setGeminiApiKey(e.target.value)}
                      className="ep-input font-mono text-xs"
                    />
                  </div>
                </div>

                {/* Model calls telemetry */}
                <div className="space-y-2">
                  <div className="ep-label">Model calls in this run</div>
                  {apiModelCalls.length > 0 ? (
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
                          {apiModelCalls.map((call, idx) => (
                            <tr key={`${call.model}-${idx}`}>
                              <td className="py-2 pr-3 text-ink font-medium">
                                {call.model}
                              </td>
                              <td className="py-2 pr-3 font-sans text-ink-2">
                                {call.purpose}
                                {call.error ? (
                                  <span className="block font-mono text-[11px] text-ink-3">
                                    {call.error}
                                  </span>
                                ) : null}
                              </td>
                              <td className="py-2 pr-3">
                                <span
                                  className={call.ok ? "ep-pass" : "ep-fail"}
                                >
                                  {call.ok ? "ok" : "error"}
                                </span>
                              </td>
                              <td className="py-2 text-right text-ink-2">
                                {call.latencyMs} ms
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="ep-inset p-3 font-mono text-xs text-ink-2">
                      No external LLM calls were recorded in this cached
                      preview. Click Run or Allow to execute a live call via
                      POST /api/gemini.
                    </p>
                  )}
                </div>

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
                            aria-pressed={sdkTab === tab}
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
                      ? (sdkTab === "typescript"
                          ? runResult.stages.stage4.sdkSnippets.typescript
                          : sdkTab === "python"
                            ? runResult.stages.stage4.sdkSnippets.python
                            : JSON.stringify(
                                runResult.stages.stage4.interactionsPayload,
                                null,
                                2,
                              )
                        ).replace(/\bdRouter\b/g, "deRoute")
                      : "Loading snippet..."}
                  </pre>
                </div>

                {/* Argon rule compliance list */}
                <div className="space-y-3">
                  <div className="ep-label">Argon parameter validator</div>
                  <ul className="ep-inset p-4 space-y-1.5 font-mono text-xs text-ink-2">
                    <li>
                      model: &quot;
                      {activeConfigValidation.normalizedConfig?.model}
                      &quot;
                    </li>
                    <li>
                      thinking_level: &quot;
                      {
                        activeConfigValidation.normalizedConfig
                          ?.thinking_level
                      }
                      &quot;
                    </li>
                    <li>
                      background:{" "}
                      {String(
                        activeConfigValidation.normalizedConfig?.background,
                      )}
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
                          <span className="text-ink font-medium">
                            {item.id}
                          </span>
                          <span className="text-ink-3">
                            {item.trustBoundary}
                          </span>
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
                      {JSON.stringify(
                        formatCleanRunJsonForDisplay(runResult),
                        null,
                        2,
                      )}
                    </pre>
                  </div>
                )}
              </div>
            </TechDetails>
          </section>
        </InkReveal>
      </div>

      {/* 5. Knowledge search (AtlasExplorer) */}
      <ExhibitSection
        tag="Private AI library"
        title="Search what we know about private AI"
        subtitle="Simple answers on how deRoute protects your messages, with technical records and scores available on request."
      >
        <AtlasExplorer />
      </ExhibitSection>
    </>
  );
}

export default function ArgonShowcasePage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/argon" rightSlot={<AuthPill />} />

      <main id="main-content" className="flex-1 w-full min-w-0">
        <AuthGate>
          <ArgonAuthenticatedView />
        </AuthGate>
      </main>

      <SpecimenFooter />
    </div>
  );
}
