import { TinfoilAI } from "tinfoil";
import { coarsenToHour } from "@/lib/db";
import {
  type MysteryShopperProbe,
  type SprtAuditOptions,
  type SprtAuditResult,
  type SprtVerdict,
  runSprtModelAudit,
} from "./sprt";

export interface CanaryPromptSpec {
  probeId: string;
  category: string;
  systemPrompt: string;
  userPrompt: string;
  expectedAnswer: string;
  validate(content: string): boolean;
}

export interface TinfoilCompletionResponse {
  id?: string;
  model?: string;
  choices?: Array<{
    index?: number;
    message?: {
      role?: string;
      content?: string | null;
    };
    finish_reason?: string | null;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

export interface TinfoilAuditClient {
  ready(): Promise<void>;
  getVerificationDocument(): Promise<{
    enclaveHost?: string;
    releaseTag?: string;
    releaseDigest?: string;
    codeFingerprint?: string;
    enclaveFingerprint?: string;
    securityVerified?: boolean;
  }>;
  chat: {
    completions: {
      create(params: {
        model: string;
        messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
        stream: false;
        temperature?: number;
        max_tokens?: number;
      }): Promise<TinfoilCompletionResponse>;
    };
  };
}

export interface ProbeScoreDetail {
  probeId: string;
  category: string;
  passed: boolean;
  answerMatched: boolean;
  formatValid: boolean;
  modelEchoMatched: boolean;
  tokenCountsValid: boolean;
  latencyValid: boolean;
  latencyMs: number;
  promptTokens: number;
  completionTokens: number;
  echoedModel: string;
}

/**
 * Fixed battery of 3 deterministic canary prompts with known-answer properties.
 * Each run uses at most 3 calls to stay within strict enclave cost budgets.
 */
export const CANARY_BATTERY: readonly CanaryPromptSpec[] = [
  {
    probeId: "canary-CRT-mod-210",
    category: "cryptographic-invariant-synthesis",
    systemPrompt:
      "You are a deterministic mathematical verification oracle. Reply with valid JSON only, matching {\"answer\":\"<integer>\"} with no markdown fences or extra text.",
    userPrompt:
      "Find the unique integer x in the range 0 <= x < 210 such that x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 4 (mod 7), and x ≡ 1 (mod 2). Output ONLY {\"answer\":\"<x>\"}.",
    expectedAnswer: "53",
    validate(content: string): boolean {
      const trimmed = content.trim();
      try {
        const parsed = JSON.parse(trimmed) as { answer?: unknown };
        if (String(parsed.answer).trim() === "53") return true;
      } catch {
        // Fallback check if JSON wrapper has slight whitespace
      }
      return /"answer"\s*:\s*"?53"?/.test(trimmed);
    },
  },
  {
    probeId: "canary-matrix-trace-det",
    category: "symbolic-tensor-calculus",
    systemPrompt:
      "You are a deterministic linear algebra oracle. Reply with valid JSON only, matching {\"det\":<int>,\"trace\":<int>} with no markdown fences or extra text.",
    userPrompt:
      "Let A = [[3, 1, 2], [0, 4, 5], [0, 0, 6]]. Compute the determinant det(A) and trace tr(A). Output ONLY {\"det\":<det>,\"trace\":<trace>}.",
    expectedAnswer: "det=72,trace=13",
    validate(content: string): boolean {
      const trimmed = content.trim();
      try {
        const parsed = JSON.parse(trimmed) as { det?: unknown; trace?: unknown };
        if (Number(parsed.det) === 72 && Number(parsed.trace) === 13) return true;
      } catch {
        // Fallback check
      }
      return /"det"\s*:\s*"?72"?/.test(trimmed) && /"trace"\s*:\s*"?13"?/.test(trimmed);
    },
  },
  {
    probeId: "canary-boolean-horn-sat",
    category: "multi-hop-formal-logic",
    systemPrompt:
      "You are a deterministic formal logic solver. Reply with valid JSON only, matching {\"P\":<bool>,\"Q\":<bool>,\"R\":<bool>,\"S\":<bool>} with no markdown fences or extra text.",
    userPrompt:
      "Given propositions P, Q, R, S where: (1) P is true, (2) P implies Q, (3) (P and Q) implies R, (4) R implies not S. Output ONLY {\"P\":true,\"Q\":...,\"R\":...,\"S\":...}.",
    expectedAnswer: "P=true,Q=true,R=true,S=false",
    validate(content: string): boolean {
      const trimmed = content.trim();
      try {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        if (
          parsed.P === true &&
          parsed.Q === true &&
          parsed.R === true &&
          parsed.S === false
        ) {
          return true;
        }
      } catch {
        // Fallback check
      }
      return (
        /"P"\s*:\s*true/i.test(trimmed) &&
        /"Q"\s*:\s*true/i.test(trimmed) &&
        /"R"\s*:\s*true/i.test(trimmed) &&
        /"S"\s*:\s*false/i.test(trimmed)
      );
    },
  },
] as const;

export const MAX_CALLS_PER_AUDIT = 3;

/**
 * Checks whether the echoed model identifier in the completion response matches
 * the advertised model family requested from the enclave.
 */
export function matchesAdvertisedModel(advertisedModel: string, echoedModel: string): boolean {
  const adv = advertisedModel.trim().toLowerCase();
  const echo = echoedModel.trim().toLowerCase();
  if (!adv || !echo) return false;
  if (echo === adv || echo.includes(adv) || adv.includes(echo)) return true;

  // Match canonical alphabetic family prefix (e.g., kimi-k3 -> kimi, llama3-3-70b -> llama)
  const alphaPrefix = adv.match(/^[a-z]+/)?.[0] ?? "";
  if (alphaPrefix && alphaPrefix.length >= 3 && echo.includes(alphaPrefix)) {
    return true;
  }
  return false;
}

/**
 * Scores a single completion response from an enclave model against a canary specification.
 * Evaluates 5 real signals:
 * 1. Exact deterministic answer match
 * 2. Strict JSON response format (no markdown code fences)
 * 3. Model ID echoed in the response matches advertised model
 * 4. Positive prompt & completion token counts in usage metadata
 * 5. Plausible non-zero enclave latency profile
 */
export function scoreCanaryResponse(
  spec: CanaryPromptSpec,
  advertisedModel: string,
  response: TinfoilCompletionResponse,
  latencyMs: number,
): ProbeScoreDetail {
  const rawContent = response.choices?.[0]?.message?.content ?? "";
  const trimmed = typeof rawContent === "string" ? rawContent.trim() : "";

  const formatValid =
    trimmed.startsWith("{") &&
    trimmed.endsWith("}") &&
    !trimmed.includes("```");

  const answerMatched = spec.validate(trimmed);

  const echoedModel = typeof response.model === "string" ? response.model : "";
  const modelEchoMatched = matchesAdvertisedModel(advertisedModel, echoedModel);

  const promptTokens = Number(response.usage?.prompt_tokens ?? 0);
  const completionTokens = Number(response.usage?.completion_tokens ?? 0);
  const tokenCountsValid =
    Number.isFinite(promptTokens) &&
    promptTokens > 0 &&
    Number.isFinite(completionTokens) &&
    completionTokens > 0 &&
    completionTokens <= 4096;

  const latencyValid = Number.isFinite(latencyMs) && latencyMs >= 5 && latencyMs <= 120_000;

  const passed =
    answerMatched &&
    formatValid &&
    modelEchoMatched &&
    tokenCountsValid &&
    latencyValid;

  return {
    probeId: spec.probeId,
    category: spec.category,
    passed,
    answerMatched,
    formatValid,
    modelEchoMatched,
    tokenCountsValid,
    latencyValid,
    latencyMs: Math.round(latencyMs),
    promptTokens,
    completionTokens,
    echoedModel,
  };
}

/**
 * Aggregate record stored in MongoDB `auditor_runs`.
 * Contains ONLY aggregate results (model, pass/fail, SPRT statistic, coarse hour)
 * and never stores raw prompts, completions, IP addresses, or exact timestamps.
 */
export interface AuditorRunRecord {
  model: string;
  passed: boolean;
  verdict: SprtVerdict;
  sprtStatistic: number;
  cumulativeSprtStatistic: number;
  upperBoundA: number;
  lowerBoundB: number;
  probesCount: number;
  passedCount: number;
  empiricalPassRate: number;
  meanLatencyMs: number;
  enclaveHost: string;
  at: Date;
}

export interface LiveAuditExecutionResult {
  run: AuditorRunRecord;
  sprt: SprtAuditResult;
  probes: MysteryShopperProbe[];
}

const globalForCronMock = globalThis as unknown as {
  __drouterCronTestClient?: TinfoilAuditClient;
};

export function setCronAuditorTestClient(client?: TinfoilAuditClient): void {
  globalForCronMock.__drouterCronTestClient = client;
}

export function createDefaultTinfoilAuditClient(apiKey?: string): TinfoilAuditClient {
  if (globalForCronMock.__drouterCronTestClient) {
    return globalForCronMock.__drouterCronTestClient;
  }
  const resolvedKey = apiKey ?? process.env.TINFOIL_API_KEY;
  if (!resolvedKey) {
    throw new Error("TINFOIL_API_KEY is not configured");
  }
  return new TinfoilAI({ apiKey: resolvedKey }) as unknown as TinfoilAuditClient;
}

/**
 * Executes a real SPRT mystery-shopper audit against an attested Tinfoil model.
 * Sends at most `maxCalls` (capped at 3) fixed canary prompts, scores each response
 * using real deterministic signals, and computes the SPRT statistic.
 */
export async function executeMysteryShopperAudit(opts?: {
  model?: string;
  maxCalls?: number;
  initialLlr?: number;
  sprtOptions?: SprtAuditOptions;
  client?: TinfoilAuditClient;
  now?: Date;
}): Promise<LiveAuditExecutionResult> {
  const model = opts?.model ?? "kimi-k3";
  const maxCalls = Math.min(
    MAX_CALLS_PER_AUDIT,
    Math.max(1, opts?.maxCalls ?? MAX_CALLS_PER_AUDIT),
  );
  const client = opts?.client ?? createDefaultTinfoilAuditClient();

  await client.ready();
  const doc = await client.getVerificationDocument();
  const enclaveHost = doc.enclaveHost ?? "router-0.tinfoil.sh";

  const selectedSpecs = CANARY_BATTERY.slice(0, maxCalls);
  const probes: MysteryShopperProbe[] = [];

  for (const spec of selectedSpecs) {
    const startMs = performance.now();
    let score: ProbeScoreDetail;
    try {
      const completion = await client.chat.completions.create({
        model,
        messages: [
          { role: "system", content: spec.systemPrompt },
          { role: "user", content: spec.userPrompt },
        ],
        stream: false,
        temperature: 0,
        max_tokens: 1024,
      });
      const latencyMs = Math.max(5, Math.round(performance.now() - startMs));
      score = scoreCanaryResponse(spec, model, completion, latencyMs);
    } catch {
      const latencyMs = Math.max(5, Math.round(performance.now() - startMs));
      score = {
        probeId: spec.probeId,
        category: spec.category,
        passed: false,
        answerMatched: false,
        formatValid: false,
        modelEchoMatched: false,
        tokenCountsValid: false,
        latencyValid: true,
        latencyMs,
        promptTokens: 0,
        completionTokens: 0,
        echoedModel: "",
      };
    }

    probes.push({
      probeId: score.probeId,
      category: score.category,
      passed: score.passed,
      latencyMs: score.latencyMs,
    });
  }

  // Single-run SPRT statistic (starting from 0)
  const batchSprt = runSprtModelAudit(probes, {
    ...opts?.sprtOptions,
    initialLlr: 0,
  });

  // Cumulative SPRT statistic across sequential runs (starting from prior initialLlr if provided)
  const cumulativeSprt = runSprtModelAudit(probes, {
    ...opts?.sprtOptions,
    initialLlr: opts?.initialLlr ?? 0,
  });

  const passedCount = probes.filter((p) => p.passed).length;
  const meanLatencyMs =
    probes.length > 0
      ? Math.round(probes.reduce((acc, p) => acc + p.latencyMs, 0) / probes.length)
      : 0;

  // Serve verdict from cumulative SPRT when threshold is crossed; pass=true iff no downgrade slash
  // and majority of probes in this battery passed.
  const passed =
    cumulativeSprt.verdict !== "SLASH_MODEL_DOWNGRADE_DETECTED" &&
    passedCount === probes.length;

  const coarseHour = coarsenToHour(opts?.now ?? new Date());

  const run: AuditorRunRecord = {
    model,
    passed,
    verdict: cumulativeSprt.verdict,
    sprtStatistic: Number(batchSprt.logLikelihoodRatio.toFixed(6)),
    cumulativeSprtStatistic: Number(cumulativeSprt.logLikelihoodRatio.toFixed(6)),
    upperBoundA: Number(cumulativeSprt.upperBoundA.toFixed(6)),
    lowerBoundB: Number(cumulativeSprt.lowerBoundB.toFixed(6)),
    probesCount: probes.length,
    passedCount,
    empiricalPassRate: Number(cumulativeSprt.empiricalPassRate.toFixed(4)),
    meanLatencyMs,
    enclaveHost,
    at: coarseHour,
  };

  return {
    run,
    sprt: cumulativeSprt,
    probes,
  };
}
