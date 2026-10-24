import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CANARY_BATTERY,
  MAX_CALLS_PER_AUDIT,
  type TinfoilAuditClient,
  type TinfoilCompletionResponse,
  clearMemoryAuditorRuns,
  executeMysteryShopperAudit,
  getAuditorRunsHistory,
  matchesAdvertisedModel,
  runSprtModelAudit,
  saveAuditorRun,
  scoreCanaryResponse,
  setCronAuditorTestClient,
} from "@/lib/auditor";
import { GET as getAuditorRoute } from "@/app/api/auditor/route";
import { GET as getCronAuditorRoute } from "@/app/api/cron/auditor/route";

vi.mock("next/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/server")>();
  return {
    ...actual,
    connection: async () => {},
  };
});

function createMockTinfoilClient(
  mode: "honest" | "downgraded-wrong-answer" | "downgraded-wrong-model",
  model = "kimi-k3",
): { client: TinfoilAuditClient; calls: number } {
  let calls = 0;

  const honestAnswers: Record<string, string> = {
    "canary-CRT-mod-210": '{"answer":"53"}',
    "canary-matrix-trace-det": '{"det":72,"trace":13}',
    "canary-boolean-horn-sat": '{"P":true,"Q":true,"R":true,"S":false}',
  };

  const client: TinfoilAuditClient = {
    async ready() {},
    async getVerificationDocument() {
      return {
        enclaveHost: "router-0.tinfoil.sh",
        releaseTag: "v1.0.0",
        securityVerified: true,
      };
    },
    chat: {
      completions: {
        async create(params) {
          calls += 1;
          await new Promise((r) => setTimeout(r, 8));
          const userMsg = params.messages.find((m) => m.role === "user")?.content ?? "";
          let matchedProbeId = "canary-CRT-mod-210";
          for (const spec of CANARY_BATTERY) {
            if (userMsg === spec.userPrompt) {
              matchedProbeId = spec.probeId;
              break;
            }
          }

          const content =
            mode === "downgraded-wrong-answer"
              ? '{"answer":"41"}'
              : honestAnswers[matchedProbeId] ?? '{"answer":"0"}';

          const echoedModel =
            mode === "downgraded-wrong-model" ? "qwen-0.5b-distill" : params.model || model;

          const resp: TinfoilCompletionResponse = {
            id: `chatcmpl-mock-${calls}`,
            model: echoedModel,
            choices: [
              {
                index: 0,
                message: {
                  role: "assistant",
                  content,
                },
                finish_reason: "stop",
              },
            ],
            usage: {
              prompt_tokens: 48,
              completion_tokens: 12,
              total_tokens: 60,
            },
          };
          return resp;
        },
      },
    },
  };

  return {
    get calls() {
      return calls;
    },
    client,
  };
}

describe("Mystery-Shopper Statistical Model Auditor (SPRT & Live Scoring)", () => {
  beforeEach(() => {
    clearMemoryAuditorRuns();
    setCronAuditorTestClient(undefined);
    delete process.env.MONGODB_URI;
  });

  it("certifies an honest kimi-k3 probe stream as PASS_GENUINE_FRONTIER_MODEL", () => {
    const honestPattern = [
      true, true, true, true, true, false, true, true, true, true, true, true, true, true, true,
    ];
    const probes = honestPattern.map((passed, idx) => ({
      probeId: `probe-honest-${idx + 1}`,
      passed,
      latencyMs: 620,
    }));
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("PASS_GENUINE_FRONTIER_MODEL");
    expect(result.logLikelihoodRatio).toBeLessThanOrEqual(result.lowerBoundB);
    expect(result.probesEvaluated).toBeGreaterThan(0);
    expect(result.probesEvaluated).toBeLessThanOrEqual(15);
    expect(result.empiricalPassRate).toBeGreaterThanOrEqual(0.85);
  });

  it("detects a cheating 8B-swap provider with SLASH_MODEL_DOWNGRADE_DETECTED within 15 probes", () => {
    const cheatingPattern = [
      false, true, false, false, false, true, false, false, false, true, false, false, true, false, false,
    ];
    const probes = cheatingPattern.map((passed, idx) => ({
      probeId: `probe-cheat-${idx + 1}`,
      passed,
      latencyMs: 180,
    }));
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("SLASH_MODEL_DOWNGRADE_DETECTED");
    expect(result.logLikelihoodRatio).toBeGreaterThanOrEqual(result.upperBoundA);
    expect(result.probesEvaluated).toBeLessThanOrEqual(15);
    expect(result.empiricalPassRate).toBeLessThan(0.5);
  });

  it("returns CONTINUE_SAMPLING when probe count is insufficient to cross either threshold", () => {
    const probes = [
      { probeId: "probe-1", passed: true, latencyMs: 600 },
      { probeId: "probe-2", passed: false, latencyMs: 610 },
      { probeId: "probe-3", passed: true, latencyMs: 590 },
    ];
    const result = runSprtModelAudit(probes);

    expect(result.verdict).toBe("CONTINUE_SAMPLING");
    expect(result.probesEvaluated).toBe(3);
    expect(result.logLikelihoodRatio).toBeGreaterThan(result.lowerBoundB);
    expect(result.logLikelihoodRatio).toBeLessThan(result.upperBoundA);
  });

  it("scores canary responses with exact-answer, JSON format, model echo, token counts, and latency signals", () => {
    const spec = CANARY_BATTERY[0];
    const goodScore = scoreCanaryResponse(
      spec,
      "kimi-k3",
      {
        model: "kimi-k3-0711",
        choices: [{ message: { content: '{"answer":"53"}' } }],
        usage: { prompt_tokens: 45, completion_tokens: 8, total_tokens: 53 },
      },
      125,
    );
    expect(goodScore.passed).toBe(true);
    expect(goodScore.answerMatched).toBe(true);
    expect(goodScore.formatValid).toBe(true);
    expect(goodScore.modelEchoMatched).toBe(true);
    expect(goodScore.tokenCountsValid).toBe(true);
    expect(goodScore.latencyValid).toBe(true);

    // Wrong answer fails
    const badAnswer = scoreCanaryResponse(
      spec,
      "kimi-k3",
      {
        model: "kimi-k3",
        choices: [{ message: { content: '{"answer":"52"}' } }],
        usage: { prompt_tokens: 45, completion_tokens: 8 },
      },
      125,
    );
    expect(badAnswer.passed).toBe(false);
    expect(badAnswer.answerMatched).toBe(false);

    // Markdown fence fails strict format check
    const badFormat = scoreCanaryResponse(
      spec,
      "kimi-k3",
      {
        model: "kimi-k3",
        choices: [{ message: { content: '```json\n{"answer":"53"}\n```' } }],
        usage: { prompt_tokens: 45, completion_tokens: 8 },
      },
      125,
    );
    expect(badFormat.passed).toBe(false);
    expect(badFormat.formatValid).toBe(false);

    // Swapped model ID echo fails
    const badModel = scoreCanaryResponse(
      spec,
      "kimi-k3",
      {
        model: "llama-3-8b-instruct",
        choices: [{ message: { content: '{"answer":"53"}' } }],
        usage: { prompt_tokens: 45, completion_tokens: 8 },
      },
      125,
    );
    expect(badModel.passed).toBe(false);
    expect(badModel.modelEchoMatched).toBe(false);
  });

  it("matches advertised model families accurately", () => {
    expect(matchesAdvertisedModel("kimi-k3", "kimi-k3")).toBe(true);
    expect(matchesAdvertisedModel("kimi-k3", "moonshotai/Kimi-K3-Instruct")).toBe(true);
    expect(matchesAdvertisedModel("llama3-3-70b", "meta-llama/Llama-3.3-70B-Instruct")).toBe(true);
    expect(matchesAdvertisedModel("kimi-k3", "qwen-2.5-7b")).toBe(false);
  });

  it("executes a 3-call battery with a mocked Tinfoil SDK and stores only coarsened aggregate results", async () => {
    const mock = createMockTinfoilClient("honest", "kimi-k3");
    const exactNow = new Date("2026-10-24T14:37:42.987Z");

    const result = await executeMysteryShopperAudit({
      model: "kimi-k3",
      client: mock.client,
      now: exactNow,
    });

    expect(mock.calls).toBe(MAX_CALLS_PER_AUDIT);
    expect(mock.calls).toBeLessThanOrEqual(3);
    expect(result.run.model).toBe("kimi-k3");
    expect(result.run.passed).toBe(true);
    expect(result.run.probesCount).toBe(3);
    expect(result.run.passedCount).toBe(3);
    expect(result.run.sprtStatistic).toBeCloseTo(3 * Math.log(0.45 / 0.9), 5);
    // Verify timestamp is coarsened to the start of the UTC hour
    expect(result.run.at.toISOString()).toBe("2026-10-24T14:00:00.000Z");
    // Verify no raw prompt or completion text is stored in the aggregate record
    expect("messages" in result.run).toBe(false);
    expect("prompt" in result.run).toBe(false);
    expect("completion" in result.run).toBe(false);
  });

  it("crosses SLASH_MODEL_DOWNGRADE_DETECTED after sequential failed batteries", async () => {
    const badMock = createMockTinfoilClient("downgraded-wrong-answer", "kimi-k3");

    const batch1 = await executeMysteryShopperAudit({
      model: "kimi-k3",
      client: badMock.client,
      initialLlr: 0,
    });
    expect(batch1.run.passed).toBe(false);
    expect(batch1.run.passedCount).toBe(0);
    expect(batch1.run.verdict).toBe("CONTINUE_SAMPLING");

    // Second sequential 3-call battery starting from batch1 cumulative LLR crosses upperBoundA
    const batch2 = await executeMysteryShopperAudit({
      model: "kimi-k3",
      client: badMock.client,
      initialLlr: batch1.run.cumulativeSprtStatistic,
    });
    expect(batch2.run.passed).toBe(false);
    expect(batch2.run.verdict).toBe("SLASH_MODEL_DOWNGRADE_DETECTED");
    expect(batch2.run.cumulativeSprtStatistic).toBeGreaterThanOrEqual(batch2.run.upperBoundA);
  });

  it("GET /api/auditor reports hasRun=false and no fabricated runs when history is empty", async () => {
    const res = await getAuditorRoute(new Request("http://localhost/api/auditor"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      hasRun: boolean;
      latestRun: unknown;
      history: unknown[];
      statusMessage: string;
    };
    expect(body.hasRun).toBe(false);
    expect(body.latestRun).toBeNull();
    expect(body.history).toEqual([]);
    expect(body.statusMessage).toContain("No real mystery-shopper audit run");
  });

  it("GET /api/cron/auditor enforces Authorization: Bearer ${CRON_SECRET} and saves aggregate run", async () => {
    process.env.CRON_SECRET = "test-cron-secret-999";
    const mock = createMockTinfoilClient("honest", "kimi-k3");
    setCronAuditorTestClient(mock.client);

    // Reject missing header
    const unauthRes = await getCronAuditorRoute(
      new Request("http://localhost/api/cron/auditor"),
    );
    expect(unauthRes.status).toBe(401);
    expect(mock.calls).toBe(0);

    // Reject wrong token
    const wrongRes = await getCronAuditorRoute(
      new Request("http://localhost/api/cron/auditor", {
        headers: { authorization: "Bearer wrong-secret" },
      }),
    );
    expect(wrongRes.status).toBe(401);
    expect(mock.calls).toBe(0);

    // Accept valid Bearer token
    const okRes = await getCronAuditorRoute(
      new Request("http://localhost/api/cron/auditor?model=kimi-k3", {
        headers: { authorization: "Bearer test-cron-secret-999" },
      }),
    );
    expect(okRes.status).toBe(200);
    expect(mock.calls).toBe(3);

    const cronBody = (await okRes.json()) as {
      ok: boolean;
      run: { model: string; passed: boolean; probesCount: number };
    };
    expect(cronBody.ok).toBe(true);
    expect(cronBody.run.model).toBe("kimi-k3");
    expect(cronBody.run.passed).toBe(true);
    expect(cronBody.run.probesCount).toBe(3);

    // Verify /api/auditor now returns the real recorded run
    const historyState = await getAuditorRunsHistory();
    expect(historyState.hasRun).toBe(true);
    expect(historyState.latestRun?.model).toBe("kimi-k3");
    expect(historyState.history.length).toBe(1);

    await saveAuditorRun(cronBody.run as never);
    const updatedRes = await getAuditorRoute(new Request("http://localhost/api/auditor"));
    const updatedBody = (await updatedRes.json()) as {
      hasRun: boolean;
      history: unknown[];
    };
    expect(updatedBody.hasRun).toBe(true);
    expect(updatedBody.history.length).toBe(2);
  });
});
