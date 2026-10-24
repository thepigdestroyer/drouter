import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/server", () => ({
  connection: async () => {},
}));

const tinfoilMocks = vi.hoisted(() => ({
  createCompletion: vi.fn(),
  ready: vi.fn(async () => {}),
  getVerificationDocument: vi.fn(async () => ({
    securityVerified: true,
    enclaveHost: "router-0.tinfoil.sh",
    releaseTag: "v0.0.167",
    releaseDigest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    codeFingerprint: "9134838da8aa4e1792566b2988820340356517c4db0c94261eb8154843e03575",
    enclaveFingerprint: "07ba19655a005e8914a8a6ff8797e9c0c317c71d50b067045b4c23d9da99e723",
    hpkePublicKey: "07ba19655a005e8914a8a6ff8797e9c0c317c71d50b067045b4c23d9da99e723",
    configRepo: "tinfoilsh/confidential-model-router",
    verifiedAt: "2026-10-24T17:00:00.000Z",
    enclaveMeasurement: {
      measurement: {
        type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
        registers: ["9134838da8aa4e17"],
      },
    },
    steps: {
      fetchDigest: { status: "success" },
      verifyCode: { status: "success" },
      verifyEnclave: { status: "success" },
      verifyCertificate: { status: "success" },
      compareMeasurements: { status: "success" },
    },
  })),
}));

vi.mock("tinfoil", () => ({
  TinfoilAI: class MockTinfoilAI {
    ready = tinfoilMocks.ready;
    getVerificationDocument = tinfoilMocks.getVerificationDocument;
    chat = {
      completions: {
        create: tinfoilMocks.createCompletion,
      },
    };
  },
}));

const creditLedgerMocks = vi.hoisted(() => ({
  verifyAndSpendCreditHeader: vi.fn(),
}));

vi.mock("@/lib/credits/ledger", () => ({
  verifyAndSpendCreditHeader: creditLedgerMocks.verifyAndSpendCreditHeader,
}));

import {
  SUPPORTED_GATEWAY_MODELS,
  buildHarnessConfigs,
  fetchLiveGatewayModels,
  parseGatewayChatRequest,
  parseTinfoilProxyModelTable,
  resetGatewayModelsCache,
} from "@/lib/gateway/harness-config";
import { GET as getModels, OPTIONS as optionsModels } from "@/app/api/v1/models/route";
import { GET as getVerify } from "@/app/api/v1/verify/route";
import {
  POST as postChatCompletions,
  OPTIONS as optionsChatCompletions,
} from "@/app/api/v1/chat/completions/route";
import { checksFromDocument } from "@/lib/tinfoil/client";
import {
  createStreamRestorer,
  parseDrouterCliArgs,
} from "../../scripts/drouter-cli.mjs";
import { PlaceholderVault } from "../../scripts/drouter-proxy.mjs";

const SAMPLE_LIVE_PROXY_TABLE = {
  updated: "2026-10-24T17:12:49Z",
  version: "v0.0.167",
  models: {
    "kimi-k3": {
      repo: "tinfoilsh/confidential-kimi-k3",
      tag: "v0.0.15",
      enclaves: {
        "kimi-k3-inf14.tinfoil.containers.tinfoil.dev": {
          hpke_key: "5df270bc",
          predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
          tls_key_fp: "6758bad9",
        },
      },
      verification: {
        observed_at: "2026-10-24T17:13:38Z",
        configured: 1,
        verified: 1,
        healthy: 1,
        unverified: 0,
      },
    },
    "glm-5-3": {
      repo: "tinfoilsh/confidential-glm5-3-nvfp4",
      tag: "v0.0.7",
      enclaves: {
        "glm-5-3-inf19-0.tinfoil.containers.tinfoil.dev": {
          hpke_key: "56126daf",
          predicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
          tls_key_fp: "30a436f4",
        },
      },
      verification: {
        observed_at: "2026-10-24T17:13:38Z",
        configured: 7,
        verified: 7,
        healthy: 7,
        unverified: 0,
      },
    },
    "gemma4-31b": {
      repo: "tinfoilsh/confidential-gemma4-31b",
      tag: "v0.0.25",
      enclaves: {
        "gemma4-31b-inf10-0.tinfoil.containers.tinfoil.dev": {
          hpke_key: "b6b44e73",
          predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
          tls_key_fp: "d81b5502",
        },
      },
      verification: {
        observed_at: "2026-10-24T17:13:38Z",
        configured: 39,
        verified: 39,
        healthy: 39,
        unverified: 0,
      },
    },
    "glm-5-3-flash": {
      repo: "tinfoilsh/confidential-glm5-3-flash",
      tag: "",
      enclaves: {},
      verification: {
        configured: 0,
        verified: 0,
        healthy: 0,
        unverified: 0,
      },
    },
    "doc-upload": {
      repo: "tinfoilsh/confidential-doc-upload",
      tag: "v0.0.39",
      enclaves: {
        "doc-upload-inf6.tinfoil.containers.tinfoil.dev": {
          hpke_key: "35a1069d",
          predicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
          tls_key_fp: "3737f708",
        },
      },
      verification: {
        configured: 1,
        verified: 1,
        healthy: 1,
      },
    },
  },
};

describe("Gateway harness-config & Live Model Table", () => {
  const origSimFlag = process.env.DROUTER_ENABLE_SIM_MODEL;
  const origStubFlag = process.env.DROUTER_STUB_UPSTREAM;

  beforeEach(() => {
    delete process.env.DROUTER_ENABLE_SIM_MODEL;
    delete process.env.DROUTER_STUB_UPSTREAM;
    resetGatewayModelsCache();
  });

  afterEach(() => {
    if (origSimFlag === undefined) delete process.env.DROUTER_ENABLE_SIM_MODEL;
    else process.env.DROUTER_ENABLE_SIM_MODEL = origSimFlag;
    if (origStubFlag === undefined) delete process.env.DROUTER_STUB_UPSTREAM;
    else process.env.DROUTER_STUB_UPSTREAM = origStubFlag;
  });

  it("excludes sim-echo-1 from production SUPPORTED_GATEWAY_MODELS", () => {
    const ids = SUPPORTED_GATEWAY_MODELS.map((m) => m.id);
    expect(ids).toContain("kimi-k3");
    expect(ids).toContain("glm-5-3");
    expect(ids).toContain("gemma4-31b");
    expect(ids).not.toContain("sim-echo-1");
  });

  it("parses Tinfoil's live proxy table and filters out non-model services and 0-host entries", async () => {
    const parsed = parseTinfoilProxyModelTable(SAMPLE_LIVE_PROXY_TABLE);
    const ids = parsed.map((m) => m.id);
    expect(ids).toEqual(["kimi-k3", "glm-5-3", "gemma4-31b"]);
    expect(ids).not.toContain("doc-upload");
    expect(ids).not.toContain("glm-5-3-flash");
    expect(ids).not.toContain("sim-echo-1");

    const mockFetch = vi.fn(async () => new Response(JSON.stringify(SAMPLE_LIVE_PROXY_TABLE), { status: 200 }));
    const liveProd = await fetchLiveGatewayModels({
      fetchImpl: mockFetch as unknown as typeof fetch,
    });
    expect(liveProd.map((m) => m.id)).toEqual(["kimi-k3", "glm-5-3", "gemma4-31b"]);
  });

  it("normalizes string content and applies defaults in parseGatewayChatRequest", () => {
    const res = parseGatewayChatRequest({
      messages: [
        { role: "system", content: "You are a helpful coding assistant." },
        { role: "user", content: "Write a test." },
      ],
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.model).toBe("kimi-k3");
      expect(res.stream).toBe(false);
      expect(res.scrubPii).toBe(false);
      expect(res.messages).toEqual([
        { role: "system", content: "You are a helpful coding assistant." },
        { role: "user", content: "Write a test." },
      ]);
    }
  });

  it("normalizes multi-part array content blocks and tool calls from OpenAI SDK harnesses", () => {
    const res = parseGatewayChatRequest({
      model: "drouter/glm-5-3",
      stream: true,
      temperature: 0.2,
      max_tokens: 512,
      scrub_pii: true,
      tools: [
        {
          type: "function",
          function: {
            name: "lookup_cohort",
            description: "Look up cohort record",
            parameters: { type: "object", properties: { id: { type: "string" } } },
          },
        },
      ],
      tool_choice: "auto",
      messages: [
        {
          role: "developer",
          content: [{ type: "text", text: "System instruction part 1" }],
        },
        {
          role: "user",
          content: [
            { type: "text", text: "First block" },
            "Second string block",
            { input_text: "Third input_text block" },
          ],
        },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_abc123",
              type: "function",
              function: { name: "lookup_cohort", arguments: '{"id":"RTH-1"}' },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_abc123",
          content: '{"status":"verified"}',
        },
      ],
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.model).toBe("glm-5-3");
      expect(res.stream).toBe(true);
      expect(res.temperature).toBe(0.2);
      expect(res.max_tokens).toBe(512);
      expect(res.scrubPii).toBe(true);
      expect(res.tools).toHaveLength(1);
      expect(res.tool_choice).toBe("auto");
      expect(res.messages[2].role).toBe("assistant");
      expect(res.messages[2].content).toBeNull();
      expect(res.messages[2].tool_calls?.[0].id).toBe("call_abc123");
      expect(res.messages[3]).toEqual({
        role: "tool",
        tool_call_id: "call_abc123",
        content: '{"status":"verified"}',
      });
    }
  });

  it("rejects invalid requests and blocks sim-echo-1 unconditionally", () => {
    expect(parseGatewayChatRequest(null).ok).toBe(false);
    expect(parseGatewayChatRequest({}).ok).toBe(false);
    expect(parseGatewayChatRequest({ messages: [] }).ok).toBe(false);
    expect(
      parseGatewayChatRequest({
        model: "non-existent-model",
        messages: [{ role: "user", content: "hi" }],
      }).ok,
    ).toBe(false);
    expect(
      parseGatewayChatRequest({
        model: "kimi-k3",
        messages: [{ role: "invalid-role", content: "hi" }],
      }).ok,
    ).toBe(false);

    // sim-echo-1 is rejected unconditionally
    const simBlocked = parseGatewayChatRequest({
      model: "sim-echo-1",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(simBlocked.ok).toBe(false);
  });

  it("builds valid OpenCode JSON and explicitly documents blind-credit auth in buildHarnessConfigs", () => {
    const configs = buildHarnessConfigs("https://drouter-demo.vercel.app/");
    const parsedOpencode = JSON.parse(configs.opencodeJson);
    expect(parsedOpencode.provider.drouter.options.baseURL).toBe(
      "https://drouter-demo.vercel.app/api/v1",
    );
    expect(parsedOpencode.provider.drouter.options._authNote).toContain(
      "any apiKey value works, auth is the blind credit header",
    );
    expect(parsedOpencode.provider.drouter.models["kimi-k3"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["glm-5-3"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["deepseek-v4-1-flash"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["gpt-oss-120b"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["llama3-3-70b"]).toBeDefined();
    expect(configs.curlCommand).toContain("https://drouter-demo.vercel.app/api/v1/chat/completions");
    expect(configs.curlCommand).toContain("auth is the blind credit header");
    expect(configs.openaiEnvExports).toContain(
      'export OPENAI_BASE_URL="https://drouter-demo.vercel.app/api/v1"',
    );
    expect(configs.openaiEnvExports).toContain("auth is the blind credit header");
    expect(configs.pythonSnippet).toContain("auth is the blind credit header");
    expect(configs.typescriptSnippet).toContain("auth is the blind credit header");
    expect(configs.localProxyCommand).toBe(
      "node scripts/drouter-cli.mjs proxy --port 4141 --upstream https://drouter-demo.vercel.app",
    );
  });
});

describe("OpenAI-Compatible Gateway Routes (/api/v1/*)", () => {
  const origApiKey = process.env.TINFOIL_API_KEY;
  const origSimFlag = process.env.DROUTER_ENABLE_SIM_MODEL;

  beforeEach(() => {
    process.env.TINFOIL_API_KEY = "test-tinfoil-key-do-not-print";
    delete process.env.DROUTER_ENABLE_SIM_MODEL;
    delete process.env.DROUTER_STUB_UPSTREAM;
    resetGatewayModelsCache();
    tinfoilMocks.createCompletion.mockReset();
    creditLedgerMocks.verifyAndSpendCreditHeader.mockReset();
  });

  afterEach(() => {
    if (origApiKey === undefined) delete process.env.TINFOIL_API_KEY;
    else process.env.TINFOIL_API_KEY = origApiKey;
    if (origSimFlag === undefined) delete process.env.DROUTER_ENABLE_SIM_MODEL;
    else process.env.DROUTER_ENABLE_SIM_MODEL = origSimFlag;
  });

  it("GET /api/v1/models returns live Tinfoil models without sim-echo-1 in production", async () => {
    const res = await getModels();
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = await res.json();
    expect(body.object).toBe("list");
    expect(body.data.length).toBeGreaterThanOrEqual(5);
    const ids = body.data.map((m: { id: string }) => m.id);
    expect(ids).toContain("kimi-k3");
    expect(ids).toContain("gemma4-31b");
    expect(ids).not.toContain("sim-echo-1");
    expect(body.data.every((m: { enclave_attested: boolean }) => m.enclave_attested === true)).toBe(
      true,
    );

    const optRes = await optionsModels();
    expect(optRes.status).toBe(204);
    expect(optRes.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("GET /api/v1/verify returns C1 to C7 with identical labels to src/lib/tinfoil/client.ts", async () => {
    const req = new Request("http://localhost:3000/api/v1/verify?model=kimi-k3");
    const res = await getVerify(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.attestation).not.toBeNull();
    expect(body.attestation.checks).toHaveLength(7);

    const expectedChecks = checksFromDocument(
      (await tinfoilMocks.getVerificationDocument()) as unknown as Parameters<
        typeof checksFromDocument
      >[0],
    );
    expect(body.attestation.checks.map((c: { id: string; label: string }) => `${c.id}:${c.label}`)).toEqual(
      expectedChecks.map((c) => `${c.id}:${c.label}`),
    );
  });

  it("verifies x-drouter-credit header (I2), records nullifier, and rejects invalid/double-spent credits", async () => {
    creditLedgerMocks.verifyAndSpendCreditHeader.mockResolvedValueOnce({
      ok: true,
      nullifier: "nullifier_abc123",
      denomination: 5,
      remainingPoolUnredeemed: 1,
    });

    tinfoilMocks.createCompletion.mockResolvedValueOnce({
      id: "chatcmpl-credit-1",
      object: "chat.completion",
      created: 1792800000,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: "Confirmed receipt for [EMAIL_1].",
          },
          finish_reason: "stop",
        },
      ],
    });

    const validReq = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-drouter-credit": '{"token":"aa","signature":"bb","denomination":5}',
      },
      body: JSON.stringify({
        model: "kimi-k3",
        stream: false,
        messages: [{ role: "user", content: "Contact dana.reyes@example.org please." }],
      }),
    });

    const validRes = await postChatCompletions(validReq);
    expect(validRes.status).toBe(200);
    expect(creditLedgerMocks.verifyAndSpendCreditHeader).toHaveBeenCalledWith(
      '{"token":"aa","signature":"bb","denomination":5}',
      "kimi-k3",
    );
    expect(validRes.headers.get("X-DRouter-Credit-Verified")).toBe("true");
    expect(validRes.headers.get("X-DRouter-Credit-Nullifier")).toBe("nullifier_abc123");
    expect(validRes.headers.get("X-DRouter-Credit-Denomination")).toBe("5");
    expect(validRes.headers.get("X-DRouter-Redactions")).toBe("1");

    // Verify PII was scrubbed before TinfoilAI saw it, and restored in the response
    const sentParams = tinfoilMocks.createCompletion.mock.calls[0][0];
    expect(sentParams.messages[0].content).toBe("Contact [EMAIL_1] please.");
    const validJson = await validRes.json();
    expect(validJson.choices[0].message.content).toBe(
      "Confirmed receipt for dana.reyes@example.org.",
    );

    // Double-spent credit token -> 409
    creditLedgerMocks.verifyAndSpendCreditHeader.mockResolvedValueOnce({
      ok: false,
      error: "Double-spend rejected: credit nullifier already spent",
      status: 409,
    });

    const replayReq = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-drouter-credit": '{"token":"aa","signature":"bb","denomination":5}',
      },
      body: JSON.stringify({
        model: "kimi-k3",
        messages: [{ role: "user", content: "Replay attempt" }],
      }),
    });

    const replayRes = await postChatCompletions(replayReq);
    expect(replayRes.status).toBe(409);
    const replayJson = await replayRes.json();
    expect(replayJson.error.message).toContain("Double-spend rejected");
    expect(tinfoilMocks.createCompletion).toHaveBeenCalledTimes(1);
  });

  it("streams SSE chunks from Tinfoil, restores split PII placeholders across chunks, and passes tool calls through", async () => {
    tinfoilMocks.createCompletion.mockImplementationOnce(async () => {
      async function* gen() {
        yield {
          id: "chatcmpl-stream-1",
          object: "chat.completion.chunk",
          created: 1792800000,
          model: "kimi-k3",
          choices: [{ index: 0, delta: { content: "Replying to [EMA" }, finish_reason: null }],
        };
        yield {
          id: "chatcmpl-stream-1",
          object: "chat.completion.chunk",
          created: 1792800000,
          model: "kimi-k3",
          choices: [
            {
              index: 0,
              delta: {
                content: "IL_1] now.",
                tool_calls: [
                  {
                    index: 0,
                    id: "call_1",
                    type: "function",
                    function: { name: "notify", arguments: '{"recipient":"[EMAIL_1]"}' },
                  },
                ],
              },
              finish_reason: "tool_calls",
            },
          ],
        };
      }
      return gen();
    });

    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "kimi-k3",
        stream: true,
        tools: [{ type: "function", function: { name: "notify", parameters: {} } }],
        messages: [{ role: "user", content: "Notify dana.reyes@example.org immediately." }],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
    expect(res.headers.get("X-DRouter-Attested")).toBe("true");
    expect(res.headers.get("X-DRouter-Redactions")).toBe("1");

    const rawSse = await res.text();
    expect(rawSse).toContain("dana.reyes@example.org");
    expect(rawSse).not.toContain("[EMAIL_1]");
    expect(rawSse).toContain("data: [DONE]");
  });

  it("POST /api/v1/chat/completions rejects simulated model sim-echo-1 with 400", async () => {
    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "sim-echo-1",
        stream: false,
        messages: [
          {
            role: "user",
            content: [{ type: "text", text: "Hello from OpenCode harness!" }],
          },
        ],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error.message).toContain("Unsupported model");

    const optRes = await optionsChatCompletions();
    expect(optRes.status).toBe(204);
  });
});

describe("drouter-cli & drouter-proxy shared helpers", () => {
  it("parses ask, proxy, verify, and config commands including --credit", () => {
    const askArgs = parseDrouterCliArgs([
      "ask",
      "Explain SEV-SNP",
      "--model",
      "glm-5-3",
      "--upstream",
      "http://localhost:3000/",
      "--credit",
      "1:aa:bb",
    ]);
    expect(askArgs.command).toBe("ask");
    expect(askArgs.prompt).toBe("Explain SEV-SNP");
    expect(askArgs.model).toBe("glm-5-3");
    expect(askArgs.upstream).toBe("http://localhost:3000");
    expect(askArgs.credit).toBe("1:aa:bb");

    const proxyArgs = parseDrouterCliArgs(["proxy", "--port", "4242"]);
    expect(proxyArgs.command).toBe("proxy");
    expect(proxyArgs.port).toBe(4242);
  });

  it("restores [[DROUTER_EMAIL_1]] placeholders split across multiple streaming chunks", () => {
    const vault = new PlaceholderVault();
    const scrubbed = vault.scrub("Contact dana.reyes@example.org");
    expect(scrubbed).toBe("Contact [[DROUTER_EMAIL_1]]");

    const restorer = createStreamRestorer(vault);
    const out1 = restorer.push("The email is [");
    const out2 = restorer.push("[DROUTER_EMAIL_1]");
    const out3 = restorer.push("].");
    const out4 = restorer.flush();

    expect(out1 + out2 + out3 + out4).toBe("The email is dana.reyes@example.org.");
  });
});
