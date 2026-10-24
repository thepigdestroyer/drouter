import { describe, expect, it, vi } from "vitest";

vi.mock("next/server", () => ({
  connection: async () => {},
}));

import {
  SUPPORTED_GATEWAY_MODELS,
  buildHarnessConfigs,
  parseGatewayChatRequest,
} from "@/lib/gateway/harness-config";
import { GET as getModels, OPTIONS as optionsModels } from "@/app/api/v1/models/route";
import {
  POST as postChatCompletions,
  OPTIONS as optionsChatCompletions,
} from "@/app/api/v1/chat/completions/route";
import { parseDrouterCliArgs } from "../../scripts/drouter-cli.mjs";

describe("Gateway harness-config", () => {
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

  it("normalizes multi-part array content blocks from coding harnesses (OpenCode / Cursor)", () => {
    const res = parseGatewayChatRequest({
      model: "drouter/glm-5-3",
      stream: true,
      temperature: 0.2,
      max_tokens: 512,
      scrub_pii: true,
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
      ],
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.model).toBe("glm-5-3");
      expect(res.stream).toBe(true);
      expect(res.temperature).toBe(0.2);
      expect(res.max_tokens).toBe(512);
      expect(res.scrubPii).toBe(true);
      expect(res.messages).toEqual([
        { role: "system", content: "System instruction part 1" },
        {
          role: "user",
          content: "First block\nSecond string block\nThird input_text block",
        },
      ]);
    }
  });

  it("rejects invalid requests in parseGatewayChatRequest", () => {
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
  });

  it("builds valid OpenCode JSON and harness configs in buildHarnessConfigs", () => {
    const configs = buildHarnessConfigs("https://drouter-demo.vercel.app/");
    const parsedOpencode = JSON.parse(configs.opencodeJson);
    expect(parsedOpencode.provider.drouter.options.baseURL).toBe(
      "https://drouter-demo.vercel.app/api/v1",
    );
    expect(parsedOpencode.provider.drouter.models["kimi-k3"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["glm-5-3"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["deepseek-v4-1-flash"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["gpt-oss-120b"]).toBeDefined();
    expect(parsedOpencode.provider.drouter.models["llama3-3-70b"]).toBeDefined();
    expect(configs.curlCommand).toContain("https://drouter-demo.vercel.app/api/v1/chat/completions");
    expect(configs.curlCommand).toContain('"model":"kimi-k3"');
    expect(configs.openaiEnvExports).toContain(
      'export OPENAI_BASE_URL="https://drouter-demo.vercel.app/api/v1"',
    );
    expect(configs.openaiEnvExports).toContain('export OPENAI_API_KEY="drouter-anonymous"');
    expect(configs.localProxyCommand).toBe(
      "node scripts/drouter-cli.mjs proxy --port 4141 --upstream https://drouter-demo.vercel.app",
    );
  });
});

describe("OpenAI-Compatible Gateway Routes (/api/v1/*)", () => {
  it("GET /api/v1/models returns all supported models with CORS headers", async () => {
    const res = await getModels();
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = await res.json();
    expect(body.object).toBe("list");
    expect(body.data.length).toBe(SUPPORTED_GATEWAY_MODELS.length);
    const ids = body.data.map((m: { id: string }) => m.id);
    expect(ids).toContain("kimi-k3");
    expect(ids).toContain("gemma4-31b");
    expect(ids).toContain("sim-echo-1");
    expect(body.data.every((m: { enclave_attested: boolean }) => m.enclave_attested === true)).toBe(
      true,
    );

    const optRes = await optionsModels();
    expect(optRes.status).toBe(204);
    expect(optRes.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("POST /api/v1/chat/completions with model sim-echo-1 (stream: false) runs full attested handshake", async () => {
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
    expect(res.status).toBe(200);
    expect(res.headers.get("X-DRouter-Attested")).toBe("simulated-sev-snp");
    expect(res.headers.get("X-DRouter-Node")).toBe("sim-1");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");

    const json = await res.json();
    expect(json.object).toBe("chat.completion");
    expect(json.model).toBe("sim-echo-1");
    expect(json.choices[0].message.role).toBe("assistant");
    expect(json.choices[0].message.content).toContain("Simulated enclave sim-1 received");
    expect(json.drouter_attestation.securityVerified).toBe(true);
    expect(json.drouter_attestation.popReceipt.verified).toBe(true);
  });

  it("POST /api/v1/chat/completions with model sim-echo-1 (stream: true) streams SSE chunks and [DONE]", async () => {
    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "sim-echo-1",
        stream: true,
        messages: [{ role: "user", content: "Stream test message" }],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-DRouter-Attested")).toBe("simulated-sev-snp");
    expect(res.headers.get("X-DRouter-Node")).toBe("sim-1");
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");

    const text = await res.text();
    expect(text).toContain("data: ");
    expect(text).toContain('"object":"chat.completion.chunk"');
    expect(text).toContain("data: [DONE]");

    const optRes = await optionsChatCompletions();
    expect(optRes.status).toBe(204);
  });
});

describe("drouter-cli argument parser", () => {
  it("parses ask, proxy, verify, and config commands", () => {
    const askArgs = parseDrouterCliArgs([
      "ask",
      "Explain SEV-SNP",
      "--model",
      "glm-5-3",
      "--upstream",
      "http://localhost:3000/",
    ]);
    expect(askArgs.command).toBe("ask");
    expect(askArgs.prompt).toBe("Explain SEV-SNP");
    expect(askArgs.model).toBe("glm-5-3");
    expect(askArgs.upstream).toBe("http://localhost:3000");

    const proxyArgs = parseDrouterCliArgs(["proxy", "--port", "4242"]);
    expect(proxyArgs.command).toBe("proxy");
    expect(proxyArgs.port).toBe(4242);
  });
});
