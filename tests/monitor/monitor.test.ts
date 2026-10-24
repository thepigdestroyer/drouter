import { describe, expect, it } from "vitest";
import {
  restorePlaceholders,
  scrubWithPlaceholders,
} from "@/lib/monitor";
import {
  createProxyServer,
  formatHelpText,
  parseCliArgs,
  runSelfTest,
} from "../../scripts/drouter-proxy.mjs";

describe("Local OpenAI-Compatible Agent Proxy CLI & Scrubber", () => {
  it("scrubs emails and secrets into reversible placeholders and restores them", () => {
    const raw =
      "Email ops@drouter.io or backup@drouter.io using key sk-live-9876543210abcdefghij and token ghp_1234567890abcdefghijklmnopqrstuv.";
    const { scrubbedText, placeholders, redactionCount } = scrubWithPlaceholders(raw);

    expect(redactionCount).toBe(4);
    expect(scrubbedText).not.toContain("ops@drouter.io");
    expect(scrubbedText).not.toContain("backup@drouter.io");
    expect(scrubbedText).not.toContain("sk-live-9876543210abcdefghij");
    expect(scrubbedText).not.toContain("ghp_1234567890abcdefghijklmnopqrstuv");
    expect(scrubbedText).toContain("[[DROUTER_EMAIL_1]]");
    expect(scrubbedText).toContain("[[DROUTER_EMAIL_2]]");
    expect(scrubbedText).toContain("[[DROUTER_SECRET_1]]");
    expect(scrubbedText).toContain("[[DROUTER_SECRET_2]]");

    const restored = restorePlaceholders(scrubbedText, placeholders);
    expect(restored).toBe(raw);
  });

  it("supports CLI --help, argument parsing, and --self-test", () => {
    const parsed = parseCliArgs([
      "--port",
      "4545",
      "--upstream",
      "https://example.com/",
      "--self-test",
    ]);
    expect(parsed).toEqual({
      port: 4545,
      upstream: "https://example.com",
      help: false,
      selfTest: true,
    });

    expect(formatHelpText()).toContain("/v1/chat/completions");

    const selfTest = runSelfTest();
    expect(selfTest.ok).toBe(true);
    expect(selfTest.scrubberPassed).toBe(true);
  });

  it("verifies enclave attestation before serving /v1/chat/completions, scrubs outbound prompts, and restores responses", async () => {
    const capturedCalls: Array<{ body: unknown; options: unknown }> = [];
    let readyCalled = 0;

    const server = (createProxyServer as (opts: Record<string, unknown>) => ReturnType<typeof createProxyServer>)({
      upstream: "https://drouter-demo.vercel.app",
      clientFactory: () => ({
        async ready() {
          readyCalled += 1;
        },
        async getVerificationDocument() {
          return {
            securityVerified: true,
            enclaveHost: "enclave.tinfoil.sh",
          };
        },
        chat: {
          completions: {
            async create(body: Record<string, unknown>, options: Record<string, unknown>) {
              capturedCalls.push({ body, options });
              const messages = body.messages as Array<{ role: string; content: string }>;
              const userPrompt = messages[0]?.content ?? "";
              return {
                id: "chatcmpl-test-1",
                object: "chat.completion",
                model: body.model,
                choices: [
                  {
                    index: 0,
                    message: {
                      role: "assistant",
                      content: `Verified reply for ${userPrompt}`,
                    },
                    finish_reason: "stop",
                  },
                ],
              };
            },
          },
        },
      }),
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const healthRes = await fetch(`${baseUrl}/health`);
      expect(healthRes.status).toBe(200);
      const healthJson = (await healthRes.json()) as {
        ok: boolean;
      };
      expect(healthJson.ok).toBe(true);

      const chatRes = await fetch(`${baseUrl}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "kimi-k3",
          messages: [
            {
              role: "user",
              content:
                "Please notify dev@company.org that key sk-proj-abcdef1234567890abcdef is rotated.",
            },
          ],
        }),
      });

      expect(chatRes.status).toBe(200);
      expect(readyCalled).toBe(1);
      expect(chatRes.headers.get("x-drouter-redactions")).toBe("2");
      expect(chatRes.headers.get("x-drouter-enclave-host")).toBe("enclave.tinfoil.sh");

      expect(capturedCalls).toHaveLength(1);
      const sentBody = capturedCalls[0].body as {
        messages: Array<{ role: string; content: string }>;
      };
      expect(sentBody.messages[0].content).not.toContain("dev@company.org");
      expect(sentBody.messages[0].content).not.toContain("sk-proj-abcdef1234567890abcdef");
      expect(sentBody.messages[0].content).toContain("[[DROUTER_EMAIL_1]]");
      expect(sentBody.messages[0].content).toContain("[[DROUTER_SECRET_1]]");

      const chatJson = (await chatRes.json()) as {
        choices: Array<{ message: { content: string } }>;
      };
      expect(chatJson.choices[0].message.content).toBe(
        "Verified reply for Please notify dev@company.org that key sk-proj-abcdef1234567890abcdef is rotated.",
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("refuses to forward prompts when enclave attestation verification fails", async () => {
    let completionCalled = false;
    const server = (createProxyServer as (opts: Record<string, unknown>) => ReturnType<typeof createProxyServer>)({
      upstream: "https://drouter-demo.vercel.app",
      clientFactory: () => ({
        async ready() {
          throw new Error("AMD SEV-SNP measurement mismatch");
        },
        async getVerificationDocument() {
          return { securityVerified: false };
        },
        chat: {
          completions: {
            async create() {
              completionCalled = true;
              return {};
            },
          },
        },
      }),
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "kimi-k3",
          messages: [{ role: "user", content: "top secret prompt" }],
        }),
      });
      expect(res.status).toBe(502);
      expect(completionCalled).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
