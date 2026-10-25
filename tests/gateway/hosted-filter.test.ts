import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/server")>();
  return {
    ...actual,
    connection: async () => {},
  };
});

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

import { POST as postChatCompletions } from "@/app/api/v1/chat/completions/route";
import { POST as postCompartment } from "@/app/api/compartment/route";
import { POST as postOhttp } from "@/app/api/ohttp/route";
import {
  UNSUPPORTED_MEDIA_ERROR_MESSAGE,
  createHostedStreamRestorer,
  filterHostedChatRequest,
  restoreHostedChatCompletion,
} from "@/lib/gateway/hosted-filter";
import { resetGatewayModelsCache } from "@/lib/gateway/harness-config";
import {
  bytesToHex,
  decapsulateOhttpResponse,
  encapsulateOhttpRequest,
  getDefaultOhttpGatewayKeypair,
  hexToBytes,
} from "@/lib/ohttp/rfc9458";
import { NextRequest } from "next/server";

describe("Hosted Gateway Mechanical Filter (F-02)", () => {
  const origApiKey = process.env.TINFOIL_API_KEY;

  beforeEach(() => {
    process.env.TINFOIL_API_KEY = "test-tinfoil-key-do-not-print";
    resetGatewayModelsCache();
    tinfoilMocks.createCompletion.mockReset();
    creditLedgerMocks.verifyAndSpendCreditHeader.mockReset();
  });

  afterEach(() => {
    if (origApiKey === undefined) delete process.env.TINFOIL_API_KEY;
    else process.env.TINFOIL_API_KEY = origApiKey;
  });

  it("filters email, phone, and ££marked££ text in system, developer, user, assistant, tool, function, and nested content-array messages before reaching upstream, drops user/metadata, and restores responses", async () => {
    tinfoilMocks.createCompletion.mockImplementationOnce(async (params: Record<string, unknown>) => {
      const serialized = JSON.stringify(params);
      // Verify sensitive strings never reached the mocked upstream
      expect(serialized).not.toContain("alice.vane@acme.org");
      expect(serialized).not.toContain("bob.chen@acme.org");
      expect(serialized).not.toContain("415-555-0199");
      expect(serialized).not.toContain("(212) 555-0147");
      expect(serialized).not.toContain("ProjectNightfall");
      expect(serialized).not.toContain("VaultOmega");
      expect(serialized).not.toContain("££");
      expect(serialized).not.toContain("usr_ tracking_id_99");
      expect(serialized).not.toContain("secret_meta_val");

      return {
        id: "chatcmpl-hosted-1",
        object: "chat.completion",
        created: 1792800000,
        model: "kimi-k3",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content:
                "Summary for [EMAIL_1] and [EMAIL_2] at [PHONE_1] / [PHONE_2] regarding [MARKED_1] and [MARKED_2].",
              reasoning_content:
                "Verified [MARKED_1] with [EMAIL_1] before calling tool.",
              tool_calls: [
                {
                  id: "call_restore_1",
                  type: "function",
                  function: {
                    name: "send_update",
                    arguments: '{"email":"[EMAIL_1]","project":"[MARKED_1]","phone":"[PHONE_1]"}',
                  },
                },
              ],
              function_call: {
                name: "legacy_update",
                arguments: '{"vault":"[MARKED_2]","phone":"[PHONE_2]"}',
              },
            },
            finish_reason: "stop",
          },
        ],
      };
    });

    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Ensure header cannot disable filtering in hosted mode
        "X-DRouter-Scrub-PII": "false",
      },
      body: JSON.stringify({
        model: "kimi-k3",
        scrubPii: false,
        user: "usr_ tracking_id_99",
        metadata: { trace: "secret_meta_val" },
        messages: [
          {
            role: "system",
            name: "alice.vane@acme.org",
            content:
              "System context: contact alice.vane@acme.org or 415-555-0199 for ££ProjectNightfall££.",
          },
          {
            role: "developer",
            content: [
              {
                type: "text",
                text: "Developer note for ££VaultOmega££ and (212) 555-0147.",
              },
            ],
          },
          {
            role: "user",
            user: "usr_ tracking_id_99",
            metadata: { inner: "secret_meta_val" },
            content: [
              {
                type: "text",
                text: "User array part 1: email bob.chen@acme.org",
              },
              {
                type: "input_text",
                input_text: "User array part 2: code ££ProjectNightfall££",
                nested: [
                  {
                    type: "text",
                    content: "Deeply nested phone 415-555-0199 and ££VaultOmega££",
                  },
                ],
              },
            ],
          },
          {
            role: "assistant",
            content: "Checking ££ProjectNightfall££",
            reasoning_content: "Reasoning about alice.vane@acme.org and ££VaultOmega££",
            tool_calls: [
              {
                id: "call_1",
                type: "function",
                function: {
                  name: "lookup",
                  arguments: '{"owner":"alice.vane@acme.org","secret":"££ProjectNightfall££"}',
                },
              },
            ],
            function_call: {
              name: "legacy_lookup",
              arguments: '{"phone":"415-555-0199","vault":"££VaultOmega££"}',
            },
          },
          {
            role: "tool",
            tool_call_id: "call_1",
            content: "Tool result for bob.chen@acme.org and (212) 555-0147",
          },
          {
            role: "function",
            name: "legacy_lookup",
            content: "Function output for ££ProjectNightfall££",
          },
        ],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(200);
    expect(tinfoilMocks.createCompletion).toHaveBeenCalledTimes(1);

    const upstreamParams = tinfoilMocks.createCompletion.mock.calls[0][0];
    expect(upstreamParams.user).toBeUndefined();
    expect(upstreamParams.metadata).toBeUndefined();

    const json = await res.json();
    const msg = json.choices[0].message;
    expect(msg.content).toBe(
      "Summary for alice.vane@acme.org and bob.chen@acme.org at 415-555-0199 / (212) 555-0147 regarding ProjectNightfall and VaultOmega.",
    );
    expect(msg.reasoning_content).toBe(
      "Verified ProjectNightfall with alice.vane@acme.org before calling tool.",
    );
    expect(msg.tool_calls[0].function.arguments).toBe(
      '{"email":"alice.vane@acme.org","project":"ProjectNightfall","phone":"415-555-0199"}',
    );
    expect(msg.function_call.arguments).toBe(
      '{"vault":"VaultOmega","phone":"(212) 555-0147"}',
    );
  });

  it("hides multi-turn ££marked££ values in earlier unmarked mentions via second-pass rehideKnownValues", async () => {
    tinfoilMocks.createCompletion.mockResolvedValueOnce({
      id: "chatcmpl-rehide-1",
      object: "chat.completion",
      created: 1792800000,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: "Confirmed: [MARKED_1] is redacted across all turns.",
          },
          finish_reason: "stop",
        },
      ],
    });

    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "kimi-k3",
        messages: [
          {
            role: "system",
            content: "System workspace is lotus.",
          },
          {
            role: "user",
            name: "lotus",
            content: [{ type: "text", text: "First mention of lotus without markers." }],
          },
          {
            role: "assistant",
            content: "Noted.",
            reasoning_content: "Thinking about lotus.",
            tool_calls: [
              {
                id: "call_early",
                type: "function",
                function: { name: "tag", arguments: '{"codename":"lotus"}' },
              },
            ],
          },
          {
            role: "user",
            content: "Please treat ££lotus££ as confidential.",
          },
        ],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(200);

    const params = tinfoilMocks.createCompletion.mock.calls[0][0] as Record<string, unknown>;
    const serialized = JSON.stringify(params);
    expect(serialized).not.toContain("lotus");
    expect(serialized).not.toContain("Lotus");
    expect(serialized).not.toContain("££");

    const msgs = params.messages as Array<Record<string, unknown>>;
    // Turn 0 (system) had unmarked "lotus"
    expect(msgs[0].content).toBe("System workspace is [MARKED_1].");
    // Turn 1 (user) had unmarked "lotus" in a content-part array and name
    expect(msgs[1].name).toBe("[MARKED_1]");
    expect((msgs[1].content as Array<Record<string, unknown>>)[0].text).toBe(
      "First mention of [MARKED_1] without markers.",
    );
    // Turn 2 (assistant) had unmarked "lotus" in reasoning_content and tool_calls
    expect(msgs[2].reasoning_content).toBe("Thinking about [MARKED_1].");
    expect(
      ((msgs[2].tool_calls as Array<Record<string, unknown>>)[0].function as Record<string, unknown>)
        .arguments,
    ).toBe('{"codename":"[MARKED_1]"}');
    // Turn 3 (user) marked ££lotus££
    expect(msgs[3].content).toBe("Please treat [MARKED_1] as confidential.");

    const body = await res.json();
    expect(body.choices[0].message.content).toBe(
      "Confirmed: lotus is redacted across all turns.",
    );
  });

  it("rejects image, audio, and file content parts with HTTP 400 ('images, audio and files are not supported yet')", async () => {
    const mediaPayloads = [
      {
        type: "image_url",
        image_url: { url: "https://example.com/photo.png" },
      },
      {
        type: "input_image",
        image_url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA",
      },
      {
        type: "input_audio",
        input_audio: { data: "UklGRiQAAABXQVZFZm10IBAAAAABAAEA", format: "wav" },
      },
      {
        type: "file",
        file: { file_id: "file-abc123" },
      },
      {
        type: "text",
        nested: [{ type: "image", source: { type: "base64", media_type: "image/jpeg", data: "abc" } }],
      },
    ];

    for (const part of mediaPayloads) {
      const req = new Request("http://localhost/api/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "kimi-k3",
          messages: [
            {
              role: "user",
              content: [{ type: "text", text: "Describe this:" }, part],
            },
          ],
        }),
      });

      const res = await postChatCompletions(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toBe(UNSUPPORTED_MEDIA_ERROR_MESSAGE);
      expect(json.error.message).toBe("images, audio and files are not supported yet");
    }

    expect(tinfoilMocks.createCompletion).not.toHaveBeenCalled();
  });

  it("restores split placeholders across streaming deltas (content, reasoning_content, tool_calls)", async () => {
    tinfoilMocks.createCompletion.mockImplementationOnce(async () => {
      async function* gen() {
        yield {
          id: "chatcmpl-stream-mech",
          object: "chat.completion.chunk",
          created: 1792800000,
          model: "kimi-k3",
          choices: [
            {
              index: 0,
              delta: {
                reasoning_content: "Checking [MAR",
                content: "Contacting [EMA",
              },
              finish_reason: null,
            },
          ],
        };
        yield {
          id: "chatcmpl-stream-mech",
          object: "chat.completion.chunk",
          created: 1792800000,
          model: "kimi-k3",
          choices: [
            {
              index: 0,
              delta: {
                reasoning_content: "KED_1] at [PHO",
                content: "IL_1] about [MARK",
                tool_calls: [
                  {
                    index: 0,
                    id: "call_s1",
                    type: "function",
                    function: {
                      name: "ping",
                      arguments: '{"target":"[MAR',
                    },
                  },
                ],
              },
              finish_reason: null,
            },
          ],
        };
        yield {
          id: "chatcmpl-stream-mech",
          object: "chat.completion.chunk",
          created: 1792800000,
          model: "kimi-k3",
          choices: [
            {
              index: 0,
              delta: {
                reasoning_content: "NE_1].",
                content: "ED_1] on [PHONE_1].",
                tool_calls: [
                  {
                    index: 0,
                    id: "call_s1",
                    type: "function",
                    function: {
                      name: "ping",
                      arguments: 'KED_1]"}',
                    },
                  },
                ],
              },
              finish_reason: "stop",
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
        messages: [
          {
            role: "user",
            content: "Email clara@example.com or call 415-555-0188 about ££SunburstKey££.",
          },
        ],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(200);
    const sseText = await res.text();
    expect(sseText).toContain("clara@example.com");
    expect(sseText).toContain("415-555-0188");
    expect(sseText).toContain("SunburstKey");
    expect(sseText).not.toContain("[EMAIL_1]");
    expect(sseText).not.toContain("[PHONE_1]");
    expect(sseText).not.toContain("[MARKED_1]");
  });

  it("applies hosted mechanical filter via POST /api/ohttp and POST /api/compartment", async () => {
    // 1. POST /api/ohttp forwarding to /api/v1/chat/completions
    tinfoilMocks.createCompletion.mockImplementationOnce(async (params: Record<string, unknown>) => {
      const serialized = JSON.stringify(params);
      expect(serialized).not.toContain("ohttp.user@example.com");
      expect(serialized).not.toContain("CobaltCipher");
      return {
        id: "chatcmpl-ohttp-mech",
        object: "chat.completion",
        created: 1792800000,
        model: "kimi-k3",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: "OHTTP reply for [EMAIL_1] and [MARKED_1].",
            },
            finish_reason: "stop",
          },
        ],
      };
    });

    const gateway = getDefaultOhttpGatewayKeypair(1);
    const innerRequest = JSON.stringify({
      method: "POST",
      path: "/api/v1/chat/completions",
      body: {
        model: "kimi-k3",
        messages: [
          {
            role: "user",
            content: [{ type: "text", text: "Contact ohttp.user@example.com for ££CobaltCipher££." }],
          },
        ],
      },
    });
    const { encapsulatedRequest, clientContext } = encapsulateOhttpRequest(
      innerRequest,
      gateway.publicKey,
      gateway.keyId,
    );

    const ohttpReq = new NextRequest("http://localhost:3000/api/ohttp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        encapsulatedRequestHex: bytesToHex(encapsulatedRequest),
      }),
    });

    const ohttpRes = await postOhttp(ohttpReq);
    expect(ohttpRes.status).toBe(200);
    const ohttpData = await ohttpRes.json();
    const decapsulated = JSON.parse(
      decapsulateOhttpResponse(hexToBytes(ohttpData.encapsulatedResponseHex), clientContext),
    );
    expect(decapsulated.status).toBe(200);
    expect(decapsulated.body.choices[0].message.content).toBe(
      "OHTTP reply for ohttp.user@example.com and CobaltCipher.",
    );

    // 2. POST /api/compartment uses mechanical session & redacts ££marked££ values
    const compReq = new NextRequest("http://localhost:3000/api/compartment", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        prompt:
          "## 1. Step One\nReview AmberFalcon notes for alice@example.com\n\n## 2. Step Two\nConfirm ££AmberFalcon££ and 415-555-0199",
      }),
    });
    const compRes = await postCompartment(compReq);
    expect(compRes.status).toBe(200);
    const compBody = await compRes.json();
    const allFragments = compBody.plan.fragments
      .map((f: { subPrompt: string }) => f.subPrompt)
      .join(" ");
    expect(allFragments).not.toContain("AmberFalcon");
    expect(allFragments).not.toContain("alice@example.com");
    expect(allFragments).not.toContain("415-555-0199");
  });

  it("unit-tests filterHostedChatRequest, restoreHostedChatCompletion, and createHostedStreamRestorer directly", () => {
    const res = filterHostedChatRequest({
      model: "kimi-k3",
      user: "drop-me",
      metadata: { drop: true },
      messages: [
        { role: "user", content: "Mention VelvetHorizon early." },
        { role: "user", content: "Later mark ££VelvetHorizon££." },
      ],
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.body.user).toBeUndefined();
      expect(res.body.metadata).toBeUndefined();
      expect(res.messages[0].content).toBe("Mention [MARKED_1] early.");
      expect(res.messages[1].content).toBe("Later mark [MARKED_1].");

      const restored = restoreHostedChatCompletion(
        {
          choices: [
            {
              message: {
                role: "assistant",
                content: "Result: [MARKED_1]",
              },
            },
          ],
        },
        res.session,
      );
      expect(restored.choices[0].message.content).toBe("Result: VelvetHorizon");

      const streamRestorer = createHostedStreamRestorer(res.session);
      const p1 = streamRestorer.push("Chunk [MAR");
      const p2 = streamRestorer.push("KED_1] done");
      const p3 = streamRestorer.flush();
      expect(p1 + p2 + p3).toBe("Chunk VelvetHorizon done");
    }
  });
});
