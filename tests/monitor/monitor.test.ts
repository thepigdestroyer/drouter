import { describe, expect, it } from "vitest";
import {
  type Action,
  CHANNELS,
  PAYLOAD_ENCRYPTIONS,
  enumerateMonitorActions,
  evaluateMonitorExit,
  restorePlaceholders,
  scrubWithPlaceholders,
  verifyMonitorPolicyExhaustive,
} from "@/lib/monitor";
import {
  createProxyServer,
  formatHelpText,
  parseCliArgs,
  runSelfTest,
} from "../../scripts/drouter-proxy.mjs";

const BASE_ACTION: Action = {
  actorVmpl: 0,
  channel: "relay-stream",
  payloadEncryption: "custody-aes-gcm",
  nonceFresh: true,
  fixedFrameCadence: true,
  hasPerSessionFields: false,
  startsWithForbiddenPrefix: false,
};

describe("Exhaustive JavaScript Model Check of Exit-Policy Specification (1,344 states)", () => {
  it("enumerates all 1,344 states of the JavaScript policy model, labels the report as a specification model check, and passes all 5 invariants", () => {
    const actions = enumerateMonitorActions();
    expect(actions).toHaveLength(1344);

    const report = verifyMonitorPolicyExhaustive();
    expect(report.kind).toBe("javascript-policy-model-check");
    expect(report.mode).toBe("model");
    expect(report.simulated).toBe(true);
    expect(report.runsInVmpl0Hardware).toBe(false);
    expect(report.summary).toContain("JavaScript model of the exit-policy specification");
    expect(report.summary).toContain("not running VMPL0 code");
    expect(report.verified).toBe(true);
    expect(report.statesChecked).toBe(1344);
    expect(report.allowedStates).toBe(60);
    expect(report.deniedStates).toBe(1284);
    expect(report.allowedStates + report.deniedStates).toBe(1344);
    expect(report.invariants).toHaveLength(5);

    const expectedIds = [
      "I1_NoPlaintextEgress",
      "I2_NoNonceReuse",
      "I3_NoEngineBypass",
      "I4_NoPerSessionControlLeak",
      "I5_ForbiddenPrefixNeverSigned",
    ];
    expect(report.invariants.map((inv) => inv.id)).toEqual(expectedIds);
    for (const inv of report.invariants) {
      expect(inv.passed).toBe(true);
      expect(inv.counterexample).toBeUndefined();
    }
  });

  it("produces concrete counterexamples when faulty rules are injected via custom predicate", () => {
    const faultI1 = verifyMonitorPolicyExhaustive((action) => {
      if (
        action.actorVmpl === 0 &&
        action.channel === "relay-stream" &&
        action.payloadEncryption === "plaintext" &&
        action.nonceFresh &&
        action.fixedFrameCadence
      ) {
        return { allowed: true, rule: "FAULTY_ALLOW_PLAINTEXT" };
      }
      return evaluateMonitorExit(action);
    });
    expect(faultI1.verified).toBe(false);
    const inv1 = faultI1.invariants.find((i) => i.id === "I1_NoPlaintextEgress");
    expect(inv1?.passed).toBe(false);
    expect(inv1?.counterexample).toMatchObject({
      actorVmpl: 0,
      channel: "relay-stream",
      payloadEncryption: "plaintext",
    });

    const faultI2 = verifyMonitorPolicyExhaustive((action) => {
      if (
        action.actorVmpl === 0 &&
        action.channel === "blob-storage" &&
        action.payloadEncryption === "freeze-aes-gcm" &&
        !action.nonceFresh
      ) {
        return { allowed: true, rule: "FAULTY_ALLOW_NONCE_REUSE" };
      }
      return evaluateMonitorExit(action);
    });
    expect(faultI2.verified).toBe(false);
    const inv2 = faultI2.invariants.find((i) => i.id === "I2_NoNonceReuse");
    expect(inv2?.passed).toBe(false);
    expect(inv2?.counterexample).toMatchObject({
      actorVmpl: 0,
      channel: "blob-storage",
      payloadEncryption: "freeze-aes-gcm",
      nonceFresh: false,
    });

    const faultI3 = verifyMonitorPolicyExhaustive((action) => {
      if (
        action.actorVmpl === 2 &&
        action.channel === "relay-stream" &&
        action.payloadEncryption === "custody-aes-gcm" &&
        action.nonceFresh &&
        action.fixedFrameCadence
      ) {
        return { allowed: true, rule: "FAULTY_ALLOW_VMPL2" };
      }
      return evaluateMonitorExit(action);
    });
    expect(faultI3.verified).toBe(false);
    const inv3 = faultI3.invariants.find((i) => i.id === "I3_NoEngineBypass");
    expect(inv3?.passed).toBe(false);
    expect(inv3?.counterexample?.actorVmpl).toBe(2);

    const faultI4 = verifyMonitorPolicyExhaustive((action) => {
      if (
        action.actorVmpl === 0 &&
        action.channel === "control-plane" &&
        action.payloadEncryption === "control-schema" &&
        action.hasPerSessionFields
      ) {
        return { allowed: true, rule: "FAULTY_ALLOW_PER_SESSION_CONTROL" };
      }
      return evaluateMonitorExit(action);
    });
    expect(faultI4.verified).toBe(false);
    const inv4 = faultI4.invariants.find((i) => i.id === "I4_NoPerSessionControlLeak");
    expect(inv4?.passed).toBe(false);
    expect(inv4?.counterexample).toMatchObject({
      channel: "control-plane",
      hasPerSessionFields: true,
    });

    const faultI5 = verifyMonitorPolicyExhaustive((action) => {
      if (
        action.actorVmpl === 0 &&
        action.channel === "snp-attest" &&
        action.startsWithForbiddenPrefix
      ) {
        return { allowed: true, rule: "FAULTY_ALLOW_FORBIDDEN_PREFIX" };
      }
      return evaluateMonitorExit(action);
    });
    expect(faultI5.verified).toBe(false);
    const inv5 = faultI5.invariants.find((i) => i.id === "I5_ForbiddenPrefixNeverSigned");
    expect(inv5?.passed).toBe(false);
    expect(inv5?.counterexample).toMatchObject({
      channel: "snp-attest",
      startsWithForbiddenPrefix: true,
    });
  });

  describe("Individual rules M0 to M5", () => {
    it("Rule M0 denies any action from actorVmpl > 0 with DENY_NON_VMPL0_EGRESS", () => {
      for (const actorVmpl of [1, 2] as const) {
        for (const channel of CHANNELS) {
          const res = evaluateMonitorExit({
            ...BASE_ACTION,
            actorVmpl,
            channel,
          });
          expect(res).toEqual({
            allowed: false,
            rule: "DENY_NON_VMPL0_EGRESS",
          });
        }
      }
    });

    it("Rule M1 (relay-stream) allows iff custody-aes-gcm AND nonceFresh AND fixedFrameCadence", () => {
      expect(evaluateMonitorExit(BASE_ACTION)).toEqual({
        allowed: true,
        rule: "M1_ALLOW_RELAY_STREAM",
      });

      for (const enc of ["freeze-aes-gcm", "plaintext", "control-schema"] as const) {
        const res = evaluateMonitorExit({ ...BASE_ACTION, payloadEncryption: enc });
        expect(res.allowed).toBe(false);
        expect(res.rule).toContain("M1_DENY");
      }

      const staleNonce = evaluateMonitorExit({ ...BASE_ACTION, nonceFresh: false });
      expect(staleNonce.allowed).toBe(false);
      expect(staleNonce.rule).toContain("M1_DENY");

      const variableCadence = evaluateMonitorExit({
        ...BASE_ACTION,
        fixedFrameCadence: false,
      });
      expect(variableCadence.allowed).toBe(false);
      expect(variableCadence.rule).toContain("M1_DENY");
    });

    it("Rule M2 (control-plane) allows iff control-schema AND hasPerSessionFields === false", () => {
      const validControl: Action = {
        ...BASE_ACTION,
        channel: "control-plane",
        payloadEncryption: "control-schema",
        hasPerSessionFields: false,
      };
      expect(evaluateMonitorExit(validControl)).toEqual({
        allowed: true,
        rule: "M2_ALLOW_CONTROL_PLANE",
      });

      for (const enc of ["custody-aes-gcm", "freeze-aes-gcm", "plaintext"] as const) {
        const res = evaluateMonitorExit({ ...validControl, payloadEncryption: enc });
        expect(res.allowed).toBe(false);
        expect(res.rule).toContain("M2_DENY");
      }

      const perSession = evaluateMonitorExit({
        ...validControl,
        hasPerSessionFields: true,
      });
      expect(perSession.allowed).toBe(false);
      expect(perSession.rule).toContain("M2_DENY");
    });

    it("Rule M3 (blob-storage) allows iff (custody-aes-gcm || freeze-aes-gcm) AND nonceFresh", () => {
      for (const enc of ["custody-aes-gcm", "freeze-aes-gcm"] as const) {
        expect(
          evaluateMonitorExit({
            ...BASE_ACTION,
            channel: "blob-storage",
            payloadEncryption: enc,
            nonceFresh: true,
          }),
        ).toEqual({
          allowed: true,
          rule: "M3_ALLOW_BLOB_STORAGE",
        });
      }

      for (const enc of ["plaintext", "control-schema"] as const) {
        const res = evaluateMonitorExit({
          ...BASE_ACTION,
          channel: "blob-storage",
          payloadEncryption: enc,
          nonceFresh: true,
        });
        expect(res.allowed).toBe(false);
        expect(res.rule).toContain("M3_DENY");
      }

      const staleBlob = evaluateMonitorExit({
        ...BASE_ACTION,
        channel: "blob-storage",
        payloadEncryption: "freeze-aes-gcm",
        nonceFresh: false,
      });
      expect(staleBlob.allowed).toBe(false);
      expect(staleBlob.rule).toContain("M3_DENY");
    });

    it("Rule M4 (snp-attest) allows iff startsWithForbiddenPrefix === false", () => {
      expect(
        evaluateMonitorExit({
          ...BASE_ACTION,
          channel: "snp-attest",
          startsWithForbiddenPrefix: false,
        }),
      ).toEqual({
        allowed: true,
        rule: "M4_ALLOW_SNP_ATTEST",
      });

      const forbidden = evaluateMonitorExit({
        ...BASE_ACTION,
        channel: "snp-attest",
        startsWithForbiddenPrefix: true,
      });
      expect(forbidden.allowed).toBe(false);
      expect(forbidden.rule).toContain("M4_DENY");
    });

    it("Rule M5 unconditionally denies raw-socket, disk-write, and shell-exec", () => {
      for (const channel of ["raw-socket", "disk-write", "shell-exec"] as const) {
        for (const payloadEncryption of PAYLOAD_ENCRYPTIONS) {
          const res = evaluateMonitorExit({
            ...BASE_ACTION,
            channel,
            payloadEncryption,
          });
          expect(res).toEqual({
            allowed: false,
            rule: "M5_DENY_FORBIDDEN_CHANNEL",
          });
        }
      }
    });
  });
});

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
    expect(selfTest.report.verified).toBe(true);
    expect(selfTest.report.statesChecked).toBe(1344);
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
        monitorPolicy: { verified: boolean; statesChecked: number };
      };
      expect(healthJson.ok).toBe(true);
      expect(healthJson.monitorPolicy.verified).toBe(true);
      expect(healthJson.monitorPolicy.statesChecked).toBe(1344);

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
