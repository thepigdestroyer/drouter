import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Identity } from "ehbp";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { encodeAccessKey } from "@/lib/credits/access-key";
import { formatCreditHeader, nullifierFor } from "@/lib/credits/blind";
import {
  getPublishedFilterFingerprint,
  rulesetFingerprint,
  setFilterFingerprintStatusForTests,
  setFilterFingerprintVerifyOptionsForTests,
} from "@/lib/privacy/fingerprint";
import { createMechanicalSession } from "@/lib/privacy/mechanical";
import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
} from "@/lib/privacy/mechanical-ruleset";
import {
  CHAT_MODEL_ALLOWLIST,
  SpentNullifierStore,
  assertSevenSealChecksPass,
  createDerouteProxyServer,
  createMechanicalStreamRestorer,
  evaluateSevenSealChecks,
  fetchAllowedChatModels,
  isAllowedLocalOrigin,
  isLocalhostHostHeader,
  isLoopbackAddress,
  redactConversationMessages,
  startDerouteProxy,
  verifyProxyFilterFingerprint,
  type DerouteProxyClientLike,
} from "@/proxy-cli/deroute-proxy";
import { resolveSourceCommit } from "../../scripts/build-proxy.mjs";
import type { BlindCreditToken, CheckResult } from "@/lib/types";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../..");
const TMP_BASE =
  "/private/var/folders/bz/mcd91b7943dgjb_pkmry9wtc0000gn/T/opencode";

function makeSampleTokens(count: number): BlindCreditToken[] {
  const out: BlindCreditToken[] = [];
  for (let i = 1; i <= count; i += 1) {
    const hexByte = i.toString(16).padStart(2, "0");
    out.push({
      token: hexByte.repeat(32),
      signature: (i + 16).toString(16).padStart(2, "0").repeat(64),
      denomination: 1,
    });
  }
  return out;
}

function makeTempDir(prefix: string): string {
  const base = fs.existsSync(TMP_BASE) ? TMP_BASE : os.tmpdir();
  return fs.mkdtempSync(path.join(base, `${prefix}-`));
}

const ALL_PASS_CHECKS: CheckResult[] = [
  { id: "C1", label: "Hardware signature chain", status: "pass", detail: "OK" },
  { id: "C2", label: "Approved software", status: "pass", detail: "OK" },
  { id: "C3", label: "HPKE key bound to enclave report", status: "pass", detail: "OK" },
  { id: "C4", label: "Running code = released code", status: "pass", detail: "OK" },
  { id: "C5", label: "Router-attested confidential GPU pool", status: "pass", detail: "OK" },
  { id: "C6", label: "Registry admission", status: "pass", detail: "OK" },
  { id: "C7", label: "Manifest-pinned model & dm-verity root", status: "pass", detail: "OK" },
];

afterEach(() => {
  setFilterFingerprintStatusForTests(null);
  setFilterFingerprintVerifyOptionsForTests(null);
});

describe("K2: deroute-proxy unit & integration tests", () => {
  it("decodes access keys strictly, creates spent.json with mode 0600, rotates tokens across restarts, and falls back to the free tier when exhausted", async () => {
    const tmpDir = makeTempDir("deroute-proxy-spent");
    const spentPath = path.join(tmpDir, ".config", "deroute", "spent.json");
    const tokens = makeSampleTokens(2);
    const accessKey = encodeAccessKey(tokens);

    // Rejects malformed keys without leaking the key string
    expect(() => {
      new SpentNullifierStore({
        filePath: spentPath,
        accessKey: "drk_not_valid_base64url_json",
      });
    }).toThrow(/Invalid access key/);

    const observedHeaders: Array<Record<string, string>> = [];
    const stderrLines: string[] = [];
    const stdoutLines: string[] = [];

    const mockClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS,
        };
      },
      chat: {
        completions: {
          async create(body, options) {
            observedHeaders.push({ ...(options?.headers ?? {}) });
            return {
              id: "chatcmpl-test",
              object: "chat.completion",
              choices: [
                {
                  index: 0,
                  message: {
                    role: "assistant",
                    content: `Ack for ${(body.messages as Array<{ content: string }>)[0].content}`,
                  },
                },
              ],
            };
          },
        },
      },
    };

    // Start first server instance with 2-token key
    const started1 = await startDerouteProxy({
      port: 0,
      accessKey,
      spentFilePath: spentPath,
      clientFactory: () => mockClient,
      stderr: (l) => stderrLines.push(l),
      stdout: (l) => stdoutLines.push(l),
    });

    try {
      expect(fs.existsSync(spentPath)).toBe(true);
      const stat = fs.statSync(spentPath);
      expect(stat.mode & 0o777).toBe(0o600);

      // Request 1 spends token[0] -> 1 remaining
      const res1 = await fetch(
        `http://127.0.0.1:${started1.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "First turn" }],
          }),
        },
      );
      expect(res1.status).toBe(200);
      expect(res1.headers.get("x-drouter-credits-remaining")).toBe("1");
      expect(observedHeaders[0]["x-drouter-credit"]).toBe(
        formatCreditHeader(tokens[0]),
      );
      expect(stderrLines).toHaveLength(0);
    } finally {
      await started1.close();
    }

    // Verify spent.json persisted token[0]'s nullifier
    const diskAfter1 = JSON.parse(fs.readFileSync(spentPath, "utf8")) as {
      spentNullifiers: string[];
    };
    expect(diskAfter1.spentNullifiers).toEqual([
      nullifierFor(tokens[0].token).toLowerCase(),
    ]);

    // Restart proxy pointing to same spent.json and same key
    const started2 = await startDerouteProxy({
      port: 0,
      accessKey,
      spentFilePath: spentPath,
      clientFactory: () => mockClient,
      stderr: (l) => stderrLines.push(l),
      stdout: (l) => stdoutLines.push(l),
    });

    try {
      // Request 2 skips token[0] and spends token[1] -> 0 remaining
      const res2 = await fetch(
        `http://127.0.0.1:${started2.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "Second turn" }],
          }),
        },
      );
      expect(res2.status).toBe(200);
      expect(res2.headers.get("x-drouter-credits-remaining")).toBe("0");
      expect(observedHeaders[1]["x-drouter-credit"]).toBe(
        formatCreditHeader(tokens[1]),
      );
      expect(stderrLines).toHaveLength(0);

      // Request 3 has exhausted the key -> falls back to free tier, logs to stderr, sets X-DRouter-Credits-Remaining: 0
      const res3 = await fetch(
        `http://127.0.0.1:${started2.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "Third turn on free tier" }],
          }),
        },
      );
      expect(res3.status).toBe(200);
      expect(res3.headers.get("x-drouter-credits-remaining")).toBe("0");
      expect(observedHeaders[2]["x-drouter-credit"]).toBeUndefined();
      expect(stderrLines.some((l) => l.includes("falling back to free tier"))).toBe(
        true,
      );

      // Never logs keys, tokens, or request bodies
      const allLogs = [...stdoutLines, ...stderrLines].join("\n");
      expect(allLogs).not.toContain(accessKey);
      expect(allLogs).not.toContain(tokens[0].token);
      expect(allLogs).not.toContain("First turn");
    } finally {
      await started2.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("applies the fingerprinted mechanical filter with session-stable placeholders to every user and assistant message (no original words in the mocked HPKE-encrypted request body) and restores responses", async () => {
    const tmpDir = makeTempDir("deroute-proxy-filter");
    const spentPath = path.join(tmpDir, "spent.json");
    const enclaveIdentity = await Identity.generate();
    const capturedWireCiphertexts: Uint8Array[] = [];
    const capturedDecryptedBodies: Array<Record<string, unknown>> = [];

    const mockClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS,
        };
      },
      chat: {
        completions: {
          async create(body) {
            // Seal the outbound request body with real RFC 9180 HPKE (EHBP) just like TinfoilAI
            capturedDecryptedBodies.push(structuredClone(body));
            const plainReq = new Request(
              "https://drouter-demo.vercel.app/api/relay/v1/chat/completions",
              {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
              },
            );
            const { request: encryptedReq } =
              await enclaveIdentity.encryptRequestWithContext(plainReq);
            const wireBytes = new Uint8Array(await encryptedReq.arrayBuffer());
            capturedWireCiphertexts.push(wireBytes);

            const msgs = body.messages as Array<{
              role: string;
              content: string;
            }>;
            const lastMsg = msgs[msgs.length - 1].content;
            return {
              id: "chatcmpl-redact",
              object: "chat.completion",
              choices: [
                {
                  index: 0,
                  message: {
                    role: "assistant",
                    content: `Processed: ${lastMsg}`,
                  },
                },
              ],
            };
          },
        },
      },
    };

    const started = await startDerouteProxy({
      port: 0,
      spentFilePath: spentPath,
      clientFactory: () => mockClient,
      stderr: () => {},
      stdout: () => {},
    });

    try {
      const turn1Messages = [
        {
          role: "user",
          content:
            "Server 10.42.7.19 failed for dana.reyes@example.com with key sk_live_51HxYzAbCdEfGhIjKlMn in /Users/dana/acme/deploy.log under ££Project Falcon££.",
        },
        {
          role: "assistant",
          content:
            "I checked 10.42.7.19 and emailed dana.reyes@example.com about ££Project Falcon££.",
        },
        {
          role: "user",
          content:
            "Now also notify marcus.vance@example.org about ££Project Falcon££ and 10.42.7.19 today.",
        },
      ];

      const res1 = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: turn1Messages,
          }),
        },
      );
      expect(res1.status).toBe(200);
      const json1 = (await res1.json()) as {
        choices: Array<{ message: { content: string } }>;
      };

      // 1. Verify raw HPKE wire ciphertext contains none of the original words
      const wireText = Buffer.from(capturedWireCiphertexts[0]).toString("utf8");
      expect(wireText).not.toContain("10.42.7.19");
      expect(wireText).not.toContain("dana.reyes@example.com");
      expect(wireText).not.toContain("marcus.vance@example.org");
      expect(wireText).not.toContain("sk_live_51HxYzAbCdEfGhIjKlMn");
      expect(wireText).not.toContain("/Users/dana/acme/deploy.log");
      expect(wireText).not.toContain("Project Falcon");

      // 2. Verify even the enclave-decrypted body contains only placeholders and none of the original words
      const serializedOutbound = JSON.stringify(capturedDecryptedBodies[0]);
      expect(serializedOutbound).not.toContain("10.42.7.19");
      expect(serializedOutbound).not.toContain("dana.reyes@example.com");
      expect(serializedOutbound).not.toContain("marcus.vance@example.org");
      expect(serializedOutbound).not.toContain("sk_live_51HxYzAbCdEfGhIjKlMn");
      expect(serializedOutbound).not.toContain("/Users/dana/acme/deploy.log");
      expect(serializedOutbound).not.toContain("Project Falcon");

      // 3. Verify placeholders are session-stable across user and assistant turns
      const sentMsgs = capturedDecryptedBodies[0].messages as Array<{
        role: string;
        content: string;
      }>;
      expect(sentMsgs[0].content).toContain("[EMAIL_1]");
      expect(sentMsgs[0].content).toContain("[MARKED_1]");
      expect(sentMsgs[0].content).toContain("[IP_1]");
      expect(sentMsgs[0].content).toContain("[SECRET_1]");
      expect(sentMsgs[0].content).toContain("[URL_1]");

      // Assistant message reuses the exact same placeholders
      expect(sentMsgs[1].content).toContain("[IP_1]");
      expect(sentMsgs[1].content).toContain("[EMAIL_1]");
      expect(sentMsgs[1].content).toContain("[MARKED_1]");

      // Second user message gets [EMAIL_2] for the new email and reuses [MARKED_1] and [IP_1]
      expect(sentMsgs[2].content).toContain("[EMAIL_2]");
      expect(sentMsgs[2].content).toContain("[MARKED_1]");
      expect(sentMsgs[2].content).toContain("[IP_1]");

      // 4. Response is restored back to original details (without ££ markers)
      const replyContent = json1.choices[0].message.content;
      expect(replyContent).toContain("marcus.vance@example.org");
      expect(replyContent).toContain("Project Falcon");
      expect(replyContent).toContain("10.42.7.19");
      expect(replyContent).not.toContain("££");
      expect(replyContent).not.toContain("[EMAIL_2]");
      expect(replyContent).not.toContain("[MARKED_1]");
      expect(replyContent).not.toContain("[IP_1]");
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("restores hidden details safely across arbitrary SSE chunk boundaries", async () => {
    const session = createMechanicalSession();
    session.redact(
      "Contact alice@example.com regarding ££Project Horizon££ with Dr. Elena Rostova.",
    );

    const restorer = createMechanicalStreamRestorer(session);
    const fragments = [
      "Hello [",
      "EMAIL",
      "_1], ",
      "welcome to [MARK",
      "ED_1] ",
      "with [NAME_1",
      "]! Plain [brackets] stay.",
    ];

    let combined = "";
    for (const frag of fragments) {
      combined += restorer.push(frag);
    }
    combined += restorer.flush();

    expect(combined).toBe(
      "Hello alice@example.com, welcome to Project Horizon with Dr. Elena Rostova! Plain [brackets] stay.",
    );

    // Also test full SSE streaming through the HTTP proxy server
    const tmpDir = makeTempDir("deroute-proxy-sse");
    const spentPath = path.join(tmpDir, "spent.json");

    const mockStreamClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS,
        };
      },
      chat: {
        completions: {
          async create() {
            async function* generateChunks() {
              const deltas = [
                "Echoing [EM",
                "AIL_1] and [",
                "MARKED",
                "_1] in stream.",
              ];
              for (const d of deltas) {
                yield {
                  id: "chatcmpl-stream",
                  object: "chat.completion.chunk",
                  choices: [{ index: 0, delta: { content: d } }],
                };
              }
            }
            return generateChunks();
          },
        },
      },
    };

    const started = await startDerouteProxy({
      port: 0,
      spentFilePath: spentPath,
      clientFactory: () => mockStreamClient,
      stderr: () => {},
      stdout: () => {},
    });

    try {
      const res = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            stream: true,
            messages: [
              {
                role: "user",
                content: "Email dana.reyes@example.com about ££Secret Launch££",
              },
            ],
          }),
        },
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      expect(res.headers.get("x-drouter-credits-remaining")).toBe("0");

      const rawSse = await res.text();
      const lines = rawSse
        .split("\n")
        .filter((l) => l.startsWith("data: ") && l !== "data: [DONE]");
      let fullText = "";
      for (const line of lines) {
        const parsed = JSON.parse(line.slice("data: ".length)) as {
          choices: Array<{ delta?: { content?: string } }>;
        };
        fullText += parsed.choices[0]?.delta?.content ?? "";
      }
      expect(fullText).toBe(
        "Echoing dana.reyes@example.com and Secret Launch in stream.",
      );
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("refuses to start on filter fingerprint mismatch and refuses requests when any of the seven checks C1-C7 fail", async () => {
    const tmpDir = makeTempDir("deroute-proxy-refusal");
    const spentPath = path.join(tmpDir, "spent.json");

    // 1. Mismatched published fingerprint refuses to start
    expect(() =>
      verifyProxyFilterFingerprint({
        published: {
          version: MECHANICAL_RULESET.version,
          fingerprint: `0x${"deadbeef".repeat(8)}`,
          anchorTx: null,
        },
      }),
    ).toThrow(/Refusing to start/);

    // 2. Modified ruleset refuses to start
    const tamperedRuleset = JSON.parse(
      JSON.stringify(MECHANICAL_RULESET),
    ) as MechanicalRuleset;
    tamperedRuleset.version = "9.9.9";
    expect(() =>
      verifyProxyFilterFingerprint({
        ruleset: tamperedRuleset,
      }),
    ).toThrow(/Refusing to start/);

    // 3. Expected fingerprint CLI flag mismatch refuses to start
    expect(() =>
      verifyProxyFilterFingerprint({
        expectedFingerprint: `0x${"00".repeat(32)}`,
      }),
    ).toThrow(/Refusing to start/);

    // 4. Failed seal check (e.g. C4 failed) refuses the request with HTTP 502 and does not spend a token
    const tokens = makeSampleTokens(1);
    const accessKey = encodeAccessKey(tokens);

    const failingClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS.map((c) =>
            c.id === "C4"
              ? {
                  ...c,
                  status: "fail" as const,
                  detail: "Launch measurement mismatch",
                }
              : c,
          ),
        };
      },
      chat: {
        completions: {
          async create() {
            throw new Error("Should not be called when seal checks fail");
          },
        },
      },
    };

    const started = await startDerouteProxy({
      port: 0,
      accessKey,
      spentFilePath: spentPath,
      clientFactory: () => failingClient,
      stderr: () => {},
      stdout: () => {},
    });

    try {
      const res = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "Hello" }],
          }),
        },
      );
      expect(res.status).toBe(502);
      const errJson = (await res.json()) as { error: { message: string } };
      expect(errJson.error.message).toContain("C4");

      // Credit token was NOT spent because seal check failed prior to sending
      const store = new SpentNullifierStore({
        filePath: spentPath,
        accessKey,
      });
      expect(store.remainingCount()).toBe(1);
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    // Also verify evaluateSevenSealChecks directly detects step failures
    const checksWithBadStep = evaluateSevenSealChecks({
      doc: {
        securityVerified: true,
        steps: {
          verifyEnclave: { status: "success" },
          verifyCode: { status: "failed", error: "Rekor signature invalid" },
          verifyCertificate: { status: "success" },
          compareMeasurements: { status: "success" },
        } as never,
      },
    });
    expect(checksWithBadStep.find((c) => c.id === "C2")?.status).toBe("fail");
  });

  it("enforces localhost-only binding, rejects external Host or Origin headers without CORS, and filters /v1/models to chat models only", async () => {
    const tmpDir = makeTempDir("deroute-proxy-localhost");
    const spentPath = path.join(tmpDir, "spent.json");

    // Refuses to bind to 0.0.0.0 or external IP
    await expect(
      startDerouteProxy({
        port: 0,
        host: "0.0.0.0",
        spentFilePath: spentPath,
      }),
    ).rejects.toThrow(/Refusing to bind to non-localhost address/);

    expect(isLoopbackAddress(undefined)).toBe(false);
    expect(isLoopbackAddress("")).toBe(false);
    expect(isLoopbackAddress("127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
    expect(isLoopbackAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("192.168.1.50")).toBe(false);

    expect(isLocalhostHostHeader(undefined)).toBe(false);
    expect(isLocalhostHostHeader("")).toBe(false);
    expect(isLocalhostHostHeader("127.0.0.1:4141")).toBe(true);
    expect(isLocalhostHostHeader("localhost:4141")).toBe(true);
    expect(isLocalhostHostHeader("evil.example.com:4141")).toBe(false);

    expect(isAllowedLocalOrigin(undefined)).toBe(true);
    expect(isAllowedLocalOrigin("")).toBe(true);
    expect(isAllowedLocalOrigin("http://127.0.0.1:3000")).toBe(false);
    expect(isAllowedLocalOrigin("http://localhost:3000")).toBe(false);
    expect(isAllowedLocalOrigin("https://evil.example.com")).toBe(false);

    // Mock live router table containing both chat models and non-chat models (whisper, tts, embed, voxtral)
    const mockFetchImpl = async () =>
      new Response(
        JSON.stringify({
          models: {
            "kimi-k3": {
              repo: "tinfoilsh/confidential-kimi-k3",
              tag: "v1",
              enclaves: { h1: { predicate: "tdx" } },
              verification: { configured: 1, verified: 1, healthy: 1 },
            },
            "gemma4-31b": {
              repo: "tinfoilsh/confidential-gemma4-31b",
              tag: "v1",
              enclaves: { h1: { predicate: "tdx" } },
              verification: { configured: 1, verified: 1, healthy: 1 },
            },
            "whisper-large-v3-turbo": {
              repo: "tinfoilsh/confidential-whisper",
              tag: "v1",
              enclaves: { h1: { predicate: "tdx" } },
              verification: { configured: 1, verified: 1, healthy: 1 },
            },
            "nomic-embed-text": {
              repo: "tinfoilsh/confidential-nomic",
              tag: "v1",
              enclaves: { h1: { predicate: "tdx" } },
              verification: { configured: 1, verified: 1, healthy: 1 },
            },
            "voxtral-small-24b": {
              repo: "tinfoilsh/confidential-voxtral",
              tag: "v1",
              enclaves: { h1: { predicate: "tdx" } },
              verification: { configured: 1, verified: 1, healthy: 1 },
            },
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );

    const intersected = await fetchAllowedChatModels({
      fetchImpl: mockFetchImpl as unknown as typeof fetch,
      forceRefresh: true,
    });
    expect(intersected.map((m) => m.id)).toEqual(["kimi-k3", "gemma4-31b"]);

    const handle = createDerouteProxyServer({
      spentFilePath: spentPath,
      fetchImpl: mockFetchImpl as unknown as typeof fetch,
      stderr: () => {},
      stdout: () => {},
    });

    await new Promise<void>((resolve) =>
      handle.server.listen(0, "127.0.0.1", () => resolve()),
    );
    const addr = handle.server.address();
    const port = addr && typeof addr === "object" ? addr.port : 0;

    try {
      // Cross-origin request from external Origin is rejected with 403 and no CORS headers
      const evilOriginRes = await fetch(`http://127.0.0.1:${port}/v1/models`, {
        headers: { Origin: "https://attacker.example.com" },
      });
      expect(evilOriginRes.status).toBe(403);
      expect(
        evilOriginRes.headers.get("access-control-allow-origin"),
      ).toBeNull();

      // DNS-rebinding Host header is rejected with 403
      const rebindStatus = await new Promise<number>((resolve, reject) => {
        const req = http.request(
          {
            host: "127.0.0.1",
            port,
            path: "/v1/models",
            method: "GET",
            headers: { Host: "rebind.attacker.com" },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", reject);
        req.end();
      });
      expect(rebindStatus).toBe(403);

      // Valid localhost GET /v1/models returns only chat models and no wildcard CORS header
      const modelsRes = await fetch(`http://127.0.0.1:${port}/v1/models`);
      expect(modelsRes.status).toBe(200);
      expect(modelsRes.headers.get("access-control-allow-origin")).toBeNull();
      const modelsBody = (await modelsRes.json()) as {
        data: Array<{ id: string }>;
      };
      expect(modelsBody.data.map((m) => m.id)).toEqual([
        "kimi-k3",
        "gemma4-31b",
      ]);
      for (const m of modelsBody.data) {
        expect(CHAT_MODEL_ALLOWLIST).toContain(m.id);
      }
    } finally {
      await new Promise<void>((resolve) => handle.server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("[I1] fails closed on all seven seal checks when fetches fail or records are missing, and never falls back to DEFAULT_MODEL", () => {
    const validSteps = {
      verifyEnclave: { status: "success" },
      verifyCode: { status: "success" },
      verifyCertificate: { status: "success" },
      compareMeasurements: { status: "success" },
    } as never;

    // 1. Missing doc.steps fails C1-C4 even if securityVerified is undefined
    const missingStepsChecks = evaluateSevenSealChecks({
      doc: {},
      matrix: null,
      proxyTable: null,
      registry: null,
      model: "kimi-k3",
    });
    for (const c of missingStepsChecks) {
      expect(c.status).toBe("fail");
    }
    expect(() => assertSevenSealChecksPass({}, missingStepsChecks)).toThrow();
    expect(() =>
      assertSevenSealChecksPass({ steps: validSteps }, ALL_PASS_CHECKS),
    ).toThrow(/securityVerified is not true/);

    // 2. When matrix, proxyTable, and registry are null (fetch failure), C5, C6, and C7 fail closed
    const nullFetchChecks = evaluateSevenSealChecks({
      doc: { securityVerified: true, steps: validSteps },
      matrix: null,
      proxyTable: null,
      registry: null,
      model: "kimi-k3",
    });
    expect(nullFetchChecks.find((c) => c.id === "C5")?.status).toBe("fail");
    expect(nullFetchChecks.find((c) => c.id === "C6")?.status).toBe("fail");
    expect(nullFetchChecks.find((c) => c.id === "C7")?.status).toBe("fail");

    // 3. When kimi-k3 is present in matrix/proxyTable, requesting gemma4-31b (absent) fails C5 and C7 without falling back to kimi-k3
    const fallbackTestChecks = evaluateSevenSealChecks({
      doc: { securityVerified: true, steps: validSteps },
      matrix: {
        models: {
          "kimi-k3": {
            repo: "tinfoilsh/confidential-kimi-k3",
            healthyHosts: 2,
            configuredHosts: 2,
            dmVerityRootHash: "abcdef1234567890abcdef1234567890",
          },
        },
      },
      proxyTable: {
        models: {
          "kimi-k3": {
            repo: "tinfoilsh/confidential-kimi-k3",
            tag: "v1",
            measurement: { registers: ["abcdef1234567890"] },
            verification: { configured: 2, verified: 2, healthy: 2 },
          },
        },
      },
      registry: {
        source: "arc",
        nodes: [{ kind: "tinfoil", status: "active", stake: 100 }],
      },
      model: "gemma4-31b",
    });
    expect(fallbackTestChecks.find((c) => c.id === "C5")?.status).toBe("fail");
    expect(fallbackTestChecks.find((c) => c.id === "C7")?.status).toBe("fail");
    expect(fallbackTestChecks.find((c) => c.id === "C6")?.status).toBe("pass");
  });

  it("[I2] rejects any Origin header (including localhost), Sec-Fetch-Site != none, and non-JSON Content-Type on POST /v1/chat/completions", async () => {
    const tmpDir = makeTempDir("deroute-proxy-i2");
    const spentPath = path.join(tmpDir, "spent.json");
    let createCalls = 0;

    const mockClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS,
        };
      },
      chat: {
        completions: {
          async create() {
            createCalls += 1;
            return {
              id: "chatcmpl-i2",
              object: "chat.completion",
              choices: [
                {
                  index: 0,
                  message: { role: "assistant", content: "ok" },
                },
              ],
            };
          },
        },
      },
    };

    const started = await startDerouteProxy({
      port: 0,
      spentFilePath: spentPath,
      clientFactory: () => mockClient,
      stderr: () => {},
      stdout: () => {},
    });

    try {
      // 1. Localhost Origin header (e.g. http://localhost:3000 or http://127.0.0.1:3000) is rejected with 403
      const localOriginRes = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Origin: "http://localhost:3000",
          },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "hi" }],
          }),
        },
      );
      expect(localOriginRes.status).toBe(403);

      // 2. Sec-Fetch-Site other than "none" (e.g. "same-site" or "cross-site") without Origin is rejected with 403
      const secFetchRes = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Sec-Fetch-Site": "cross-site",
          },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "hi" }],
          }),
        },
      );
      expect(secFetchRes.status).toBe(403);

      // Sec-Fetch-Site: none is allowed
      const secFetchNoneRes = await fetch(
        `http://127.0.0.1:${started.port}/v1/models`,
        {
          headers: { "Sec-Fetch-Site": "none" },
        },
      );
      expect(secFetchNoneRes.status).toBe(200);

      // 3. POST /v1/chat/completions with Content-Type: text/plain returns 415 Unsupported Media Type
      const textPlainRes = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            "Content-Type": "text/plain",
          },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: [{ role: "user", content: "hi" }],
          }),
        },
      );
      expect(textPlainRes.status).toBe(415);
      expect(createCalls).toBe(0);
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("[M1, M2, M3] resolves source commit from DEROUTE_SOURCE_COMMIT or proxy input commits, writes spent.json atomically via temp file rename, and redacts/restores assistant tool_calls and role:tool messages", async () => {
    // M1: resolveSourceCommit honors DEROUTE_SOURCE_COMMIT and otherwise queries proxy inputs
    const prevEnv = process.env.DEROUTE_SOURCE_COMMIT;
    try {
      process.env.DEROUTE_SOURCE_COMMIT = "0567e917e341";
      expect(resolveSourceCommit()).toBe("0567e917e341");
      delete process.env.DEROUTE_SOURCE_COMMIT;
      const fromGit = resolveSourceCommit();
      expect(fromGit).toMatch(/^[0-9a-f]{7,12}$/);
    } finally {
      if (prevEnv === undefined) {
        delete process.env.DEROUTE_SOURCE_COMMIT;
      } else {
        process.env.DEROUTE_SOURCE_COMMIT = prevEnv;
      }
    }

    // M2: SpentNullifierStore writes atomically via `${filePath}.tmp.${process.pid}` then renames
    const tmpDir = makeTempDir("deroute-proxy-m2-m3");
    const spentPath = path.join(tmpDir, "spent.json");
    const tokens = makeSampleTokens(1);
    const accessKey = encodeAccessKey(tokens);

    const renameCalls: Array<{ oldPath: string; newPath: string }> = [];
    const origRenameSync = fs.renameSync.bind(fs);
    const renameSpy = (oldPath: fs.PathLike, newPath: fs.PathLike) => {
      renameCalls.push({
        oldPath: String(oldPath),
        newPath: String(newPath),
      });
      return origRenameSync(oldPath, newPath);
    };
    fs.renameSync = renameSpy as typeof fs.renameSync;

    try {
      const store = new SpentNullifierStore({
        filePath: spentPath,
        accessKey,
      });
      store.spendNextToken();
    } finally {
      fs.renameSync = origRenameSync;
    }

    expect(renameCalls.length).toBeGreaterThanOrEqual(2);
    expect(renameCalls[0].oldPath).toBe(`${spentPath}.tmp.${process.pid}`);
    expect(renameCalls[0].newPath).toBe(spentPath);
    expect(fs.existsSync(`${spentPath}.tmp.${process.pid}`)).toBe(false);
    expect(fs.statSync(spentPath).mode & 0o777).toBe(0o600);

    // M3: Redacts and restores assistant tool_calls[].function.arguments and role: "tool" messages
    const session = createMechanicalSession();
    const inputMessages = [
      {
        role: "user",
        content: "Check server 10.42.7.19 for dana.reyes@example.com.",
      },
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "call_1",
            type: "function",
            function: {
              name: "lookup_host",
              arguments: JSON.stringify({
                ip: "10.42.7.19",
                owner: "dana.reyes@example.com",
                secret: "sk_live_51HxYzAbCdEfGhIjKlMn",
              }),
            },
          },
        ],
      },
      {
        role: "tool",
        tool_call_id: "call_1",
        content:
          "Host 10.42.7.19 owned by dana.reyes@example.com has secret sk_live_51HxYzAbCdEfGhIjKlMn.",
      },
    ];

    const { messages: redacted } = redactConversationMessages(
      inputMessages,
      session,
    );
    const serializedRedacted = JSON.stringify(redacted);
    expect(serializedRedacted).not.toContain("10.42.7.19");
    expect(serializedRedacted).not.toContain("dana.reyes@example.com");
    expect(serializedRedacted).not.toContain("sk_live_51HxYzAbCdEfGhIjKlMn");

    const assistantToolArgs = (
      (redacted[1].tool_calls as Array<{ function: { arguments: string } }>)[0]
    ).function.arguments;
    expect(assistantToolArgs).toContain("[IP_1]");
    expect(assistantToolArgs).toContain("[EMAIL_1]");
    expect(assistantToolArgs).toContain("[SECRET_1]");
    expect(redacted[2].content).toContain("[IP_1]");
    expect(redacted[2].content).toContain("[EMAIL_1]");
    expect(redacted[2].content).toContain("[SECRET_1]");

    // Also verify end-to-end restoration of choice.message.tool_calls[].function.arguments
    const started = await startDerouteProxy({
      port: 0,
      spentFilePath: path.join(tmpDir, "spent2.json"),
      clientFactory: () => ({
        async ready() {},
        async getVerificationDocument() {
          return {
            securityVerified: true,
            enclaveHost: "router-0.tinfoil.sh",
            checks: ALL_PASS_CHECKS,
          };
        },
        chat: {
          completions: {
            async create(body) {
              const sent = body.messages as Array<{
                role: string;
                content?: string;
                tool_calls?: Array<{ function: { arguments: string } }>;
              }>;
              const toolArgs = sent[1]?.tool_calls?.[0]?.function.arguments ?? "";
              return {
                id: "chatcmpl-tool",
                object: "chat.completion",
                choices: [
                  {
                    index: 0,
                    message: {
                      role: "assistant",
                      content: `Tool output was: ${sent[2]?.content}`,
                      tool_calls: [
                        {
                          id: "call_2",
                          type: "function",
                          function: {
                            name: "notify",
                            arguments: toolArgs,
                          },
                        },
                      ],
                    },
                  },
                ],
              };
            },
          },
        },
      }),
      stderr: () => {},
      stdout: () => {},
    });

    try {
      const res = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            messages: inputMessages,
          }),
        },
      );
      expect(res.status).toBe(200);
      const completionJson = (await res.json()) as {
        choices: Array<{
          message: {
            content: string;
            tool_calls: Array<{ function: { arguments: string } }>;
          };
        }>;
      };
      const msg = completionJson.choices[0].message;
      expect(msg.content).toContain("10.42.7.19");
      expect(msg.content).toContain("dana.reyes@example.com");
      expect(msg.content).toContain("sk_live_51HxYzAbCdEfGhIjKlMn");
      expect(msg.tool_calls[0].function.arguments).toContain("10.42.7.19");
      expect(msg.tool_calls[0].function.arguments).toContain(
        "dana.reyes@example.com",
      );
      expect(msg.tool_calls[0].function.arguments).toContain(
        "sk_live_51HxYzAbCdEfGhIjKlMn",
      );
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("verifies shasum -a 256 -c and runs the built single-file bundle from a temp directory outside the repo with plain node and no node_modules", async () => {
    const bundleSrc = path.join(
      REPO_ROOT,
      "public",
      "downloads",
      "deroute-proxy.mjs",
    );
    const shaSrc = path.join(
      REPO_ROOT,
      "public",
      "downloads",
      "deroute-proxy.mjs.sha256",
    );
    expect(fs.existsSync(bundleSrc)).toBe(true);
    expect(fs.existsSync(shaSrc)).toBe(true);

    const headText = fs.readFileSync(bundleSrc, "utf8").slice(0, 200);
    expect(headText.startsWith("#!/usr/bin/env node\n// deRoute Private Local Proxy (source commit:")).toBe(
      true,
    );

    const isolatedDir = makeTempDir("deroute-standalone-bundle");
    const bundleDest = path.join(isolatedDir, "deroute-proxy.mjs");
    const shaDest = path.join(isolatedDir, "deroute-proxy.mjs.sha256");
    const spentDest = path.join(isolatedDir, "spent.json");

    fs.copyFileSync(bundleSrc, bundleDest);
    fs.copyFileSync(shaSrc, shaDest);

    try {
      // 1. Verify shasum -a 256 -c passes in the isolated temp directory
      const shasumOut = execFileSync(
        "shasum",
        ["-a", "256", "-c", "deroute-proxy.mjs.sha256"],
        {
          cwd: isolatedDir,
          encoding: "utf8",
        },
      );
      expect(shasumOut).toContain("deroute-proxy.mjs: OK");

      // 2. Verify the standalone bundle refuses to start when --expected-fingerprint mismatches
      let mismatchExitedNonZero = false;
      try {
        execFileSync(
          process.execPath,
          [bundleDest, "--expected-fingerprint", `0x${"11".repeat(32)}`],
          {
            cwd: isolatedDir,
            stdio: "pipe",
          },
        );
      } catch {
        mismatchExitedNonZero = true;
      }
      expect(mismatchExitedNonZero).toBe(true);

      // 3. Pick an ephemeral port and start the standalone bundle with plain node (no node_modules)
      const port = await new Promise<number>((resolve, reject) => {
        const srv = http.createServer();
        srv.listen(0, "127.0.0.1", () => {
          const addr = srv.address();
          const p = addr && typeof addr === "object" ? addr.port : 0;
          srv.close((err) => (err ? reject(err) : resolve(p)));
        });
      });

      const child = spawn(
        process.execPath,
        [bundleDest, "--port", String(port), "--spent-path", spentDest],
        {
          cwd: isolatedDir,
          env: {
            ...process.env,
            HOME: isolatedDir,
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );

      let stdoutText = "";
      let stderrText = "";

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(
            new Error(
              `Timed out waiting for standalone deroute-proxy.mjs to listen. stdout=${stdoutText} stderr=${stderrText}`,
            ),
          );
        }, 15_000);

        child.stdout.on("data", (chunk: Buffer) => {
          stdoutText += chunk.toString("utf8");
          if (stdoutText.includes("Listening on http://127.0.0.1:")) {
            clearTimeout(timeout);
            resolve();
          }
        });
        child.stderr.on("data", (chunk: Buffer) => {
          stderrText += chunk.toString("utf8");
        });
        child.once("exit", (code) => {
          clearTimeout(timeout);
          reject(
            new Error(
              `deroute-proxy.mjs exited prematurely with code ${String(code)}: ${stderrText}`,
            ),
          );
        });
      });

      try {
        expect(stdoutText).toMatch(
          /Personal-detail filter v\d+\.\d+\.\d+ verified \(fingerprint: 0x[0-9a-f]{64}\)/,
        );

        const healthRes = await fetch(`http://127.0.0.1:${port}/health`);
        expect(healthRes.status).toBe(200);
        const healthJson = (await healthRes.json()) as {
          ok: boolean;
          filterVersion: string;
          filterFingerprint: string;
        };
        expect(healthJson.ok).toBe(true);
        expect(healthJson.filterVersion).toMatch(/^\d+\.\d+\.\d+$/);
        expect(healthJson.filterFingerprint).toMatch(/^0x[0-9a-f]{64}$/);
        expect(stdoutText).toContain(
          `Personal-detail filter v${healthJson.filterVersion} verified (fingerprint: ${healthJson.filterFingerprint})`,
        );
      } finally {
        child.kill("SIGTERM");
      }
    } finally {
      fs.rmSync(isolatedDir, { recursive: true, force: true });
    }
  });

  it("restores streamed tool_calls[].function.arguments across 3-chunk placeholder splits, two parallel tool calls, two choices, finish_reason flush, and streams ending without finish_reason", async () => {
    const tmpDir = makeTempDir("deroute-proxy-stream-tool-calls");
    const spentPath = path.join(tmpDir, "spent.json");
    let streamScenario: "finish_reason" | "no_finish_reason" = "finish_reason";

    const mockStreamClient: DerouteProxyClientLike = {
      async ready() {},
      async getVerificationDocument() {
        return {
          securityVerified: true,
          enclaveHost: "router-0.tinfoil.sh",
          checks: ALL_PASS_CHECKS,
        };
      },
      chat: {
        completions: {
          async create() {
            if (streamScenario === "finish_reason") {
              async function* genWithFinishReason() {
                // Chunk 1: initial metadata + start of 3-chunk split placeholders across two parallel tool calls and two choices
                yield {
                  id: "chatcmpl-stream-tc-1",
                  object: "chat.completion.chunk",
                  choices: [
                    {
                      index: 0,
                      delta: {
                        role: "assistant",
                        content: "Choice0 [EM",
                        tool_calls: [
                          {
                            index: 0,
                            id: "call_0_0",
                            type: "function",
                            function: {
                              name: "send_email",
                              arguments: '{"to":"[EM',
                            },
                          },
                          {
                            index: 1,
                            id: "call_0_1",
                            type: "function",
                            function: {
                              name: "ping_host",
                              arguments: '{"host":"[I',
                            },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                    {
                      index: 1,
                      delta: {
                        role: "assistant",
                        content: "Choice1 [IP",
                        tool_calls: [
                          {
                            index: 0,
                            id: "call_1_0",
                            type: "function",
                            function: {
                              name: "use_secret",
                              arguments: '{"key":"[SEC',
                            },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                  ],
                };

                // Chunk 2: middle fragment of placeholders (no closing ']' yet -> held back)
                yield {
                  id: "chatcmpl-stream-tc-1",
                  object: "chat.completion.chunk",
                  choices: [
                    {
                      index: 0,
                      delta: {
                        content: "AIL",
                        tool_calls: [
                          {
                            index: 0,
                            function: { arguments: "AIL_" },
                          },
                          {
                            index: 1,
                            function: { arguments: "P_1" },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                    {
                      index: 1,
                      delta: {
                        content: "_1",
                        tool_calls: [
                          {
                            index: 0,
                            function: { arguments: "RET_" },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                  ],
                };

                // Chunk 3: closing ']' of placeholders + trailing unclosed '[UNCLOSED' to test finish_reason flush
                yield {
                  id: "chatcmpl-stream-tc-1",
                  object: "chat.completion.chunk",
                  choices: [
                    {
                      index: 0,
                      delta: {
                        content: "_1]!",
                        tool_calls: [
                          {
                            index: 0,
                            function: { arguments: '1]","tag":"[UNCLOSED0' },
                          },
                          {
                            index: 1,
                            function: { arguments: ']"}' },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                    {
                      index: 1,
                      delta: {
                        content: "]!",
                        tool_calls: [
                          {
                            index: 0,
                            function: { arguments: '1]"}' },
                          },
                        ],
                      },
                      finish_reason: null,
                    },
                  ],
                };

                // Chunk 4: finish_reason arrives -> flushes any held-back text on that choice
                yield {
                  id: "chatcmpl-stream-tc-1",
                  object: "chat.completion.chunk",
                  choices: [
                    {
                      index: 0,
                      delta: {},
                      finish_reason: "tool_calls",
                    },
                    {
                      index: 1,
                      delta: {},
                      finish_reason: "tool_calls",
                    },
                  ],
                };
              }
              return genWithFinishReason();
            }

            async function* genWithoutFinishReason() {
              // Stream that ends without finish_reason while holding back partial bracket prefixes
              yield {
                id: "chatcmpl-stream-tc-2",
                object: "chat.completion.chunk",
                choices: [
                  {
                    index: 0,
                    delta: {
                      content: "Stream [EMAIL",
                      tool_calls: [
                        {
                          index: 0,
                          id: "call_nf_0",
                          type: "function",
                          function: {
                            name: "notify",
                            arguments: '{"to":"[EM',
                          },
                        },
                      ],
                    },
                  },
                  {
                    index: 1,
                    delta: {
                      tool_calls: [
                        {
                          index: 0,
                          id: "call_nf_1",
                          type: "function",
                          function: {
                            name: "connect",
                            arguments: '{"ip":"[IP_1]","tail":"[TAIL_OPEN',
                          },
                        },
                      ],
                    },
                  },
                ],
              };
              yield {
                id: "chatcmpl-stream-tc-2",
                object: "chat.completion.chunk",
                choices: [
                  {
                    index: 0,
                    delta: {
                      content: "_1] [OPEN_END",
                      tool_calls: [
                        {
                          index: 0,
                          function: {
                            arguments: "AIL",
                          },
                        },
                      ],
                    },
                  },
                ],
              };
              yield {
                id: "chatcmpl-stream-tc-2",
                object: "chat.completion.chunk",
                choices: [
                  {
                    index: 0,
                    delta: {
                      tool_calls: [
                        {
                          index: 0,
                          function: {
                            arguments: '_1]","note":"[PARTIAL_AT_EOF',
                          },
                        },
                      ],
                    },
                  },
                ],
              };
              // Ends without any finish_reason chunk!
            }
            return genWithoutFinishReason();
          },
        },
      },
    };

    const started = await startDerouteProxy({
      port: 0,
      spentFilePath: spentPath,
      clientFactory: () => mockStreamClient,
      stderr: () => {},
      stdout: () => {},
    });

    const parseSseStream = (rawSse: string) => {
      const dataLines = rawSse
        .split("\n")
        .filter((l) => l.startsWith("data: ") && l !== "data: [DONE]");
      const contentByChoice = new Map<number, string>();
      const toolArgsByChoiceAndIndex = new Map<string, string>();
      const allEmittedFragments: string[] = [];

      for (const line of dataLines) {
        const parsed = JSON.parse(line.slice("data: ".length)) as {
          choices?: Array<{
            index?: number;
            delta?: {
              content?: string;
              tool_calls?: Array<{
                index?: number;
                function?: { arguments?: string };
              }>;
            };
          }>;
        };
        const choices = parsed.choices ?? [];
        for (let i = 0; i < choices.length; i += 1) {
          const ch = choices[i];
          const cIdx = typeof ch.index === "number" ? ch.index : i;
          const cDelta = ch.delta?.content;
          if (typeof cDelta === "string" && cDelta.length > 0) {
            allEmittedFragments.push(cDelta);
            contentByChoice.set(
              cIdx,
              (contentByChoice.get(cIdx) ?? "") + cDelta,
            );
          }
          const tcs = ch.delta?.tool_calls ?? [];
          for (let j = 0; j < tcs.length; j += 1) {
            const tc = tcs[j];
            const tcIdx = typeof tc.index === "number" ? tc.index : j;
            const argDelta = tc.function?.arguments;
            if (typeof argDelta === "string" && argDelta.length > 0) {
              allEmittedFragments.push(argDelta);
              const key = `${cIdx}:${tcIdx}`;
              toolArgsByChoiceAndIndex.set(
                key,
                (toolArgsByChoiceAndIndex.get(key) ?? "") + argDelta,
              );
            }
          }
        }
      }

      return {
        contentByChoice,
        toolArgsByChoiceAndIndex,
        allEmittedFragments,
      };
    };

    try {
      // Scenario 1: 3-chunk split placeholders, two parallel tool calls, two choices, and finish_reason flush
      streamScenario = "finish_reason";
      const res1 = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            stream: true,
            messages: [
              {
                role: "user",
                content:
                  "Contact dana.reyes@example.com on 10.42.7.19 with key sk_live_51HxYzAbCdEfGhIjKlMn.",
              },
            ],
          }),
        },
      );
      expect(res1.status).toBe(200);
      const rawSse1 = await res1.text();
      expect(rawSse1).toContain("data: [DONE]");

      const parsed1 = parseSseStream(rawSse1);
      // Never emits a partial placeholder fragment for EMAIL_1, IP_1, or SECRET_1
      for (const frag of parsed1.allEmittedFragments) {
        expect(frag).not.toContain("[EMAIL");
        expect(frag).not.toContain("AIL_1]");
        expect(frag).not.toContain("[IP");
        expect(frag).not.toContain("P_1]");
        expect(frag).not.toContain("[SEC");
        expect(frag).not.toContain("RET_1]");
      }

      expect(parsed1.contentByChoice.get(0)).toBe(
        "Choice0 dana.reyes@example.com!",
      );
      expect(parsed1.contentByChoice.get(1)).toBe("Choice1 10.42.7.19!");
      expect(parsed1.toolArgsByChoiceAndIndex.get("0:0")).toBe(
        '{"to":"dana.reyes@example.com","tag":"[UNCLOSED0',
      );
      expect(parsed1.toolArgsByChoiceAndIndex.get("0:1")).toBe(
        '{"host":"10.42.7.19"}',
      );
      expect(parsed1.toolArgsByChoiceAndIndex.get("1:0")).toBe(
        '{"key":"sk_live_51HxYzAbCdEfGhIjKlMn"}',
      );

      // Scenario 2: Stream ending without finish_reason flushes on [DONE]
      streamScenario = "no_finish_reason";
      const res2 = await fetch(
        `http://127.0.0.1:${started.port}/v1/chat/completions`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "kimi-k3",
            stream: true,
            messages: [
              {
                role: "user",
                content:
                  "Contact dana.reyes@example.com on 10.42.7.19 with key sk_live_51HxYzAbCdEfGhIjKlMn.",
              },
            ],
          }),
        },
      );
      expect(res2.status).toBe(200);
      const rawSse2 = await res2.text();
      expect(rawSse2).toContain("data: [DONE]");

      const parsed2 = parseSseStream(rawSse2);
      for (const frag of parsed2.allEmittedFragments) {
        expect(frag).not.toContain("[EMAIL");
        expect(frag).not.toContain("AIL_1]");
        expect(frag).not.toContain("[IP_1]");
      }
      expect(parsed2.contentByChoice.get(0)).toBe(
        "Stream dana.reyes@example.com [OPEN_END",
      );
      expect(parsed2.toolArgsByChoiceAndIndex.get("0:0")).toBe(
        '{"to":"dana.reyes@example.com","note":"[PARTIAL_AT_EOF',
      );
      expect(parsed2.toolArgsByChoiceAndIndex.get("1:0")).toBe(
        '{"ip":"10.42.7.19","tail":"[TAIL_OPEN',
      );
    } finally {
      await started.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
