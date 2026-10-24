import { beforeEach, describe, expect, it, vi } from "vitest";

const mockSandboxState = vi.hoisted(() => {
  const createCalls: Array<Record<string, unknown>> = [];
  const writeFilesCalls: Array<Array<{ path: string; content: Buffer | string; mode?: number }>> = [];
  const runCommandCalls: Array<Record<string, unknown>> = [];
  let stopCalled = 0;
  let deleteCalled = 0;
  let nextStdout = "42\n";
  let nextStderr = "";
  let nextExitCode = 0;
  let delayMs = 0;

  return {
    createCalls,
    writeFilesCalls,
    runCommandCalls,
    get stopCalled() {
      return stopCalled;
    },
    get deleteCalled() {
      return deleteCalled;
    },
    reset() {
      createCalls.length = 0;
      writeFilesCalls.length = 0;
      runCommandCalls.length = 0;
      stopCalled = 0;
      deleteCalled = 0;
      nextStdout = "42\n";
      nextStderr = "";
      nextExitCode = 0;
      delayMs = 0;
    },
    setNextOutput(opts: { stdout?: string; stderr?: string; exitCode?: number; delayMs?: number }) {
      nextStdout = opts.stdout ?? "";
      nextStderr = opts.stderr ?? "";
      nextExitCode = opts.exitCode ?? 0;
      delayMs = opts.delayMs ?? 0;
    },
    incStop() {
      stopCalled += 1;
    },
    incDelete() {
      deleteCalled += 1;
    },
    get nextStdout() {
      return nextStdout;
    },
    get nextStderr() {
      return nextStderr;
    },
    get nextExitCode() {
      return nextExitCode;
    },
    get delayMs() {
      return delayMs;
    },
  };
});

vi.mock("@vercel/sandbox", () => {
  return {
    Sandbox: {
      create: vi.fn(async (params: Record<string, unknown> = {}) => {
        mockSandboxState.createCalls.push(params);
        return {
          name: "sbx-mock-firecracker-01",
          vcpus: 1,
          memory: 2048,
          currentSession: () => ({
            sessionId: "sbx_mock_session_01",
          }),
          writeFiles: vi.fn(async (files: Array<{ path: string; content: Buffer | string; mode?: number }>) => {
            mockSandboxState.writeFilesCalls.push(files);
          }),
          runCommand: vi.fn(async (cmdParams: Record<string, unknown>) => {
            mockSandboxState.runCommandCalls.push(cmdParams);
            if (mockSandboxState.delayMs > 0) {
              await new Promise((r) => setTimeout(r, mockSandboxState.delayMs));
            }
            const out = mockSandboxState.nextStdout;
            const err = mockSandboxState.nextStderr;
            const code = mockSandboxState.nextExitCode;
            return {
              exitCode: code,
              stdout: async () => out,
              stderr: async () => err,
            };
          }),
          stop: vi.fn(async () => {
            mockSandboxState.incStop();
            return {};
          }),
          delete: vi.fn(async () => {
            mockSandboxState.incDelete();
          }),
        };
      }),
    },
  };
});

vi.mock("next/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/server")>();
  return {
    ...actual,
    connection: vi.fn(async () => {}),
  };
});

import {
  AgentEnvSandbox,
  MAX_SANDBOX_CODE_CHARS,
  SANDBOX_DESCRIPTION,
  SANDBOX_ISOLATION_MODE,
  capOutputText,
  decryptSandboxStdout,
  destroySandbox,
  execInSandbox,
  forkSandbox,
  getSandboxCapabilities,
  normalizeSandboxLanguage,
  pauseSandbox,
  spawnSandbox,
} from "@/lib/sandbox/microvm";
import { runInVercelSandbox } from "@/lib/sandbox/vercel-runner";
import {
  GET,
  POST,
  resetSandboxRouteStateForTests,
} from "@/app/api/sandbox/route";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";

describe("Vercel Sandbox Firecracker microVM integration & API route", () => {
  beforeEach(() => {
    mockSandboxState.reset();
    resetSandboxRouteStateForTests();
    resetRateLimitStateForTests();
  });

  it("executes Python and Node code via @vercel/sandbox without leaking any host env vars", async () => {
    process.env.SUPER_SECRET_TEST_TOKEN = "do-not-leak-me";
    mockSandboxState.setNextOutput({ stdout: "hello from firecracker\n", exitCode: 0 });

    const res = await runInVercelSandbox({
      language: "python3",
      code: 'print("hello from firecracker")',
    });

    expect(res.isolation).toBe("vercel-sandbox-firecracker");
    expect(res.description).toBe(
      "Vercel Sandbox is an isolated Firecracker microVM, not a hardware-attested enclave."
    );
    expect(res.sandboxId).toBe("sbx_mock_session_01");
    expect(res.language).toBe("python3");
    expect(res.filePath).toBe("/tmp/user_code.py");
    expect(res.stdout).toBe("hello from firecracker\n");
    expect(res.exitCode).toBe(0);
    expect(res.stopped).toBe(true);
    expect(res.durationMs).toBeGreaterThan(0);

    // Verify smallest resources, short timeout, non-persistent, and empty env
    expect(mockSandboxState.createCalls).toHaveLength(1);
    const createArgs = mockSandboxState.createCalls[0];
    expect(createArgs.resources).toEqual({ vcpus: 1 });
    expect(createArgs.persistent).toBe(false);
    expect(createArgs.env).toEqual({});

    // Verify runCommand also receives an empty env and never receives process.env
    expect(mockSandboxState.runCommandCalls).toHaveLength(1);
    const cmdArgs = mockSandboxState.runCommandCalls[0];
    expect(cmdArgs.cmd).toBe("python3");
    expect(cmdArgs.args).toEqual(["/tmp/user_code.py"]);
    expect(cmdArgs.env).toEqual({});
    expect(cmdArgs.sudo).toBe(false);

    // Verify stop() was called
    expect(mockSandboxState.stopCalled).toBe(1);
    delete process.env.SUPER_SECRET_TEST_TOKEN;
  });

  it("caps oversized stdout and stderr streams to maxOutputBytes", async () => {
    const hugeOut = "A".repeat(20_000);
    const hugeErr = "E".repeat(20_000);
    mockSandboxState.setNextOutput({
      stdout: hugeOut,
      stderr: hugeErr,
      exitCode: 0,
    });

    const res = await runInVercelSandbox({
      language: "node",
      code: 'console.log("A".repeat(20000))',
      maxOutputBytes: 1024,
    });

    expect(res.language).toBe("node");
    expect(res.filePath).toBe("/tmp/user_code.js");
    expect(res.stdoutTruncated).toBe(true);
    expect(res.stderrTruncated).toBe(true);
    expect(res.stdout.length).toBe(1024);
    expect(res.stderr.length).toBe(1024);
  });

  it("GET /api/sandbox returns capability info and isolation metadata", async () => {
    const req = new Request("http://localhost:3000/api/sandbox", { method: "GET" });
    const response = await GET(req);
    expect(response.status).toBe(200);
    const json = await response.json();

    expect(json.isolation).toBe(SANDBOX_ISOLATION_MODE);
    expect(json.description).toBe(SANDBOX_DESCRIPTION);
    expect(json.specReference).toBe(SANDBOX_DESCRIPTION);
    expect(json.sandboxId).toMatch(/^sbx-/);
    expect(typeof json.durationMs).toBe("number");
    expect(json.capabilities.hardwareAttested).toBe(false);
    expect(json.capabilities.tee).toBe(false);
    expect(json.capabilities.envPassedToSandbox).toBe(false);
    expect(json.trace.fork.parentStatePreserved).toBe(true);
  });

  it("POST /api/sandbox runs code and enforces body cap, code length cap, rate limits, and concurrency limit", async () => {
    mockSandboxState.setNextOutput({ stdout: "84\n", exitCode: 0 });

    const validReq = new Request("http://localhost:3000/api/sandbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.10",
      },
      body: JSON.stringify({
        language: "python3",
        code: "print(42 * 2)",
      }),
    });

    const res = await POST(validReq);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.isolation).toBe("vercel-sandbox-firecracker");
    expect(body.sandboxId).toBe("sbx_mock_session_01");
    expect(body.stdout).toBe("84\n");
    expect(typeof body.durationMs).toBe("number");
    expect(body.envPassedToSandbox).toBe(false);

    // Code length cap check
    const tooLongCodeReq = new Request("http://localhost:3000/api/sandbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.11",
      },
      body: JSON.stringify({
        language: "python3",
        code: "x = 1\n".repeat(2000), // > 8192 chars
      }),
    });
    const tooLongRes = await POST(tooLongCodeReq);
    expect(tooLongRes.status).toBe(413);

    // Body size cap check (> 16 KB)
    const hugeBodyReq = new Request("http://localhost:3000/api/sandbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.12",
      },
      body: JSON.stringify({
        language: "python3",
        code: "print(1)",
        extraPadding: "P".repeat(20_000),
      }),
    });
    const hugeBodyRes = await POST(hugeBodyReq);
    expect(hugeBodyRes.status).toBe(413);

    // Concurrency limit check (max 2 concurrent sandboxes)
    mockSandboxState.setNextOutput({ stdout: "slow\n", exitCode: 0, delayMs: 80 });
    const makeSlowReq = (ip: string) =>
      POST(
        new Request("http://localhost:3000/api/sandbox", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": ip,
          },
          body: JSON.stringify({ language: "node", code: "console.log('slow')" }),
        })
      );

    const [c1, c2, c3] = await Promise.all([
      makeSlowReq("198.51.100.1"),
      makeSlowReq("198.51.100.2"),
      makeSlowReq("198.51.100.3"),
    ]);
    const statuses = [c1.status, c2.status, c3.status].sort();
    expect(statuses).toEqual([200, 200, 429]);

    // Per-IP rate limit check (capacity 6 per IP)
    mockSandboxState.setNextOutput({ stdout: "fast\n", exitCode: 0, delayMs: 0 });
    let rateLimitedSeen = false;
    for (let i = 0; i < 8; i++) {
      const r = await POST(
        new Request("http://localhost:3000/api/sandbox", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "192.0.2.99",
          },
          body: JSON.stringify({ language: "python3", code: "print(1)" }),
        })
      );
      if (r.status === 429) {
        rateLimitedSeen = true;
        break;
      }
    }
    expect(rateLimitedSeen).toBe(true);
  });

  it("normalizeSandboxLanguage and capOutputText helpers validate inputs", () => {
    expect(normalizeSandboxLanguage("python")).toBe("python3");
    expect(normalizeSandboxLanguage("python3")).toBe("python3");
    expect(normalizeSandboxLanguage("node")).toBe("node");
    expect(normalizeSandboxLanguage("javascript")).toBe("node");
    expect(() => normalizeSandboxLanguage("ruby")).toThrow(/Unsupported/);

    const capped = capOutputText("abcdef", 3);
    expect(capped).toEqual({ text: "abc", truncated: true });
    expect(MAX_SANDBOX_CODE_CHARS).toBe(8192);
    expect(getSandboxCapabilities().isolation).toBe("vercel-sandbox-firecracker");
  });
});

describe("MicroVM State Tracker Compatibility (spawn -> exec -> pause -> fork -> destroy)", () => {
  it("runs the full spawn -> exec -> pause -> fork -> destroy lifecycle", () => {
    const sessionId = "session-kimi-k3-trajectory-01";
    const sbx = spawnSandbox(sessionId);

    expect(sbx.sessionId).toBe(sessionId);
    expect(sbx.status).toBe("running");
    expect(sbx.cpuAllocated).toBe(true);
    expect(sbx.ramAllocated).toBe(true);
    expect(sbx.dirtyPagesCount).toBeGreaterThan(0);

    const keyHexBeforeDestroy = sbx.sessionKeyHex;

    const execRes = execInSandbox(sbx, {
      tool: "math",
      code: "21 * 2",
    });

    expect(execRes.exitCode).toBe(0);
    expect(execRes.decryptedStdoutForTest).toBe("42");
    expect(execRes.stdoutCiphertextHex).toBeTruthy();
    expect(execRes.nonceHex).toHaveLength(24);
    expect(execRes.dirtyPagesCount).toBe(sbx.dirtyPagesCount);
    expect(
      decryptSandboxStdout(
        sbx,
        keyHexBeforeDestroy,
        execRes.stdoutCiphertextHex,
        execRes.nonceHex
      )
    ).toBe("42");

    const pauseRes = pauseSandbox(sbx);
    expect(pauseRes.status).toBe("paused");
    expect(pauseRes.cpuAllocated).toBe(false);
    expect(pauseRes.ramAllocated).toBe(false);
    expect(pauseRes.resumeLatencyMs).toBe(49);
    expect(pauseRes.checkpointLatencyMs).toBe(133);
    expect(pauseRes.checkpointCiphertextHex).toBeTruthy();

    const child = forkSandbox(sbx);
    expect(child.parentSandboxId).toBe(sbx.sandboxId);
    expect(child.sessionId).toBe(sbx.sessionId);

    const destroyChild = destroySandbox(child);
    expect(destroyChild.status).toBe("destroyed");
    expect(destroyChild.zeroedPages).toBe(destroyChild.totalPages);
    expect(destroyChild.keyZeroed).toBe(true);

    const destroyParent = destroySandbox(sbx);
    expect(destroyParent.status).toBe("destroyed");
    expect(destroyParent.zeroedPages).toBe(destroyParent.totalPages);
    expect(destroyParent.totalPages).toBeGreaterThan(0);
    expect(destroyParent.keyZeroed).toBe(true);
  });

  it("forkSandbox inherits parent state with copy-on-write isolation without mutating parent", () => {
    const parent = spawnSandbox("session-cow-fork-test");

    execInSandbox(parent, {
      tool: "python",
      code: "secret_alpha = 9001; print(secret_alpha)",
    });
    execInSandbox(parent, {
      tool: "bash",
      code: 'echo "parent-secret-payload" > /tmp/vault.txt',
    });

    const parentPagesBeforeFork = parent.dirtyPagesCount;
    const child = forkSandbox(parent);

    // Child inherits parent's variables and files
    const childReadParentVar = execInSandbox(child, {
      tool: "python",
      code: "print(secret_alpha)",
    });
    expect(childReadParentVar.decryptedStdoutForTest).toBe("9001");

    const childReadParentFile = execInSandbox(child, {
      tool: "bash",
      code: "cat /tmp/vault.txt",
    });
    expect(childReadParentFile.decryptedStdoutForTest).toBe(
      "parent-secret-payload"
    );

    // Mutate state in child
    execInSandbox(child, {
      tool: "python",
      code: "secret_alpha = 0; child_only = 777",
    });
    execInSandbox(child, {
      tool: "bash",
      code: 'echo "mutated-by-child" > /tmp/vault.txt',
    });

    // Verify parent state and dirty pages were not mutated by child executions
    expect(parent.dirtyPagesCount).toBe(parentPagesBeforeFork);
    expect(parent.env.secret_alpha).toBe("9001");
    expect(parent.env.child_only).toBeUndefined();
    expect(parent.files["/tmp/vault.txt"]).toBe("parent-secret-payload");

    const parentVerifyVar = execInSandbox(parent, {
      tool: "python",
      code: "print(secret_alpha)",
    });
    expect(parentVerifyVar.decryptedStdoutForTest).toBe("9001");

    const parentVerifyFile = execInSandbox(parent, {
      tool: "bash",
      code: "cat /tmp/vault.txt",
    });
    expect(parentVerifyFile.decryptedStdoutForTest).toBe(
      "parent-secret-payload"
    );
  });

  it("destroySandbox zeroes all pages and blocks subsequent execInSandbox, pauseSandbox, and forkSandbox calls", () => {
    const sbx = new AgentEnvSandbox("session-zeroize-test");
    sbx.exec({ tool: "python", code: "x = 123; print(x)" });

    const receipt = sbx.destroy();
    expect(receipt.zeroedPages).toBe(receipt.totalPages);
    expect(receipt.totalPages).toBeGreaterThan(0);
    expect(receipt.keyZeroed).toBe(true);
    expect(sbx.instance.sessionKey.every((b) => b === 0)).toBe(true);
    expect(
      sbx.instance.dirtyPages.every((page) => page.every((b) => b === 0))
    ).toBe(true);

    expect(() =>
      sbx.exec({ tool: "python", code: "print(x)" })
    ).toThrow(/destroyed/i);
    expect(() => sbx.pause()).toThrow(/destroyed/i);
    expect(() => sbx.fork()).toThrow(/destroyed/i);
  });
});
