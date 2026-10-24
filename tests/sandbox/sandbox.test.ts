import { describe, expect, it } from "vitest";
import {
  AgentEnvSandbox,
  decryptSandboxStdout,
  destroySandbox,
  execInSandbox,
  forkSandbox,
  pauseSandbox,
  spawnSandbox,
} from "@/lib/sandbox/microvm";

describe("Enclave-to-Enclave Attested Agent Tool Sandbox (AgentENV)", () => {
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
