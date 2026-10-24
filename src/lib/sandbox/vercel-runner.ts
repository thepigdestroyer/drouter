// Server-only: imports the Node-only Vercel Sandbox SDK. Import this module only
// from route handlers, never from code that client components can reach.
import { Sandbox } from "@vercel/sandbox";
import {
  SANDBOX_ISOLATION_MODE,
  SANDBOX_DESCRIPTION,
  MAX_SANDBOX_CODE_CHARS,
  MAX_SANDBOX_OUTPUT_BYTES,
  DEFAULT_SANDBOX_TIMEOUT_MS,
  DEFAULT_COMMAND_TIMEOUT_MS,
  SMALLEST_SANDBOX_VCPUS,
  normalizeSandboxLanguage,
  capOutputText,
  type LiveSandboxRunOptions,
  type LiveSandboxRunResult,
} from "./microvm";

/**
 * Executes user code inside a real isolated Vercel Sandbox Firecracker microVM.
 * Vercel Sandbox is an isolated Firecracker microVM, not a hardware-attested enclave.
 *
 * Security invariants:
 * - Creates a fresh non-persistent microVM with smallest resources (1 vCPU) and short timeout.
 * - Writes user code to a file inside `/tmp` rather than interpolating into a shell string.
 * - Never passes any environment variable or secret from the host into `Sandbox.create` or `runCommand`.
 * - Caps stdout and stderr byte lengths.
 * - Always stops and deletes the sandbox in `finally`.
 */
export async function runInVercelSandbox(
  options: LiveSandboxRunOptions
): Promise<LiveSandboxRunResult> {
  if (typeof options.code !== "string" || options.code.trim().length === 0) {
    throw new Error("Sandbox code must be a non-empty string.");
  }
  if (options.code.length > MAX_SANDBOX_CODE_CHARS) {
    throw new Error(
      `Sandbox code exceeds maximum length of ${MAX_SANDBOX_CODE_CHARS} characters.`
    );
  }
  if (options.code.includes("\0")) {
    throw new Error("Sandbox code must not contain NUL bytes.");
  }

  const runtime = normalizeSandboxLanguage(options.language);
  const timeoutMs = Math.min(
    Math.max(options.timeoutMs ?? DEFAULT_SANDBOX_TIMEOUT_MS, 5_000),
    60_000
  );
  const commandTimeoutMs = Math.min(
    Math.max(options.commandTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS, 1_000),
    timeoutMs
  );
  const maxOutputBytes = Math.min(
    Math.max(options.maxOutputBytes ?? MAX_SANDBOX_OUTPUT_BYTES, 256),
    65_536
  );

  const filePath = runtime === "python3" ? "/tmp/user_code.py" : "/tmp/user_code.js";
  const startedAt = Date.now();

  // Never pass any host env var or secret into the sandbox.
  const emptyEnv: Record<string, string> = Object.freeze({});

  const sandbox = await Sandbox.create({
    timeout: timeoutMs,
    resources: { vcpus: SMALLEST_SANDBOX_VCPUS },
    persistent: false,
    env: { ...emptyEnv },
  });

  let stopped = false;
  let sandboxId = sandbox.name;
  try {
    try {
      const session = sandbox.currentSession();
      if (session?.sessionId) {
        sandboxId = session.sessionId;
      }
    } catch {
      sandboxId = sandbox.name;
    }

    await sandbox.writeFiles([
      {
        path: filePath,
        content: Buffer.from(options.code, "utf8"),
        mode: 0o600,
      },
    ]);

    const cmdResult = await sandbox.runCommand({
      cmd: runtime,
      args: [filePath],
      cwd: "/tmp",
      env: { ...emptyEnv },
      sudo: false,
      timeoutMs: commandTimeoutMs,
    });

    const [rawStdout, rawStderr] = await Promise.all([
      cmdResult.stdout(),
      cmdResult.stderr(),
    ]);

    const cappedOut = capOutputText(rawStdout, maxOutputBytes);
    const cappedErr = capOutputText(rawStderr, maxOutputBytes);

    try {
      await sandbox.stop();
      stopped = true;
    } catch {
      stopped = false;
    }
    try {
      await sandbox.delete();
    } catch {
      // Best-effort cleanup of non-persistent sandbox metadata
    }

    const durationMs = Math.max(1, Date.now() - startedAt);
    const vcpus = sandbox.vcpus ?? SMALLEST_SANDBOX_VCPUS;
    const memoryMb = sandbox.memory ?? vcpus * 2048;

    return {
      isolation: SANDBOX_ISOLATION_MODE,
      description: SANDBOX_DESCRIPTION,
      sandboxId,
      sandboxName: sandbox.name,
      language: runtime,
      filePath,
      stdout: cappedOut.text,
      stderr: cappedErr.text,
      stdoutTruncated: cappedOut.truncated,
      stderrTruncated: cappedErr.truncated,
      exitCode: cmdResult.exitCode ?? 1,
      durationMs,
      vcpus,
      memoryMb,
      stopped,
    };
  } finally {
    if (!stopped) {
      try {
        await sandbox.stop();
      } catch {
        // Ignore stop errors in finally if session already terminated
      }
      try {
        await sandbox.delete();
      } catch {
        // Ignore delete errors in finally
      }
    }
  }
}
