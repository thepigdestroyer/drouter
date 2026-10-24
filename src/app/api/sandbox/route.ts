import { NextResponse, connection } from "next/server";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import {
  MAX_SANDBOX_CODE_CHARS,
  MAX_SANDBOX_OUTPUT_BYTES,
  SANDBOX_DESCRIPTION,
  SANDBOX_ISOLATION_MODE,
  destroySandbox,
  execInSandbox,
  forkSandbox,
  getSandboxCapabilities,
  normalizeSandboxLanguage,
  pauseSandbox,
  spawnSandbox,
} from "@/lib/sandbox/microvm";
import { runInVercelSandbox } from "@/lib/sandbox/vercel-runner";

const MAX_SANDBOX_POST_BODY_BYTES = 16_384; // 16 KB strict body cap
const MAX_CONCURRENT_SANDBOXES = 2;

const sandboxGetLimiter = createTokenBucketLimiter({
  name: "sandbox-get",
  capacity: 120,
  refillPerSec: 4,
});

const sandboxPostIpLimiter = createTokenBucketLimiter({
  name: "sandbox-post-ip",
  capacity: 6,
  refillPerSec: 1 / 20,
});

const sandboxPostGlobalLimiter = createGlobalBucketLimiter({
  name: "sandbox-post-global",
  capacity: 20,
  refillPerSec: 20 / 3600,
});

const globalForSandboxConcurrency = globalThis as unknown as {
  __drouterSandboxActiveCount?: number;
};

export function getActiveSandboxCount(): number {
  return globalForSandboxConcurrency.__drouterSandboxActiveCount ?? 0;
}

export function resetSandboxRouteStateForTests(): void {
  globalForSandboxConcurrency.__drouterSandboxActiveCount = 0;
  sandboxPostGlobalLimiter.reset();
}

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = sandboxGetLimiter.check(request);
    if (limited) return limited;
  }

  const startedAt = Date.now();
  const sessionId = "ehbp-sess-kimi-k3-1m-demo";
  const parent = spawnSandbox(sessionId);

  const parentExec1 = execInSandbox(parent, {
    tool: "python",
    code: "portfolio_npv = 1250000; print(portfolio_npv)",
  });

  const parentExec2 = execInSandbox(parent, {
    tool: "bash",
    code: 'echo "CONFIDENTIAL_MERGER_TARGET=Helios" > /tmp/deal.env',
  });

  const pauseReceipt = pauseSandbox(parent);

  const child = forkSandbox(parent);

  const childSpeculativeExec = execInSandbox(child, {
    tool: "python",
    code: "portfolio_npv = 0; print(portfolio_npv)",
  });

  const parentVerifyExec = execInSandbox(parent, {
    tool: "python",
    code: "print(portfolio_npv)",
  });

  const childDestroyReceipt = destroySandbox(child);
  const parentDestroyReceipt = destroySandbox(parent);
  const durationMs = Math.max(1, Date.now() - startedAt);
  const capabilities = getSandboxCapabilities({
    maxBodyBytes: MAX_SANDBOX_POST_BODY_BYTES,
    maxConcurrentExecutions: MAX_CONCURRENT_SANDBOXES,
  });

  return NextResponse.json({
    isolation: SANDBOX_ISOLATION_MODE,
    description: SANDBOX_DESCRIPTION,
    sandboxId: parent.sandboxId,
    durationMs,
    capabilities,
    sessionId,
    specReference: SANDBOX_DESCRIPTION,
    trace: {
      spawn: {
        sandboxId: parent.sandboxId,
        imageMeasurementHex: parent.imageMeasurementHex,
        rtmr3Hex: parent.rtmr3Hex,
      },
      exec: [parentExec1, parentExec2],
      pause: pauseReceipt,
      fork: {
        childSandboxId: child.sandboxId,
        parentSandboxId: child.parentSandboxId,
        childSpeculativeExec,
        parentVerifyExec,
        parentStatePreserved:
          parentVerifyExec.decryptedStdoutForTest === "1250000",
      },
      destroy: {
        child: childDestroyReceipt,
        parent: parentDestroyReceipt,
      },
    },
  });
}

interface SandboxPostBody {
  language?: string;
  tool?: string;
  code?: unknown;
  timeoutMs?: number;
}

export async function POST(request: Request) {
  let body: SandboxPostBody;
  try {
    body = await readBoundedJson<SandboxPostBody>(
      request,
      MAX_SANDBOX_POST_BODY_BYTES
    );
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json(
        {
          error: err.message,
          isolation: SANDBOX_ISOLATION_MODE,
        },
        { status: 413 }
      );
    }
    if (err instanceof InvalidJsonBodyError) {
      return NextResponse.json(
        {
          error: err.message,
          isolation: SANDBOX_ISOLATION_MODE,
        },
        { status: 400 }
      );
    }
    return NextResponse.json(
      {
        error: "Malformed request body",
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 400 }
    );
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return NextResponse.json(
      {
        error: "Request body must be a JSON object.",
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 400 }
    );
  }

  if (typeof body.code !== "string" || body.code.trim().length === 0) {
    return NextResponse.json(
      {
        error: "Field `code` must be a non-empty string.",
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 400 }
    );
  }

  if (body.code.length > MAX_SANDBOX_CODE_CHARS) {
    return NextResponse.json(
      {
        error: `Field \`code\` exceeds maximum length of ${MAX_SANDBOX_CODE_CHARS} characters.`,
        maxCodeChars: MAX_SANDBOX_CODE_CHARS,
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 413 }
    );
  }

  if (body.code.includes("\0")) {
    return NextResponse.json(
      {
        error: "Field `code` must not contain NUL bytes.",
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 400 }
    );
  }

  let runtime: "python3" | "node";
  try {
    runtime = normalizeSandboxLanguage(body.language ?? body.tool ?? "python3");
  } catch (err) {
    return NextResponse.json(
      {
        error: err instanceof Error ? err.message : "Unsupported language",
        isolation: SANDBOX_ISOLATION_MODE,
      },
      { status: 400 }
    );
  }

  // Per-IP rate limit
  const ipLimited = sandboxPostIpLimiter.check(request);
  if (ipLimited) return ipLimited;

  // Global rate limit
  const globalDecision = sandboxPostGlobalLimiter.consume(1);
  if (!globalDecision.allowed) {
    return NextResponse.json(
      {
        error: "Global sandbox execution rate limit exceeded. Please retry later.",
        retryAfterSec: globalDecision.retryAfterSec,
        isolation: SANDBOX_ISOLATION_MODE,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(globalDecision.retryAfterSec),
          "Cache-Control": "no-store",
        },
      }
    );
  }

  // Global concurrency limit (1 to 2 concurrent sandboxes)
  const active = globalForSandboxConcurrency.__drouterSandboxActiveCount ?? 0;
  if (active >= MAX_CONCURRENT_SANDBOXES) {
    return NextResponse.json(
      {
        error: `Global sandbox concurrency limit (${MAX_CONCURRENT_SANDBOXES}) reached. Please retry shortly.`,
        retryAfterSec: 5,
        isolation: SANDBOX_ISOLATION_MODE,
      },
      {
        status: 429,
        headers: {
          "Retry-After": "5",
          "Cache-Control": "no-store",
        },
      }
    );
  }

  globalForSandboxConcurrency.__drouterSandboxActiveCount = active + 1;
  try {
    const result = await runInVercelSandbox({
      language: runtime,
      code: body.code,
      timeoutMs: body.timeoutMs,
      maxOutputBytes: MAX_SANDBOX_OUTPUT_BYTES,
    });

    // Also include legacy state-tracker fields for backward compatibility
    const sim = spawnSandbox(`live-${result.sandboxId}`);
    const simExec = execInSandbox(sim, {
      tool: "python",
      code: body.code.slice(0, 256),
    });
    const simDestroy = destroySandbox(sim);

    return NextResponse.json(
      {
        ok: result.exitCode === 0,
        isolation: SANDBOX_ISOLATION_MODE,
        description: SANDBOX_DESCRIPTION,
        specReference: SANDBOX_DESCRIPTION,
        sandboxId: result.sandboxId,
        sandboxName: result.sandboxName,
        language: result.language,
        filePath: result.filePath,
        stdout: result.stdout,
        stderr: result.stderr,
        stdoutTruncated: result.stdoutTruncated,
        stderrTruncated: result.stderrTruncated,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        vcpus: result.vcpus,
        memoryMb: result.memoryMb,
        stopped: result.stopped,
        envPassedToSandbox: false,
        sessionId: sim.sessionId,
        trace: {
          spawn: {
            sandboxId: result.sandboxId,
            imageMeasurementHex: sim.imageMeasurementHex,
            rtmr3Hex: sim.rtmr3Hex,
          },
          exec: [
            {
              ...simExec,
              exitCode: result.exitCode,
              durationMs: result.durationMs,
              decryptedStdoutForTest: result.stdout,
            },
          ],
          destroy: {
            parent: simDestroy,
          },
        },
      },
      {
        status: 200,
        headers: { "Cache-Control": "no-store" },
      }
    );
  } catch (err) {
    const rawMsg = err instanceof Error ? err.message : "Sandbox execution failed";
    return NextResponse.json(
      {
        ok: false,
        isolation: SANDBOX_ISOLATION_MODE,
        description: SANDBOX_DESCRIPTION,
        error: rawMsg,
      },
      {
        status: 502,
        headers: { "Cache-Control": "no-store" },
      }
    );
  } finally {
    const current = globalForSandboxConcurrency.__drouterSandboxActiveCount ?? 1;
    globalForSandboxConcurrency.__drouterSandboxActiveCount = Math.max(0, current - 1);
  }
}
