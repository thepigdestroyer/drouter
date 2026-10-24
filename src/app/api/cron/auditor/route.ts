import { NextResponse, connection } from "next/server";
import {
  MAX_CALLS_PER_AUDIT,
  executeMysteryShopperAudit,
  getAuditorRunsHistory,
  saveAuditorRun,
} from "@/lib/auditor";
import { bytesEqual, utf8 } from "@/lib/sim/bytes";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";

const ALLOWED_MODELS = new Set<string>(TINFOIL_MODELS.map((m) => m.id));

function verifyCronAuthorization(request: Request): {
  ok: boolean;
  status: number;
  error?: string;
} {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.trim().length === 0) {
    return {
      ok: false,
      status: 401,
      error: "Unauthorized: CRON_SECRET is not configured or missing Bearer token",
    };
  }

  const authHeader = request.headers.get("authorization") ?? "";
  const expected = `Bearer ${secret}`;
  const actualBytes = utf8(authHeader);
  const expectedBytes = utf8(expected);

  if (!bytesEqual(actualBytes, expectedBytes)) {
    return {
      ok: false,
      status: 401,
      error: "Unauthorized: invalid Bearer CRON_SECRET header",
    };
  }

  return { ok: true, status: 200 };
}

export async function GET(request: Request) {
  await connection();

  const auth = verifyCronAuthorization(request);
  if (!auth.ok) {
    return NextResponse.json({ ok: false, error: auth.error }, { status: auth.status });
  }

  let requestedModel = "kimi-k3";
  try {
    const url = new URL(request.url, "http://localhost");
    const modelParam = url.searchParams.get("model");
    if (modelParam && ALLOWED_MODELS.has(modelParam)) {
      requestedModel = modelParam;
    }
  } catch {
    // Use default model
  }

  // Carry forward cumulative SPRT log-likelihood ratio for the same model if previous runs exist
  const historyState = await getAuditorRunsHistory(10);
  const priorForModel = historyState.history.find((r) => r.model === requestedModel);
  const initialLlr =
    priorForModel && priorForModel.verdict === "CONTINUE_SAMPLING"
      ? priorForModel.cumulativeSprtStatistic
      : 0;

  try {
    const execution = await executeMysteryShopperAudit({
      model: requestedModel,
      maxCalls: MAX_CALLS_PER_AUDIT,
      initialLlr,
    });

    const saved = await saveAuditorRun(execution.run);

    return NextResponse.json({
      ok: true,
      storedInMongo: saved.storedInMongo,
      run: saved.sanitized,
      sprt: execution.sprt,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to run mystery-shopper audit";
    return NextResponse.json(
      { ok: false, error: message },
      { status: 502 },
    );
  }
}
