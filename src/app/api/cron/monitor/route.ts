import { NextResponse, connection } from "next/server";
import {
  executeContinuousMonitorRun,
  type ExecuteMonitorOptions,
} from "@/lib/accountability";
import { bytesEqual, utf8 } from "@/lib/sim/bytes";

let testMonitorOptions: ExecuteMonitorOptions | null = null;

export function setCronMonitorTestOptions(opts: ExecuteMonitorOptions | null): void {
  testMonitorOptions = opts;
}

export function verifyCronMonitorAuthorization(request: Request): {
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

  const auth = verifyCronMonitorAuthorization(request);
  if (!auth.ok) {
    return NextResponse.json({ ok: false, error: auth.error }, { status: auth.status });
  }

  try {
    const result = await executeContinuousMonitorRun(testMonitorOptions ?? undefined);
    return NextResponse.json({
      ok: true,
      storedInMongo: result.storedInMongo,
      run: result.run,
      signedTreeHead: result.signedTreeHead,
      rampStates: result.rampStates,
      routerLatency: result.routerLatency,
      arcTransactionsUsed: result.arcTransactionsUsed,
    });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to run continuous enclave monitor";
    return NextResponse.json({ ok: false, error: message }, { status: 502 });
  }
}
