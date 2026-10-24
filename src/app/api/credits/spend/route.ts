import { NextResponse } from "next/server";
import type { BlindCreditToken } from "@/lib/types";
import { ledgerStats, spendToken } from "@/lib/credits/ledger";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_CREDITS_SPEND_BODY_BYTES = 8192;

const spendLimiter = createTokenBucketLimiter({
  name: "credits-spend",
  capacity: 30,
  refillPerSec: 0.5,
});

export async function POST(request: Request) {
  const limited = spendLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<{
      token?: BlindCreditToken;
      nodeId?: string;
    }>(request, MAX_CREDITS_SPEND_BODY_BYTES);
    if (!body || !body.token) {
      return NextResponse.json(
        { ok: false, error: "Missing 'token' in request body" },
        { status: 400 }
      );
    }

    const safeNodeId =
      typeof body.nodeId === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(body.nodeId)
        ? body.nodeId
        : "default-node";

    const result = await spendToken(body.token, safeNodeId);
    if (!result.ok) {
      return NextResponse.json(
        { ok: false, error: result.error, stats: ledgerStats() },
        { status: result.status }
      );
    }

    return NextResponse.json({
      ok: true,
      nullifier: result.nullifier,
      denomination: result.denomination,
      remainingPoolUnredeemed: result.remainingPoolUnredeemed,
      stats: ledgerStats(),
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ ok: false, error: err.message }, { status: 413 });
    }
    const message =
      err instanceof InvalidJsonBodyError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Failed to process token spend";
    return NextResponse.json({ ok: false, error: message }, { status: 400 });
  }
}
