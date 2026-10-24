import { NextResponse, connection } from "next/server";
import {
  issuerPublicInfo,
  ledgerStats,
  mintBlindedBatch,
} from "@/lib/credits/ledger";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_CREDITS_MINT_BODY_BYTES = 32_768;

/**
 * Free daily allowance per salted IP hash: 10 credit units per UTC day
 * (salted in-memory token bucket; raw IPs are never stored).
 */
export const FREE_DAILY_CREDIT_ALLOWANCE = 10;

const getLimiter = createTokenBucketLimiter({
  name: "credits-get",
  capacity: 60,
  refillPerSec: 2,
});

const mintBurstLimiter = createTokenBucketLimiter({
  name: "credits-mint-burst",
  capacity: 20,
  refillPerSec: 20 / 60,
});

const freeDailyAllowanceLimiter = createTokenBucketLimiter({
  name: "credits-free-daily",
  capacity: FREE_DAILY_CREDIT_ALLOWANCE,
  refillPerSec: FREE_DAILY_CREDIT_ALLOWANCE / 86_400,
});

export async function GET(request?: Request) {
  try {
    await connection();
  } catch {
    // Allow direct handler invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }
  return NextResponse.json({
    ...issuerPublicInfo(),
    freeDailyAllowance: FREE_DAILY_CREDIT_ALLOWANCE,
    stats: ledgerStats(),
  });
}

export async function POST(request: Request) {
  const limited = mintBurstLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<Record<string, unknown>>(
      request,
      MAX_CREDITS_MINT_BODY_BYTES
    );

    if (
      body &&
      ("txHash" in body ||
        "payerAddress" in body ||
        "walletAddress" in body ||
        "sender" in body)
    ) {
      return NextResponse.json(
        {
          error:
            "Direct txHash and static-address payments have been removed. Request a one-time deposit address at POST /api/credits/invoice and claim via POST /api/credits/claim.",
        },
        { status: 400 }
      );
    }

    const blinded = body?.blinded;
    if (!Array.isArray(blinded) || blinded.length === 0) {
      return NextResponse.json(
        { error: "Request body must provide a non-empty 'blinded' array" },
        { status: 400 }
      );
    }

    if (blinded.some((b) => typeof b !== "string" || b.length > 1024)) {
      return NextResponse.json(
        { error: "Each blinded token must be a hex string <= 1024 chars" },
        { status: 400 }
      );
    }

    const denomination =
      typeof body.denomination === "number" ? body.denomination : 1;

    // Free path: enforce daily allowance per salted IP hash (cost = count * denomination)
    const creditCost = blinded.length * Math.max(1, denomination);
    const allowance = freeDailyAllowanceLimiter.consume(request, creditCost);
    if (!allowance.allowed) {
      const info = issuerPublicInfo();
      return NextResponse.json(
        {
          error: `Free daily credit allowance (${FREE_DAILY_CREDIT_ALLOWANCE} credits/day) exhausted. Request a one-time deposit address at POST /api/credits/invoice and claim blind credits via POST /api/credits/claim.`,
          retryAfterSec: allowance.retryAfterSec,
          chainId: info.chainId,
          usdcContract: info.usdcContract,
          usdcDecimals: info.usdcDecimals,
          usdcPerCredit: info.usdcPerCredit,
          invoiceDenominationsUsdc: info.invoiceDenominationsUsdc,
        },
        {
          status: 402,
          headers: {
            "Retry-After": String(allowance.retryAfterSec),
            "Cache-Control": "no-store",
          },
        }
      );
    }

    const result = mintBlindedBatch(blinded as string[], denomination);

    return NextResponse.json({
      ...result,
      mode: "free-allowance",
      remainingFreeToday: allowance.remaining,
      stats: ledgerStats(),
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    const message =
      err instanceof InvalidJsonBodyError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Failed to sign blinded tokens";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
