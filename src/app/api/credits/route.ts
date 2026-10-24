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

const getLimiter = createTokenBucketLimiter({
  name: "credits-get",
  capacity: 60,
  refillPerSec: 2,
});

const mintLimiter = createTokenBucketLimiter({
  name: "credits-mint",
  capacity: 20,
  refillPerSec: 20 / 60,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }
  return NextResponse.json({
    ...issuerPublicInfo(),
    stats: ledgerStats(),
  });
}

export async function POST(request: Request) {
  const limited = mintLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<{
      blinded?: string[];
      denomination?: number;
    }>(request, MAX_CREDITS_MINT_BODY_BYTES);
    if (!body || !Array.isArray(body.blinded) || body.blinded.length === 0) {
      return NextResponse.json(
        { error: "Request body must provide a non-empty 'blinded' array" },
        { status: 400 }
      );
    }

    if (body.blinded.some((b) => typeof b !== "string" || b.length > 1024)) {
      return NextResponse.json(
        { error: "Each blinded token must be a hex string <= 1024 chars" },
        { status: 400 },
      );
    }

    const denomination =
      typeof body.denomination === "number" ? body.denomination : 1;
    const result = mintBlindedBatch(body.blinded, denomination);

    return NextResponse.json({
      ...result,
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
