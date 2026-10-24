import { NextResponse } from "next/server";
import { ledgerStats, redeemBatch } from "@/lib/credits/ledger";
import {
  BodyTooLargeError,
  createTokenBucketLimiter,
  readBoundedBytes,
} from "@/lib/ratelimit";

const MAX_REDEEM_BODY_BYTES = 4096;

const redeemLimiter = createTokenBucketLimiter({
  name: "credits-redeem",
  capacity: 20,
  refillPerSec: 20 / 60,
});

export async function POST(request: Request) {
  const limited = redeemLimiter.check(request);
  if (limited) return limited;

  try {
    const rawBytes = await readBoundedBytes(request, MAX_REDEEM_BODY_BYTES);
    let body: { nodeId?: string } = {};
    if (rawBytes.byteLength > 0) {
      try {
        body = JSON.parse(new TextDecoder().decode(rawBytes)) as { nodeId?: string };
      } catch {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
    }
    const safeNodeId =
      typeof body?.nodeId === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(body.nodeId)
        ? body.nodeId
        : undefined;
    const summary = await redeemBatch(safeNodeId);
    return NextResponse.json({
      ...summary,
      stats: ledgerStats(),
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    const message =
      err instanceof Error ? err.message : "Failed to redeem credit batch";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
