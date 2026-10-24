import { NextResponse } from "next/server";
import type { BlindCreditToken } from "@/lib/types";
import { ledgerStats, spendToken } from "@/lib/credits/ledger";

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as {
      token?: BlindCreditToken;
      nodeId?: string;
    };
    if (!body || !body.token) {
      return NextResponse.json(
        { ok: false, error: "Missing 'token' in request body" },
        { status: 400 }
      );
    }

    const result = await spendToken(body.token, body.nodeId);
    if (!result.ok) {
      return NextResponse.json(
        { ok: false, error: result.error, stats: ledgerStats() },
        { status: result.status }
      );
    }

    return NextResponse.json({
      ok: true,
      nullifier: result.nullifier,
      remainingPoolUnredeemed: result.remainingPoolUnredeemed,
      stats: ledgerStats(),
    });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to process token spend";
    return NextResponse.json({ ok: false, error: message }, { status: 400 });
  }
}
