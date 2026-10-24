import { NextResponse } from "next/server";
import { ledgerStats, redeemBatch } from "@/lib/credits/ledger";

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as {
      nodeId?: string;
    };
    const summary = await redeemBatch(body?.nodeId);
    return NextResponse.json({
      ...summary,
      stats: ledgerStats(),
    });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to redeem credit batch";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
