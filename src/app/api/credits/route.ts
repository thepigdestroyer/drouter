import { NextResponse, connection } from "next/server";
import {
  issuerPublicInfo,
  ledgerStats,
  mintBlindedBatch,
} from "@/lib/credits/ledger";

export async function GET() {
  await connection();
  return NextResponse.json({
    ...issuerPublicInfo(),
    stats: ledgerStats(),
  });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as {
      blinded?: string[];
      denomination?: number;
    };
    if (!body || !Array.isArray(body.blinded) || body.blinded.length === 0) {
      return NextResponse.json(
        { error: "Request body must provide a non-empty 'blinded' array" },
        { status: 400 }
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
    const message =
      err instanceof Error ? err.message : "Failed to sign blinded tokens";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
