import { NextResponse } from "next/server";
import { claimCreditInvoice, ledgerStats } from "@/lib/credits/ledger";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_CLAIM_BODY_BYTES = 32_768;

const claimLimiter = createTokenBucketLimiter({
  name: "credits-claim",
  capacity: 20,
  refillPerSec: 20 / 60,
});

export async function POST(request: Request) {
  const limited = claimLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<Record<string, unknown>>(
      request,
      MAX_CLAIM_BODY_BYTES
    );

    if (!body || typeof body !== "object") {
      return NextResponse.json(
        { error: "Request body must be a JSON object" },
        { status: 400 }
      );
    }

    if (
      "payerAddress" in body ||
      "walletAddress" in body ||
      "sender" in body ||
      "from" in body
    ) {
      return NextResponse.json(
        {
          error:
            "deRoute never accepts or stores payer wallet addresses on credit claims",
        },
        { status: 400 }
      );
    }

    const claimSecret =
      typeof body.claimSecret === "string" ? body.claimSecret : "";
    if (!claimSecret) {
      return NextResponse.json(
        { error: "Missing required 'claimSecret' (32-byte hex string)" },
        { status: 400 }
      );
    }

    const blinded = body.blinded;
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

    const invoiceId =
      typeof body.invoiceId === "string" ? body.invoiceId : undefined;
    const denomination =
      typeof body.denomination === "number" ? body.denomination : undefined;

    const claimed = await claimCreditInvoice({
      invoiceId,
      claimSecret,
      blindedHexes: blinded as string[],
      denomination,
    });

    if (!claimed.ok) {
      return NextResponse.json(
        { error: claimed.error },
        { status: claimed.status }
      );
    }

    return NextResponse.json(
      {
        ok: true,
        invoiceId: claimed.invoiceId,
        signatures: claimed.signatures,
        denomination: claimed.denomination,
        keyBits: claimed.keyBits,
        creditsGranted: claimed.creditsGranted,
        amountUsdc: claimed.amountUsdc,
        depositAddress: claimed.depositAddress,
        chainId: claimed.chainId,
        confirmations: claimed.confirmations,
        mode: "paid-invoice",
        stats: ledgerStats(),
      },
      { headers: { "Cache-Control": "no-store" } }
    );
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    const message =
      err instanceof InvalidJsonBodyError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Failed to claim blind credits";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
