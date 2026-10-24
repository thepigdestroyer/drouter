import { NextResponse } from "next/server";
import { createCreditInvoice } from "@/lib/credits/ledger";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_INVOICE_BODY_BYTES = 4096;

const invoiceLimiter = createTokenBucketLimiter({
  name: "credits-invoice",
  capacity: 20,
  refillPerSec: 20 / 60,
});

export async function POST(request: Request) {
  const limited = invoiceLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<Record<string, unknown>>(
      request,
      MAX_INVOICE_BODY_BYTES
    );

    if (!body || typeof body !== "object") {
      return NextResponse.json(
        { error: "Request body must be a JSON object" },
        { status: 400 }
      );
    }

    if ("claimSecret" in body) {
      return NextResponse.json(
        {
          error:
            "Never send claimSecret to /api/credits/invoice; send only claimHash = sha256(claimSecret)",
        },
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
            "deRoute never accepts or stores payer wallet addresses on credit invoices",
        },
        { status: 400 }
      );
    }

    const claimHash = typeof body.claimHash === "string" ? body.claimHash : "";
    if (!claimHash) {
      return NextResponse.json(
        { error: "Missing required 'claimHash' (32-byte sha256 hex string)" },
        { status: 400 }
      );
    }

    const denomination =
      typeof body.denomination === "number" ? body.denomination : undefined;
    const credits =
      typeof body.credits === "number" ? body.credits : undefined;
    const amountUsdc =
      typeof body.amountUsdc === "string" ? body.amountUsdc : undefined;

    const result = await createCreditInvoice({
      claimHash,
      denomination,
      credits,
      amountUsdc,
    });

    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(
      {
        invoiceId: result.invoiceId,
        depositAddress: result.depositAddress,
        amountUsdc: result.amountUsdc,
        denomination: result.denomination,
        chainId: result.chainId,
        usdcContract: result.usdcContract,
        usdcDecimals: result.usdcDecimals,
        expiresAt: result.expiresAt,
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
          : "Failed to create credit invoice";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
