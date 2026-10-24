import { createRateLimiter, parseAnchorBody } from "@/lib/arc/anchor-input";
import { anchorReceipt, explorerTx, recordVerification } from "@/lib/arc/registry";

const allow = createRateLimiter({ max: 30, windowMs: 60_000 });

function clientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return fwd || req.headers.get("x-real-ip") || "unknown";
}

export async function POST(req: Request) {
  if (!allow(clientIp(req))) {
    return Response.json({ error: "rate limit exceeded" }, { status: 429, headers: { "Retry-After": "60" } });
  }

  let json: unknown;
  try {
    json = await req.json();
  } catch {
    return Response.json({ error: "invalid JSON body" }, { status: 400 });
  }
  const parsed = parseAnchorBody(json);
  if (!parsed.ok) return Response.json({ error: parsed.error }, { status: 400 });
  const { receiptHash, nodeId, ok, evidenceHash } = parsed.value;

  const anchorTx = await anchorReceipt(receiptHash);
  const verificationTx = evidenceHash ? await recordVerification(nodeId, ok ?? true, evidenceHash) : null;

  return Response.json({
    anchorTx,
    verificationTx,
    anchorUrl: anchorTx ? explorerTx(anchorTx) : null,
    verificationUrl: verificationTx ? explorerTx(verificationTx) : null,
  });
}
