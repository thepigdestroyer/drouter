import { parseAnchorBody } from "@/lib/arc/anchor-input";
import { anchorReceipt, explorerTx, nodeKeyFor, recordVerification } from "@/lib/arc/registry";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_ANCHOR_BODY_BYTES = 4096;

// Per-IP token bucket: max 6 bursts, refills at 6 per hour (1 per 600s)
const ipLimiter = createTokenBucketLimiter({
  name: "arc-anchor-ip",
  capacity: 6,
  refillPerSec: 6 / 3600,
});

// Global token bucket: max 20 bursts, refills at 20 per hour (protects Arc verifier wallet USDC gas)
const globalAnchorLimiter = createGlobalBucketLimiter({
  name: "arc-anchor-global",
  capacity: 20,
  refillPerSec: 20 / 3600,
});

// Deduplicate recently anchored receipt hashes to prevent repeated on-chain gas spend
const recentReceipts = new Map<string, { anchorTx: `0x${string}` | null; verificationTx: `0x${string}` | null; at: number }>();

export async function POST(req: Request) {
  const limited = ipLimiter.check(req);
  if (limited) return limited;

  let json: unknown;
  try {
    json = await readBoundedJson(req, MAX_ANCHOR_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "invalid JSON body" },
      { status: 400 },
    );
  }

  const parsed = parseAnchorBody(json);
  if (!parsed.ok) return Response.json({ error: parsed.error }, { status: 400 });
  const { receiptHash, nodeId, ok, evidenceHash } = parsed.value;

  if (!nodeKeyFor(nodeId)) {
    return Response.json({ error: "nodeId is not a registered node in the Arc registry" }, { status: 400 });
  }

  const normalizedReceipt = receiptHash.toLowerCase();
  const cached = recentReceipts.get(normalizedReceipt);
  if (cached && Date.now() - cached.at < 3_600_000) {
    return Response.json({
      anchorTx: cached.anchorTx,
      verificationTx: cached.verificationTx,
      anchorUrl: cached.anchorTx ? explorerTx(cached.anchorTx) : null,
      verificationUrl: cached.verificationTx ? explorerTx(cached.verificationTx) : null,
      deduplicated: true,
    });
  }

  const txCost = evidenceHash ? 2 : 1;
  const globalCheck = globalAnchorLimiter.consume(txCost);
  if (!globalCheck.allowed) {
    return Response.json(
      { error: "hourly on-chain anchoring cap reached", retryAfterSec: globalCheck.retryAfterSec },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    return Response.json({
      anchorTx: null,
      verificationTx: null,
      anchorUrl: null,
      verificationUrl: null,
      stubbed: true,
    });
  }

  const anchorTx = await anchorReceipt(receiptHash);
  const verificationTx = evidenceHash ? await recordVerification(nodeId, ok ?? true, evidenceHash) : null;

  if (recentReceipts.size > 500) {
    const firstKey = recentReceipts.keys().next().value;
    if (firstKey) recentReceipts.delete(firstKey);
  }
  recentReceipts.set(normalizedReceipt, { anchorTx, verificationTx, at: Date.now() });

  return Response.json({
    anchorTx,
    verificationTx,
    anchorUrl: anchorTx ? explorerTx(anchorTx) : null,
    verificationUrl: verificationTx ? explorerTx(verificationTx) : null,
  });
}
