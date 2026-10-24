import { connection } from "next/server";
import { ARC_CHAIN_ID, ARC_EXPLORER, explorerAddress, listNodes } from "@/lib/arc/registry";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const registryLimiter = createTokenBucketLimiter({
  name: "registry-get",
  capacity: 120,
  refillPerSec: 4,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = registryLimiter.check(request);
    if (limited) return limited;
  }
  const result = await listNodes();
  return Response.json({
    ...result,
    txHash: null,
    explorerUrl: result.address ? explorerAddress(result.address) : ARC_EXPLORER,
    chainId: ARC_CHAIN_ID,
    explorer: ARC_EXPLORER,
  });
}
