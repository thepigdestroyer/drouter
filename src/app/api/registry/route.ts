import { cacheLife } from "next/cache";
import { ARC_CHAIN_ID, ARC_EXPLORER, listNodes } from "@/lib/arc/registry";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const registryLimiter = createTokenBucketLimiter({
  name: "registry-get",
  capacity: 120,
  refillPerSec: 4,
});

// With cacheComponents enabled, `revalidate` and `runtime` segment configs are not allowed;
// cacheLife gives the 15 s revalidation and route handlers already run on Node.js.
async function loadRegistry(addressKey: string) {
  "use cache";
  void addressKey;
  cacheLife({ stale: 15, revalidate: 15, expire: 60 });
  return { ...(await listNodes()), chainId: ARC_CHAIN_ID, explorer: ARC_EXPLORER };
}

export async function GET(request?: Request) {
  if (request) {
    const limited = registryLimiter.check(request);
    if (limited) return limited;
  }
  return Response.json(await loadRegistry(process.env.ARC_REGISTRY_ADDRESS ?? ""));
}
