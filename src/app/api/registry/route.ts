import { cacheLife } from "next/cache";
import { ARC_CHAIN_ID, ARC_EXPLORER, listNodes } from "@/lib/arc/registry";

// With cacheComponents enabled, `revalidate` and `runtime` segment configs are not allowed;
// cacheLife gives the 15 s revalidation and route handlers already run on Node.js.
async function loadRegistry() {
  "use cache";
  cacheLife({ stale: 15, revalidate: 15, expire: 60 });
  return { ...(await listNodes()), chainId: ARC_CHAIN_ID, explorer: ARC_EXPLORER };
}

export async function GET() {
  return Response.json(await loadRegistry());
}
