import { simPost } from "@/lib/sim/http";
import { nodeKeyshare } from "@/lib/sim/node";

export const POST = simPost((simId, body: Parameters<typeof nodeKeyshare>[1]) => nodeKeyshare(simId, body));
