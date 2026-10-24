import { simPost } from "@/lib/sim/http";
import { nodeHello } from "@/lib/sim/node";

export const POST = simPost((simId, body: Parameters<typeof nodeHello>[1]) => nodeHello(simId, body));
