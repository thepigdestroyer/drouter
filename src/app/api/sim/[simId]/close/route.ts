import { simPost } from "@/lib/sim/http";
import { nodeClose } from "@/lib/sim/node";

export const POST = simPost((simId, body: Parameters<typeof nodeClose>[1]) => nodeClose(simId, body));
