import { simPost } from "@/lib/sim/http";
import { nodeTurn } from "@/lib/sim/node";

export const POST = simPost((simId, body: Parameters<typeof nodeTurn>[1]) => nodeTurn(simId, body));
