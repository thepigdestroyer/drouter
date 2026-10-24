import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import { SimError } from "./errors";
import { simNodeSpec } from "./manifest";

/** Thin HTTP adapter shared by the sim route files: JSON in, JSON out, SimError -> status. */

const NO_STORE = { "cache-control": "no-store" };
const MAX_SIM_BODY_BYTES = 131_072; // 128 KB max sim payload

const simLimiter = createTokenBucketLimiter({
  name: "sim-routes",
  capacity: 120,
  refillPerSec: 4,
});

export async function respond<T>(fn: () => T | Promise<T>, request?: Request): Promise<Response> {
  if (request) {
    const limited = simLimiter.check(request, NO_STORE);
    if (limited) return limited;
  }
  try {
    return Response.json(await fn(), { headers: NO_STORE });
  } catch (err) {
    if (err instanceof SimError) {
      return Response.json({ error: err.message }, { status: err.status, headers: NO_STORE });
    }
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413, headers: NO_STORE });
    }
    const message = err instanceof Error ? err.message : "";
    if (message.includes("SIM_HARDWARE_SEED")) {
      return Response.json({ error: "simulated hardware is not configured" }, { status: 503, headers: NO_STORE });
    }
    return Response.json({ error: "internal error" }, { status: 500, headers: NO_STORE });
  }
}

async function readJson(request: Request): Promise<unknown> {
  try {
    const body = await readBoundedJson(request, MAX_SIM_BODY_BYTES);
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body;
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      throw err;
    }
    if (err instanceof InvalidJsonBodyError) {
      throw new SimError(400, "request body must be a JSON object");
    }
    throw new SimError(400, "request body must be a JSON object");
  }
}

type SimRouteContext = { params: Promise<{ simId: string }> };

/** Builds a POST handler for /api/sim/[simId]/<action>. Unknown simId returns 404 before the body is read. */
export function simPost<Req, Res>(handler: (simId: string, body: Req) => Res) {
  return (request: Request, context: SimRouteContext): Promise<Response> =>
    respond(async () => {
      const { simId } = await context.params;
      simNodeSpec(simId);
      return handler(simId, (await readJson(request)) as Req);
    }, request);
}
