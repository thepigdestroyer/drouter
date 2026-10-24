import { vi } from "vitest";
import type { EvidenceBundle, HelloResponse, SimRoots } from "@/lib/sim/types";

// `connection()` only works inside a Next request scope.
vi.mock("next/server", () => ({ connection: async () => {} }));

import { GET as rootsRoute } from "@/app/api/sim/roots/route";
import { POST as closeRoute } from "@/app/api/sim/[simId]/close/route";
import { POST as helloRoute } from "@/app/api/sim/[simId]/hello/route";
import { POST as keyshareRoute } from "@/app/api/sim/[simId]/keyshare/route";
import { POST as turnRoute } from "@/app/api/sim/[simId]/turn/route";

const POSTS: Record<string, (req: Request, ctx: { params: Promise<{ simId: string }> }) => Promise<Response>> = {
  hello: helloRoute,
  keyshare: keyshareRoute,
  turn: turnRoute,
  close: closeRoute,
};

export interface FetchHooks {
  tamperRoots?: (roots: SimRoots) => void;
  tamperEvidence?: (evidence: EvidenceBundle) => void;
}

/** A fetch that dispatches straight into the real route handlers, with optional on-the-wire tampering. */
export function routeFetch(hooks: FetchHooks = {}): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input.toString(), "http://sim.test");
    const parts = url.pathname.split("/").filter(Boolean); // api sim ...
    if (parts[2] === "roots") {
      const res = await rootsRoute();
      if (!hooks.tamperRoots) return res;
      const roots = (await res.json()) as SimRoots;
      hooks.tamperRoots(roots);
      return Response.json(roots);
    }
    const [simId, action] = [parts[2], parts[3]];
    const handler = POSTS[action];
    if (!handler) return Response.json({ error: "not found" }, { status: 404 });
    const res = await handler(new Request(url, { method: "POST", body: init?.body as string }), {
      params: Promise.resolve({ simId }),
    });
    if (action === "hello" && hooks.tamperEvidence && res.ok) {
      const body = (await res.json()) as HelloResponse;
      hooks.tamperEvidence(body.evidence);
      return Response.json(body);
    }
    return res;
  }) as typeof fetch;
}

export function flipHexByte(hex: string, byteIndex: number): string {
  const i = byteIndex * 2;
  const flipped = (parseInt(hex.slice(i, i + 2), 16) ^ 0x01).toString(16).padStart(2, "0");
  return hex.slice(0, i) + flipped + hex.slice(i + 2);
}
