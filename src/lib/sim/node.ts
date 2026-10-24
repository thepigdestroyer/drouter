import type {
  CloseRequest,
  HelloRequest,
  HelloResponse,
  KeyshareRequest,
  KeyshareResponse,
  PopReceiptWire,
  TurnRequest,
  TurnResponse,
} from "./types";

export interface NodeContext {
  now?: number;
}

const REMOVED_MSG =
  "Simulated practice nodes (sim-1, sim-2, sim-3) have been removed from production; use attested Tinfoil enclaves.";

export function nodeHello(_simId: string, _req: HelloRequest, _ctx: NodeContext = {}): HelloResponse {
  throw new Error(REMOVED_MSG);
}

export function nodeKeyshare(
  _simId: string,
  _req: KeyshareRequest,
  _ctx: NodeContext = {},
): KeyshareResponse {
  throw new Error(REMOVED_MSG);
}

export function nodeTurn(_simId: string, _req: TurnRequest, _ctx: NodeContext = {}): TurnResponse {
  throw new Error(REMOVED_MSG);
}

export function nodeClose(
  _simId: string,
  _req: CloseRequest,
  _ctx: NodeContext = {},
): PopReceiptWire {
  throw new Error(REMOVED_MSG);
}
