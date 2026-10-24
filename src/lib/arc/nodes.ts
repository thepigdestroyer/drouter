import { formatUnits, keccak256, toHex } from "viem";
import type { Hex, NodeKind, NodeRecord, NodeStatus } from "@/lib/types";

const hashString = (s: string): Hex => keccak256(toHex(s));

const TINFOIL_IMAGE = "tinfoilsh/confidential-model-router";
const SIM_IMAGE = "drouter-sim-node-image/v0.1.0";

interface DemoNodeDef {
  key: string;
  kind: NodeKind;
  name: string;
  endpoint: string;
  region: string;
  measurementSource: string;
}

const DEFS: DemoNodeDef[] = [
  {
    key: "tinfoil-router",
    kind: "tinfoil",
    name: "Tinfoil confidential router",
    endpoint: "inference.tinfoil.sh",
    region: "us",
    measurementSource: TINFOIL_IMAGE,
  },
  { key: "sim-1", kind: "sim", name: "Simulated node 1", endpoint: "/api/sim/sim-1", region: "eu-west", measurementSource: SIM_IMAGE },
  { key: "sim-2", kind: "sim", name: "Simulated node 2", endpoint: "/api/sim/sim-2", region: "us-east", measurementSource: SIM_IMAGE },
  { key: "sim-3", kind: "sim", name: "Simulated node 3", endpoint: "/api/sim/sim-3", region: "ap-south", measurementSource: SIM_IMAGE },
];

export const DEMO_NODES = DEFS.map((d) => ({
  ...d,
  id: hashString(d.key),
  measurement: hashString(d.measurementSource),
}));

const KEY_BY_ID = new Map<string, string>(DEMO_NODES.map((n) => [n.id.toLowerCase(), n.key]));

/** Node key ("sim-1", "tinfoil-router", ...) for a registry id, if it is one of the known demo nodes. */
export function nodeKeyFor(id: Hex): string | undefined {
  return KEY_BY_ID.get(id.toLowerCase());
}

const ZERO_ADDRESS: Hex = "0x0000000000000000000000000000000000000000";

/** The demo nodes built locally, used when the registry is not configured or unreachable. */
export function fallbackNodes(): NodeRecord[] {
  return DEMO_NODES.map((n) => ({
    id: n.id,
    kind: n.kind,
    name: n.name,
    endpoint: n.endpoint,
    measurement: n.measurement,
    operator: ZERO_ADDRESS,
    stake: "0",
    status: "active",
    region: n.region,
    registeredAt: 0,
    lastVerifiedAt: 0,
    lastVerifiedOk: false,
  }));
}

/** Shape of the `getNode` return value as decoded by viem. */
export interface RawNode {
  operator: Hex;
  kind: string;
  name: string;
  endpoint: string;
  measurement: Hex;
  region: string;
  stake: bigint;
  status: number;
  registeredAt: bigint;
  lastVerifiedAt: bigint;
  lastVerifiedOk: boolean;
}

const STATUSES: NodeStatus[] = ["active", "suspended", "revoked"];

export function mapNode(id: Hex, raw: RawNode): NodeRecord {
  return {
    id,
    kind: raw.kind === "tinfoil" ? "tinfoil" : "sim",
    name: raw.name,
    endpoint: raw.endpoint,
    measurement: raw.measurement,
    operator: raw.operator,
    stake: formatUnits(raw.stake, 18),
    // Unknown status values are treated as untrusted.
    status: STATUSES[raw.status] ?? "revoked",
    region: raw.region,
    registeredAt: Number(raw.registeredAt),
    lastVerifiedAt: Number(raw.lastVerifiedAt),
    lastVerifiedOk: raw.lastVerifiedOk,
  };
}
