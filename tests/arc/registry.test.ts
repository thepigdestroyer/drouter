import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, toHex } from "viem";
import {
  DEMO_NODES,
  fallbackNodes,
  mapNode,
  nodeKeyFor,
} from "@/lib/arc/nodes";
import { explorerAddress, explorerTx, listNodes } from "@/lib/arc/registry";
import { DEMO_NODES as scriptNodes } from "../../scripts/arc-common.mjs";

const idOf = (key: string) => keccak256(toHex(key));

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("node ids", () => {
  it("equal keccak256 of the key strings", () => {
    expect(DEMO_NODES.map((n) => n.key)).toEqual(["tinfoil-router", "sim-1", "sim-2", "sim-3"]);
    for (const n of DEMO_NODES) expect(n.id).toBe(idOf(n.key));
  });

  it("nodeKeyFor maps ids back to keys", () => {
    expect(nodeKeyFor(idOf("sim-2"))).toBe("sim-2");
    expect(nodeKeyFor(idOf("sim-2").toUpperCase().replace("0X", "0x") as `0x${string}`)).toBe("sim-2");
    expect(nodeKeyFor(idOf("nope"))).toBeUndefined();
  });

  it("measurements are keccak256 of the image strings", () => {
    const [tinfoil, ...sims] = DEMO_NODES;
    expect(tinfoil.measurement).toBe(idOf("tinfoilsh/confidential-model-router"));
    for (const s of sims) expect(s.measurement).toBe(idOf("drouter-sim-node-image/v0.1.0"));
  });

  it("seed script definitions agree with the library", () => {
    expect(scriptNodes.map((n) => ({ ...n }))).toEqual(
      DEMO_NODES.map(({ key, kind, name, endpoint, region, measurementSource }) => ({
        key,
        kind,
        name,
        endpoint,
        region,
        measurementSource,
      })),
    );
  });
});

describe("mapNode", () => {
  const operator = "0x1111111111111111111111111111111111111111" as const;
  const raw = (over: Record<string, unknown> = {}) => ({
    operator,
    kind: "sim",
    name: "Simulated node 1",
    endpoint: "/api/sim/sim-1",
    measurement: idOf("drouter-sim-node-image/v0.1.0"),
    region: "eu-west",
    stake: BigInt(10_000_000_000_000_000),
    status: 0,
    registeredAt: BigInt(1_700_000_000),
    lastVerifiedAt: BigInt(1_700_000_100),
    lastVerifiedOk: true,
    ...over,
  });

  it("formats USDC stake with 18 decimals and converts bigints", () => {
    const n = mapNode(idOf("sim-1"), raw());
    expect(n).toEqual({
      id: idOf("sim-1"),
      kind: "sim",
      name: "Simulated node 1",
      endpoint: "/api/sim/sim-1",
      measurement: idOf("drouter-sim-node-image/v0.1.0"),
      operator,
      stake: "0.01",
      status: "active",
      region: "eu-west",
      registeredAt: 1_700_000_000,
      lastVerifiedAt: 1_700_000_100,
      lastVerifiedOk: true,
    });
    expect(mapNode(idOf("sim-1"), raw({ stake: BigInt(0) })).stake).toBe("0");
    expect(mapNode(idOf("sim-1"), raw({ stake: BigInt(1_500_000_000_000_000_000) })).stake).toBe("1.5");
  });

  it("maps status numbers", () => {
    expect(mapNode(idOf("sim-1"), raw({ status: 0 })).status).toBe("active");
    expect(mapNode(idOf("sim-1"), raw({ status: 1 })).status).toBe("suspended");
    expect(mapNode(idOf("sim-1"), raw({ status: 2 })).status).toBe("revoked");
    expect(mapNode(idOf("sim-1"), raw({ status: 9 })).status).toBe("revoked");
  });

  it("maps kind", () => {
    expect(mapNode(idOf("tinfoil-router"), raw({ kind: "tinfoil" })).kind).toBe("tinfoil");
  });
});

describe("listNodes", () => {
  it("returns the fallback set when ARC_REGISTRY_ADDRESS is unset", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", "");
    const res = await listNodes();
    expect(res.source).toBe("fallback");
    expect(res.address).toBeUndefined();
    expect(res.nodes).toEqual(fallbackNodes());
    expect(res.nodes).toHaveLength(4);
    for (const n of res.nodes) {
      expect(n.stake).toBe("0");
      expect(n.lastVerifiedAt).toBe(0);
      expect(n.status).toBe("active");
    }
    expect(res.nodes.map((n) => n.id)).toEqual(["tinfoil-router", "sim-1", "sim-2", "sim-3"].map(idOf));
  });

  it("falls back when the RPC is unreachable", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", "0x2222222222222222222222222222222222222222");
    vi.stubEnv("ARC_RPC_URL", "http://127.0.0.1:9");
    const res = await listNodes();
    expect(res.source).toBe("fallback");
    expect(res.nodes).toHaveLength(4);
  });
});

describe("explorer helpers", () => {
  it("build explorer urls", () => {
    expect(explorerTx("0xabc")).toBe("https://explorer.testnet.arc.io/tx/0xabc");
    expect(explorerAddress("0xdef")).toBe("https://explorer.testnet.arc.io/address/0xdef");
  });
});
