import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, toHex } from "viem";
import {
  DEMO_NODES,
  fallbackNodes,
  mapNode,
  nodeIdFor,
  nodeKeyFor,
} from "@/lib/arc/nodes";
import {
  anchorReceipt,
  explorerAddress,
  explorerTx,
  hashEvidenceObject,
  listNodes,
  readMinStakeUsdc,
  readOnChainNode,
  recordVerification,
  setArcClientDepsForTests,
} from "@/lib/arc/registry";
import { GET as getRegistry } from "@/app/api/registry/route";
import { DEMO_NODES as scriptNodes } from "../../scripts/arc-common.mjs";

vi.mock("next/server", () => ({
  connection: vi.fn(async () => undefined),
}));

const idOf = (key: string) => keccak256(toHex(key));

afterEach(() => {
  setArcClientDepsForTests(null);
  vi.unstubAllEnvs();
});

describe("node ids", () => {
  it("equal keccak256 of the key strings", () => {
    expect(DEMO_NODES.map((n) => n.key)).toEqual(["tinfoil-router", "sim-1", "sim-2", "sim-3"]);
    for (const n of DEMO_NODES) expect(n.id).toBe(idOf(n.key));
  });

  it("nodeKeyFor and nodeIdFor map between ids and keys", () => {
    expect(nodeKeyFor(idOf("sim-2"))).toBe("sim-2");
    expect(nodeKeyFor(idOf("sim-2").toUpperCase().replace("0X", "0x") as `0x${string}`)).toBe("sim-2");
    expect(nodeKeyFor(idOf("nope"))).toBeUndefined();
    expect(nodeIdFor("sim-1")).toBe(idOf("sim-1"));
    expect(nodeIdFor("tinfoil-router")).toBe(idOf("tinfoil-router"));
    expect(nodeIdFor("unknown")).toBeUndefined();
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

describe("listNodes and mocked viem client", () => {
  const operator = "0x1111111111111111111111111111111111111111" as const;
  const registryAddr = "0xbc8085c2b6fe6e0db05f169925c0b841828f4481" as const;

  it("returns the fallback set when ARC_REGISTRY_ADDRESS is unset, with explicit error and onChain: false", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", "");
    vi.stubEnv("NEXT_PUBLIC_ARC_REGISTRY_ADDRESS", "");
    const res = await listNodes();
    expect(res.source).toBe("fallback");
    expect(res.onChain).toBe(false);
    expect(res.error).toContain("not configured");
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

  it("falls back when the RPC is unreachable and explicitly sets source=fallback, onChain=false, and error", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);
    setArcClientDepsForTests({
      readContract: vi.fn(async () => {
        throw new Error("Connection refused");
      }),
    });
    const res = await listNodes();
    expect(res.source).toBe("fallback");
    expect(res.onChain).toBe(false);
    expect(res.error).toContain("unreachable");
    expect(res.nodes).toHaveLength(4);
  });

  it("reads live nodes, stake, and minStake from mocked viem public client", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);
    const readContractMock = vi.fn(async ({ functionName, args }) => {
      if (functionName === "nodeCount") return BigInt(2);
      if (functionName === "minStake") return BigInt(10_000_000_000_000_000);
      if (functionName === "nodeIdAt") {
        const idx = Number(args?.[0] ?? 0);
        return idx === 0 ? idOf("tinfoil-router") : idOf("sim-1");
      }
      if (functionName === "getNode") {
        const id = args?.[0];
        if (id === idOf("tinfoil-router")) {
          return {
            operator,
            kind: "tinfoil",
            name: "Tinfoil confidential router",
            endpoint: "inference.tinfoil.sh",
            measurement: idOf("tinfoilsh/confidential-model-router"),
            region: "us",
            stake: BigInt(10_000_000_000_000_000),
            status: 0,
            registeredAt: BigInt(1700000000),
            lastVerifiedAt: BigInt(1700000500),
            lastVerifiedOk: true,
          };
        }
        return {
          operator,
          kind: "sim",
          name: "Simulated node 1",
          endpoint: "/api/sim/sim-1",
          measurement: idOf("drouter-sim-node-image/v0.1.0"),
          region: "eu-west",
          stake: BigInt(10_000_000_000_000_000),
          status: 0,
          registeredAt: BigInt(1700000000),
          lastVerifiedAt: BigInt(1700000600),
          lastVerifiedOk: false,
        };
      }
      throw new Error(`Unexpected functionName: ${functionName}`);
    });

    setArcClientDepsForTests({ readContract: readContractMock });

    const res = await listNodes();
    expect(res.source).toBe("arc");
    expect(res.onChain).toBe(true);
    expect(res.address).toBe(registryAddr);
    expect(res.minStake).toBe("0.01");
    expect(res.nodes).toHaveLength(2);
    expect(res.nodes[0].stake).toBe("0.01");
    expect(res.nodes[1].lastVerifiedOk).toBe(false);

    const node1 = await readOnChainNode("sim-1");
    expect(node1?.stake).toBe("0.01");
    expect(await readMinStakeUsdc()).toBe(0.01);

    // Verify GET /api/registry route includes txHash, explorerUrl, onChain
    const routeRes = await getRegistry();
    const json = await routeRes.json();
    expect(json.source).toBe("arc");
    expect(json.onChain).toBe(true);
    expect(json.txHash).toBeNull();
    expect(json.explorerUrl).toBe(explorerAddress(registryAddr));
  });

  it("executes recordVerification and anchorReceipt via mocked viem wallet client", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);
    const fakeTxHash = `0x${"ab".repeat(32)}` as const;
    const writeContractMock = vi.fn(async () => fakeTxHash);

    setArcClientDepsForTests({
      readContract: vi.fn(async () => BigInt(0)),
      estimateFeesPerGas: vi.fn(async () => ({ maxFeePerGas: BigInt(25_000_000_000) })),
      writeContract: writeContractMock,
    });

    const evHash = hashEvidenceObject({ event: "canary-leak", node: "sim-1" });
    expect(evHash).toMatch(/^0x[0-9a-f]{64}$/);

    const tx1 = await recordVerification(idOf("sim-1"), false, evHash);
    expect(tx1).toBe(fakeTxHash);
    expect(writeContractMock).toHaveBeenCalledWith(
      expect.objectContaining({
        address: registryAddr,
        functionName: "recordVerification",
        args: [idOf("sim-1"), false, evHash],
        maxFeePerGas: BigInt(25_000_000_000),
      }),
    );

    const tx2 = await anchorReceipt(evHash);
    expect(tx2).toBe(fakeTxHash);
    expect(writeContractMock).toHaveBeenCalledWith(
      expect.objectContaining({
        address: registryAddr,
        functionName: "anchorReceipt",
        args: [evHash],
      }),
    );
  });
});

describe("explorer helpers", () => {
  it("build explorer urls", () => {
    expect(explorerTx("0xabc")).toBe("https://explorer.testnet.arc.io/tx/0xabc");
    expect(explorerAddress("0xdef")).toBe("https://explorer.testnet.arc.io/address/0xdef");
  });
});
