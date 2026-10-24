import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, toHex } from "viem";
import {
  buildLiveMetadataByNodeId,
  buildModelMeasurementSource,
  DEMO_NODES,
  fallbackNodes,
  isLegacySimNode,
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
  resetLiveProxyCacheForTests,
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
  resetLiveProxyCacheForTests();
  vi.unstubAllEnvs();
});

describe("real Tinfoil node set and ids", () => {
  const expectedKeys = [
    "tinfoil-router",
    "tinfoil-kimi-k3",
    "tinfoil-glm-5-3",
    "tinfoil-deepseek-v4-1-flash",
    "tinfoil-gpt-oss-120b",
    "tinfoil-llama3-3-70b",
  ];

  it("includes the Tinfoil router and all 5 model enclaves with zero simulated nodes", () => {
    expect(DEMO_NODES.map((n) => n.key)).toEqual(expectedKeys);
    for (const n of DEMO_NODES) {
      expect(n.kind).toBe("tinfoil");
      expect(n.id).toBe(idOf(n.key));
      expect(n.measurement).toBe(idOf(n.measurementSource));
      expect(n.measurementRegisters.length).toBeGreaterThan(0);
    }
  });

  it("nodeKeyFor and nodeIdFor map real nodes and aliases, and reject sim-1/2/3", () => {
    expect(nodeKeyFor(idOf("tinfoil-router"))).toBe("tinfoil-router");
    expect(nodeKeyFor(idOf("tinfoil-kimi-k3"))).toBe("tinfoil-kimi-k3");
    expect(
      nodeKeyFor(idOf("tinfoil-kimi-k3").toUpperCase().replace("0X", "0x") as `0x${string}`),
    ).toBe("tinfoil-kimi-k3");

    // Aliases by modelId, endpoint host, and repo
    expect(nodeIdFor("tinfoil-router")).toBe(idOf("tinfoil-router"));
    expect(nodeIdFor("inference.tinfoil.sh")).toBe(idOf("tinfoil-router"));
    expect(nodeIdFor("tinfoil-kimi-k3")).toBe(idOf("tinfoil-kimi-k3"));
    expect(nodeIdFor("kimi-k3")).toBe(idOf("tinfoil-kimi-k3"));
    expect(nodeIdFor("kimi-k3-inf14.tinfoil.containers.tinfoil.dev")).toBe(
      idOf("tinfoil-kimi-k3"),
    );
    expect(nodeIdFor("tinfoilsh/confidential-kimi-k3")).toBe(idOf("tinfoil-kimi-k3"));

    // Simulated practice nodes are excluded
    for (const simKey of ["sim-1", "sim-2", "sim-3"]) {
      expect(nodeKeyFor(idOf(simKey))).toBeUndefined();
      expect(nodeIdFor(simKey)).toBeUndefined();
      expect(isLegacySimNode(idOf(simKey))).toBe(true);
    }
    expect(nodeKeyFor(idOf("nope"))).toBeUndefined();
    expect(nodeIdFor("unknown")).toBeUndefined();
  });

  it("seed script definitions agree with the library", () => {
    expect(
      scriptNodes.map(({ key, kind, name, endpoint, region, repo, releaseTag, measurementSource }) => ({
        key,
        kind,
        name,
        endpoint,
        region,
        repo,
        releaseTag,
        measurementSource,
      })),
    ).toEqual(
      DEMO_NODES.map(({ key, kind, name, endpoint, region, repo, releaseTag, measurementSource }) => ({
        key,
        kind,
        name,
        endpoint,
        region,
        repo,
        releaseTag,
        measurementSource,
      })),
    );
  });
});

describe("mapNode and live proxy metadata", () => {
  const operator = "0x7a5cCE3386c4D572A9C2891103250fA878838cfB" as const;
  const kimiDef = DEMO_NODES[1];
  const raw = (over: Record<string, unknown> = {}) => ({
    operator,
    kind: "tinfoil",
    name: kimiDef.name,
    endpoint: kimiDef.endpoint,
    measurement: kimiDef.measurement,
    region: "us",
    stake: BigInt(10_000_000_000_000_000),
    status: 0,
    registeredAt: BigInt(1_700_000_000),
    lastVerifiedAt: BigInt(1_700_000_100),
    lastVerifiedOk: true,
    ...over,
  });

  it("formats USDC stake with 18 decimals and attaches real Tinfoil metadata", () => {
    const n = mapNode(idOf("tinfoil-kimi-k3"), raw());
    expect(n).toMatchObject({
      id: idOf("tinfoil-kimi-k3"),
      key: "tinfoil-kimi-k3",
      modelId: "kimi-k3",
      kind: "tinfoil",
      name: "Tinfoil Kimi K3 enclave",
      endpoint: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
      measurement: kimiDef.measurement,
      operator,
      stake: "0.01",
      status: "active",
      region: "us",
      registeredAt: 1_700_000_000,
      lastVerifiedAt: 1_700_000_100,
      lastVerifiedOk: true,
      repo: "tinfoilsh/confidential-kimi-k3",
      releaseTag: "v0.0.15",
      hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
      measurementRegisters: kimiDef.measurementRegisters,
    });
    expect(mapNode(idOf("tinfoil-kimi-k3"), raw({ stake: BigInt(0) })).stake).toBe("0");
    expect(
      mapNode(idOf("tinfoil-kimi-k3"), raw({ stake: BigInt(1_500_000_000_000_000_000) })).stake,
    ).toBe("1.5");
  });

  it("maps status numbers", () => {
    expect(mapNode(idOf("tinfoil-router"), raw({ status: 0 })).status).toBe("active");
    expect(mapNode(idOf("tinfoil-router"), raw({ status: 1 })).status).toBe("suspended");
    expect(mapNode(idOf("tinfoil-router"), raw({ status: 2 })).status).toBe("revoked");
    expect(mapNode(idOf("tinfoil-router"), raw({ status: 9 })).status).toBe("revoked");
  });

  it("extracts updated measurements and host details from live .well-known/tinfoil-proxy payload", () => {
    const liveMap = buildLiveMetadataByNodeId({
      version: "v0.0.168",
      models: {
        "kimi-k3": {
          repo: "tinfoilsh/confidential-kimi-k3",
          tag: "v0.0.16",
          measurement: {
            type: "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            registers: ["aa".repeat(48), "bb".repeat(48), "cc".repeat(48)],
          },
          enclaves: {
            "kimi-k3-inf15.tinfoil.containers.tinfoil.dev": {
              hpke_key: "11".repeat(32),
              predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
              tls_key_fp: "22".repeat(32),
            },
          },
          verification: { configured: 2, verified: 2, healthy: 2 },
        },
      },
    });
    const meta = liveMap.get(idOf("tinfoil-kimi-k3").toLowerCase());
    expect(meta?.releaseTag).toBe("v0.0.16");
    expect(meta?.endpoint).toBe("kimi-k3-inf15.tinfoil.containers.tinfoil.dev");
    expect(meta?.healthyHosts).toBe(2);
    expect(meta?.measurement).toBe(
      idOf(
        buildModelMeasurementSource("tinfoilsh/confidential-kimi-k3", "v0.0.16", [
          "aa".repeat(48),
          "bb".repeat(48),
          "cc".repeat(48),
        ]),
      ),
    );
  });
});

describe("listNodes and mocked viem client", () => {
  const operator = "0x7a5cCE3386c4D572A9C2891103250fA878838cfB" as const;
  const registryAddr = "0xbc8085c2b6fe6e0db05f169925c0b841828f4481" as const;

  it("returns the real Tinfoil fallback set when ARC_REGISTRY_ADDRESS is unset, with zero sim nodes", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", "");
    vi.stubEnv("NEXT_PUBLIC_ARC_REGISTRY_ADDRESS", "");
    setArcClientDepsForTests({ readContract: vi.fn() });
    const res = await listNodes();
    expect(res.source).toBe("fallback");
    expect(res.onChain).toBe(false);
    expect(res.error).toContain("not configured");
    expect(res.address).toBeUndefined();
    expect(res.nodes).toEqual(fallbackNodes());
    expect(res.nodes).toHaveLength(6);
    for (const n of res.nodes) {
      expect(n.kind).toBe("tinfoil");
      expect(n.stake).toBe("0");
      expect(n.status).toBe("active");
    }
    expect(res.nodes.map((n) => n.id)).toEqual(DEMO_NODES.map((n) => n.id));
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
    expect(res.nodes).toHaveLength(6);
  });

  it("reads live Tinfoil nodes from chain, filters out revoked legacy sim nodes, and enriches with live proxy metadata", async () => {
    vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);
    const onChainIds = [
      idOf("tinfoil-router"),
      idOf("sim-1"), // legacy revoked sim node on-chain; must be filtered out
      idOf("tinfoil-kimi-k3"),
    ];

    const readContractMock = vi.fn(async ({ functionName, args }) => {
      if (functionName === "nodeCount") return BigInt(onChainIds.length);
      if (functionName === "minStake") return BigInt(10_000_000_000_000_000);
      if (functionName === "nodeIdAt") {
        const idx = Number(args?.[0] ?? 0);
        return onChainIds[idx];
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
        if (id === idOf("tinfoil-kimi-k3")) {
          return {
            operator,
            kind: "tinfoil",
            name: "Tinfoil Kimi K3 enclave",
            endpoint: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
            measurement: DEMO_NODES[1].measurement,
            region: "us",
            stake: BigInt(10_000_000_000_000_000),
            status: 0,
            registeredAt: BigInt(1700000100),
            lastVerifiedAt: BigInt(1700000600),
            lastVerifiedOk: true,
          };
        }
        throw new Error(`Unexpected getNode for id ${String(id)}`);
      }
      throw new Error(`Unexpected functionName: ${functionName}`);
    });

    setArcClientDepsForTests({
      readContract: readContractMock,
      fetchProxyTable: async () => ({
        version: "v0.0.167",
        updated: "2026-10-24T22:32:49Z",
      }),
    });

    const res = await listNodes();
    expect(res.source).toBe("arc");
    expect(res.onChain).toBe(true);
    expect(res.address).toBe(registryAddr);
    expect(res.minStake).toBe("0.01");
    expect(res.proxyVersion).toBe("v0.0.167");
    expect(res.nodes).toHaveLength(2);
    expect(res.nodes.map((n) => n.key)).toEqual(["tinfoil-router", "tinfoil-kimi-k3"]);
    expect(res.nodes[1].repo).toBe("tinfoilsh/confidential-kimi-k3");
    expect(res.nodes[1].releaseTag).toBe("v0.0.15");

    const kimiNode = await readOnChainNode("kimi-k3");
    expect(kimiNode?.stake).toBe("0.01");
    expect(kimiNode?.endpoint).toBe("kimi-k3-inf14.tinfoil.containers.tinfoil.dev");

    // Legacy sim nodes return null from readOnChainNode
    expect(await readOnChainNode("sim-1")).toBeNull();
    expect(await readMinStakeUsdc()).toBe(0.01);

    // Verify GET /api/registry route includes txHash, explorerUrl, onChain, and zero sim nodes
    const routeRes = await getRegistry();
    const json = await routeRes.json();
    expect(json.source).toBe("arc");
    expect(json.onChain).toBe(true);
    expect(json.txHash).toBeNull();
    expect(json.explorerUrl).toBe(explorerAddress(registryAddr));
    expect(json.nodes.every((n: { kind: string }) => n.kind === "tinfoil")).toBe(true);
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

    const evHash = hashEvidenceObject({ event: "monitor-check", node: "tinfoil-kimi-k3" });
    expect(evHash).toMatch(/^0x[0-9a-f]{64}$/);

    const tx1 = await recordVerification(idOf("tinfoil-kimi-k3"), true, evHash);
    expect(tx1).toBe(fakeTxHash);
    expect(writeContractMock).toHaveBeenCalledWith(
      expect.objectContaining({
        address: registryAddr,
        functionName: "recordVerification",
        args: [idOf("tinfoil-kimi-k3"), true, evHash],
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
