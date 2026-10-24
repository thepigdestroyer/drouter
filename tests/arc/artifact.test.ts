import { describe, expect, it } from "vitest";
import artifact from "@/lib/arc/artifact.json";
import { registryAbi } from "@/lib/arc/abi";

const names = (type: string) =>
  (artifact.abi as { type: string; name?: string }[])
    .filter((e) => e.type === type)
    .map((e) => e.name);

describe("compiled DRouterRegistry artifact", () => {
  it("has deployable bytecode", () => {
    expect(artifact.bytecode).toMatch(/^0x[0-9a-f]{200,}$/);
  });

  it("exposes the expected functions", () => {
    expect(names("function")).toEqual(
      expect.arrayContaining([
        "owner",
        "verifiers",
        "setVerifier",
        "minStake",
        "registerNode",
        "addStake",
        "recordVerification",
        "anchorReceipt",
        "setStatus",
        "slash",
        "nodeCount",
        "nodeIdAt",
        "getNode",
      ]),
    );
  });

  it("exposes the expected events", () => {
    expect(names("event")).toEqual(
      expect.arrayContaining(["NodeRegistered", "NodeVerified", "ReceiptAnchored", "Slashed"]),
    );
  });

  it("registerNode and addStake are payable", () => {
    const fn = (n: string) =>
      (artifact.abi as { name?: string; stateMutability?: string }[]).find((e) => e.name === n);
    expect(fn("registerNode")?.stateMutability).toBe("payable");
    expect(fn("addStake")?.stateMutability).toBe("payable");
  });

  it("abi.ts matches the artifact", () => {
    expect(JSON.parse(JSON.stringify(registryAbi))).toEqual(artifact.abi);
  });
});
