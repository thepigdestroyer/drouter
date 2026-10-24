import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CheckResult } from "@/lib/types";
import { openSimSession } from "@/lib/sim/client";
import { flipHexByte, routeFetch, type FetchHooks } from "./helpers";

async function collect(iter: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const chunk of iter) out += chunk;
  return out;
}

function open(hooks: FetchHooks = {}, simId = "sim-1") {
  const seen: CheckResult[] = [];
  const promise = openSimSession("", simId, { onCheck: (c) => seen.push(c), fetch: routeFetch(hooks) });
  return { promise, seen };
}

describe("browser client against the real routes", () => {
  it("verifies all checks, chats across turns and gets a verified receipt", async () => {
    const { promise, seen } = open();
    const session = await promise;
    expect(session.simId).toBe("sim-1");
    expect(seen.map((c) => c.id)).toEqual(["C1", "C2", "C3", "C4", "C5", "C6", "C7"]);
    expect(seen.map((c) => c.status)).toEqual(["pass", "pass", "pass", "pass", "pass", "skip", "pass"]);
    expect(seen[5].detail).toBe("Registry ticket checked against Arc by the app");
    expect(seen.map((c) => c.label)).toEqual([
      "Hardware signature chain",
      "Approved software",
      "Fresh and bound to this session",
      "Registered chip and manifest",
      "GPUs in confidential mode",
      "Registry admission",
      "Committed model",
    ]);
    expect(session.checks).toEqual(seen);
    expect(session.evidence.gpuCount).toBe(8);
    expect(session.evidence.tcb).toEqual({ fmc: 2, bootloader: 3, tee: 1, snp: 4, microcode: 9 });
    expect(session.evidence.measurement).toHaveLength(96);
    expect(session.evidence.chipId).toHaveLength(128);
    expect(session.evidence.reportData).toHaveLength(128);
    expect(session.evidence.policy).toMatchObject({ smt: false, debug: false, migrationAgent: false, abiMajor: 1 });

    const first = await collect(session.send("héllo bubble"));
    expect(first).toMatch(/^Simulated enclave sim-1 received 13 tokens inside the bubble\. Session context: 13 tokens\./);
    expect(first).toContain("route to a Tinfoil node for a real model");
    expect(await collect(session.send("/count"))).toBe("13");
    // multi-frame reply (> 64 tokens) decodes across frame boundaries
    expect(first.length).toBeGreaterThan(64);

    const receipt = await session.close();
    expect(receipt.verified).toBe(true);
    expect(receipt.nodeId).toBe("sim-1");
    await expect(collect(session.send("after close"))).rejects.toThrow(/closed/);
  });

  it("works on every sim node", async () => {
    for (const id of ["sim-2", "sim-3"]) {
      const session = await open({}, id).promise;
      expect(await collect(session.send("/count"))).toBe("0");
    }
  });

  it("serialises overlapping sends", async () => {
    const session = await open().promise;
    const a = session.send("one")[Symbol.asyncIterator]();
    const pending = a.next();
    await expect(collect(session.send("two"))).rejects.toThrow(/in progress/);
    await pending;
    while (!(await a.next()).done);
  });

  it("flags a receipt that does not verify", async () => {
    const real = routeFetch();
    const session = await openSimSession("", "sim-1", {
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const res = await real(input, init);
        if (String(input).endsWith("/close")) {
          const body = await res.json();
          return Response.json({ ...body, time: body.time + 1 });
        }
        return res;
      }) as typeof fetch,
    });
    expect((await session.close()).verified).toBe(false);
  });

  it("throws for an unknown node", async () => {
    await expect(open({}, "sim-9").promise).rejects.toThrow(/unknown simulated node/);
  });
});

describe("each attestation check fails when its input is tampered", () => {
  async function expectFailure(hooks: FetchHooks, id: string) {
    const { promise, seen } = open(hooks);
    await expect(promise).rejects.toThrow(new RegExp(`^${id} failed`));
    const failed = seen.filter((c) => c.status === "fail");
    expect(failed.map((c) => c.id)).toEqual([id]);
    expect(seen[seen.length - 1].id).toBe(id);
  }

  it("C1: attestation report byte flipped", async () => {
    await expectFailure({ tamperEvidence: (e) => void (e.report = flipHexByte(e.report, 0x90)) }, "C1");
  });

  it("C1: signature byte flipped", async () => {
    await expectFailure({ tamperEvidence: (e) => void (e.report = flipHexByte(e.report, 0x2a0)) }, "C1");
  });

  it("C1: VCEK statement not signed by the AMD root", async () => {
    await expectFailure(
      { tamperEvidence: (e) => void (e.vcekCertificate.statement.tcb = { ...e.vcekCertificate.statement.tcb, snp: 200 }) },
      "C1",
    );
  });

  it("C1: pinned AMD root differs", async () => {
    await expectFailure({ tamperRoots: (r) => void (r.amdRoot = "02" + "11".repeat(48)) }, "C1");
  });

  it("C1: TCB below the published minimum", async () => {
    await expectFailure({ tamperRoots: (r) => void (r.minTcb = { ...r.minTcb, microcode: 50 }) }, "C1");
  });

  it("C2: approved measurement differs", async () => {
    await expectFailure({ tamperRoots: (r) => void (r.approvedMeasurement = flipHexByte(r.approvedMeasurement, 3)) }, "C2");
  });

  it("C3: presented custody key swapped (report data no longer matches)", async () => {
    await expectFailure(
      { tamperEvidence: (e) => void (e.custody.x25519PublicKey = flipHexByte(e.custody.x25519PublicKey, 5)) },
      "C3",
    );
  });

  it("C3: stale evidence from another session's nonce", async () => {
    const stale: { evidence?: unknown } = {};
    const hooks1: FetchHooks = { tamperEvidence: (e) => void (stale.evidence = structuredClone(e)) };
    await open(hooks1).promise;
    await expectFailure(
      { tamperEvidence: (e) => void Object.assign(e, structuredClone(stale.evidence)) },
      "C3",
    );
  });

  it("C4: registered chip differs", async () => {
    await expectFailure(
      { tamperRoots: (r) => void (r.nodes[0].chipId = flipHexByte(r.nodes[0].chipId, 1)) },
      "C4",
    );
  });

  it("C4: registered manifest differs", async () => {
    await expectFailure(
      { tamperRoots: (r) => void (r.nodes[0].manifestHash = flipHexByte(r.nodes[0].manifestHash, 1)) },
      "C4",
    );
  });

  it("C5: GPU CC mode turned off", async () => {
    await expectFailure({ tamperEvidence: (e) => void (e.gpus[3].report.ccMode = false) }, "C5");
  });

  it("C5: GPU nonce replayed from another GPU", async () => {
    await expectFailure({ tamperEvidence: (e) => void (e.gpus[2].report.nonce = e.gpus[1].report.nonce) }, "C5");
  });

  it("C5: a GPU is missing", async () => {
    await expectFailure({ tamperEvidence: (e) => void e.gpus.pop() }, "C5");
  });

  it("C5: pinned NVIDIA root differs", async () => {
    await expectFailure({ tamperRoots: (r) => void (r.nvidiaRoot = flipHexByte(r.nvidiaRoot, 0)) }, "C5");
  });

  it("C7: model root is not the allowlisted weights", async () => {
    await expectFailure({ tamperRoots: (r) => void (r.model.modelRoot = flipHexByte(r.model.modelRoot, 0)) }, "C7");
  });
});

describe("HTTP behaviour", () => {
  beforeEach(() => vi.spyOn(console, "error").mockImplementation(() => {}));
  afterEach(() => vi.restoreAllMocks());

  it("returns 404 JSON for unknown simIds and 400 for bad bodies", async () => {
    const f = routeFetch();
    const unknown = await f("/api/sim/sim-42/hello", { method: "POST", body: "{}" });
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: "unknown simulated node" });
    const bad = await f("/api/sim/sim-1/hello", { method: "POST", body: "not json" });
    expect(bad.status).toBe(400);
    const invalid = await f("/api/sim/sim-1/hello", { method: "POST", body: JSON.stringify({ clientNonce: "zz", modelId: "sim-echo-1" }) });
    expect(invalid.status).toBe(400);
  });

  it("serves the roots document", async () => {
    const res = await routeFetch()("/api/sim/roots");
    const roots = await res.json();
    expect(res.status).toBe(200);
    expect(roots.nodes.map((n: { simId: string; region: string }) => [n.simId, n.region])).toEqual([
      ["sim-1", "eu-west"],
      ["sim-2", "us-east"],
      ["sim-3", "ap-south"],
    ]);
    expect(roots.model.id).toBe("sim-echo-1");
    expect(roots.approvedMeasurement).toHaveLength(96);
    expect(roots.nodes[0].gpuIds).toHaveLength(8);
  });

  it("reports missing hardware seed without leaking details", async () => {
    const seed = process.env.SIM_HARDWARE_SEED;
    delete process.env.SIM_HARDWARE_SEED;
    try {
      const res = await routeFetch()("/api/sim/roots");
      expect(res.status).toBe(503);
      expect(JSON.stringify(await res.json())).not.toContain(seed!);
    } finally {
      process.env.SIM_HARDWARE_SEED = seed;
    }
  });
});
