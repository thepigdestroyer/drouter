import { describe, expect, it } from "vitest";
import {
  computeFragmentCompromiseRisk,
  reassembleCompartmentOutputs,
  splitTaskIntoCompartments,
} from "@/lib/compartment/splitter";

describe("Compartmentalized Sub-Agent Task Splitter", () => {
  it("computes fullLeakProbability = 3.2e-9 and anyFragmentLeakProbability ~ 0.0961 for p = 0.02, m = 5", () => {
    const risk = computeFragmentCompromiseRisk(0.02, 5);

    expect(risk.singleNodeLeakProbability).toBeCloseTo(0.02, 10);
    expect(risk.fullLeakProbability).toBeCloseTo(3.2e-9, 15);
    expect(risk.anyFragmentLeakProbability).toBeCloseTo(0.0960792032, 4);
    expect(risk.fullLeakReductionFactor).toBeCloseTo(6_250_000, 2);
  });

  it("assigns distinct nodes to each fragment when enough nodes are provided and sets valid jitter & keys", () => {
    const prompt = [
      "## Section 1: Revenue Forecast",
      "Analyze confidential Q4 enterprise ARR bookings.",
      "## Section 2: Security Audit",
      "Review enclave attestation logs for anomalous TCB versions.",
      "## Section 3: Payroll Schedule",
      "Compute executive retention bonus vesting dates.",
      "## Section 4: Litigation Brief",
      "Assess patent claim chart overlap.",
      "## Section 5: Acquisition Terms",
      "Model dilution impact of the proposed term sheet.",
    ].join("\n\n");

    const nodes = [
      "node-enclave-1",
      "node-enclave-2",
      "node-enclave-3",
      "node-enclave-4",
      "node-enclave-5",
      "node-enclave-6",
    ];

    const plan = splitTaskIntoCompartments(prompt, nodes);
    expect(plan.fragments.length).toBe(5);

    const assignedNodes = plan.fragments.map((f) => f.assignedNodeId);
    const uniqueAssignedNodes = new Set(assignedNodes);
    expect(uniqueAssignedNodes.size).toBe(plan.fragments.length);

    const uniqueKeys = new Set(plan.fragments.map((f) => f.isolatedKeyId));
    expect(uniqueKeys.size).toBe(plan.fragments.length);

    for (const [idx, frag] of plan.fragments.entries()) {
      expect(frag.index).toBe(idx);
      expect(frag.jitterDelayMs).toBeGreaterThanOrEqual(50);
      expect(frag.jitterDelayMs).toBeLessThanOrEqual(600);
      expect(frag.subPrompt.length).toBeGreaterThan(0);
    }
    expect(plan.synthesisPlan).toContain("5 compartmentalized sub-prompts");
  });

  it("cycles only after all distinct nodes are used when fewer nodes than fragments are provided", () => {
    const prompt = [
      "1. Task Alpha",
      "2. Task Beta",
      "3. Task Gamma",
      "4. Task Delta",
    ].join("\n");

    const twoNodes = ["node-a", "node-b"];
    const plan = splitTaskIntoCompartments(prompt, twoNodes);

    expect(plan.fragments.length).toBe(4);
    // First cycle of 2 must use both distinct nodes before repeating
    const firstCycle = new Set([
      plan.fragments[0].assignedNodeId,
      plan.fragments[1].assignedNodeId,
    ]);
    expect(firstCycle.size).toBe(2);
  });

  it("preserves deterministic fragment order on reassembleCompartmentOutputs even when outputs arrive out of order", () => {
    const outOfOrderOutputs = [
      { index: 2, assignedNodeId: "node-c", response: "Result for part three." },
      { index: 0, assignedNodeId: "node-a", response: "Result for part one." },
      { index: 1, assignedNodeId: "node-b", response: "Result for part two." },
    ];

    const reassembled = reassembleCompartmentOutputs(outOfOrderOutputs);
    const idxOne = reassembled.indexOf("Result for part one.");
    const idxTwo = reassembled.indexOf("Result for part two.");
    const idxThree = reassembled.indexOf("Result for part three.");

    expect(idxOne).toBeGreaterThanOrEqual(0);
    expect(idxTwo).toBeGreaterThan(idxOne);
    expect(idxThree).toBeGreaterThan(idxTwo);
  });
});
