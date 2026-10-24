import { describe, expect, it } from "vitest";
import {
  DEFAULT_HEART_GRID,
  blindEnvelopeRound,
  evaluateNodeChoice,
  judgeCandidateNodes,
  simulateSubpoenaPop,
  tapMemoryBus,
} from "@/lib/game/gauntlet";

describe("The Enclave Gauntlet · 4 Interactive Security Exhibits", () => {
  describe("Exhibit 01: tapMemoryBus (The $900 Memory-Bus Probe)", () => {
    it("leaks 100% of the 4x4 pattern under naive-cpu-xts due to identical 16-byte blocks", () => {
      const result = tapMemoryBus(DEFAULT_HEART_GRID, "naive-cpu-xts");
      expect(result.mode).toBe("naive-cpu-xts");
      expect(result.blocks).toHaveLength(16);
      expect(result.repeatedBlocks).toBeGreaterThan(0);
      expect(result.uniqueBlocks).toBe(2);
      expect(result.leakRatePct).toBe(100);
      expect(result.reconstructedGrid).toEqual(DEFAULT_HEART_GRID);
    });

    it("produces 0 repeated blocks, >7.8 bits/byte entropy, and 0% leak in drouter-gpu-hbm mode", () => {
      const result = tapMemoryBus(DEFAULT_HEART_GRID, "drouter-gpu-hbm");
      expect(result.mode).toBe("drouter-gpu-hbm");
      expect(result.blocks).toHaveLength(16);
      expect(result.repeatedBlocks).toBe(0);
      expect(result.uniqueBlocks).toBe(16);
      expect(result.entropyBitsPerByte).toBeGreaterThan(7.8);
      expect(result.leakRatePct).toBe(0);
      expect(result.reconstructedGrid.every((cell) => cell === null)).toBe(true);
    });
  });

  describe("Exhibit 02: blindEnvelopeRound (The Carbon-Paper Blind Credit)", () => {
    it("blinds, signs, unblinds, and verifies a valid RSA signature while proving 6-way permutation unlinkability", () => {
      const round = blindEnvelopeRound({ t: 42, r: 19 });
      expect(round.signatureValid).toBe(true);
      expect(round.recomputedFromSignature).toBe(round.t);
      expect(round.purchases).toHaveLength(3);
      expect(round.spentTokens).toHaveLength(3);
      expect(round.spentTokens.every((st) => st.signatureValid)).toBe(true);
      expect(round.permutations).toHaveLength(6);
      expect(round.validPermutationsCount).toBe(6);
      expect(round.unlinkable).toBe(true);
    });

    it("supports arbitrary player choices for token secret t and blinding factor r", () => {
      const round = blindEnvelopeRound(123, 57);
      expect(round.signatureValid).toBe(true);
      expect(round.unlinkable).toBe(true);
      expect(round.validPermutationsCount).toBe(6);
    });
  });

  describe("Exhibit 03: judgeCandidateNodes & evaluateNodeChoice (Spot the Forged Enclave)", () => {
    it("generates 3 candidate nodes with debug bit imposter, dm-verity imposter, and 1 authentic node", () => {
      const nodes = judgeCandidateNodes();
      expect(nodes).toHaveLength(3);

      const alpha = nodes.find((n) => n.id === "node-alpha")!;
      const bravo = nodes.find((n) => n.id === "node-bravo")!;
      const charlie = nodes.find((n) => n.id === "node-charlie")!;

      expect(alpha.policyDebugAllowed).toBe(true);
      expect(alpha.isAuthentic).toBe(false);

      expect(bravo.dmVerityMatchesSigstore).toBe(false);
      expect(bravo.isAuthentic).toBe(false);

      expect(charlie.policyDebugAllowed).toBe(false);
      expect(charlie.dmVerityMatchesSigstore).toBe(true);
      expect(charlie.isAuthentic).toBe(true);
    });

    it("scores player choices and identifies the exact register that caught each imposter", () => {
      const nodes = judgeCandidateNodes();

      const pickAlpha = evaluateNodeChoice("node-alpha", nodes);
      expect(pickAlpha.correct).toBe(false);
      expect(pickAlpha.caughtRegister).toBe("ATT_REPORT.POLICY[19]");

      const pickBravo = evaluateNodeChoice("node-bravo", nodes);
      expect(pickBravo.correct).toBe(false);
      expect(pickBravo.caughtRegister).toBe("INITRD.DM_VERITY_ROOT");

      const pickCharlie = evaluateNodeChoice("node-charlie", nodes);
      expect(pickCharlie.correct).toBe(true);
      expect(pickCharlie.authenticNodeId).toBe("node-charlie");
      expect(pickCharlie.caughtRegister).toBe("ALL_REGISTERS_CLEAN");
    });
  });

  describe("Exhibit 04: simulateSubpoenaPop (Pop the Bubble Before the Subpoena)", () => {
    it("zeroes GPU pages on pop, yields 0 readable bytes on host RAM dump, and preserves user-only freeze recovery until shredded", () => {
      // Freeze then pop then subpoena dump
      const frozenAndPopped = simulateSubpoenaPop(["freeze", "pop", "host-ram-dump"]);
      expect(frozenAndPopped.gpuPagesZeroed).toBe(true);
      expect(frozenAndPopped.gpuActiveBytesRemaining).toBe(0);
      expect(frozenAndPopped.hostDumpReadableBytes).toBe(0);
      expect(frozenAndPopped.cloudBlobDecryptableWithUserKey).toBe(true);
      expect(frozenAndPopped.cloudBlobDecryptableByServer).toBe(false);

      // Shred client secret too
      const shredded = simulateSubpoenaPop(["freeze", "pop", "shred-secret", "host-ram-dump"]);
      expect(shredded.gpuPagesZeroed).toBe(true);
      expect(shredded.hostDumpReadableBytes).toBe(0);
      expect(shredded.cloudBlobDecryptableWithUserKey).toBe(false);
      expect(shredded.cloudBlobDecryptableByServer).toBe(false);
    });
  });
});
