import { describe, expect, it } from "vitest";
import {
  applyOperatorShareCaps,
  evaluateCanaryRealismAuc,
  evaluateTimingSignal,
  requiredNodeStakeUsdc,
  UNVERIFIED_OPERATOR_CAP_PCT,
  VERIFIED_OPERATOR_CAP_PCT,
} from "@/lib/tiers/economics";
import {
  createSampleTierAPlusEvidence,
  createSignedTdxQuote,
  RISER_PROOF_CPU_ALLOWLIST,
  verifyTdxTierBQuote,
  verifyTierAPlusEvidence,
} from "@/lib/tiers/tdx-spdm";

describe("Subsystem 11: Platform Tiers (B / A+), Operator Share Caps, Economics & V8 Canary Realism", () => {
  describe("Tier B (Intel TDX Quote v4 Verifier)", () => {
    it("rejects a valid TDX quote when allowTierB is false (client must opt in)", () => {
      const quote = createSignedTdxQuote();
      const result = verifyTdxTierBQuote(quote, {
        allowTierB: false,
        expectedMrtd: quote.mrtd,
        expectedReportData: quote.reportData,
        minTcbSvn: 5,
      });

      expect(result.accepted).toBe(false);
      expect(result.tier).toBe("B");
      expect(result.assuranceWarning).toContain("lower assurance");
      expect(result.reason).toContain("allowTierB is false");
    });

    it("rejects a TDX quote when tdAttributesDebug is true", () => {
      const debugQuote = createSignedTdxQuote({ tdAttributesDebug: true });
      const result = verifyTdxTierBQuote(debugQuote, {
        allowTierB: true,
        expectedMrtd: debugQuote.mrtd,
        expectedReportData: debugQuote.reportData,
        minTcbSvn: 5,
      });

      expect(result.accepted).toBe(false);
      expect(result.reason).toContain("DEBUG");
    });

    it("rejects a TDX quote when tcbSvn < minTcbSvn, mrtd mismatches, reportData mismatches, or P-256 signature is invalid", () => {
      const quote = createSignedTdxQuote({ tcbSvn: 4 });

      const lowSvn = verifyTdxTierBQuote(quote, {
        allowTierB: true,
        expectedMrtd: quote.mrtd,
        expectedReportData: quote.reportData,
        minTcbSvn: 5,
      });
      expect(lowSvn.accepted).toBe(false);

      const mrtdMismatch = verifyTdxTierBQuote(quote, {
        allowTierB: true,
        expectedMrtd: "00".repeat(48),
        expectedReportData: quote.reportData,
        minTcbSvn: 4,
      });
      expect(mrtdMismatch.accepted).toBe(false);

      const reportDataMismatch = verifyTdxTierBQuote(quote, {
        allowTierB: true,
        expectedMrtd: quote.mrtd,
        expectedReportData: "ff".repeat(32),
        minTcbSvn: 4,
      });
      expect(reportDataMismatch.accepted).toBe(false);

      const tamperedSigQuote = {
        ...quote,
        pckSignatureHex: "00".repeat(64),
      };
      const badSig = verifyTdxTierBQuote(tamperedSigQuote, {
        allowTierB: true,
        expectedMrtd: quote.mrtd,
        expectedReportData: quote.reportData,
        minTcbSvn: 4,
      });
      expect(badSig.accepted).toBe(false);
    });

    it("accepts a valid TDX Quote v4 when allowTierB is true and all checks pass", () => {
      const quote = createSignedTdxQuote({ tcbSvn: 7 });
      const result = verifyTdxTierBQuote(quote, {
        allowTierB: true,
        expectedMrtd: quote.mrtd,
        expectedReportData: quote.reportData,
        minTcbSvn: 5,
      });

      expect(result.accepted).toBe(true);
      expect(result.tier).toBe("B");
      expect(result.assuranceWarning).toContain("lower assurance");
    });
  });

  describe("Tier A+ (SPDM 1.2 + TEE-IO Binding + Riser-Proof Memory Allowlist)", () => {
    const expectedVmId = "cvm-snp-vm-001";

    it("upgrades a node to Tier A+ only when all 10 SPDM 1.2 signatures, teeIoBoundVmId, and riserProofMemory pass", () => {
      const evidence = createSampleTierAPlusEvidence({
        nodeId: "node-aplus-1",
        cpuModel: RISER_PROOF_CPU_ALLOWLIST[0],
        teeIoBoundVmId: expectedVmId,
      });

      const res = verifyTierAPlusEvidence(evidence, expectedVmId);
      expect(res.accepted).toBe(true);
      expect(res.tier).toBe("A+");
      expect(res.spdmVerifiedCount).toBe(10);
      expect(res.teeIoBound).toBe(true);
      expect(res.riserProofMemory).toBe(true);
    });

    it("keeps node at Tier A when teeIoBoundVmId mismatches expectedVmId (GPU attestation relay gap)", () => {
      const evidence = createSampleTierAPlusEvidence({
        nodeId: "node-relay-gap",
        cpuModel: RISER_PROOF_CPU_ALLOWLIST[0],
        teeIoBoundVmId: "other-vm-id",
      });

      const res = verifyTierAPlusEvidence(evidence, expectedVmId);
      expect(res.accepted).toBe(false);
      expect(res.tier).toBe("A");
      expect(res.teeIoBound).toBe(false);
    });

    it("keeps node at Tier A when CPU model is not in the riser-proof on-package/soldered memory allowlist", () => {
      const evidence = createSampleTierAPlusEvidence({
        nodeId: "node-dimm-socketed",
        cpuModel: "Generic Socketed DDR5 DIMM Server CPU",
        teeIoBoundVmId: expectedVmId,
      });

      const res = verifyTierAPlusEvidence(evidence, expectedVmId);
      expect(res.accepted).toBe(false);
      expect(res.tier).toBe("A");
      expect(res.riserProofMemory).toBe(false);
    });

    it("keeps node at Tier A when any SPDM 1.2 device signature or measurement is tampered", () => {
      const evidence = createSampleTierAPlusEvidence({
        nodeId: "node-tampered-gpu",
        cpuModel: RISER_PROOF_CPU_ALLOWLIST[1],
        teeIoBoundVmId: expectedVmId,
      });
      evidence.devices[3] = {
        ...evidence.devices[3],
        signatureHex: "00".repeat(64),
      };

      const res = verifyTierAPlusEvidence(evidence, expectedVmId);
      expect(res.accepted).toBe(false);
      expect(res.tier).toBe("A");
      expect(res.spdmVerifiedCount).toBe(9);
    });
  });

  describe("Operator Share-Cap Scaler (Spec §4 & §5)", () => {
    it("enforces the 2.0% verified operator cap and 0.5% unverified operator cap across multi-node operators", () => {
      const nodes = [
        // Verified whale operator with 2 nodes having huge raw weight
        { nodeId: "whale-v-1", operatorId: "op-whale-verified", operatorVerified: true, rawWeight: 5000 },
        { nodeId: "whale-v-2", operatorId: "op-whale-verified", operatorVerified: true, rawWeight: 5000 },
        // Unverified operator with 2 nodes having large raw weight
        { nodeId: "sybil-u-1", operatorId: "op-unverified-1", operatorVerified: false, rawWeight: 2000 },
        { nodeId: "sybil-u-2", operatorId: "op-unverified-1", operatorVerified: false, rawWeight: 2000 },
        // 60 verified independent operators with modest raw weight
        ...Array.from({ length: 60 }, (_, idx) => ({
          nodeId: `ind-node-${idx + 1}`,
          operatorId: `op-ind-${idx + 1}`,
          operatorVerified: true,
          rawWeight: 100,
        })),
      ];

      const results = applyOperatorShareCaps(nodes);

      // Sum effectiveSharePct by operatorId
      const shareByOp = new Map<string, number>();
      for (const r of results) {
        shareByOp.set(r.operatorId, (shareByOp.get(r.operatorId) ?? 0) + r.effectiveSharePct);
      }

      const whaleShare = shareByOp.get("op-whale-verified") ?? 0;
      const unverifiedShare = shareByOp.get("op-unverified-1") ?? 0;

      expect(whaleShare).toBeCloseTo(VERIFIED_OPERATOR_CAP_PCT, 4);
      expect(unverifiedShare).toBeCloseTo(UNVERIFIED_OPERATOR_CAP_PCT, 4);

      const whaleNodes = results.filter((r) => r.operatorId === "op-whale-verified");
      expect(whaleNodes.every((n) => n.capped)).toBe(true);

      const unverifiedNodes = results.filter((r) => r.operatorId === "op-unverified-1");
      expect(unverifiedNodes.every((n) => n.capped)).toBe(true);

      // Verify no operator exceeds its respective cap
      for (const r of results) {
        const opTotal = shareByOp.get(r.operatorId) ?? 0;
        const isVerified = r.operatorId !== "op-unverified-1";
        const cap = isVerified ? VERIFIED_OPERATOR_CAP_PCT : UNVERIFIED_OPERATOR_CAP_PCT;
        expect(opTotal).toBeLessThanOrEqual(cap + 1e-5);
      }
    });
  });

  describe("Economic Stake Sizing, Weak-Signal Timing Check, and V8 Canary Realism AUC", () => {
    it("computes requiredNodeStakeUsdc per Spec §8.6 ($50k leak gain @ 3% canary rate)", () => {
      const single = requiredNodeStakeUsdc({
        estimatedLeakGainUsdc: 50_000,
        canaryRate: 0.03,
        sessionsBeforeMisuseUse: 1,
      });
      expect(single.detectionProbability).toBeCloseTo(0.03, 6);
      expect(single.minStakeUsdc).toBe(Math.ceil(50_000 / 0.03));

      const multi = requiredNodeStakeUsdc({
        estimatedLeakGainUsdc: 50_000,
        canaryRate: 0.03,
        sessionsBeforeMisuseUse: 10,
      });
      const expectedProb = 1 - Math.pow(0.97, 10);
      expect(multi.detectionProbability).toBeCloseTo(expectedProb, 6);
      expect(multi.minStakeUsdc).toBe(Math.ceil(50_000 / expectedProb));
    });

    it("evaluates confidential-mode timing signal and never auto-slashes (autoSlash === false)", () => {
      const suspicious = evaluateTimingSignal(10.1, 10.0); // 1.0% overhead (< 3%)
      expect(suspicious.flaggedForVerifierReview).toBe(true);
      expect(suspicious.autoSlash).toBe(false);
      expect(suspicious.observedOverheadPct).toBeCloseTo(1.0, 2);

      const normal = evaluateTimingSignal(10.6, 10.0); // 6.0% overhead (>= 3%)
      expect(normal.flaggedForVerifierReview).toBe(false);
      expect(normal.autoSlash).toBe(false);
      expect(normal.observedOverheadPct).toBeCloseTo(6.0, 2);
    });

    it("evaluates V8 canary realism classifier ROC AUC (v8Passed === true for indistinguishable, false for separable)", () => {
      const indistinguishable = [
        { isCanary: true, suspicionScore: 0.48 },
        { isCanary: false, suspicionScore: 0.50 },
        { isCanary: true, suspicionScore: 0.52 },
        { isCanary: false, suspicionScore: 0.49 },
        { isCanary: true, suspicionScore: 0.45 },
        { isCanary: false, suspicionScore: 0.46 },
        { isCanary: true, suspicionScore: 0.55 },
        { isCanary: false, suspicionScore: 0.54 },
      ];
      const passEval = evaluateCanaryRealismAuc(indistinguishable);
      expect(passEval.v8Passed).toBe(true);
      expect(passEval.auc).toBeLessThanOrEqual(0.6);
      expect(passEval.auc).toBeGreaterThanOrEqual(0.4);

      const separable = [
        { isCanary: true, suspicionScore: 0.91 },
        { isCanary: true, suspicionScore: 0.88 },
        { isCanary: true, suspicionScore: 0.95 },
        { isCanary: true, suspicionScore: 0.84 },
        { isCanary: false, suspicionScore: 0.12 },
        { isCanary: false, suspicionScore: 0.19 },
        { isCanary: false, suspicionScore: 0.25 },
        { isCanary: false, suspicionScore: 0.08 },
      ];
      const failEval = evaluateCanaryRealismAuc(separable);
      expect(failEval.auc).toBe(1.0);
      expect(failEval.v8Passed).toBe(false);
    });
  });
});
