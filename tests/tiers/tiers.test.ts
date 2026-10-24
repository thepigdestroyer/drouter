import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { GET as getTiers } from "@/app/api/tiers/route";
import {
  buildMeasuredTiersCatalog,
  GEMINI_4_ARGON_MAX_CONTEXT_TOKENS,
  KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
} from "@/lib/tiers/catalog";
import {
  applyOperatorShareCaps,
  evaluateCanaryRealismAuc,
  evaluateTimingSignal,
  requiredNodeStakeUsdc,
  UNVERIFIED_OPERATOR_CAP_PCT,
  VERIFIED_OPERATOR_CAP_PCT,
} from "@/lib/tiers/economics";
import {
  canonicalSpdmPayload,
  canonicalTdxQuotePayload,
  measureLiveTinfoilQuoteVerifications,
  p256SignHex,
  RISER_PROOF_CPU_ALLOWLIST,
  TDX_TEE_TYPE,
  verifyTdxTierBQuote,
  verifyTierAPlusEvidence,
  type SpdmDeviceClass,
  type SpdmDeviceMeasurement,
  type TdxQuoteV4,
  type TierAPlusEvidence,
} from "@/lib/tiers/tdx-spdm";

function deriveTestKeyPair(label: string) {
  const seed = sha256(utf8ToBytes("test-tiers-p256-seed"));
  const secretKey = hkdf(sha256, seed, undefined, utf8ToBytes(label), 32);
  const publicKeyHex = bytesToHex(p256.getPublicKey(secretKey, false));
  return { secretKey, publicKeyHex };
}

function makeTestSignedTdxQuote(
  params?: Partial<{
    teeType: number;
    mrtd: string;
    rtmr0: string;
    reportData: string;
    tdAttributesDebug: boolean;
    tcbSvn: number;
  }>,
): TdxQuoteV4 {
  const mrtd = params?.mrtd ?? bytesToHex(sha384(utf8ToBytes("test-tdx-mrtd")));
  const rtmr0 = params?.rtmr0 ?? bytesToHex(sha384(utf8ToBytes("test-tdx-rtmr0")));
  const reportData =
    params?.reportData ?? bytesToHex(sha256(utf8ToBytes("test-session-binding")));
  const teeType = params?.teeType ?? TDX_TEE_TYPE;
  const tdAttributesDebug = params?.tdAttributesDebug ?? false;
  const tcbSvn = params?.tcbSvn ?? 7;

  const { secretKey, publicKeyHex } = deriveTestKeyPair("test-pck-tdx-v4");
  const payload = canonicalTdxQuotePayload({
    teeType,
    mrtd,
    rtmr0,
    reportData,
    tdAttributesDebug,
    tcbSvn,
  });
  return {
    teeType,
    mrtd,
    rtmr0,
    reportData,
    tdAttributesDebug,
    tcbSvn,
    pckSignatureHex: p256SignHex(payload, secretKey),
    pckPublicKeyHex: publicKeyHex,
  };
}

function makeTestTierAPlusEvidence(params?: {
  nodeId?: string;
  cpuModel?: string;
  teeIoBoundVmId?: string;
  signedVmId?: string;
}): TierAPlusEvidence {
  const nodeId = params?.nodeId ?? "tier-aplus-node-1";
  const cpuModel = params?.cpuModel ?? RISER_PROOF_CPU_ALLOWLIST[0];
  const teeIoBoundVmId = params?.teeIoBoundVmId ?? "cvm-snp-vm-001";
  const signedVmId = params?.signedVmId ?? teeIoBoundVmId;

  const specs: { deviceId: string; deviceClass: SpdmDeviceClass }[] = [
    { deviceId: "gpu-0", deviceClass: "GPU" },
    { deviceId: "gpu-1", deviceClass: "GPU" },
    { deviceId: "gpu-2", deviceClass: "GPU" },
    { deviceId: "gpu-3", deviceClass: "GPU" },
    { deviceId: "gpu-4", deviceClass: "GPU" },
    { deviceId: "gpu-5", deviceClass: "GPU" },
    { deviceId: "gpu-6", deviceClass: "GPU" },
    { deviceId: "gpu-7", deviceClass: "GPU" },
    { deviceId: "nic-0", deviceClass: "NIC" },
    { deviceId: "nvme-0", deviceClass: "NVME" },
  ];

  const devices: SpdmDeviceMeasurement[] = specs.map((spec) => {
    const digest = bytesToHex(
      sha384(utf8ToBytes(`spdm-fw-measurement/${spec.deviceClass}/${spec.deviceId}/v1`)),
    );
    const nonceHex = bytesToHex(sha256(utf8ToBytes(`spdm-nonce/${nodeId}/${spec.deviceId}`)));
    const { secretKey, publicKeyHex } = deriveTestKeyPair(
      `spdm-device-key/${nodeId}/${spec.deviceId}`,
    );
    const payload = canonicalSpdmPayload(
      {
        deviceId: spec.deviceId,
        deviceClass: spec.deviceClass,
        spdmVersion: "1.2",
        measurementDigestHex: digest,
        nonceHex,
      },
      signedVmId,
    );
    return {
      deviceId: spec.deviceId,
      deviceClass: spec.deviceClass,
      spdmVersion: "1.2",
      measurementDigestHex: digest,
      expectedDigestHex: digest,
      nonceHex,
      devicePublicKeyHex: publicKeyHex,
      signatureHex: p256SignHex(payload, secretKey),
    };
  });

  return {
    nodeId,
    cpuModel,
    teeIoBoundVmId,
    devices,
  };
}

describe("Subsystem 11: Platform Tiers (Live Quote Verification, Operator Share Caps & Economics)", () => {
  describe("Tier B (Intel TDX Quote v4 Policy Verifier)", () => {
    it("rejects a valid TDX quote when allowTierB is false (client must opt in)", () => {
      const quote = makeTestSignedTdxQuote();
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
      const debugQuote = makeTestSignedTdxQuote({ tdAttributesDebug: true });
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
      const quote = makeTestSignedTdxQuote({ tcbSvn: 4 });

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
      const quote = makeTestSignedTdxQuote({ tcbSvn: 7 });
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
      const evidence = makeTestTierAPlusEvidence({
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
      const evidence = makeTestTierAPlusEvidence({
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
      const evidence = makeTestTierAPlusEvidence({
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
      const evidence = makeTestTierAPlusEvidence({
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
        { nodeId: "whale-v-1", operatorId: "op-whale-verified", operatorVerified: true, rawWeight: 5000 },
        { nodeId: "whale-v-2", operatorId: "op-whale-verified", operatorVerified: true, rawWeight: 5000 },
        { nodeId: "sybil-u-1", operatorId: "op-unverified-1", operatorVerified: false, rawWeight: 2000 },
        { nodeId: "sybil-u-2", operatorId: "op-unverified-1", operatorVerified: false, rawWeight: 2000 },
        ...Array.from({ length: 60 }, (_, idx) => ({
          nodeId: `ind-node-${idx + 1}`,
          operatorId: `op-ind-${idx + 1}`,
          operatorVerified: true,
          rawWeight: 100,
        })),
      ];

      const results = applyOperatorShareCaps(nodes);

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

  describe("Tiers Catalog & GET /api/tiers Ground Truth (Live Tinfoil Quotes & Real SEAL FHE Tier C)", () => {
    it("sources Kimi K3 max context at 262,144 tokens, removes invented tok/s numbers, and measures live Tier C SEAL FHE latency", async () => {
      const catalog = await buildMeasuredTiersCatalog({
        cryptoVerifyLatencyMs: {
          tierASevSnpVerifyMs: 2.1,
          tierBTdxQuoteVerifyMs: 1.25,
          tierAPlusSpdmVerifyMs: 4.5,
        },
      });

      expect(catalog.kimiK3MaxContextTokens).toBe(262_144);
      expect(catalog.gemini4ArgonMaxContextTokens).toBe(1_000_000);
      expect(KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS).toBe(262_144);
      expect(GEMINI_4_ARGON_MAX_CONTEXT_TOKENS).toBe(1_000_000);

      const tierA = catalog.entries.find((e) => e.tier === "Tier A");
      const tierAPlus = catalog.entries.find((e) => e.tier === "Tier A+");
      const tierB = catalog.entries.find((e) => e.tier === "Tier B");
      const tierC = catalog.entries.find((e) => e.tier === "Tier C");

      expect(tierA?.maxContextTokens).toBe(262_144);
      expect(tierAPlus?.maxContextTokens).toBe(262_144);
      expect(tierB?.maxContextTokens).toBe(262_144);
      expect(tierA?.throughputTokPerSec).toBeNull();
      expect(tierAPlus?.throughputTokPerSec).toBeNull();
      expect(tierB?.throughputTokPerSec).toBeNull();

      expect(tierC?.maxContextTokens).toBe(128);
      expect(tierC?.measuredEvalLatencyMs).toBeGreaterThan(0);
      expect(tierC?.throughputOpsPerSec).toBeGreaterThan(0);
      expect(catalog.liveFheMeasurement.serverSawPlaintext).toBe(false);
      expect(catalog.liveFheMeasurement.verification.maxScoreAbsError!).toBeLessThan(1e-2);
    });

    it(
      "measures verification latency on real live AMD SEV-SNP (Genoa/Turin) and Intel TDX v4 quotes in GET /api/tiers",
      async () => {
        const liveMeasurements = await measureLiveTinfoilQuoteVerifications();
        if (liveMeasurements.tierASevSnpRouter.verification) {
          expect(liveMeasurements.tierASevSnpRouter.verification.verified).toBe(true);
          expect(liveMeasurements.tierASevSnpRouter.measuredVerifyLatencyMs).toBeGreaterThan(0);
        }
        if (liveMeasurements.tierAPlusTurinEnclave.verification) {
          expect(liveMeasurements.tierAPlusTurinEnclave.verification.verified).toBe(true);
          expect(liveMeasurements.tierAPlusTurinEnclave.verification.productName).toBe("Turin");
          expect(liveMeasurements.tierAPlusTurinEnclave.measuredVerifyLatencyMs).toBeGreaterThan(0);
        }
        if (liveMeasurements.tierBTdxEnclave.verification) {
          expect(liveMeasurements.tierBTdxEnclave.verification.verified).toBe(true);
          expect(liveMeasurements.tierBTdxEnclave.measuredVerifyLatencyMs).toBeGreaterThan(0);
        }

        const res = await getTiers();
        expect(res.status).toBe(200);
        const json = (await res.json()) as {
          parameters: { kimiK3MaxContextTokens: number };
          tiers: {
            tierA: { maxContextTokens: number; measuredVerifyLatencyMs: number | null };
            tierB: { measuredVerifyLatencyMs: number | null; maxContextTokens: number };
            tierAPlus: { measuredVerifyLatencyMs: number | null; maxContextTokens: number };
            tierC: {
              scopeDisclosure: string;
              liveFheMeasurement: {
                serverSawPlaintext: boolean;
                verification: { maxScoreAbsError: number };
              };
            };
          };
          catalog: Array<{ tier: string; maxContextTokens: number }>;
        };

        expect(json.parameters.kimiK3MaxContextTokens).toBe(262_144);
        expect(json.tiers.tierA.maxContextTokens).toBe(262_144);
        expect(json.tiers.tierB.maxContextTokens).toBe(262_144);
        expect(json.tiers.tierC.liveFheMeasurement.serverSawPlaintext).toBe(false);
        expect(
          json.tiers.tierC.liveFheMeasurement.verification.maxScoreAbsError,
        ).toBeLessThan(1e-2);
        expect(json.catalog).toHaveLength(4);
      },
      25_000,
    );
  });
});
