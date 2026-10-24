import { describe, expect, it } from "vitest";
import { GET as getAshi, POST as postAshi } from "@/app/api/ashi/route";
import {
  clientDecryptEvaluationResult,
  clientEncryptVector128,
  computePlaintextReferenceScores,
  FHE_POLY_MODULUS_DEGREE,
  FHE_SCOPE_DISCLOSURE,
  FHE_VECTOR_DIM,
  runLiveFheLinearRoundTrip,
  serverEvaluateEncryptedLinearScores,
} from "@/lib/ashi/fhe";
import {
  DEFAULT_ASHI_CRYPTO,
  DEFAULT_ASHI_MODEL,
  FHE_ASIC,
  GPU_FLOOR,
  GPU_TODAY,
  evaluateAshiTierC,
  passLatency,
  simulatePshv,
} from "@/lib/ashi/model";

describe("ASHI Tier C Cryptographic FHE Engine", () => {
  describe("Real node-seal 7.0.0 (Microsoft SEAL 4.1.2 WASM) CKKS Linear Classifier", () => {
    it("executes a real CKKS encrypt -> homomorphic dot-product + squared norm -> decrypt round trip with < 1e-2 error", async () => {
      const measurement = await runLiveFheLinearRoundTrip({
        text: "tee.fail ddr5 memory bus interposer passive probe aes-xts static iv riser-proof soldered memory spdm 1.2",
      });

      expect(measurement.scheme).toBe("CKKS");
      expect(measurement.polyModulusDegree).toBe(FHE_POLY_MODULUS_DEGREE);
      expect(measurement.vectorDimension).toBe(FHE_VECTOR_DIM);
      expect(measurement.serverSawPlaintext).toBe(false);
      expect(measurement.serverSawSecretKey).toBe(false);
      expect(measurement.scopeDisclosure).toContain("linear classifier");
      expect(measurement.scopeDisclosure).toContain("NOT run a frontier LLM");

      // Real measured byte sizes
      expect(measurement.sizesBytes.inputCiphertextBytes).toBeGreaterThan(10_000);
      expect(measurement.sizesBytes.resultCiphertextBytes).toBeGreaterThan(10_000);
      expect(measurement.sizesBytes.relinKeysBytes).toBeGreaterThan(10_000);
      expect(measurement.sizesBytes.galoisKeysBytes).toBeGreaterThan(50_000);

      // Real measured latencies
      expect(measurement.timingsMs.serverTotalEvalMs).toBeGreaterThan(0);
      expect(measurement.timingsMs.totalRoundTripMs).toBeGreaterThan(0);

      // Numerical accuracy vs plaintext reference
      expect(measurement.verification.maxScoreAbsError).toBeDefined();
      expect(measurement.verification.maxScoreAbsError!).toBeLessThan(1e-2);
      expect(measurement.verification.normAbsError).toBeDefined();
      expect(measurement.verification.normAbsError!).toBeLessThan(1e-2);
      expect(measurement.verification.fheSquaredL2Norm).toBeCloseTo(1.0, 2);
      expect(measurement.verification.predictedClassId).toBe(
        "hardware-bus-interposer-defense",
      );
    });

    it("correctly classifies distinct domain embeddings homomorphically without the server ever seeing secretKey or plaintext", async () => {
      const text =
        "circle arc blockchain on-chain attestation usdc settlement contract canary trap honeypot bounty slashing stake operator cap";
      const clientBundle = await clientEncryptVector128({ text });

      // Ensure requestPayload has no secret key or plaintext
      expect("secretKeyBase64" in clientBundle.requestPayload).toBe(false);
      expect("inputVector128" in clientBundle.requestPayload).toBe(false);

      const serverEval = await serverEvaluateEncryptedLinearScores(
        clientBundle.requestPayload,
      );
      expect(serverEval.serverSawPlaintext).toBe(false);
      expect(serverEval.serverSawSecretKey).toBe(false);

      const decrypted = await clientDecryptEvaluationResult({
        secretKeyBase64: clientBundle.secretKeyBase64,
        resultCiphertextBase64: serverEval.resultCiphertextBase64,
        normCiphertextBase64: serverEval.normCiphertextBase64,
        referenceVector128: clientBundle.inputVector128,
      });

      const ref = computePlaintextReferenceScores(clientBundle.inputVector128);
      expect(decrypted.predictedClassId).toBe(ref.predictedClassId);
      expect(decrypted.predictedClassId).toBe("onchain-accountability-slashing");
      expect(decrypted.maxScoreAbsError!).toBeLessThan(1e-2);
    });

    it("serves POST /api/ashi for encrypted payloads and rejects any request leaking plaintext or secretKey", async () => {
      const clientBundle = await clientEncryptVector128({
        text: "zero knowledge halo2 plonky3 fhe mpc ohttp oblivious http rsa blind credit nullifier",
      });

      // 1. Reject if caller accidentally includes secretKeyBase64 or text
      const leakyReq = new Request("http://localhost:3000/api/ashi", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...clientBundle.requestPayload,
          secretKeyBase64: clientBundle.secretKeyBase64,
        }),
      });
      const leakyRes = await postAshi(leakyReq);
      expect(leakyRes.status).toBe(400);
      const leakyJson = (await leakyRes.json()) as { error: string };
      expect(leakyJson.error).toContain("Privacy violation rejected");

      // 2. Accept valid ciphertext-only payload and verify decrypted result
      const validReq = new Request("http://localhost:3000/api/ashi", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(clientBundle.requestPayload),
      });
      const validRes = await postAshi(validReq);
      expect(validRes.status).toBe(200);
      const evalJson = (await validRes.json()) as Awaited<
        ReturnType<typeof serverEvaluateEncryptedLinearScores>
      >;
      expect(evalJson.serverSawPlaintext).toBe(false);
      expect(evalJson.resultCiphertextBase64.length).toBeGreaterThan(1000);

      const decrypted = await clientDecryptEvaluationResult({
        secretKeyBase64: clientBundle.secretKeyBase64,
        resultCiphertextBase64: evalJson.resultCiphertextBase64,
        normCiphertextBase64: evalJson.normCiphertextBase64,
        referenceVector128: clientBundle.inputVector128,
      });
      expect(decrypted.predictedClassId).toBe("cryptographic-fhe-mpc-routing");
      expect(decrypted.maxScoreAbsError!).toBeLessThan(1e-2);
    });

    it("returns live FHE measurements and sourced 262,144 Kimi K3 context in GET /api/ashi", async () => {
      const res = await getAshi();
      expect(res.status).toBe(200);
      const data = (await res.json()) as {
        kimiK3MaxContextTokens: number;
        fheScopeDisclosure: string;
        isAnalyticalSimulation: boolean;
        liveFhe: Awaited<ReturnType<typeof runLiveFheLinearRoundTrip>>;
        tierComparison: Array<{
          tier: string;
          maxContextTokens: number;
          throughputTokPerSec: number | null;
          usdPerMillionOutputTokens: number | null;
        }>;
      };

      expect(data.kimiK3MaxContextTokens).toBe(262_144);
      expect(data.fheScopeDisclosure).toBe(FHE_SCOPE_DISCLOSURE);
      expect(data.isAnalyticalSimulation).toBe(true);
      expect(data.liveFhe.verification.maxScoreAbsError!).toBeLessThan(1e-2);

      const tierA = data.tierComparison.find((t) => t.tier === "Tier A");
      const tierB = data.tierComparison.find((t) => t.tier === "Tier B");
      const tierC = data.tierComparison.find((t) => t.tier === "Tier C");

      expect(tierA?.maxContextTokens).toBe(262_144);
      expect(tierB?.maxContextTokens).toBe(262_144);
      // Invented static LLM throughput numbers (85, 82, 95) are removed (null)
      expect(tierA?.throughputTokPerSec).toBeNull();
      expect(tierB?.throughputTokPerSec).toBeNull();
      // Tier C reports the real 128-d input vector dimension and live measured ops/sec
      expect(tierC?.maxContextTokens).toBe(128);
      expect(tierC?.throughputTokPerSec).toBeGreaterThan(0);
    });
  });

  describe("Labelled Analytical Frontier FHE Model (model.ts)", () => {
    it("maintains ~2.4 GB constant encrypted state vs ~2.7 TB full 1M encrypted KV cache (>1,000x reduction)", () => {
      const result = evaluateAshiTierC({ alpha: 0.95 });

      expect(result.isAnalyticalSimulation).toBe(true);
      expect(result.kimiK3MaxContextTokens).toBe(262_144);
      expect(result.stateGb).toBeCloseTo(2.42, 1);
      expect(result.fullKvCacheTbAt1M).toBeCloseTo(2.65, 1);

      const ratio = (result.fullKvCacheTbAt1M * 1000) / result.stateGb;
      expect(ratio).toBeGreaterThan(1000);
    });

    it("computes refresh cadence as 16 bootstraps per 96-layer pass (every 6 layers)", () => {
      const result = evaluateAshiTierC({ alpha: 0.95 });

      expect(DEFAULT_ASHI_MODEL.layers).toBe(96);
      expect(DEFAULT_ASHI_MODEL.levelsPerLayer).toBe(5);
      expect(DEFAULT_ASHI_CRYPTO.levelsPerBts).toBe(30);
      expect(result.bootstrapsPerPass).toBe(16);
      expect(DEFAULT_ASHI_MODEL.layers / result.bootstrapsPerPass).toBe(6);
    });

    it("exceeds 50 tok/s committed decode throughput on both GPU_FLOOR and FHE_ASIC at alpha = 0.95", () => {
      const result = evaluateAshiTierC({ alpha: 0.95 });

      const gpuFloor = result.profiles.find((p) => p.name === GPU_FLOOR.name);
      const fheAsic = result.profiles.find((p) => p.name === FHE_ASIC.name);
      const gpuToday = result.profiles.find((p) => p.name === GPU_TODAY.name);

      expect(gpuFloor).toBeDefined();
      expect(fheAsic).toBeDefined();
      expect(gpuToday).toBeDefined();

      expect(gpuFloor!.committedTokPerSec).toBeGreaterThan(50);
      expect(fheAsic!.committedTokPerSec).toBeGreaterThan(50);
    });

    it("increases committed tok/s and lowers usdPerMillionOutputTokens as draft acceptance alpha rises", () => {
      const lowAlpha = evaluateAshiTierC({ alpha: 0.8 });
      const midAlpha = evaluateAshiTierC({ alpha: 0.9 });
      const highAlpha = evaluateAshiTierC({ alpha: 0.95 });

      for (let i = 0; i < lowAlpha.profiles.length; i++) {
        expect(midAlpha.profiles[i].committedTokPerSec).toBeGreaterThan(
          lowAlpha.profiles[i].committedTokPerSec,
        );
        expect(highAlpha.profiles[i].committedTokPerSec).toBeGreaterThan(
          midAlpha.profiles[i].committedTokPerSec,
        );

        expect(midAlpha.profiles[i].usdPerMillionOutputTokens).toBeLessThan(
          lowAlpha.profiles[i].usdPerMillionOutputTokens,
        );
        expect(highAlpha.profiles[i].usdPerMillionOutputTokens).toBeLessThan(
          midAlpha.profiles[i].usdPerMillionOutputTokens,
        );
      }

      const tPassFloor = passLatency(
        DEFAULT_ASHI_MODEL,
        DEFAULT_ASHI_CRYPTO,
        GPU_FLOOR,
      );
      const pshv80 = simulatePshv(0.8, tPassFloor, 8, 4, 0.04, GPU_FLOOR);
      const pshv95 = simulatePshv(0.95, tPassFloor, 8, 4, 0.04, GPU_FLOOR);

      expect(pshv95.committedTokPerSec).toBeGreaterThan(
        pshv80.committedTokPerSec,
      );
      expect(pshv95.usdPerMillionOutputTokens).toBeLessThan(
        pshv80.usdPerMillionOutputTokens,
      );
      expect(pshv95.prefillCost.lazy150K.usd).toBeLessThan(
        pshv95.prefillCost.full1M.usd,
      );
    });
  });
});
