import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { GET as getWeightsRoute } from "@/app/api/weights/route";
import {
  computeShardMerkleRoot,
  listModelRegistry,
  OPEN_MODEL_CATALOG,
  proveShardMembership,
  verifyLiveModelWeightProvenance,
  verifyShardBeforeLoad,
} from "@/lib/weights/open-shards";

describe("Subsystem 9: Model Weights Registry & Live Provenance Verification", () => {
  describe("Open-weight model real HF shard Merkle tree & verifier", () => {
    it("exposes only real open models in OPEN_MODEL_CATALOG with real Hugging Face shard counts and provenance", () => {
      expect(OPEN_MODEL_CATALOG["kimi-k3"].shardCount).toBe(96);
      expect(OPEN_MODEL_CATALOG["kimi-k3"].totalParams).toBe("2.8T");
      expect(OPEN_MODEL_CATALOG["kimi-k3"].weightRepoCommit).toBe(
        "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
      );
      expect(OPEN_MODEL_CATALOG["glm-5-3"].shardCount).toBe(88);
      expect(OPEN_MODEL_CATALOG["deepseek-v4-1-flash"].shardCount).toBe(48);
      expect(OPEN_MODEL_CATALOG["gpt-oss-120b"].shardCount).toBe(15);
      expect(OPEN_MODEL_CATALOG["llama3-3-70b"].shardCount).toBe(15);
      expect(OPEN_MODEL_CATALOG["kimi-linear-48b"].shardCount).toBe(20);
      expect(OPEN_MODEL_CATALOG["sim-echo-1"]).toBeUndefined();

      const registry = listModelRegistry();
      const ids = registry.map((r) => r.modelId);
      expect(ids).toEqual([
        "kimi-k3",
        "glm-5-3",
        "deepseek-v4-1-flash",
        "gpt-oss-120b",
        "llama3-3-70b",
        "kimi-linear-48b",
      ]);
      expect(ids).not.toContain("sim-echo-1");
      expect(ids).not.toContain("frontier-closed-x1");
    });

    it("verifies Merkle root and membership proof for every shard index across all catalog models", () => {
      for (const model of Object.values(OPEN_MODEL_CATALOG)) {
        const computedRoot = computeShardMerkleRoot(model.shardHashes);
        expect(computedRoot).toBe(model.merkleRoot);

        for (let idx = 0; idx < model.shardHashes.length; idx++) {
          const proof = proveShardMembership(model.shardHashes, idx);
          expect(proof.shardHash).toBe(model.shardHashes[idx]);
          expect(proof.root).toBe(model.merkleRoot);
          expect(verifyShardBeforeLoad(proof.shardHash, proof, model.merkleRoot)).toBe(true);
        }
      }
    });

    it("rejects corrupted shard hashes, tampered proof steps, or wrong committed roots", () => {
      const model = OPEN_MODEL_CATALOG["kimi-k3"];
      const proof = proveShardMembership(model.shardHashes, 17);

      const corruptedShardHash = bytesToHex(sha256(utf8ToBytes("corrupted-shard-payload")));
      expect(verifyShardBeforeLoad(corruptedShardHash, proof, model.merkleRoot)).toBe(false);

      const wrongRoot = OPEN_MODEL_CATALOG["glm-5-3"].merkleRoot;
      expect(verifyShardBeforeLoad(proof.shardHash, proof, wrongRoot)).toBe(false);

      const tamperedProof = {
        ...proof,
        proof: proof.proof.map((step, i) =>
          i === 0 ? { ...step, hash: corruptedShardHash } : step,
        ),
      };
      expect(verifyShardBeforeLoad(proof.shardHash, tamperedProof, model.merkleRoot)).toBe(
        false,
      );
    });
  });

  describe("Live Tinfoil, GitHub release & Hugging Face provenance verification", () => {
    it("fetches live Tinfoil proxy table, GitHub tinfoil-deployment.json, and Hugging Face API and verifies cross-source match", async () => {
      const result = await verifyLiveModelWeightProvenance("kimi-k3", {
        bypassCache: true,
      });

      expect(result.modelId).toBe("kimi-k3");
      expect(result.proxyTable.repo).toBe("tinfoilsh/confidential-kimi-k3");
      expect(result.deploymentManifest.weightRepoCommit).toBe(
        "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
      );
      expect(result.comparisons.hfRepoCommitMatchesAcrossSources).toBe(true);
      expect(result.comparisons.weightMpkHashMatchesAcrossSources).toBe(true);
      expect(result.comparisons.shardMerkleRootMatchesCommitted).toBe(true);
      expect(result.comparisons.dmVerityRootMatchesAcrossSources).toBe(true);
      expect(result.comparisons.configSha256MatchesCmdline).toBe(true);
      expect(result.comparisons.measurementRegistersMatchProxy).toBe(true);
      expect(result.enclaveStatus.c5Pass).toBe(true);
      expect(result.enclaveStatus.c7Pass).toBe(true);
      if (result.fetchedLive.huggingFaceApi) {
        expect(result.comparisons.hfCommitConfirmedViaPublicApi).toBe(true);
        expect(result.verified).toBe(true);
      }
    });

    it("detects tampered dm-verity root, tampered MPK hash, or missing Hugging Face commit across sources", async () => {
      const spec = OPEN_MODEL_CATALOG["kimi-k3"];
      const validYaml = [
        "cpus: 32",
        "memory: 524288",
        "gpus: 8",
        "models:",
        `  - name: "kimi-k3"`,
        `    repo: "${spec.weightRepoCommit}"`,
        `    mpk: "${spec.weightMpkHash}"`,
        "containers:",
        `  - name: "kimi-k3"`,
        `    image: "ghcr.io/tinfoilsh/confidential-kimi-k3@${spec.containerImageDigest}"`,
        "    runtime: nvidia",
        "    gpus: all",
        "    env:",
        '      - VLLM_DISABLE_UVA: "1"',
        '      - VLLM_ALLREDUCE_USE_SYMM_MEM: "0"',
        "    command:",
        '      - "--model"',
        '      - "/tinfoil/mpk/mpk-58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792"',
      ].join("\n");
      const validConfigB64 = Buffer.from(validYaml, "utf8").toString("base64");
      const validConfigSha256 = bytesToHex(sha256(utf8ToBytes(validYaml)));

      // 1. All sources match -> verified: true
      const matchingFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes(".well-known/tinfoil-proxy")) {
          return new Response(
            JSON.stringify({
              models: {
                "kimi-k3": {
                  repo: spec.tinfoilRepo,
                  tag: spec.tinfoilTag,
                  measurement: {
                    type: "https://tinfoil.sh/predicate/tdx-guest/v2",
                    registers: spec.measurementRegisters,
                  },
                  enclaves: {
                    "kimi-k3-inf14.tinfoil.containers.tinfoil.dev": {
                      hpke_key: "aa".repeat(32),
                      predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
                      tls_key_fp: "bb".repeat(32),
                    },
                  },
                  verification: {
                    configured: 1,
                    verified: 1,
                    healthy: 1,
                    unverified: 0,
                    hosts: {
                      "kimi-k3-inf14.tinfoil.containers.tinfoil.dev": {
                        code_tag: spec.tinfoilTag,
                      },
                    },
                  },
                },
              },
            }),
            { status: 200 },
          );
        }
        if (url.includes("tinfoil-deployment.json")) {
          return new Response(
            JSON.stringify({
              snp_measurement: spec.measurementRegisters?.[0],
              tdx_measurement: {
                rtmr1: spec.measurementRegisters?.[1],
                rtmr2: spec.measurementRegisters?.[2],
              },
              vm_shape: spec.vmShape,
              cmdline: `roothash=${spec.dmVerityRootHash} tinfoil-config-hash=${validConfigSha256}`,
              hashes: {
                root: spec.dmVerityRootHash,
                kernel: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
                initrd: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
              },
              config: validConfigB64,
            }),
            { status: 200 },
          );
        }
        if (url.includes("huggingface.co/api/models/")) {
          return new Response(
            JSON.stringify({
              sha: spec.hfCommit,
              siblings: Array.from({ length: 96 }, (_, i) => ({
                rfilename: `model-${i + 1}.safetensors`,
              })),
            }),
            { status: 200 },
          );
        }
        return new Response("Not found", { status: 404 });
      };

      const cleanRes = await verifyLiveModelWeightProvenance("kimi-k3", {
        fetchImpl: matchingFetch,
      });
      expect(cleanRes.verified).toBe(true);
      expect(cleanRes.comparisons.hfRepoCommitMatchesAcrossSources).toBe(true);
      expect(cleanRes.comparisons.hfCommitConfirmedViaPublicApi).toBe(true);
      expect(cleanRes.comparisons.weightMpkHashMatchesAcrossSources).toBe(true);
      expect(cleanRes.comparisons.dmVerityRootMatchesAcrossSources).toBe(true);
      expect(cleanRes.comparisons.configSha256MatchesCmdline).toBe(true);
      expect(cleanRes.comparisons.measurementRegistersMatchProxy).toBe(true);

      // 2. Tamper dm-verity root in cmdline and HF commit SHA -> fails provenance check
      const tamperedFetch: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url.includes("tinfoil-deployment.json")) {
          return new Response(
            JSON.stringify({
              snp_measurement: spec.measurementRegisters?.[0],
              tdx_measurement: {
                rtmr1: spec.measurementRegisters?.[1],
                rtmr2: spec.measurementRegisters?.[2],
              },
              vm_shape: spec.vmShape,
              cmdline: `roothash=${"ff".repeat(32)} tinfoil-config-hash=${validConfigSha256}`,
              hashes: {
                root: spec.dmVerityRootHash,
              },
              config: validConfigB64,
            }),
            { status: 200 },
          );
        }
        if (url.includes("huggingface.co/api/models/")) {
          return new Response(JSON.stringify({ sha: "00".repeat(20) }), { status: 200 });
        }
        return matchingFetch(input, init);
      };

      const tamperedRes = await verifyLiveModelWeightProvenance("kimi-k3", {
        fetchImpl: tamperedFetch,
      });
      expect(tamperedRes.verified).toBe(false);
      expect(tamperedRes.comparisons.dmVerityRootMatchesAcrossSources).toBe(false);
      expect(tamperedRes.comparisons.hfCommitConfirmedViaPublicApi).toBe(false);
      expect(tamperedRes.comparisons.hfRepoCommitMatchesAcrossSources).toBe(false);
    });

    it("GET /api/weights returns real provenance comparisons and real HF shard Merkle proofs", async () => {
      const getRes = await getWeightsRoute(new Request("http://localhost:3000/api/weights?model=kimi-k3"));
      expect(getRes.status).toBe(200);
      const getJson = (await getRes.json()) as {
        models: Array<{ modelId: string; shardCount: number }>;
        sampleProof: { modelId: string; verified: boolean; shardHash: string; root: string };
        provenance: { modelId: string; comparisons: Record<string, boolean> };
        allModelsProvenance: Record<string, { modelId: string }>;
      };
      expect(getJson.sampleProof.modelId).toBe("kimi-k3");
      expect(getJson.sampleProof.verified).toBe(true);
      expect(getJson.sampleProof.shardHash).toBe(OPEN_MODEL_CATALOG["kimi-k3"].shardHashes[0]);
      expect(getJson.provenance.modelId).toBe("kimi-k3");
      expect(getJson.provenance.comparisons.dmVerityRootMatchesAcrossSources).toBe(true);
      expect(getJson.provenance.comparisons.weightMpkHashMatchesAcrossSources).toBe(true);
      expect(Object.keys(getJson.allModelsProvenance)).toContain("kimi-k3");
      expect(Object.keys(getJson.allModelsProvenance)).toContain("glm-5-3");
    });
  });
});
