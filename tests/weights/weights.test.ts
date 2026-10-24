import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  createCustodyProviderKeypair,
  custodyUnwrapWeightKey,
  providerWrapWeightKey,
} from "@/lib/weights/closed-release";
import {
  computeShardMerkleRoot,
  listModelRegistry,
  OPEN_MODEL_CATALOG,
  proveShardMembership,
  verifyShardBeforeLoad,
} from "@/lib/weights/open-shards";

describe("Subsystem 9: Model Weights Registry (Spec §2.6 & §4)", () => {
  describe("Open-weight model shard Merkle tree & verifier", () => {
    it("exposes all required open models in OPEN_MODEL_CATALOG and listModelRegistry()", () => {
      expect(OPEN_MODEL_CATALOG["kimi-k3"].shardCount).toBe(64);
      expect(OPEN_MODEL_CATALOG["kimi-k3"].totalParams).toBe("2.8T");
      expect(OPEN_MODEL_CATALOG["kimi-linear-48b"].shardCount).toBe(8);
      expect(OPEN_MODEL_CATALOG["glm-5-3"].shardCount).toBe(16);
      expect(OPEN_MODEL_CATALOG["llama3-3-70b"].shardCount).toBe(8);
      expect(OPEN_MODEL_CATALOG["sim-echo-1"].shardCount).toBe(1);

      const registry = listModelRegistry();
      const ids = registry.map((r) => r.modelId);
      expect(ids).toContain("kimi-k3");
      expect(ids).toContain("kimi-linear-48b");
      expect(ids).toContain("glm-5-3");
      expect(ids).toContain("llama3-3-70b");
      expect(ids).toContain("sim-echo-1");
    });

    it("verifies Merkle root and membership proof for every shard index across all catalog models", () => {
      for (const model of Object.values(OPEN_MODEL_CATALOG)) {
        const computedRoot = computeShardMerkleRoot(model.shardHashes);
        expect(computedRoot).toBe(model.merkleRoot);

        for (let idx = 0; idx < model.shardHashes.length; idx++) {
          const proof = proveShardMembership(model.shardHashes, idx);
          expect(proof.shardHash).toBe(model.shardHashes[idx]);
          expect(proof.root).toBe(model.merkleRoot);
          expect(
            verifyShardBeforeLoad(proof.shardHash, proof, model.merkleRoot)
          ).toBe(true);
        }
      }
    });

    it("rejects corrupted shard hashes, tampered proof steps, or wrong committed roots", () => {
      const model = OPEN_MODEL_CATALOG["kimi-k3"];
      const proof = proveShardMembership(model.shardHashes, 17);

      const corruptedShardHash = bytesToHex(
        sha256(utf8ToBytes("corrupted-shard-payload"))
      );
      expect(
        verifyShardBeforeLoad(corruptedShardHash, proof, model.merkleRoot)
      ).toBe(false);

      const wrongRoot = OPEN_MODEL_CATALOG["glm-5-3"].merkleRoot;
      expect(
        verifyShardBeforeLoad(proof.shardHash, proof, wrongRoot)
      ).toBe(false);

      const tamperedProof = {
        ...proof,
        proof: proof.proof.map((step, i) =>
          i === 0 ? { ...step, hash: corruptedShardHash } : step
        ),
      };
      expect(
        verifyShardBeforeLoad(proof.shardHash, tamperedProof, model.merkleRoot)
      ).toBe(false);
    });
  });

  describe("Closed-model provider attested weight-key release protocol", () => {
    const approvedMeasurement = bytesToHex(
      sha256(utf8ToBytes("drouter:approved-tee-rim-measurement:v1"))
    );
    const sampleWeightKeyHex = bytesToHex(
      sha256(utf8ToBytes("provider-master-aes256-weight-key-material"))
    );

    it("releases wrapped weight key when node evidence meets measurement and quorum requirements and unwraps inside custody module", () => {
      const custodyKeys = createCustodyProviderKeypair(
        bytesToHex(sha256(utf8ToBytes("deterministic-custody-seed-1")))
      );
      expect(custodyKeys.bindingHash).toHaveLength(64);

      const res = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-001",
          measurement: approvedMeasurement,
          approvedMeasurement,
          status: "full",
          quorumSignatures: 5,
          requiredQuorum: 4,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });

      expect(res.released).toBe(true);
      if (!res.released) throw new Error("Expected release");

      const recoveredWeightKey = custodyUnwrapWeightKey(res, custodyKeys);
      expect(recoveredWeightKey).toBe(sampleWeightKeyHex);

      // Tampering with ciphertext or signature must throw inside custodyUnwrapWeightKey
      const tamperedCiphertext = {
        ...res,
        wrappedKeyCiphertextHex:
          res.wrappedKeyCiphertextHex.slice(0, -2) +
          (res.wrappedKeyCiphertextHex.endsWith("00") ? "ff" : "00"),
      };
      expect(() =>
        custodyUnwrapWeightKey(tamperedCiphertext, custodyKeys)
      ).toThrow();
    });

    it("refuses weight key release when measurement mismatches, node is suspended, or quorum signatures are below threshold", () => {
      const custodyKeys = createCustodyProviderKeypair();

      const wrongMeasurementRes = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-002",
          measurement: bytesToHex(sha256(utf8ToBytes("unapproved-measurement"))),
          approvedMeasurement,
          status: "full",
          quorumSignatures: 5,
          requiredQuorum: 4,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });
      expect(wrongMeasurementRes.released).toBe(false);
      if (!wrongMeasurementRes.released) {
        expect(wrongMeasurementRes.reason).toMatch(/measurement/i);
      }

      const suspendedRes = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-003",
          measurement: approvedMeasurement,
          approvedMeasurement,
          status: "suspended",
          quorumSignatures: 5,
          requiredQuorum: 4,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });
      expect(suspendedRes.released).toBe(false);
      if (!suspendedRes.released) {
        expect(suspendedRes.reason).toMatch(/suspended/i);
      }

      const lowQuorumRes = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-004",
          measurement: approvedMeasurement,
          approvedMeasurement,
          status: "ramp",
          quorumSignatures: 2,
          requiredQuorum: 4,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });
      expect(lowQuorumRes.released).toBe(false);
      if (!lowQuorumRes.released) {
        expect(lowQuorumRes.reason).toMatch(/quorum/i);
      }

      // requiredQuorum: 0 bypass attempt must be rejected
      const zeroQuorumBypass = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-005",
          measurement: approvedMeasurement,
          approvedMeasurement,
          status: "full",
          quorumSignatures: 0,
          requiredQuorum: 0,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });
      expect(zeroQuorumBypass.released).toBe(false);

      // Forged provider public key in release bundle must be rejected by custodyUnwrapWeightKey
      const validRel = providerWrapWeightKey({
        providerId: "provider-alpha",
        modelId: "frontier-closed-x1",
        weightKeyHex: sampleWeightKeyHex,
        nodeEvidence: {
          chipId: "H200-TEE-006",
          measurement: approvedMeasurement,
          approvedMeasurement,
          status: "full",
          quorumSignatures: 5,
          requiredQuorum: 4,
          custodyX25519Pk: custodyKeys.x25519PublicKey,
          custodyMlkemPk: custodyKeys.mlkemPublicKey,
        },
      });
      if (!validRel.released) throw new Error("Expected release");
      expect(() =>
        custodyUnwrapWeightKey(validRel, custodyKeys, "aa".repeat(32))
      ).toThrow(/Provider public key does not match/i);
    });
  });
});
