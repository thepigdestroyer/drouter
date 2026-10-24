import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  computeAuditPathFromLeaves,
  computeLeafHash,
  computeMerkleRootFromLeaves,
  createSignedTransparencyEntry,
  getTransparencyLog,
  proveInclusion,
  verifyInclusion,
} from "@/lib/transparency/log";
import {
  getVerifierSet,
  issueQuorumTicket,
  verifyQuorumTicket,
} from "@/lib/transparency/quorum";

describe("Software Transparency Log (RFC 6962 Merkle tree & signatures)", () => {
  it("verifies Merkle inclusion proof for each approved release entry", () => {
    const log = getTransparencyLog();
    expect(log.entries).toHaveLength(3);
    expect(log.entries.map((e) => e.imageId)).toEqual([
      "tinfoilsh/confidential-model-router",
      "drouter-sim-node-image/v0.1.0",
      "drouter-monitor-svsm/v0.1.0",
    ]);

    for (let i = 0; i < log.entries.length; i++) {
      const entry = log.entries[i];
      const proof = proveInclusion(i);
      expect(proof.root).toBe(log.root);
      const res = verifyInclusion(entry, proof);
      expect(res.ok).toBe(true);
      expect(res.builderCount).toBe(3);
      expect(res.reviewerCount).toBeGreaterThanOrEqual(4);
      expect(res.reviewWindowPassed).toBe(true);
    }
  });

  it("fails verifyInclusion if any entry field or sibling hash is tampered", () => {
    const log = getTransparencyLog();
    const entry = log.entries[1];
    const proof = proveInclusion(1);

    // Tamper with entry version
    const tamperedEntry = { ...entry, version: "v0.1.1-backdoor" };
    expect(verifyInclusion(tamperedEntry, proof).ok).toBe(false);

    // Tamper with entry measurement
    const tamperedMeasurement = { ...entry, measurement: "ff".repeat(48) };
    expect(verifyInclusion(tamperedMeasurement, proof).ok).toBe(false);

    // Tamper with a sibling hash in the audit path
    const tamperedProof = {
      ...proof,
      auditPath: proof.auditPath.map((step, idx) =>
        idx === 0 ? { ...step, hash: "aa".repeat(32) } : step,
      ),
    };
    expect(verifyInclusion(entry, tamperedProof).ok).toBe(false);
  });

  it("fails verifyInclusion when <3 builders, <4 reviewers, or 14-day review window is unexpired", () => {
    const baseTime = 1750000000;

    // 1. Only 2 builders (< 3)
    const twoBuilders = createSignedTransparencyEntry({
      index: 0,
      imageId: "drouter-sim-node-image/v0.1.0",
      version: "v0.1.0",
      measurement: "11".repeat(48),
      approvedAt: baseTime,
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 2,
      reviewerCount: 5,
    });
    const leaf1 = computeLeafHash(twoBuilders);
    const root1 = bytesToHex(computeMerkleRootFromLeaves([leaf1]));
    const resBuilders = verifyInclusion(
      twoBuilders,
      { root: root1, auditPath: [] },
      baseTime + 15 * 86400,
    );
    expect(resBuilders.ok).toBe(false);
    expect(resBuilders.builderCount).toBe(2);

    // 2. Only 3 reviewers (< 4 for normal release)
    const threeReviewers = createSignedTransparencyEntry({
      index: 0,
      imageId: "drouter-sim-node-image/v0.1.0",
      version: "v0.1.0",
      measurement: "11".repeat(48),
      approvedAt: baseTime,
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 3,
      reviewerCount: 3,
    });
    const leaf2 = computeLeafHash(threeReviewers);
    const root2 = bytesToHex(computeMerkleRootFromLeaves([leaf2]));
    const resReviewers = verifyInclusion(
      threeReviewers,
      { root: root2, auditPath: [] },
      baseTime + 15 * 86400,
    );
    expect(resReviewers.ok).toBe(false);
    expect(resReviewers.reviewerCount).toBe(3);

    // 3. Unexpired 14-day review window (only 10 days elapsed)
    const validNormal = createSignedTransparencyEntry({
      index: 0,
      imageId: "drouter-sim-node-image/v0.1.0",
      version: "v0.1.0",
      measurement: "11".repeat(48),
      approvedAt: baseTime,
      reviewWindowDays: 14,
      emergency: false,
      builderCount: 3,
      reviewerCount: 5,
    });
    const leaf3 = computeLeafHash(validNormal);
    const root3 = bytesToHex(computeMerkleRootFromLeaves([leaf3]));
    const resUnexpired = verifyInclusion(
      validNormal,
      { root: root3, auditPath: [] },
      baseTime + 10 * 86400,
    );
    expect(resUnexpired.ok).toBe(false);
    expect(resUnexpired.reviewWindowPassed).toBe(false);
  });

  it("passes verifyInclusion for an emergency entry with 7/7 reviewers after 48h", () => {
    const approvedAt = 1750000000;
    const emergencyEntry = createSignedTransparencyEntry({
      index: 0,
      imageId: "drouter-monitor-svsm/v0.1.0-hotfix",
      version: "v0.1.1",
      measurement: "22".repeat(48),
      approvedAt,
      reviewWindowDays: 2,
      emergency: true,
      builderCount: 3,
      reviewerCount: 7,
    });
    const leaves = [computeLeafHash(emergencyEntry)];
    const root = bytesToHex(computeMerkleRootFromLeaves(leaves));
    const auditPath = computeAuditPathFromLeaves(leaves, 0);

    // Fails before 48h (e.g. after 24h)
    const before48h = verifyInclusion(
      emergencyEntry,
      { root, auditPath },
      approvedAt + 24 * 3600,
    );
    expect(before48h.ok).toBe(false);
    expect(before48h.reviewWindowPassed).toBe(false);

    // Passes after 48h with all 7/7 reviewers
    const after48h = verifyInclusion(
      emergencyEntry,
      { root, auditPath },
      approvedAt + 49 * 3600,
    );
    expect(after48h.ok).toBe(true);
    expect(after48h.builderCount).toBe(3);
    expect(after48h.reviewerCount).toBe(7);
    expect(after48h.reviewWindowPassed).toBe(true);
  });
});

describe("5-of-7 Verifier Quorum Tickets", () => {
  it("exposes 7 independent verifiers with threshold k = 5", () => {
    const set = getVerifierSet();
    expect(set.threshold).toBe(5);
    expect(set.total).toBe(7);
    expect(set.verifiers).toHaveLength(7);
  });

  it("passes with 5-of-7 signatures and fails with 4-of-7, forged signature, or suspended status", () => {
    const baseParams = {
      nodeId: "sim-1",
      chipId: "ab".repeat(64),
      nodeIdentityPk: "cd".repeat(32),
      epoch: 10,
      status: "full" as const,
      weight: 10000,
    };

    // Passes with 5-of-7 signatures
    const validTicket = issueQuorumTicket({ ...baseParams, signerCount: 5 });
    const passRes = verifyQuorumTicket(validTicket);
    expect(passRes.ok).toBe(true);
    expect(passRes.validSignatures).toBe(5);
    expect(passRes.required).toBe(5);

    // Fails with 4-of-7 signatures
    const fourOfSeven = issueQuorumTicket({ ...baseParams, signerCount: 4 });
    const failFour = verifyQuorumTicket(fourOfSeven);
    expect(failFour.ok).toBe(false);
    expect(failFour.validSignatures).toBe(4);

    // Fails if a signature is forged
    const forgedTicket = {
      ...validTicket,
      signatures: validTicket.signatures.map((sig, i) =>
        i === 0 ? { ...sig, signature: "00".repeat(64) } : sig,
      ),
    };
    const failForged = verifyQuorumTicket(forgedTicket);
    expect(failForged.ok).toBe(false);

    // Fails if status === "suspended"
    const suspendedTicket = issueQuorumTicket({
      ...baseParams,
      status: "suspended",
      weight: 5000,
      signerCount: 6,
    });
    const failSuspended = verifyQuorumTicket(suspendedTicket);
    expect(failSuspended.ok).toBe(false);
  });
});
