import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/server", () => ({
  connection: async () => {},
}));

import { GET as getTransparencyRoute, POST as postTransparencyRoute } from "@/app/api/transparency/route";
import {
  coarsenEpochSecToHour,
  computeAuditPathFromLeaves,
  computeLeafHash,
  computeMerkleRootFromLeaves,
  computeNodeHash,
  computeRawLeafHash,
  createSignedTransparencyEntry,
  getOperatorPublicKey,
  getTransparencyLog,
  proveConsistency,
  proveConsistencyFromLeaves,
  proveInclusion,
  signTreeHead,
  verifyConsistencyProofClient,
  verifyInclusion,
  verifyInclusionProofClient,
  verifySignedTreeHeadClient,
  verifyTransparencyProofBundleClient,
} from "@/lib/transparency/log";
import {
  getVerifierSet,
  issueQuorumTicket,
  verifyQuorumTicket,
} from "@/lib/transparency/quorum";
import {
  appendVerificationEventToLog,
  getPersistedTransparencyLog,
  resetAnchorRateLimitState,
  setAnchorReceiptOverride,
  setTransparencyCollectionOverride,
  type TransparencyCollectionLike,
} from "@/lib/transparency/store";

function createMockCollection(): {
  col: TransparencyCollectionLike;
  docs: Record<string, unknown>[];
} {
  const docs: Record<string, unknown>[] = [];

  const matches = (doc: Record<string, unknown>, filter: Record<string, unknown>): boolean => {
    return Object.entries(filter).every(([k, v]) => doc[k] === v);
  };

  const col: TransparencyCollectionLike = {
    find(filter: Record<string, unknown>) {
      const filtered = docs.filter((d) => matches(d, filter));
      return {
        sort(spec: Record<string, 1 | -1>) {
          const [field, dir] = Object.entries(spec)[0] ?? ["index", 1];
          const sorted = [...filtered].sort((a, b) => {
            const av = Number(a[field] ?? 0);
            const bv = Number(b[field] ?? 0);
            return dir === -1 ? bv - av : av - bv;
          });
          return {
            async toArray() {
              return sorted.map((d) => ({ ...d }));
            },
            limit(n: number) {
              return {
                async toArray() {
                  return sorted.slice(0, n).map((d) => ({ ...d }));
                },
              };
            },
          };
        },
        async toArray() {
          return filtered.map((d) => ({ ...d }));
        },
      };
    },
    async findOne(filter: Record<string, unknown>) {
      const found = docs.find((d) => matches(d, filter));
      return found ? { ...found } : null;
    },
    async insertOne(doc: Record<string, unknown>) {
      docs.push({ ...doc });
      return { acknowledged: true };
    },
    async insertMany(newDocs: Record<string, unknown>[]) {
      for (const d of newDocs) docs.push({ ...d });
      return { acknowledged: true };
    },
    async updateOne(filter: Record<string, unknown>, update: Record<string, unknown>, options?: Record<string, unknown>) {
      const idx = docs.findIndex((d) => matches(d, filter));
      const setFields = (update.$set ?? {}) as Record<string, unknown>;
      if (idx >= 0) {
        docs[idx] = { ...docs[idx], ...setFields };
      } else if (options?.upsert) {
        docs.push({ ...filter, ...setFields });
      }
      return { acknowledged: true };
    },
    async countDocuments(filter: Record<string, unknown> = {}) {
      return docs.filter((d) => matches(d, filter)).length;
    },
  };

  return { col, docs };
}

afterEach(() => {
  setTransparencyCollectionOverride(null);
  setAnchorReceiptOverride(null);
  resetAnchorRateLimitState();
});

describe("RFC 6962 Standard Test Vectors & Client Proof Verifiers", () => {
  it("matches official RFC 6962 / Certificate Transparency SHA-256 Merkle tree test vectors", () => {
    // 1. Empty tree root = SHA-256("")
    const emptyRoot = bytesToHex(computeMerkleRootFromLeaves([]));
    expect(emptyRoot).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 2. Single leaf of empty bytes: MTH({""}) = SHA-256(0x00)
    const leaf0 = computeRawLeafHash(new Uint8Array(0));
    expect(bytesToHex(leaf0)).toBe("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    expect(bytesToHex(computeMerkleRootFromLeaves([leaf0]))).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );

    // 3. Standard 7-leaf RFC 6962 tree where D[i] = utf8("leaf-i")
    const leaves = Array.from({ length: 7 }, (_, i) => computeRawLeafHash(utf8ToBytes(`leaf-${i}`)));

    // Verify manual RFC 6962 Section 2.1 structure for 4 leaves and 7 leaves:
    // MTH(D[4]) = SHA256(0x01 || SHA256(0x01 || L0 || L1) || SHA256(0x01 || L2 || L3))
    const h01 = computeNodeHash(leaves[0], leaves[1]);
    const h23 = computeNodeHash(leaves[2], leaves[3]);
    const h0123 = computeNodeHash(h01, h23);
    expect(bytesToHex(computeMerkleRootFromLeaves(leaves.slice(0, 4)))).toBe(bytesToHex(h0123));

    const h45 = computeNodeHash(leaves[4], leaves[5]);
    const h456 = computeNodeHash(h45, leaves[6]);
    const h0to6 = computeNodeHash(h0123, h456);
    const root7 = bytesToHex(computeMerkleRootFromLeaves(leaves));
    expect(root7).toBe(bytesToHex(h0to6));

    // Verify inclusion proofs across all 7 leaves using pure client verifier
    for (let i = 0; i < leaves.length; i++) {
      const auditPath = computeAuditPathFromLeaves(leaves, i);
      const res = verifyInclusionProofClient({
        leafHash: bytesToHex(leaves[i]),
        root: root7,
        auditPath,
        leafIndex: i,
        treeSize: leaves.length,
      });
      expect(res.ok).toBe(true);
      expect(res.computedRoot).toBe(root7);
    }

    // Verify consistency proofs for every pair (firstSize, secondSize) in 0..7
    for (let second = 1; second <= leaves.length; second++) {
      for (let first = 0; first <= second; first++) {
        const cProof = proveConsistencyFromLeaves(leaves, first, second);
        const cVerdict = verifyConsistencyProofClient(cProof);
        expect(cVerdict.ok).toBe(true);

        if (first > 0 && first < second) {
          // Tampering with consistency path or secondRoot must fail
          const badRoot = verifyConsistencyProofClient({
            ...cProof,
            secondRoot: "aa".repeat(32),
          });
          expect(badRoot.ok).toBe(false);

          const badPath = verifyConsistencyProofClient({
            ...cProof,
            consistencyPath: cProof.consistencyPath.map((h, idx) => (idx === 0 ? "bb".repeat(32) : h)),
          });
          expect(badPath.ok).toBe(false);
        }
      }
    }
  });

  it("signs and verifies operator tree heads (STH) with hour-coarsened timestamps", () => {
    const rawRoot = bytesToHex(sha256(utf8ToBytes("test-merkle-root")));
    const uncoarsenedTime = 1761330123; // Not divisible by 3600
    const sth = signTreeHead({
      treeSize: 5,
      rootHash: rawRoot,
      timestampSec: uncoarsenedTime,
    });

    expect(sth.timestampSec).toBe(coarsenEpochSecToHour(uncoarsenedTime));
    expect(sth.timestampSec % 3600).toBe(0);
    expect(sth.operatorPublicKey).toBe(getOperatorPublicKey());

    const verified = verifySignedTreeHeadClient(sth, getOperatorPublicKey());
    expect(verified.ok).toBe(true);

    // Rejects tampered treeSize
    expect(verifySignedTreeHeadClient({ ...sth, treeSize: 6 }, getOperatorPublicKey()).ok).toBe(false);
    // Rejects uncoarsened timestamp
    expect(verifySignedTreeHeadClient({ ...sth, timestampSec: sth.timestampSec + 15 }, getOperatorPublicKey()).ok).toBe(
      false,
    );
    // Rejects wrong operator public key
    expect(verifySignedTreeHeadClient(sth, "11".repeat(32)).ok).toBe(false);
  });
});

describe("Software Transparency Log (RFC 6962 Merkle tree & signatures)", () => {
  it("verifies Merkle inclusion proof and consistency proof for each approved release entry", () => {
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
      expect(proof.leafIndex).toBe(i);
      expect(proof.treeSize).toBe(3);
      const res = verifyInclusion(entry, proof);
      expect(res.ok).toBe(true);
      expect(res.builderCount).toBe(3);
      expect(res.reviewerCount).toBeGreaterThanOrEqual(4);
      expect(res.reviewWindowPassed).toBe(true);
      expect(verifyInclusionProofClient(proof).ok).toBe(true);
    }

    const consistency = proveConsistency(1, 3);
    expect(verifyConsistencyProofClient(consistency).ok).toBe(true);
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
    expect(verifyInclusionProofClient(tamperedProof).ok).toBe(false);
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

describe("MongoDB Persistence (Mocked `transparency_log`), Hourly Arc Anchoring & API Route", () => {
  it("persists genesis leaves, appends verification events with coarse timestamps, verifies bundle, and rate-limits Arc anchoring to at most hourly", async () => {
    const { col, docs } = createMockCollection();
    setTransparencyCollectionOverride(col);

    const anchorCalls: string[] = [];
    setAnchorReceiptOverride(async (receiptHash) => {
      anchorCalls.push(receiptHash);
      return `0x${"ab".repeat(32)}`;
    });

    const t0 = 1760000123; // Will be coarsened to 1760000123 - (1760000123 % 3600) = 1759996800
    const initial = await getPersistedTransparencyLog({ nowSec: t0, anchorIfDue: true });
    expect(initial.persisted).toBe(true);
    expect(initial.events).toHaveLength(3);
    expect(initial.signedTreeHead.treeSize).toBe(3);
    expect(initial.signedTreeHead.timestampSec % 3600).toBe(0);
    expect(initial.signedTreeHead.anchorTx).toBe(`0x${"ab".repeat(32)}`);
    expect(anchorCalls).toHaveLength(1);

    // Appending a new verification event within the same hour must NOT trigger a second Arc transaction
    const appended1 = await appendVerificationEventToLog({
      nodeId: "tinfoil-router",
      nodeKind: "tinfoil",
      ok: true,
      measurement: "aa".repeat(48),
      evidenceHash: "bb".repeat(32),
      enclaveHost: "router-0.tinfoil.sh",
      timestampSec: t0 + 600, // +10 minutes (< 1 hour)
      anchorOnArc: true,
    });

    expect(appended1.persisted).toBe(true);
    expect(appended1.event.index).toBe(3);
    expect(appended1.event.epochHourSec % 3600).toBe(0);
    expect(appended1.signedTreeHead.treeSize).toBe(4);
    expect(anchorCalls).toHaveLength(1); // Still 1 because <1h elapsed

    const bundleVerdict = verifyTransparencyProofBundleClient({
      sth: appended1.signedTreeHead,
      expectedOperatorPublicKey: getOperatorPublicKey(),
      inclusionProof: appended1.inclusionProof,
      consistencyProof: appended1.consistencyProof,
    });
    expect(bundleVerdict.ok).toBe(true);
    expect(bundleVerdict.sthVerified).toBe(true);
    expect(bundleVerdict.inclusionVerified).toBe(true);
    expect(bundleVerdict.consistencyVerified).toBe(true);

    // Appending after >1 hour triggers a new Arc anchor transaction
    const appended2 = await appendVerificationEventToLog({
      nodeId: "sim-1",
      nodeKind: "sim",
      ok: true,
      measurement: "cc".repeat(48),
      evidenceHash: "dd".repeat(32),
      timestampSec: t0 + 3700, // >1 hour later
      anchorOnArc: true,
    });
    expect(appended2.signedTreeHead.treeSize).toBe(5);
    expect(anchorCalls).toHaveLength(2);
    expect(docs.filter((d) => d.docType === "leaf")).toHaveLength(5);
  });

  it("serves GET and POST /api/transparency with quorumSimulated: true, operatorPublicKey, signedTreeHead, and proofs", async () => {
    const { col } = createMockCollection();
    setTransparencyCollectionOverride(col);

    const getRes = await getTransparencyRoute(new Request("http://localhost/api/transparency?first=1&second=3"));
    expect(getRes.status).toBe(200);
    const body = await getRes.json();

    expect(body.quorumSimulated).toBe(true);
    expect(body.operatorPublicKey).toBe(getOperatorPublicKey());
    expect(body.verifierSet.quorumSimulated).toBe(true);
    expect(body.verifierSet.operatorPublicKey).toBe(getOperatorPublicKey());
    expect(verifySignedTreeHeadClient(body.signedTreeHead, body.operatorPublicKey).ok).toBe(true);
    expect(verifyConsistencyProofClient(body.consistencyProof).ok).toBe(true);
    expect(body.tickets["sim-1"].quorumSimulated).toBe(true);
    expect(body.tickets["sim-1"].operatorPublicKey).toBe(getOperatorPublicKey());
    expect(body.tickets["sim-1"].chipId.startsWith("73696d2d636869702d30303030303030")).toBe(true);

    const postRes = await postTransparencyRoute(
      new Request("http://localhost/api/transparency", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          nodeId: "tinfoil-router",
          nodeKind: "tinfoil",
          ok: true,
          measurement: "12".repeat(48),
          evidenceHash: "34".repeat(32),
          enclaveHost: "router-0.tinfoil.sh",
        }),
      }),
    );
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);
    expect(postBody.quorumSimulated).toBe(true);
    expect(postBody.operatorPublicKey).toBe(getOperatorPublicKey());
    expect(postBody.event.index).toBe(3);
    expect(
      verifyTransparencyProofBundleClient({
        sth: postBody.signedTreeHead,
        expectedOperatorPublicKey: postBody.operatorPublicKey,
        inclusionProof: postBody.inclusionProof,
        consistencyProof: postBody.consistencyProof,
      }).ok,
    ).toBe(true);
  });
});

describe("Simulated 5-of-7 Verifier Quorum Tickets", () => {
  it("labels the 7-verifier set with quorumSimulated: true, operatorPublicKey, and non-deceptive names", () => {
    const set = getVerifierSet();
    expect(set.threshold).toBe(5);
    expect(set.total).toBe(7);
    expect(set.quorumSimulated).toBe(true);
    expect(set.operatorPublicKey).toBe(getOperatorPublicKey());
    expect(set.verifiers).toHaveLength(7);
    for (const v of set.verifiers) {
      expect(v.simulated).toBe(true);
      expect(v.name).toContain("Simulated Verifier");
    }
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
    expect(validTicket.quorumSimulated).toBe(true);
    expect(validTicket.operatorPublicKey).toBe(getOperatorPublicKey());
    const passRes = verifyQuorumTicket(validTicket);
    expect(passRes.ok).toBe(true);
    expect(passRes.validSignatures).toBe(5);
    expect(passRes.required).toBe(5);
    expect(passRes.quorumSimulated).toBe(true);
    expect(passRes.operatorPublicKey).toBe(getOperatorPublicKey());

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
