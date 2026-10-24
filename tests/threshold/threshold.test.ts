import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  authorizeThresholdKeyRelease,
  combineShares,
  splitSecret,
} from "@/lib/threshold/shamir";

describe("Shamir k-of-n Threshold Key Release", () => {
  const sampleSecretHex = bytesToHex(
    sha256(utf8ToBytes("drouter:test-secret-32-byte-master-key"))
  );

  it("reconstructs the exact 32-byte secret from any 3 of 5 shares ([1,2,3], [2,4,5], [1,3,5])", () => {
    const k = 3;
    const n = 5;
    const shares = splitSecret(sampleSecretHex, k, n, "deadbeefcafebabe");

    expect(shares).toHaveLength(5);
    for (const share of shares) {
      expect(share.yHex).toMatch(/^[0-9a-f]{64}$/);
      const expectedCommitment = bytesToHex(
        sha256(utf8ToBytes(`${share.index}:${share.yHex}`))
      );
      expect(share.commitmentHex).toBe(expectedCommitment);
    }

    const subset123 = [shares[0], shares[1], shares[2]];
    const subset245 = [shares[1], shares[3], shares[4]];
    const subset135 = [shares[0], shares[2], shares[4]];

    expect(combineShares(subset123, k)).toBe(sampleSecretHex);
    expect(combineShares(subset245, k)).toBe(sampleSecretHex);
    expect(combineShares(subset135, k)).toBe(sampleSecretHex);
  });

  it("fails to reconstruct the secret when given fewer than k=3 shares (e.g. 2 shares)", () => {
    const k = 3;
    const n = 5;
    const shares = splitSecret(sampleSecretHex, k, n, "deadbeefcafebabe");

    const twoSharesA = [shares[0], shares[1]];
    const twoSharesB = [shares[1], shares[4]];

    expect(combineShares(twoSharesA, k)).not.toBe(sampleSecretHex);
    expect(combineShares(twoSharesB, k)).not.toBe(sampleSecretHex);
    expect(combineShares([shares[0]], k)).not.toBe(sampleSecretHex);
  });

  it("releases and reconstructs the 32-byte key when all regional checker criteria pass", () => {
    const result = authorizeThresholdKeyRelease({
      sessionId: "session-alpha-01",
      chipId: "H200-SXM-NV-0042",
      measurementOk: true,
      registryActive: true,
      notFlagged: true,
      k: 3,
      n: 5,
    });

    expect(result.released).toBe(true);
    expect(result.k).toBe(3);
    expect(result.n).toBe(5);
    expect(result.approvals).toHaveLength(5);
    expect(result.approvals.map((a) => a.checkerId)).toEqual([
      "checker-zurich",
      "checker-frankfurt",
      "checker-virginia",
      "checker-tokyo",
      "checker-reykjavik",
    ]);
    expect(result.approvals.every((a) => a.approved && a.share !== undefined)).toBe(
      true
    );
    expect(result.reconstructedKeyHex).toMatch(/^[0-9a-f]{64}$/);

    // Any 3 of the released shares also reconstruct the same key
    const releasedShares = result.approvals.map((a) => a.share!);
    expect(
      combineShares(
        [releasedShares[0], releasedShares[2], releasedShares[4]],
        3
      )
    ).toBe(result.reconstructedKeyHex);
  });

  it("refuses key release when measurementOk is false or notFlagged is false", () => {
    const badMeasurement = authorizeThresholdKeyRelease({
      sessionId: "session-alpha-01",
      chipId: "H200-SXM-NV-0042",
      measurementOk: false,
      registryActive: true,
      notFlagged: true,
      k: 3,
      n: 5,
    });

    expect(badMeasurement.released).toBe(false);
    expect(badMeasurement.reconstructedKeyHex).toBeUndefined();
    expect(badMeasurement.approvals.every((a) => !a.approved && !a.share)).toBe(
      true
    );
    expect(badMeasurement.reason).toContain("measurementOk=false");

    const flaggedNode = authorizeThresholdKeyRelease({
      sessionId: "session-alpha-01",
      chipId: "H200-SXM-NV-0042",
      measurementOk: true,
      registryActive: true,
      notFlagged: false,
      k: 3,
      n: 5,
    });

    expect(flaggedNode.released).toBe(false);
    expect(flaggedNode.reconstructedKeyHex).toBeUndefined();
    expect(flaggedNode.approvals.every((a) => !a.approved && !a.share)).toBe(
      true
    );
    expect(flaggedNode.reason).toContain("notFlagged=false");
  });
});
