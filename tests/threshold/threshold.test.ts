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

  it("fails to reconstruct the secret when given fewer than k=3 shares (throws on under-threshold)", () => {
    const k = 3;
    const n = 5;
    const shares = splitSecret(sampleSecretHex, k, n, "deadbeefcafebabe");

    const twoSharesA = [shares[0], shares[1]];
    const twoSharesB = [shares[1], shares[4]];

    expect(() => combineShares(twoSharesA, k)).toThrow(/Insufficient shares/i);
    expect(() => combineShares(twoSharesB, k)).toThrow(/Insufficient shares/i);
    expect(() => combineShares([shares[0]], k)).toThrow(/Insufficient shares/i);
    expect(() => combineShares([], k)).toThrow(/Insufficient shares/i);
  });

  it("rejects secrets >= SHAMIR_PRIME, x=0 shares, negative indices, duplicate x indices, and tampered commitments", async () => {
    const { SHAMIR_PRIME, verifyShareCommitment } = await import("@/lib/threshold/shamir");
    const shares = splitSecret(sampleSecretHex, 3, 5, "deadbeefcafebabe");

    for (const s of shares) {
      expect(verifyShareCommitment(s)).toBe(true);
    }

    // Secret >= SHAMIR_PRIME must throw rather than silently reducing mod P
    const primeHex = SHAMIR_PRIME.toString(16).padStart(64, "0");
    const maxUint256Hex = "f".repeat(64);
    expect(() => splitSecret(primeHex, 3, 5)).toThrow(/exceeds GF\(P\)/i);
    expect(() => splitSecret(maxUint256Hex, 3, 5)).toThrow(/exceeds GF\(P\)/i);

    // Share with x=0 or negative index must throw
    expect(() =>
      combineShares([{ index: 0, yHex: shares[0].yHex }, shares[1], shares[2]], 3)
    ).toThrow(/Invalid share index/i);
    expect(() =>
      combineShares([{ index: -1, yHex: shares[0].yHex }, shares[1], shares[2]], 3)
    ).toThrow(/Invalid share index/i);

    // Duplicate x index must throw
    expect(() =>
      combineShares([shares[0], shares[0], shares[2]], 3)
    ).toThrow(/Duplicate share index/i);

    // Tampered commitmentHex must throw
    expect(() =>
      combineShares(
        [
          { ...shares[0], commitmentHex: "00".repeat(32) },
          shares[1],
          shares[2],
        ],
        3
      )
    ).toThrow(/commitment mismatch/i);

    // Fuzz loop: 250 random secrets and random k-of-n subsets
    for (let trial = 0; trial < 250; trial++) {
      const randBytes = new Uint8Array(32);
      crypto.getRandomValues(randBytes);
      randBytes[0] &= 0x7f; // strictly < SHAMIR_PRIME
      const secHex = bytesToHex(randBytes);
      const s = splitSecret(secHex, 3, 5);
      expect(combineShares([s[0], s[2], s[4]], 3)).toBe(secHex);
      expect(combineShares([s[1], s[3], s[4]], 3)).toBe(secHex);
    }
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
