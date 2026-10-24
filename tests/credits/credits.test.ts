import { describe, expect, it } from "vitest";
import {
  blindToken,
  deriveIssuerKey,
  getPublicKey,
  nullifierFor,
  signBlinded,
  unblindSignature,
  verifyTokenSignature,
} from "@/lib/credits/blind";
import {
  issuerPublicInfo,
  ledgerStats,
  mintBlindedBatch,
  redeemBatch,
  spendToken,
} from "@/lib/credits/ledger";
import type { BlindCreditToken } from "@/lib/types";

const TEST_SEED =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

describe("Subsystem 1: Unlinkable Blind-Signed Credits (Spec §7)", () => {
  it("derives identical deterministic 1024-bit RSA keypair across calls", () => {
    const k1 = deriveIssuerKey(TEST_SEED);
    const k2 = deriveIssuerKey(TEST_SEED);
    expect(k1.n).toBe(k2.n);
    expect(k1.e).toBe("010001");
    expect(k1.d).toBe(k2.d);
    expect(k1.n.length).toBeGreaterThanOrEqual(254);

    const kOther = deriveIssuerKey("ff".repeat(32));
    expect(kOther.n).not.toBe(k1.n);
  });

  it("completes blind -> signBlinded -> unblind -> verifyTokenSignature round-trip and varies blindedHex with rHex", () => {
    const pub = getPublicKey(TEST_SEED);
    const tokenHex = "deadbeef".repeat(8);
    const denomination = 5;

    const b1 = blindToken(tokenHex, denomination, pub, "03".repeat(32));
    const b2 = blindToken(tokenHex, denomination, pub, "07".repeat(32));
    expect(b1.blindedHex).not.toBe(b2.blindedHex);

    const blindSig = signBlinded(b1.blindedHex, denomination, TEST_SEED);
    const unblindedSig = unblindSignature(blindSig, b1.rHex, pub);

    const token: BlindCreditToken = {
      token: tokenHex,
      signature: unblindedSig,
      denomination,
    };
    expect(verifyTokenSignature(token, pub)).toBe(true);
  });

  it("rejects forged signatures and denomination tampering", () => {
    const pub = getPublicKey(TEST_SEED);
    const tokenHex = "cafebabe".repeat(8);
    const { blindedHex, rHex } = blindToken(tokenHex, 1, pub);
    const blindSig = signBlinded(blindedHex, 1, TEST_SEED);
    const signature = unblindSignature(blindSig, rHex, pub);

    // Tampered denomination (1 -> 20)
    expect(
      verifyTokenSignature(
        { token: tokenHex, signature, denomination: 20 },
        pub
      )
    ).toBe(false);

    // Forged signature
    expect(
      verifyTokenSignature(
        { token: tokenHex, signature: "1234567890abcdef", denomination: 1 },
        pub
      )
    ).toBe(false);

    // Tampered token secret
    expect(
      verifyTokenSignature(
        { token: "00".repeat(32), signature, denomination: 1 },
        pub
      )
    ).toBe(false);
  });

  it("enforces double-spend protection with HTTP 409 on nullifier reuse", async () => {
    const pub = issuerPublicInfo();
    const tokenHex = "11223344556677889900aabbccddeeff".repeat(2);
    const { blindedHex, rHex } = blindToken(tokenHex, 5, pub);
    const { signatures } = mintBlindedBatch([blindedHex], 5);
    const signature = unblindSignature(signatures[0], rHex, pub);

    const creditToken: BlindCreditToken = {
      token: tokenHex,
      signature,
      denomination: 5,
    };

    const firstSpend = await spendToken(creditToken, "node-alpha");
    expect(firstSpend.ok).toBe(true);
    if (firstSpend.ok) {
      expect(firstSpend.nullifier).toBe(nullifierFor(tokenHex));
    }

    const secondSpend = await spendToken(creditToken, "node-beta");
    expect(secondSpend.ok).toBe(false);
    if (!secondSpend.ok) {
      expect(secondSpend.status).toBe(409);
      expect(secondSpend.error).toContain("Double-spend rejected");
    }
  });

  it("aggregates unredeemed tokens in redeemBatch and zeroes unredeemedCount", async () => {
    const pub = issuerPublicInfo();
    const t1Hex = "aa01".repeat(16);
    const t2Hex = "bb02".repeat(16);

    const b1 = blindToken(t1Hex, 1, pub);
    const b2 = blindToken(t2Hex, 20, pub);

    const { signatures: sigs1 } = mintBlindedBatch([b1.blindedHex], 1);
    const { signatures: sigs2 } = mintBlindedBatch([b2.blindedHex], 20);

    const tok1: BlindCreditToken = {
      token: t1Hex,
      signature: unblindSignature(sigs1[0], b1.rHex, pub),
      denomination: 1,
    };
    const tok2: BlindCreditToken = {
      token: t2Hex,
      signature: unblindSignature(sigs2[0], b2.rHex, pub),
      denomination: 20,
    };

    const s1 = await spendToken(tok1, "node-batch");
    const s2 = await spendToken(tok2, "node-batch");
    expect(s1.ok).toBe(true);
    expect(s2.ok).toBe(true);
    expect(ledgerStats().unredeemedCount).toBeGreaterThanOrEqual(2);

    const batch = await redeemBatch();
    expect(batch.redeemedCount).toBeGreaterThanOrEqual(2);
    expect(batch.totalCredits).toBeGreaterThanOrEqual(21);
    expect(batch.batchHash).toMatch(/^[0-9a-f]{64}$/);
    expect(ledgerStats().unredeemedCount).toBe(0);
  });
});
