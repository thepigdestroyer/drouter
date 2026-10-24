import { generatePrimeSync } from "node:crypto";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { HDKey, HARDENED_OFFSET } from "@scure/bip32";
import { privateKeyToAccount } from "viem/accounts";
import { beforeEach, describe, expect, it } from "vitest";
import { POST as postClaimRoute } from "@/app/api/credits/claim/route";
import { POST as postInvoiceRoute } from "@/app/api/credits/invoice/route";
import { GET as getCreditsRoute, POST as postCreditsRoute } from "@/app/api/credits/route";
import { POST as postSpendRoute } from "@/app/api/credits/spend/route";
import { POST as postRelay } from "@/app/api/relay/v1/[...path]/route";
import { POST as postRelayHop } from "@/app/api/relay/[relayId]/v1/[...path]/route";
import {
  blindToken,
  deriveIssuerKey,
  formatCreditHeader,
  getPublicKey,
  nullifierFor,
  parseCreditHeader,
  signBlinded,
  unblindSignature,
  verifyTokenSignature,
} from "@/lib/credits/blind";
import {
  claimPaidCredits,
  clearStoredCredits,
  generateClaimSecret,
  getStoredCredits,
  hashClaimSecret,
  requestCreditInvoice,
  storeCreditTokens,
  storedCreditBalance,
  takeCreditHeader,
} from "@/lib/credits/client";
import {
  ARC_CREDIT_CHAIN_ID,
  ARC_USDC_ADDRESS,
  ARC_USDC_DECIMALS,
  FIXED_INVOICE_AMOUNTS_USDC,
  FIXED_INVOICE_UNITS,
  USDC_UNITS_PER_CREDIT,
  claimCreditInvoice,
  coarsenExpiryToHourMs,
  coarsenTimestampToHourMs,
  deriveDepositAddress,
  getStoredInvoiceRecordForTests,
  getStoredPaymentRecordForTests,
  issuerPublicInfo,
  ledgerStats,
  mintBlindedBatch,
  redeemBatch,
  resetCreditsLedgerForTests,
  setCreditPaymentVerifierDepsForTests,
  spendToken,
} from "@/lib/credits/ledger";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import type { BlindCreditToken, Hex } from "@/lib/types";

const TEST_SEED =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

describe("Subsystem 1: Unlinkable Blind-Signed Credits & One-Time Deposit Invoices (D5)", () => {
  beforeEach(() => {
    resetCreditsLedgerForTests();
    resetRateLimitStateForTests();
    clearStoredCredits();
  });

  it("derives identical deterministic 1024-bit RSA keypair across calls and reports keyBits", () => {
    const savedPq = process.env.CREDITS_ISSUER_RSA_PQ;
    delete process.env.CREDITS_ISSUER_RSA_PQ;
    try {
      const k1 = deriveIssuerKey(TEST_SEED);
      const k2 = deriveIssuerKey(TEST_SEED);
      expect(k1.n).toBe(k2.n);
      expect(k1.e).toBe("010001");
      expect(k1.d).toBe(k2.d);
      expect(k1.keyBits).toBe(1024);
      expect(k1.n.length).toBeGreaterThanOrEqual(254);

      const kOther = deriveIssuerKey("ff".repeat(32));
      expect(kOther.n).not.toBe(k1.n);
    } finally {
      if (savedPq !== undefined) process.env.CREDITS_ISSUER_RSA_PQ = savedPq;
    }
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

  it("uses a 2048-bit issuer key from CREDITS_ISSUER_RSA_PQ, reports keyBits=2048, and completes the blind round-trip", () => {
    const exps = [BigInt(65537), BigInt(65539), BigInt(65543)];
    const usable = (p: bigint) => exps.every((e) => (p - BigInt(1)) % e !== BigInt(0));
    let p = BigInt(0);
    let q = BigInt(0);
    for (;;) {
      p = generatePrimeSync(1024, { bigint: true });
      q = generatePrimeSync(1024, { bigint: true });
      if (p !== q && usable(p) && usable(q) && (p * q).toString(2).length === 2048) break;
    }
    const savedPq = process.env.CREDITS_ISSUER_RSA_PQ;
    process.env.CREDITS_ISSUER_RSA_PQ = `${p.toString(16)}:${q.toString(16)}`;
    try {
      const pub = getPublicKey(TEST_SEED);
      expect(pub.keyBits).toBe(2048);
      expect(BigInt("0x" + pub.n).toString(2).length).toBe(2048);
      for (const denomination of [1, 5, 20]) {
        const tokenHex = "a1b2c3d4".repeat(8);
        const { blindedHex, rHex } = blindToken(tokenHex, denomination, pub);
        const signature = unblindSignature(signBlinded(blindedHex, denomination, TEST_SEED), rHex, pub);
        expect(verifyTokenSignature({ token: tokenHex, signature, denomination }, pub)).toBe(true);
        expect(verifyTokenSignature({ token: tokenHex, signature, denomination: denomination === 1 ? 20 : 1 }, pub)).toBe(false);
      }
    } finally {
      if (savedPq !== undefined) process.env.CREDITS_ISSUER_RSA_PQ = savedPq;
      else delete process.env.CREDITS_ISSUER_RSA_PQ;
    }
  });

  it("rejects forged signatures and denomination tampering", () => {
    const pub = getPublicKey(TEST_SEED);
    const tokenHex = "cafebabe".repeat(8);
    const { blindedHex, rHex } = blindToken(tokenHex, 1, pub);
    const blindSig = signBlinded(blindedHex, 1, TEST_SEED);
    const signature = unblindSignature(blindSig, rHex, pub);

    expect(
      verifyTokenSignature(
        { token: tokenHex, signature, denomination: 20 },
        pub
      )
    ).toBe(false);

    expect(
      verifyTokenSignature(
        { token: tokenHex, signature: "1234567890abcdef", denomination: 1 },
        pub
      )
    ).toBe(false);

    expect(
      verifyTokenSignature(
        { token: "00".repeat(32), signature, denomination: 1 },
        pub
      )
    ).toBe(false);
  });

  it("enforces double-spend protection with HTTP 409 on nullifier reuse and coarsens timestamps to UTC hour", async () => {
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
      expect(firstSpend.denomination).toBe(5);
    }

    const secondSpend = await spendToken(creditToken, "node-beta");
    expect(secondSpend.ok).toBe(false);
    if (!secondSpend.ok) {
      expect(secondSpend.status).toBe(409);
      expect(secondSpend.error).toContain("Double-spend rejected");
    }

    const sampleTime = 1_760_001_234_567;
    const coarsened = coarsenTimestampToHourMs(sampleTime);
    expect(coarsened % 3_600_000).toBe(0);
    const coarsenedExpiry = coarsenExpiryToHourMs(sampleTime);
    expect(coarsenedExpiry % 3_600_000).toBe(0);
    expect(coarsenedExpiry - sampleTime).toBeGreaterThanOrEqual(3_600_000);
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
    expect(batch.timestamp % 3_600_000).toBe(0);
    expect(ledgerStats().unredeemedCount).toBe(0);
  });

  it("defeats blind-signature denomination escalation and concurrent double-spend races", async () => {
    const pub = issuerPublicInfo();
    const attackerTokenHex = "fedcba9876543210".repeat(4);

    const blindedAs20 = blindToken(attackerTokenHex, 20, pub);
    const { signatures } = mintBlindedBatch([blindedAs20.blindedHex], 1);
    const unblindedForgedSig = unblindSignature(signatures[0], blindedAs20.rHex, pub);

    expect(
      verifyTokenSignature(
        { token: attackerTokenHex, signature: unblindedForgedSig, denomination: 20 },
        pub
      )
    ).toBe(false);
    expect(
      verifyTokenSignature(
        { token: attackerTokenHex, signature: unblindedForgedSig, denomination: 1 },
        pub
      )
    ).toBe(false);

    const raceTokenHex = "99887766554433221100aabbccddeeff".repeat(2);
    const bRace = blindToken(raceTokenHex, 5, pub);
    const { signatures: raceSigs } = mintBlindedBatch([bRace.blindedHex], 5);
    const validRaceToken: BlindCreditToken = {
      token: raceTokenHex,
      signature: unblindSignature(raceSigs[0], bRace.rHex, pub),
      denomination: 5,
    };

    const raceResults = await Promise.all(
      Array.from({ length: 10 }, (_, idx) => spendToken(validRaceToken, `node-${idx}`))
    );
    const successes = raceResults.filter((r) => r.ok);
    const rejections = raceResults.filter((r) => !r.ok && r.status === 409);
    expect(successes).toHaveLength(1);
    expect(rejections).toHaveLength(9);
  });

  it("implements interface I2 takeCreditHeader() by popping one token from storage or returning null when empty", async () => {
    expect(await takeCreditHeader()).toBeNull();

    const pub = issuerPublicInfo();
    const t1Hex = "0123456789abcdef".repeat(4);
    const t2Hex = "fedcba9876543210".repeat(4);
    const b1 = blindToken(t1Hex, 5, pub);
    const b2 = blindToken(t2Hex, 1, pub);
    const sig1 = unblindSignature(mintBlindedBatch([b1.blindedHex], 5).signatures[0], b1.rHex, pub);
    const sig2 = unblindSignature(mintBlindedBatch([b2.blindedHex], 1).signatures[0], b2.rHex, pub);

    storeCreditTokens([
      { token: t1Hex, signature: sig1, denomination: 5 },
      { token: t2Hex, signature: sig2, denomination: 1 },
    ]);
    expect(storedCreditBalance()).toBe(6);
    expect(getStoredCredits()).toHaveLength(2);

    const h1 = await takeCreditHeader();
    expect(h1).not.toBeNull();
    const parsed1 = parseCreditHeader(h1);
    expect(parsed1).toEqual({ token: t1Hex, signature: sig1, denomination: 5 });
    expect(storedCreditBalance()).toBe(1);

    const compact = `${parsed1!.denomination}:${parsed1!.token}:${parsed1!.signature}`;
    expect(parseCreditHeader(compact)).toEqual(parsed1);

    const h2 = await takeCreditHeader();
    expect(parseCreditHeader(h2)).toEqual({ token: t2Hex, signature: sig2, denomination: 1 });
    expect(storedCreditBalance()).toBe(0);
    expect(await takeCreditHeader()).toBeNull();
  });

  it("verifies x-drouter-credit on relay inference routes, rejects double spends (409), and raises caller limits", async () => {
    process.env.DROUTER_STUB_UPSTREAM = "1";
    try {
      const pub = issuerPublicInfo();
      const tokHex = "ab12cd34".repeat(8);
      const b = blindToken(tokHex, 5, pub);
      const sig = unblindSignature(mintBlindedBatch([b.blindedHex], 5).signatures[0], b.rHex, pub);
      const validHeader = formatCreditHeader({ token: tokHex, signature: sig, denomination: 5 });

      const ip = "198.51.100.77";
      for (let i = 0; i < 20; i++) {
        const freeReq = new Request("http://localhost/api/relay/v1/chat/completions", {
          method: "POST",
          headers: {
            "x-forwarded-for": ip,
            "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
            "x-tinfoil-model": "kimi-k3",
            "ehbp-encapsulated-key": "11".repeat(32),
          },
          body: "encrypted-payload",
        });
        const r = await postRelay(freeReq, { params: Promise.resolve({ path: ["chat", "completions"] }) });
        expect(r.status).toBe(200);
      }

      const blockedFreeReq = new Request("http://localhost/api/relay/v1/chat/completions", {
        method: "POST",
        headers: {
          "x-forwarded-for": ip,
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "x-tinfoil-model": "kimi-k3",
          "ehbp-encapsulated-key": "11".repeat(32),
        },
        body: "encrypted-payload",
      });
      const blockedRes = await postRelay(blockedFreeReq, {
        params: Promise.resolve({ path: ["chat", "completions"] }),
      });
      expect(blockedRes.status).toBe(429);

      const largeBody = new Uint8Array(300_000);
      largeBody.fill(0x42);
      const creditReq = new Request("http://localhost/api/relay/v1/chat/completions", {
        method: "POST",
        headers: {
          "x-forwarded-for": ip,
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "x-tinfoil-model": "kimi-k3",
          "ehbp-encapsulated-key": "11".repeat(32),
          "x-drouter-credit": validHeader,
        },
        body: largeBody,
      });
      const creditRes = await postRelay(creditReq, {
        params: Promise.resolve({ path: ["chat", "completions"] }),
      });
      expect(creditRes.status).toBe(200);
      expect(creditRes.headers.get("X-DRouter-Credit-Nullifier")).toBe(nullifierFor(tokHex));
      expect(creditRes.headers.get("X-DRouter-Credit-Denomination")).toBe("5");

      const afterBoostReq = new Request("http://localhost/api/relay/v1/chat/completions", {
        method: "POST",
        headers: {
          "x-forwarded-for": ip,
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "x-tinfoil-model": "kimi-k3",
          "ehbp-encapsulated-key": "11".repeat(32),
        },
        body: "encrypted-payload",
      });
      const afterBoostRes = await postRelay(afterBoostReq, {
        params: Promise.resolve({ path: ["chat", "completions"] }),
      });
      expect(afterBoostRes.status).toBe(200);

      const replayHopReq = new Request("http://localhost/api/relay/relay-eu-zurich/v1/chat/completions", {
        method: "POST",
        headers: {
          "x-forwarded-for": ip,
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "x-tinfoil-model": "kimi-k3",
          "ehbp-encapsulated-key": "11".repeat(32),
          "x-drouter-credit": validHeader,
        },
        body: "encrypted-payload",
      });
      const replayRes = await postRelayHop(replayHopReq, {
        params: Promise.resolve({ relayId: "relay-eu-zurich", path: ["chat", "completions"] }),
      });
      expect(replayRes.status).toBe(409);

      const forgedReq = new Request("http://localhost/api/relay/v1/chat/completions", {
        method: "POST",
        headers: {
          "x-forwarded-for": ip,
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "x-tinfoil-model": "kimi-k3",
          "ehbp-encapsulated-key": "11".repeat(32),
          "x-drouter-credit": JSON.stringify({
            token: "ff".repeat(32),
            signature: "1234",
            denomination: 1,
          }),
        },
        body: "encrypted-payload",
      });
      const forgedRes = await postRelay(forgedReq, {
        params: Promise.resolve({ path: ["chat", "completions"] }),
      });
      expect(forgedRes.status).toBe(400);
    } finally {
      delete process.env.DROUTER_STUB_UPSTREAM;
    }
  });

  it("derives one-time deposit addresses from CREDITS_DEPOSIT_XPUB via @scure/bip32 matching the offline spending key", () => {
    const master = HDKey.fromMasterSeed(hexToBytes(TEST_SEED));
    const accountNode = master.derive("m/44'/60'/0'/0");
    const xpub = accountNode.publicExtendedKey;
    const xprv = accountNode.privateExtendedKey;

    const seen = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const childPriv = accountNode.deriveChild(i);
      const expectedFromOfflinePriv = privateKeyToAccount(
        (`0x${bytesToHex(childPriv.privateKey!)}`) as Hex
      ).address;
      const derivedFromXpub = deriveDepositAddress(i, xpub);
      expect(derivedFromXpub).toBe(expectedFromOfflinePriv);
      expect(seen.has(derivedFromXpub)).toBe(false);
      seen.add(derivedFromXpub);
    }

    // Never accept an extended private key (xprv) as CREDITS_DEPOSIT_XPUB
    expect(() => deriveDepositAddress(0, xprv)).toThrow(/never a private key/);
    // Reject negative or hardened derivation indices
    expect(() => deriveDepositAddress(-1, xpub)).toThrow(/Invalid BIP32/);
    expect(() => deriveDepositAddress(HARDENED_OFFSET, xpub)).toThrow(/Invalid BIP32/);
  });

  it("enforces free daily allowance, rejects legacy txHash path, and completes the one-time deposit invoice + claim flow via mocked viem Transfer logs", async () => {
    const pub = issuerPublicInfo();
    expect("issuerAddress" in pub).toBe(false);
    expect(pub.chainId).toBe(ARC_CREDIT_CHAIN_ID);
    expect(pub.usdcContract).toBe(ARC_USDC_ADDRESS);
    expect(pub.usdcDecimals).toBe(ARC_USDC_DECIMALS);
    expect(pub.invoiceDenominationsUsdc).toEqual(FIXED_INVOICE_AMOUNTS_USDC);

    const ip = "203.0.113.88";
    const makeBlindedBatch = (count: number, denom = 1) =>
      Array.from({ length: count }, (_, i) => {
        const secret = `${(i + 1).toString(16).padStart(2, "0")}`.repeat(32);
        return { secret, ...blindToken(secret, denom, pub) };
      });

    // 1. Free daily allowance: 10 credits/day per salted IP hash
    const batch1 = makeBlindedBatch(5, 1);
    const res1 = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({ blinded: batch1.map((b) => b.blindedHex), denomination: 1 }),
      })
    );
    expect(res1.status).toBe(200);
    const json1 = await res1.json();
    expect(json1.mode).toBe("free-allowance");
    expect(json1.remainingFreeToday).toBe(5);

    const batch2 = makeBlindedBatch(5, 1);
    const res2 = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({ blinded: batch2.map((b) => b.blindedHex), denomination: 1 }),
      })
    );
    expect(res2.status).toBe(200);
    const json2 = await res2.json();
    expect(json2.remainingFreeToday).toBe(0);

    // 11th free credit from same IP is rejected with 402 and points to /api/credits/invoice (never a static address)
    const batch3 = makeBlindedBatch(1, 1);
    const res3 = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({ blinded: batch3.map((b) => b.blindedHex), denomination: 1 }),
      })
    );
    expect(res3.status).toBe(402);
    const err3 = await res3.json();
    expect(err3.error).toContain("/api/credits/invoice");
    expect("issuerAddress" in err3).toBe(false);

    // Legacy txHash submission to POST /api/credits is rejected with 400
    const legacyTxRes = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({
          blinded: batch3.map((b) => b.blindedHex),
          denomination: 1,
          txHash: "0x" + "ab".repeat(32),
        }),
      })
    );
    expect(legacyTxRes.status).toBe(400);

    // 2. Invoice creation: rejects raw claimSecret, payer addresses, and non-fixed denominations
    const { claimSecret, claimHash } = generateClaimSecret();

    const leakedSecretRes = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash, claimSecret, denomination: 5 }),
      })
    );
    expect(leakedSecretRes.status).toBe(400);

    const payerAddrRes = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          claimHash,
          denomination: 5,
          payerAddress: "0x1111111111111111111111111111111111111111",
        }),
      })
    );
    expect(payerAddrRes.status).toBe(400);

    const nonFixedDenomRes = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash, denomination: 7 }),
      })
    );
    expect(nonFixedDenomRes.status).toBe(400);

    const nonFixedAmountRes = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash, amountUsdc: "0.0003" }),
      })
    );
    expect(nonFixedAmountRes.status).toBe(400);

    // Valid invoice creation for denomination 5 (0.0005 USDC)
    const invRes1 = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash, denomination: 5 }),
      })
    );
    expect(invRes1.status).toBe(200);
    const inv1 = await invRes1.json();
    expect(inv1.depositAddress).toBe(deriveDepositAddress(0));
    expect(inv1.amountUsdc).toBe("0.0005");
    expect(inv1.denomination).toBe(5);
    expect(inv1.expiresAt % 3_600_000).toBe(0);

    // Verify stored invoice record has ONLY the 6 permitted fields (no depositAddress, no payerAddress, no IP, no claimSecret)
    const storedInv1 = getStoredInvoiceRecordForTests(inv1.invoiceId);
    expect(storedInv1).not.toBeNull();
    expect(Object.keys(storedInv1!).sort()).toEqual(
      ["amount", "claimHash", "derivationIndex", "expiresAt", "invoiceId", "paid"].sort()
    );
    expect(storedInv1!.derivationIndex).toBe(0);
    expect(storedInv1!.amount).toBe("0.0005");
    expect(storedInv1!.claimHash).toBe(claimHash);
    expect(storedInv1!.paid).toBe(false);

    // Reusing the same claimHash for a second invoice is rejected with 409
    const dupHashRes = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash, denomination: 5 }),
      })
    );
    expect(dupHashRes.status).toBe(409);

    // Second invoice derives a distinct one-time deposit address (derivationIndex = 1)
    const sec2 = generateClaimSecret();
    const invRes2 = await postInvoiceRoute(
      new Request("http://localhost/api/credits/invoice", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ claimHash: sec2.claimHash, denomination: 20 }),
      })
    );
    expect(invRes2.status).toBe(200);
    const inv2 = await invRes2.json();
    expect(inv2.depositAddress).toBe(deriveDepositAddress(1));
    expect(inv2.depositAddress).not.toBe(inv1.depositAddress);
    expect(inv2.amountUsdc).toBe("0.002");

    // 3. Claim verification with mocked viem USDC Transfer logs on Arc Testnet
    const paidBatch5 = makeBlindedBatch(1, 5); // 1 token of denomination 5 = 5 credits

    // Wrong claimSecret is rejected with 403
    const wrongSecretRes = await postClaimRoute(
      new Request("http://localhost/api/credits/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invoiceId: inv1.invoiceId,
          claimSecret: "ff".repeat(32),
          blinded: paidBatch5.map((b) => b.blindedHex),
          denomination: 5,
        }),
      })
    );
    expect(wrongSecretRes.status).toBe(403);

    // Unpaid deposit address (empty Transfer logs) is rejected with 400
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(2000),
      getUsdcTransferLogs: async () => [],
    });

    const unpaidRes = await postClaimRoute(
      new Request("http://localhost/api/credits/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invoiceId: inv1.invoiceId,
          claimSecret,
          blinded: paidBatch5.map((b) => b.blindedHex),
          denomination: 5,
        }),
      })
    );
    expect(unpaidRes.status).toBe(400);
    const unpaidJson = await unpaidRes.json();
    expect(unpaidJson.error).toContain("No confirmed USDC Transfer log");

    // Insufficient USDC transfer (only 100 units = 0.0001 USDC instead of 500 units = 0.0005 USDC) is rejected with 400
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(2000),
      getUsdcTransferLogs: async ({ depositAddress }) => [
        {
          address: ARC_USDC_ADDRESS,
          blockNumber: BigInt(1999),
          transactionHash: ("0x" + "11".repeat(32)) as Hex,
          value: USDC_UNITS_PER_CREDIT, // 100 units (1 credit)
          args: { to: depositAddress, value: USDC_UNITS_PER_CREDIT },
        },
      ],
    });

    const underpaidRes = await postClaimRoute(
      new Request("http://localhost/api/credits/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invoiceId: inv1.invoiceId,
          claimSecret,
          blinded: paidBatch5.map((b) => b.blindedHex),
          denomination: 5,
        }),
      })
    );
    expect(underpaidRes.status).toBe(400);
    const underpaidJson = await underpaidRes.json();
    expect(underpaidJson.error).toContain("Insufficient USDC deposit");

    // Valid USDC Transfer log of 500 units (0.0005 USDC) to inv1.depositAddress
    const validDepositTxHash = ("0x" + "aa".repeat(32)) as Hex;
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(2005),
      getUsdcTransferLogs: async ({ depositAddress }) => [
        {
          address: ARC_USDC_ADDRESS,
          blockNumber: BigInt(2004),
          transactionHash: validDepositTxHash,
          value: FIXED_INVOICE_UNITS[5], // 500 units (0.0005 USDC)
          args: { to: depositAddress, value: FIXED_INVOICE_UNITS[5] },
        },
      ],
    });

    const claimRes = await postClaimRoute(
      new Request("http://localhost/api/credits/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invoiceId: inv1.invoiceId,
          claimSecret,
          blinded: paidBatch5.map((b) => b.blindedHex),
          denomination: 5,
        }),
      })
    );
    expect(claimRes.status).toBe(200);
    const claimJson = await claimRes.json();
    expect(claimJson.ok).toBe(true);
    expect(claimJson.mode).toBe("paid-invoice");
    expect(claimJson.signatures).toHaveLength(1);
    expect(claimJson.creditsGranted).toBe(5);
    expect(claimJson.amountUsdc).toBe("0.0005");
    expect(claimJson.depositAddress).toBe(inv1.depositAddress);
    // Response never includes any payer/sender address
    expect("payerAddress" in claimJson).toBe(false);
    expect("sender" in claimJson).toBe(false);
    expect("from" in claimJson).toBe(false);

    // Stored payment record in credit_payments has ONLY txHash and amount (no sender address)
    const storedPayment = getStoredPaymentRecordForTests(validDepositTxHash);
    expect(storedPayment).toEqual({
      txHash: validDepositTxHash,
      amount: "0.0005",
    });
    expect(Object.keys(storedPayment!).sort()).toEqual(["amount", "txHash"]);
    expect(getStoredInvoiceRecordForTests(inv1.invoiceId)?.paid).toBe(true);

    // Replaying the claim on the same invoice is rejected with 409
    const replayClaimRes = await postClaimRoute(
      new Request("http://localhost/api/credits/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invoiceId: inv1.invoiceId,
          claimSecret,
          blinded: paidBatch5.map((b) => b.blindedHex),
          denomination: 5,
        }),
      })
    );
    expect(replayClaimRes.status).toBe(409);

    // Expired invoice is rejected with 410
    const expiredCheck = await claimCreditInvoice({
      invoiceId: inv2.invoiceId,
      claimSecret: sec2.claimSecret,
      blindedHexes: [paidBatch5[0].blindedHex],
      denomination: 20,
      nowMs: inv2.expiresAt + 1000,
    });
    expect(expiredCheck.ok).toBe(false);
    if (!expiredCheck.ok) {
      expect(expiredCheck.status).toBe(410);
      expect(expiredCheck.error).toContain("expired");
    }

    // Unblind the claimed token and spend it via POST /api/credits/spend
    const unblindedPaidToken: BlindCreditToken = {
      token: paidBatch5[0].secret,
      signature: unblindSignature(claimJson.signatures[0], paidBatch5[0].rHex, pub),
      denomination: 5,
    };
    const spendRes = await postSpendRoute(
      new Request("http://localhost/api/credits/spend", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: unblindedPaidToken, nodeId: "tinfoil-router" }),
      })
    );
    expect(spendRes.status).toBe(200);
    const spendJson = await spendRes.json();
    expect(spendJson.ok).toBe(true);
    expect(spendJson.denomination).toBe(5);

    const getRes = await getCreditsRoute();
    const getJson = await getRes.json();
    expect(typeof getJson.keyBits).toBe("number");
    expect("issuerAddress" in getJson).toBe(false);
    expect(getJson.usdcContract).toBe(ARC_USDC_ADDRESS);
  });

  it("completes browser client requestCreditInvoice -> claimPaidCredits -> takeCreditHeader flow", async () => {
    const originalFetch = globalThis.fetch;
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(5000),
      getUsdcTransferLogs: async ({ depositAddress }) => [
        {
          address: ARC_USDC_ADDRESS,
          blockNumber: BigInt(4999),
          transactionHash: ("0x" + "cc".repeat(32)) as Hex,
          value: FIXED_INVOICE_UNITS[5],
          args: { to: depositAddress, value: FIXED_INVOICE_UNITS[5] },
        },
      ],
    });

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const req = new Request(url.toString(), init);
      if (url.pathname === "/api/credits" && (!init?.method || init.method === "GET")) {
        return getCreditsRoute(req);
      }
      if (url.pathname === "/api/credits/invoice" && init?.method === "POST") {
        return postInvoiceRoute(req);
      }
      if (url.pathname === "/api/credits/claim" && init?.method === "POST") {
        return postClaimRoute(req);
      }
      throw new Error(`Unexpected fetch path: ${url.pathname}`);
    }) as typeof fetch;

    try {
      const handle = await requestCreditInvoice("http://localhost", 5);
      expect(handle.claimHash).toBe(hashClaimSecret(handle.claimSecret));
      expect(handle.amountUsdc).toBe("0.0005");
      expect(handle.depositAddress).toBe(deriveDepositAddress(0));

      const tokens = await claimPaidCredits("http://localhost", {
        invoiceId: handle.invoiceId,
        claimSecret: handle.claimSecret,
        count: 5,
        denomination: 1,
      });
      expect(tokens).toHaveLength(5);
      expect(storedCreditBalance()).toBe(5);

      const header = await takeCreditHeader();
      expect(header).not.toBeNull();
      expect(storedCreditBalance()).toBe(4);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
