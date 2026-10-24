import { generatePrimeSync } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
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
  clearStoredCredits,
  getStoredCredits,
  storeCreditTokens,
  storedCreditBalance,
  takeCreditHeader,
} from "@/lib/credits/client";
import {
  ARC_CREDIT_CHAIN_ID,
  USDC_WEI_PER_CREDIT,
  coarsenTimestampToHourMs,
  getCreditIssuerAddress,
  issuerPublicInfo,
  ledgerStats,
  mintBlindedBatch,
  redeemBatch,
  resetCreditsLedgerForTests,
  setCreditPaymentVerifierDepsForTests,
  spendToken,
  verifyAndMintPaidBatch,
} from "@/lib/credits/ledger";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import type { BlindCreditToken, Hex } from "@/lib/types";

const TEST_SEED =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

describe("Subsystem 1: Unlinkable Blind-Signed Credits (Spec §7)", () => {
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

  it("defeats blind-signature denomination escalation (blinding denom=20 and signing at denom=1) and concurrent double-spend races", async () => {
    const pub = issuerPublicInfo();
    const attackerTokenHex = "fedcba9876543210".repeat(4);

    // Attacker blinds a denomination=20 message but requests a denomination=1 signature
    const blindedAs20 = blindToken(attackerTokenHex, 20, pub);
    const { signatures } = mintBlindedBatch([blindedAs20.blindedHex], 1);
    const unblindedForgedSig = unblindSignature(signatures[0], blindedAs20.rHex, pub);

    // Must fail verification for denomination=20 AND denomination=1
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

    // Concurrent double-spend race test: 10 parallel spendToken calls on the same valid token
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

    // Compact colon format also parses cleanly
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

      // 1. Exhaust the caller's free per-IP relay bucket (20 requests)
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

      // 21st free request is rate limited (429)
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

      // 2. Request with valid x-drouter-credit (denomination 5) succeeds, bypasses 429,
      //    supports >256 KB body (up to 512 KB), and credits 5*4 = 20 tokens back to the caller's bucket.
      const largeBody = new Uint8Array(300_000); // > 256 KB free cap, <= 512 KB credit cap
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

      // Subsequent request from the same IP now succeeds thanks to refilled quota
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

      // 3. Replaying the same x-drouter-credit on the hop relay route is rejected with 409 Double-Spend
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

      // 4. Forged x-drouter-credit is rejected with 400
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

  it("enforces the free daily credit allowance per salted IP and verifies paid Arc USDC transactions via mock viem", async () => {
    const pub = issuerPublicInfo();
    const ip = "203.0.113.88";

    // Mint 10 credits (two batches of 5) using the free daily allowance
    const makeBlindedBatch = (count: number, denom = 1) =>
      Array.from({ length: count }, (_, i) => {
        const secret = `${(i + 1).toString(16).padStart(2, "0")}`.repeat(32);
        return blindToken(secret, denom, pub);
      });

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
    expect(typeof json1.keyBits).toBe("number");

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

    // 11th free credit from same IP is rejected with HTTP 402 Payment Required
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
    expect(err3.error).toContain("Free daily credit allowance");
    expect(err3.issuerAddress).toBe(getCreditIssuerAddress());

    // Paid path with mocked viem client: verifies recipient, amount, chainId 5042002, confirmations, and prevents replay
    const issuerAddr = getCreditIssuerAddress();
    const validTxHash = (`0x${"ab".repeat(32)}`) as Hex;
    const paidBatch = makeBlindedBatch(2, 5); // 2 * 5 = 10 credits -> needs 10 * USDC_WEI_PER_CREDIT

    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(1005),
      getTransaction: async ({ hash }) => ({
        hash,
        to: issuerAddr,
        value: BigInt(10) * USDC_WEI_PER_CREDIT,
        chainId: ARC_CREDIT_CHAIN_ID,
        blockNumber: BigInt(1004),
      }),
      getTransactionReceipt: async () => ({
        status: "success",
        blockNumber: BigInt(1004),
        to: issuerAddr,
        logs: [],
      }),
    });

    // Even though IP's free allowance is 0, submitting valid paid txHash mints 2x5=10 credits
    const paidRes = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({
          blinded: paidBatch.map((b) => b.blindedHex),
          denomination: 5,
          txHash: validTxHash,
        }),
      })
    );
    expect(paidRes.status).toBe(200);
    const paidJson = await paidRes.json();
    expect(paidJson.mode).toBe("paid");
    expect(paidJson.signatures).toHaveLength(2);
    expect(paidJson.payment.creditsGranted).toBe(10);
    expect(paidJson.payment.chainId).toBe(ARC_CREDIT_CHAIN_ID);

    // Replaying the same txHash is rejected with HTTP 409
    const replayPaidRes = await postCreditsRoute(
      new Request("http://localhost/api/credits", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({
          blinded: paidBatch.map((b) => b.blindedHex),
          denomination: 5,
          txHash: validTxHash,
        }),
      })
    );
    expect(replayPaidRes.status).toBe(409);

    // Wrong recipient is rejected with HTTP 400
    const wrongRecipientTx = (`0x${"cd".repeat(32)}`) as Hex;
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(1010),
      getTransaction: async ({ hash }) => ({
        hash,
        to: "0x000000000000000000000000000000000000dead",
        value: BigInt(10) * USDC_WEI_PER_CREDIT,
        chainId: ARC_CREDIT_CHAIN_ID,
        blockNumber: BigInt(1009),
      }),
      getTransactionReceipt: async () => ({
        status: "success",
        blockNumber: BigInt(1009),
        to: "0x000000000000000000000000000000000000dead",
        logs: [],
      }),
    });
    const wrongRecipResult = await verifyAndMintPaidBatch({
      txHash: wrongRecipientTx,
      blindedHexes: paidBatch.map((b) => b.blindedHex),
      denomination: 5,
    });
    expect(wrongRecipResult.ok).toBe(false);
    if (!wrongRecipResult.ok) {
      expect(wrongRecipResult.status).toBe(400);
      expect(wrongRecipResult.error).toContain("does not transfer USDC to credit issuer");
    }

    // Insufficient USDC amount is rejected with HTTP 400
    const lowValueTx = (`0x${"ef".repeat(32)}`) as Hex;
    setCreditPaymentVerifierDepsForTests({
      getChainId: async () => ARC_CREDIT_CHAIN_ID,
      getBlockNumber: async () => BigInt(1010),
      getTransaction: async ({ hash }) => ({
        hash,
        to: issuerAddr,
        value: USDC_WEI_PER_CREDIT, // only 1 credit worth, requesting 10
        chainId: ARC_CREDIT_CHAIN_ID,
        blockNumber: BigInt(1009),
      }),
      getTransactionReceipt: async () => ({
        status: "success",
        blockNumber: BigInt(1009),
        to: issuerAddr,
        logs: [],
      }),
    });
    const lowValResult = await verifyAndMintPaidBatch({
      txHash: lowValueTx,
      blindedHexes: paidBatch.map((b) => b.blindedHex),
      denomination: 5,
    });
    expect(lowValResult.ok).toBe(false);
    if (!lowValResult.ok) {
      expect(lowValResult.status).toBe(400);
      expect(lowValResult.error).toContain("Insufficient USDC payment");
    }

    // GET /api/credits and POST /api/credits/spend work and report keyBits
    const getRes = await getCreditsRoute();
    const getJson = await getRes.json();
    expect(typeof getJson.keyBits).toBe("number");
    expect(getJson.issuerAddress).toBe(issuerAddr);

    const unblindedPaidToken: BlindCreditToken = {
      token: `${(1).toString(16).padStart(2, "0")}`.repeat(32),
      signature: unblindSignature(paidJson.signatures[0], paidBatch[0].rHex, pub),
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
  });
});
