import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { MongoClient, type Collection, type Db } from "mongodb";
import {
  createPublicClient,
  defineChain,
  formatUnits,
  http,
  isAddress,
  parseAbiItem,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { arcTestnet } from "viem/chains";
import type { BlindCreditToken, Hex } from "@/lib/types";
import {
  CREDIT_DENOMINATIONS,
  getPublicKey,
  nullifierFor,
  parseCreditHeader,
  signBlinded,
  verifyTokenSignature,
} from "./blind";

export const ARC_CREDIT_CHAIN_ID = 5042002;
export const USDC_WEI_PER_CREDIT = BigInt("100000000000000"); // 0.0001 USDC (18 decimals) per 1 credit
export const USDC_PER_CREDIT = "0.0001";
export const MIN_PAYMENT_CONFIRMATIONS = 1;
export const DEFAULT_ISSUER_ADDRESS: Hex = "0x508e5B6bEd0d172776702f26ADA65c37D5bb73E7";

const ERC20_TRANSFER_EVENT = parseAbiItem(
  "event Transfer(address indexed from, address indexed to, uint256 value)"
);
const ERC20_TRANSFER_TOPIC0 =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export interface NullifierRecord {
  nullifier: string;
  denomination: number;
  nodeId: string;
  spentAt: number;
  redeemed: boolean;
}

/**
 * Payment record persisted in `credit_payments`.
 * Privacy policy: stores ONLY `txHash` and `amount` (no wallet address, IP, or exact timestamp).
 */
export interface CreditPaymentRecord {
  txHash: string;
  amount: string;
}

export interface CreditPaymentLookupTx {
  hash: Hex;
  to: Hex | null;
  value: bigint;
  chainId?: number;
  blockNumber: bigint | null;
}

export interface CreditPaymentLookupReceipt {
  status: "success" | "reverted";
  blockNumber: bigint;
  to: Hex | null;
  logs: Array<{
    address: Hex;
    topics: Hex[];
    data: Hex;
  }>;
}

export interface CreditPaymentVerifierDeps {
  getChainId: () => Promise<number>;
  getBlockNumber: () => Promise<bigint>;
  getTransaction: (params: { hash: Hex }) => Promise<CreditPaymentLookupTx>;
  getTransactionReceipt: (params: { hash: Hex }) => Promise<CreditPaymentLookupReceipt>;
}

let testPaymentDeps: CreditPaymentVerifierDeps | null = null;

/** Injects mocked viem client methods for deterministic unit tests of on-chain payment verification. */
export function setCreditPaymentVerifierDepsForTests(
  deps: CreditPaymentVerifierDeps | null
): void {
  testPaymentDeps = deps;
}

const spentNullifiers = new Map<string, NullifierRecord>();
const inFlightNullifiers = new Set<string>();
const redeemedPaymentTxHashes = new Map<string, CreditPaymentRecord>();
const inFlightPaymentTxHashes = new Set<string>();
let redeemedBatchesCount = 0;

let mongoDbPromise: Promise<Db | null> | null = null;
let mongoIndexesPromise: Promise<void> | null = null;

/** Rounds a timestamp down to the start of its UTC hour (ms) so exact spend times are never stored. */
export function coarsenTimestampToHourMs(nowMs = Date.now()): number {
  return nowMs - (nowMs % 3_600_000);
}

function getIssuerSeed(): string {
  const seed = process.env.CREDITS_ISSUER_SEED || process.env.SIM_HARDWARE_SEED;
  if (seed) return seed;
  // Tests may run without secrets; production must never fall back to a public seed.
  if (process.env.VITEST) return "01".repeat(32);
  throw new Error("CREDITS_ISSUER_SEED or SIM_HARDWARE_SEED must be set");
}

/**
 * Resolves the Arc testnet USDC recipient address for paid credit issuance.
 * Priority: CREDITS_ISSUER_ADDRESS -> address derived from ARC_VERIFIER_PRIVATE_KEY -> DEFAULT_ISSUER_ADDRESS.
 * Private keys are never returned or logged.
 */
export function getCreditIssuerAddress(): Hex {
  const configured = process.env.CREDITS_ISSUER_ADDRESS?.trim();
  if (configured && isAddress(configured)) {
    return configured as Hex;
  }
  const verifierKey = process.env.ARC_VERIFIER_PRIVATE_KEY?.trim();
  if (verifierKey) {
    try {
      const normalized = (
        verifierKey.startsWith("0x") ? verifierKey : `0x${verifierKey}`
      ) as Hex;
      return privateKeyToAccount(normalized).address;
    } catch {
      // Fallback to default address
    }
  }
  return DEFAULT_ISSUER_ADDRESS;
}

async function getMongoDb(): Promise<Db | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;

  try {
    if (!mongoDbPromise) {
      const client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 2000,
        connectTimeoutMS: 2000,
      });
      mongoDbPromise = client
        .connect()
        .then((c) => c.db(process.env.MONGODB_DB || "drouter"))
        .catch(() => null);
    }
    const db = await mongoDbPromise;
    if (!db) return null;
    if (!mongoIndexesPromise) {
      mongoIndexesPromise = Promise.all([
        db
          .collection("credit_nullifiers")
          .createIndex({ nullifier: 1 }, { unique: true, name: "nullifier_unique" }),
        db
          .collection("credit_payments")
          .createIndex({ txHash: 1 }, { unique: true, name: "txHash_unique" }),
      ])
        .then(() => undefined)
        .catch(() => undefined);
    }
    await mongoIndexesPromise;
    return db;
  } catch {
    return null;
  }
}

async function getNullifierCollection(): Promise<Collection<NullifierRecord> | null> {
  const db = await getMongoDb();
  return db ? db.collection<NullifierRecord>("credit_nullifiers") : null;
}

async function getPaymentCollection(): Promise<Collection<CreditPaymentRecord> | null> {
  const db = await getMongoDb();
  return db ? db.collection<CreditPaymentRecord>("credit_payments") : null;
}

function isDuplicateKeyError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: unknown }).code;
  return code === 11000;
}

export function resetCreditsLedgerForTests(): void {
  spentNullifiers.clear();
  inFlightNullifiers.clear();
  redeemedPaymentTxHashes.clear();
  inFlightPaymentTxHashes.clear();
  redeemedBatchesCount = 0;
  testPaymentDeps = null;
}

export function issuerPublicInfo(): {
  n: string;
  e: string;
  denominations: number[];
  keyBits: number;
  issuerAddress: Hex;
  chainId: number;
  usdcPerCredit: string;
  minConfirmations: number;
} {
  const pub = getPublicKey(getIssuerSeed());
  return {
    ...pub,
    issuerAddress: getCreditIssuerAddress(),
    chainId: ARC_CREDIT_CHAIN_ID,
    usdcPerCredit: USDC_PER_CREDIT,
    minConfirmations: MIN_PAYMENT_CONFIRMATIONS,
  };
}

export function mintBlindedBatch(
  blindedHexes: string[],
  denomination = 1
): { signatures: string[]; denomination: number; keyBits: number } {
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    throw new Error(
      `Invalid denomination ${denomination}. Must be one of ${CREDIT_DENOMINATIONS.join(", ")}`
    );
  }
  if (!Array.isArray(blindedHexes) || blindedHexes.length === 0) {
    throw new Error("blindedHexes must be a non-empty array");
  }
  if (blindedHexes.length > 32) {
    throw new Error("Maximum batch size is 32 blinded tokens per request");
  }

  const seed = getIssuerSeed();
  const { keyBits } = getPublicKey(seed);
  const signatures = blindedHexes.map((b) => {
    if (typeof b !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(b.trim())) {
      throw new Error("Invalid hex in blinded token batch");
    }
    return signBlinded(b, denomination, seed);
  });

  return { signatures, denomination, keyBits };
}

function buildArcPaymentVerifierClient(): CreditPaymentVerifierDeps {
  if (testPaymentDeps) return testPaymentDeps;
  const url = process.env.ARC_RPC_URL || arcTestnet.rpcUrls.default.http[0];
  const chain = defineChain({ ...arcTestnet, rpcUrls: { default: { http: [url] } } });
  const client = createPublicClient({
    chain,
    transport: http(undefined, { timeout: 8_000, retryCount: 1 }),
  });
  return {
    getChainId: () => client.getChainId(),
    getBlockNumber: () => client.getBlockNumber(),
    getTransaction: async ({ hash }) => {
      const tx = await client.getTransaction({ hash });
      return {
        hash: tx.hash as Hex,
        to: (tx.to as Hex | null) ?? null,
        value: tx.value,
        chainId: typeof tx.chainId === "number" ? tx.chainId : undefined,
        blockNumber: tx.blockNumber ?? null,
      };
    },
    getTransactionReceipt: async ({ hash }) => {
      const r = await client.getTransactionReceipt({ hash });
      return {
        status: r.status === "success" ? "success" : "reverted",
        blockNumber: r.blockNumber,
        to: (r.to as Hex | null) ?? null,
        logs: (r.logs ?? []).map((l) => ({
          address: l.address as Hex,
          topics: (l.topics as Hex[]) ?? [],
          data: l.data as Hex,
        })),
      };
    },
  };
}

function extractErc20TransferToIssuer(
  logs: CreditPaymentLookupReceipt["logs"],
  issuerLower: string
): bigint {
  let total = BigInt(0);
  void ERC20_TRANSFER_EVENT;
  for (const log of logs) {
    if (!Array.isArray(log.topics) || log.topics.length < 3) continue;
    if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
    const toTopic = log.topics[2]?.toLowerCase() ?? "";
    if (!toTopic.endsWith(issuerLower.slice(2))) continue;
    try {
      const rawData = log.data && log.data !== "0x" ? log.data : "0x0";
      const val = BigInt(rawData);
      if (val > BigInt(0)) {
        // Normalize 6-decimal ERC-20 USDC transfers up to 18-decimal wei if value is small
        const scaled = val < BigInt("1000000000000") ? val * BigInt("1000000000000") : val;
        total += scaled;
      }
    } catch {
      // Ignore malformed log data
    }
  }
  return total;
}

/**
 * Verifies an Arc testnet (chain 5042002) USDC transfer transaction hash on-chain via viem,
 * atomically records `{ txHash, amount }` in `credit_payments` (never storing wallet addresses or IPs),
 * and blind-signs the requested credits if the payment covers `blindedHexes.length * denomination`.
 */
export async function verifyAndMintPaidBatch(params: {
  txHash: string;
  blindedHexes: string[];
  denomination?: number;
}): Promise<
  | {
      ok: true;
      signatures: string[];
      denomination: number;
      keyBits: number;
      payment: {
        txHash: Hex;
        amountUsdc: string;
        creditsGranted: number;
        confirmations: number;
        issuerAddress: Hex;
        chainId: number;
      };
    }
  | { ok: false; error: string; status: number }
> {
  const denomination = params.denomination ?? 1;
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    return {
      ok: false,
      error: `Invalid denomination ${denomination}. Must be one of ${CREDIT_DENOMINATIONS.join(", ")}`,
      status: 400,
    };
  }
  if (!Array.isArray(params.blindedHexes) || params.blindedHexes.length === 0) {
    return {
      ok: false,
      error: "Request body must provide a non-empty 'blinded' array",
      status: 400,
    };
  }
  if (params.blindedHexes.length > 32) {
    return {
      ok: false,
      error: "Maximum batch size is 32 blinded tokens per request",
      status: 400,
    };
  }

  const rawHash = typeof params.txHash === "string" ? params.txHash.trim().toLowerCase() : "";
  if (!/^0x[0-9a-f]{64}$/.test(rawHash)) {
    return {
      ok: false,
      error: "Invalid transaction hash: expected 0x-prefixed 32-byte hex string",
      status: 400,
    };
  }
  const normalizedTxHash = rawHash as Hex;

  if (
    redeemedPaymentTxHashes.has(normalizedTxHash) ||
    inFlightPaymentTxHashes.has(normalizedTxHash)
  ) {
    return {
      ok: false,
      error: "Payment transaction hash has already been redeemed for blind credits",
      status: 409,
    };
  }

  inFlightPaymentTxHashes.add(normalizedTxHash);
  try {
    const paymentCol = await getPaymentCollection();
    if (paymentCol) {
      try {
        const existing = await paymentCol.findOne({ txHash: normalizedTxHash });
        if (existing) {
          redeemedPaymentTxHashes.set(normalizedTxHash, {
            txHash: existing.txHash,
            amount: existing.amount,
          });
          return {
            ok: false,
            error: "Payment transaction hash has already been redeemed for blind credits",
            status: 409,
          };
        }
      } catch {
        // Proceed to verification + atomic insert
      }
    }

    const client = buildArcPaymentVerifierClient();
    let chainId: number;
    let tx: CreditPaymentLookupTx;
    let receipt: CreditPaymentLookupReceipt;
    let latestBlock: bigint;

    try {
      [chainId, tx, receipt, latestBlock] = await Promise.all([
        client.getChainId(),
        client.getTransaction({ hash: normalizedTxHash }),
        client.getTransactionReceipt({ hash: normalizedTxHash }),
        client.getBlockNumber(),
      ]);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Transaction not found on Arc testnet";
      return {
        ok: false,
        error: `Could not verify transaction on Arc testnet: ${detail.slice(0, 140)}`,
        status: 400,
      };
    }

    if (chainId !== ARC_CREDIT_CHAIN_ID) {
      return {
        ok: false,
        error: `Wrong RPC chainId ${chainId}; expected Arc testnet (${ARC_CREDIT_CHAIN_ID})`,
        status: 400,
      };
    }

    if (tx.chainId !== undefined && tx.chainId !== ARC_CREDIT_CHAIN_ID) {
      return {
        ok: false,
        error: `Transaction chainId ${tx.chainId} does not match Arc testnet (${ARC_CREDIT_CHAIN_ID})`,
        status: 400,
      };
    }

    if (receipt.status !== "success") {
      return {
        ok: false,
        error: "Payment transaction reverted on-chain",
        status: 400,
      };
    }

    const txBlock = receipt.blockNumber ?? tx.blockNumber;
    if (txBlock === null || txBlock === undefined) {
      return {
        ok: false,
        error: "Payment transaction is still pending confirmation",
        status: 400,
      };
    }

    const confirmations =
      latestBlock >= txBlock ? Number(latestBlock - txBlock) + 1 : 1;
    if (confirmations < MIN_PAYMENT_CONFIRMATIONS) {
      return {
        ok: false,
        error: `Insufficient confirmations (${confirmations}/${MIN_PAYMENT_CONFIRMATIONS})`,
        status: 400,
      };
    }

    const issuerAddress = getCreditIssuerAddress();
    const issuerLower = issuerAddress.toLowerCase();
    const directToMatch = (tx.to ?? receipt.to ?? "").toLowerCase() === issuerLower;

    let paidWei = directToMatch ? tx.value : BigInt(0);
    if (paidWei === BigInt(0)) {
      paidWei = extractErc20TransferToIssuer(receipt.logs, issuerLower);
    }

    if (paidWei <= BigInt(0)) {
      return {
        ok: false,
        error: `Transaction does not transfer USDC to credit issuer ${issuerAddress}`,
        status: 400,
      };
    }

    const requestedCredits = params.blindedHexes.length * denomination;
    const requiredWei = BigInt(requestedCredits) * USDC_WEI_PER_CREDIT;
    if (paidWei < requiredWei) {
      return {
        ok: false,
        error: `Insufficient USDC payment: sent ${formatUnits(paidWei, 18)} USDC, need at least ${formatUnits(requiredWei, 18)} USDC for ${requestedCredits} credit(s)`,
        status: 400,
      };
    }

    const amountUsdc = formatUnits(paidWei, 18);
    // Validate and sign blinded tokens before recording payment so malformed hex never burns a valid txHash
    let minted: { signatures: string[]; denomination: number; keyBits: number };
    try {
      minted = mintBlindedBatch(params.blindedHexes, denomination);
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : "Invalid blinded tokens",
        status: 400,
      };
    }

    // Store ONLY txHash and amount in credit_payments (no sender address, no IP, no timestamp)
    const paymentRecord: CreditPaymentRecord = {
      txHash: normalizedTxHash,
      amount: amountUsdc,
    };

    if (paymentCol) {
      try {
        await paymentCol.insertOne({ ...paymentRecord });
      } catch (err) {
        if (isDuplicateKeyError(err)) {
          redeemedPaymentTxHashes.set(normalizedTxHash, paymentRecord);
          return {
            ok: false,
            error: "Payment transaction hash has already been redeemed for blind credits",
            status: 409,
          };
        }
        // Best-effort persistence if Mongo fails transiently for non-duplicate reason
      }
    }

    redeemedPaymentTxHashes.set(normalizedTxHash, paymentRecord);

    return {
      ok: true,
      signatures: minted.signatures,
      denomination: minted.denomination,
      keyBits: minted.keyBits,
      payment: {
        txHash: normalizedTxHash,
        amountUsdc,
        creditsGranted: requestedCredits,
        confirmations,
        issuerAddress,
        chainId: ARC_CREDIT_CHAIN_ID,
      },
    };
  } finally {
    inFlightPaymentTxHashes.delete(normalizedTxHash);
  }
}

function countUnredeemed(): number {
  let count = 0;
  spentNullifiers.forEach((record) => {
    if (!record.redeemed) count++;
  });
  return count;
}

export async function spendToken(
  token: BlindCreditToken,
  nodeId = "default-node"
): Promise<
  | {
      ok: true;
      nullifier: string;
      denomination: number;
      remainingPoolUnredeemed: number;
    }
  | { ok: false; error: string; status: number }
> {
  if (
    !token ||
    typeof token.token !== "string" ||
    typeof token.signature !== "string" ||
    typeof token.denomination !== "number"
  ) {
    return {
      ok: false,
      error: "Malformed credit token payload",
      status: 400,
    };
  }

  const pub = issuerPublicInfo();
  if (!verifyTokenSignature(token, pub)) {
    return {
      ok: false,
      error: "Invalid RSA blind signature on credit token",
      status: 400,
    };
  }

  const nullifier = nullifierFor(token.token);

  if (spentNullifiers.has(nullifier) || inFlightNullifiers.has(nullifier)) {
    return {
      ok: false,
      error: "Double-spend rejected: credit nullifier already spent",
      status: 409,
    };
  }

  // Reserve nullifier synchronously before any async I/O to eliminate TOCTOU race conditions
  inFlightNullifiers.add(nullifier);
  try {
    const coarsenedSpentAt = coarsenTimestampToHourMs(Date.now());
    const record: NullifierRecord = {
      nullifier,
      denomination: token.denomination,
      nodeId,
      spentAt: coarsenedSpentAt,
      redeemed: false,
    };

    const col = await getNullifierCollection();
    if (col) {
      try {
        // Atomic upsert with $setOnInsert on unique `nullifier` guarantees single-spend across processes
        const res = await col.updateOne(
          { nullifier },
          { $setOnInsert: { ...record } },
          { upsert: true }
        );
        if (res.upsertedCount === 0 && res.matchedCount > 0) {
          spentNullifiers.set(nullifier, record);
          return {
            ok: false,
            error: "Double-spend rejected: credit nullifier already spent",
            status: 409,
          };
        }
      } catch (err) {
        if (isDuplicateKeyError(err)) {
          spentNullifiers.set(nullifier, record);
          return {
            ok: false,
            error: "Double-spend rejected: credit nullifier already spent",
            status: 409,
          };
        }
        // Best-effort Mongo persistence on transient connection errors
      }
    }

    spentNullifiers.set(nullifier, record);

    return {
      ok: true,
      nullifier,
      denomination: token.denomination,
      remainingPoolUnredeemed: countUnredeemed(),
    };
  } finally {
    inFlightNullifiers.delete(nullifier);
  }
}

/**
 * Parses and spends a raw `x-drouter-credit` header value.
 * Used by relay inference routes (`/api/relay/v1/*` and `/api/relay/[relayId]/v1/*`).
 */
export async function verifyAndSpendCreditHeader(
  rawHeader: string,
  nodeId = "relay-v1"
): Promise<
  | {
      ok: true;
      nullifier: string;
      denomination: number;
      remainingPoolUnredeemed: number;
    }
  | { ok: false; error: string; status: number }
> {
  const parsed = parseCreditHeader(rawHeader);
  if (!parsed) {
    return {
      ok: false,
      error: "Malformed x-drouter-credit header",
      status: 400,
    };
  }
  return spendToken(parsed, nodeId);
}

export async function redeemBatch(nodeId?: string): Promise<{
  redeemedCount: number;
  totalCredits: number;
  batchHash: string;
  timestamp: number;
}> {
  const timestamp = coarsenTimestampToHourMs(Date.now());
  const toRedeem: NullifierRecord[] = [];

  spentNullifiers.forEach((record) => {
    if (!record.redeemed && (!nodeId || record.nodeId === nodeId)) {
      record.redeemed = true;
      toRedeem.push(record);
    }
  });

  const redeemedCount = toRedeem.length;
  const totalCredits = toRedeem.reduce((sum, r) => sum + r.denomination, 0);

  const sortedNullifiers = toRedeem
    .map((r) => r.nullifier)
    .sort()
    .join(",");
  const batchHash = bytesToHex(
    sha256(
      utf8ToBytes(
        `drouter/v1/credit-batch:${nodeId || "all"}:${timestamp}:${redeemedCount}:${totalCredits}:${sortedNullifiers}`
      )
    )
  );

  if (redeemedCount > 0) {
    redeemedBatchesCount++;
    const col = await getNullifierCollection();
    if (col) {
      try {
        await col.updateMany(
          { nullifier: { $in: toRedeem.map((r) => r.nullifier) } },
          { $set: { redeemed: true } }
        );
      } catch {
        // Best-effort Mongo update
      }
    }
  }

  return {
    redeemedCount,
    totalCredits,
    batchHash,
    timestamp,
  };
}

export function ledgerStats(): {
  spentCount: number;
  unredeemedCount: number;
  redeemedBatches: number;
  paidRedemptions: number;
} {
  return {
    spentCount: spentNullifiers.size,
    unredeemedCount: countUnredeemed(),
    redeemedBatches: redeemedBatchesCount,
    paidRedemptions: redeemedPaymentTxHashes.size,
  };
}
