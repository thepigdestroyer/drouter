import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { HDKey, HARDENED_OFFSET } from "@scure/bip32";
import { MongoClient, type Collection, type Db } from "mongodb";
import { resolveDbName } from "@/lib/mongo/db-name";
import {
  createPublicClient,
  defineChain,
  formatUnits,
  http,
  parseAbiItem,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
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
/** Canonical Circle Arc Testnet ERC-20 USDC contract address (from viem/tokens & Circle Arc docs). */
export const ARC_USDC_ADDRESS: Hex = "0x3600000000000000000000000000000000000000";
/** Circle Arc Testnet ERC-20 USDC uses 6 decimals. */
export const ARC_USDC_DECIMALS = 6;
/** 0.0001 USDC in 6-decimal base units (100 micro-USDC) per 1 credit. */
export const USDC_UNITS_PER_CREDIT = BigInt(100);
export const USDC_PER_CREDIT = "0.0001";
export const MIN_PAYMENT_CONFIRMATIONS = 1;
export const INVOICE_TTL_INDEX_NAME = "expiresAt_ttl";

/** Fixed USDC invoice amounts keyed by credit denomination (1, 5, 20) to prevent amount fingerprinting. */
export const FIXED_INVOICE_AMOUNTS_USDC: Record<number, string> = {
  1: "0.0001",
  5: "0.0005",
  20: "0.002",
};

/** Fixed 6-decimal USDC base units keyed by credit denomination (1 -> 100, 5 -> 500, 20 -> 2000). */
export const FIXED_INVOICE_UNITS: Record<number, bigint> = {
  1: BigInt(100),
  5: BigInt(500),
  20: BigInt(2000),
};

const AMOUNT_USDC_TO_DENOMINATION: Record<string, number> = {
  "0.0001": 1,
  "0.0005": 5,
  "0.002": 20,
  "0.0020": 20,
};

const ERC20_TRANSFER_EVENT = parseAbiItem(
  "event Transfer(address indexed from, address indexed to, uint256 value)"
);
const ERC20_TRANSFER_TOPIC0 =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const TEST_MASTER_SEED_HEX =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

export interface NullifierRecord {
  nullifier: string;
  denomination: number;
  nodeId: string;
  spentAt: number;
  redeemed: boolean;
}

/**
 * Invoice record persisted in `credit_invoices`.
 * Privacy policy: stores ONLY `invoiceId`, `derivationIndex`, `amount`, `claimHash`,
 * coarse `expiresAt` (UTC hour boundary Date for TTL expiry), and `paid`.
 * Never stores payer addresses, deposit addresses, IP addresses, or `claimSecret`.
 */
export interface CreditInvoiceRecord {
  invoiceId: string;
  derivationIndex: number;
  amount: string;
  claimHash: string;
  expiresAt: Date;
  paid: boolean;
}

/**
 * Payment record persisted in `credit_payments`.
 * Privacy policy: stores ONLY `txHash` and `amount` (never sender/payer address, IP, or timestamp).
 */
export interface CreditPaymentRecord {
  txHash: string;
  amount: string;
}

/**
 * Sender-stripped USDC Transfer log entry on Arc Testnet.
 * Privacy policy: `from` / `topics[1]` is stripped at ingestion and never represented here.
 */
export interface UsdcTransferLogEntry {
  address?: Hex;
  blockNumber: bigint | null;
  transactionHash?: Hex | null;
  logIndex?: number | null;
  value?: bigint;
  args?: {
    to?: Hex;
    value?: bigint;
  };
  topics?: Hex[];
  data?: Hex;
}

export interface CreditPaymentVerifierDeps {
  getChainId: () => Promise<number>;
  getBlockNumber: () => Promise<bigint>;
  getUsdcTransferLogs: (params: {
    depositAddress: Hex;
    fromBlock: bigint;
    toBlock: bigint;
  }) => Promise<UsdcTransferLogEntry[]>;
}

let testPaymentDeps: CreditPaymentVerifierDeps | null = null;
let cachedTestXpub: string | null = null;

/** Injects mocked viem log reader methods for deterministic unit tests of one-time deposit verification. */
export function setCreditPaymentVerifierDepsForTests(
  deps: CreditPaymentVerifierDeps | null
): void {
  testPaymentDeps = deps;
}

const spentNullifiers = new Map<string, NullifierRecord>();
const inFlightNullifiers = new Set<string>();
const invoicesById = new Map<string, CreditInvoiceRecord>();
const invoiceIdByClaimHash = new Map<string, string>();
const usedDerivationIndices = new Set<number>();
const inFlightClaims = new Set<string>();
const redeemedPaymentTxHashes = new Map<string, CreditPaymentRecord>();
const inFlightPaymentTxHashes = new Set<string>();
let nextDerivationIndex = 0;
let derivationIndexSyncedFromMongo = false;
let redeemedBatchesCount = 0;

let mongoDbPromise: Promise<Db | null> | null = null;
let mongoIndexesPromise: Promise<void> | null = null;

/** Rounds a timestamp down to the start of its UTC hour (ms) so exact times are never stored. */
export function coarsenTimestampToHourMs(nowMs = Date.now()): number {
  return nowMs - (nowMs % 3_600_000);
}

/**
 * Computes a coarse UTC-hour expiry timestamp at least 1 full hour in the future
 * (`coarsenTimestampToHourMs(nowMs) + 2 * 3_600_000`), preventing creation-time correlation.
 */
export function coarsenExpiryToHourMs(nowMs = Date.now()): number {
  return coarsenTimestampToHourMs(nowMs) + 2 * 3_600_000;
}

function getIssuerSeed(): string {
  const seed = process.env.CREDITS_ISSUER_SEED || process.env.SIM_HARDWARE_SEED;
  if (seed) return seed;
  if (process.env.VITEST) return "01".repeat(32);
  throw new Error("CREDITS_ISSUER_SEED or SIM_HARDWARE_SEED must be set");
}

function getDepositXpub(xpubOverride?: string): string {
  const explicit = xpubOverride?.trim() || process.env.CREDITS_DEPOSIT_XPUB?.trim();
  if (explicit) return explicit;
  if (process.env.VITEST) {
    if (!cachedTestXpub) {
      const master = HDKey.fromMasterSeed(hexToBytes(TEST_MASTER_SEED_HEX));
      const accountNode = master.derive("m/44'/60'/0'/0");
      cachedTestXpub = accountNode.publicExtendedKey;
    }
    return cachedTestXpub;
  }
  throw new Error("CREDITS_DEPOSIT_XPUB must be set");
}

/**
 * Derives a one-time deposit address on Arc (chain 5042002) from `CREDITS_DEPOSIT_XPUB`
 * (BIP32 account xpub at m/44'/60'/0'/0) at non-hardened child `derivationIndex`.
 * The spending key is kept offline by the owner; the server only ever holds the public xpub.
 */
export function deriveDepositAddress(
  derivationIndex: number,
  xpubOverride?: string
): Hex {
  if (
    !Number.isInteger(derivationIndex) ||
    derivationIndex < 0 ||
    derivationIndex >= HARDENED_OFFSET
  ) {
    throw new Error(
      `Invalid BIP32 non-hardened derivation index: ${derivationIndex}`
    );
  }
  const xpub = getDepositXpub(xpubOverride);
  const hd = HDKey.fromExtendedKey(xpub);
  if (hd.privateKey) {
    throw new Error(
      "CREDITS_DEPOSIT_XPUB must be an extended public key (xpub), never a private key"
    );
  }
  const child = hd.deriveChild(derivationIndex);
  if (!child.publicKey) {
    throw new Error("Failed to derive child public key from CREDITS_DEPOSIT_XPUB");
  }
  const uncompressed = secp256k1.Point.fromBytes(child.publicKey).toBytes(false);
  return publicKeyToAddress((`0x${bytesToHex(uncompressed)}`) as Hex) as Hex;
}

function normalizeHex32(raw: string, label: string): string {
  if (typeof raw !== "string") {
    throw new Error(`Invalid ${label}: expected 32-byte hex string`);
  }
  const trimmed = raw.trim().toLowerCase();
  const withoutPrefix = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  if (!/^[0-9a-f]{64}$/.test(withoutPrefix)) {
    throw new Error(`Invalid ${label}: expected 32-byte (64-hex-char) string`);
  }
  return withoutPrefix;
}

/**
 * Computes `sha256(claimSecret)` as a 64-char lowercase hex string from a 32-byte hex `claimSecret`.
 */
export function hashClaimSecret(claimSecretHex: string): string {
  const normalized = normalizeHex32(claimSecretHex, "claimSecret");
  return bytesToHex(sha256(hexToBytes(normalized)));
}

function candidateClaimHashes(claimSecretHex: string): string[] {
  const normalized = normalizeHex32(claimSecretHex, "claimSecret");
  const fromBytes = bytesToHex(sha256(hexToBytes(normalized)));
  const fromUtf8Normalized = bytesToHex(sha256(utf8ToBytes(normalized)));
  const fromUtf8Raw = bytesToHex(sha256(utf8ToBytes(claimSecretHex.trim())));
  return Array.from(new Set([fromBytes, fromUtf8Normalized, fromUtf8Raw]));
}

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function randomInvoiceId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
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
        .then((c) => c.db(resolveDbName()))
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
        db
          .collection("credit_invoices")
          .createIndex({ invoiceId: 1 }, { unique: true, name: "invoiceId_unique" }),
        db
          .collection("credit_invoices")
          .createIndex({ claimHash: 1 }, { unique: true, name: "claimHash_unique" }),
        db
          .collection("credit_invoices")
          .createIndex(
            { derivationIndex: 1 },
            { unique: true, name: "derivationIndex_unique" }
          ),
        db
          .collection("credit_invoices")
          .createIndex(
            { expiresAt: 1 },
            { expireAfterSeconds: 0, name: INVOICE_TTL_INDEX_NAME }
          ),
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

async function getInvoiceCollection(): Promise<Collection<CreditInvoiceRecord> | null> {
  const db = await getMongoDb();
  return db ? db.collection<CreditInvoiceRecord>("credit_invoices") : null;
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
  invoicesById.clear();
  invoiceIdByClaimHash.clear();
  usedDerivationIndices.clear();
  inFlightClaims.clear();
  redeemedPaymentTxHashes.clear();
  inFlightPaymentTxHashes.clear();
  nextDerivationIndex = 0;
  derivationIndexSyncedFromMongo = true; // Keep deterministic 0-based index in unit tests
  redeemedBatchesCount = 0;
  testPaymentDeps = null;
}

export function getStoredInvoiceRecordForTests(
  invoiceId: string
): CreditInvoiceRecord | null {
  const rec = invoicesById.get(invoiceId);
  return rec ? { ...rec, expiresAt: new Date(rec.expiresAt.getTime()) } : null;
}

export function getStoredPaymentRecordForTests(
  txHash: string
): CreditPaymentRecord | null {
  const rec = redeemedPaymentTxHashes.get(txHash.toLowerCase());
  return rec ? { ...rec } : null;
}

export function issuerPublicInfo(): {
  n: string;
  e: string;
  denominations: number[];
  keyBits: number;
  chainId: number;
  usdcContract: Hex;
  usdcDecimals: number;
  usdcPerCredit: string;
  invoiceDenominationsUsdc: Record<number, string>;
  minConfirmations: number;
} {
  const pub = getPublicKey(getIssuerSeed());
  return {
    ...pub,
    chainId: ARC_CREDIT_CHAIN_ID,
    usdcContract: ARC_USDC_ADDRESS,
    usdcDecimals: ARC_USDC_DECIMALS,
    usdcPerCredit: USDC_PER_CREDIT,
    invoiceDenominationsUsdc: { ...FIXED_INVOICE_AMOUNTS_USDC },
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

function resolveFixedDenomination(params: {
  denomination?: number;
  credits?: number;
  amountUsdc?: string;
}): { ok: true; denomination: number; amountUsdc: string } | { ok: false; error: string } {
  let denomFromNum: number | undefined;
  if (params.denomination !== undefined) {
    denomFromNum = params.denomination;
  } else if (params.credits !== undefined) {
    denomFromNum = params.credits;
  }

  let denomFromAmount: number | undefined;
  if (params.amountUsdc !== undefined) {
    const trimmed = String(params.amountUsdc).trim();
    const mapped = AMOUNT_USDC_TO_DENOMINATION[trimmed];
    if (!mapped) {
      return {
        ok: false,
        error: `Invalid amountUsdc '${trimmed}'. Must be one of fixed denominations: ${Object.values(
          FIXED_INVOICE_AMOUNTS_USDC
        ).join(", ")} USDC`,
      };
    }
    denomFromAmount = mapped;
  }

  if (
    denomFromNum !== undefined &&
    denomFromAmount !== undefined &&
    denomFromNum !== denomFromAmount
  ) {
    return {
      ok: false,
      error: `Mismatched denomination (${denomFromNum}) and amountUsdc (${params.amountUsdc})`,
    };
  }

  const chosen = denomFromNum ?? denomFromAmount ?? 1;
  if (!CREDIT_DENOMINATIONS.includes(chosen)) {
    return {
      ok: false,
      error: `Invalid denomination ${chosen}. Must be one of fixed denominations: ${CREDIT_DENOMINATIONS.join(
        ", "
      )}`,
    };
  }

  return {
    ok: true,
    denomination: chosen,
    amountUsdc: FIXED_INVOICE_AMOUNTS_USDC[chosen],
  };
}

async function allocateNextDerivationIndex(
  invoiceCol: Collection<CreditInvoiceRecord> | null
): Promise<number> {
  if (invoiceCol && !derivationIndexSyncedFromMongo && !process.env.VITEST) {
    derivationIndexSyncedFromMongo = true;
    try {
      const paymentCol = await getPaymentCollection();
      const [highestInvoice, paidCount] = await Promise.all([
        invoiceCol
          .find({}, { projection: { derivationIndex: 1, _id: 0 } })
          .sort({ derivationIndex: -1 })
          .limit(1)
          .toArray(),
        paymentCol ? paymentCol.countDocuments() : Promise.resolve(0),
      ]);
      const maxFromInvoices =
        highestInvoice.length > 0 &&
        typeof highestInvoice[0].derivationIndex === "number"
          ? highestInvoice[0].derivationIndex + 1
          : 0;
      nextDerivationIndex = Math.max(nextDerivationIndex, maxFromInvoices, paidCount);
    } catch {
      // Fallback to in-memory counter
    }
  }

  while (usedDerivationIndices.has(nextDerivationIndex)) {
    nextDerivationIndex++;
  }
  const allocated = nextDerivationIndex;
  usedDerivationIndices.add(allocated);
  nextDerivationIndex++;
  return allocated;
}

/**
 * Creates a one-time deposit-address invoice for a fixed credit denomination (1, 5, or 20).
 * Persists ONLY `{ invoiceId, derivationIndex, amount, claimHash, expiresAt, paid }` in `credit_invoices`.
 */
export async function createCreditInvoice(params: {
  claimHash: string;
  denomination?: number;
  credits?: number;
  amountUsdc?: string;
  nowMs?: number;
}): Promise<
  | {
      ok: true;
      invoiceId: string;
      depositAddress: Hex;
      amountUsdc: string;
      denomination: number;
      chainId: number;
      usdcContract: Hex;
      usdcDecimals: number;
      expiresAt: number;
    }
  | { ok: false; error: string; status: number }
> {
  let normalizedClaimHash: string;
  try {
    normalizedClaimHash = normalizeHex32(params.claimHash, "claimHash");
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Invalid claimHash",
      status: 400,
    };
  }

  const resolved = resolveFixedDenomination({
    denomination: params.denomination,
    credits: params.credits,
    amountUsdc: params.amountUsdc,
  });
  if (!resolved.ok) {
    return {
      ok: false,
      error: resolved.error,
      status: 400,
    };
  }

  if (invoiceIdByClaimHash.has(normalizedClaimHash)) {
    return {
      ok: false,
      error: "claimHash has already been used for an invoice",
      status: 409,
    };
  }

  const invoiceCol = process.env.VITEST ? null : await getInvoiceCollection();
  if (invoiceCol) {
    try {
      const existing = await invoiceCol.findOne(
        { claimHash: normalizedClaimHash },
        { projection: { invoiceId: 1, _id: 0 } }
      );
      if (existing) {
        return {
          ok: false,
          error: "claimHash has already been used for an invoice",
          status: 409,
        };
      }
    } catch {
      // Proceed to atomic insert
    }
  }

  const nowMs = params.nowMs ?? Date.now();
  const expiresAtMs = coarsenExpiryToHourMs(nowMs);
  const expiresAtDate = new Date(expiresAtMs);

  for (let attempt = 0; attempt < 8; attempt++) {
    const derivationIndex = await allocateNextDerivationIndex(invoiceCol);
    let depositAddress: Hex;
    try {
      depositAddress = deriveDepositAddress(derivationIndex);
    } catch (err) {
      usedDerivationIndices.delete(derivationIndex);
      return {
        ok: false,
        error:
          err instanceof Error
            ? err.message
            : "Failed to derive one-time deposit address",
        status: 500,
      };
    }

    const invoiceId = randomInvoiceId();
    // Strict schema: store ONLY invoiceId, derivationIndex, amount, claimHash, coarse expiresAt, paid
    const record: CreditInvoiceRecord = {
      invoiceId,
      derivationIndex,
      amount: resolved.amountUsdc,
      claimHash: normalizedClaimHash,
      expiresAt: expiresAtDate,
      paid: false,
    };

    if (invoiceCol) {
      try {
        await invoiceCol.insertOne({ ...record });
      } catch (err) {
        if (isDuplicateKeyError(err)) {
          const msg = err instanceof Error ? err.message : "";
          if (msg.includes("claimHash")) {
            usedDerivationIndices.delete(derivationIndex);
            return {
              ok: false,
              error: "claimHash has already been used for an invoice",
              status: 409,
            };
          }
          // Collision on derivationIndex or invoiceId: try next index
          continue;
        }
      }
    }

    invoicesById.set(invoiceId, record);
    invoiceIdByClaimHash.set(normalizedClaimHash, invoiceId);

    return {
      ok: true,
      invoiceId,
      depositAddress,
      amountUsdc: resolved.amountUsdc,
      denomination: resolved.denomination,
      chainId: ARC_CREDIT_CHAIN_ID,
      usdcContract: ARC_USDC_ADDRESS,
      usdcDecimals: ARC_USDC_DECIMALS,
      expiresAt: expiresAtMs,
    };
  }

  return {
    ok: false,
    error: "Failed to allocate a unique derivation index for invoice",
    status: 500,
  };
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
    getUsdcTransferLogs: async ({ depositAddress, fromBlock, toBlock }) => {
      const logs = await client.getLogs({
        address: ARC_USDC_ADDRESS,
        event: ERC20_TRANSFER_EVENT,
        args: { to: depositAddress },
        fromBlock,
        toBlock,
      });
      // Strip sender (`args.from` and `topics[1]`) immediately so payer addresses never enter memory or storage
      return logs.map((l) => ({
        address: l.address as Hex,
        blockNumber: l.blockNumber ?? null,
        transactionHash: (l.transactionHash as Hex | null) ?? null,
        logIndex: typeof l.logIndex === "number" ? l.logIndex : null,
        value: typeof l.args?.value === "bigint" ? l.args.value : BigInt(0),
        args: {
          to: (l.args?.to as Hex | undefined) ?? depositAddress,
          value: typeof l.args?.value === "bigint" ? l.args.value : BigInt(0),
        },
      }));
    },
  };
}

function extractTransferLogsToDepositAddress(params: {
  logs: UsdcTransferLogEntry[];
  depositAddress: Hex;
  latestBlock: bigint;
}): {
  paidUnits: bigint;
  minConfirmations: number;
  txHashes: string[];
} {
  const targetLower = params.depositAddress.toLowerCase();
  const usdcLower = ARC_USDC_ADDRESS.toLowerCase();
  let paidUnits = BigInt(0);
  let minConfirmations = Number.MAX_SAFE_INTEGER;
  const txHashes: string[] = [];

  for (const log of params.logs) {
    if (log.address && log.address.toLowerCase() !== usdcLower) {
      continue;
    }

    let recipientMatches = false;
    if (log.args?.to) {
      recipientMatches = log.args.to.toLowerCase() === targetLower;
    } else if (Array.isArray(log.topics) && log.topics.length >= 3) {
      if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
      const toTopic = log.topics[2]?.toLowerCase() ?? "";
      recipientMatches = toTopic.endsWith(targetLower.slice(2));
    } else {
      recipientMatches = true;
    }
    if (!recipientMatches) continue;

    if (log.blockNumber === null || log.blockNumber === undefined) {
      continue;
    }
    if (params.latestBlock < log.blockNumber) {
      continue;
    }
    const confirmations = Number(params.latestBlock - log.blockNumber) + 1;
    if (confirmations < MIN_PAYMENT_CONFIRMATIONS) {
      continue;
    }

    let val = BigInt(0);
    if (typeof log.value === "bigint") {
      val = log.value;
    } else if (typeof log.args?.value === "bigint") {
      val = log.args.value;
    } else if (typeof log.data === "string" && log.data !== "0x") {
      try {
        val = BigInt(log.data);
      } catch {
        val = BigInt(0);
      }
    }

    if (val <= BigInt(0)) continue;

    const txHash = log.transactionHash ? log.transactionHash.toLowerCase() : null;
    if (
      txHash &&
      (redeemedPaymentTxHashes.has(txHash) || inFlightPaymentTxHashes.has(txHash))
    ) {
      continue;
    }

    paidUnits += val;
    if (confirmations < minConfirmations) {
      minConfirmations = confirmations;
    }
    if (txHash && !txHashes.includes(txHash)) {
      txHashes.push(txHash);
    }
  }

  return {
    paidUnits,
    minConfirmations:
      minConfirmations === Number.MAX_SAFE_INTEGER ? 0 : minConfirmations,
    txHashes,
  };
}

/**
 * Claims blind-signed credits for a paid one-time deposit invoice using `claimSecret`.
 * Verifies `sha256(claimSecret) === invoice.claimHash`, checks invoice expiry, scans USDC
 * `Transfer` logs into the invoice's derived one-time `depositAddress` on Arc Testnet (5042002)
 * without ever reading or storing sender addresses, enforces replay protection, and blind-signs.
 */
export async function claimCreditInvoice(params: {
  invoiceId?: string;
  claimSecret: string;
  blindedHexes: string[];
  denomination?: number;
  nowMs?: number;
}): Promise<
  | {
      ok: true;
      invoiceId: string;
      signatures: string[];
      denomination: number;
      keyBits: number;
      creditsGranted: number;
      amountUsdc: string;
      depositAddress: Hex;
      chainId: number;
      confirmations: number;
    }
  | { ok: false; error: string; status: number }
> {
  let hashes: string[];
  try {
    hashes = candidateClaimHashes(params.claimSecret);
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error
          ? err.message
          : "Invalid claimSecret: expected 32-byte hex string",
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

  const invoiceCol = process.env.VITEST ? null : await getInvoiceCollection();
  const paymentCol = process.env.VITEST ? null : await getPaymentCollection();

  let invoice: CreditInvoiceRecord | null = null;
  const trimmedInvoiceId =
    typeof params.invoiceId === "string" ? params.invoiceId.trim() : "";

  if (trimmedInvoiceId) {
    invoice = invoicesById.get(trimmedInvoiceId) ?? null;
    if (!invoice && invoiceCol) {
      try {
        const found = await invoiceCol.findOne(
          { invoiceId: trimmedInvoiceId },
          { projection: { _id: 0 } }
        );
        if (found) {
          invoice = {
            invoiceId: found.invoiceId,
            derivationIndex: found.derivationIndex,
            amount: found.amount,
            claimHash: found.claimHash,
            expiresAt:
              found.expiresAt instanceof Date
                ? found.expiresAt
                : new Date(String(found.expiresAt)),
            paid: Boolean(found.paid),
          };
          invoicesById.set(invoice.invoiceId, invoice);
          invoiceIdByClaimHash.set(invoice.claimHash, invoice.invoiceId);
        }
      } catch {
        // Proceed with null check
      }
    }
  } else {
    for (const h of hashes) {
      const id = invoiceIdByClaimHash.get(h);
      if (id && invoicesById.has(id)) {
        invoice = invoicesById.get(id)!;
        break;
      }
    }
    if (!invoice && invoiceCol) {
      try {
        const found = await invoiceCol.findOne(
          { claimHash: { $in: hashes } },
          { projection: { _id: 0 } }
        );
        if (found) {
          invoice = {
            invoiceId: found.invoiceId,
            derivationIndex: found.derivationIndex,
            amount: found.amount,
            claimHash: found.claimHash,
            expiresAt:
              found.expiresAt instanceof Date
                ? found.expiresAt
                : new Date(String(found.expiresAt)),
            paid: Boolean(found.paid),
          };
          invoicesById.set(invoice.invoiceId, invoice);
          invoiceIdByClaimHash.set(invoice.claimHash, invoice.invoiceId);
        }
      } catch {
        // Proceed with null check
      }
    }
  }

  if (!invoice) {
    return {
      ok: false,
      error: "Invoice not found",
      status: 404,
    };
  }

  const secretMatches = hashes.some((h) =>
    constantTimeHexEqual(h, invoice!.claimHash)
  );
  if (!secretMatches) {
    return {
      ok: false,
      error: "Invalid claimSecret: sha256(claimSecret) does not match invoice claimHash",
      status: 403,
    };
  }

  const invoiceCredits = AMOUNT_USDC_TO_DENOMINATION[invoice.amount];
  if (!invoiceCredits) {
    return {
      ok: false,
      error: `Invoice has unsupported denomination amount ${invoice.amount}`,
      status: 400,
    };
  }

  const tokenDenomination =
    params.denomination ??
    (params.blindedHexes.length === 1 ? invoiceCredits : 1);
  if (!CREDIT_DENOMINATIONS.includes(tokenDenomination)) {
    return {
      ok: false,
      error: `Invalid denomination ${tokenDenomination}. Must be one of ${CREDIT_DENOMINATIONS.join(
        ", "
      )}`,
      status: 400,
    };
  }

  const requestedCredits = params.blindedHexes.length * tokenDenomination;
  if (requestedCredits !== invoiceCredits) {
    return {
      ok: false,
      error: `Requested credits (${params.blindedHexes.length} * ${tokenDenomination} = ${requestedCredits}) must match fixed invoice denomination (${invoiceCredits} credit(s) for ${invoice.amount} USDC)`,
      status: 400,
    };
  }

  if (invoice.paid || inFlightClaims.has(invoice.invoiceId)) {
    return {
      ok: false,
      error: "Invoice has already been claimed",
      status: 409,
    };
  }

  const nowMs = params.nowMs ?? Date.now();
  const expiresAtMs = invoice.expiresAt.getTime();
  if (nowMs >= expiresAtMs) {
    return {
      ok: false,
      error: "Invoice has expired",
      status: 410,
    };
  }

  inFlightClaims.add(invoice.invoiceId);
  try {
    const depositAddress = deriveDepositAddress(invoice.derivationIndex);
    const client = buildArcPaymentVerifierClient();

    let chainId: number;
    let latestBlock: bigint;
    let logs: UsdcTransferLogEntry[];
    try {
      [chainId, latestBlock] = await Promise.all([
        client.getChainId(),
        client.getBlockNumber(),
      ]);
      if (chainId !== ARC_CREDIT_CHAIN_ID) {
        return {
          ok: false,
          error: `Wrong RPC chainId ${chainId}; expected Arc testnet (${ARC_CREDIT_CHAIN_ID})`,
          status: 400,
        };
      }
      // Arc Testnet RPC supports up to 10,000 blocks per eth_getLogs query
      const fromBlock =
        latestBlock > BigInt(9000) ? latestBlock - BigInt(9000) : BigInt(0);
      logs = await client.getUsdcTransferLogs({
        depositAddress,
        fromBlock,
        toBlock: latestBlock,
      });
    } catch (err) {
      const detail =
        err instanceof Error
          ? err.message
          : "Failed to query USDC Transfer logs on Arc testnet";
      return {
        ok: false,
        error: `Could not verify deposit logs on Arc testnet: ${detail.slice(0, 140)}`,
        status: 400,
      };
    }

    const extracted = extractTransferLogsToDepositAddress({
      logs,
      depositAddress,
      latestBlock,
    });

    if (extracted.paidUnits <= BigInt(0)) {
      return {
        ok: false,
        error: `No confirmed USDC Transfer log found to one-time deposit address ${depositAddress}`,
        status: 400,
      };
    }

    const requiredUnits = FIXED_INVOICE_UNITS[invoiceCredits];
    if (extracted.paidUnits < requiredUnits) {
      return {
        ok: false,
        error: `Insufficient USDC deposit: received ${formatUnits(
          extracted.paidUnits,
          ARC_USDC_DECIMALS
        )} USDC, need ${invoice.amount} USDC for ${invoiceCredits} credit(s)`,
        status: 400,
      };
    }

    const paymentTxKey =
      extracted.txHashes[0] ?? `invoice:${invoice.invoiceId}`;
    if (
      redeemedPaymentTxHashes.has(paymentTxKey) ||
      inFlightPaymentTxHashes.has(paymentTxKey)
    ) {
      return {
        ok: false,
        error: "Deposit payment has already been redeemed for blind credits",
        status: 409,
      };
    }

    if (paymentCol) {
      try {
        const existingPayment = await paymentCol.findOne(
          { txHash: paymentTxKey },
          { projection: { txHash: 1, amount: 1, _id: 0 } }
        );
        if (existingPayment) {
          redeemedPaymentTxHashes.set(paymentTxKey, {
            txHash: existingPayment.txHash,
            amount: existingPayment.amount,
          });
          return {
            ok: false,
            error: "Deposit payment has already been redeemed for blind credits",
            status: 409,
          };
        }
      } catch {
        // Proceed to atomic update
      }
    }

    // Sign blinded tokens before marking paid so malformed hex never burns a valid deposit
    let minted: { signatures: string[]; denomination: number; keyBits: number };
    try {
      minted = mintBlindedBatch(params.blindedHexes, tokenDenomination);
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : "Invalid blinded tokens",
        status: 400,
      };
    }

    inFlightPaymentTxHashes.add(paymentTxKey);
    try {
      if (invoiceCol) {
        try {
          const updateRes = await invoiceCol.updateOne(
            { invoiceId: invoice.invoiceId, paid: false },
            { $set: { paid: true } }
          );
          if (updateRes.matchedCount === 0) {
            invoice.paid = true;
            return {
              ok: false,
              error: "Invoice has already been claimed",
              status: 409,
            };
          }
        } catch {
          // Best-effort persistence on transient error
        }
      }

      const paymentRecord: CreditPaymentRecord = {
        txHash: paymentTxKey,
        amount: invoice.amount,
      };

      if (paymentCol) {
        try {
          await paymentCol.insertOne({ ...paymentRecord });
        } catch (err) {
          if (isDuplicateKeyError(err)) {
            redeemedPaymentTxHashes.set(paymentTxKey, paymentRecord);
            return {
              ok: false,
              error: "Deposit payment has already been redeemed for blind credits",
              status: 409,
            };
          }
        }
      }

      invoice.paid = true;
      redeemedPaymentTxHashes.set(paymentTxKey, paymentRecord);

      return {
        ok: true,
        invoiceId: invoice.invoiceId,
        signatures: minted.signatures,
        denomination: minted.denomination,
        keyBits: minted.keyBits,
        creditsGranted: invoiceCredits,
        amountUsdc: invoice.amount,
        depositAddress,
        chainId: ARC_CREDIT_CHAIN_ID,
        confirmations: extracted.minConfirmations,
      };
    } finally {
      inFlightPaymentTxHashes.delete(paymentTxKey);
    }
  } finally {
    inFlightClaims.delete(invoice.invoiceId);
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

    const col = process.env.VITEST ? null : await getNullifierCollection();
    if (col) {
      try {
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
    const col = process.env.VITEST ? null : await getNullifierCollection();
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
  activeInvoices: number;
} {
  let unpaidCount = 0;
  invoicesById.forEach((inv) => {
    if (!inv.paid) unpaidCount++;
  });
  return {
    spentCount: spentNullifiers.size,
    unredeemedCount: countUnredeemed(),
    redeemedBatches: redeemedBatchesCount,
    paidRedemptions: redeemedPaymentTxHashes.size,
    activeInvoices: unpaidCount,
  };
}
