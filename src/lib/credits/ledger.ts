import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { MongoClient } from "mongodb";
import type { BlindCreditToken } from "@/lib/types";
import {
  CREDIT_DENOMINATIONS,
  getPublicKey,
  nullifierFor,
  signBlinded,
  verifyTokenSignature,
} from "./blind";

export interface NullifierRecord {
  nullifier: string;
  denomination: number;
  nodeId: string;
  spentAt: number;
  redeemed: boolean;
}

const spentNullifiers = new Map<string, NullifierRecord>();
let redeemedBatchesCount = 0;

let mongoClientPromise: Promise<MongoClient | null> | null = null;

function getIssuerSeed(): string {
  return (
    process.env.CREDITS_ISSUER_SEED ||
    process.env.SIM_HARDWARE_SEED ||
    "01".repeat(32)
  );
}

async function getMongoCollection() {
  const uri = process.env.MONGODB_URI;
  if (!uri) return null;

  try {
    if (!mongoClientPromise) {
      const client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 1500,
        connectTimeoutMS: 1500,
      });
      mongoClientPromise = client
        .connect()
        .then(() => client)
        .catch(() => null);
    }
    const client = await mongoClientPromise;
    if (!client) return null;
    const dbName = process.env.MONGODB_DB || "drouter";
    return client.db(dbName).collection<NullifierRecord>("credit_nullifiers");
  } catch {
    return null;
  }
}

export function issuerPublicInfo(): {
  n: string;
  e: string;
  denominations: number[];
} {
  return getPublicKey(getIssuerSeed());
}

export function mintBlindedBatch(
  blindedHexes: string[],
  denomination = 1
): { signatures: string[]; denomination: number } {
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
  const signatures = blindedHexes.map((b) => {
    if (typeof b !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(b.trim())) {
      throw new Error("Invalid hex in blinded token batch");
    }
    return signBlinded(b, denomination, seed);
  });

  return { signatures, denomination };
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
  | { ok: true; nullifier: string; remainingPoolUnredeemed: number }
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

  if (spentNullifiers.has(nullifier)) {
    return {
      ok: false,
      error: "Double-spend rejected: credit nullifier already spent",
      status: 409,
    };
  }

  const col = await getMongoCollection();
  if (col) {
    try {
      const existing = await col.findOne({ nullifier });
      if (existing) {
        spentNullifiers.set(nullifier, {
          nullifier: existing.nullifier,
          denomination: existing.denomination,
          nodeId: existing.nodeId,
          spentAt: existing.spentAt,
          redeemed: existing.redeemed,
        });
        return {
          ok: false,
          error: "Double-spend rejected: credit nullifier already spent",
          status: 409,
        };
      }
    } catch {
      // Best-effort Mongo check
    }
  }

  const record: NullifierRecord = {
    nullifier,
    denomination: token.denomination,
    nodeId,
    spentAt: Date.now(),
    redeemed: false,
  };

  spentNullifiers.set(nullifier, record);

  if (col) {
    try {
      await col.insertOne({ ...record });
    } catch {
      // Best-effort Mongo persistence
    }
  }

  return {
    ok: true,
    nullifier,
    remainingPoolUnredeemed: countUnredeemed(),
  };
}

export async function redeemBatch(nodeId?: string): Promise<{
  redeemedCount: number;
  totalCredits: number;
  batchHash: string;
  timestamp: number;
}> {
  const timestamp = Date.now();
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
    const col = await getMongoCollection();
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
} {
  return {
    spentCount: spentNullifiers.size,
    unredeemedCount: countUnredeemed(),
    redeemedBatches: redeemedBatchesCount,
  };
}
