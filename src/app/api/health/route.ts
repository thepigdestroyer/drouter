import { cacheLife } from "next/cache";
import { connection } from "next/server";
import { MongoClient } from "mongodb";
import { arcTestnet } from "viem/chains";
import { createPublicClient, defineChain, http } from "viem";
import { ATC_ATTESTATION_URL } from "@/lib/relay";

export interface HealthCheckItem {
  ok: boolean;
  detail: string;
}

export interface HealthResponse {
  ok: boolean;
  checks: Record<string, HealthCheckItem>;
}

export const REQUIRED_ENV_NAMES = [
  "TINFOIL_API_KEY",
  "MONGODB_URI",
  "ARC_RPC_URL",
  "ARC_REGISTRY_ADDRESS",
  "ARC_VERIFIER_PRIVATE_KEY",
  "SIM_HARDWARE_SEED",
  "CREDITS_ISSUER_RSA_PQ",
] as const;

export const OPTIONAL_ENV_NAMES = [
  "MONGODB_DB",
  "NEXT_PUBLIC_ARC_REGISTRY_ADDRESS",
  "ARC_DEPLOYER_PRIVATE_KEY",
  "CREDITS_ISSUER_SEED",
  "ATLAS_INGEST_TOKEN",
  "CRON_SECRET",
  "GEMINI_API_KEY",
  "VOYAGE_API_KEY",
  "VOYAGE_MODEL",
] as const;

export interface HealthDependencies {
  env?: Record<string, string | undefined>;
  pingMongo?: (uri: string, dbName: string) => Promise<void>;
  getArcBlockNumber?: (rpcUrl: string) => Promise<bigint>;
  fetchAttestation?: (url: string) => Promise<{ ok: boolean; status: number }>;
}

const globalForHealthMongo = globalThis as unknown as {
  __drouterHealthMongo?: Promise<MongoClient>;
  __drouterHealthMongoUri?: string;
};

async function defaultPingMongo(uri: string, dbName: string): Promise<void> {
  if (globalForHealthMongo.__drouterHealthMongoUri !== uri) {
    globalForHealthMongo.__drouterHealthMongo = undefined;
    globalForHealthMongo.__drouterHealthMongoUri = uri;
  }
  globalForHealthMongo.__drouterHealthMongo ??= new MongoClient(uri, {
    appName: "drouter-health",
    maxPoolSize: 2,
    serverSelectionTimeoutMS: 4_000,
    connectTimeoutMS: 4_000,
  }).connect();

  try {
    const client = await globalForHealthMongo.__drouterHealthMongo;
    await client.db(dbName).command({ ping: 1 });
  } catch (err) {
    globalForHealthMongo.__drouterHealthMongo = undefined;
    throw err;
  }
}

async function defaultGetArcBlockNumber(rpcUrl: string): Promise<bigint> {
  const customChain = defineChain({
    ...arcTestnet,
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  const client = createPublicClient({
    chain: customChain,
    transport: http(rpcUrl, { timeout: 5_000, retryCount: 0 }),
  });
  return client.getBlockNumber();
}

async function defaultFetchAttestation(
  url: string,
): Promise<{ ok: boolean; status: number }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const res = await fetch(url, {
      method: "GET",
      cache: "no-store",
      signal: controller.signal,
    });
    return { ok: res.ok, status: res.status };
  } finally {
    clearTimeout(timer);
  }
}

function hasNonEmptyEnv(
  env: Record<string, string | undefined>,
  name: string,
): boolean {
  const val = env[name];
  return typeof val === "string" && val.trim().length > 0;
}

export async function runHealthChecks(
  deps: HealthDependencies = {},
): Promise<HealthResponse> {
  const env = deps.env ?? process.env;
  const pingMongo = deps.pingMongo ?? defaultPingMongo;
  const getArcBlockNumber = deps.getArcBlockNumber ?? defaultGetArcBlockNumber;
  const fetchAttestation = deps.fetchAttestation ?? defaultFetchAttestation;

  const isStub = env.DROUTER_STUB_UPSTREAM === "1";

  // 1. Required env vars check (by name only; never inspect or return secret values)
  const presentRequired: string[] = [];
  const missingRequired: string[] = [];
  for (const name of REQUIRED_ENV_NAMES) {
    if (hasNonEmptyEnv(env, name)) {
      presentRequired.push(name);
    } else {
      missingRequired.push(name);
    }
  }
  const presentOptional = OPTIONAL_ENV_NAMES.filter((name) =>
    hasNonEmptyEnv(env, name),
  );

  const envCheck: HealthCheckItem =
    missingRequired.length === 0
      ? {
          ok: true,
          detail: `All ${REQUIRED_ENV_NAMES.length} required variables present (${REQUIRED_ENV_NAMES.join(", ")}); optional present: ${presentOptional.length > 0 ? presentOptional.join(", ") : "none"}`,
        }
      : {
          ok: false,
          detail: `Missing required variables: ${missingRequired.join(", ")}; present: ${presentRequired.length > 0 ? presentRequired.join(", ") : "none"}`,
        };

  // 2. MongoDB ping check
  const mongoPromise = (async (): Promise<HealthCheckItem> => {
    if (isStub) {
      return { ok: true, detail: "MongoDB ping stubbed (DROUTER_STUB_UPSTREAM=1)" };
    }
    const uri = env.MONGODB_URI;
    if (!uri || uri.trim().length === 0) {
      return { ok: false, detail: "MONGODB_URI is not configured" };
    }
    const dbName =
      env.MONGODB_DB && env.MONGODB_DB.trim().length > 0
        ? env.MONGODB_DB.trim()
        : "drouter";
    try {
      await pingMongo(uri, dbName);
      return { ok: true, detail: `MongoDB ping succeeded on database ${dbName}` };
    } catch {
      return { ok: false, detail: `MongoDB ping failed on database ${dbName}` };
    }
  })();

  // 3. Arc RPC block number check
  const arcPromise = (async (): Promise<HealthCheckItem> => {
    if (isStub) {
      return { ok: true, detail: "Arc RPC block number stubbed (DROUTER_STUB_UPSTREAM=1)" };
    }
    const rpcUrl =
      env.ARC_RPC_URL && env.ARC_RPC_URL.trim().length > 0
        ? env.ARC_RPC_URL.trim()
        : arcTestnet.rpcUrls.default.http[0];
    try {
      const blockNumber = await getArcBlockNumber(rpcUrl);
      if (typeof blockNumber === "bigint" && blockNumber >= BigInt(0)) {
        return {
          ok: true,
          detail: `Arc Testnet RPC reachable at block ${blockNumber.toString(10)}`,
        };
      }
      return { ok: false, detail: "Arc Testnet RPC returned invalid block number" };
    } catch {
      return { ok: false, detail: "Arc Testnet RPC unreachable" };
    }
  })();

  // 4. Tinfoil attestation endpoint check
  const tinfoilPromise = (async (): Promise<HealthCheckItem> => {
    if (isStub) {
      return {
        ok: true,
        detail: "Tinfoil attestation endpoint stubbed (DROUTER_STUB_UPSTREAM=1)",
      };
    }
    try {
      const res = await fetchAttestation(ATC_ATTESTATION_URL);
      if (res.ok) {
        return {
          ok: true,
          detail: `Tinfoil attestation endpoint reachable (HTTP ${res.status})`,
        };
      }
      return {
        ok: false,
        detail: `Tinfoil attestation endpoint returned HTTP ${res.status}`,
      };
    } catch {
      return {
        ok: false,
        detail: "Tinfoil attestation endpoint unreachable",
      };
    }
  })();

  const [mongodb, arcRpc, tinfoilAttestation] = await Promise.all([
    mongoPromise,
    arcPromise,
    tinfoilPromise,
  ]);

  const checks: Record<string, HealthCheckItem> = {
    mongodb,
    arcRpc,
    tinfoilAttestation,
    env: envCheck,
  };

  const ok = Object.values(checks).every((c) => c.ok);
  return { ok, checks };
}

async function loadCachedHealth(): Promise<HealthResponse> {
  "use cache";
  cacheLife({ stale: 30, revalidate: 30, expire: 60 });
  return runHealthChecks();
}

export async function GET(): Promise<Response> {
  await connection();
  const report = await loadCachedHealth();
  return Response.json(report, {
    status: 200,
    headers: {
      "Cache-Control": "public, max-age=30, s-maxage=30, stale-while-revalidate=30",
    },
  });
}
