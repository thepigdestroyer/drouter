import { afterEach, describe, expect, it, vi } from "vitest";

const connectionSpy = vi.fn(async () => {});
const cacheLifeSpy = vi.fn();

vi.mock("next/server", () => ({
  connection: () => connectionSpy(),
}));

vi.mock("next/cache", () => ({
  cacheLife: (arg: unknown) => cacheLifeSpy(arg),
}));

import {
  GET,
  OPTIONAL_ENV_NAMES,
  REQUIRED_ENV_NAMES,
  runHealthChecks,
} from "@/app/api/health/route";

describe("GET /api/health (Interface I4)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    connectionSpy.mockClear();
    cacheLifeSpy.mockClear();
  });

  const sampleSecretValues: Record<string, string> = {
    TINFOIL_API_KEY: "tf-super-secret-value-alpha-9001",
    MONGODB_URI: "mongodb+srv://drouter-app:mongo-secret-pass-777@cluster.mongodb.net/drouter",
    MONGODB_DB: "drouter",
    ARC_RPC_URL: "https://rpc.testnet.arc.network/secret-key-888",
    ARC_REGISTRY_ADDRESS: "0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
    ARC_VERIFIER_PRIVATE_KEY: "0xdeadbeefcafebabe11223344556677889900aabbccddeeff0011223344556677",
    SIM_HARDWARE_SEED: "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0",
    CREDITS_ISSUER_RSA_PQ: "primeP_secret_hex_111:primeQ_secret_hex_222",
    CRON_SECRET: "cron-secret-token-333",
    GEMINI_API_KEY: "AIzaSySecretGeminiKey444",
    VOYAGE_API_KEY: "pa-secret-voyage-key-555",
  };

  it("returns ok: true when MongoDB ping, Arc RPC block number, Tinfoil attestation, and required env vars all pass, and never leaks secret values", async () => {
    const pingMongo = vi.fn(async () => {});
    const getArcBlockNumber = vi.fn(async () => BigInt(4_815_162));
    const fetchAttestation = vi.fn(async () => ({ ok: true, status: 200 }));

    const result = await runHealthChecks({
      env: sampleSecretValues,
      pingMongo,
      getArcBlockNumber,
      fetchAttestation,
    });

    expect(result.ok).toBe(true);
    expect(result.checks.mongodb).toEqual({
      ok: true,
      detail: "MongoDB ping succeeded on database drouter",
    });
    expect(result.checks.arcRpc).toEqual({
      ok: true,
      detail: "Arc Testnet RPC reachable at block 4815162",
    });
    expect(result.checks.tinfoilAttestation).toEqual({
      ok: true,
      detail: "Tinfoil attestation endpoint reachable (HTTP 200)",
    });
    expect(result.checks.env.ok).toBe(true);
    for (const reqName of REQUIRED_ENV_NAMES) {
      expect(result.checks.env.detail).toContain(reqName);
    }

    // Critical security invariant: no secret value may ever appear in the serialized response
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("tf-super-secret-value-alpha-9001");
    expect(serialized).not.toContain("mongo-secret-pass-777");
    expect(serialized).not.toContain("secret-key-888");
    expect(serialized).not.toContain("deadbeefcafebabe11223344556677889900aabbccddeeff0011223344556677");
    expect(serialized).not.toContain("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0");
    expect(serialized).not.toContain("primeP_secret_hex_111");
    expect(serialized).not.toContain("cron-secret-token-333");
    expect(serialized).not.toContain("AIzaSySecretGeminiKey444");
    expect(serialized).not.toContain("pa-secret-voyage-key-555");
  });

  it("reports missing required env vars by name only and sets ok: false", async () => {
    const partialEnv: Record<string, string | undefined> = {
      ...sampleSecretValues,
      TINFOIL_API_KEY: "",
      CREDITS_ISSUER_RSA_PQ: undefined,
    };

    const result = await runHealthChecks({
      env: partialEnv,
      pingMongo: async () => {},
      getArcBlockNumber: async () => BigInt(100),
      fetchAttestation: async () => ({ ok: true, status: 200 }),
    });

    expect(result.ok).toBe(false);
    expect(result.checks.env.ok).toBe(false);
    expect(result.checks.env.detail).toContain("TINFOIL_API_KEY");
    expect(result.checks.env.detail).toContain("CREDITS_ISSUER_RSA_PQ");
    expect(result.checks.mongodb.ok).toBe(true);
    expect(result.checks.arcRpc.ok).toBe(true);
    expect(result.checks.tinfoilAttestation.ok).toBe(true);
  });

  it("handles individual upstream failures (MongoDB, Arc RPC, Tinfoil attestation) cleanly without throwing or leaking error strings", async () => {
    const result = await runHealthChecks({
      env: sampleSecretValues,
      pingMongo: async () => {
        throw new Error("MongoServerSelectionError: connection refused to mongodb+srv://drouter-app:mongo-secret-pass-777@cluster");
      },
      getArcBlockNumber: async () => {
        throw new Error("HttpRequestError: https://rpc.testnet.arc.network/secret-key-888 timed out");
      },
      fetchAttestation: async () => ({ ok: false, status: 503 }),
    });

    expect(result.ok).toBe(false);
    expect(result.checks.mongodb).toEqual({
      ok: false,
      detail: "MongoDB ping failed on database drouter",
    });
    expect(result.checks.arcRpc).toEqual({
      ok: false,
      detail: "Arc Testnet RPC unreachable",
    });
    expect(result.checks.tinfoilAttestation).toEqual({
      ok: false,
      detail: "Tinfoil attestation endpoint returned HTTP 503",
    });
    expect(result.checks.env.ok).toBe(true);

    // Ensure thrown error messages containing credentials are never echoed in detail
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("mongo-secret-pass-777");
    expect(serialized).not.toContain("secret-key-888");
  });

  it("calls await connection(), configures 30-second cacheLife, and returns JSON in GET route handler", async () => {
    const prevStub = process.env.DROUTER_STUB_UPSTREAM;
    process.env.DROUTER_STUB_UPSTREAM = "1";
    try {
      const res = await GET();
      expect(connectionSpy).toHaveBeenCalledTimes(1);
      expect(cacheLifeSpy).toHaveBeenCalledWith({
        stale: 30,
        revalidate: 30,
        expire: 60,
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Cache-Control")).toContain("max-age=30");

      const body = (await res.json()) as {
        ok: boolean;
        checks: Record<string, { ok: boolean; detail: string }>;
      };
      expect(typeof body.ok).toBe("boolean");
      expect(body.checks.mongodb.ok).toBe(true);
      expect(body.checks.arcRpc.ok).toBe(true);
      expect(body.checks.tinfoilAttestation.ok).toBe(true);
      expect(body.checks.env).toBeDefined();
      expect(OPTIONAL_ENV_NAMES).toContain("CRON_SECRET");
      expect(OPTIONAL_ENV_NAMES).toContain("GEMINI_API_KEY");
      expect(OPTIONAL_ENV_NAMES).toContain("VOYAGE_API_KEY");
    } finally {
      if (prevStub === undefined) {
        delete process.env.DROUTER_STUB_UPSTREAM;
      } else {
        process.env.DROUTER_STUB_UPSTREAM = prevStub;
      }
    }
  });
});
