import { afterEach, describe, expect, it, vi } from "vitest";
import { deriveIssuerKey } from "@/lib/credits/blind";

const DEMO_SEED = "64726f757465722d6761756e746c65742d726f756e642d322d697373756572";

describe("credit issuer key outside the server", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("derives the demo key in a production browser without reading server secrets", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("CREDITS_ISSUER_RSA_PQ", "");
    vi.stubGlobal("window", {});
    const key = deriveIssuerKey(DEMO_SEED);
    expect(key.n.length).toBeGreaterThan(0);
    expect(key.e).toBe("010001");
  });

  it("still refuses to issue on a production server without the issuer key", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("CREDITS_ISSUER_RSA_PQ", "");
    expect(() => deriveIssuerKey("ab".repeat(16))).toThrow(/CREDITS_ISSUER_RSA_PQ must be set/);
  });
});
