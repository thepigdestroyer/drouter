import { beforeEach, describe, expect, it } from "vitest";
import { HONEST_LIMITS } from "@/app/about/page";
import {
  CATALOG_VERIFIED_ON,
  CONFIDENTIAL_PROVIDERS,
  SPEC_V2_ROADMAP,
  filterProviders,
} from "@/lib/providers/catalog";
import {
  PROVIDER_LIVE_CACHE_TTL_MS,
  clearProviderLiveStatusCache,
  getAllProvidersLiveStatus,
  getProviderLiveStatus,
  type FetchLike,
} from "@/lib/providers/live-status";

describe("Frontier Confidential Provider Directory & Spec v2 Roadmap", () => {
  beforeEach(() => {
    clearProviderLiveStatusCache();
  });

  it("contains all 10 confidential TEE providers with complete metadata, sourceUrl, verifiedOn date, and no em dashes", () => {
    expect(CONFIDENTIAL_PROVIDERS).toHaveLength(10);

    const ids = CONFIDENTIAL_PROVIDERS.map((p) => p.id);
    expect(ids).toEqual([
      "tinfoil",
      "phala-redpill",
      "near-ai-cloud",
      "venice-ai",
      "prem-ai",
      "ppq-ai",
      "confidential-ai",
      "chutes-bittensor",
      "privatemode-cosmian",
      "nanogpt",
    ]);

    for (const provider of CONFIDENTIAL_PROVIDERS) {
      expect(provider.name.length).toBeGreaterThan(1);
      expect(provider.url).toMatch(/^https:\/\//);
      expect(provider.docsUrl).toMatch(/^https:\/\//);
      expect(provider.sourceUrl).toMatch(
        /^https:\/\/confidentialinference\.net\/providers\//,
      );
      expect(provider.verifiedOn).toBe(CATALOG_VERIFIED_ON);
      expect(typeof provider.verified).toBe("boolean");
      expect(provider.verificationSummary.length).toBeGreaterThan(20);
      expect(provider.cpuTee.length).toBeGreaterThan(2);
      expect(provider.gpuTee.length).toBeGreaterThan(2);
      expect(provider.frontierModels.length).toBeGreaterThanOrEqual(3);
      expect(provider.inputUsdPerM).toMatch(/^\$\d+\.\d+\+\/M$/);
      expect(provider.trustNotes.length).toBeGreaterThan(40);
      expect(provider.trustNotes).not.toContain("\u2014");
      expect(provider.verificationSummary).not.toContain("\u2014");
    }
  });

  it("attaches a sourceUrl, verifiedOn date, and verified/unverified status to every hardware, models, channelSecurity, and pricing claim", () => {
    for (const provider of CONFIDENTIAL_PROVIDERS) {
      const claimKeys = [
        "hardware",
        "models",
        "channelSecurity",
        "pricing",
      ] as const;
      for (const key of claimKeys) {
        const claim = provider.claims[key];
        expect(claim).toBeDefined();
        expect(claim.claim.length).toBeGreaterThan(15);
        expect(claim.claim).not.toContain("\u2014");
        expect(claim.sourceUrl).toMatch(/^https:\/\//);
        expect(claim.verifiedOn).toBe("2026-10-24");
        expect(["verified", "unverified"]).toContain(claim.status);
      }
    }

    // Tinfoil has all 4 claims verified
    const tinfoil = CONFIDENTIAL_PROVIDERS.find((p) => p.id === "tinfoil")!;
    expect(tinfoil.claims.hardware.status).toBe("verified");
    expect(tinfoil.claims.models.status).toBe("verified");
    expect(tinfoil.claims.channelSecurity.status).toBe("verified");
    expect(tinfoil.claims.pricing.status).toBe("verified");

    // Providers with incomplete route/hardware evidence have unverified hardware/channel claims
    const unverifiedProviders = CONFIDENTIAL_PROVIDERS.filter(
      (p) => p.id !== "tinfoil",
    );
    for (const p of unverifiedProviders) {
      expect(p.verified).toBe(false);
      const hasUnverifiedClaim =
        p.claims.hardware.status === "unverified" ||
        p.claims.channelSecurity.status === "unverified" ||
        p.claims.pricing.status === "unverified";
      expect(hasUnverifiedClaim).toBe(true);
    }

    // Confidential AI does not invent non-existent enterprise models and notes request-capacity models accurately
    const confAi = CONFIDENTIAL_PROVIDERS.find(
      (p) => p.id === "confidential-ai",
    )!;
    expect(confAi.frontierModels[0]).toContain("DeepSeek V4 Flash");
    expect(
      confAi.frontierModels.some((m) => m.includes("DeepSeek R1")),
    ).toBe(false);
  });

  it("marks Tinfoil as live-integrated and verified, and separates E2EE vs gateway-tee-only providers", () => {
    const tinfoil = CONFIDENTIAL_PROVIDERS.find((p) => p.id === "tinfoil");
    expect(tinfoil).toBeDefined();
    expect(tinfoil?.statusInDrouter).toBe("live-integrated");
    expect(tinfoil?.verified).toBe(true);
    expect(tinfoil?.channelSecurity).toBe(
      "HPKE Encrypted HTTP Body (EHBP, RFC 9180) + Attested TLS",
    );

    const e2eeProviders = filterProviders({ requireE2ee: true });
    expect(e2eeProviders).toHaveLength(7);
    expect(
      e2eeProviders.every((p) => p.statusInDrouter !== "gateway-tee-only"),
    ).toBe(true);
  });

  it("filters providers by model query ('Kimi'), E2EE requirement, and PQC hybrid support", () => {
    const kimiProviders = filterProviders({ modelQuery: "Kimi" });
    const kimiIds = kimiProviders.map((p) => p.id);
    expect(kimiIds).toEqual([
      "tinfoil",
      "near-ai-cloud",
      "venice-ai",
      "ppq-ai",
      "confidential-ai",
      "chutes-bittensor",
      "nanogpt",
    ]);

    const pqcProviders = filterProviders({ requirePqc: true });
    expect(pqcProviders.map((p) => p.id)).toEqual([
      "tinfoil",
      "phala-redpill",
      "venice-ai",
      "prem-ai",
      "ppq-ai",
      "confidential-ai",
      "privatemode-cosmian",
      "nanogpt",
    ]);

    const kimiE2eePqc = filterProviders({
      modelQuery: "Kimi",
      requireE2ee: true,
      requirePqc: true,
    });
    expect(kimiE2eePqc.map((p) => p.id)).toEqual([
      "tinfoil",
      "venice-ai",
      "ppq-ai",
      "confidential-ai",
    ]);
  });

  it("fetches live provider status and caches responses for 1 hour (one fetch per provider per hour)", async () => {
    let fetchCount = 0;
    const mockFetch: FetchLike = async (url) => {
      fetchCount += 1;
      if (url.includes("atc.tinfoil.sh")) {
        return {
          ok: true,
          status: 200,
          async json() {
            return {
              domain: "router-0.tinfoil.sh",
              digest:
                "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
            };
          },
        };
      }
      if (url.includes("gateway.prem.io")) {
        return {
          ok: false,
          status: 401,
          async json() {
            return { error: "Unauthorized" };
          },
        };
      }
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            data: [{ id: "private/kimi-k3", privacyLevel: "e2e" }],
          };
        },
      };
    };

    const t0 = 1_760_000_000_000;
    const status1 = await getProviderLiveStatus("tinfoil", {
      fetchFn: mockFetch,
      nowMs: t0,
    });
    expect(status1.reachable).toBe(true);
    expect(status1.attestationResponds).toBe(true);
    expect(status1.cacheTtlSeconds).toBe(3600);
    expect(fetchCount).toBe(1);

    // Calling again 30 minutes later must hit the 1-hour cache without fetching again
    const status2 = await getProviderLiveStatus("tinfoil", {
      fetchFn: mockFetch,
      nowMs: t0 + 30 * 60 * 1000,
    });
    expect(status2).toEqual(status1);
    expect(fetchCount).toBe(1);

    // Calling after 1 hour + 1 ms expires the cache and triggers a fresh fetch
    const status3 = await getProviderLiveStatus("tinfoil", {
      fetchFn: mockFetch,
      nowMs: t0 + PROVIDER_LIVE_CACHE_TTL_MS + 1,
    });
    expect(status3.reachable).toBe(true);
    expect(fetchCount).toBe(2);

    // Auth-gated endpoint (Prem) reports auth required
    const premStatus = await getProviderLiveStatus("prem-ai", {
      fetchFn: mockFetch,
      nowMs: t0,
    });
    expect(premStatus.reachable).toBe(false);
    expect(premStatus.statusLabel).toContain("Auth required");

    // All 10 providers return structured live status
    const allStatuses = await getAllProvidersLiveStatus();
    expect(Object.keys(allStatuses)).toHaveLength(10);
  });

  it("includes accurate HONEST_LIMITS covering small CKKS FHE linear classifier, Vercel Sandbox Firecracker microVM, Kimi K3 262,144 limit, Tinfoil sidecars, and simulated nodes", () => {
    expect(HONEST_LIMITS.length).toBeGreaterThanOrEqual(8);
    const combinedText = HONEST_LIMITS.map(
      (l) => `${l.title} ${l.detail}`,
    ).join(" ");
    expect(combinedText).toContain("262,144");
    expect(combinedText).toContain("gpt-oss-safeguard-120b");
    expect(combinedText).toContain("CKKS");
    expect(combinedText).toContain("Firecracker microVM");
    expect(combinedText).toContain("SIM_HARDWARE_SEED");
    for (const item of HONEST_LIMITS) {
      expect(item.title).not.toContain("\u2014");
      expect(item.detail).not.toContain("\u2014");
    }
  });

  it("exports 5 complete SPEC_V2_ROADMAP architectural proposals without em dashes", () => {
    expect(SPEC_V2_ROADMAP).toHaveLength(5);
    for (const item of SPEC_V2_ROADMAP) {
      expect(item.id.length).toBeGreaterThan(3);
      expect(item.title.length).toBeGreaterThan(10);
      expect(item.bottleneckSolved.length).toBeGreaterThan(20);
      expect(item.mechanism.length).toBeGreaterThan(20);
      expect(item.verificationArtifact.length).toBeGreaterThan(20);
      expect(item.title).not.toContain("\u2014");
      expect(item.bottleneckSolved).not.toContain("\u2014");
      expect(item.mechanism).not.toContain("\u2014");
      expect(item.verificationArtifact).not.toContain("\u2014");
    }
  });
});
