import { describe, expect, it } from "vitest";
import {
  CONFIDENTIAL_PROVIDERS,
  SPEC_V2_ROADMAP,
  filterProviders,
} from "@/lib/providers/catalog";

describe("Frontier Confidential Provider Directory & Spec v2 Roadmap", () => {
  it("contains all 10 confidential TEE providers with complete metadata and no em dashes", () => {
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
      expect(provider.cpuTee.length).toBeGreaterThan(2);
      expect(provider.gpuTee.length).toBeGreaterThan(2);
      expect(provider.frontierModels.length).toBeGreaterThanOrEqual(3);
      expect(provider.inputUsdPerM).toMatch(/^\$\d+\.\d+\+\/M$/);
      expect(provider.trustNotes.length).toBeGreaterThan(40);
      expect(provider.trustNotes).not.toContain("\u2014");
    }
  });

  it("marks Tinfoil as live-integrated and separates E2EE vs gateway-tee-only providers", () => {
    const tinfoil = CONFIDENTIAL_PROVIDERS.find((p) => p.id === "tinfoil");
    expect(tinfoil).toBeDefined();
    expect(tinfoil?.statusInDrouter).toBe("live-integrated");
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
      "chutes-bittensor",
      "nanogpt",
    ]);

    const pqcProviders = filterProviders({ requirePqc: true });
    expect(pqcProviders.map((p) => p.id)).toEqual([
      "tinfoil",
      "phala-redpill",
      "ppq-ai",
      "confidential-ai",
    ]);

    const kimiE2eePqc = filterProviders({
      modelQuery: "Kimi",
      requireE2ee: true,
      requirePqc: true,
    });
    expect(kimiE2eePqc.map((p) => p.id)).toEqual(["tinfoil", "ppq-ai"]);
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
