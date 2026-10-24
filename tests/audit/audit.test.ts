import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  GITHUB_BLOB_BASE,
  githubBlobUrl,
  THREAT_SCENARIOS,
  THREAT_VILLAINS,
} from "@/components/threat-matrix";
import {
  buildPlainTrustPoints,
  buildVerifiableClaims,
  shortHex,
} from "@/components/audit/audit-helpers";
import { HONEST_LIMITS } from "@/app/about/page";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";

const REPO_ROOT = path.resolve(__dirname, "../..");

const BANNED_JARGON_PATTERNS = [
  /\battestation\b/i,
  /\battested\b/i,
  /\benclaves?\b/i,
  /\bTEE\b/,
  /\bSEV-SNP\b/i,
  /\bSNP\b/,
  /\bTDX\b/,
  /\bHPKE\b/i,
  /\bRFC\b/,
  /\bMerkle\b/i,
  /\bnullifiers?\b/i,
  /\bRSA\b/,
  /\bquorums?\b/i,
  /\bSigstore\b/i,
  /\bRekor\b/i,
  /\bVCEK\b/i,
  /\bCKKS\b/i,
  /\bFHE\b/,
  /\bhomomorphic\b/i,
  /\bdm-verity\b/i,
  /\bmeasurements?\b/i,
  /\bciphertexts?\b/i,
  /\bhash(?:es)?\b/i,
  /\bdigests?\b/i,
  /\bECDSA\b/i,
  /\bX25519\b/i,
  /\bPII\b/,
  /\bOHTTP\b/i,
  /\bSPRT\b/,
  /\bArc testnet\b/i,
  /\brelay hop\b/i,
  /\bbucket bytes\b/i,
];

function expectPlainLanguage(text: string) {
  for (const pat of BANNED_JARGON_PATTERNS) {
    expect(text).not.toMatch(pat);
  }
  expect(text).not.toContain("\u2014");
  expect(text).not.toContain("dRouter");
}

describe("ThreatMatrix scenarios, villains, and defense test links", () => {
  it("exposes 4 plain-language villains mapped to real scenarios without banned jargon", () => {
    expect(THREAT_VILLAINS).toHaveLength(4);
    const labels = THREAT_VILLAINS.map((v) => v.label.toLowerCase());
    expect(labels).toContain("a nosy server owner");
    expect(labels).toContain("a hacker with a probe");
    expect(labels).toContain("a fake server");
    expect(labels).toContain("a leaky company");

    for (const villain of THREAT_VILLAINS) {
      expectPlainLanguage(
        `${villain.label} ${villain.shortTag} ${villain.whatTheyTry} ${villain.whatStopsThem}`,
      );
      expect(villain.scenarioIds.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("exposes 7 scenarios with real repository test paths, exact test names, and GitHub links", () => {
    expect(THREAT_SCENARIOS).toHaveLength(7);

    for (const scenario of THREAT_SCENARIOS) {
      expect(scenario.defenseTests.length).toBeGreaterThanOrEqual(1);

      for (const ref of scenario.defenseTests) {
        expect(ref.githubUrl).toBe(`${GITHUB_BLOB_BASE}/${ref.filePath}`);
        expect(ref.githubUrl).toBe(githubBlobUrl(ref.filePath));

        const absTestPath = path.join(REPO_ROOT, ref.filePath);
        expect(fs.existsSync(absTestPath)).toBe(true);

        const testContent = fs.readFileSync(absTestPath, "utf8");
        expect(testContent).toContain(ref.testName);

        if (ref.codePath && ref.codeUrl) {
          expect(ref.codeUrl).toBe(githubBlobUrl(ref.codePath));
          const absCodePath = path.join(REPO_ROOT, ref.codePath);
          expect(fs.existsSync(absCodePath)).toBe(true);
        }
      }

      const combinedText = JSON.stringify(scenario);
      expect(combinedText).not.toContain("7.99");
      expect(combinedText).not.toContain("50% reporter bounty");
      expect(combinedText).not.toContain("50% slash bounty");
      expect(combinedText).not.toContain("dRouter");
      expect(combinedText).not.toContain("sim-1");
      expect(combinedText).not.toContain("SIM_HARDWARE_SEED");
      expect(combinedText).not.toContain("Simulated");
    }
  });
});

describe("buildVerifiableClaims and buildPlainTrustPoints live record links", () => {
  const sampleMatrix: DeepAttestationBundle = {
    routerHost: "router-0.tinfoil.sh",
    routerReleaseTag: "v0.0.167",
    routerReleaseDigest:
      "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    routerConfigRepo: "tinfoilsh/confidential-model-router",
    routerSnpReport: {
      version: 5,
      guestSvn: 0,
      policyHex: "0x30000",
      smtAllowed: true,
      migrationAllowed: false,
      debugAllowed: false,
      vmpl: 0,
      productName: "Genoa",
      tcb: { fmc: 0, bootloader: 10, tee: 0, snp: 27, microcode: 88 },
      chipIdHex:
        "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e",
      measurementHex: "9134838da8aa4e17",
      reportDataHex: "1d4252c16e41db5a",
      tlsKeyFpFromReportDataHex: "1d4252c1",
      hpkeKeyFromReportDataHex: "5b89805f",
      signatureRHex: "aa".repeat(48),
      signatureSHex: "bb".repeat(48),
    },
    routerReleaseUrl:
      "https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.167",
    routerSigstoreUrl:
      "https://search.sigstore.dev/?hash=5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    amdKdsUrl:
      "https://kdsintf.amd.com/vcek/v1/Genoa/cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e?blSPL=10&teeSPL=0&snpSPL=27&ucodeSPL=88",
    proxyWellKnownUrl: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    models: {
      "kimi-k3": {
        modelId: "kimi-k3",
        repo: "tinfoilsh/confidential-kimi-k3",
        tag: "v0.0.15",
        hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)",
        configuredHosts: 1,
        verifiedHosts: 1,
        healthyHosts: 1,
        unverifiedHosts: 0,
        enclaveHosts: [
          {
            host: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
            hpkeKey: "5df270bc",
            predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
            tlsKeyFp: "6758bad9",
            codeTag: "v0.0.15",
          },
        ],
        measurementRegisters: ["69c02910"],
        vmShape: { cpus: 32, memoryMb: 524288, gpus: 8, disks: 5 },
        dmVerityRootHash:
          "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
        kernelHash: "91b9c797",
        initrdHash: "42294820",
        containerImageDigest: "sha256:748f5dee",
        weightRepoCommit:
          "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
        weightMpkHash: "58d5e74b",
        ccGpuFlagsVerified: true,
        releaseUrl:
          "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
        sigstoreSearchUrl:
          "https://search.sigstore.dev/?hash=41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
        huggingFaceUrl:
          "https://huggingface.co/moonshotai/Kimi-K3/tree/a590ce090cb049c93a33dfe8c208ec652aa20503",
      },
    },
    fetchedAt: "2026-10-24T17:00:00.000Z",
  };

  it("constructs exact release tag, Sigstore digest, AMD KDS chip VCEK, proxy host, and Arc tx links from live bundles", () => {
    const claims = buildVerifiableClaims({
      matrix: sampleMatrix,
      accountability: {
        rampStates: {},
        onChain: true,
        txHash: `0x${"ab".repeat(32)}`,
        explorerUrl: `https://explorer.testnet.arc.io/tx/0x${"ab".repeat(32)}`,
        registryNodes: [
          {
            id: `0x${"11".repeat(32)}`,
            kind: "tinfoil",
            name: "Tinfoil confidential router",
            endpoint: "inference.tinfoil.sh",
            measurement: `0x${"22".repeat(32)}`,
            operator: `0x${"33".repeat(20)}`,
            stake: "0.01",
            status: "active",
            region: "us",
            registeredAt: 1792851417,
            lastVerifiedAt: 1792852705,
            lastVerifiedOk: true,
          },
        ],
      },
      transparency: null,
    });

    expect(claims).toHaveLength(5);

    expect(claims[0].href).toBe(
      "https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.167",
    );
    expect(claims[0].secondaryHref).toBe(
      "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
    );
    expect(claims[1].href).toBe(
      "https://search.sigstore.dev/?hash=5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    );
    expect(claims[2].href).toContain(
      "https://kdsintf.amd.com/vcek/v1/Genoa/cfdce31f5c40fc4e6eef803f",
    );
    expect(claims[2].href).toContain("blSPL=10&teeSPL=0&snpSPL=27&ucodeSPL=88");
    expect(claims[3].href).toBe(
      "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    );
    expect(claims[3].secondaryHref).toBe(
      "https://huggingface.co/moonshotai/Kimi-K3/tree/a590ce090cb049c93a33dfe8c208ec652aa20503",
    );
    expect(claims[4].href).toBe(
      `https://explorer.testnet.arc.io/tx/0x${"ab".repeat(32)}`,
    );
    expect(shortHex("0123456789abcdef0123456789abcdef", 6, 4)).toBe(
      "012345...cdef",
    );
  });

  it("constructs 3 plain trust points with Check it yourself links and zero banned jargon", () => {
    const points = buildPlainTrustPoints({
      matrix: sampleMatrix,
      accountability: null,
      transparency: null,
    });

    expect(points).toHaveLength(3);
    for (const point of points) {
      expect(point.buttonLabel).toBe("Check it yourself");
      expect(point.href).toMatch(/^https:\/\//);
      expectPlainLanguage(
        `${point.title} ${point.description} ${point.badge} ${point.buttonLabel}`,
      );
    }
  });

  it("provides plain-language HONEST_LIMITS summaries without banned jargon", () => {
    expect(HONEST_LIMITS.length).toBeGreaterThanOrEqual(8);
    for (const limit of HONEST_LIMITS) {
      expectPlainLanguage(`${limit.plainTitle} ${limit.plainSummary}`);
    }
  });

  it("ensures unexpanded JSX in audit, network, about, provider-catalog-client, and threat-matrix contains no banned jargon, em dashes, or dRouter", () => {
    const ownedUiFiles = [
      "src/app/audit/page.tsx",
      "src/app/network/page.tsx",
      "src/app/about/page.tsx",
      "src/app/about/provider-catalog-client.tsx",
      "src/components/threat-matrix.tsx",
    ];

    for (const relPath of ownedUiFiles) {
      const fullPath = path.join(REPO_ROOT, relPath);
      const source = fs.readFileSync(fullPath, "utf8");

      // No em dashes anywhere in file
      expect(source).not.toContain("\u2014");

      // No simulated or practice UI references
      expect(source).not.toMatch(/\bsim-/);
      expect(source).not.toMatch(/\bquorumSimulated\b/);
      expect(source).not.toMatch(/\bPractice\b/);
      expect(source).not.toMatch(/\benclaveHostCount\b/);
      expect(source).not.toContain('rel="noreferrer"');

      // Strip <TechDetails ...>...</TechDetails> blocks first, then inspect top-level component JSX
      const withoutTechDetails = source.replace(
        /<TechDetails[\s\S]*?<\/TechDetails>/g,
        "",
      );
      const jsxMatches = Array.from(
        withoutTechDetails.matchAll(/\n  return \([\s\S]*?\n  \);/g),
      );
      expect(jsxMatches.length).toBeGreaterThan(0);
      const jsxSection = jsxMatches
        .map((m) => m[0])
        .join("\n")
        // strip JSX tags and attribute values/identifiers, leaving rendered text nodes
        .replace(/<[^>]+>/g, " ")
        .replace(/\{[^}]*\}/g, " ");

      expectPlainLanguage(jsxSection);
    }
  });
});
