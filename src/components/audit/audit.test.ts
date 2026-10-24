import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  GITHUB_BLOB_BASE,
  githubBlobUrl,
  THREAT_SCENARIOS,
} from "@/components/threat-matrix";
import {
  buildVerifiableClaims,
  shortHex,
} from "@/components/audit/audit-helpers";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";

const REPO_ROOT = path.resolve(__dirname, "../../..");

describe("ThreatMatrix scenarios and defense test links", () => {
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

      // Ensure no invented statistics (like 7.99 bits/byte or fabricated 50% / 10% / 90% bounty splits) remain
      const combinedText = JSON.stringify(scenario);
      expect(combinedText).not.toContain("7.99");
      expect(combinedText).not.toContain("50% reporter bounty");
      expect(combinedText).not.toContain("50% slash bounty");
    }
  });
});

describe("buildVerifiableClaims live record links", () => {
  it("constructs exact release tag, Sigstore digest, AMD KDS chip VCEK, proxy host, and Arc tx links from live bundles", () => {
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

    const claims = buildVerifiableClaims({
      matrix: sampleMatrix,
      accountability: {
        manifests: [],
        rampStates: {},
        activeCanaries: {},
        recentClaims: [],
        forbiddenPrefix: "aa".repeat(32),
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

    // 1. Exact GitHub release tag URL
    expect(claims[0].href).toBe(
      "https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.167",
    );
    expect(claims[0].secondaryHref).toBe(
      "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
    );

    // 2. Exact Sigstore Rekor digest query URL
    expect(claims[1].href).toBe(
      "https://search.sigstore.dev/?hash=5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    );

    // 3. Exact AMD KDS VCEK leaf cert URL with chipIdHex and TCB SPL params
    expect(claims[2].href).toContain(
      "https://kdsintf.amd.com/vcek/v1/Genoa/cfdce31f5c40fc4e6eef803f",
    );
    expect(claims[2].href).toContain("blSPL=10&teeSPL=0&snpSPL=27&ucodeSPL=88");

    // 4. Live Tinfoil proxy manifest & HuggingFace weight commit tree
    expect(claims[3].href).toBe(
      "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    );
    expect(claims[3].secondaryHref).toBe(
      "https://huggingface.co/moonshotai/Kimi-K3/tree/a590ce090cb049c93a33dfe8c208ec652aa20503",
    );

    // 5. Circle Arc Testnet transaction / registry link
    expect(claims[4].href).toBe(
      `https://explorer.testnet.arc.io/tx/0x${"ab".repeat(32)}`,
    );
    expect(shortHex("0123456789abcdef0123456789abcdef", 6, 4)).toBe(
      "012345...cdef",
    );
  });
});
