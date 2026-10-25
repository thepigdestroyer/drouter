import { gunzipSync } from "node:zlib";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as accountabilityRouteModule from "@/app/api/accountability/route";
import { GET as getAccountability } from "@/app/api/accountability/route";
import {
  GET as getCronMonitor,
  setCronMonitorTestOptions,
} from "@/app/api/cron/monitor/route";
import {
  clearKdsCertChainCacheForTests,
  clearMemoryMonitorRuns,
  computeRealRampStatesFromHistory,
  evaluateEnclaveReleaseChange,
  executeContinuousMonitorRun,
  getMonitorArcTxCount,
  getMonitorRunsHistory,
  MAX_ARC_FAILURE_TX_PER_RUN,
  measureRouterRtt,
  resetMonitorArcTxCountForTests,
  resetRouterRttCacheForTests,
  resolveRegistryNodeId,
  sanitizeMonitorRunRecord,
  setMonitorCollectionOverride,
} from "@/lib/accountability";
import { setArcClientDepsForTests } from "@/lib/arc/registry";
import { clearMemoryAuditorRuns, saveAuditorRun } from "@/lib/auditor";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import {
  resetAnchorRateLimitState,
  setAnchorReceiptOverride,
  setLiveVerificationViewOverride,
  setTransparencyCollectionOverride,
  setVerifierSubmissionsCollectionOverride,
} from "@/lib/transparency/store";
import { resolveDbName } from "@/lib/mongo/db-name";
import { OPEN_MODEL_CATALOG } from "@/lib/weights/open-shards";

vi.mock("next/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/server")>();
  return {
    ...actual,
    connection: vi.fn(async () => undefined),
  };
});

// Real router-0.tinfoil.sh attestation bundle captured from https://atc.tinfoil.sh/attestation
const REAL_ROUTER_ATC_FIXTURE = {
  domain: "router-0.tinfoil.sh",
  digest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
  releaseTag: "v0.0.167",
  enclaveAttestationReport: {
    format: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    body: "H4sIAAAAAAAA/+zQWYhSURwG8HtHhmIaWiemqRwZqgsSQptcKOy6lASJpFlqitkOSWYuLRCilXYltFwgFHuosLRIwgpEIbhmgWaLmYgYUnh7CcR8aVHTKDwvEfhoD/3gcP7nwPcdOKMQQAHDQDAEQWO/p2UyBFz2UbliQsup7KGKdpFPzLmFWcGcgMlr1n+zyhsHrnY3KRyWvUcLBfT1l/WNWT/ss6efcq/Plc4vWg76ENalqdXuDeed4TvCSc9uDR0/R2EzD02mK+M+ZDq+eBvvPdMkSeg7Tdv3HeU1tMdVqeAKeHdYBDtzt2qnTx6fiB7BQvEHmy+SIkJespcZnVhr/BnN2BsA/OPUAvhv9dCrdzWakt0RahsWTKMqmfEYQoksQhPZRxf4d0fbrq9J8cw+6suyswXnPxET2cAZcWq/Tn7q5jHr/RBm04L+tSgM/VrgPK/fD/Z/1Ru8lzpMfvR7DRvvbfnAby1JB+tNlfLtDdmLzyu2Xlt+whDhZQjXym7y+cOlecwBcn/yo+FARpfBx0h6MHp2pHhZsco44nbOqCVqD8eUDm/n4tV1drJNyliEhFG/DXL/DdfPAQBvENyOoAQAAA==",
  },
  vcek: "MIIFPzCCAvOgAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwezEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmljZXMxEjAQBgNVBAMMCVNFVi1HZW5vYTAeFw0yNjA4MjcxMzE2MDVaFw0zMzA4MjcxMzE2MDVaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkNFSzB2MBAGByqGSM49AgEGBSuBBAAiA2IABH/f981J/gjUGsrLeZQ9bXODcUtEOFOJzdng7iTJt7341tGBhyd/DBl6wcCUn8fcQ38Xo/o2nFIcuUkO+SWmiv1UGDFT61kq+hCw9K9mh2Fbt/ONA8t18QH+kqNzadGjG6OCARMwggEPMBAGCSsGAQQBnHgBAQQDAgEAMBQGCSsGAQQBnHgBAgQHFgVHZW5vYTARBgorBgEEAZx4AQMBBAMCAQowEQYKKwYBBAGceAEDAgQDAgEAMBEGCisGAQQBnHgBAwQEAwIBADARBgorBgEEAZx4AQMFBAMCAQAwEQYKKwYBBAGceAEDBgQDAgEAMBEGCisGAQQBnHgBAwcEAwIBADARBgorBgEEAZx4AQMDBAMCARswEQYKKwYBBAGceAEDCAQDAgFYME0GCSsGAQQBnHgBBARAz9zjH1xA/E5u74A/a17XfoiyJgOpEze6yrWERqsF+473u1IhYR3O2Y36AdHqwRTKmnlSwmJwWXejbYGwpT+FbjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATADggIBAAn2vnnZA08WzI4A+FkHkwS68CNHAnLO0R4PeYu3et8cf7dPpLGt9M6mLi5TyBShwAqLjda1fOR7LWcQ+D1LlhqHaqZ57WrUk+YZNy1M+EgG/a9u1qrq2f2nluYsDo7bO+3o0ZSx+WPUHp1Py+AoTGVcDhu0Bj10UXsw2Oct7KAgwVkX44FpgtYXPjOHkv9oq0F+Uld3LAs0SJ4mznBZvqwMu+B3Z+v1++KT0zryRQsETRlslonwj/Z08gmMPFuqi8E+NOmcxSu9rL1cZxHpeYS7OMXOKduLfHz7QhAhUYJLN/ko/nGil5fLaiS7XtVFx6fj/njCFBmRQuXzSu91cBRQ2fXhHw7x0JBBRWXZxQS/vjhJ5LW5XXwqiKYJ6GWZoTzVRp4VydWjMaCUT8tdYLILX4cnam1jhxegb/ILw+5NOOioL42n5xUNltYNkDPRGrm9B98RFzvmm3JJren0QnwnZbEywZIo/FAJO4GdQgi7fhdweawU3Eak2qzj7N1ZNQ9op0jn5BkuBw1wlQ9XVk8zjb4SXyQ2Z36WTD/bOoIPgWOfm+9HgfAfREu2WyVSD1mTsKYLCiyz1pOaCeEkpUOspf3nNhoEMjyznVC7A2ylp7htHV8exFE5ocMYeYC2n6caNtk5X1zoqxO33RPLUZAjlv3VgwNJmOMYGbpASHca",
  sigstoreBundle: {
    dsseEnvelope: {
      payload: Buffer.from(
        JSON.stringify({
          _type: "https://in-toto.io/Statement/v1",
          subject: [
            {
              name: "tinfoil-deployment.json",
              digest: {
                sha256: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
              },
            },
          ],
          predicateType: "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
          predicate: {
            snp_measurement:
              "9134838da8aa4e1792566b2988820340356517c4db0c94261eb8154843e0357554ba72fcf185f950d9301fbede574c90",
            tdx_measurement: {
              rtmr1:
                "482d0a481acfdf35c0e90b17faf98d313b3d26e948ab34cb349e5cc7b49f9dee85b56c0e20db740832d122285fac8e4f",
              rtmr2:
                "d6c58e0c3c480b9cbac434248ae68ecad6e380f2e361982d6ca50ddff67fc7f9b5c6c66575e2aa93ccf6e1b7552b7f15",
            },
            hashes: {
              version: "v0.14.15",
              root: "72399940d5f095d1510035bd50baed7fbc2552a31c65938acff8bf352ad89398",
              initrd: "deb5ce956eea4dbd709cab140045e9234691109209fd215290417658184116ef",
              kernel: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
              raw: "7a0225578f8906003a29886c7613142cc5a5d857dd2b8582920115c704c37997",
            },
            config: Buffer.from(
              'containers:\n  - name: "router"\n    image: "ghcr.io/tinfoilsh/confidential-model-router@sha256:25637edb386003fc3d1d089023080d81249076fcbb166e045967314370ebc057a" # v0.0.167\n',
              "utf8",
            ).toString("base64"),
          },
        }),
        "utf8",
      ).toString("base64"),
    },
  },
};

let cachedGenoaCertChainPem: string | null = null;
async function loadGenoaCertChainPem(): Promise<string> {
  if (cachedGenoaCertChainPem) return cachedGenoaCertChainPem;
  const res = await fetch("https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain");
  cachedGenoaCertChainPem = await res.text();
  return cachedGenoaCertChainPem;
}

function buildModelDeploymentJson(
  modelId: string,
  overrides?: {
    dmVerityRootHash?: string;
    weightRepoCommit?: string;
    weightMpkHash?: string;
    snpMeasurement?: string;
  },
) {
  const spec = OPEN_MODEL_CATALOG[modelId];
  const weightRepoCommit = overrides?.weightRepoCommit ?? spec.weightRepoCommit!;
  const weightMpkHash = overrides?.weightMpkHash ?? spec.weightMpkHash!;
  const mpkPrefix = weightMpkHash.split("_")[0];
  const dmVerityRootHash = overrides?.dmVerityRootHash ?? spec.dmVerityRootHash!;
  const gpus = spec.vmShape?.gpus ?? 8;

  const yamlLines = [
    `cpus: ${spec.vmShape?.cpus ?? 32}`,
    `memory: ${spec.vmShape?.memoryMb ?? 524288}`,
    `gpus: ${gpus}`,
    "models:",
    `  - name: "${modelId}"`,
    `    repo: "${weightRepoCommit}"`,
    `    mpk: "${weightMpkHash}"`,
    "containers:",
    `  - name: "${modelId}"`,
    `    image: "ghcr.io/${spec.tinfoilRepo}@${spec.containerImageDigest}"`,
    "    runtime: nvidia",
    "    gpus: all",
    "    env:",
    '      - VLLM_DISABLE_UVA: "1"',
    '      - VLLM_ALLREDUCE_USE_SYMM_MEM: "0"',
    "    command:",
    '      - "--model"',
    `      - "/tinfoil/mpk/mpk-${mpkPrefix}"`,
  ].join("\n");

  const configB64 = Buffer.from(yamlLines, "utf8").toString("base64");
  const configSha256 = bytesToHex(sha256(utf8ToBytes(yamlLines)));

  return {
    snp_measurement: overrides?.snpMeasurement ?? spec.measurementRegisters?.[0],
    tdx_measurement: {
      rtmr1: spec.measurementRegisters?.[1],
      rtmr2: spec.measurementRegisters?.[2],
    },
    vm_shape: spec.vmShape,
    cmdline: `roothash=${dmVerityRootHash} tinfoil-config-hash=${configSha256}`,
    hashes: {
      version: "v0.14.15",
      root: dmVerityRootHash,
      kernel: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
      initrd: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    },
    config: configB64,
  };
}

function createMockUpstreamFetch(opts?: {
  genoaCertChainPem: string;
  tamperRouterReport?: boolean;
  tagOverrides?: Record<string, string>;
  hostHpkeOverrides?: Record<string, string>;
  hostCodeTagOverrides?: Record<string, string>;
  tamperModelHfCommit?: Record<string, string>;
  unverifiedHostCountOverrides?: Record<string, number>;
}): typeof fetch {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    if (init?.method === "HEAD" && url.includes(".well-known/tinfoil-proxy")) {
      return new Response(null, { status: 200 });
    }

    if (url.includes("atc.tinfoil.sh/attestation")) {
      if (opts?.tamperRouterReport) {
        const raw = new Uint8Array(
          gunzipSync(Buffer.from(REAL_ROUTER_ATC_FIXTURE.enclaveAttestationReport.body, "base64")),
        );
        raw[0x90] ^= 0xff; // Tamper measurement byte inside signed region
        return new Response(
          JSON.stringify({
            ...REAL_ROUTER_ATC_FIXTURE,
            enclaveAttestationReport: {
              ...REAL_ROUTER_ATC_FIXTURE.enclaveAttestationReport,
              body: Buffer.from(raw).toString("base64"),
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify(REAL_ROUTER_ATC_FIXTURE), { status: 200 });
    }

    if (url.includes("kdsintf.amd.com/vcek/v1/Genoa/cert_chain")) {
      return new Response(opts?.genoaCertChainPem ?? "", { status: 200 });
    }

    if (url.includes(".well-known/tinfoil-proxy")) {
      const modelsObj: Record<string, unknown> = {};
      for (const m of TINFOIL_MODELS) {
        const spec = OPEN_MODEL_CATALOG[m.id];
        const tag = opts?.tagOverrides?.[m.id] ?? spec.tinfoilTag!;
        const hostName = `${m.id}-inf14.tinfoil.containers.tinfoil.dev`;
        const hpkeKey = opts?.hostHpkeOverrides?.[m.id] ?? bytesToHex(sha256(utf8ToBytes(`hpke/${m.id}`)));
        const codeTag = opts?.hostCodeTagOverrides?.[m.id] ?? tag;
        const unverified = opts?.unverifiedHostCountOverrides?.[m.id] ?? 0;
        modelsObj[m.id] = {
          repo: spec.tinfoilRepo,
          tag,
          measurement: {
            type: "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            registers: spec.measurementRegisters,
          },
          enclaves: {
            [hostName]: {
              hpke_key: hpkeKey,
              predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
              tls_key_fp: bytesToHex(sha256(utf8ToBytes(`tls/${m.id}`))),
            },
          },
          verification: {
            configured: 1,
            verified: unverified > 0 ? 0 : 1,
            healthy: 1,
            unverified,
            hosts: {
              [hostName]: {
                code_tag: codeTag,
                last_success: "2026-10-24T22:00:00Z",
                expires_at: "2026-10-28T00:00:00Z",
              },
            },
          },
        };
      }
      return new Response(
        JSON.stringify({
          version: "v0.0.167",
          models: modelsObj,
        }),
        { status: 200 },
      );
    }

    if (url.includes("tinfoil-deployment.json")) {
      const matchedModel = TINFOIL_MODELS.find((m) =>
        url.includes(OPEN_MODEL_CATALOG[m.id].tinfoilRepo!),
      );
      if (matchedModel) {
        return new Response(
          JSON.stringify(buildModelDeploymentJson(matchedModel.id)),
          { status: 200 },
        );
      }
    }

    if (url.includes("huggingface.co/api/models/")) {
      const matchedModel = TINFOIL_MODELS.find((m) => {
        const hfRepo = OPEN_MODEL_CATALOG[m.id].hfRepo!;
        return url.includes(hfRepo);
      });
      if (matchedModel) {
        const spec = OPEN_MODEL_CATALOG[matchedModel.id];
        const sha = opts?.tamperModelHfCommit?.[matchedModel.id] ?? spec.hfCommit!;
        return new Response(
          JSON.stringify({
            sha,
            siblings: Array.from({ length: spec.shardCount }, (_, idx) => ({
              rfilename: `model-${idx + 1}.safetensors`,
            })),
          }),
          { status: 200 },
        );
      }
    }

    return new Response("Not found", { status: 404 });
  };
}

function createInMemoryTransparencyCollection() {
  const docs: Record<string, unknown>[] = [];
  return {
    find(filter: Record<string, unknown>) {
      const matched = docs.filter((d) =>
        Object.entries(filter).every(([k, v]) => d[k] === v),
      );
      return {
        sort(spec: Record<string, 1 | -1>) {
          const [field, dir] = Object.entries(spec)[0] ?? ["index", 1];
          const sorted = [...matched].sort(
            (a, b) => (Number(a[field] ?? 0) - Number(b[field] ?? 0)) * dir,
          );
          return {
            toArray: async () => sorted,
            limit: (n: number) => ({ toArray: async () => sorted.slice(0, n) }),
          };
        },
        toArray: async () => matched,
      };
    },
    async findOne(filter: Record<string, unknown>) {
      return (
        docs.find((d) => Object.entries(filter).every(([k, v]) => d[k] === v)) ??
        null
      );
    },
    async insertOne(doc: Record<string, unknown>) {
      docs.push({ ...doc });
    },
    async insertMany(items: Record<string, unknown>[]) {
      for (const item of items) docs.push({ ...item });
    },
    async updateOne(
      filter: Record<string, unknown>,
      update: Record<string, unknown>,
      options?: Record<string, unknown>,
    ) {
      const idx = docs.findIndex((d) =>
        Object.entries(filter).every(([k, v]) => d[k] === v),
      );
      const setFields = (update.$set ?? {}) as Record<string, unknown>;
      if (idx >= 0) {
        docs[idx] = { ...docs[idx], ...setFields };
      } else if (options?.upsert) {
        docs.push({ ...filter, ...setFields });
      }
    },
    async deleteMany(filter: Record<string, unknown>) {
      for (let i = docs.length - 1; i >= 0; i--) {
        if (Object.entries(filter).every(([k, v]) => docs[i][k] === v)) {
          docs.splice(i, 1);
        }
      }
    },
    async countDocuments() {
      return docs.length;
    },
  };
}

beforeEach(() => {
  resetRateLimitStateForTests();
  clearMemoryMonitorRuns();
  clearMemoryAuditorRuns();
  clearKdsCertChainCacheForTests();
  resetRouterRttCacheForTests();
  resetMonitorArcTxCountForTests();
  resetAnchorRateLimitState();
  setMonitorCollectionOverride(null);
  setTransparencyCollectionOverride(createInMemoryTransparencyCollection());
  setVerifierSubmissionsCollectionOverride(null);
  setLiveVerificationViewOverride(null);
  setAnchorReceiptOverride(null);
  setCronMonitorTestOptions(null);
});

afterEach(() => {
  setArcClientDepsForTests(null);
  setMonitorCollectionOverride(null);
  setTransparencyCollectionOverride(null);
  setVerifierSubmissionsCollectionOverride(null);
  setLiveVerificationViewOverride(null);
  setAnchorReceiptOverride(null);
  setCronMonitorTestOptions(null);
  clearMemoryMonitorRuns();
  clearMemoryAuditorRuns();
  clearKdsCertChainCacheForTests();
  resetRouterRttCacheForTests();
  resetMonitorArcTxCountForTests();
  resetAnchorRateLimitState();
  resetRateLimitStateForTests();
  vi.unstubAllEnvs();
});

describe("D7 Continuous Enclave Monitoring & Real Accountability", () => {
  describe("GET /api/cron/monitor Bearer CRON_SECRET authorization", () => {
    it("rejects requests when CRON_SECRET is missing or Bearer token does not match", async () => {
      vi.stubEnv("CRON_SECRET", "");
      const resNoEnv = await getCronMonitor(
        new Request("http://localhost/api/cron/monitor"),
      );
      expect(resNoEnv.status).toBe(401);

      vi.stubEnv("CRON_SECRET", "test-cron-secret-value-123");
      const resMissingHeader = await getCronMonitor(
        new Request("http://localhost/api/cron/monitor"),
      );
      expect(resMissingHeader.status).toBe(401);

      const resWrongToken = await getCronMonitor(
        new Request("http://localhost/api/cron/monitor", {
          headers: { authorization: "Bearer wrong-cron-secret-value" },
        }),
      );
      expect(resWrongToken.status).toBe(401);
    });

    it("executes a full monitor run when authorized with Bearer CRON_SECRET", async () => {
      const genoaCertChainPem = await loadGenoaCertChainPem();
      vi.stubEnv("CRON_SECRET", "test-cron-secret-value-123");

      let anchorCalls = 0;
      setAnchorReceiptOverride(async () => {
        anchorCalls += 1;
        return `0x${"a".repeat(63)}${anchorCalls}` as `0x${string}`;
      });

      const mockFetch = createMockUpstreamFetch({ genoaCertChainPem });
      setCronMonitorTestOptions({
        fetchImpl: mockFetch,
        nowSec: 1761350400,
      });

      const res = await getCronMonitor(
        new Request("http://localhost/api/cron/monitor", {
          headers: { authorization: "Bearer test-cron-secret-value-123" },
        }),
      );
      expect(res.status).toBe(200);
      const body = await res.json();

      expect(body.ok).toBe(true);
      expect(body.run.ok).toBe(true);
      expect(body.run.epochHourSec).toBe(1761350400);
      expect(body.run.epochHourSec % 3600).toBe(0);
      expect(body.run.totalEnclaves).toBe(1 + TINFOIL_MODELS.length);
      expect(body.run.passedEnclaves).toBe(1 + TINFOIL_MODELS.length);
      expect(body.run.failedEnclaves).toBe(0);
      expect(body.run.failures).toEqual([]);
      expect(anchorCalls).toBe(1);
      expect(body.signedTreeHead.anchorTx).toBe(`0x${"a".repeat(63)}1`);
    });
  });

  describe("Real Enclave Verification, Release Change Detection & On-Chain Failure Recording", () => {
    it("detects release upgrades, unannounced host restarts, rolling skew, and unannounced measurement changes across consecutive runs", async () => {
      const genoaCertChainPem = await loadGenoaCertChainPem();
      setAnchorReceiptOverride(async () => `0x${"b".repeat(64)}` as `0x${string}`);

      // Run 1: Initial baseline
      const run1 = await executeContinuousMonitorRun({
        fetchImpl: createMockUpstreamFetch({ genoaCertChainPem }),
        nowSec: 1761350400,
      });
      expect(run1.run.ok).toBe(true);
      const kimi1 = run1.run.enclaves.find((e) => e.nodeId === "kimi-k3")!;
      expect(kimi1.releaseChange.kind).toBe("initial");
      expect(kimi1.releaseChange.changed).toBe(false);
      expect(run1.rampStates["kimi-k3"].phase).toBe("steady");
      expect(run1.rampStates["kimi-k3"].weightBps).toBe(10000);

      // Run 2: Unchanged
      const run2 = await executeContinuousMonitorRun({
        fetchImpl: createMockUpstreamFetch({ genoaCertChainPem }),
        nowSec: 1761354000,
      });
      const kimi2 = run2.run.enclaves.find((e) => e.nodeId === "kimi-k3")!;
      expect(kimi2.releaseChange.kind).toBe("unchanged");
      expect(kimi2.releaseChange.changed).toBe(false);
      expect(run2.rampStates["kimi-k3"].phase).toBe("steady");
      expect(run2.rampStates["kimi-k3"].weightBps).toBe(10000);

      // Run 3: Unannounced host HPKE key rotation on kimi-k3 and release upgrade on glm-5-3
      const run3 = await executeContinuousMonitorRun({
        fetchImpl: createMockUpstreamFetch({
          genoaCertChainPem,
          hostHpkeOverrides: { "kimi-k3": "ff".repeat(32) },
          tagOverrides: { "glm-5-3": "v0.0.8" },
        }),
        nowSec: 1761357600,
      });
      const kimi3 = run3.run.enclaves.find((e) => e.nodeId === "kimi-k3")!;
      expect(kimi3.releaseChange.kind).toBe("unannounced-restart");
      expect(kimi3.releaseChange.changed).toBe(true);
      expect(kimi3.releaseChange.unannounced).toBe(true);
      expect(run3.rampStates["kimi-k3"].phase).toBe("canary-only");
      expect(run3.rampStates["kimi-k3"].weightBps).toBe(0);

      const glm3 = run3.run.enclaves.find((e) => e.nodeId === "glm-5-3")!;
      expect(glm3.releaseChange.kind).toBe("release-upgrade");
      expect(glm3.releaseChange.previousTag).toBe("v0.0.7");
      expect(glm3.releaseChange.currentTag).toBe("v0.0.8");
      expect(run3.rampStates["glm-5-3"].phase).toBe("linear-ramp");
      expect(run3.rampStates["glm-5-3"].weightBps).toBe(5000);

      // Direct unit check for unannounced measurement change without tag change
      const unannouncedMeas = evaluateEnclaveReleaseChange({
        nodeId: "kimi-k3",
        currentTag: kimi1.releaseTag,
        currentMeasurement: "deadbeef".repeat(12),
        currentDmVerityRoot: kimi1.dmVerityRootHash,
        currentHosts: kimi1.enclaveHosts,
        previous: kimi1,
      });
      expect(unannouncedMeas.kind).toBe("unannounced-measurement-change");
      expect(unannouncedMeas.changed).toBe(true);
      expect(unannouncedMeas.unannounced).toBe(true);
    });

    it("records verification failures on Arc with evidence hashes when attestation, weight provenance, or SPRT auditor fails (capped at <= 3 Arc tx)", async () => {
      const genoaCertChainPem = await loadGenoaCertChainPem();
      const registryAddr = "0xbc8085c2b6fe6e0db05f169925c0b841828f4481" as const;
      vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);

      let txSeq = 0;
      const writeCalls: { functionName: string; args: readonly unknown[] }[] = [];

      setArcClientDepsForTests({
        readContract: vi.fn(async ({ functionName }) => {
          if (functionName === "nodeCount") return BigInt(0);
          if (functionName === "minStake") return BigInt(10_000_000_000_000_000);
          throw new Error(`Unexpected readContract: ${functionName}`);
        }),
        writeContract: vi.fn(async ({ functionName, args }) => {
          txSeq += 1;
          writeCalls.push({ functionName, args });
          return `0x${String(txSeq).padStart(64, "0")}` as `0x${string}`;
        }),
      });
      setAnchorReceiptOverride(async () => null);

      // Record a failed SPRT mystery-shopper audit run for llama3-3-70b
      await saveAuditorRun({
        model: "llama3-3-70b",
        passed: false,
        verdict: "SLASH_MODEL_DOWNGRADE_DETECTED",
        sprtStatistic: -3.2,
        cumulativeSprtStatistic: -3.2,
        upperBoundA: 2.77,
        lowerBoundB: -2.77,
        probesCount: 4,
        passedCount: 0,
        empiricalPassRate: 0,
        meanLatencyMs: 210,
        enclaveHost: "llama3-3-70b-inf12.tinfoil.containers.tinfoil.dev",
        at: new Date(1761350400 * 1000),
      });

      // Trigger failures on 4 enclaves simultaneously:
      // 1. tinfoil-router: tampered SEV-SNP report byte
      // 2. kimi-k3: tampered Hugging Face commit SHA
      // 3. glm-5-3: unverified host in proxy table
      // 4. llama3-3-70b: failed SPRT auditor verdict
      const res = await executeContinuousMonitorRun({
        fetchImpl: createMockUpstreamFetch({
          genoaCertChainPem,
          tamperRouterReport: true,
          tamperModelHfCommit: { "kimi-k3": "00".repeat(20) },
          unverifiedHostCountOverrides: { "glm-5-3": 1 },
        }),
        nowSec: 1761350400,
        anchorTreeHead: false,
      });

      expect(res.run.ok).toBe(false);
      expect(res.run.failedEnclaves).toBe(4);
      expect(res.run.failures).toHaveLength(4);

      // Verify hard cap of at most 3 Arc transactions
      expect(MAX_ARC_FAILURE_TX_PER_RUN).toBe(3);
      expect(res.arcTransactionsUsed).toBe(3);
      expect(getMonitorArcTxCount()).toBe(3);
      expect(writeCalls).toHaveLength(3);

      expect(writeCalls[0]).toEqual({
        functionName: "recordVerification",
        args: [
          resolveRegistryNodeId("tinfoil-router"),
          false,
          res.run.failures[0].evidenceHash,
        ],
      });
      expect(writeCalls[1]).toEqual({
        functionName: "recordVerification",
        args: [
          resolveRegistryNodeId("kimi-k3"),
          false,
          res.run.failures[1].evidenceHash,
        ],
      });
      expect(writeCalls[2]).toEqual({
        functionName: "recordVerification",
        args: [
          resolveRegistryNodeId("glm-5-3"),
          false,
          res.run.failures[2].evidenceHash,
        ],
      });

      // 4th failure is recorded in run.failures with evidenceHash but no on-chain tx due to 3-tx cap
      expect(res.run.failures[3].nodeId).toBe("llama3-3-70b");
      expect(res.run.failures[3].evidenceHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(res.run.failures[3].txHash).toBeNull();
      expect(res.rampStates["llama3-3-70b"].status).toBe("suspended");
      expect(res.rampStates["llama3-3-70b"].weightBps).toBe(0);
    });

    it("anchors the transparency tree head at most once per hour across multiple runs", async () => {
      const genoaCertChainPem = await loadGenoaCertChainPem();
      let anchorCount = 0;
      setAnchorReceiptOverride(async () => {
        anchorCount += 1;
        return `0x${"c".repeat(63)}${anchorCount}` as `0x${string}`;
      });

      const mockFetch = createMockUpstreamFetch({ genoaCertChainPem });

      // First run at t = 1761350400 anchors
      await executeContinuousMonitorRun({
        fetchImpl: mockFetch,
        nowSec: 1761350400,
      });
      expect(anchorCount).toBe(1);

      // Second run 15 minutes later (t + 900s < 3600s) does NOT anchor again
      await executeContinuousMonitorRun({
        fetchImpl: mockFetch,
        nowSec: 1761350400 + 900,
      });
      expect(anchorCount).toBe(1);

      // Third run 61 minutes later (t + 3660s >= 3600s) anchors new tree head
      await executeContinuousMonitorRun({
        fetchImpl: mockFetch,
        nowSec: 1761350400 + 3660,
      });
      expect(anchorCount).toBe(2);
    });
  });

  describe("Privacy & GET /api/accountability Contract", () => {
    it("coarsens timestamps to the UTC hour and strips forbidden PII fields from monitor_runs", () => {
      const dirty = {
        runId: "monitor-test",
        epochHourSec: 1761352123, // Not divisible by 3600
        at: new Date("2026-10-24T23:48:43.512Z"),
        ok: true,
        routerHost: "router-0.tinfoil.sh",
        routerReleaseTag: "v0.0.167",
        routerReleaseDigest: "5233a27f",
        routerRttMs: 31.48,
        totalEnclaves: 1,
        passedEnclaves: 1,
        failedEnclaves: 0,
        releaseChangesCount: 0,
        enclaves: [],
        releaseChanges: [],
        failures: [],
        auditor: {
          hasRun: false,
          model: null,
          verdict: null,
          passed: null,
          probesCount: null,
          passedCount: null,
          empiricalPassRate: null,
          cumulativeSprtStatistic: null,
          enclaveHost: null,
          at: null,
        },
        transparencyRoot: "aa".repeat(32),
        transparencyTreeSize: 4,
        anchorTx: null,
        anchoredAtSec: 1761352123,
        ip: "203.0.113.99",
        prompt: "secret user prompt",
        headers: { authorization: "Bearer secret" },
      } as unknown as Parameters<typeof sanitizeMonitorRunRecord>[0];

      const clean = sanitizeMonitorRunRecord(dirty);
      expect(clean.epochHourSec % 3600).toBe(0);
      expect(clean.at.getUTCMinutes()).toBe(0);
      expect(clean.at.getUTCSeconds()).toBe(0);
      expect(clean.at.getUTCMilliseconds()).toBe(0);
      expect(clean.anchoredAtSec! % 3600).toBe(0);
      expect("ip" in (clean as unknown as Record<string, unknown>)).toBe(false);
      expect("prompt" in (clean as unknown as Record<string, unknown>)).toBe(false);
      expect("headers" in (clean as unknown as Record<string, unknown>)).toBe(false);
    });

    it("returns real monitoring history on GET /api/accountability, filters out sim nodes, and removes practice POST actions", async () => {
      expect("POST" in accountabilityRouteModule).toBe(false);

      const genoaCertChainPem = await loadGenoaCertChainPem();
      setAnchorReceiptOverride(async () => `0x${"d".repeat(64)}` as `0x${string}`);

      await executeContinuousMonitorRun({
        fetchImpl: createMockUpstreamFetch({ genoaCertChainPem }),
        nowSec: 1761350400,
      });

      const res = await getAccountability(
        new Request("http://localhost/api/accountability?limit=10"),
      );
      expect(res.status).toBe(200);
      const data = await res.json();

      expect(data.hasRun).toBe(true);
      expect(data.latestRun).toBeDefined();
      expect(data.history).toHaveLength(1);
      expect(data.enclaves.length).toBe(1 + TINFOIL_MODELS.length);
      expect(data.enclaves.every((e: { nodeKind: string }) => e.nodeKind === "tinfoil")).toBe(
        true,
      );
      expect(
        data.registryNodes.every(
          (n: { kind: string; endpoint: string }) =>
            n.kind === "tinfoil" && !n.endpoint.startsWith("/api/sim"),
        ),
      ).toBe(true);
      expect(Object.keys(data.rampStates)).toContain("tinfoil-router");
      expect(Object.keys(data.rampStates)).toContain("kimi-k3");
      expect(Object.keys(data.rampStates).some((k) => k.startsWith("sim-"))).toBe(false);

      // Practice fields must be absent
      expect(data.manifests).toBeUndefined();
      expect(data.activeCanaries).toBeUndefined();
      expect(data.recentClaims).toBeUndefined();
      expect(data.forbiddenPrefix).toBeUndefined();
      expect(data.latencyTriangulations).toBeUndefined();
    });

    it("measures router RTT using 3 HEAD probes", async () => {
      resetRouterRttCacheForTests();
      let headCount = 0;
      const rtt = await measureRouterRtt("inference.tinfoil.sh", async () => {
        headCount += 1;
        return new Response(null, { status: 200 });
      });
      expect(headCount).toBe(3);
      expect(rtt).not.toBeNull();
      expect(rtt!.host).toBe("inference.tinfoil.sh");
      expect(rtt!.samplesMs).toHaveLength(3);
      expect(rtt!.bestRttMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Live Tinfoil Enclave Continuous Monitor Integration", () => {
    it("resolves database name to drouter_test under vitest", () => {
      const prevDb = process.env.MONGODB_DB;
      delete process.env.MONGODB_DB;
      try {
        expect(resolveDbName()).toBe("drouter_test");
      } finally {
        if (prevDb !== undefined) process.env.MONGODB_DB = prevDb;
      }
    });

    it(
      "verifies live Tinfoil router and all real model enclaves end-to-end",
      async () => {
        if (process.env.DROUTER_STUB_UPSTREAM === "1") return;

        const result = await executeContinuousMonitorRun({
          anchorTreeHead: false,
          maxArcFailureTx: 0,
        });

        expect(["router-0.tinfoil.sh", "inference.tinfoil.sh"]).toContain(
          result.run.routerHost,
        );
        expect(result.run.totalEnclaves).toBeGreaterThanOrEqual(6);

        const router = result.run.enclaves.find((e) => e.nodeId === "tinfoil-router")!;
        expect(router.attestationChainOk).toBe(true);
        expect(router.measurementMatchesRelease).toBe(true);
        expect(router.ok).toBe(true);

        const kimi = result.run.enclaves.find((e) => e.nodeId === "kimi-k3")!;
        expect(kimi.attestationChainOk).toBe(true);
        expect(kimi.measurementMatchesRelease).toBe(true);
        expect(kimi.modelProvenanceOk).toBe(true);
        expect(kimi.ok).toBe(true);

        expect(result.storedInMongo).toBe(false);

        const history = await getMonitorRunsHistory(5);
        expect(history.hasRun).toBe(true);
        expect(history.latestRun?.runId).toBe(result.run.runId);
      },
      30_000,
    );
  });
});
