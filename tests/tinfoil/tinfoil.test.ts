import { describe, expect, it } from "vitest";
import { RELAY_HOPS, pacedStream, padJsonPayloadToBucket } from "@/lib/relay";
import { toHex } from "@/lib/sim/bytes";
import { SIM_TCB } from "@/lib/sim/constants";
import { encodeReport, REPORT_SIZE, SIM_POLICY, tcbToU64, type SnpReportFields } from "@/lib/sim/snp";
import { checksFromDocument, RELAY_HOPS as CLIENT_RELAY_HOPS } from "@/lib/tinfoil/client";
import {
  decodeSnpReportBytes,
  parseDeploymentConfigYaml,
  verifyModelEnclaveStatus,
  type ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";

const REAL_KIMI_K3_YAML = `cvm-version: 0.14.14
cpus: 32
memory: 524288
gpus: 8

models:
  - name: "kimi-k3"
    repo: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503"
    mpk: "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c"
  - name: kimi-k3-dspark
    repo: RedHatAI/Kimi-K3-speculator.dspark@38a88101e0d46bb22134b9da340f381b954d40d4
    mpk: e99380779c9921cfdf2dff4ca3b711cda3cc0195e25d9b17633fd191f0ed849c_9489838080_e0171adb-1eda-58a2-aec6-b53125a821dd
    schema: 1

containers:
  - name: "kimi-k3"
    image: "ghcr.io/tinfoilsh/confidential-kimi-k3@sha256:748f5dee73f5d2c15dcc3eb0f6200139b871b23a909b42f95aacc509d9cdc238" # v0.0.15
    runtime: nvidia
    gpus: all
    restart: always
    env:
      - VLLM_DISABLE_UVA: "1"
      - PYTORCH_CUDA_ALLOC_CONF: "expandable_segments:True"
      - FLASHINFER_NO_DOWNLOAD: "1"
      - NUMBA_CACHE_DIR: "/root/numba-cache"
      - VLLM_ALLREDUCE_USE_SYMM_MEM: "0"
      - VLLM_ALLREDUCE_USE_FLASHINFER: "0"
      - VLLM_ENGINE_READY_TIMEOUT_S: "3600"
      - VLLM_USE_V2_MODEL_RUNNER: "1"
    command:
      [
        "--model",
        "/tinfoil/mpk/mpk-58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792",
        "--tensor-parallel-size",
        "8",
        "--disable-custom-all-reduce",
      ]
`;

function buildSampleSnpBytes(overrides: Partial<SnpReportFields> = {}): Uint8Array {
  const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);
  const fields: SnpReportFields = {
    version: 5,
    guestSvn: 0,
    policy: SIM_POLICY,
    familyId: fill(16, 0x01),
    imageId: fill(16, 0x02),
    vmpl: 0,
    signatureAlgo: 1,
    currentTcb: tcbToU64(SIM_TCB),
    platformInfo: BigInt(0),
    flags: 0,
    reportData: fill(64, 0xaa),
    measurement: fill(48, 0xbb),
    hostData: fill(32, 0x05),
    idKeyDigest: fill(48, 0x06),
    authorKeyDigest: fill(48, 0x07),
    reportId: fill(32, 0x08),
    reportIdMa: fill(32, 0x09),
    reportedTcb: tcbToU64(SIM_TCB),
    chipId: fill(64, 0xcc),
    committedTcb: tcbToU64(SIM_TCB),
    launchTcb: tcbToU64(SIM_TCB),
    ...overrides,
  };
  return encodeReport(fields);
}

function buildSampleModelAttestation(
  overrides: Partial<ModelEnclaveAttestation> = {},
): ModelEnclaveAttestation {
  return {
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
        hpkeKey: "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
        predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tlsKeyFp: "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
        codeTag: "v0.0.15",
      },
    ],
    measurementRegisters: [
      "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
    ],
    vmShape: {
      cpus: 32,
      memoryMb: 524288,
      gpus: 8,
      disks: 5,
    },
    dmVerityRootHash: "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
    kernelHash: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
    initrdHash: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    containerImageDigest: "sha256:748f5dee73f5d2c15dcc3eb0f6200139b871b23a909b42f95aacc509d9cdc238",
    weightRepoCommit: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
    weightMpkHash:
      "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c",
    ccGpuFlagsVerified: true,
    releaseUrl: "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
    sigstoreSearchUrl:
      "https://search.sigstore.dev/?hash=41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
    huggingFaceUrl: "https://huggingface.co/moonshotai/Kimi-K3/tree/a590ce090cb049c93a33dfe8c208ec652aa20503",
    ...overrides,
  };
}

describe("Two-Hop Enclave & GPU Trust Verifier", () => {
  it("decodeSnpReportBytes accurately parses a 1,184-byte binary SNP report", () => {
    const rawBytes = buildSampleSnpBytes();
    expect(rawBytes.length).toBe(REPORT_SIZE);
    expect(rawBytes.length).toBe(1184);

    const decoded = decodeSnpReportBytes(rawBytes);
    expect(decoded.version).toBe(5);
    expect(decoded.guestSvn).toBe(0);
    expect(decoded.debugAllowed).toBe(false);
    expect(decoded.smtAllowed).toBe(false);
    expect(decoded.migrationAllowed).toBe(false);
    expect(decoded.vmpl).toBe(0);
    expect(decoded.tcb).toEqual(SIM_TCB);
    expect(decoded.chipIdHex).toBe(toHex(new Uint8Array(64).fill(0xcc)));
    expect(decoded.measurementHex).toBe(toHex(new Uint8Array(48).fill(0xbb)));
    expect(decoded.reportDataHex).toBe(toHex(new Uint8Array(64).fill(0xaa)));
  });

  it("parseDeploymentConfigYaml extracts weightRepoCommit, weightMpkHash, containerImageDigest, and ccGpuFlagsVerified from Kimi K3 YAML", () => {
    const parsed = parseDeploymentConfigYaml(REAL_KIMI_K3_YAML);
    expect(parsed.weightRepoCommit).toBe(
      "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
    );
    expect(parsed.weightMpkHash).toBe(
      "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c",
    );
    expect(parsed.containerImageDigest).toBe(
      "sha256:748f5dee73f5d2c15dcc3eb0f6200139b871b23a909b42f95aacc509d9cdc238",
    );
    expect(parsed.ccGpuFlagsVerified).toBe(true);

    const unsafeYaml = REAL_KIMI_K3_YAML.replace('VLLM_DISABLE_UVA: "1"', 'VLLM_DISABLE_UVA: "0"');
    expect(parseDeploymentConfigYaml(unsafeYaml).ccGpuFlagsVerified).toBe(false);
  });

  it("verifyModelEnclaveStatus passes when hosts are verified and GPUs are in CC mode, and fails on unverified hosts or 0 GPUs", () => {
    const healthy = buildSampleModelAttestation();
    const res = verifyModelEnclaveStatus(healthy);
    expect(res.c5Pass).toBe(true);
    expect(res.c5Detail).toContain(
      "8× NVIDIA confidential GPUs attested by router (1/1 hosts healthy, TDX + CC mode, VLLM_DISABLE_UVA=1, SYMM_MEM=0",
    );
    expect(res.c7Pass).toBe(true);
    expect(res.c7Detail).toBe(
      "Pinned weight package mpk-58d5e74b… (moonshotai/Kimi-K3@a590ce09) on dm-verity root 41068e07…",
    );

    const withUnverified = buildSampleModelAttestation({
      configuredHosts: 2,
      verifiedHosts: 1,
      unverifiedHosts: 1,
    });
    expect(verifyModelEnclaveStatus(withUnverified).c5Pass).toBe(false);

    const withZeroGpus = buildSampleModelAttestation({
      vmShape: { cpus: 32, memoryMb: 524288, gpus: 0, disks: 5 },
    });
    expect(verifyModelEnclaveStatus(withZeroGpus).c5Pass).toBe(false);

    const withoutRootHash = buildSampleModelAttestation({
      dmVerityRootHash: "",
    });
    expect(verifyModelEnclaveStatus(withoutRootHash).c7Pass).toBe(false);
  });

  it("checksFromDocument upgrades C5 and C7 using the model enclave attestation", () => {
    const fakeDoc = {
      enclaveHost: "router-0.tinfoil.sh",
      releaseTag: "v0.0.167",
      releaseDigest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
      codeFingerprint: "abc",
      enclaveFingerprint: "def",
      hpkePublicKey: "123",
      tlsPublicKey: "456",
      selectedRouterEndpoint: "router-0.tinfoil.sh",
      configRepo: "tinfoilsh/confidential-model-router",
      securityVerified: true,
      enclaveMeasurement: {
        measurement: {
          type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
          registers: ["abc"],
        },
      },
      codeMeasurement: {
        type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
        registers: ["abc"],
      },
      steps: {
        fetchDigest: { status: "success" as const },
        verifyCode: { status: "success" as const },
        verifyEnclave: { status: "success" as const },
        compareMeasurements: { status: "success" as const },
        verifyCertificate: { status: "success" as const },
      },
    };

    const checks = checksFromDocument(fakeDoc, buildSampleModelAttestation());
    const c5 = checks.find((c) => c.id === "C5");
    const c7 = checks.find((c) => c.id === "C7");
    expect(c5?.status).toBe("pass");
    expect(c5?.detail).toContain("8× NVIDIA confidential GPUs attested by router");
    expect(c7?.status).toBe("pass");
    expect(c7?.detail).toContain("Pinned weight package mpk-58d5e74b…");
  });

  it("padJsonPayloadToBucket pads a 180-byte JSON payload to 4,096 B and a 5,000-byte payload to 8,192 B while preserving JSON.parse equivalence", () => {
    const baseObj = {
      model: "kimi-k3",
      stream: true,
      messages: [{ role: "user", content: "x".repeat(105) }],
    };
    const json180 = JSON.stringify(baseObj);
    expect(new TextEncoder().encode(json180).byteLength).toBe(180);

    const padded180 = padJsonPayloadToBucket(json180);
    expect(padded180.originalBytes).toBe(180);
    expect(padded180.bucketBytes).toBe(4096);
    expect(new TextEncoder().encode(padded180.paddedJson).byteLength).toBe(4096);
    expect(JSON.parse(padded180.paddedJson)).toEqual(baseObj);

    const largeObj = {
      model: "kimi-k3",
      stream: true,
      messages: [{ role: "user", content: "y".repeat(4925) }],
    };
    const json5000 = JSON.stringify(largeObj);
    expect(new TextEncoder().encode(json5000).byteLength).toBe(5000);

    const padded5000 = padJsonPayloadToBucket(json5000);
    expect(padded5000.originalBytes).toBe(5000);
    expect(padded5000.bucketBytes).toBe(8192);
    expect(new TextEncoder().encode(padded5000.paddedJson).byteLength).toBe(8192);
    expect(JSON.parse(padded5000.paddedJson)).toEqual(largeObj);
  });

  it("RELAY_HOPS defines 3 independent regional oblivious relays and pacedStream preserves full byte stream", async () => {
    expect(RELAY_HOPS).toHaveLength(3);
    expect(CLIENT_RELAY_HOPS).toEqual(RELAY_HOPS);
    const regions = new Set(RELAY_HOPS.map((h) => h.region));
    const operators = new Set(RELAY_HOPS.map((h) => h.operator));
    expect(regions.size).toBe(3);
    expect(operators.size).toBe(3);

    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])];
    const src = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(c);
        controller.close();
      },
    });
    const paced = pacedStream(src, 10);
    const reader = paced.getReader();
    const out: number[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) out.push(...Array.from(value));
    }
    expect(out).toEqual([1, 2, 3, 4, 5]);
  });
});
