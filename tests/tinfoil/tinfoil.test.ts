import { gunzipSync } from "node:zlib";
import { bytesToHex as toHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { GET as getRelayAttestation } from "@/app/api/relay/attestation/route";
import { GET as getHopRelayAttestation } from "@/app/api/relay/[relayId]/attestation/route";
import { GET as getEnclaveMatrix } from "@/app/api/relay/enclave-matrix/route";
import { RELAY_HOPS, pacedStream, padJsonPayloadToBucket } from "@/lib/relay";
import { checksFromDocument, RELAY_HOPS as CLIENT_RELAY_HOPS } from "@/lib/tinfoil/client";
import {
  decodeSnpReportBytes,
  decodeTdxQuoteBytes,
  parseDeploymentConfigYaml,
  verifyAmdSevSnpChainEndToEnd,
  verifyModelEnclaveStatus,
  verifyNvidiaEatJwtAgainstJwks,
  verifyTdxQuoteEndToEnd,
  type ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";

/** Recorded fixture for YAML parsing logic only (clearly named as a test fixture). */
const FIXTURE_KIMI_K3_DEPLOYMENT_YAML = `cvm-version: 0.14.14
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

const REPORT_SIZE = 1184;
const EXPECTED_TURIN_TCB = { fmc: 0, bootloader: 4, tee: 0, snp: 24, microcode: 213 };

function buildFixtureSnpReportBytes(): Uint8Array {
  const out = new Uint8Array(REPORT_SIZE);
  const dv = new DataView(out.buffer);
  dv.setUint32(0x00, 5, true); // version 5
  dv.setUint32(0x04, 0, true); // guestSvn 0
  dv.setBigUint64(0x08, (BigInt(1) << BigInt(17)) | (BigInt(1) << BigInt(8)), true); // policy 0x20100
  dv.setUint32(0x30, 0, true); // vmpl 0
  dv.setUint32(0x34, 1, true); // signatureAlgo ECDSA-P384-SHA384
  const tcbU64 =
    (BigInt(EXPECTED_TURIN_TCB.fmc) << BigInt(0)) |
    (BigInt(EXPECTED_TURIN_TCB.bootloader) << BigInt(8)) |
    (BigInt(EXPECTED_TURIN_TCB.tee) << BigInt(16)) |
    (BigInt(EXPECTED_TURIN_TCB.snp) << BigInt(24)) |
    (BigInt(EXPECTED_TURIN_TCB.microcode) << BigInt(56));
  dv.setBigUint64(0x38, tcbU64, true);
  dv.setBigUint64(0x180, tcbU64, true);
  out[0x188] = 0x1a; // family 0x1A (Turin)
  out[0x189] = 0x02;
  out.fill(0xaa, 0x50, 0x50 + 64); // reportData
  out.fill(0xbb, 0x90, 0x90 + 48); // measurement
  out.fill(0xcc, 0x1a0, 0x1a0 + 64); // chipId
  return out;
}

function buildFixtureModelAttestation(
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

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

describe("Two-Hop Enclave & GPU Trust Verifier", () => {
  it("decodeSnpReportBytes accurately parses a 1,184-byte binary SNP report fixture", () => {
    const rawBytes = buildFixtureSnpReportBytes();
    expect(rawBytes.length).toBe(REPORT_SIZE);
    expect(rawBytes.length).toBe(1184);

    const decoded = decodeSnpReportBytes(rawBytes);
    expect(decoded.version).toBe(5);
    expect(decoded.guestSvn).toBe(0);
    expect(decoded.debugAllowed).toBe(false);
    expect(decoded.smtAllowed).toBe(false);
    expect(decoded.migrationAllowed).toBe(false);
    expect(decoded.vmpl).toBe(0);
    expect(decoded.tcb).toEqual(EXPECTED_TURIN_TCB);
    expect(decoded.chipIdHex).toBe(toHex(new Uint8Array(64).fill(0xcc)));
    expect(decoded.measurementHex).toBe(toHex(new Uint8Array(48).fill(0xbb)));
    expect(decoded.reportDataHex).toBe(toHex(new Uint8Array(64).fill(0xaa)));
  });

  it("parseDeploymentConfigYaml extracts weightRepoCommit, weightMpkHash, containerImageDigest, and ccGpuFlagsVerified from Kimi K3 YAML fixture", () => {
    const parsed = parseDeploymentConfigYaml(FIXTURE_KIMI_K3_DEPLOYMENT_YAML);
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

    const unsafeYaml = FIXTURE_KIMI_K3_DEPLOYMENT_YAML.replace(
      'VLLM_DISABLE_UVA: "1"',
      'VLLM_DISABLE_UVA: "0"',
    );
    expect(parseDeploymentConfigYaml(unsafeYaml).ccGpuFlagsVerified).toBe(false);
  });

  it("verifyModelEnclaveStatus passes when hosts are verified and GPUs are in CC mode, and fails on unverified hosts, 0 GPUs, or unavailable status", () => {
    const healthy = buildFixtureModelAttestation();
    const res = verifyModelEnclaveStatus(healthy);
    expect(res.c5Pass).toBe(true);
    expect(res.c5Detail).toContain(
      "8× NVIDIA confidential GPUs attested by router (1/1 hosts healthy, TDX + CC mode, VLLM_DISABLE_UVA=1, SYMM_MEM=0",
    );
    expect(res.c7Pass).toBe(true);
    expect(res.c7Detail).toBe(
      "Pinned weight package mpk-58d5e74b… (moonshotai/Kimi-K3@a590ce09) on dm-verity root 41068e07…",
    );

    const withUnverified = buildFixtureModelAttestation({
      configuredHosts: 2,
      verifiedHosts: 1,
      unverifiedHosts: 1,
    });
    expect(verifyModelEnclaveStatus(withUnverified).c5Pass).toBe(false);

    const withZeroGpus = buildFixtureModelAttestation({
      vmShape: { cpus: 32, memoryMb: 524288, gpus: 0, disks: 5 },
    });
    expect(verifyModelEnclaveStatus(withZeroGpus).c5Pass).toBe(false);

    const withoutRootHash = buildFixtureModelAttestation({
      dmVerityRootHash: "",
    });
    expect(verifyModelEnclaveStatus(withoutRootHash).c7Pass).toBe(false);

    const unavailableModel = buildFixtureModelAttestation({
      status: "unavailable",
      unavailableReason: "Upstream release manifest unreachable",
    });
    const unavailableRes = verifyModelEnclaveStatus(unavailableModel);
    expect(unavailableRes.c5Pass).toBe(false);
    expect(unavailableRes.c7Pass).toBe(false);
    expect(unavailableRes.c5Detail).toContain("Unavailable: Upstream release manifest unreachable");

    const failedSigstore = buildFixtureModelAttestation({
      sigstoreVerified: false,
    });
    expect(verifyModelEnclaveStatus(failedSigstore).c5Pass).toBe(false);
    expect(verifyModelEnclaveStatus(failedSigstore).c7Pass).toBe(false);
  });

  it("checksFromDocument keeps C1-C7 labels stable, surfaces AMD SEV-SNP chain result, and upgrades C5 and C7 from model attestation", () => {
    const fixtureDoc = {
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

    const checks = checksFromDocument(fixtureDoc, buildFixtureModelAttestation(), {
      verified: true,
      productName: "Genoa",
      arkSubject: "CN=ARK-Genoa, O=Advanced Micro Devices",
      askSubject: "CN=SEV-Genoa, O=Advanced Micro Devices",
      vcekSubject: "CN=SEV-VCEK, O=Advanced Micro Devices",
      arkFingerprintSha256: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
      askFingerprintSha256: "5464738c1546aed5f2cecf1dc98c5c960a92e8913238a61711bc90ec6e828521",
      vcekFingerprintSha256: "abcd",
      arkSelfSigned: true,
      askSignedByArk: true,
      vcekSignedByAsk: true,
      vcekTcbMatched: true,
      vcekHwidMatched: true,
      reportSignatureVerified: true,
      kdsVcekUrl: "https://kdsintf.amd.com/vcek/v1/Genoa/chip",
      kdsCertChainUrl: "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain",
    });

    expect(checks.map((c) => `${c.id}:${c.label}`)).toEqual([
      "C1:Hardware signature chain",
      "C2:Approved software",
      "C3:HPKE key bound to enclave report",
      "C4:Running code = released code",
      "C5:Router-attested confidential GPU pool",
      "C6:Registry admission",
      "C7:Manifest-pinned model & dm-verity root",
    ]);

    const c1 = checks.find((c) => c.id === "C1");
    const c5 = checks.find((c) => c.id === "C5");
    const c7 = checks.find((c) => c.id === "C7");
    expect(c1?.status).toBe("pass");
    expect(c1?.detail).toContain("VCEK -> CN=SEV-Genoa -> CN=ARK-Genoa");
    expect(c5?.status).toBe("pass");
    expect(c5?.detail).toContain("8× NVIDIA confidential GPUs attested by router");
    expect(c7?.status).toBe("pass");
    expect(c7?.detail).toContain("Pinned weight package mpk-58d5e74b…");

    // Without modelAttestation, both C5 and C7 must be "skip", never "pass"
    const checksWithoutModel = checksFromDocument(fixtureDoc);
    expect(checksWithoutModel.find((c) => c.id === "C5")?.status).toBe("skip");
    expect(checksWithoutModel.find((c) => c.id === "C7")?.status).toBe("skip");
  });

  it("verifyNvidiaEatJwtAgainstJwks cryptographically verifies ES384 EAT JWTs and rejects tampered tokens", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"],
    );
    const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const kid = "nv-eat-test-kid-01";
    const jwks = {
      keys: [{ ...pubJwk, kid }],
    };

    const headerB64 = toBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "ES384", typ: "JWT", kid })),
    );
    const payloadB64 = toBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          iss: "https://nras.attestation.nvidia.com",
          "x-nvidia-overall-att-result": true,
          secboot: true,
          dbgstat: "disabled",
        }),
      ),
    );
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sigBuf = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-384" },
      keyPair.privateKey,
      signingInput,
    );
    const jwt = `${headerB64}.${payloadB64}.${toBase64Url(new Uint8Array(sigBuf))}`;

    const verified = await verifyNvidiaEatJwtAgainstJwks(jwt, jwks);
    expect(verified.verified).toBe(true);
    expect(verified.kid).toBe(kid);
    expect(verified.overallAttResult).toBe(true);
    expect(verified.secboot).toBe(true);
    expect(verified.dbgstat).toBe("disabled");

    // Tamper signature byte
    const tamperedSig = new Uint8Array(sigBuf);
    tamperedSig[0] ^= 0xff;
    const tamperedJwt = `${headerB64}.${payloadB64}.${toBase64Url(tamperedSig)}`;
    const failed = await verifyNvidiaEatJwtAgainstJwks(tamperedJwt, jwks);
    expect(failed.verified).toBe(false);
  });

  it("returns explicit unavailable state with reason when upstream is disabled or unreachable (no snapshot fallbacks)", async () => {
    const prevStub = process.env.DROUTER_STUB_UPSTREAM;
    process.env.DROUTER_STUB_UPSTREAM = "1";
    try {
      const matrixRes = await getEnclaveMatrix();
      expect(matrixRes.status).toBe(503);
      const matrixJson = await matrixRes.json();
      expect(matrixJson.status).toBe("unavailable");
      expect(matrixJson.unavailable).toBe(true);
      expect(matrixJson.unavailableReason).toContain("DROUTER_STUB_UPSTREAM=1");
      expect(matrixJson.routerHost).toBe("");
      expect(matrixJson.routerReleaseDigest).toBe("");
      expect(matrixJson.models["kimi-k3"].status).toBe("unavailable");
      expect(matrixJson.models["kimi-k3"].enclaveHosts).toEqual([]);

      const attRes = await getRelayAttestation(new Request("http://localhost:3000/api/relay/attestation"));
      expect(attRes.status).toBe(503);
      const attJson = await attRes.json();
      expect(attJson.status).toBe("unavailable");
      expect(attJson.unavailable).toBe(true);

      const hopRes = await getHopRelayAttestation(
        new Request("http://localhost:3000/api/relay/relay-eu-zurich/attestation"),
        { params: Promise.resolve({ relayId: "relay-eu-zurich" }) },
      );
      expect(hopRes.status).toBe(503);
      expect(hopRes.headers.get("x-drouter-relay-hop")).toBe("relay-eu-zurich");
      const hopJson = await hopRes.json();
      expect(hopJson.status).toBe("unavailable");
      expect(hopJson.unavailable).toBe(true);
    } finally {
      if (prevStub === undefined) {
        delete process.env.DROUTER_STUB_UPSTREAM;
      } else {
        process.env.DROUTER_STUB_UPSTREAM = prevStub;
      }
    }
  });

  it(
    "cryptographically verifies live router AMD SEV-SNP (Genoa), model AMD SEV-SNP (Turin), and model Intel TDX v4 quotes end-to-end",
    async () => {
      if (process.env.DROUTER_STUB_UPSTREAM === "1") return;

      // 1. Router AMD SEV-SNP (Genoa) end-to-end chain verification
      const [routerAtc, genoaChainRes] = await Promise.all([
        fetch("https://atc.tinfoil.sh/attestation").then((r) => r.json()),
        fetch("https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain").then((r) => r.text()),
      ]);
      const routerReportBytes = new Uint8Array(
        gunzipSync(Buffer.from(routerAtc.enclaveAttestationReport.body, "base64")),
      );
      const routerChain = await verifyAmdSevSnpChainEndToEnd(
        routerReportBytes,
        routerAtc.vcek,
        genoaChainRes,
      );
      expect(routerChain.verified).toBe(true);
      expect(routerChain.productName).toBe("Genoa");
      expect(routerChain.arkSelfSigned).toBe(true);
      expect(routerChain.askSignedByArk).toBe(true);
      expect(routerChain.vcekSignedByAsk).toBe(true);
      expect(routerChain.vcekTcbMatched).toBe(true);
      expect(routerChain.vcekHwidMatched).toBe(true);
      expect(routerChain.reportSignatureVerified).toBe(true);

      // Tampering a byte in the signed region must fail ECDSA-P384 verification
      const tamperedRouterBytes = new Uint8Array(routerReportBytes);
      tamperedRouterBytes[0x90] ^= 0xff;
      const tamperedChain = await verifyAmdSevSnpChainEndToEnd(
        tamperedRouterBytes,
        routerAtc.vcek,
        genoaChainRes,
      );
      expect(tamperedChain.verified).toBe(false);
      expect(tamperedChain.reportSignatureVerified).toBe(false);

      // 2. Model enclave Intel TDX v4 quote end-to-end verification (deepseek-v4-1-flash)
      const proxy = await fetch("https://inference.tinfoil.sh/.well-known/tinfoil-proxy").then(
        (r) => r.json(),
      );
      const dsModel = proxy.models["deepseek-v4-1-flash"];
      const dsHost =
        Object.keys(dsModel.enclaves).find(
          (h) => dsModel.verification?.hosts?.[h]?.code_tag === dsModel.tag,
        ) ?? Object.keys(dsModel.enclaves)[0];
      const dsAtt = await fetch(`https://${dsHost}/.well-known/tinfoil-attestation`).then((r) =>
        r.json(),
      );
      const dsQuoteBytes = new Uint8Array(gunzipSync(Buffer.from(dsAtt.body, "base64")));
      const parsedTdx = decodeTdxQuoteBytes(dsQuoteBytes);
      expect(parsedTdx.version).toBe(4);
      expect(parsedTdx.teeType).toBe(0x81);
      expect(parsedTdx.pckCertChainPems.length).toBe(3);

      const tdxVerified = await verifyTdxQuoteEndToEnd(dsQuoteBytes, {
        rtmr1Hex: dsModel.measurement.registers[1],
        rtmr2Hex: dsModel.measurement.registers[2],
      });
      expect(tdxVerified.verified).toBe(true);
      expect(tdxVerified.pckChainVerified).toBe(true);
      expect(tdxVerified.qeReportSignatureVerified).toBe(true);
      expect(tdxVerified.attKeyBindingVerified).toBe(true);
      expect(tdxVerified.quoteBodySignatureVerified).toBe(true);
      expect(tdxVerified.rtmr1Matched).toBe(true);
      expect(tdxVerified.rtmr2Matched).toBe(true);
    },
    25_000,
  );

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
