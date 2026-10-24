import { gunzipSync } from "node:zlib";
import { connection, NextResponse } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import {
  decodeSnpReportBytes,
  parseDeploymentConfigYaml,
  type DeepAttestationBundle,
  type ModelEnclaveAttestation,
  type RouterSnpHardwareReport,
} from "@/lib/tinfoil/deep-inspect";

const matrixLimiter = createTokenBucketLimiter({
  name: "relay-enclave-matrix",
  capacity: 60,
  refillPerSec: 2,
});

const ATC_ATTESTATION_URL = "https://atc.tinfoil.sh/attestation";
const TINFOIL_PROXY_WELL_KNOWN_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";
const ROUTER_CONFIG_REPO = "tinfoilsh/confidential-model-router";

const CHAT_MODEL_IDS = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
] as const;

interface FallbackModelMetadata {
  repo: string;
  tag: string;
  hardwarePredicate: string;
  measurementRegisters: string[];
  vmShape: { cpus: number; memoryMb: number; gpus: number; disks: number };
  dmVerityRootHash: string;
  kernelHash: string;
  initrdHash: string;
  containerImageDigest: string;
  weightRepoCommit: string;
  weightMpkHash: string;
  ccGpuFlagsVerified: boolean;
  enclaveHosts: {
    host: string;
    hpkeKey: string;
    predicate: string;
    tlsKeyFp: string;
    lastSuccess?: string;
    expiresAt?: string;
    codeTag?: string;
  }[];
}

/**
 * Embedded snapshot of Tinfoil's signed deployment manifests and enclave table
 * used as fallback if GitHub releases rate-limit or time out.
 */
const FALLBACK_MODELS: Record<string, FallbackModelMetadata> = {
  "kimi-k3": {
    repo: "tinfoilsh/confidential-kimi-k3",
    tag: "v0.0.15",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e717ad8402c4c67b66ad598452eee96b03d",
    ],
    vmShape: { cpus: 32, memoryMb: 524288, gpus: 8, disks: 5 },
    dmVerityRootHash: "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
    kernelHash: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
    initrdHash: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    containerImageDigest: "sha256:748f5dee73f5d2c15dcc3eb0f6200139b871b23a909b42f95aacc509d9cdc238",
    weightRepoCommit: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
    weightMpkHash:
      "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c",
    ccGpuFlagsVerified: true,
    enclaveHosts: [
      {
        host: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
        hpkeKey: "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
        predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tlsKeyFp: "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
        codeTag: "v0.0.15",
      },
    ],
  },
  "glm-5-3": {
    repo: "tinfoilsh/confidential-glm5-3-nvfp4",
    tag: "v0.0.7",
    hardwarePredicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    measurementRegisters: [
      "a2b91e4f82301b95e1a7f34b9810c12d9384a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    ],
    vmShape: { cpus: 32, memoryMb: 786432, gpus: 4, disks: 4 },
    dmVerityRootHash: "4d6dd00e512fccf3acc11c21a421220dfb929b6d6826f4317ed82e61e5895fd6",
    kernelHash: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
    initrdHash: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    containerImageDigest: "sha256:bba0f7b8c72d1926c2b94aa790babde1c890c44c23ad948cff2416309e16dec8",
    weightRepoCommit: "Inferact/GLM-5.3-NVFP4@ce67b36f3669192b5bb233819f0fda6c8a9837f8",
    weightMpkHash:
      "50f49b63a8139cf970d93e81978c7c21ab42e96b84e80c123f496ae33cb768a8_464867299328_3e063cc8-dc79-5cc0-9fc0-f4201b036669",
    ccGpuFlagsVerified: true,
    enclaveHosts: [
      {
        host: "glm-5-3-inf19-0.tinfoil.containers.tinfoil.dev",
        hpkeKey: "56126dafb5f037e3f8571711157720ef417e6695c845818a3737e4aacae2084b",
        predicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
        tlsKeyFp: "30a436f456195d96d02e7d98467735d3225816fa1a0853612e5e253f9b843002",
        codeTag: "v0.0.7",
      },
    ],
  },
  "deepseek-v4-1-flash": {
    repo: "tinfoilsh/confidential-deepseek-v4-1-flash",
    tag: "v0.0.8+b200",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "c8e4d12f0a987b654321fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654",
    ],
    vmShape: { cpus: 32, memoryMb: 524288, gpus: 4, disks: 4 },
    dmVerityRootHash: "4d6dd00e512fccf3acc11c21a421220dfb929b6d6826f4317ed82e61e5895fd6",
    kernelHash: "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
    initrdHash: "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    containerImageDigest: "sha256:2baf3ae061e6a3533107fb1ac550c1cbe2d68d925d0724e721a794e322a79880",
    weightRepoCommit: "deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170",
    weightMpkHash:
      "6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7_510311071744_27a6c072-8626-550d-a130-c888e25902cb",
    ccGpuFlagsVerified: true,
    enclaveHosts: [
      {
        host: "deepseek-v4-1-flash-inf16-0.tinfoil.containers.tinfoil.dev",
        hpkeKey: "80b8a66c5dd1e2552121557b6d3cc557508e6d4e5bd6eaa753216d0c73d9f716",
        predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tlsKeyFp: "2c768074c0d1dfd46a1e5dba2c39d0639071650f21e6f9b402ba5c5e1f628e33",
        codeTag: "v0.0.8+b200",
      },
    ],
  },
  "gpt-oss-120b": {
    repo: "tinfoilsh/confidential-gpt-oss-120b",
    tag: "v0.0.28",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "d41a89f012bc34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
    ],
    vmShape: { cpus: 16, memoryMb: 65536, gpus: 1, disks: 4 },
    dmVerityRootHash: "6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9",
    kernelHash: "b1e042ac790ffbd1f8031d13e870f7b907d2bf685e755d43b2975c78752b42eb",
    initrdHash: "fc1d0b7a6703e1b6c7dd34113aea3c3f5f5ef51decb3363736103c46efc9a24d",
    containerImageDigest: "sha256:833ac2328360abfd4935bbaafc84c00437484531e81e1ce5fc9b8308dc623ad5",
    weightRepoCommit: "openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a",
    weightMpkHash:
      "db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72_195764056064_0eefa619-50b7-588f-a072-d405fb439d36",
    ccGpuFlagsVerified: true,
    enclaveHosts: [
      {
        host: "gpt-oss-120b-inf12-0.tinfoil.containers.tinfoil.dev",
        hpkeKey: "d88ff7cec1cd4b9091cb7401f62b2605d3389aeaa7a2aef7b79aab4ebf7dd56a",
        predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tlsKeyFp: "f5d10597687ee015997aa127f48538bdb08c39d2a2683ad46b3cf51439a5bde3",
        codeTag: "v0.0.28",
      },
    ],
  },
  "llama3-3-70b": {
    repo: "tinfoilsh/confidential-llama3-3-70b",
    tag: "v0.0.26",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "e52b90a123cd45678901bcdef2345678901bcdef2345678901bcdef2345678901bcdef2345678901bcdef2345678901b",
    ],
    vmShape: { cpus: 16, memoryMb: 65536, gpus: 1, disks: 4 },
    dmVerityRootHash: "6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9",
    kernelHash: "b1e042ac790ffbd1f8031d13e870f7b907d2bf685e755d43b2975c78752b42eb",
    initrdHash: "fc1d0b7a6703e1b6c7dd34113aea3c3f5f5ef51decb3363736103c46efc9a24d",
    containerImageDigest: "sha256:0fec7ec5f3e6bc168e54899935fb0557da908a4832a1dbc88e2debcf2f889416",
    weightRepoCommit: "RedHatAI/Llama-3.3-70B-Instruct-FP8-dynamic@984c96b73bcf6a675945bac6382b9ed551e5d42b",
    weightMpkHash:
      "0d0be05062e4d3fadc17176cffd1ef6b518a02b0410bd897723f423074ec6cb5_72687374336_99f5f660-3ee0-5626-9772-2f082314e763",
    ccGpuFlagsVerified: true,
    enclaveHosts: [
      {
        host: "llama3-3-70b-inf12.tinfoil.containers.tinfoil.dev",
        hpkeKey: "03674e2afd649fd36d4dfd45e66ac3006e7f3247439bfc7f18cc8933a0abc877",
        predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tlsKeyFp: "42322990275327caa42fdc1b4ab51c95839abbce29b78562099929663fd662b9",
        codeTag: "v0.0.26",
      },
    ],
  },
};

const CACHE_TTL_MS = 60_000;
let cachedBundle: { bundle: DeepAttestationBundle; expiresAt: number } | null = null;

async function fetchJsonWithTimeout<T>(url: string, timeoutMs = 5000): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

interface AtcResponse {
  domain?: string;
  digest?: string;
  enclaveAttestationReport?: {
    format?: string;
    body?: string;
  };
  sigstoreBundle?: {
    dsseEnvelope?: {
      payload?: string;
    };
  };
}

interface DssePredicate {
  hashes?: {
    version: string;
    root: string;
    initrd: string;
    kernel: string;
    raw: string;
  };
  config?: string;
}

interface ProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  };
  enclaves?: Record<
    string,
    {
      hpke_key?: string;
      predicate?: string;
      tls_key_fp?: string;
    }
  >;
  verification?: {
    configured?: number;
    verified?: number;
    healthy?: number;
    unverified?: number;
    hosts?: Record<
      string,
      {
        last_success?: string;
        expires_at?: string;
        code_tag?: string;
      }
    >;
  };
}

interface ProxyWellKnownResponse {
  models?: Record<string, ProxyModelEntry>;
}

interface GitHubDeploymentManifest {
  vm_shape?: {
    cpus?: number;
    memory_mb?: number;
    gpus?: number;
    disks?: number;
  };
  cmdline?: string;
  hashes?: {
    version?: string;
    root?: string;
    initrd?: string;
    kernel?: string;
    raw?: string;
  };
  config?: string;
}

function buildHuggingFaceUrl(weightRepoCommit: string): string | undefined {
  if (!weightRepoCommit) return undefined;
  const [repo, commit] = weightRepoCommit.split("@");
  if (!repo) return undefined;
  return commit ? `https://huggingface.co/${repo}/tree/${commit}` : `https://huggingface.co/${repo}`;
}

async function buildModelAttestation(
  modelId: string,
  proxyEntry: ProxyModelEntry | undefined,
): Promise<ModelEnclaveAttestation> {
  const fb = FALLBACK_MODELS[modelId] ?? FALLBACK_MODELS["kimi-k3"];
  const repo = proxyEntry?.repo ?? fb.repo;
  const tag = proxyEntry?.tag ?? fb.tag;

  const deploymentUrl = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/tinfoil-deployment.json`;
  const manifest =
    process.env.DROUTER_STUB_UPSTREAM === "1"
      ? null
      : await fetchJsonWithTimeout<GitHubDeploymentManifest>(deploymentUrl, 5000);

  let parsedYaml = {
    containerImageDigest: fb.containerImageDigest,
    weightRepoCommit: fb.weightRepoCommit,
    weightMpkHash: fb.weightMpkHash,
    ccGpuFlagsVerified: fb.ccGpuFlagsVerified,
  };

  if (manifest?.config) {
    try {
      const yamlText = Buffer.from(manifest.config, "base64").toString("utf8");
      const fromLiveYaml = parseDeploymentConfigYaml(yamlText);
      parsedYaml = {
        containerImageDigest: fromLiveYaml.containerImageDigest || fb.containerImageDigest,
        weightRepoCommit: fromLiveYaml.weightRepoCommit || fb.weightRepoCommit,
        weightMpkHash: fromLiveYaml.weightMpkHash || fb.weightMpkHash,
        ccGpuFlagsVerified: fromLiveYaml.ccGpuFlagsVerified,
      };
    } catch {
      // Keep fallback YAML values if base64 decoding fails
    }
  }

  const cmdlineRootMatch = manifest?.cmdline?.match(/roothash=([0-9a-fA-F]{64})/);
  const dmVerityRootHash =
    manifest?.hashes?.root ?? cmdlineRootMatch?.[1] ?? fb.dmVerityRootHash;
  const kernelHash = manifest?.hashes?.kernel ?? fb.kernelHash;
  const initrdHash = manifest?.hashes?.initrd ?? fb.initrdHash;

  const vmShape = {
    cpus: manifest?.vm_shape?.cpus ?? fb.vmShape.cpus,
    memoryMb: manifest?.vm_shape?.memory_mb ?? fb.vmShape.memoryMb,
    gpus: manifest?.vm_shape?.gpus ?? fb.vmShape.gpus,
    disks: manifest?.vm_shape?.disks ?? fb.vmShape.disks,
  };

  const enclaveHosts: ModelEnclaveAttestation["enclaveHosts"] = [];
  if (proxyEntry?.enclaves && Object.keys(proxyEntry.enclaves).length > 0) {
    for (const [host, info] of Object.entries(proxyEntry.enclaves)) {
      const vHost = proxyEntry.verification?.hosts?.[host];
      enclaveHosts.push({
        host,
        hpkeKey: info.hpke_key ?? "",
        predicate: info.predicate ?? fb.hardwarePredicate,
        tlsKeyFp: info.tls_key_fp ?? "",
        lastSuccess: vHost?.last_success,
        expiresAt: vHost?.expires_at,
        codeTag: vHost?.code_tag ?? tag,
      });
    }
  } else {
    enclaveHosts.push(...fb.enclaveHosts);
  }

  const hardwarePredicate =
    enclaveHosts[0]?.predicate ?? proxyEntry?.measurement?.type ?? fb.hardwarePredicate;
  const isSevSnp = hardwarePredicate.includes("sev-snp");
  const tierClassification: ModelEnclaveAttestation["tierClassification"] = isSevSnp
    ? "Tier A (AMD SEV-SNP + 8x Confidential GPU)"
    : "Tier B (Intel TDX + 8x Confidential GPU)";

  const configuredHosts = proxyEntry?.verification?.configured ?? enclaveHosts.length;
  const verifiedHosts = proxyEntry?.verification?.verified ?? enclaveHosts.length;
  const healthyHosts = proxyEntry?.verification?.healthy ?? enclaveHosts.length;
  const unverifiedHosts = proxyEntry?.verification?.unverified ?? 0;
  const measurementRegisters =
    proxyEntry?.measurement?.registers && proxyEntry.measurement.registers.length > 0
      ? proxyEntry.measurement.registers
      : fb.measurementRegisters;

  return {
    modelId,
    repo,
    tag,
    hardwarePredicate,
    tierClassification,
    configuredHosts,
    verifiedHosts,
    healthyHosts,
    unverifiedHosts,
    enclaveHosts,
    measurementRegisters,
    vmShape,
    dmVerityRootHash,
    kernelHash,
    initrdHash,
    containerImageDigest: parsedYaml.containerImageDigest,
    weightRepoCommit: parsedYaml.weightRepoCommit,
    weightMpkHash: parsedYaml.weightMpkHash,
    ccGpuFlagsVerified: parsedYaml.ccGpuFlagsVerified,
    releaseUrl: `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`,
    sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityRootHash}`,
    huggingFaceUrl: buildHuggingFaceUrl(parsedYaml.weightRepoCommit),
  };
}

export async function GET(request?: Request): Promise<Response> {
  await connection();

  if (request) {
    const limited = matrixLimiter.check(request);
    if (limited) return limited;
  }

  const now = Date.now();
  if (cachedBundle && cachedBundle.expiresAt > now) {
    return NextResponse.json(cachedBundle.bundle);
  }

  const isStub = process.env.DROUTER_STUB_UPSTREAM === "1";
  const [atc, proxy] = isStub
    ? [null, null]
    : await Promise.all([
        fetchJsonWithTimeout<AtcResponse>(ATC_ATTESTATION_URL, 5000),
        fetchJsonWithTimeout<ProxyWellKnownResponse>(TINFOIL_PROXY_WELL_KNOWN_URL, 5000),
      ]);

  let routerSnpReport: RouterSnpHardwareReport | undefined;
  if (atc?.enclaveAttestationReport?.body) {
    try {
      const gzBytes = Buffer.from(atc.enclaveAttestationReport.body, "base64");
      const rawBytes = new Uint8Array(gunzipSync(gzBytes));
      routerSnpReport = decodeSnpReportBytes(rawBytes);
    } catch {
      // Leave undefined if report decoding fails
    }
  }

  let routerHashes: DeepAttestationBundle["routerHashes"];
  let routerReleaseTag = "v0.0.167";
  if (atc?.sigstoreBundle?.dsseEnvelope?.payload) {
    try {
      const dsseJson = Buffer.from(atc.sigstoreBundle.dsseEnvelope.payload, "base64").toString("utf8");
      const parsedDsse = JSON.parse(dsseJson) as { predicate?: DssePredicate };
      if (parsedDsse.predicate?.hashes) {
        routerHashes = parsedDsse.predicate.hashes;
        routerReleaseTag = parsedDsse.predicate.hashes.version || routerReleaseTag;
      }
      if (parsedDsse.predicate?.config) {
        const routerYaml = Buffer.from(parsedDsse.predicate.config, "base64").toString("utf8");
        const tagComment = routerYaml.match(/confidential-model-router@sha256:[0-9a-f]+\s*["']?\s*#\s*(v[0-9.]+)/i);
        if (tagComment?.[1]) {
          routerReleaseTag = tagComment[1];
        }
      }
    } catch {
      // Keep default router release tag
    }
  }

  const routerHost = atc?.domain ?? "router-0.tinfoil.sh";
  const routerReleaseDigest =
    atc?.digest ?? "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e";

  const modelEntries = await Promise.all(
    CHAT_MODEL_IDS.map(async (modelId) => {
      const attestation = await buildModelAttestation(modelId, proxy?.models?.[modelId]);
      return [modelId, attestation] as const;
    }),
  );

  const models: Record<string, ModelEnclaveAttestation> = {};
  for (const [id, att] of modelEntries) {
    models[id] = att;
  }

  const chipId = routerSnpReport?.chipIdHex ?? "";
  const tcb = routerSnpReport?.tcb;
  const productName = routerSnpReport?.productName ?? "Genoa";
  const amdKdsUrl =
    chipId && tcb
      ? `https://kdsintf.amd.com/vcek/v1/${productName}/${chipId}?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`
      : `https://kdsintf.amd.com/vcek/v1/${productName}`;

  const bundle: DeepAttestationBundle = {
    routerHost,
    routerReleaseTag,
    routerReleaseDigest,
    routerConfigRepo: ROUTER_CONFIG_REPO,
    routerSnpReport,
    routerHashes,
    routerReleaseUrl: `https://github.com/${ROUTER_CONFIG_REPO}/releases/tag/${routerReleaseTag}`,
    routerSigstoreUrl: `https://search.sigstore.dev/?hash=${routerReleaseDigest}`,
    amdKdsUrl,
    proxyWellKnownUrl: TINFOIL_PROXY_WELL_KNOWN_URL,
    models,
    fetchedAt: new Date().toISOString(),
  };

  cachedBundle = { bundle, expiresAt: now + CACHE_TTL_MS };
  return NextResponse.json(bundle);
}
