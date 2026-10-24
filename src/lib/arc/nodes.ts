import { formatUnits, keccak256, toHex } from "viem";
import type { Hex, NodeKind, NodeRecord, NodeStatus } from "@/lib/types";

const hashString = (s: string): Hex => keccak256(toHex(s));

export const TINFOIL_PROXY_WELL_KNOWN_URL =
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";

export const LEGACY_SIM_KEYS = ["sim-1", "sim-2", "sim-3"] as const;
const LEGACY_SIM_IDS = new Set<string>(
  LEGACY_SIM_KEYS.map((k) => hashString(k).toLowerCase()),
);

export function buildModelMeasurementSource(
  repo: string,
  releaseTag: string,
  registers: readonly string[],
): string {
  return `${repo}@${releaseTag}:${registers.join(":")}`;
}

export interface TinfoilNodeMetadata {
  key: string;
  modelId?: string;
  repo: string;
  releaseTag: string;
  hardwarePredicate: string;
  measurementRegisters: string[];
  hpkePublicKey?: string;
  tlsKeyFp?: string;
  enclaveHosts: string[];
  configuredHosts: number;
  verifiedHosts: number;
  healthyHosts: number;
}

export interface EnrichedNodeRecord extends NodeRecord, Partial<TinfoilNodeMetadata> {}

export interface DemoNodeDef extends TinfoilNodeMetadata {
  kind: NodeKind;
  name: string;
  endpoint: string;
  region: string;
  measurementSource: string;
}

const DEFS: DemoNodeDef[] = [
  {
    key: "tinfoil-router",
    kind: "tinfoil",
    name: "Tinfoil confidential router",
    endpoint: "inference.tinfoil.sh",
    region: "us",
    repo: "tinfoilsh/confidential-model-router",
    releaseTag: "v0.0.167",
    hardwarePredicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    measurementRegisters: [
      "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    ],
    measurementSource: "tinfoilsh/confidential-model-router",
    enclaveHosts: ["inference.tinfoil.sh", "router-0.tinfoil.sh"],
    configuredHosts: 1,
    verifiedHosts: 1,
    healthyHosts: 1,
  },
  {
    key: "tinfoil-kimi-k3",
    modelId: "kimi-k3",
    kind: "tinfoil",
    name: "Tinfoil Kimi K3 enclave",
    endpoint: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
    region: "us",
    repo: "tinfoilsh/confidential-kimi-k3",
    releaseTag: "v0.0.15",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e717ad8402c4c67b66ad598452eee96b03d",
    ],
    measurementSource: buildModelMeasurementSource(
      "tinfoilsh/confidential-kimi-k3",
      "v0.0.15",
      [
        "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
        "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
        "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e717ad8402c4c67b66ad598452eee96b03d",
      ],
    ),
    hpkePublicKey: "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
    tlsKeyFp: "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
    enclaveHosts: ["kimi-k3-inf14.tinfoil.containers.tinfoil.dev"],
    configuredHosts: 1,
    verifiedHosts: 1,
    healthyHosts: 1,
  },
  {
    key: "tinfoil-glm-5-3",
    modelId: "glm-5-3",
    kind: "tinfoil",
    name: "Tinfoil GLM-5.3 enclave",
    endpoint: "glm-5-3-inf19-0.tinfoil.containers.tinfoil.dev",
    region: "us",
    repo: "tinfoilsh/confidential-glm5-3-nvfp4",
    releaseTag: "v0.0.7",
    hardwarePredicate: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    measurementRegisters: [
      "b64eb23f1441a8f25e29d901782fbb82f894f434db70cb1658dd37c398715bfff070f3b732f2e623bf151e56d2699188",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "affb1973ecb2abb9edfe87939de38030f1a38ce4de08966e3580721b41436409d6bc9ab8c6dbdbe7a4476d360b639721",
    ],
    measurementSource: buildModelMeasurementSource(
      "tinfoilsh/confidential-glm5-3-nvfp4",
      "v0.0.7",
      [
        "b64eb23f1441a8f25e29d901782fbb82f894f434db70cb1658dd37c398715bfff070f3b732f2e623bf151e56d2699188",
        "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
        "affb1973ecb2abb9edfe87939de38030f1a38ce4de08966e3580721b41436409d6bc9ab8c6dbdbe7a4476d360b639721",
      ],
    ),
    hpkePublicKey: "56126dafb5f037e3f8571711157720ef417e6695c845818a3737e4aacae2084b",
    tlsKeyFp: "30a436f456195d96d02e7d98467735d3225816fa1a0853612e5e253f9b843002",
    enclaveHosts: [
      "glm-5-3-inf19-0.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf19-1.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf20-0.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf20-1.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf21-0.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf21-1.tinfoil.containers.tinfoil.dev",
      "glm-5-3-inf22-0.tinfoil.containers.tinfoil.dev",
    ],
    configuredHosts: 7,
    verifiedHosts: 7,
    healthyHosts: 7,
  },
  {
    key: "tinfoil-deepseek-v4-1-flash",
    modelId: "deepseek-v4-1-flash",
    kind: "tinfoil",
    name: "Tinfoil DeepSeek V4.1 Flash enclave",
    endpoint: "deepseek-v4-1-flash-inf15-0.tinfoil.containers.tinfoil.dev",
    region: "us",
    repo: "tinfoilsh/confidential-deepseek-v4-1-flash",
    releaseTag: "v0.0.8+b200",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "7f2fcb9d95e9173d468bc0a06af24cb31c56d675e0af21fd56b44fb63037e0debae98aac97c94bdd3cecbcf8c071664a",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "ad5b695ef9fbaa04321e33d49481c79a8d38bb849cac0b1df7db9a2f2ef34823fdc4cad270005a05df2773410b7194f3",
    ],
    measurementSource: buildModelMeasurementSource(
      "tinfoilsh/confidential-deepseek-v4-1-flash",
      "v0.0.8+b200",
      [
        "7f2fcb9d95e9173d468bc0a06af24cb31c56d675e0af21fd56b44fb63037e0debae98aac97c94bdd3cecbcf8c071664a",
        "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
        "ad5b695ef9fbaa04321e33d49481c79a8d38bb849cac0b1df7db9a2f2ef34823fdc4cad270005a05df2773410b7194f3",
      ],
    ),
    hpkePublicKey: "451e8b48d0c6af5bc4ee72b8c800395fd1a80de9d32c123b7ae60a4df9b1467c",
    tlsKeyFp: "d56f45c63c90d388e81832e124de063fb1700d0558ab9f85b62eb183f6a01900",
    enclaveHosts: [
      "deepseek-v4-1-flash-inf15-0.tinfoil.containers.tinfoil.dev",
      "deepseek-v4-1-flash-inf16-0.tinfoil.containers.tinfoil.dev",
      "deepseek-v4-1-flash-inf16-1.tinfoil.containers.tinfoil.dev",
    ],
    configuredHosts: 3,
    verifiedHosts: 3,
    healthyHosts: 3,
  },
  {
    key: "tinfoil-gpt-oss-120b",
    modelId: "gpt-oss-120b",
    kind: "tinfoil",
    name: "Tinfoil GPT-OSS 120B enclave",
    endpoint: "gpt-oss-120b-inf12-0.tinfoil.containers.tinfoil.dev",
    region: "us",
    repo: "tinfoilsh/confidential-gpt-oss-120b",
    releaseTag: "v0.0.28",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "fc301c823b6e8c4f942a91bd0aa8fca062b06169f37480629ebbbcd9189a8cc266908b762eff9a75629e244576729b62",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "2a3ef603ddb6020819386c1a2c518c23e6836f94b2902b15f65d8a18900c701640d6d7042d0991d29f0cec27e7267cf4",
    ],
    measurementSource: buildModelMeasurementSource(
      "tinfoilsh/confidential-gpt-oss-120b",
      "v0.0.28",
      [
        "fc301c823b6e8c4f942a91bd0aa8fca062b06169f37480629ebbbcd9189a8cc266908b762eff9a75629e244576729b62",
        "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
        "2a3ef603ddb6020819386c1a2c518c23e6836f94b2902b15f65d8a18900c701640d6d7042d0991d29f0cec27e7267cf4",
      ],
    ),
    hpkePublicKey: "d88ff7cec1cd4b9091cb7401f62b2605d3389aeaa7a2aef7b79aab4ebf7dd56a",
    tlsKeyFp: "f5d10597687ee015997aa127f48538bdb08c39d2a2683ad46b3cf51439a5bde3",
    enclaveHosts: [
      "gpt-oss-120b-inf12-0.tinfoil.containers.tinfoil.dev",
      "gpt-oss-120b-inf12-1.tinfoil.containers.tinfoil.dev",
      "gpt-oss-120b-inf12-2.tinfoil.containers.tinfoil.dev",
    ],
    configuredHosts: 3,
    verifiedHosts: 3,
    healthyHosts: 3,
  },
  {
    key: "tinfoil-llama3-3-70b",
    modelId: "llama3-3-70b",
    kind: "tinfoil",
    name: "Tinfoil Llama 3.3 70B enclave",
    endpoint: "llama3-3-70b-inf12.tinfoil.containers.tinfoil.dev",
    region: "us",
    repo: "tinfoilsh/confidential-llama3-3-70b",
    releaseTag: "v0.0.26",
    hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
    measurementRegisters: [
      "b99fec0d07a1313e686406c945ab07cd900ee11cdeef59f77efcd572943376853f6dae2d26bff905ba28fc61000a14d3",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "d05901d119685ef5354210c57f4cdd4f756f57c10bc4c2b1f811d6662326a6b9eb326d71c05871c216b94a84827a5dd2",
    ],
    measurementSource: buildModelMeasurementSource(
      "tinfoilsh/confidential-llama3-3-70b",
      "v0.0.26",
      [
        "b99fec0d07a1313e686406c945ab07cd900ee11cdeef59f77efcd572943376853f6dae2d26bff905ba28fc61000a14d3",
        "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
        "d05901d119685ef5354210c57f4cdd4f756f57c10bc4c2b1f811d6662326a6b9eb326d71c05871c216b94a84827a5dd2",
      ],
    ),
    hpkePublicKey: "03674e2afd649fd36d4dfd45e66ac3006e7f3247439bfc7f18cc8933a0abc877",
    tlsKeyFp: "42322990275327caa42fdc1b4ab51c95839abbce29b78562099929663fd662b9",
    enclaveHosts: ["llama3-3-70b-inf12.tinfoil.containers.tinfoil.dev"],
    configuredHosts: 1,
    verifiedHosts: 1,
    healthyHosts: 1,
  },
];

export const DEMO_NODES = DEFS.map((d) => ({
  ...d,
  id: hashString(d.key),
  measurement: hashString(d.measurementSource),
}));

export const REAL_NODES = DEMO_NODES;

const DEF_BY_ID = new Map<string, (typeof DEMO_NODES)[number]>(
  DEMO_NODES.map((n) => [n.id.toLowerCase(), n]),
);

const KEY_BY_ID = new Map<string, string>(
  DEMO_NODES.map((n) => [n.id.toLowerCase(), n.key]),
);

/** Node key ("tinfoil-router", "tinfoil-kimi-k3", ...) for a registry id, if it is one of the known real nodes. */
export function nodeKeyFor(id: Hex): string | undefined {
  return KEY_BY_ID.get(id.toLowerCase());
}

const ID_BY_KEY = new Map<string, Hex>();
for (const n of DEMO_NODES) {
  ID_BY_KEY.set(n.key, n.id);
  ID_BY_KEY.set(n.endpoint, n.id);
  ID_BY_KEY.set(n.repo, n.id);
  if (n.modelId) {
    ID_BY_KEY.set(n.modelId, n.id);
  }
  for (const host of n.enclaveHosts) {
    ID_BY_KEY.set(host, n.id);
  }
}

/** Registry bytes32 id for a node key ("tinfoil-router", "tinfoil-kimi-k3", "kimi-k3", host, ...), if it is a known real node. */
export function nodeIdFor(key: string): Hex | undefined {
  return ID_BY_KEY.get(key);
}

/** Returns true if an on-chain node record is a legacy simulated practice node that must be excluded from production APIs. */
export function isLegacySimNode(
  id: Hex,
  raw?: Pick<RawNode, "kind" | "endpoint">,
): boolean {
  if (LEGACY_SIM_IDS.has(id.toLowerCase())) return true;
  if (!raw) return false;
  if (raw.kind !== "tinfoil") return true;
  if (typeof raw.endpoint === "string" && raw.endpoint.startsWith("/api/sim/")) {
    return true;
  }
  return false;
}

export interface LiveProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  } | null;
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
  };
}

export interface LiveProxyTablePayload {
  models?: Record<string, LiveProxyModelEntry>;
  version?: string;
  updated?: string;
  observed_at?: string;
}

/**
 * Extracts live Tinfoil enclave metadata per registered node ID from Tinfoil's `.well-known/tinfoil-proxy` table.
 */
export function buildLiveMetadataByNodeId(
  proxyTable: LiveProxyTablePayload | null | undefined,
): Map<string, Partial<TinfoilNodeMetadata> & { endpoint?: string; measurement?: Hex }> {
  const out = new Map<
    string,
    Partial<TinfoilNodeMetadata> & { endpoint?: string; measurement?: Hex }
  >();
  if (!proxyTable || typeof proxyTable !== "object") return out;

  const routerNode = DEMO_NODES[0];
  if (routerNode && typeof proxyTable.version === "string" && proxyTable.version.trim()) {
    out.set(routerNode.id.toLowerCase(), {
      releaseTag: proxyTable.version.trim(),
    });
  }

  const rawModels = proxyTable.models;
  if (!rawModels || typeof rawModels !== "object") return out;

  for (const baseNode of DEMO_NODES) {
    if (!baseNode.modelId) continue;
    const entry = rawModels[baseNode.modelId];
    if (!entry || typeof entry !== "object") continue;

    const enclaves = entry.enclaves && typeof entry.enclaves === "object" ? entry.enclaves : {};
    const hosts = Object.keys(enclaves);
    const primaryHost = hosts[0] ?? baseNode.endpoint;
    const primaryInfo = enclaves[primaryHost];
    const registers =
      Array.isArray(entry.measurement?.registers) && entry.measurement.registers.length > 0
        ? entry.measurement.registers
        : baseNode.measurementRegisters;
    const repo = entry.repo || baseNode.repo;
    const releaseTag = entry.tag || baseNode.releaseTag;
    const hardwarePredicate =
      primaryInfo?.predicate || entry.measurement?.type || baseNode.hardwarePredicate;

    const configuredHosts = entry.verification?.configured ?? hosts.length;
    const verifiedHosts = entry.verification?.verified ?? hosts.length;
    const healthyHosts = entry.verification?.healthy ?? hosts.length;

    out.set(baseNode.id.toLowerCase(), {
      key: baseNode.key,
      modelId: baseNode.modelId,
      endpoint: primaryHost,
      repo,
      releaseTag,
      hardwarePredicate,
      measurementRegisters: registers,
      hpkePublicKey: primaryInfo?.hpke_key ?? baseNode.hpkePublicKey,
      tlsKeyFp: primaryInfo?.tls_key_fp ?? baseNode.tlsKeyFp,
      enclaveHosts: hosts.length > 0 ? hosts : baseNode.enclaveHosts,
      configuredHosts,
      verifiedHosts,
      healthyHosts,
      measurement: hashString(buildModelMeasurementSource(repo, releaseTag, registers)),
    });
  }

  return out;
}

const ZERO_ADDRESS: Hex = "0x0000000000000000000000000000000000000000";

/** The real Tinfoil nodes built locally from the proxy table, used when the Arc registry is not configured or unreachable. */
export function fallbackNodes(
  liveTable?: LiveProxyTablePayload | null,
): EnrichedNodeRecord[] {
  const liveById = buildLiveMetadataByNodeId(liveTable);
  return DEMO_NODES.map((n) => {
    const live = liveById.get(n.id.toLowerCase());
    return {
      id: n.id,
      key: n.key,
      ...(n.modelId ? { modelId: n.modelId } : {}),
      kind: n.kind,
      name: n.name,
      endpoint: live?.endpoint ?? n.endpoint,
      measurement: live?.measurement ?? n.measurement,
      operator: ZERO_ADDRESS,
      stake: "0",
      status: "active",
      region: n.region,
      registeredAt: 0,
      lastVerifiedAt: 0,
      lastVerifiedOk: false,
      repo: live?.repo ?? n.repo,
      releaseTag: live?.releaseTag ?? n.releaseTag,
      hardwarePredicate: live?.hardwarePredicate ?? n.hardwarePredicate,
      measurementRegisters: live?.measurementRegisters ?? n.measurementRegisters,
      ...(live?.hpkePublicKey ?? n.hpkePublicKey
        ? { hpkePublicKey: live?.hpkePublicKey ?? n.hpkePublicKey }
        : {}),
      ...(live?.tlsKeyFp ?? n.tlsKeyFp
        ? { tlsKeyFp: live?.tlsKeyFp ?? n.tlsKeyFp }
        : {}),
      enclaveHosts: live?.enclaveHosts ?? n.enclaveHosts,
      configuredHosts: live?.configuredHosts ?? n.configuredHosts,
      verifiedHosts: live?.verifiedHosts ?? n.verifiedHosts,
      healthyHosts: live?.healthyHosts ?? n.healthyHosts,
    };
  });
}

/** Shape of the `getNode` return value as decoded by viem. */
export interface RawNode {
  operator: Hex;
  kind: string;
  name: string;
  endpoint: string;
  measurement: Hex;
  region: string;
  stake: bigint;
  status: number;
  registeredAt: bigint;
  lastVerifiedAt: bigint;
  lastVerifiedOk: boolean;
}

const STATUSES: NodeStatus[] = ["active", "suspended", "revoked"];

export function mapNode(
  id: Hex,
  raw: RawNode,
  liveMeta?: Partial<TinfoilNodeMetadata>,
): EnrichedNodeRecord {
  const baseDef = DEF_BY_ID.get(id.toLowerCase());
  const baseRecord: EnrichedNodeRecord = {
    id,
    kind: raw.kind === "tinfoil" ? "tinfoil" : "sim",
    name: raw.name,
    endpoint: raw.endpoint,
    measurement: raw.measurement,
    operator: raw.operator,
    stake: formatUnits(raw.stake, 18),
    // Unknown status values are treated as untrusted.
    status: STATUSES[raw.status] ?? "revoked",
    region: raw.region,
    registeredAt: Number(raw.registeredAt),
    lastVerifiedAt: Number(raw.lastVerifiedAt),
    lastVerifiedOk: raw.lastVerifiedOk,
  };

  if (!baseDef && !liveMeta) {
    return baseRecord;
  }

  const key = liveMeta?.key ?? baseDef?.key;
  const modelId = liveMeta?.modelId ?? baseDef?.modelId;
  const repo = liveMeta?.repo ?? baseDef?.repo;
  const releaseTag = liveMeta?.releaseTag ?? baseDef?.releaseTag;
  const hardwarePredicate = liveMeta?.hardwarePredicate ?? baseDef?.hardwarePredicate;
  const measurementRegisters =
    liveMeta?.measurementRegisters ?? baseDef?.measurementRegisters;
  const hpkePublicKey = liveMeta?.hpkePublicKey ?? baseDef?.hpkePublicKey;
  const tlsKeyFp = liveMeta?.tlsKeyFp ?? baseDef?.tlsKeyFp;
  const enclaveHosts = liveMeta?.enclaveHosts ?? baseDef?.enclaveHosts;
  const configuredHosts = liveMeta?.configuredHosts ?? baseDef?.configuredHosts;
  const verifiedHosts = liveMeta?.verifiedHosts ?? baseDef?.verifiedHosts;
  const healthyHosts = liveMeta?.healthyHosts ?? baseDef?.healthyHosts;

  return {
    ...baseRecord,
    ...(key ? { key } : {}),
    ...(modelId ? { modelId } : {}),
    ...(repo ? { repo } : {}),
    ...(releaseTag ? { releaseTag } : {}),
    ...(hardwarePredicate ? { hardwarePredicate } : {}),
    ...(measurementRegisters ? { measurementRegisters } : {}),
    ...(hpkePublicKey ? { hpkePublicKey } : {}),
    ...(tlsKeyFp ? { tlsKeyFp } : {}),
    ...(enclaveHosts ? { enclaveHosts } : {}),
    ...(configuredHosts !== undefined ? { configuredHosts } : {}),
    ...(verifiedHosts !== undefined ? { verifiedHosts } : {}),
    ...(healthyHosts !== undefined ? { healthyHosts } : {}),
  };
}
