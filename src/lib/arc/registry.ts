// Server-only: reads/writes Arc with private keys from the environment. Never import into client components.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { arcTestnet } from "viem/chains";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  formatUnits,
  http,
  isAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "@/lib/types";
import { registryAbi } from "./abi";
import {
  buildLiveMetadataByNodeId,
  fallbackNodes,
  isLegacySimNode,
  mapNode,
  nodeIdFor,
  nodeKeyFor,
  TINFOIL_PROXY_WELL_KNOWN_URL,
  type EnrichedNodeRecord,
  type LiveProxyTablePayload,
  type RawNode,
} from "./nodes";

export { nodeIdFor, nodeKeyFor, type EnrichedNodeRecord };

export const ARC_CHAIN_ID = 5042002;
export const ARC_EXPLORER = "https://explorer.testnet.arc.io";

const MIN_MAX_FEE = BigInt(20_000_000_000); // Arc mempool minimum: 20 gwei
const PRIORITY_FEE = BigInt(1_000_000_000);
const PROXY_CACHE_TTL_MS = 60_000;

export const explorerTx = (hash: string) => `${ARC_EXPLORER}/tx/${hash}`;
export const explorerAddress = (addr: string) => `${ARC_EXPLORER}/address/${addr}`;

export interface ListNodesResult {
  source: "arc" | "fallback";
  onChain: boolean;
  address?: Hex;
  minStake?: string;
  proxyVersion?: string;
  proxyUpdatedAt?: string;
  error?: string;
  nodes: EnrichedNodeRecord[];
}

export interface ArcClientDeps {
  readContract: (params: {
    address: Hex;
    abi: typeof registryAbi;
    functionName: string;
    args?: readonly unknown[];
  }) => Promise<unknown>;
  estimateFeesPerGas?: () => Promise<{ maxFeePerGas: bigint }>;
  writeContract?: (params: {
    address: Hex;
    abi: typeof registryAbi;
    functionName: string;
    args: readonly unknown[];
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
  }) => Promise<Hex>;
  fetchProxyTable?: () => Promise<LiveProxyTablePayload | null>;
}

let testClientDeps: ArcClientDeps | null = null;
let cachedProxyTable: { table: LiveProxyTablePayload; fetchedAt: number } | null = null;

/** Injects mocked viem client methods for deterministic unit tests. */
export function setArcClientDepsForTests(deps: ArcClientDeps | null): void {
  testClientDeps = deps;
}

export function resetLiveProxyCacheForTests(): void {
  cachedProxyTable = null;
}

export async function fetchLiveTinfoilProxyTable(
  fetchImpl?: typeof fetch,
): Promise<LiveProxyTablePayload | null> {
  if (testClientDeps) {
    return testClientDeps.fetchProxyTable ? await testClientDeps.fetchProxyTable() : null;
  }
  if (!fetchImpl && process.env.DROUTER_STUB_UPSTREAM === "1") {
    return null;
  }

  const now = Date.now();
  if (!fetchImpl && cachedProxyTable && now - cachedProxyTable.fetchedAt < PROXY_CACHE_TTL_MS) {
    return cachedProxyTable.table;
  }

  const doFetch = fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3_500);
  try {
    const res = await doFetch(TINFOIL_PROXY_WELL_KNOWN_URL, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return cachedProxyTable?.table ?? null;
    const table = (await res.json()) as LiveProxyTablePayload;
    if (!fetchImpl && table && typeof table === "object") {
      cachedProxyTable = { table, fetchedAt: Date.now() };
    }
    return table;
  } catch {
    return cachedProxyTable?.table ?? null;
  } finally {
    clearTimeout(timer);
  }
}

function registryAddress(): Hex | null {
  const a = process.env.ARC_REGISTRY_ADDRESS || process.env.NEXT_PUBLIC_ARC_REGISTRY_ADDRESS;
  return a && isAddress(a) ? (a as Hex) : null;
}

function chain() {
  const url = process.env.ARC_RPC_URL || arcTestnet.rpcUrls.default.http[0];
  return defineChain({ ...arcTestnet, rpcUrls: { default: { http: [url] } } });
}

function publicClient() {
  if (testClientDeps) {
    return {
      readContract: testClientDeps.readContract,
      estimateFeesPerGas:
        testClientDeps.estimateFeesPerGas ??
        (async () => ({ maxFeePerGas: MIN_MAX_FEE })),
    };
  }
  return createPublicClient({
    chain: chain(),
    transport: http(undefined, { timeout: 8_000, retryCount: 1 }),
  });
}

export function hashEvidenceObject(evidence: unknown): Hex {
  const json = JSON.stringify(evidence);
  return `0x${bytesToHex(sha256(utf8ToBytes(json)))}`;
}

export async function readOnChainNode(nodeKeyOrId: string): Promise<EnrichedNodeRecord | null> {
  const address = registryAddress();
  if (!address) return null;
  const id: Hex | undefined = nodeKeyOrId.startsWith("0x")
    ? (nodeKeyOrId as Hex)
    : nodeIdFor(nodeKeyOrId);
  if (!id || isLegacySimNode(id)) return null;
  try {
    const client = publicClient();
    const [raw, proxyTable] = await Promise.all([
      client.readContract({
        address,
        abi: registryAbi,
        functionName: "getNode",
        args: [id],
      }) as Promise<RawNode>,
      fetchLiveTinfoilProxyTable(),
    ]);
    if (isLegacySimNode(id, raw)) return null;
    const liveById = buildLiveMetadataByNodeId(proxyTable);
    return mapNode(id, raw, liveById.get(id.toLowerCase()));
  } catch {
    return null;
  }
}

export async function readMinStakeUsdc(): Promise<number | null> {
  const address = registryAddress();
  if (!address) return null;
  try {
    const client = publicClient();
    const raw = (await client.readContract({
      address,
      abi: registryAbi,
      functionName: "minStake",
    })) as bigint;
    const n = Number(formatUnits(raw, 18));
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

export async function listNodes(): Promise<ListNodesResult> {
  const address = registryAddress();
  const proxyPromise = fetchLiveTinfoilProxyTable();

  if (!address) {
    const proxyTable = await proxyPromise;
    return {
      source: "fallback",
      onChain: false,
      error: "ARC_REGISTRY_ADDRESS is not configured; returning local fallback node list.",
      ...(proxyTable?.version ? { proxyVersion: proxyTable.version } : {}),
      ...(proxyTable?.updated ? { proxyUpdatedAt: proxyTable.updated } : {}),
      nodes: fallbackNodes(proxyTable),
    };
  }
  try {
    const client = publicClient();
    const [count, minStakeRaw, proxyTable] = await Promise.all([
      client.readContract({
        address,
        abi: registryAbi,
        functionName: "nodeCount",
      }) as Promise<bigint>,
      client
        .readContract({
          address,
          abi: registryAbi,
          functionName: "minStake",
        })
        .catch(() => null) as Promise<bigint | null>,
      proxyPromise,
    ]);
    const ids = await Promise.all(
      Array.from({ length: Number(count) }, (_, i) =>
        client.readContract({
          address,
          abi: registryAbi,
          functionName: "nodeIdAt",
          args: [BigInt(i)],
        }) as Promise<Hex>,
      ),
    );
    const liveById = buildLiveMetadataByNodeId(proxyTable);
    const rawEntries = await Promise.all(
      ids.map(async (id) => {
        if (isLegacySimNode(id)) return null;
        const raw = (await client.readContract({
          address,
          abi: registryAbi,
          functionName: "getNode",
          args: [id],
        })) as RawNode;
        if (isLegacySimNode(id, raw)) return null;
        return mapNode(id, raw, liveById.get(id.toLowerCase()));
      }),
    );
    const nodes = rawEntries.filter((n): n is EnrichedNodeRecord => n !== null);
    const minStake =
      typeof minStakeRaw === "bigint" ? formatUnits(minStakeRaw, 18) : undefined;
    return {
      source: "arc",
      onChain: true,
      address,
      ...(minStake !== undefined ? { minStake } : {}),
      ...(proxyTable?.version ? { proxyVersion: proxyTable.version } : {}),
      ...(proxyTable?.updated ? { proxyUpdatedAt: proxyTable.updated } : {}),
      nodes,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Arc RPC unreachable";
    console.error("[arc] listNodes failed, using fallback");
    const proxyTable = await proxyPromise.catch(() => null);
    return {
      source: "fallback",
      onChain: false,
      address,
      error: `Arc Testnet RPC unreachable (${msg.slice(0, 120)}); returning local fallback node list.`,
      ...(proxyTable?.version ? { proxyVersion: proxyTable.version } : {}),
      ...(proxyTable?.updated ? { proxyUpdatedAt: proxyTable.updated } : {}),
      nodes: fallbackNodes(proxyTable),
    };
  }
}

// Writes share one verifier account, so serialise them to keep nonces ordered.
let writeQueue: Promise<unknown> = Promise.resolve();

function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const run = writeQueue.then(task, task);
  writeQueue = run.catch(() => undefined);
  return run;
}

async function verifierWrite(
  functionName: "recordVerification" | "anchorReceipt",
  args: readonly unknown[],
): Promise<Hex | null> {
  const address = registryAddress();
  if (!address) return null;

  if (testClientDeps?.writeContract) {
    try {
      return await enqueue(async () => {
        let maxFeePerGas = MIN_MAX_FEE;
        try {
          if (testClientDeps?.estimateFeesPerGas) {
            const est = await testClientDeps.estimateFeesPerGas();
            if (est.maxFeePerGas > maxFeePerGas) maxFeePerGas = est.maxFeePerGas;
          }
        } catch {}
        return testClientDeps!.writeContract!({
          address,
          abi: registryAbi,
          functionName,
          args,
          maxFeePerGas,
          maxPriorityFeePerGas: PRIORITY_FEE,
        });
      });
    } catch {
      console.error(`[arc] ${functionName} failed`);
      return null;
    }
  }

  const key = process.env.ARC_VERIFIER_PRIVATE_KEY;
  if (!key) return null;
  try {
    return await enqueue(async () => {
      const account = privateKeyToAccount((key.startsWith("0x") ? key : `0x${key}`) as Hex);
      const c = chain();
      const pub = createPublicClient({
        chain: c,
        transport: http(undefined, { timeout: 8_000, retryCount: 1 }),
      });
      const wallet = createWalletClient({
        account,
        chain: c,
        transport: http(undefined, { timeout: 8_000, retryCount: 1 }),
      });

      let maxFeePerGas = MIN_MAX_FEE;
      try {
        const est = await pub.estimateFeesPerGas();
        if (est.maxFeePerGas > maxFeePerGas) maxFeePerGas = est.maxFeePerGas;
      } catch {}

      return wallet.writeContract({
        address,
        abi: registryAbi,
        functionName,
        args,
        maxFeePerGas,
        maxPriorityFeePerGas: PRIORITY_FEE,
      } as never);
    });
  } catch {
    console.error(`[arc] ${functionName} failed`);
    return null;
  }
}

export function recordVerification(id: Hex, ok: boolean, evidenceHash: Hex): Promise<Hex | null> {
  return verifierWrite("recordVerification", [id, ok, evidenceHash]);
}

export function anchorReceipt(receiptHash: Hex): Promise<Hex | null> {
  return verifierWrite("anchorReceipt", [receiptHash]);
}
