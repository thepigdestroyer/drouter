// Server-only: reads/writes Arc with private keys from the environment. Never import into client components.
import { arcTestnet } from "viem/chains";
import { createPublicClient, createWalletClient, defineChain, http, isAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex, NodeRecord } from "@/lib/types";
import { registryAbi } from "./abi";
import { fallbackNodes, mapNode, nodeKeyFor, type RawNode } from "./nodes";

export { nodeKeyFor };

export const ARC_CHAIN_ID = 5042002;
export const ARC_EXPLORER = "https://explorer.testnet.arc.io";

const MIN_MAX_FEE = BigInt(20_000_000_000); // Arc mempool minimum: 20 gwei
const PRIORITY_FEE = BigInt(1_000_000_000);

export const explorerTx = (hash: string) => `${ARC_EXPLORER}/tx/${hash}`;
export const explorerAddress = (addr: string) => `${ARC_EXPLORER}/address/${addr}`;

export interface ListNodesResult {
  source: "arc" | "fallback";
  address?: Hex;
  nodes: NodeRecord[];
}

function registryAddress(): Hex | null {
  const a = process.env.ARC_REGISTRY_ADDRESS;
  return a && isAddress(a) ? (a as Hex) : null;
}

function chain() {
  const url = process.env.ARC_RPC_URL || arcTestnet.rpcUrls.default.http[0];
  return defineChain({ ...arcTestnet, rpcUrls: { default: { http: [url] } } });
}

function publicClient() {
  return createPublicClient({ chain: chain(), transport: http(undefined, { timeout: 8_000, retryCount: 1 }) });
}

export async function listNodes(): Promise<ListNodesResult> {
  const address = registryAddress();
  if (!address) return { source: "fallback", nodes: fallbackNodes() };
  try {
    const client = publicClient();
    const count = await client.readContract({ address, abi: registryAbi, functionName: "nodeCount" });
    const ids = await Promise.all(
      Array.from({ length: Number(count) }, (_, i) =>
        client.readContract({ address, abi: registryAbi, functionName: "nodeIdAt", args: [BigInt(i)] }),
      ),
    );
    const nodes = await Promise.all(
      ids.map(async (id) => {
        const raw = await client.readContract({ address, abi: registryAbi, functionName: "getNode", args: [id] });
        return mapNode(id, raw as RawNode);
      }),
    );
    return { source: "arc", address, nodes };
  } catch {
    console.error("[arc] listNodes failed, using fallback");
    return { source: "fallback", nodes: fallbackNodes() };
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
  const key = process.env.ARC_VERIFIER_PRIVATE_KEY;
  if (!address || !key) return null;
  try {
    return await enqueue(async () => {
      const account = privateKeyToAccount((key.startsWith("0x") ? key : `0x${key}`) as Hex);
      const c = chain();
      const pub = createPublicClient({ chain: c, transport: http(undefined, { timeout: 8_000, retryCount: 1 }) });
      const wallet = createWalletClient({ account, chain: c, transport: http(undefined, { timeout: 8_000, retryCount: 1 }) });

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
