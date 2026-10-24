import { createPublicClient, createWalletClient, formatUnits, http, isAddress, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  DEMO_NODES,
  EXPLORER,
  FAUCET_URL,
  MIN_STAKE,
  arcChain,
  gasFees,
  loadArtifact,
  loadEnv,
  privateKey,
} from "./arc-common.mjs";

const env = loadEnv();
const address = env.ARC_REGISTRY_ADDRESS;
if (!address || !isAddress(address)) {
  console.error("ARC_REGISTRY_ADDRESS is not set. Run: node scripts/arc-deploy.mjs");
  process.exit(1);
}

const chain = await arcChain(env);
const account = privateKeyToAccount(privateKey(env, "ARC_DEPLOYER_PRIVATE_KEY"));
const { abi } = loadArtifact();
const publicClient = createPublicClient({ chain, transport: http() });
const walletClient = createWalletClient({ account, chain, transport: http() });

const balance = await publicClient.getBalance({ address: account.address });
console.log(`Operator ${account.address} balance ${formatUnits(balance, 18)} USDC`);

const existing = new Set(
  await Promise.all(
    Array.from({ length: Number(await publicClient.readContract({ address, abi, functionName: "nodeCount" })) }, (_, i) =>
      publicClient.readContract({ address, abi, functionName: "nodeIdAt", args: [BigInt(i)] }),
    ),
  ),
);

for (const node of DEMO_NODES) {
  const id = keccak256(toHex(node.key));
  if (existing.has(id)) {
    console.log(`skip ${node.key} (already registered)`);
    continue;
  }
  if (balance < MIN_STAKE) {
    console.error(`Operator balance too low to stake. Fund ${account.address} at ${FAUCET_URL}`);
    process.exit(1);
  }
  const hash = await walletClient.writeContract({
    address,
    abi,
    functionName: "registerNode",
    args: [id, node.kind, node.name, node.endpoint, keccak256(toHex(node.measurementSource)), node.region],
    value: MIN_STAKE,
    ...(await gasFees(publicClient)),
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    console.error(`registerNode ${node.key} failed: ${EXPLORER}/tx/${hash}`);
    process.exit(1);
  }
  console.log(`registered ${node.key} ${id} ${EXPLORER}/tx/${hash}`);
}
console.log("Seed complete");
