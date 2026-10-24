import { createPublicClient, createWalletClient, formatUnits, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  EXPLORER,
  FAUCET_URL,
  MIN_STAKE,
  arcChain,
  gasFees,
  loadArtifact,
  loadEnv,
  privateKey,
  upsertEnv,
} from "./arc-common.mjs";

const env = loadEnv();
const chain = await arcChain(env);
const deployer = privateKeyToAccount(privateKey(env, "ARC_DEPLOYER_PRIVATE_KEY"));
const verifier = privateKeyToAccount(privateKey(env, "ARC_VERIFIER_PRIVATE_KEY"));
const { abi, bytecode } = loadArtifact();

const publicClient = createPublicClient({ chain, transport: http() });
const walletClient = createWalletClient({ account: deployer, chain, transport: http() });

const balance = await publicClient.getBalance({ address: deployer.address });
if (balance === 0n) {
  console.error(
    `Deployer ${deployer.address} has zero USDC on Arc Testnet.\n` +
      `Fund it at ${FAUCET_URL} (select Arc Testnet) and run this script again.`,
  );
  process.exit(1);
}
console.log(`Deployer ${deployer.address} balance ${formatUnits(balance, 18)} USDC`);

const hash = await walletClient.deployContract({
  abi,
  bytecode,
  args: [MIN_STAKE],
  ...(await gasFees(publicClient)),
});
console.log(`Deploy tx ${EXPLORER}/tx/${hash}`);
const receipt = await publicClient.waitForTransactionReceipt({ hash });
if (receipt.status !== "success" || !receipt.contractAddress) {
  console.error("Deployment failed");
  process.exit(1);
}
const address = receipt.contractAddress;

const verifierTx = await walletClient.writeContract({
  address,
  abi,
  functionName: "setVerifier",
  args: [verifier.address, true],
  ...(await gasFees(publicClient)),
});
const verifierReceipt = await publicClient.waitForTransactionReceipt({ hash: verifierTx });
if (verifierReceipt.status !== "success") {
  console.error(`setVerifier failed: ${EXPLORER}/tx/${verifierTx}`);
  process.exit(1);
}

upsertEnv({ ARC_REGISTRY_ADDRESS: address, NEXT_PUBLIC_ARC_REGISTRY_ADDRESS: address });
console.log(`DRouterRegistry deployed at ${address}`);
console.log(`Verifier ${verifier.address} authorised`);
console.log(`${EXPLORER}/address/${address}`);
console.log("Wrote ARC_REGISTRY_ADDRESS and NEXT_PUBLIC_ARC_REGISTRY_ADDRESS to .env.local");
