import { createPublicClient, createWalletClient, formatUnits, http, isAddress, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  DEMO_NODES,
  EXPLORER,
  FAUCET_URL,
  LEGACY_SIM_KEYS,
  MIN_STAKE,
  STATUS_REVOKED,
  TINFOIL_PROXY_WELL_KNOWN_URL,
  arcChain,
  buildModelMeasurementSource,
  gasFees,
  loadArtifact,
  loadEnv,
  privateKey,
} from "./arc-common.mjs";

const MAX_TX_CAP = 8;

async function fetchLiveProxyModels() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const res = await fetch(TINFOIL_PROXY_WELL_KNOWN_URL, {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (!res.ok) return null;
      const json = await res.json();
      return json?.models && typeof json.models === "object" ? json.models : null;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
}

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

const count = Number(await publicClient.readContract({ address, abi, functionName: "nodeCount" }));
const existingIds = await Promise.all(
  Array.from({ length: count }, (_, i) =>
    publicClient.readContract({ address, abi, functionName: "nodeIdAt", args: [BigInt(i)] }),
  ),
);
const existingNodes = new Map();
for (const id of existingIds) {
  const raw = await publicClient.readContract({ address, abi, functionName: "getNode", args: [id] });
  existingNodes.set(id.toLowerCase(), { id, raw });
}

let txCount = 0;

// 1. Revoke any active/suspended simulated practice nodes on chain
const simIds = new Set(LEGACY_SIM_KEYS.map((k) => keccak256(toHex(k)).toLowerCase()));
for (const [idLower, { id, raw }] of existingNodes.entries()) {
  if ((simIds.has(idLower) || raw.kind === "sim") && Number(raw.status) !== STATUS_REVOKED) {
    if (txCount >= MAX_TX_CAP) {
      throw new Error(`Reached max transaction cap (${MAX_TX_CAP}) before revoking ${id}`);
    }
    txCount += 1;
    const hash = await walletClient.writeContract({
      address,
      abi,
      functionName: "setStatus",
      args: [id, STATUS_REVOKED],
      ...(await gasFees(publicClient)),
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") {
      console.error(`setStatus(${id}, REVOKED) failed: ${EXPLORER}/tx/${hash}`);
      process.exit(1);
    }
    console.log(`revoked sim node ${raw.name} (${id}) ${EXPLORER}/tx/${hash}`);
  }
}

// 2. Register real Tinfoil router & model enclaves from live proxy table
const liveModels = await fetchLiveProxyModels();

for (const baseNode of DEMO_NODES) {
  const id = keccak256(toHex(baseNode.key));
  if (existingNodes.has(id.toLowerCase())) {
    console.log(`skip ${baseNode.key} (already registered)`);
    continue;
  }

  let endpoint = baseNode.endpoint;
  let measurementSource = baseNode.measurementSource;

  if (baseNode.modelId && liveModels?.[baseNode.modelId]) {
    const entry = liveModels[baseNode.modelId];
    const hosts = entry.enclaves ? Object.keys(entry.enclaves) : [];
    const registers = Array.isArray(entry.measurement?.registers) ? entry.measurement.registers : [];
    if (hosts.length > 0) endpoint = hosts[0];
    if (entry.repo && entry.tag && registers.length > 0) {
      measurementSource = buildModelMeasurementSource(entry.repo, entry.tag, registers);
    }
  }

  if (txCount >= MAX_TX_CAP) {
    throw new Error(`Reached max transaction cap (${MAX_TX_CAP}) before registering ${baseNode.key}`);
  }
  if (balance < MIN_STAKE) {
    console.error(`Operator balance too low to stake. Fund ${account.address} at ${FAUCET_URL}`);
    process.exit(1);
  }
  txCount += 1;
  const hash = await walletClient.writeContract({
    address,
    abi,
    functionName: "registerNode",
    args: [id, baseNode.kind, baseNode.name, endpoint, keccak256(toHex(measurementSource)), baseNode.region],
    value: MIN_STAKE,
    ...(await gasFees(publicClient)),
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    console.error(`registerNode ${baseNode.key} failed: ${EXPLORER}/tx/${hash}`);
    process.exit(1);
  }
  console.log(`registered ${baseNode.key} ${id} (${endpoint}) ${EXPLORER}/tx/${hash}`);
}
console.log(`Seed complete (${txCount} transactions sent)`);
