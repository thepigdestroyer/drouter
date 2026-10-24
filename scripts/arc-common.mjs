import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineChain } from "viem";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const ENV_PATH = join(ROOT, ".env.local");
export const ARTIFACT_PATH = join(ROOT, "src/lib/arc/artifact.json");
export const FAUCET_URL = "https://faucet.circle.com";
export const EXPLORER = "https://explorer.testnet.arc.io";
export const MIN_STAKE = 10_000_000_000_000_000n; // 0.01 USDC, 18 decimals
export const MIN_MAX_FEE = 20_000_000_000n; // Arc mempool minimum, 20 gwei

export const DEMO_NODES = [
  {
    key: "tinfoil-router",
    kind: "tinfoil",
    name: "Tinfoil confidential router",
    endpoint: "inference.tinfoil.sh",
    region: "us",
    measurementSource: "tinfoilsh/confidential-model-router",
  },
  ...[
    ["sim-1", "Simulated node 1", "eu-west"],
    ["sim-2", "Simulated node 2", "us-east"],
    ["sim-3", "Simulated node 3", "ap-south"],
  ].map(([key, name, region]) => ({
    key,
    kind: "sim",
    name,
    endpoint: `/api/sim/${key}`,
    region,
    measurementSource: "drouter-sim-node-image/v0.1.0",
  })),
];

export function parseEnv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    let value = line.slice(eq + 1).trim();
    if (/^(".*"|'.*')$/.test(value)) value = value.slice(1, -1);
    out[line.slice(0, eq).trim().replace(/^export\s+/, "")] = value;
  }
  return out;
}

export function loadEnv() {
  const file = existsSync(ENV_PATH) ? parseEnv(readFileSync(ENV_PATH, "utf8")) : {};
  return { ...file, ...Object.fromEntries(Object.entries(process.env).filter(([, v]) => v)) };
}

/** Replace `KEY=...` lines in .env.local, appending any that are missing. */
export function upsertEnv(updates) {
  let lines = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8").split("\n") : [];
  for (const [key, value] of Object.entries(updates)) {
    const i = lines.findIndex((l) => l.startsWith(`${key}=`));
    if (i >= 0) lines[i] = `${key}=${value}`;
    else {
      if (lines.length && lines[lines.length - 1] === "") lines.pop();
      lines.push(`${key}=${value}`, "");
    }
  }
  writeFileSync(ENV_PATH, lines.join("\n"));
}

export function privateKey(env, name) {
  const v = env[name];
  if (!v) throw new Error(`${name} is not set in .env.local`);
  return v.startsWith("0x") ? v : `0x${v}`;
}

export function loadArtifact() {
  if (!existsSync(ARTIFACT_PATH)) {
    throw new Error("src/lib/arc/artifact.json missing. Run: node scripts/arc-compile.mjs");
  }
  return JSON.parse(readFileSync(ARTIFACT_PATH, "utf8"));
}

export async function arcChain(env) {
  const { arcTestnet } = await import("viem/chains");
  const url = env.ARC_RPC_URL || arcTestnet.rpcUrls.default.http[0];
  return defineChain({ ...arcTestnet, rpcUrls: { default: { http: [url] } } });
}

/** Fee fields satisfying Arc's 20 gwei minimum maxFeePerGas. */
export async function gasFees(publicClient) {
  let maxFeePerGas = MIN_MAX_FEE;
  try {
    const est = await publicClient.estimateFeesPerGas();
    if (est.maxFeePerGas > maxFeePerGas) maxFeePerGas = est.maxFeePerGas;
  } catch {}
  return { maxFeePerGas, maxPriorityFeePerGas: 1_000_000_000n };
}
