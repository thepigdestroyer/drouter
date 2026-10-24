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

export const TINFOIL_PROXY_WELL_KNOWN_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";
export const LEGACY_SIM_KEYS = ["sim-1", "sim-2", "sim-3"];
export const STATUS_REVOKED = 2;

export function buildModelMeasurementSource(repo, releaseTag, registers) {
  return `${repo}@${releaseTag}:${registers.join(":")}`;
}

export const DEMO_NODES = [
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
    measurementSource: buildModelMeasurementSource("tinfoilsh/confidential-kimi-k3", "v0.0.15", [
      "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e717ad8402c4c67b66ad598452eee96b03d",
    ]),
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
    measurementSource: buildModelMeasurementSource("tinfoilsh/confidential-glm5-3-nvfp4", "v0.0.7", [
      "b64eb23f1441a8f25e29d901782fbb82f894f434db70cb1658dd37c398715bfff070f3b732f2e623bf151e56d2699188",
      "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e",
      "affb1973ecb2abb9edfe87939de38030f1a38ce4de08966e3580721b41436409d6bc9ab8c6dbdbe7a4476d360b639721",
    ]),
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
    measurementSource: buildModelMeasurementSource("tinfoilsh/confidential-gpt-oss-120b", "v0.0.28", [
      "fc301c823b6e8c4f942a91bd0aa8fca062b06169f37480629ebbbcd9189a8cc266908b762eff9a75629e244576729b62",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "2a3ef603ddb6020819386c1a2c518c23e6836f94b2902b15f65d8a18900c701640d6d7042d0991d29f0cec27e7267cf4",
    ]),
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
    measurementSource: buildModelMeasurementSource("tinfoilsh/confidential-llama3-3-70b", "v0.0.26", [
      "b99fec0d07a1313e686406c945ab07cd900ee11cdeef59f77efcd572943376853f6dae2d26bff905ba28fc61000a14d3",
      "a787299fe2e84295a406dde367abac5b40128c1e13aa81dfde4a5c2e39682e45cde7bb84cefc7f33f25ac645fc265030",
      "d05901d119685ef5354210c57f4cdd4f756f57c10bc4c2b1f811d6662326a6b9eb326d71c05871c216b94a84827a5dd2",
    ]),
  },
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
