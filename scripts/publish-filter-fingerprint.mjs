#!/usr/bin/env node
/**
 * Computes the canonical SHA-256 fingerprint of `MECHANICAL_RULESET`, anchors
 * `keccak256("deroute-filter:" + version + ":" + fingerprint)` on the Arc
 * registry using the existing `anchorReceipt` helper (`src/lib/arc/registry.ts`)
 * and the verifier key from the environment, and writes
 * `{ version, fingerprint, anchorTx, chainId, anchoredAt }` to
 * `src/lib/privacy/published-fingerprint.json`.
 *
 * Refuses to send any Arc transaction or overwrite `published-fingerprint.json`
 * unless `--confirm` is passed. Never prints private keys or secrets.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPublicClient, http } from "viem";
import { arcChain, EXPLORER, loadEnv } from "./arc-common.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const PUBLISHED_JSON_PATH = join(
  ROOT,
  "src/lib/privacy/published-fingerprint.json",
);

async function loadTypeScriptModule(relPath) {
  const fullPath = join(ROOT, relPath);
  try {
    return await import(pathToFileURL(fullPath).href);
  } catch {
    // Fallback if plain Node without tsx loader is invoked: use tsx's ESM register API
    const tsxApi = await import("tsx/esm/api");
    return await tsxApi.tsImport(pathToFileURL(fullPath).href, import.meta.url);
  }
}

export async function runPublishFilterFingerprint(argv = process.argv.slice(2)) {
  const confirmed = argv.includes("--confirm");

  const rulesetMod = await loadTypeScriptModule(
    "src/lib/privacy/mechanical-ruleset.ts",
  );
  const fingerprintMod = await loadTypeScriptModule(
    "src/lib/privacy/fingerprint.ts",
  );

  const ruleset = rulesetMod.MECHANICAL_RULESET;
  const version = ruleset.version;
  const fingerprint = fingerprintMod.rulesetFingerprint(ruleset);
  const anchorReceiptHash = fingerprintMod.computeFilterAnchorReceiptHash(
    version,
    fingerprint,
  );

  console.log(`Filter version:      ${version}`);
  console.log(`Ruleset fingerprint: ${fingerprint}`);
  console.log(`Arc receipt payload: deroute-filter:${version}:${fingerprint}`);
  console.log(`Arc receipt hash:    ${anchorReceiptHash}`);

  if (!confirmed) {
    console.error(
      "Refusing to anchor on Arc or write published-fingerprint.json without --confirm.",
    );
    return {
      ok: false,
      confirmed: false,
      version,
      fingerprint,
      anchorReceiptHash,
    };
  }

  // Hydrate public/env variables from .env.local into process.env for anchorReceipt
  const env = loadEnv();
  if (env.ARC_REGISTRY_ADDRESS && !process.env.ARC_REGISTRY_ADDRESS) {
    process.env.ARC_REGISTRY_ADDRESS = env.ARC_REGISTRY_ADDRESS;
  }
  if (env.ARC_RPC_URL && !process.env.ARC_RPC_URL) {
    process.env.ARC_RPC_URL = env.ARC_RPC_URL;
  }
  if (env.ARC_VERIFIER_PRIVATE_KEY && !process.env.ARC_VERIFIER_PRIVATE_KEY) {
    process.env.ARC_VERIFIER_PRIVATE_KEY = env.ARC_VERIFIER_PRIVATE_KEY;
  }

  if (!process.env.ARC_REGISTRY_ADDRESS) {
    throw new Error("ARC_REGISTRY_ADDRESS is not set in environment or .env.local");
  }
  if (!process.env.ARC_VERIFIER_PRIVATE_KEY) {
    throw new Error(
      "ARC_VERIFIER_PRIVATE_KEY is not set in environment or .env.local",
    );
  }

  const arcRegistryMod = await loadTypeScriptModule("src/lib/arc/registry.ts");
  const anchorTx = await arcRegistryMod.anchorReceipt(anchorReceiptHash);
  if (!anchorTx) {
    throw new Error("anchorReceipt returned null (Arc transaction failed)");
  }

  const chain = await arcChain(env);
  const publicClient = createPublicClient({ chain, transport: http() });
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: anchorTx,
  });
  if (receipt.status !== "success") {
    throw new Error(
      `anchorReceipt transaction reverted: ${EXPLORER}/tx/${anchorTx}`,
    );
  }

  const anchoredAt = new Date().toISOString();
  const chainId = arcRegistryMod.ARC_CHAIN_ID ?? 5042002;
  const output = {
    version,
    fingerprint,
    anchorTx,
    chainId,
    anchoredAt,
  };

  writeFileSync(
    PUBLISHED_JSON_PATH,
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );

  console.log(`Anchored on Arc:     ${anchorTx}`);
  console.log(`Explorer URL:        ${EXPLORER}/tx/${anchorTx}`);
  console.log(`Chain ID:            ${chainId}`);
  console.log(`Anchored at:         ${anchoredAt}`);
  console.log(`Updated:             src/lib/privacy/published-fingerprint.json`);

  return {
    ok: true,
    confirmed: true,
    ...output,
    anchorReceiptHash,
  };
}

const isMain =
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  runPublishFilterFingerprint()
    .then((res) => {
      if (!res.ok) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    });
}
