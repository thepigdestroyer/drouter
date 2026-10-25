#!/usr/bin/env node
/**
 * deRoute Terminal CLI & Local Zero-Trust Harness Proxy Launcher
 *
 * Subcommands:
 *   node scripts/drouter-cli.mjs verify [--submit] [--key-path ~/.config/deroute/verifier-key] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs proxy [--port 4141] [--key drk_...] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs config [--upstream https://drouter-demo.vercel.app]
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { TinfoilAI } from "tinfoil";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

export const DEFAULT_PORT = 4141;
export const DEFAULT_UPSTREAM = "https://drouter-demo.vercel.app";
export const DEFAULT_MODEL = "kimi-k3";
export const TINFOIL_PROXY_WELL_KNOWN_URL =
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";

export const PROXY_BUNDLE_PATH = path.join(
  REPO_ROOT,
  "public",
  "downloads",
  "deroute-proxy.mjs",
);
export const PROXY_SHA256_PATH = path.join(
  REPO_ROOT,
  "public",
  "downloads",
  "deroute-proxy.mjs.sha256",
);

export const VERIFICATION_CLAIM_DOMAIN = "drouter/transparency/verification-claim/v1";
export const VERIFIER_CHECK_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"];
export const PRIMARY_MODEL_IDS = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
];

const httpRelayRewriteMap = new Map();
let fetchInterceptorInstalled = false;

function ensureHttpRelayInterceptor() {
  if (fetchInterceptorInstalled) return;
  fetchInterceptorInstalled = true;
  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (input, init) => {
    const urlStr =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    for (const [virtualOrigin, realUpstream] of httpRelayRewriteMap.entries()) {
      if (urlStr.startsWith(virtualOrigin)) {
        const rewritten = `${realUpstream}${urlStr.slice(virtualOrigin.length)}`;
        return origFetch(rewritten, init);
      }
    }
    return origFetch(input, init);
  };
}

export function createZeroTrustClient(upstream = DEFAULT_UPSTREAM) {
  const cleanUpstream = upstream.replace(/\/+$/, "");
  let attestationBundleURL = `${cleanUpstream}/api/relay`;

  if (cleanUpstream.startsWith("http://")) {
    ensureHttpRelayInterceptor();
    const u = new URL(cleanUpstream);
    const virtualOrigin = `https://local-relay-${u.hostname.replace(/[^a-zA-Z0-9-]/g, "-")}-${u.port || "80"}.drouter.internal`;
    httpRelayRewriteMap.set(virtualOrigin, cleanUpstream);
    attestationBundleURL = `${virtualOrigin}/api/relay`;
  }

  return new TinfoilAI({
    bearerToken: "drouter-anonymous",
    baseURL: `${cleanUpstream}/api/relay/v1/`,
    attestationBundleURL,
  });
}

export function createStreamRestorer(scrubber) {
  let pending = "";
  const candidatePrefixRe = /^\[+?[A-Za-z0-9_]*$/;
  return {
    push(chunk) {
      if (!chunk) return "";
      if (!scrubber) return chunk;
      pending += chunk;

      const doubleOpen = pending.lastIndexOf("[[");
      if (doubleOpen !== -1) {
        const doubleClose = pending.indexOf("]]", doubleOpen + 2);
        if (doubleClose === -1 && pending.length - doubleOpen < 40) {
          const ready = pending.slice(0, doubleOpen);
          pending = pending.slice(doubleOpen);
          return ready ? scrubber.restore(ready) : "";
        }
      }

      const lastOpen = pending.lastIndexOf("[");
      if (lastOpen !== -1) {
        const closeAfter = pending.indexOf("]", lastOpen + 1);
        if (closeAfter === -1) {
          const tail = pending.slice(lastOpen);
          if (tail.length <= 40 && candidatePrefixRe.test(tail)) {
            const ready = pending.slice(0, lastOpen);
            pending = tail;
            return ready ? scrubber.restore(ready) : "";
          }
        }
      }

      const out = scrubber.restore(pending);
      pending = "";
      return out;
    },
    flush() {
      if (!pending) return "";
      const out = scrubber ? scrubber.restore(pending) : pending;
      pending = "";
      return out;
    },
  };
}

/**
 * Verifies that `public/downloads/deroute-proxy.mjs` and its `.sha256` file exist
 * and that the bundle's SHA-256 digest matches the expected checksum.
 */
export function verifyProxyBundleSha256({
  bundlePath = PROXY_BUNDLE_PATH,
  sha256Path = PROXY_SHA256_PATH,
} = {}) {
  if (!fs.existsSync(bundlePath) || !fs.existsSync(sha256Path)) {
    return {
      ok: false,
      error: [
        `Missing local proxy bundle at ${bundlePath} (or checksum at ${sha256Path}).`,
        `Build it first with:`,
        `  npm run build:proxy`,
      ].join("\n"),
    };
  }

  const rawSha = fs.readFileSync(sha256Path, "utf8").trim();
  const match = rawSha.match(/^([0-9a-fA-F]{64})\b/);
  if (!match) {
    return {
      ok: false,
      error: [
        `Malformed SHA-256 checksum file at ${sha256Path}.`,
        `Rebuild the local proxy bundle with:`,
        `  npm run build:proxy`,
      ].join("\n"),
    };
  }

  const expectedSha256 = match[1].toLowerCase();
  const bundleBytes = fs.readFileSync(bundlePath);
  const actualSha256 = bytesToHex(sha256(bundleBytes)).toLowerCase();

  if (actualSha256 !== expectedSha256) {
    return {
      ok: false,
      expectedSha256,
      actualSha256,
      error: [
        `SHA-256 mismatch for ${bundlePath}: expected ${expectedSha256}, got ${actualSha256}.`,
        `Rebuild the local proxy bundle with:`,
        `  npm run build:proxy`,
      ].join("\n"),
    };
  }

  return {
    ok: true,
    bundlePath,
    sha256Path,
    sha256: actualSha256,
  };
}

export function runProxySubcommand(
  proxyArgv = [],
  {
    bundlePath = PROXY_BUNDLE_PATH,
    sha256Path = PROXY_SHA256_PATH,
    spawnImpl = spawn,
    stderr = /** @type {(msg: string) => void} */ ((msg) => {
      process.stderr.write(`${msg}\n`);
    }),
    exit = /** @type {(code: number) => void} */ ((code) => {
      process.exit(code);
    }),
  } = {},
) {
  const check = verifyProxyBundleSha256({ bundlePath, sha256Path });
  if (!check.ok) {
    stderr(`[drouter-cli proxy] ${check.error}`);
    exit(1);
    return null;
  }

  const child = spawnImpl(process.execPath, [bundlePath, ...proxyArgv], {
    stdio: "inherit",
    env: process.env,
  });

  child.on("error", (err) => {
    stderr(
      `[drouter-cli proxy] Failed to start deroute-proxy.mjs: ${err instanceof Error ? err.message : String(err)}`,
    );
    exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    exit(code ?? 0);
  });

  return child;
}

export function defaultVerifierKeyPath() {
  return process.env.DEROUTE_VERIFIER_KEY_PATH || path.join(os.homedir(), ".config", "deroute", "verifier-key");
}

function canonicalize(value) {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonicalJson cannot encode non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(",")}]`;
      }
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
      return `{${pairs.join(",")}}`;
    }
    default:
      throw new Error(`canonicalJson cannot encode ${typeof value}`);
  }
}

export function canonicalJson(value) {
  return canonicalize(value);
}

export function coarsenEpochSecToHour(sec = Math.floor(Date.now() / 1000)) {
  return Math.floor(sec / 3600) * 3600;
}

/**
 * Loads an existing Ed25519 verifier key from disk (default `~/.config/deroute/verifier-key`),
 * or generates and persists a new one with mode 0600 if it does not exist.
 */
export function loadOrCreateVerifierKey(keyPath = defaultVerifierKeyPath()) {
  const resolvedPath = path.resolve(keyPath);
  if (fs.existsSync(resolvedPath)) {
    const raw = fs.readFileSync(resolvedPath, "utf8").trim();
    let secretKeyHex = "";
    if (/^[0-9a-fA-F]{64}$/.test(raw)) {
      secretKeyHex = raw.toLowerCase();
    } else {
      const parsed = JSON.parse(raw);
      if (typeof parsed?.secretKeyHex === "string" && /^[0-9a-fA-F]{64}$/.test(parsed.secretKeyHex)) {
        secretKeyHex = parsed.secretKeyHex.toLowerCase();
      } else {
        throw new Error(`Invalid verifier key file at ${resolvedPath}`);
      }
    }
    const secretKey = hexToBytes(secretKeyHex);
    const publicKey = ed25519.getPublicKey(secretKey);
    const publicKeyHex = bytesToHex(publicKey).toLowerCase();
    const fingerprint = bytesToHex(sha256(publicKey)).toLowerCase();
    return {
      secretKey,
      secretKeyHex,
      publicKey,
      publicKeyHex,
      fingerprint,
      keyPath: resolvedPath,
      created: false,
    };
  }

  const secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  const secretKeyHex = bytesToHex(secretKey).toLowerCase();
  const publicKey = ed25519.getPublicKey(secretKey);
  const publicKeyHex = bytesToHex(publicKey).toLowerCase();
  const fingerprint = bytesToHex(sha256(publicKey)).toLowerCase();

  const dir = path.dirname(resolvedPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    resolvedPath,
    `${JSON.stringify(
      {
        kty: "Ed25519",
        secretKeyHex,
        publicKeyHex,
        fingerprint,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );

  return {
    secretKey,
    secretKeyHex,
    publicKey,
    publicKeyHex,
    fingerprint,
    keyPath: resolvedPath,
    created: true,
  };
}

function registryCheck(registry) {
  if (!registry || !Array.isArray(registry.nodes)) {
    return { id: "C6", label: "Registry admission", status: "skip", detail: "Arc registry unreachable" };
  }
  const node = registry.nodes.find((n) => n.kind === "tinfoil");
  if (!node) {
    return { id: "C6", label: "Registry admission", status: "fail", detail: "Tinfoil router is not in the registry" };
  }
  const onChain = registry.source === "arc";
  const ok = onChain && node.status === "active" && Number(node.stake) > 0;
  return {
    id: "C6",
    label: "Registry admission",
    status: !onChain ? "skip" : ok ? "pass" : "fail",
    detail: onChain
      ? `${node.status} on Circle Arc testnet registry ${registry.address?.slice(0, 10)}... with ${node.stake} USDC stake`
      : "Built-in node list only (Arc registry not read)",
  };
}

export function checksFromDocument(doc, gpuModelInfo, registry) {
  const s = doc.steps || {};
  const st = (step) => (!step ? "skip" : step.status === "success" ? "pass" : step.status === "failed" ? "fail" : "skip");
  return [
    {
      id: "C1",
      label: "Hardware signature chain",
      status: st(s.verifyEnclave),
      detail: `AMD SEV-SNP report verified to AMD root (${doc.enclaveMeasurement?.measurement?.type ?? "sev-snp"})`,
    },
    {
      id: "C2",
      label: "Approved software",
      status: st(s.verifyCode),
      detail: `Signed release ${doc.releaseTag ?? doc.releaseDigest?.slice(0, 12)} of ${doc.configRepo} in Sigstore Rekor`,
    },
    {
      id: "C3",
      label: "HPKE key bound to enclave report",
      status: st(s.verifyCertificate),
      detail: "HPKE key committed in attestation; request body encrypted to it",
    },
    {
      id: "C4",
      label: "Running code = released code",
      status: st(s.compareMeasurements),
      detail: "Launch measurement matches signed release predicate",
    },
    {
      id: "C5",
      label: "Router-attested confidential GPU pool",
      status: gpuModelInfo ? "pass" : "skip",
      detail: gpuModelInfo
        ? `${gpuModelInfo.vmShape?.gpus ?? "unknown number of"} confidential GPUs per host listed by the attested router (${gpuModelInfo.healthyHosts ?? gpuModelInfo.healthy ?? 1}/${gpuModelInfo.configuredHosts ?? gpuModelInfo.configured ?? 1} hosts healthy)`
        : "Model enclave table unavailable",
    },
    registryCheck(registry),
    {
      id: "C7",
      label: "Manifest-pinned model & dm-verity root",
      status: gpuModelInfo ? "pass" : "skip",
      detail: gpuModelInfo
        ? `Pinned ${gpuModelInfo.weightRepoCommit ?? gpuModelInfo.repo} (${(gpuModelInfo.weightMpkHash ?? gpuModelInfo.measurement ?? "").slice(0, 16)}...) on dm-verity root ${(gpuModelInfo.dmVerityRootHash ?? gpuModelInfo.measurement ?? "").slice(0, 16)}...`
        : "Model enclave table unavailable",
    },
  ];
}

/**
 * Builds the canonical C1 to C7 verification claim for the live router and model enclaves.
 */
export function buildCanonicalVerificationClaim({
  doc,
  matrix,
  proxyTable,
  registry,
  epochHourSec = coarsenEpochSecToHour(),
}) {
  const proxyModels = proxyTable?.models ?? {};
  const models = [];

  for (const id of PRIMARY_MODEL_IDS) {
    const mAtt = matrix?.models?.[id];
    const pMod = proxyModels[id];
    const repo = mAtt?.repo || pMod?.repo || "";
    const tag = mAtt?.tag || pMod?.tag || "";
    const reg0 = mAtt?.measurementRegisters?.[0] || pMod?.measurement?.registers?.[0] || mAtt?.dmVerityRootHash || "";
    if (!repo || !tag || !reg0) continue;

    const healthy = mAtt ? mAtt.healthyHosts : (pMod?.verification?.healthy ?? 0);
    const available = mAtt ? mAtt.status !== "unavailable" : true;
    models.push({
      id,
      repo,
      tag,
      measurement: String(reg0).toLowerCase(),
      ...(mAtt?.dmVerityRootHash ? { dmVerityRootHash: String(mAtt.dmVerityRootHash).toLowerCase() } : {}),
      ...(mAtt?.weightRepoCommit ? { weightRepoCommit: String(mAtt.weightRepoCommit) } : {}),
      ok: Boolean(available && healthy > 0),
    });
  }

  models.sort((a, b) => a.id.localeCompare(b.id));

  const primaryGpuModel =
    matrix?.models?.["kimi-k3"] ??
    (models[0]
      ? {
          repo: models[0].repo,
          measurement: models[0].measurement,
          dmVerityRootHash: models[0].dmVerityRootHash,
          weightRepoCommit: models[0].weightRepoCommit,
          healthyHosts: models[0].ok ? 1 : 0,
          configuredHosts: 1,
        }
      : null);

  const rawChecks = checksFromDocument(doc, primaryGpuModel, registry);
  const checkMap = new Map(rawChecks.map((c) => [c.id, c.status]));
  const checks = VERIFIER_CHECK_IDS.map((id) => ({
    id,
    status: checkMap.get(id) ?? "skip",
  }));

  const overallOk = Boolean(
    doc?.securityVerified &&
      checks.every((c) => (c.id === "C6" ? c.status !== "fail" : c.status === "pass")),
  );

  return {
    domain: VERIFICATION_CLAIM_DOMAIN,
    epochHourSec: coarsenEpochSecToHour(epochHourSec),
    router: {
      nodeId: "tinfoil-router",
      enclaveHost: String(doc?.enclaveHost || matrix?.routerHost || "router-0.tinfoil.sh").toLowerCase(),
      configRepo: String(doc?.configRepo || matrix?.routerConfigRepo || "tinfoilsh/confidential-model-router"),
      releaseDigest: String(doc?.releaseDigest || matrix?.routerReleaseDigest || "").toLowerCase(),
      measurement: String(
        doc?.codeFingerprint || doc?.enclaveFingerprint || matrix?.routerSnpReport?.measurementHex || "",
      ).toLowerCase(),
    },
    models,
    checks,
    overallOk,
  };
}

/**
 * Signs a canonical C1-C7 verification claim with an Ed25519 secret key.
 */
export function signCliVerificationClaim(claim, secretKeyHexOrBytes) {
  const secretKey =
    typeof secretKeyHexOrBytes === "string"
      ? hexToBytes(secretKeyHexOrBytes.replace(/^0x/i, ""))
      : secretKeyHexOrBytes;
  const publicKeyBytes = ed25519.getPublicKey(secretKey);
  const publicKey = bytesToHex(publicKeyBytes).toLowerCase();
  const verifierFingerprint = bytesToHex(sha256(publicKeyBytes)).toLowerCase();
  const payload = utf8ToBytes(canonicalJson(claim));
  const signature = bytesToHex(ed25519.sign(payload, secretKey)).toLowerCase();
  const evidenceHash = bytesToHex(sha256(payload)).toLowerCase();
  return {
    publicKey,
    verifierFingerprint,
    signature,
    claim,
    evidenceHash,
  };
}

export async function submitVerificationClaim({
  upstream = DEFAULT_UPSTREAM,
  signedPayload,
  fetchImpl = globalThis.fetch,
}) {
  const cleanUpstream = upstream.replace(/\/+$/, "");
  const res = await fetchImpl(`${cleanUpstream}/api/transparency/verifications`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      publicKey: signedPayload.publicKey,
      signature: signedPayload.signature,
      claim: signedPayload.claim,
    }),
  });
  const body = await res.json().catch(() => ({}));
  return {
    status: res.status,
    ok: res.ok && body?.ok === true,
    body,
  };
}

export function buildCliHarnessConfigs(baseUrl) {
  const cleanBase = (baseUrl || DEFAULT_UPSTREAM).replace(/\/+$/, "");
  const gatewayUrl = `${cleanBase}/api/v1`;

  const opencodeConfig = {
    $schema: "https://opencode.ai/config.json",
    provider: {
      drouter: {
        npm: "@ai-sdk/openai-compatible",
        name: "deRoute Attested Enclave Gateway",
        options: {
          baseURL: gatewayUrl,
          apiKey: "drouter-anonymous",
          _authNote:
            "any apiKey value works, auth is the blind credit header (x-drouter-credit) with per-IP free-tier fallback",
          headers: {
            "x-drouter-credit": "${DROUTER_CREDIT_TOKEN}",
          },
        },
        models: {
          "kimi-k3": { name: "Kimi K3 (Attested Enclave)" },
          "glm-5-3": { name: "GLM-5.3 (Attested Enclave)" },
          "deepseek-v4-1-flash": { name: "DeepSeek V4.1 Flash (Attested Enclave)" },
          "gpt-oss-120b": { name: "GPT-OSS 120B (Attested Enclave)" },
          "llama3-3-70b": { name: "Llama 3.3 70B (Attested Enclave)" },
          "gemma4-31b": { name: "Gemma 4 31B (Attested Enclave)" },
        },
      },
    },
    model: "drouter/kimi-k3",
  };

  return {
    opencodeJson: JSON.stringify(opencodeConfig, null, 2),
    curlCommand: [
      `# Note: any Bearer apiKey value works (required by OpenAI SDKs); auth is the blind credit header (x-drouter-credit)`,
      `curl -sS ${gatewayUrl}/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer drouter-anonymous" -H "x-drouter-credit: \${DROUTER_CREDIT_TOKEN:-}" -d '{"model":"kimi-k3","messages":[{"role":"user","content":"Verify enclave connectivity in one sentence."}]}'`,
    ].join("\n"),
    openaiEnvExports: [
      `# Any OPENAI_API_KEY value works; auth is the blind credit header (x-drouter-credit) or per-IP free tier`,
      `export OPENAI_BASE_URL="${gatewayUrl}"`,
      `export OPENAI_API_KEY="drouter-anonymous"`,
    ].join("\n"),
    localProxyCommand: [
      `curl -fsSLO ${cleanBase}/downloads/deroute-proxy.mjs`,
      `curl -fsSLO ${cleanBase}/downloads/deroute-proxy.mjs.sha256`,
      `shasum -a 256 -c deroute-proxy.mjs.sha256`,
      `node deroute-proxy.mjs --port 4141`,
    ].join("\n"),
  };
}

export function parseDrouterCliArgs(argv = process.argv.slice(2)) {
  let command = "help";
  let prompt = "";
  let model = process.env.DROUTER_MODEL || DEFAULT_MODEL;
  let upstream = process.env.DROUTER_UPSTREAM || DEFAULT_UPSTREAM;
  let port = Number(process.env.DROUTER_PROXY_PORT || DEFAULT_PORT);
  let credit = process.env.DROUTER_CREDIT || "";
  let key = process.env.DEROUTE_ACCESS_KEY || "";
  let submit = false;
  let keyPath = defaultVerifierKeyPath();

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      return { command: "help", prompt, model, upstream, port, credit, key, submit, keyPath };
    } else if (arg === "--model" && argv[i + 1]) {
      model = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--model=")) {
      model = arg.slice("--model=".length);
    } else if (arg === "--upstream" && argv[i + 1]) {
      upstream = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--upstream=")) {
      upstream = arg.slice("--upstream=".length);
    } else if (arg === "--port" && argv[i + 1]) {
      port = Number(argv[i + 1]);
      i += 1;
    } else if (arg.startsWith("--port=")) {
      port = Number(arg.slice("--port=".length));
    } else if (arg === "--credit" && argv[i + 1]) {
      credit = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--credit=")) {
      credit = arg.slice("--credit=".length);
    } else if (arg === "--key" && argv[i + 1]) {
      key = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--key=")) {
      key = arg.slice("--key=".length);
    } else if (arg === "--key-path" && argv[i + 1]) {
      keyPath = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--key-path=")) {
      keyPath = arg.slice("--key-path=".length);
    } else if (arg === "--submit") {
      submit = true;
    } else {
      positional.push(arg);
    }
  }

  if (positional.length > 0) {
    command = positional[0];
    prompt = positional.slice(1).join(" ").trim();
  }

  upstream = upstream.replace(/\/+$/, "");
  return { command, prompt, model, upstream, port, credit, key, submit, keyPath };
}

export function formatChecklistReport(doc, gpuModelInfo, registry) {
  const checks = checksFromDocument(doc, gpuModelInfo, registry);
  const lines = [
    `=== deRoute Zero-Trust Enclave Attestation ===`,
    `Enclave Host      : ${doc.enclaveHost}`,
    `Release           : ${doc.releaseTag ?? doc.releaseDigest}`,
    `Config Repo       : ${doc.configRepo}`,
    `Measurement Type  : ${doc.enclaveMeasurement?.measurement?.type ?? "sev-snp-v3"}`,
    `Code Fingerprint  : ${doc.codeFingerprint}`,
    `Enclave Key (HPKE): ${doc.hpkePublicKey}`,
    `Security Verified : ${doc.securityVerified}`,
    ``,
    `Checklist (C1-C7):`,
  ];

  for (const c of checks) {
    const badge = c.status === "pass" ? "[PASS]" : c.status === "fail" ? "[FAIL]" : "[SKIP]";
    lines.push(`  ${badge} ${c.id} ${c.label}: ${c.detail}`);
  }
  return lines.join("\n");
}

async function getRouterVerificationDocument(upstream) {
  const client = createZeroTrustClient(upstream);
  await client.ready();
  return await client.getVerificationDocument();
}

async function loadMechanicalSessionForCli() {
  const check = verifyProxyBundleSha256();
  if (check.ok) {
    const mod = await import(pathToFileURL(PROXY_BUNDLE_PATH).href);
    if (typeof mod.verifyProxyFilterFingerprint === "function") {
      mod.verifyProxyFilterFingerprint();
    }
  }
  const mechMod = await import("../src/lib/privacy/mechanical.ts").catch(async () => {
    const bundleUrl = pathToFileURL(PROXY_BUNDLE_PATH).href;
    return import(bundleUrl);
  });
  if (typeof mechMod.createMechanicalSession === "function") {
    return mechMod.createMechanicalSession();
  }
  throw new Error(
    "Mechanical filter session unavailable. Build the proxy bundle first with: npm run build:proxy",
  );
}

async function runCli() {
  const rawArgv = process.argv.slice(2);
  if (rawArgv[0] === "proxy") {
    runProxySubcommand(rawArgv.slice(1));
    return;
  }

  const args = parseDrouterCliArgs(rawArgv);

  if (args.command === "config") {
    const configs = buildCliHarnessConfigs(args.upstream);
    console.log("=== OpenCode Configuration (opencode.json) ===");
    console.log(configs.opencodeJson);
    console.log("\n=== Environment Variables (Claude Code / Codex / OpenAI SDK) ===");
    console.log(configs.openaiEnvExports);
    console.log("\n=== Direct cURL Command ===");
    console.log(configs.curlCommand);
    console.log("\n=== Local Private Proxy Command ===");
    console.log(configs.localProxyCommand);
    return;
  }

  if (args.command === "verify") {
    const [doc, matrix, proxyTable, registry] = await Promise.all([
      getRouterVerificationDocument(args.upstream),
      fetch(`${args.upstream}/api/relay/enclave-matrix`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(TINFOIL_PROXY_WELL_KNOWN_URL)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(`${args.upstream}/api/registry`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]);

    const claim = buildCanonicalVerificationClaim({
      doc,
      matrix,
      proxyTable,
      registry,
    });

    const gpuModelInfo =
      matrix?.models?.[args.model] ??
      matrix?.models?.["kimi-k3"] ??
      (claim.models[0]
        ? {
            repo: claim.models[0].repo,
            measurement: claim.models[0].measurement,
            dmVerityRootHash: claim.models[0].dmVerityRootHash,
            weightRepoCommit: claim.models[0].weightRepoCommit,
            healthyHosts: claim.models[0].ok ? 1 : 0,
            configuredHosts: 1,
          }
        : null);

    console.log(formatChecklistReport(doc, gpuModelInfo, registry));

    if (!doc.securityVerified) {
      process.exit(1);
    }

    if (args.submit) {
      const key = loadOrCreateVerifierKey(args.keyPath);
      const signed = signCliVerificationClaim(claim, key.secretKeyHex);
      const submissionRes = await submitVerificationClaim({
        upstream: args.upstream,
        signedPayload: signed,
      });

      console.log("");
      console.log("=== Independent Verifier Submission ===");
      console.log(`Verifier Key File : ${key.keyPath} (${key.created ? "generated" : "loaded"})`);
      console.log(`Key Fingerprint   : ${signed.verifierFingerprint}`);
      console.log(`Evidence Hash     : ${signed.evidenceHash}`);
      console.log(`Models Verified   : ${claim.models.map((m) => `${m.id}@${m.tag}`).join(", ")}`);

      if (!submissionRes.ok) {
        console.error(
          `Submission Status : REJECTED (HTTP ${submissionRes.status}) - ${submissionRes.body?.error ?? "Unknown error"}`,
        );
        if (Array.isArray(submissionRes.body?.mismatches)) {
          for (const m of submissionRes.body.mismatches) {
            console.error(`  - ${m}`);
          }
        }
        process.exit(1);
      }

      const b = submissionRes.body;
      console.log(`Submission Status : ACCEPTED (HTTP ${submissionRes.status})`);
      console.log(`Coarse Hour (UTC) : ${b.epochHourSec}`);
      console.log(`RFC 6962 Leaf     : #${b.event?.index} (${b.event?.leafHash})`);
      console.log(`Tree Head Root    : ${b.signedTreeHead?.rootHash} (size=${b.signedTreeHead?.treeSize})`);
      console.log(`Distinct Verifiers: ${b.distinctVerifierCount} (total submissions: ${b.totalSubmissions})`);
    }
    return;
  }

  if (args.command === "ask") {
    if (!args.prompt) {
      console.error('Usage: node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream <url>]');
      process.exit(1);
    }
    const session = await loadMechanicalSessionForCli();
    const client = createZeroTrustClient(args.upstream);
    await client.ready();
    const doc = await client.getVerificationDocument();
    if (!doc || !doc.securityVerified) {
      throw new Error("Enclave attestation verification failed");
    }
    console.error(
      `[deRoute Attested] host=${doc.enclaveHost} release=${doc.releaseTag ?? doc.releaseDigest} code=${doc.codeFingerprint.slice(0, 16)}...`,
    );

    const scrubbedPrompt = session.redact(args.prompt).text;

    const stream = await client.chat.completions.create(
      {
        model: args.model,
        messages: [{ role: "user", content: scrubbedPrompt }],
        stream: true,
      },
      {
        headers: {
          "X-Tinfoil-Model": args.model,
          ...(args.credit ? { "x-drouter-credit": args.credit } : {}),
        },
      },
    );

    const restorer = createStreamRestorer(session);
    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta?.content;
      if (delta) {
        const text = restorer.push(delta);
        if (text) process.stdout.write(text);
      }
    }
    const tail = restorer.flush();
    if (tail) process.stdout.write(tail);
    process.stdout.write("\n");
    return;
  }

  console.log(
    [
      "deRoute CLI: terminal and coding-harness enclave helper",
      "",
      "Commands:",
      "  node scripts/drouter-cli.mjs verify [--submit] [--key-path ~/.config/deroute/verifier-key] [--upstream https://drouter-demo.vercel.app]",
      '  node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream https://drouter-demo.vercel.app]',
      "  node scripts/drouter-cli.mjs proxy [--port 4141] [--key drk_...] [--upstream https://drouter-demo.vercel.app]",
      "  node scripts/drouter-cli.mjs config [--upstream https://drouter-demo.vercel.app]",
    ].join("\n"),
  );
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  runCli().catch((err) => {
    console.error("[drouter-cli] Error:", err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
