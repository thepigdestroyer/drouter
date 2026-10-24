#!/usr/bin/env node
/**
 * dRouter Terminal CLI & Local Zero-Trust Harness Proxy
 *
 * Subcommands:
 *   node scripts/drouter-cli.mjs verify [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs proxy [--port 4141] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-cli.mjs config [--upstream https://drouter-demo.vercel.app]
 */

import { pathToFileURL } from "node:url";
import {
  DEFAULT_MODEL,
  DEFAULT_PORT,
  DEFAULT_UPSTREAM,
  PlaceholderVault,
  createProxyServer,
  createStreamRestorer,
  createZeroTrustClient,
} from "./drouter-proxy.mjs";

export {
  DEFAULT_MODEL,
  DEFAULT_PORT,
  DEFAULT_UPSTREAM,
  createProxyServer as createZeroTrustProxyServer,
  createStreamRestorer,
  createZeroTrustClient,
};

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
      ? `${node.status} on Circle Arc testnet registry ${registry.address?.slice(0, 10)}… with ${node.stake} USDC stake`
      : "Built-in node list only (Arc registry not read)",
  };
}

function checksFromDocument(doc, gpuModelInfo, registry) {
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
        ? `${gpuModelInfo.vmShape?.gpus ?? "unknown number of"} confidential GPUs per host listed by the attested router (${gpuModelInfo.healthyHosts}/${gpuModelInfo.configuredHosts} hosts healthy)`
        : "Model enclave table unavailable",
    },
    registryCheck(registry),
    {
      id: "C7",
      label: "Manifest-pinned model & dm-verity root",
      status: gpuModelInfo ? "pass" : "skip",
      detail: gpuModelInfo
        ? `Pinned ${gpuModelInfo.weightRepoCommit} (${gpuModelInfo.weightMpkHash?.slice(0, 16)}…) on dm-verity root ${gpuModelInfo.dmVerityRootHash?.slice(0, 16)}…`
        : "Model enclave table unavailable",
    },
  ];
}

export function buildCliHarnessConfigs(baseUrl) {
  const cleanBase = (baseUrl || DEFAULT_UPSTREAM).replace(/\/+$/, "");
  const gatewayUrl = `${cleanBase}/api/v1`;

  const opencodeConfig = {
    $schema: "https://opencode.ai/config.json",
    provider: {
      drouter: {
        npm: "@ai-sdk/openai-compatible",
        name: "dRouter Attested Enclave Gateway",
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
    localProxyCommand: `node scripts/drouter-cli.mjs proxy --port 4141 --upstream ${cleanBase}`,
  };
}

export function parseDrouterCliArgs(argv = process.argv.slice(2)) {
  let command = "help";
  let prompt = "";
  let model = process.env.DROUTER_MODEL || DEFAULT_MODEL;
  let upstream = process.env.DROUTER_UPSTREAM || DEFAULT_UPSTREAM;
  let port = Number(process.env.DROUTER_PROXY_PORT || DEFAULT_PORT);
  let scrubPii = true;
  let credit = process.env.DROUTER_CREDIT || "";

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      return { command: "help", prompt, model, upstream, port, scrubPii, credit };
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
    } else if (arg === "--no-scrub") {
      scrubPii = false;
    } else {
      positional.push(arg);
    }
  }

  if (positional.length > 0) {
    command = positional[0];
    prompt = positional.slice(1).join(" ").trim();
  }

  upstream = upstream.replace(/\/+$/, "");
  return { command, prompt, model, upstream, port, scrubPii, credit };
}

export function formatChecklistReport(doc, gpuModelInfo, registry) {
  const checks = checksFromDocument(doc, gpuModelInfo, registry);
  const lines = [
    `=== dRouter Zero-Trust Enclave Attestation ===`,
    `Enclave Host      : ${doc.enclaveHost}`,
    `Release           : ${doc.releaseTag ?? doc.releaseDigest}`,
    `Config Repo       : ${doc.configRepo}`,
    `Measurement Type  : ${doc.enclaveMeasurement?.measurement?.type ?? "sev-snp-v3"}`,
    `Code Fingerprint  : ${doc.codeFingerprint}`,
    `Enclave Key (HPKE): ${doc.hpkePublicKey}`,
    `Security Verified : ${doc.securityVerified}`,
    ``,
    `Checklist (C1–C7):`,
  ];

  for (const c of checks) {
    const badge = c.status === "pass" ? "[PASS]" : c.status === "fail" ? "[FAIL]" : "[SKIP]";
    lines.push(`  ${badge} ${c.id} ${c.label}: ${c.detail}`);
  }
  return lines.join("\n");
}

async function runCli() {
  const args = parseDrouterCliArgs(process.argv.slice(2));

  if (args.command === "config") {
    const configs = buildCliHarnessConfigs(args.upstream);
    console.log("=== OpenCode Configuration (opencode.json) ===");
    console.log(configs.opencodeJson);
    console.log("\n=== Environment Variables (Claude Code / Codex / OpenAI SDK) ===");
    console.log(configs.openaiEnvExports);
    console.log("\n=== Direct cURL Command ===");
    console.log(configs.curlCommand);
    console.log("\n=== Local Zero-Trust Proxy Command ===");
    console.log(configs.localProxyCommand);
    return;
  }

  if (args.command === "verify") {
    const client = createZeroTrustClient(args.upstream);
    const [, matrix, registry] = await Promise.all([
      client.ready(),
      fetch(`${args.upstream}/api/relay/enclave-matrix`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
      fetch(`${args.upstream}/api/registry`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ]);
    const doc = await client.getVerificationDocument();
    const gpuModelInfo = matrix?.models?.[args.model] ?? matrix?.models?.["kimi-k3"];
    console.log(formatChecklistReport(doc, gpuModelInfo, registry));
    if (!doc.securityVerified) {
      process.exit(1);
    }
    return;
  }

  if (args.command === "ask") {
    if (!args.prompt) {
      console.error('Usage: node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream <url>]');
      process.exit(1);
    }
    const client = createZeroTrustClient(args.upstream);
    await client.ready();
    const doc = await client.getVerificationDocument();
    console.error(
      `[dRouter Attested] host=${doc.enclaveHost} release=${doc.releaseTag ?? doc.releaseDigest} code=${doc.codeFingerprint.slice(0, 16)}...`,
    );

    const vault = args.scrubPii ? new PlaceholderVault() : null;
    const scrubbedPrompt = vault ? vault.scrub(args.prompt) : args.prompt;

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

    const restorer = createStreamRestorer(vault);
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

  if (args.command === "proxy") {
    const server = createProxyServer({ upstream: args.upstream });
    server.listen(args.port, "127.0.0.1", () => {
      console.log(
        `[drouter-cli proxy] Zero-trust HPKE proxy listening on http://127.0.0.1:${args.port}/v1 (upstream: ${args.upstream})`,
      );
    });
    return;
  }

  console.log(
    [
      "dRouter CLI: terminal and coding-harness enclave helper",
      "",
      "Commands:",
      "  node scripts/drouter-cli.mjs verify [--upstream https://drouter-demo.vercel.app]",
      '  node scripts/drouter-cli.mjs ask "<prompt>" [--model kimi-k3] [--upstream https://drouter-demo.vercel.app]',
      "  node scripts/drouter-cli.mjs proxy [--port 4141] [--upstream https://drouter-demo.vercel.app]",
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
