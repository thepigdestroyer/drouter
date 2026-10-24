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

import http from "node:http";
import { pathToFileURL } from "node:url";
import { TinfoilAI } from "tinfoil";
import {
  SUPPORTED_GATEWAY_MODELS,
  buildHarnessConfigs,
  parseGatewayChatRequest,
} from "../src/lib/gateway/harness-config.ts";
import { checksFromDocument } from "../src/lib/tinfoil/client.ts";
import { createSessionScrubber } from "../src/lib/privacy/scrubber.ts";

export const DEFAULT_UPSTREAM = "https://drouter-demo.vercel.app";
export const DEFAULT_PORT = 4141;
export const DEFAULT_MODEL = "kimi-k3";

export function parseDrouterCliArgs(argv = process.argv.slice(2)) {
  let command = "help";
  let prompt = "";
  let model = process.env.DROUTER_MODEL || DEFAULT_MODEL;
  let upstream = process.env.DROUTER_UPSTREAM || DEFAULT_UPSTREAM;
  let port = Number(process.env.DROUTER_PROXY_PORT || DEFAULT_PORT);
  let scrubPii = true;

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      return { command: "help", prompt, model, upstream, port, scrubPii };
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
  return { command, prompt, model, upstream, port, scrubPii };
}

export function createZeroTrustClient(upstream = DEFAULT_UPSTREAM) {
  const cleanUpstream = upstream.replace(/\/+$/, "");
  return new TinfoilAI({
    bearerToken: "drouter-demo",
    baseURL: `${cleanUpstream}/api/relay/v1/`,
    attestationBundleURL: `${cleanUpstream}/api/relay`,
  });
}

export function formatChecklistReport(doc) {
  const checks = checksFromDocument(doc);
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
    lines.push(`  ${badge} ${c.id} ${c.label} — ${c.detail}`);
  }
  return lines.join("\n");
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "content-length": Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

export function createZeroTrustProxyServer({
  upstream = DEFAULT_UPSTREAM,
  clientFactory,
} = {}) {
  const cleanUpstream = upstream.replace(/\/+$/, "");
  const makeClient = clientFactory ?? (() => createZeroTrustClient(cleanUpstream));

  let cachedClient = null;
  let cachedDoc = null;

  async function ensureVerifiedClient() {
    if (cachedClient && cachedDoc) {
      return { client: cachedClient, doc: cachedDoc };
    }
    const client = makeClient();
    await client.ready();
    const doc = await client.getVerificationDocument();
    if (doc?.securityVerified === false) {
      throw new Error("Enclave attestation failed: securityVerified is false");
    }
    cachedClient = client;
    cachedDoc = doc;
    return { client, doc };
  }

  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "Authorization, Content-Type, X-DRouter-Scrub-PII",
        "access-control-allow-methods": "GET, POST, OPTIONS",
      });
      res.end();
      return;
    }

    if (req.method === "GET" && (url.pathname === "/v1/models" || url.pathname === "/api/v1/models")) {
      sendJson(res, 200, {
        object: "list",
        data: SUPPORTED_GATEWAY_MODELS.map((m) => ({
          id: m.id,
          object: "model",
          created: 1792800000,
          owned_by: m.provider,
          enclave_attested: true,
        })),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, {
        ok: true,
        upstream: cleanUpstream,
        enclaveVerified: Boolean(cachedDoc?.securityVerified),
        enclaveHost: cachedDoc?.enclaveHost ?? null,
      });
      return;
    }

    if (
      req.method === "POST" &&
      (url.pathname === "/v1/chat/completions" || url.pathname === "/api/v1/chat/completions")
    ) {
      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        sendJson(res, 400, {
          error: { message: "Invalid JSON body", type: "invalid_request_error" },
        });
        return;
      }

      const parsed = parseGatewayChatRequest(body);
      if (!parsed.ok) {
        sendJson(res, 400, {
          error: { message: parsed.error, type: "invalid_request_error" },
        });
        return;
      }

      const scrubber = createSessionScrubber();
      const scrubbedMessages = parsed.messages.map((m) => ({
        role: m.role,
        content: scrubber.scrub(m.content).scrubbed,
      }));

      try {
        const { client, doc } = await ensureVerifiedClient();
        const enclaveHeaders = {
          "X-DRouter-Attested": "true",
          "X-DRouter-Enclave-Host": String(doc?.enclaveHost ?? ""),
          "X-DRouter-Release": String(doc?.releaseTag || doc?.releaseDigest || ""),
          "X-DRouter-Code-Fingerprint": String(doc?.codeFingerprint ?? ""),
          "X-DRouter-Enclave-Fingerprint": String(doc?.enclaveFingerprint ?? ""),
        };

        if (parsed.stream) {
          const stream = await client.chat.completions.create(
            {
              model: parsed.model,
              messages: scrubbedMessages,
              stream: true,
              ...(parsed.temperature !== undefined ? { temperature: parsed.temperature } : {}),
              ...(parsed.max_tokens !== undefined ? { max_tokens: parsed.max_tokens } : {}),
            },
            { headers: { "X-Tinfoil-Model": parsed.model } },
          );

          res.writeHead(200, {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
            "access-control-allow-origin": "*",
            ...enclaveHeaders,
          });

          for await (const chunk of stream) {
            if (chunk?.choices?.[0]?.delta?.content) {
              chunk.choices[0].delta.content = scrubber.restore(
                chunk.choices[0].delta.content,
              );
            }
            res.write(`data: ${JSON.stringify(chunk)}\n\n`);
          }
          res.write("data: [DONE]\n\n");
          res.end();
          return;
        }

        const completion = await client.chat.completions.create(
          {
            model: parsed.model,
            messages: scrubbedMessages,
            stream: false,
            ...(parsed.temperature !== undefined ? { temperature: parsed.temperature } : {}),
            ...(parsed.max_tokens !== undefined ? { max_tokens: parsed.max_tokens } : {}),
          },
          { headers: { "X-Tinfoil-Model": parsed.model } },
        );

        const choices = Array.isArray(completion?.choices)
          ? completion.choices.map((c) => {
              if (typeof c?.message?.content === "string") {
                return {
                  ...c,
                  message: {
                    ...c.message,
                    content: scrubber.restore(c.message.content),
                  },
                };
              }
              return c;
            })
          : [];

        sendJson(
          res,
          200,
          {
            ...completion,
            choices,
            drouter_attestation: {
              securityVerified: doc.securityVerified,
              enclaveHost: doc.enclaveHost,
              releaseTag: doc.releaseTag,
              codeFingerprint: doc.codeFingerprint,
              enclaveFingerprint: doc.enclaveFingerprint,
            },
          },
          enclaveHeaders,
        );
      } catch (err) {
        sendJson(res, 502, {
          error: {
            message: err instanceof Error ? err.message : String(err),
            type: "enclave_proxy_error",
          },
        });
      }
      return;
    }

    sendJson(res, 404, {
      error: { message: `Not found: ${req.method} ${url.pathname}`, type: "not_found_error" },
    });
  });
}

async function runCli() {
  const args = parseDrouterCliArgs(process.argv.slice(2));

  if (args.command === "config") {
    const configs = buildHarnessConfigs(args.upstream);
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
    await client.ready();
    const doc = await client.getVerificationDocument();
    console.log(formatChecklistReport(doc));
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

    const scrubber = args.scrubPii ? createSessionScrubber() : null;
    const scrubbedPrompt = scrubber ? scrubber.scrub(args.prompt).scrubbed : args.prompt;

    const stream = await client.chat.completions.create(
      {
        model: args.model,
        messages: [{ role: "user", content: scrubbedPrompt }],
        stream: true,
      },
      { headers: { "X-Tinfoil-Model": args.model } },
    );

    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta?.content;
      if (delta) {
        process.stdout.write(scrubber ? scrubber.restore(delta) : delta);
      }
    }
    process.stdout.write("\n");
    return;
  }

  if (args.command === "proxy") {
    const server = createZeroTrustProxyServer({ upstream: args.upstream });
    server.listen(args.port, "127.0.0.1", () => {
      console.log(
        `[drouter-cli proxy] Zero-trust HPKE proxy listening on http://127.0.0.1:${args.port}/v1 (upstream: ${args.upstream})`,
      );
    });
    return;
  }

  console.log(
    [
      "dRouter CLI — Terminal & Coding-Harness Enclave Helper",
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
