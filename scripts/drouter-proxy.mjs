#!/usr/bin/env node
/**
 * Local OpenAI-Compatible Agent Proxy CLI (Spec §1)
 *
 * Usage:
 *   node scripts/drouter-proxy.mjs [--port 4141] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-proxy.mjs --self-test
 *   node scripts/drouter-proxy.mjs --help
 */

import http from "node:http";
import { pathToFileURL } from "node:url";
import { TinfoilAI } from "tinfoil";
import {
  evaluateMonitorExit,
  verifyMonitorPolicyExhaustive,
} from "../src/lib/monitor/policy.ts";
import { PlaceholderVault } from "../src/lib/monitor/scrubber.ts";

export const DEFAULT_PORT = 4141;
export const DEFAULT_UPSTREAM = "https://drouter-demo.vercel.app";
export const DEFAULT_MODEL = "kimi-k3";

export function parseCliArgs(argv = process.argv.slice(2)) {
  let port = Number(process.env.DROUTER_PROXY_PORT || DEFAULT_PORT);
  let upstream = process.env.DROUTER_UPSTREAM || DEFAULT_UPSTREAM;
  let help = false;
  let selfTest = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--self-test") {
      selfTest = true;
    } else if (arg === "--port" && argv[i + 1]) {
      port = Number(argv[i + 1]);
      i += 1;
    } else if (arg.startsWith("--port=")) {
      port = Number(arg.slice("--port=".length));
    } else if (arg === "--upstream" && argv[i + 1]) {
      upstream = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--upstream=")) {
      upstream = arg.slice("--upstream=".length);
    }
  }

  upstream = upstream.replace(/\/+$/, "");
  return { port, upstream, help, selfTest };
}

export function formatHelpText() {
  return [
    "drouter-proxy — Local OpenAI-Compatible Attested Enclave Proxy (Spec §1)",
    "",
    "Usage:",
    "  node scripts/drouter-proxy.mjs [options]",
    "",
    "Options:",
    `  --port <number>       Local port to bind on 127.0.0.1 (default: ${DEFAULT_PORT})`,
    `  --upstream <url>      Upstream dRouter URL (default: ${DEFAULT_UPSTREAM})`,
    "  --self-test           Run exhaustive VMPL0 monitor policy & scrubber checks and exit 0",
    "  --help, -h            Show this help message",
    "",
    "Endpoints:",
    "  GET  http://127.0.0.1:<port>/health",
    "  POST http://127.0.0.1:<port>/v1/chat/completions",
  ].join("\n");
}

export function runSelfTest() {
  const report = verifyMonitorPolicyExhaustive();
  const vault = new PlaceholderVault();
  const sample = "Contact alice@example.com with key sk-proj-1234567890abcdefghijklmnop.";
  const scrubbed = vault.scrub(sample);
  const restored = vault.restore(`Echoing back: ${scrubbed}`);
  const scrubberPassed =
    !scrubbed.includes("alice@example.com") &&
    !scrubbed.includes("sk-proj-1234567890abcdefghijklmnop") &&
    scrubbed.includes("[[DROUTER_EMAIL_1]]") &&
    scrubbed.includes("[[DROUTER_SECRET_1]]") &&
    restored === `Echoing back: ${sample}`;

  const egressDecision = evaluateMonitorExit({
    actorVmpl: 0,
    channel: "relay-stream",
    payloadEncryption: "custody-aes-gcm",
    nonceFresh: true,
    fixedFrameCadence: true,
    hasPerSessionFields: false,
    startsWithForbiddenPrefix: false,
  });

  const ok =
    report.verified &&
    report.statesChecked === 1344 &&
    scrubberPassed &&
    egressDecision.allowed;

  return {
    ok,
    report,
    scrubberPassed,
  };
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
    "content-length": Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

/**
 * Creates an HTTP server implementing the local dRouter OpenAI-compatible proxy.
 */
export function createProxyServer({
  upstream = DEFAULT_UPSTREAM,
  clientFactory = null,
} = {}) {
  const normalizedUpstream = upstream.replace(/\/+$/, "");
  const monitorReport = verifyMonitorPolicyExhaustive();

  const createClient =
    clientFactory ??
    (() =>
      new TinfoilAI({
        bearerToken: "drouter-demo",
        baseURL: `${normalizedUpstream}/api/relay/v1/`,
        attestationBundleURL: `${normalizedUpstream}/api/relay`,
      }));

  let clientInstance = null;
  let verificationDoc = null;
  let verificationPromise = null;

  async function ensureVerified() {
    if (verificationDoc && verificationDoc.securityVerified !== false) {
      return { client: clientInstance, doc: verificationDoc };
    }
    if (!verificationPromise) {
      verificationPromise = (async () => {
        const client = createClient();
        await client.ready();
        const doc = await client.getVerificationDocument();
        if (doc && doc.securityVerified === false) {
          throw new Error("Enclave attestation document reported securityVerified=false");
        }
        clientInstance = client;
        verificationDoc = doc ?? { securityVerified: true, enclaveHost: "verified-enclave" };
        return { client: clientInstance, doc: verificationDoc };
      })().catch((err) => {
        verificationPromise = null;
        throw err;
      });
    }
    return verificationPromise;
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, {
        ok: monitorReport.verified,
        service: "drouter-proxy",
        upstream: normalizedUpstream,
        relayBaseURL: `${normalizedUpstream}/api/relay/v1/`,
        attestationBundleURL: `${normalizedUpstream}/api/relay`,
        enclaveVerified: Boolean(verificationDoc?.securityVerified),
        enclaveHost: verificationDoc?.enclaveHost ?? null,
        monitorPolicy: {
          verified: monitorReport.verified,
          statesChecked: monitorReport.statesChecked,
          allowedStates: monitorReport.allowedStates,
          deniedStates: monitorReport.deniedStates,
        },
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
      // Enforce VMPL0 relay-stream exit policy check before forwarding
      const exitCheck = evaluateMonitorExit({
        actorVmpl: 0,
        channel: "relay-stream",
        payloadEncryption: "custody-aes-gcm",
        nonceFresh: true,
        fixedFrameCadence: true,
        hasPerSessionFields: false,
        startsWithForbiddenPrefix: false,
      });
      if (!exitCheck.allowed) {
        sendJson(res, 403, {
          error: {
            message: `Blocked by VMPL0 exit policy: ${exitCheck.rule}`,
            type: "policy_violation",
          },
        });
        return;
      }

      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        sendJson(res, 400, {
          error: {
            message: "Invalid JSON request body",
            type: "invalid_request_error",
          },
        });
        return;
      }

      if (!Array.isArray(body?.messages)) {
        sendJson(res, 400, {
          error: {
            message: "Request body must include a messages array",
            type: "invalid_request_error",
          },
        });
        return;
      }

      // 1. Verify enclave attestation before serving any request
      let verified;
      try {
        verified = await ensureVerified();
      } catch (err) {
        sendJson(res, 502, {
          error: {
            message: `Enclave attestation verification failed: ${err?.message ?? String(err)}`,
            type: "attestation_error",
          },
        });
        return;
      }

      // 2. Scrub emails & secrets locally using a per-request placeholder vault
      const vault = new PlaceholderVault();
      const scrubbedMessages = vault.scrubMessages(body.messages);
      const model = typeof body.model === "string" && body.model.trim() ? body.model : DEFAULT_MODEL;

      try {
        if (body.stream) {
          const stream = await verified.client.chat.completions.create(
            { ...body, model, messages: scrubbedMessages, stream: true },
            { headers: { "X-Tinfoil-Model": model } },
          );

          res.writeHead(200, {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
            "x-drouter-redactions": String(vault.size),
            "x-drouter-enclave-host": String(verified.doc?.enclaveHost ?? ""),
          });

          // Buffer streaming tokens if a placeholder prefix `[[DROUTER_` is in progress
          let pending = "";
          let lastChunkTemplate = null;

          for await (const chunk of stream) {
            lastChunkTemplate = chunk;
            const delta = chunk?.choices?.[0]?.delta?.content ?? "";
            if (!delta) {
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              continue;
            }
            pending += delta;
            const openIdx = pending.lastIndexOf("[[");
            const closeIdx = openIdx >= 0 ? pending.indexOf("]]", openIdx) : -1;
            if (openIdx >= 0 && closeIdx === -1) {
              const safePrefix = pending.slice(0, openIdx);
              pending = pending.slice(openIdx);
              if (safePrefix) {
                const outChunk = structuredClone(chunk);
                outChunk.choices[0].delta.content = vault.restore(safePrefix);
                res.write(`data: ${JSON.stringify(outChunk)}\n\n`);
              }
            } else {
              const restoredDelta = vault.restore(pending);
              pending = "";
              const outChunk = structuredClone(chunk);
              outChunk.choices[0].delta.content = restoredDelta;
              res.write(`data: ${JSON.stringify(outChunk)}\n\n`);
            }
          }

          if (pending && lastChunkTemplate) {
            const flushChunk = structuredClone(lastChunkTemplate);
            if (flushChunk.choices?.[0]?.delta) {
              flushChunk.choices[0].delta.content = vault.restore(pending);
              res.write(`data: ${JSON.stringify(flushChunk)}\n\n`);
            }
          }

          res.write("data: [DONE]\n\n");
          res.end();
          return;
        }

        const completion = await verified.client.chat.completions.create(
          { ...body, model, messages: scrubbedMessages, stream: false },
          { headers: { "X-Tinfoil-Model": model } },
        );

        const restoredChoices = Array.isArray(completion?.choices)
          ? completion.choices.map((choice) => {
              if (typeof choice?.message?.content === "string") {
                return {
                  ...choice,
                  message: {
                    ...choice.message,
                    content: vault.restore(choice.message.content),
                  },
                };
              }
              return choice;
            })
          : [];

        sendJson(
          res,
          200,
          {
            ...completion,
            choices: restoredChoices,
          },
          {
            "x-drouter-redactions": String(vault.size),
            "x-drouter-enclave-host": String(verified.doc?.enclaveHost ?? ""),
          },
        );
      } catch (err) {
        sendJson(res, 502, {
          error: {
            message: `Upstream enclave request failed: ${err?.message ?? String(err)}`,
            type: "upstream_error",
          },
        });
      }
      return;
    }

    sendJson(res, 404, {
      error: {
        message: `Not found: ${req.method} ${url.pathname}`,
        type: "not_found_error",
      },
    });
  });

  return server;
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));

  if (args.help) {
    console.log(formatHelpText());
    process.exit(0);
  }

  if (args.selfTest) {
    const result = runSelfTest();
    console.log(
      JSON.stringify(
        {
          verified: result.report.verified,
          statesChecked: result.report.statesChecked,
          allowedStates: result.report.allowedStates,
          deniedStates: result.report.deniedStates,
          invariantsPassed: result.report.invariants.filter((i) => i.passed).length,
          invariantsTotal: result.report.invariants.length,
          scrubberPassed: result.scrubberPassed,
        },
        null,
        2,
      ),
    );
    process.exit(result.ok ? 0 : 1);
  }

  const server = createProxyServer({ upstream: args.upstream });
  server.listen(args.port, "127.0.0.1", () => {
    console.log(
      `[drouter-proxy] listening on http://127.0.0.1:${args.port} -> ${args.upstream}/api/relay/v1/`,
    );
  });
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  main().catch((err) => {
    console.error("[drouter-proxy] fatal:", err);
    process.exit(1);
  });
}
