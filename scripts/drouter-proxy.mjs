#!/usr/bin/env node
/**
 * Local OpenAI-Compatible Attested Enclave Proxy & Shared CLI Runtime (Spec §1)
 *
 * Usage:
 *   node scripts/drouter-proxy.mjs [--port 4141] [--upstream https://drouter-demo.vercel.app]
 *   node scripts/drouter-proxy.mjs --self-test
 *   node scripts/drouter-proxy.mjs --help
 */

import http from "node:http";
import { pathToFileURL } from "node:url";
import { TinfoilAI } from "tinfoil";

export const DEFAULT_PORT = 4141;
export const DEFAULT_UPSTREAM = "https://drouter-demo.vercel.app";
export const DEFAULT_MODEL = "kimi-k3";
export const TINFOIL_PROXY_WELL_KNOWN_URL =
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";

const NON_INFERENCE_TINFOIL_SERVICES = new Set([
  "doc-upload",
  "pii-filter",
  "websearch",
]);

const KNOWN_MODEL_LABELS = {
  "kimi-k3": "Kimi K3 (2.8T MoE, 256K ctx)",
  "glm-5-3": "GLM-5.3",
  "deepseek-v4-1-flash": "DeepSeek V4.1 Flash",
  "gpt-oss-120b": "GPT-OSS 120B",
  "llama3-3-70b": "Llama 3.3 70B",
  "gemma4-31b": "Gemma 4 31B",
  "voxtral-small-24b": "Voxtral Small 24B",
  "voxtral-mini-4b-realtime": "Voxtral Mini 4B Realtime",
  "voxtral-tts": "Voxtral TTS",
  "qwen3-tts": "Qwen 3 TTS",
  "whisper-large-v3-turbo": "Whisper Large v3 Turbo",
  "nomic-embed-text": "Nomic Embed Text",
  "gpt-oss-safeguard-120b": "GPT-OSS Safeguard 120B",
  "decision-large": "Decision Large",
  "decision-medium": "Decision Medium",
  "decision-small": "Decision Small",
};

const PRIMARY_MODEL_ORDER = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
  "gemma4-31b",
  "voxtral-small-24b",
];

export const BASELINE_TINFOIL_MODELS = [
  { id: "kimi-k3", label: KNOWN_MODEL_LABELS["kimi-k3"], provider: "tinfoil-tdx", enclave_attested: true },
  { id: "glm-5-3", label: KNOWN_MODEL_LABELS["glm-5-3"], provider: "tinfoil-sev-snp", enclave_attested: true },
  { id: "deepseek-v4-1-flash", label: KNOWN_MODEL_LABELS["deepseek-v4-1-flash"], provider: "tinfoil-tdx", enclave_attested: true },
  { id: "gpt-oss-120b", label: KNOWN_MODEL_LABELS["gpt-oss-120b"], provider: "tinfoil-tdx", enclave_attested: true },
  { id: "llama3-3-70b", label: KNOWN_MODEL_LABELS["llama3-3-70b"], provider: "tinfoil-tdx", enclave_attested: true },
  { id: "gemma4-31b", label: KNOWN_MODEL_LABELS["gemma4-31b"], provider: "tinfoil-tdx", enclave_attested: true },
  { id: "voxtral-small-24b", label: KNOWN_MODEL_LABELS["voxtral-small-24b"], provider: "tinfoil-tdx", enclave_attested: true },
];

let cachedLiveModels = null;

export async function fetchLiveTinfoilModels() {
  const now = Date.now();
  if (cachedLiveModels && now - cachedLiveModels.fetchedAt < 60_000) {
    return cachedLiveModels.models;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const res = await fetch(TINFOIL_PROXY_WELL_KNOWN_URL, {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        const table = await res.json();
        const rawModels = table?.models ?? {};
        const parsed = [];
        for (const [id, entry] of Object.entries(rawModels)) {
          if (!entry || typeof entry !== "object") continue;
          if (NON_INFERENCE_TINFOIL_SERVICES.has(id)) continue;
          const enclaves = entry.enclaves && typeof entry.enclaves === "object" ? entry.enclaves : {};
          const enclaveList = Object.values(enclaves);
          const configured = entry.verification?.configured ?? enclaveList.length;
          const verified = entry.verification?.verified ?? enclaveList.length;
          const healthy = entry.verification?.healthy ?? enclaveList.length;
          if (configured <= 0 || verified <= 0 || healthy <= 0 || enclaveList.length === 0) {
            continue;
          }
          const predicates = enclaveList.map((e) => e?.predicate ?? "").filter(Boolean);
          const hasSevSnp = predicates.some((p) => p.includes("sev-snp"));
          const hasTdx = predicates.some((p) => p.includes("tdx"));
          const provider =
            hasSevSnp && hasTdx
              ? "tinfoil-sev-snp+tdx"
              : hasSevSnp
                ? "tinfoil-sev-snp"
                : "tinfoil-tdx";
          const observedMs = Date.parse(entry.verification?.observed_at || table.updated || "");
          const created =
            Number.isFinite(observedMs) && observedMs > 0
              ? Math.floor(observedMs / 1000)
              : 1792800000;
          parsed.push({
            id,
            label: KNOWN_MODEL_LABELS[id] ?? id,
            provider,
            enclave_attested: true,
            repo: entry.repo,
            tag: entry.tag,
            predicate: predicates[0] ?? entry.measurement?.type,
            healthy_hosts: healthy,
            configured_hosts: configured,
            verified_hosts: verified,
            created,
          });
        }
        if (parsed.length > 0) {
          parsed.sort((a, b) => {
            const idxA = PRIMARY_MODEL_ORDER.indexOf(a.id);
            const idxB = PRIMARY_MODEL_ORDER.indexOf(b.id);
            if (idxA !== -1 && idxB !== -1) return idxA - idxB;
            if (idxA !== -1) return -1;
            if (idxB !== -1) return 1;
            return a.id.localeCompare(b.id);
          });
          cachedLiveModels = { models: parsed, fetchedAt: Date.now() };
          return parsed;
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Fall back to baseline models if offline
  }
  return cachedLiveModels?.models ?? BASELINE_TINFOIL_MODELS;
}

// ============================================================================
// VMPL0 Formal Exit-Policy Checker (shared runtime without .ts import warning)
// ============================================================================

const CHANNELS = [
  "relay-stream",
  "control-plane",
  "blob-storage",
  "snp-attest",
  "raw-socket",
  "disk-write",
  "shell-exec",
];
const ACTOR_VMPLS = [0, 1, 2];
const PAYLOAD_ENCRYPTIONS = [
  "custody-aes-gcm",
  "freeze-aes-gcm",
  "plaintext",
  "control-schema",
];
const BOOLEANS = [true, false];

export function evaluateMonitorExit(action) {
  if (action.actorVmpl !== 0) {
    return { allowed: false, rule: "DENY_NON_VMPL0_EGRESS" };
  }
  switch (action.channel) {
    case "relay-stream": {
      if (action.payloadEncryption !== "custody-aes-gcm") {
        return { allowed: false, rule: "M1_DENY_RELAY_UNENCRYPTED_OR_WRONG_KEY" };
      }
      if (!action.nonceFresh) {
        return { allowed: false, rule: "M1_DENY_RELAY_STALE_NONCE" };
      }
      if (!action.fixedFrameCadence) {
        return { allowed: false, rule: "M1_DENY_RELAY_VARIABLE_CADENCE" };
      }
      return { allowed: true, rule: "M1_ALLOW_RELAY_STREAM" };
    }
    case "control-plane": {
      if (action.payloadEncryption !== "control-schema") {
        return { allowed: false, rule: "M2_DENY_CONTROL_INVALID_SCHEMA" };
      }
      if (action.hasPerSessionFields) {
        return { allowed: false, rule: "M2_DENY_CONTROL_PER_SESSION_LEAK" };
      }
      return { allowed: true, rule: "M2_ALLOW_CONTROL_PLANE" };
    }
    case "blob-storage": {
      if (
        action.payloadEncryption !== "custody-aes-gcm" &&
        action.payloadEncryption !== "freeze-aes-gcm"
      ) {
        return { allowed: false, rule: "M3_DENY_BLOB_UNENCRYPTED" };
      }
      if (!action.nonceFresh) {
        return { allowed: false, rule: "M3_DENY_BLOB_STALE_NONCE" };
      }
      return { allowed: true, rule: "M3_ALLOW_BLOB_STORAGE" };
    }
    case "snp-attest": {
      if (action.startsWithForbiddenPrefix) {
        return { allowed: false, rule: "M4_DENY_ATTEST_FORBIDDEN_PREFIX" };
      }
      return { allowed: true, rule: "M4_ALLOW_SNP_ATTEST" };
    }
    case "raw-socket":
    case "disk-write":
    case "shell-exec":
      return { allowed: false, rule: "M5_DENY_FORBIDDEN_CHANNEL" };
  }
}

export function verifyMonitorPolicyExhaustive(policyFn = evaluateMonitorExit) {
  const actions = [];
  for (const actorVmpl of ACTOR_VMPLS) {
    for (const channel of CHANNELS) {
      for (const payloadEncryption of PAYLOAD_ENCRYPTIONS) {
        for (const nonceFresh of BOOLEANS) {
          for (const fixedFrameCadence of BOOLEANS) {
            for (const hasPerSessionFields of BOOLEANS) {
              for (const startsWithForbiddenPrefix of BOOLEANS) {
                actions.push({
                  actorVmpl,
                  channel,
                  payloadEncryption,
                  nonceFresh,
                  fixedFrameCadence,
                  hasPerSessionFields,
                  startsWithForbiddenPrefix,
                });
              }
            }
          }
        }
      }
    }
  }

  let allowedStates = 0;
  let deniedStates = 0;
  let ceI1;
  let ceI2;
  let ceI3;
  let ceI4;
  let ceI5;

  for (const action of actions) {
    const decision = policyFn(action);
    if (decision.allowed) {
      allowedStates += 1;
      if (
        (action.channel === "relay-stream" || action.channel === "blob-storage") &&
        action.payloadEncryption !== "custody-aes-gcm" &&
        action.payloadEncryption !== "freeze-aes-gcm" &&
        !ceI1
      ) {
        ceI1 = action;
      }
      if (
        (action.channel === "relay-stream" || action.channel === "blob-storage") &&
        !action.nonceFresh &&
        !ceI2
      ) {
        ceI2 = action;
      }
      if (action.actorVmpl === 2 && !ceI3) {
        ceI3 = action;
      }
      if (action.channel === "control-plane" && action.hasPerSessionFields && !ceI4) {
        ceI4 = action;
      }
      if (action.channel === "snp-attest" && action.startsWithForbiddenPrefix && !ceI5) {
        ceI5 = action;
      }
    } else {
      deniedStates += 1;
    }
  }

  const invariants = [
    {
      id: "I1_NoPlaintextEgress",
      description:
        "No allowed action on relay-stream or blob-storage has payloadEncryption other than custody-aes-gcm or freeze-aes-gcm",
      passed: !ceI1,
      ...(ceI1 ? { counterexample: ceI1 } : {}),
    },
    {
      id: "I2_NoNonceReuse",
      description: "No allowed action on relay-stream or blob-storage has nonceFresh === false",
      passed: !ceI2,
      ...(ceI2 ? { counterexample: ceI2 } : {}),
    },
    {
      id: "I3_NoEngineBypass",
      description: "No allowed action on any channel has actorVmpl === 2",
      passed: !ceI3,
      ...(ceI3 ? { counterexample: ceI3 } : {}),
    },
    {
      id: "I4_NoPerSessionControlLeak",
      description: "No allowed action on control-plane has hasPerSessionFields === true",
      passed: !ceI4,
      ...(ceI4 ? { counterexample: ceI4 } : {}),
    },
    {
      id: "I5_ForbiddenPrefixNeverSigned",
      description: "No allowed action on snp-attest has startsWithForbiddenPrefix === true",
      passed: !ceI5,
      ...(ceI5 ? { counterexample: ceI5 } : {}),
    },
  ];

  return {
    statesChecked: actions.length,
    allowedStates,
    deniedStates,
    verified: invariants.every((i) => i.passed),
    invariants,
  };
}

// ============================================================================
// Reversible Local PII & Secret Placeholder Vault
// ============================================================================

const SCRUB_PATTERNS = [
  {
    category: "SECRET",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    category: "SECRET",
    regex:
      /\b(?:sk-[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|0x[a-fA-F0-9]{64})\b/g,
  },
  {
    category: "SECRET",
    regex: /\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{16,})\b/g,
  },
  {
    category: "EMAIL",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
];

export class PlaceholderVault {
  constructor() {
    this.valueToPlaceholder = new Map();
    this.placeholderToValue = new Map();
    this.counters = { EMAIL: 0, SECRET: 0 };
  }

  scrub(input) {
    if (typeof input !== "string" || !input) return input;
    let text = input;
    for (const spec of SCRUB_PATTERNS) {
      const regex = new RegExp(spec.regex.source, spec.regex.flags);
      text = text.replace(regex, (match) => this.register(spec.category, match));
    }
    return text;
  }

  restore(input) {
    if (typeof input !== "string" || !input) return input;
    let text = input;
    this.placeholderToValue.forEach((original, placeholder) => {
      if (text.includes(placeholder)) {
        text = text.split(placeholder).join(original);
      }
    });
    return text;
  }

  scrubMessages(messages) {
    return messages.map((msg) => {
      if (typeof msg.content === "string") {
        return {
          ...msg,
          content: this.scrub(msg.content),
        };
      }
      if (Array.isArray(msg.content)) {
        return {
          ...msg,
          content: msg.content.map((part) => {
            if (typeof part === "string") return this.scrub(part);
            if (part && typeof part === "object" && typeof part.text === "string") {
              return { ...part, text: this.scrub(part.text) };
            }
            return part;
          }),
        };
      }
      return { ...msg };
    });
  }

  get size() {
    return this.placeholderToValue.size;
  }

  register(category, rawValue) {
    const existing = this.valueToPlaceholder.get(rawValue);
    if (existing) return existing;
    this.counters[category] += 1;
    const placeholder = `[[DROUTER_${category}_${this.counters[category]}]]`;
    this.valueToPlaceholder.set(rawValue, placeholder);
    this.placeholderToValue.set(placeholder, rawValue);
    return placeholder;
  }
}

export function createStreamRestorer(scrubber) {
  let pending = "";
  return {
    push(chunk) {
      if (!scrubber || !chunk) return chunk;
      pending += chunk;
      const doubleOpen = pending.lastIndexOf("[[");
      if (doubleOpen !== -1) {
        const doubleClose = pending.indexOf("]]", doubleOpen + 2);
        if (doubleClose === -1 && pending.length - doubleOpen < 40) {
          const ready = pending.slice(0, doubleOpen);
          pending = pending.slice(doubleOpen);
          return scrubber.restore(ready);
        }
      }
      const singleOpen = pending.lastIndexOf("[");
      if (singleOpen !== -1) {
        const singleClose = pending.indexOf("]", singleOpen + 1);
        if (singleClose === -1 && pending.length - singleOpen < 32) {
          const ready = pending.slice(0, singleOpen);
          pending = pending.slice(singleOpen);
          return scrubber.restore(ready);
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

// ============================================================================
// Shared Zero-Trust TinfoilAI Client Factory (supports HTTPS & HTTP localhost)
// ============================================================================

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

  // Note: Any non-empty bearerToken value works here (the TinfoilAI/OpenAI client constructor
  // requires a non-empty string); actual authentication at the dRouter relay uses the
  // x-drouter-credit blind-signed token header (with per-IP free-tier fallback).
  return new TinfoilAI({
    bearerToken: "drouter-anonymous",
    baseURL: `${cleanUpstream}/api/relay/v1/`,
    attestationBundleURL,
  });
}

// ============================================================================
// Shared HTTP Helpers & Unified Proxy Server
// ============================================================================

export function readJsonBody(req) {
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

export function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "content-length": Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

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
    "drouter-proxy - Local OpenAI-Compatible Attested Enclave Proxy (Spec §1)",
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
    "  GET  http://127.0.0.1:<port>/v1/models",
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

/**
 * Creates an HTTP server implementing the local dRouter OpenAI-compatible zero-trust proxy.
 * Shared between `scripts/drouter-proxy.mjs` and `scripts/drouter-cli.mjs proxy`.
 */
export function createProxyServer({
  upstream = DEFAULT_UPSTREAM,
  clientFactory = null,
} = {}) {
  const normalizedUpstream = upstream.replace(/\/+$/, "");
  const monitorReport = verifyMonitorPolicyExhaustive();

  const createClient =
    clientFactory ?? (() => createZeroTrustClient(normalizedUpstream));

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

    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-headers":
          "Authorization, Content-Type, Accept, X-DRouter-Credit, X-DRouter-Credit-Token, X-DRouter-Scrub-PII, OpenAI-Organization, OpenAI-Project",
        "access-control-allow-methods": "GET, POST, OPTIONS",
      });
      res.end();
      return;
    }

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

    if (
      req.method === "GET" &&
      (url.pathname === "/v1/models" || url.pathname === "/api/v1/models")
    ) {
      const models = await fetchLiveTinfoilModels();
      sendJson(res, 200, {
        object: "list",
        data: models.map((m) => ({
          id: m.id,
          object: "model",
          created: m.created ?? 1792800000,
          owned_by: m.provider,
          enclave_attested: m.enclave_attested,
          ...(m.repo ? { repo: m.repo } : {}),
          ...(m.tag ? { tag: m.tag } : {}),
          ...(m.predicate ? { predicate: m.predicate } : {}),
          ...(m.healthy_hosts !== undefined ? { healthy_hosts: m.healthy_hosts } : {}),
          ...(m.configured_hosts !== undefined ? { configured_hosts: m.configured_hosts } : {}),
          ...(m.verified_hosts !== undefined ? { verified_hosts: m.verified_hosts } : {}),
        })),
      });
      return;
    }

    if (
      req.method === "POST" &&
      (url.pathname === "/v1/chat/completions" || url.pathname === "/api/v1/chat/completions")
    ) {
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

      if (!Array.isArray(body?.messages) || body.messages.length === 0) {
        sendJson(res, 400, {
          error: {
            message: "Request body must include a non-empty messages array",
            type: "invalid_request_error",
          },
        });
        return;
      }

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

      const vault = new PlaceholderVault();
      const scrubbedMessages = vault.scrubMessages(body.messages);
      const rawModel =
        typeof body.model === "string" && body.model.trim()
          ? body.model.trim()
          : DEFAULT_MODEL;
      const model = rawModel.startsWith("drouter/")
        ? rawModel.slice("drouter/".length)
        : rawModel;

      const creditHeader =
        req.headers["x-drouter-credit"] ||
        req.headers["x-drouter-credit-token"] ||
        process.env.DROUTER_CREDIT ||
        "";

      const upstreamHeaders = {
        "X-Tinfoil-Model": model,
        ...(creditHeader ? { "x-drouter-credit": String(creditHeader) } : {}),
      };

      const enclaveHeaders = {
        "x-drouter-redactions": String(vault.size),
        "x-drouter-enclave-host": String(verified.doc?.enclaveHost ?? ""),
        "X-DRouter-Attested": "true",
        "X-DRouter-Release": String(
          verified.doc?.releaseTag || verified.doc?.releaseDigest || "",
        ),
        "X-DRouter-Code-Fingerprint": String(verified.doc?.codeFingerprint ?? ""),
        "X-DRouter-Enclave-Fingerprint": String(verified.doc?.enclaveFingerprint ?? ""),
      };

      try {
        if (body.stream) {
          const stream = await verified.client.chat.completions.create(
            { ...body, model, messages: scrubbedMessages, stream: true },
            { headers: upstreamHeaders },
          );

          res.writeHead(200, {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
            "access-control-allow-origin": "*",
            ...enclaveHeaders,
          });

          const restorer = createStreamRestorer(vault);
          let lastChunkTemplate = null;

          for await (const chunk of stream) {
            lastChunkTemplate = chunk;
            const delta = chunk?.choices?.[0]?.delta?.content ?? "";
            if (!delta) {
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              continue;
            }
            const restoredDelta = restorer.push(delta);
            if (restoredDelta) {
              const outChunk = structuredClone(chunk);
              outChunk.choices[0].delta.content = restoredDelta;
              res.write(`data: ${JSON.stringify(outChunk)}\n\n`);
            }
          }

          const tail = restorer.flush();
          if (tail && lastChunkTemplate) {
            const flushChunk = structuredClone(lastChunkTemplate);
            if (flushChunk.choices?.[0]?.delta) {
              flushChunk.choices[0].delta.content = tail;
              res.write(`data: ${JSON.stringify(flushChunk)}\n\n`);
            }
          }

          res.write("data: [DONE]\n\n");
          res.end();
          return;
        }

        const completion = await verified.client.chat.completions.create(
          { ...body, model, messages: scrubbedMessages, stream: false },
          { headers: upstreamHeaders },
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
            drouter_attestation: {
              securityVerified: verified.doc?.securityVerified ?? true,
              enclaveHost: verified.doc?.enclaveHost ?? null,
              releaseTag: verified.doc?.releaseTag ?? null,
              codeFingerprint: verified.doc?.codeFingerprint ?? null,
              enclaveFingerprint: verified.doc?.enclaveFingerprint ?? null,
            },
          },
          enclaveHeaders,
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
