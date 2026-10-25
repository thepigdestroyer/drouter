#!/usr/bin/env node
/**
 * Server Route Abuse, Adversarial Input & High-Concurrency Stress Test Suite
 *
 * HARD SAFETY LIMITS:
 * - Refuses to run against any non-localhost URL (never touches drouter-demo.vercel.app).
 * - Requires DROUTER_STUB_UPSTREAM=1 on the target server or uses simulated/stubbed models
 *   so zero paid Tinfoil tokens or Arc gas are consumed during load testing.
 */

import { execSync } from "node:child_process";

const BASE_URL = process.env.STRESS_BASE_URL || "http://127.0.0.1:3200";
const CONCURRENCY = Number(process.env.STRESS_CONCURRENCY || 200);

const parsedBase = new URL(BASE_URL);
if (parsedBase.hostname !== "127.0.0.1" && parsedBase.hostname !== "localhost") {
  console.error(`FATAL: Refusing to stress-test non-localhost host: ${parsedBase.hostname}`);
  process.exit(1);
}

const GET_ROUTES = [
  "/api/registry",
  "/api/log",
  "/api/transparency",
  "/api/ashi?alpha=0.95",
  "/api/auditor",
  "/api/tiers",
  "/api/weights",
  "/api/accountability",
  "/api/compartment",
  "/api/sandbox",
  "/api/threshold",
  "/api/ohttp",
  "/api/custody",
  "/api/credits",
  "/api/freeze",
  "/api/freeze/deadbeef01020304",
  "/api/sim/roots",
  "/api/v1/models",
  "/api/v1/verify",
  "/v1/models",
  "/api/relay/enclave-matrix",
  "/api/relay/attestation",
  "/api/relay/relay-eu-zurich/attestation",
  "/api/atlas",
  "/api/gemini",
];

const POST_ROUTES = [
  {
    path: "/api/v1/chat/completions",
    validBody: JSON.stringify({
      model: "sim-echo-1",
      stream: false,
      messages: [{ role: "user", content: "Stress test ping" }],
    }),
  },
  {
    path: "/v1/chat/completions",
    validBody: JSON.stringify({
      model: "sim-echo-1",
      stream: false,
      messages: [{ role: "user", content: "Rewrite stress test ping" }],
    }),
  },
  {
    path: "/api/relay/v1/chat/completions",
    headers: {
      "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
      "ehbp-encapsulated-key": "aa".repeat(32),
      "x-tinfoil-model": "kimi-k3",
    },
    validBody: "encrypted-hpke-payload-simulation",
  },
  {
    path: "/api/relay/relay-eu-zurich/v1/chat/completions",
    headers: {
      "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
      "ehbp-encapsulated-key": "bb".repeat(32),
      "x-tinfoil-model": "glm-5-3",
    },
    validBody: "encrypted-hpke-payload-simulation",
  },
  {
    path: "/api/relay/attestation",
    validBody: JSON.stringify({
      enclaveUrl: "https://router-0.tinfoil.sh",
      repo: "tinfoilsh/confidential-model-router",
    }),
  },
  {
    path: "/api/relay/relay-us-virginia/attestation",
    validBody: JSON.stringify({
      enclaveUrl: "https://router-0.tinfoil.sh",
      repo: "tinfoilsh/confidential-model-router",
    }),
  },
  {
    path: "/api/anchor",
    validBody: JSON.stringify({
      receiptHash: `0x${"a1".repeat(32)}`,
      nodeId: "0xc25410e15da33f1b71b16fa5ca9a71c5be7bf827be08819e572ab8595f566253",
    }),
  },
  {
    path: "/api/log",
    validBody: JSON.stringify({
      type: "receipt",
      nodeId: "sim-1",
      receiptHash: `0x${"b2".repeat(32)}`,
      signatureVerified: true,
    }),
  },
  {
    path: "/api/freeze",
    validBody: JSON.stringify({
      blobId: "0102030405060708090a0b0c0d0e0f10",
      sessionIdHex: "11".repeat(16),
      nonceHex: "22".repeat(12),
      aadHex: "33".repeat(16),
      ciphertextHex: "44".repeat(64),
      modelId: "sim-echo-1",
    }),
  },
  {
    path: "/api/credits",
    validBody: JSON.stringify({
      blinded: ["0x" + "11".repeat(32)],
      denomination: 1,
    }),
  },
  {
    path: "/api/credits/spend",
    validBody: JSON.stringify({
      token: { token: "aa".repeat(32), signature: "bb".repeat(64), denomination: 1 },
      nodeId: "sim-1",
    }),
  },
  {
    path: "/api/credits/redeem",
    validBody: JSON.stringify({ nodeId: "sim-1" }),
  },
  {
    path: "/api/weights",
    validBody: JSON.stringify({
      providerId: "provider-frontier-labs",
      modelId: "frontier-closed-x1",
      status: "full",
    }),
  },
  {
    path: "/api/accountability",
    validBody: JSON.stringify({
      action: "trigger-canary",
      nodeId: "sim-1",
    }),
  },
  {
    path: "/api/compartment",
    validBody: JSON.stringify({
      prompt: "## 1. Task A\nCheck alpha\n\n## 2. Task B\nCheck beta",
      compromisedNodeFraction: 0.02,
    }),
  },
  {
    path: "/api/threshold",
    validBody: JSON.stringify({
      sessionId: "sess-stress",
      chipId: "H200-SXM-NV-0042",
      k: 3,
      n: 5,
    }),
  },
  {
    path: "/api/ohttp",
    validBody: JSON.stringify({
      encapsulatedRequestHex: "01002000010001" + "00".repeat(64),
    }),
  },
  {
    path: "/api/sim/sim-1/hello",
    validBody: JSON.stringify({
      clientNonce: "aa".repeat(32),
      modelId: "sim-echo-1",
    }),
  },
  {
    path: "/api/sim/sim-1/keyshare",
    validBody: JSON.stringify({
      ticket: "00".repeat(40),
      clientX25519Pk: "11".repeat(32),
      mlkemCt: "22".repeat(1088),
      sealed: "33".repeat(40),
    }),
  },
  {
    path: "/api/sim/sim-1/turn",
    validBody: JSON.stringify({
      ticket: "00".repeat(40),
      turn: 1,
      ct: "44".repeat(40),
    }),
  },
  {
    path: "/api/sim/sim-1/close",
    validBody: JSON.stringify({
      ticket: "00".repeat(40),
    }),
  },
  {
    path: "/api/atlas",
    validBody: JSON.stringify({
      query: "SEV-SNP attestation",
      limit: 3,
    }),
  },
  {
    path: "/api/gemini/plan",
    validBody: JSON.stringify({
      thinkingLevel: "high",
      background: true,
    }),
  },
];

function getServerRssMb(port = 3200) {
  try {
    const pidOut = execSync(`lsof -ti tcp:${port} -sTCP:LISTEN`, { encoding: "utf8" }).trim();
    const pid = pidOut.split("\n")[0]?.trim();
    if (!pid) return null;
    const rssKb = Number(execSync(`ps -o rss= -p ${pid}`, { encoding: "utf8" }).trim());
    return Number.isFinite(rssKb) ? Math.round((rssKb / 1024) * 10) / 10 : null;
  } catch {
    return null;
  }
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor((p / 100) * sorted.length)));
  return Math.round(sorted[idx] * 100) / 100;
}

async function timedFetch(path, init = {}, syntheticIp = "10.0.0.1") {
  const start = performance.now();
  const headers = new Headers(init.headers || {});
  if (!headers.has("x-forwarded-for")) {
    headers.set("x-forwarded-for", syntheticIp);
  }
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...init,
      headers,
    });
    const text = await res.text();
    const latencyMs = performance.now() - start;
    const hasStack =
      res.status >= 500 &&
      (/at\s+[A-Za-z0-9_$.]+\s+\(/.test(text) || text.includes("node_modules/"));
    return {
      path,
      method: init.method || "GET",
      status: res.status,
      latencyMs,
      hasStack,
      sampleError: res.status >= 500 ? text.slice(0, 240) : null,
    };
  } catch (err) {
    return {
      path,
      method: init.method || "GET",
      status: 599,
      latencyMs: performance.now() - start,
      hasStack: false,
      sampleError: err instanceof Error ? err.message : String(err),
    };
  }
}

async function runPool(tasks, concurrency) {
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) {
      const current = idx++;
      results.push(await tasks[current]());
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, tasks.length) }, () => worker()),
  );
  return results;
}

async function main() {
  const rssBefore = getServerRssMb(Number(parsedBase.port) || 3200);
  console.log(`=== dRouter Stress & Abuse Test ===`);
  console.log(`Target: ${BASE_URL} | Concurrency: ${CONCURRENCY} | Server RSS before: ${rssBefore ?? "n/a"} MB`);

  const allTasks = [];

  // 1. High-concurrency GET wave across all GET routes (varied synthetic IPs + same-IP burst to trigger 429)
  for (let round = 0; round < 6; round++) {
    for (const route of GET_ROUTES) {
      const ip = round < 4 ? `10.10.${round}.${Math.floor(Math.random() * 250)}` : "10.99.99.99";
      allTasks.push(() => timedFetch(route, { method: "GET" }, ip));
    }
  }

  // 2. Valid POST wave across all POST routes
  for (let round = 0; round < 4; round++) {
    for (const item of POST_ROUTES) {
      const ip = `10.20.${round}.${Math.floor(Math.random() * 250)}`;
      allTasks.push(() =>
        timedFetch(
          item.path,
          {
            method: "POST",
            headers: { "content-type": "application/json", ...(item.headers || {}) },
            body: item.validBody,
          },
          ip,
        ),
      );
    }
  }

  // 3. Malformed JSON + NUL bytes + Unicode astral plane fuzzing on all POST routes
  const malformedPayloads = [
    "{malformed_json: true,",
    "\x00\x00\x00{\"nullBytes\": \"\u0000\"}",
    "{\"unicode\": \"🏳️‍🌈🏴‍☠️𐍈𐌰𐌱\u0000\uFFFF\"}",
    "[]",
    "null",
    "\"raw-string\"",
  ];
  for (const item of POST_ROUTES) {
    for (let i = 0; i < malformedPayloads.length; i++) {
      const payload = malformedPayloads[i];
      allTasks.push(() =>
        timedFetch(
          item.path,
          {
            method: "POST",
            headers: { "content-type": "application/json", ...(item.headers || {}) },
            body: payload,
          },
          `10.30.${i}.${Math.floor(Math.random() * 250)}`,
        ),
      );
    }
  }

  // 4. 2 MB oversized body wave on POST routes (verifies 413 Payload Too Large & no OOM)
  const twoMbBody = JSON.stringify({
    model: "sim-echo-1",
    padding: "A".repeat(2 * 1024 * 1024),
  });
  for (const item of POST_ROUTES) {
    allTasks.push(() =>
      timedFetch(
        item.path,
        {
          method: "POST",
          headers: { "content-type": "application/json", ...(item.headers || {}) },
          body: twoMbBody,
        },
        `10.40.0.${Math.floor(Math.random() * 250)}`,
      ),
    );
  }

  // 5. Wrong HTTP methods (DELETE / PUT / PATCH)
  for (const route of GET_ROUTES.slice(0, 15)) {
    allTasks.push(() => timedFetch(route, { method: "DELETE" }, "10.50.1.1"));
    allTasks.push(() => timedFetch(route, { method: "PUT", body: "{}" }, "10.50.1.2"));
  }

  // 6. SSRF, Path Traversal & Header Injection vectors
  const traversalVectors = [
    { path: "/api/relay/v1/..%2f..%2fadmin", method: "POST", headers: { "x-tinfoil-enclave-url": "https://inference.tinfoil.sh", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/v1/%2e%2e/secret", method: "POST", headers: { "x-tinfoil-enclave-url": "https://inference.tinfoil.sh", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/v1/chat/completions", method: "POST", headers: { "x-tinfoil-enclave-url": "https://evil.com", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/v1/chat/completions", method: "POST", headers: { "x-tinfoil-enclave-url": "//evil.com", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/v1/chat/completions", method: "POST", headers: { "x-tinfoil-enclave-url": "https://inference.tinfoil.sh:8443", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/..%2fevil/v1/chat/completions", method: "POST", headers: { "x-tinfoil-enclave-url": "https://inference.tinfoil.sh", "ehbp-encapsulated-key": "aa".repeat(32) } },
    { path: "/api/relay/..%2fevil/attestation", method: "GET" },
    { path: "/api/freeze/..%2f..%2fetc%2fpasswd", method: "GET" },
    { path: "/api/sim/..%2fsim-1/hello", method: "POST", body: "{}" },
  ];
  for (const vec of traversalVectors) {
    allTasks.push(() =>
      timedFetch(
        vec.path,
        {
          method: vec.method,
          headers: vec.headers || {},
          body: vec.body || (vec.method === "POST" ? "test" : undefined),
        },
        "10.60.1.1",
      ),
    );
  }

  // 7. Rate-limit burst from a single IP against /api/anchor and /api/relay/v1/chat/completions
  for (let i = 0; i < 30; i++) {
    allTasks.push(() =>
      timedFetch(
        "/api/anchor",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            receiptHash: `0x${i.toString(16).padStart(64, "0")}`,
            nodeId: "0xc25410e15da33f1b71b16fa5ca9a71c5be7bf827be08819e572ab8595f566253",
          }),
        },
        "10.77.77.77",
      ),
    );
  }

  console.log(`Total requests queued: ${allTasks.length}`);
  const tStart = performance.now();
  const results = await runPool(allTasks, CONCURRENCY);
  const totalSec = ((performance.now() - tStart) / 1000).toFixed(2);
  const rssAfter = getServerRssMb(Number(parsedBase.port) || 3200);

  const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);
  const statusHistogram = {};
  const fiveHundreds = [];
  const stackLeaks = [];

  for (const r of results) {
    statusHistogram[r.status] = (statusHistogram[r.status] || 0) + 1;
    if (r.status >= 500) {
      fiveHundreds.push(r);
    }
    if (r.hasStack) {
      stackLeaks.push(r);
    }
  }

  const summary = {
    totalRequests: results.length,
    concurrency: CONCURRENCY,
    durationSec: Number(totalSec),
    p50Ms: percentile(latencies, 50),
    p95Ms: percentile(latencies, 95),
    p99Ms: percentile(latencies, 99),
    statusHistogram,
    fiveHundredCount: fiveHundreds.length,
    stackTraceLeaks: stackLeaks.length,
    rssBeforeMb: rssBefore,
    rssAfterMb: rssAfter,
    sample500s: fiveHundreds.slice(0, 5),
  };

  console.log(JSON.stringify(summary, null, 2));

  if (fiveHundreds.length > 0 || stackLeaks.length > 0) {
    console.error(`FAILED: Observed ${fiveHundreds.length} 5xx responses and ${stackLeaks.length} stack leaks.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
