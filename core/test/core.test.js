import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson, coarsenEpochSecToHour, sha256Hex } from "../src/canonical.js";
import { EMBEDDING_DIMENSIONS, getWholeKnowledgeCorpus } from "../src/corpus.js";
import {
  ALLOWED_PLANNER_TOOLS,
  assertContentFree,
  assertValidToolCall,
  bucketTaskDescriptor,
  ContentFreeEgressError,
  LOOKUP_TOPICS,
  ToolPolicyViolationError,
  validateTaskDescriptor,
} from "../src/firewall.js";
import {
  ED25519_SPKI_PREFIX_HEX,
  getKeyRing,
  getPublicKeysResponse,
  resetKeyRingForTests,
  spkiHexToRawPublicKeyHex,
  writeTestAttestedKeyPemFiles,
} from "../src/keys.js";
import {
  signGeminiEgressReceipt,
  signTreeHeadWithAttestedKey,
  verifyGeminiEgressReceipt,
  verifySignedTreeHead,
} from "../src/receipts.js";
import { createCoreServer, MAX_BODY_BYTES } from "../src/server.js";

function makeValidDescriptor(overrides = {}) {
  return {
    taskKind: "analyze",
    inputHandle: "$INPUT",
    inputTokenEstimate: 1024,
    redactionCounts: {
      EMAIL: 2,
      NAME: 1,
      TOTAL: 3,
    },
    verification: {
      mechanicalRedactionPassed: true,
      attestedPiiFilterVerified: true,
      bucketAligned4096: true,
    },
    allowedTools: [...ALLOWED_PLANNER_TOOLS],
    ...overrides,
  };
}

test("TaskDescriptor validator accepts valid bucketed descriptor and rejects unbucketed or free-text fields", () => {
  const valid = validateTaskDescriptor(makeValidDescriptor());
  assert.equal(valid.valid, true);
  assert.equal(valid.errors.length, 0);
  assert.equal(valid.descriptor.inputHandle, "$INPUT");
  assert.equal(valid.descriptor.inputTokenEstimate, 1024);

  // Also accepts wrapped { taskDescriptor }
  const wrapped = validateTaskDescriptor({ taskDescriptor: makeValidDescriptor() });
  assert.equal(wrapped.valid, true);

  // Rejects non-power-of-two inputTokenEstimate
  const nonBucketed = validateTaskDescriptor(
    makeValidDescriptor({ inputTokenEstimate: 1500 }),
  );
  assert.equal(nonBucketed.valid, false);
  assert.ok(nonBucketed.errors.some((e) => e.includes("power-of-two")));

  // Rejects redactionCounts > 5 (Wave 6 A3 cap)
  const uncappedCounts = validateTaskDescriptor(
    makeValidDescriptor({ redactionCounts: { EMAIL: 6 } }),
  );
  assert.equal(uncappedCounts.valid, false);
  assert.ok(uncappedCounts.errors.some((e) => e.includes("0..5")));

  // Rejects wrong inputHandle
  const badHandle = validateTaskDescriptor(
    makeValidDescriptor({ inputHandle: "patient Alice Smith" }),
  );
  assert.equal(badHandle.valid, false);

  // Rejects unexpected extra fields
  const extraField = validateTaskDescriptor(
    makeValidDescriptor({ scrubbedPrompt: "Summarize this clinical trial" }),
  );
  assert.equal(extraField.valid, false);
  assert.ok(extraField.errors.some((e) => e.includes("scrubbedPrompt")));

  // bucketTaskDescriptor rounds up tokens to power of two and caps redactionCounts at 5
  const bucketed = bucketTaskDescriptor({
    taskKind: "summarize",
    inputTokenEstimate: 1300,
    redactionCounts: { EMAIL: 19, SECRET: 8, TOTAL: 27 },
    verification: { mechanicalRedactionPassed: true },
  });
  assert.equal(bucketed.inputTokenEstimate, 2048);
  assert.equal(bucketed.redactionCounts.EMAIL, 5);
  assert.equal(bucketed.redactionCounts.SECRET, 5);
  assert.equal(bucketed.redactionCounts.TOTAL, 5);
  assert.equal(validateTaskDescriptor(bucketed).valid, true);
});

test("assertContentFree allows handles, LOOKUP_TOPICS, and real SHA-256 digests, and blocks all free text or smuggled ASCII", () => {
  // Valid payload with handles, enums, and closed lookup vocabulary
  assert.doesNotThrow(() => {
    assertContentFree({
      taskDescriptor: makeValidDescriptor(),
      topic: LOOKUP_TOPICS[0],
      resultHandle: "$RESULT_1",
      contentSha256: "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      status: "allowed",
    });
  });

  // Rejects free-text prompt string
  assert.throws(
    () => assertContentFree({ content: "Patient Jane Doe visited clinic on 2026-04-12" }),
    ContentFreeEgressError,
  );

  // Rejects JSON-smuggled free text inside a string
  assert.throws(
    () => assertContentFree({ text: JSON.stringify({ content: "leaked user prompt" }) }),
    ContentFreeEgressError,
  );

  // Rejects ASCII-smuggled hex disguised as 0x SHA-256 hash
  const smuggledHex =
    "0x" + Buffer.from("Patient Jane Doe SSN 123-45-6789", "utf8").toString("hex");
  assert.equal(smuggledHex.length, 66);
  assert.throws(
    () => assertContentFree({ contentSha256: smuggledHex }),
    ContentFreeEgressError,
  );

  // Rejects unallowlisted object key
  assert.throws(
    () => assertContentFree({ userPrompt: "$INPUT" }),
    ContentFreeEgressError,
  );
});

test("Attested Ed25519 keys load from PKCS#8 and SPKI PEM files and sign/verify egress receipts and tree heads", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-core-keys-"));
  try {
    const egressSeed = "11".repeat(32);
    const treeSeed = "22".repeat(32);
    writeTestAttestedKeyPemFiles(tmpDir, "egress-signing", egressSeed);
    writeTestAttestedKeyPemFiles(tmpDir, "tree-signing", treeSeed);

    const ring = resetKeyRingForTests(tmpDir);
    assert.equal(ring["egress-signing"].source, "attested-mount");
    assert.equal(ring["tree-signing"].source, "attested-mount");
    assert.ok(ring["egress-signing"].spkiHex.startsWith(ED25519_SPKI_PREFIX_HEX));
    assert.equal(
      spkiHexToRawPublicKeyHex(ring["egress-signing"].spkiHex),
      ring["egress-signing"].publicKeyHex,
    );

    const pubResponse = getPublicKeysResponse(ring);
    assert.equal(pubResponse.ok, true);
    assert.equal(
      pubResponse.keys["egress-signing"].publicKeyHex,
      ring["egress-signing"].publicKeyHex,
    );
    assert.equal(
      pubResponse.keys["tree-signing"].spkiHex,
      ring["tree-signing"].spkiHex,
    );

    // Sign and verify a Gemini egress receipt
    const outboundGeminiPayload = {
      model: "gemini-4-argon",
      background: true,
      generation_config: {
        thinking_level: "medium",
        max_output_tokens: 131072,
      },
      input: [
        {
          type: "text",
          text: canonicalJson(makeValidDescriptor()),
        },
      ],
    };
    const receipt = signGeminiEgressReceipt(
      outboundGeminiPayload,
      ring["egress-signing"],
      1792886400,
    );
    assert.equal(receipt.kind, "gemini-egress");
    assert.equal(receipt.epochHourSec, 1792886400);
    assert.equal(receipt.publicKey, ring["egress-signing"].publicKeyHex);
    assert.equal(receipt.sha256, sha256Hex(receipt.canonicalRequest));

    const verified = verifyGeminiEgressReceipt(receipt, ring["egress-signing"].publicKeyHex);
    assert.equal(verified.ok, true);

    // Tampered canonicalRequest fails verification
    const tampered = {
      ...receipt,
      canonicalRequest: receipt.canonicalRequest.replace("1024", "2048"),
    };
    assert.equal(verifyGeminiEgressReceipt(tampered).ok, false);

    // Sign and verify a transparency tree head with tree-signing key
    const sth = signTreeHeadWithAttestedKey(
      {
        treeSize: 16,
        rootHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        timestampSec: 1792886400,
      },
      ring["tree-signing"],
    );
    assert.equal(sth.operatorPublicKey, ring["tree-signing"].publicKeyHex);
    const sthVerified = verifySignedTreeHead(sth, ring["tree-signing"].publicKeyHex);
    assert.equal(sthVerified.ok, true);
  } finally {
    resetKeyRingForTests();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Whole-library knowledge corpus returns deterministic 16-doc shape with verified contentSha256 and no em dashes", async () => {
  const first = await getWholeKnowledgeCorpus({ db: null });
  const second = await getWholeKnowledgeCorpus({ db: null });

  assert.equal(first.ok, true);
  assert.equal(first.database, "drouter");
  assert.equal(first.collection, "enclave_intelligence");
  assert.equal(first.totalDocs, 16);
  assert.equal(first.documents.length, 16);
  assert.equal(first.contentSha256, second.contentSha256);
  assert.equal(
    first.contentSha256,
    `0x${sha256Hex(canonicalJson(first.documents))}`,
  );

  for (const doc of first.documents) {
    assert.equal(typeof doc.docId, "string");
    assert.equal(typeof doc.title, "string");
    assert.equal(typeof doc.summary, "string");
    assert.ok(Array.isArray(doc.tags) && doc.tags.length > 0);
    assert.ok(doc.sourceUrl.startsWith("https://"));
    assert.equal(typeof doc.retrievedAt, "string");
    assert.ok(Array.isArray(doc.embedding));
    assert.equal(doc.embedding.length, EMBEDDING_DIMENSIONS);
    assert.ok(!/[\u2013\u2014]/.test(doc.title));
    assert.ok(!/[\u2013\u2014]/.test(doc.summary));
  }
});

test("HTTP server enforces CORS, query-param prohibition, body size limits, and endpoints", async () => {
  const mockedGenaiClient = {
    interactions: {
      async create(req) {
        assertContentFree(req, "$.mockedGeminiReceived");
        return {
          id: "inter-1",
          status: "completed",
          output_text: "Planned confidential execution over $INPUT.",
          steps: [
            {
              type: "function_call",
              id: "call-1",
              name: "scrub_and_symmetry_mask",
              arguments: {
                inputHandle: "$INPUT",
                bucketQuantumBytes: 4096,
              },
            },
            {
              type: "function_call",
              id: "call-2",
              name: "invoke_attested_enclave",
              arguments: {
                inputHandle: "$INPUT",
                enclaveModel: "kimi-k3",
                taskKind: "analyze",
              },
            },
          ],
        };
      },
    },
  };

  const server = createCoreServer({
    db: null,
    timestampSec: 1792886400,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    // 1. GET /health
    const healthRes = await fetch(`${baseUrl}/health`, {
      headers: { Origin: "https://drouter-demo.vercel.app" },
    });
    assert.equal(healthRes.status, 200);
    assert.equal(
      healthRes.headers.get("access-control-allow-origin"),
      "https://drouter-demo.vercel.app",
    );
    const healthJson = await healthRes.json();
    assert.equal(healthJson.ok, true);
    assert.equal(healthJson.service, "deroute-core");

    // 2. Disallowed CORS origin returns 403
    const badCorsRes = await fetch(`${baseUrl}/health`, {
      headers: { Origin: "https://attacker.example.com" },
    });
    assert.equal(badCorsRes.status, 403);
    assert.equal(badCorsRes.headers.get("access-control-allow-origin"), null);

    // 3. GET /keys
    const keysRes = await fetch(`${baseUrl}/keys`, {
      headers: { Origin: "http://localhost:3000" },
    });
    assert.equal(keysRes.status, 200);
    const keysJson = await keysRes.json();
    assert.equal(keysJson.ok, true);
    assert.match(keysJson.keys["egress-signing"].publicKeyHex, /^[0-9a-f]{64}$/);
    assert.match(keysJson.keys["egress-signing"].spkiHex, /^[0-9a-f]{88}$/);
    assert.match(keysJson.keys["tree-signing"].publicKeyHex, /^[0-9a-f]{64}$/);
    assert.match(keysJson.keys["tree-signing"].spkiHex, /^[0-9a-f]{88}$/);

    // 4. GET /knowledge/corpus rejects query parameters and serves identical whole corpus without them
    const badCorpusQuery = await fetch(`${baseUrl}/knowledge/corpus?topic=tdx`);
    assert.equal(badCorpusQuery.status, 400);

    const corpusRes = await fetch(`${baseUrl}/knowledge/corpus`);
    assert.equal(corpusRes.status, 200);
    const corpusJson = await corpusRes.json();
    assert.equal(corpusJson.totalDocs, 16);
    assert.match(corpusJson.contentSha256, /^0x[0-9a-f]{64}$/);

    // 5. POST /agent/plan without GEMINI_API_KEY returns 503 planner: "unavailable" + valid signed egressReceipt
    const prevKey = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    try {
      const unavailRes = await fetch(`${baseUrl}/agent/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidDescriptor()),
      });
      assert.equal(unavailRes.status, 503);
      const unavailJson = await unavailRes.json();
      assert.equal(unavailJson.ok, false);
      assert.equal(unavailJson.planner, "unavailable");
      assert.equal(
        verifyGeminiEgressReceipt(
          unavailJson.egressReceipt,
          keysJson.keys["egress-signing"].publicKeyHex,
        ).ok,
        true,
      );
    } finally {
      if (prevKey !== undefined) process.env.GEMINI_API_KEY = prevKey;
    }

    // 6. POST /transparency/sign-tree-head signs valid tree head and rejects malformed one
    const badSthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        treeSize: 5,
        rootHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        timestampSec: 12345, // not divisible by 3600
      }),
    });
    assert.equal(badSthRes.status, 400);

    const sthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        treeSize: 5,
        rootHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        timestampSec: coarsenEpochSecToHour(1792886400),
      }),
    });
    assert.equal(sthRes.status, 200);
    const sthJson = await sthRes.json();
    assert.equal(sthJson.ok, true);
    assert.equal(
      verifySignedTreeHead(sthJson.sth, keysJson.keys["tree-signing"].publicKeyHex).ok,
      true,
    );

    // 7. Oversized POST body returns 413
    const hugeBody = JSON.stringify({ pad: "x".repeat(MAX_BODY_BYTES + 1024) });
    const hugeRes = await fetch(`${baseUrl}/agent/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: hugeBody,
    });
    assert.equal(hugeRes.status, 413);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  // Test POST /agent/plan with mocked Gemini Interactions client
  const serverWithGemini = createCoreServer({
    db: null,
    genaiClient: mockedGenaiClient,
    timestampSec: 1792886400,
  });
  await new Promise((resolve) => serverWithGemini.listen(0, "127.0.0.1", resolve));
  const addr2 = serverWithGemini.address();
  const baseUrl2 = `http://127.0.0.1:${addr2.port}`;

  try {
    const planRes = await fetch(`${baseUrl2}/agent/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(makeValidDescriptor()),
    });
    assert.equal(planRes.status, 200);
    const planJson = await planRes.json();
    assert.equal(planJson.ok, true);
    assert.equal(planJson.planner, "gemini-4-argon");
    assert.equal(planJson.plan.steps.length, 2);
    assert.equal(planJson.plan.steps[0].tool, "scrub_and_symmetry_mask");
    assert.equal(
      verifyGeminiEgressReceipt(
        planJson.egressReceipt,
        getKeyRing()["egress-signing"].publicKeyHex,
      ).ok,
      true,
    );
  } finally {
    await new Promise((resolve) => serverWithGemini.close(resolve));
  }

  // Test tool allowlist rejection when model returns an unallowlisted tool or free-text arg
  assert.throws(
    () =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "raw prompt text instead of handle",
        enclaveModel: "kimi-k3",
      }),
    ToolPolicyViolationError,
  );
});

test("HTTP server returns 422 on untrusted model tool policy violation, 204 on OPTIONS preflight, and 404/405 on invalid routes/methods", async () => {
  const maliciousGenaiClient = {
    interactions: {
      async create() {
        return {
          id: "inter-bad",
          status: "completed",
          steps: [
            {
              type: "function_call",
              id: "call-1",
              name: "exfiltrate_to_webhook",
              arguments: {
                inputHandle: "$INPUT",
              },
            },
          ],
        };
      },
    },
  };

  const server = createCoreServer({
    db: null,
    genaiClient: maliciousGenaiClient,
    timestampSec: 1792886400,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // Malicious tool call from Gemini is blocked with 422
    const badToolRes = await fetch(`${baseUrl}/agent/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(makeValidDescriptor()),
    });
    assert.equal(badToolRes.status, 422);
    const badToolJson = await badToolRes.json();
    assert.equal(badToolJson.ok, false);
    assert.equal(badToolJson.error, "tool_policy_violation");

    // OPTIONS preflight from allowed origin returns 204
    const preflightRes = await fetch(`${baseUrl}/agent/plan`, {
      method: "OPTIONS",
      headers: { Origin: "https://drouter-demo.vercel.app" },
    });
    assert.equal(preflightRes.status, 204);
    assert.equal(
      preflightRes.headers.get("access-control-allow-origin"),
      "https://drouter-demo.vercel.app",
    );

    // Unlisted route returns 404
    const notFoundRes = await fetch(`${baseUrl}/unlisted-route`);
    assert.equal(notFoundRes.status, 404);

    // Wrong HTTP method returns 405
    const wrongMethodRes = await fetch(`${baseUrl}/health`, { method: "POST" });
    assert.equal(wrongMethodRes.status, 405);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

