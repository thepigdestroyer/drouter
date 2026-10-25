import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { canonicalJson, coarsenEpochSecToHour, sha256Hex } from "../src/canonical.js";
import { EMBEDDING_DIMENSIONS, getWholeKnowledgeCorpus } from "../src/corpus.js";
import {
  ALLOWED_PLANNER_TOOLS,
  ARGON_CONFIDENTIAL_TOOLS,
  assertContentFree,
  assertGoogleBoundMessage,
  assertValidToolCall,
  bucketTaskDescriptor,
  ContentFreeEgressError,
  createDigestHandleMapState,
  GEMINI_4_ARGON_MODEL_ID,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  replaceDigestsWithOpaqueHandles,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ToolPolicyViolationError,
  validateTaskDescriptor,
  validateToolCallArguments,
} from "../src/firewall.js";
import {
  computePublicKeysBindingSha256,
  ED25519_SPKI_PREFIX_HEX,
  getKeyRing,
  getPublicKeysResponse,
  loadAttestedKeyPair,
  resetKeyRingForTests,
  spkiHexToRawPublicKeyHex,
  writeTestAttestedKeyPemFiles,
} from "../src/keys.js";
import {
  computeMerkleRootFromLeaves,
  createVerificationLogEvent,
  signGeminiEgressReceipt,
  signTreeHeadWithAttestedKey,
  TreeHeadStateVerificationError,
  verifyAndSignTreeHead,
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

// The HTTP hardening and planner tests run on the plain HTTP path (Tinfoil mode, where the shim terminates TLS);
// boot mode is HTTPS-only and is covered by test/server-gcp.test.js.
function makeTinfoilTestKeysDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-core-http-keys-"));
  writeTestAttestedKeyPemFiles(dir, "egress-signing", "33".repeat(32));
  writeTestAttestedKeyPemFiles(dir, "tree-signing", "44".repeat(32));
  return dir;
}

function makeMockTransparencyDb(leaves) {
  return {
    collection(name) {
      if (name === "transparency_log") {
        return {
          find() {
            return {
              sort() {
                return {
                  async toArray() {
                    return leaves.map((l) => ({ ...l, docType: "leaf" }));
                  },
                };
              },
              async toArray() {
                return leaves.map((l) => ({ ...l, docType: "leaf" }));
              },
            };
          },
        };
      }
      return {
        find() {
          return {
            async toArray() {
              return [];
            },
          };
        },
      };
    },
  };
}

test("TaskDescriptor validator accepts valid bucketed descriptor, canonicalizes allowedTools, truncates error previews, and rejects unbucketed or free-text fields", () => {
  const valid = validateTaskDescriptor(makeValidDescriptor());
  assert.equal(valid.valid, true);
  assert.equal(valid.errors.length, 0);
  assert.equal(valid.descriptor.inputHandle, "$INPUT");
  assert.equal(valid.descriptor.inputTokenEstimate, 1024);

  // Also accepts wrapped { taskDescriptor }
  const wrapped = validateTaskDescriptor({ taskDescriptor: makeValidDescriptor() });
  assert.equal(wrapped.valid, true);

  // MINOR-1: Permuted allowedTools are normalized to canonical ALLOWED_PLANNER_TOOLS order
  const reversedTools = [...ALLOWED_PLANNER_TOOLS].reverse();
  const canonicalized = validateTaskDescriptor(
    makeValidDescriptor({ allowedTools: reversedTools }),
  );
  assert.equal(canonicalized.valid, true);
  assert.deepEqual(canonicalized.descriptor.allowedTools, [...ALLOWED_PLANNER_TOOLS]);

  const bucketedPermuted = bucketTaskDescriptor({
    taskKind: "summarize",
    inputTokenEstimate: 1300,
    redactionCounts: { EMAIL: 19, SECRET: 8, TOTAL: 27 },
    verification: { mechanicalRedactionPassed: true },
    allowedTools: reversedTools,
  });
  assert.equal(bucketedPermuted.inputTokenEstimate, 2048);
  assert.equal(bucketedPermuted.redactionCounts.EMAIL, 5);
  assert.equal(bucketedPermuted.redactionCounts.SECRET, 5);
  assert.equal(bucketedPermuted.redactionCounts.TOTAL, 5);
  assert.deepEqual(bucketedPermuted.allowedTools, [...ALLOWED_PLANNER_TOOLS]);
  assert.equal(validateTaskDescriptor(bucketedPermuted).valid, true);

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

  // Rejects wrong inputHandle and truncates/strips control chars in error messages (MINOR-2)
  const longBadHandle = "patient\u0000Alice\u0007Smith_" + "X".repeat(120);
  const badHandle = validateTaskDescriptor(
    makeValidDescriptor({ inputHandle: longBadHandle }),
  );
  assert.equal(badHandle.valid, false);
  assert.ok(!badHandle.errors[0].includes("\u0000"));
  assert.ok(!badHandle.errors[0].includes("X".repeat(50)));

  // Rejects unexpected extra fields
  const extraField = validateTaskDescriptor(
    makeValidDescriptor({ scrubbedPrompt: "Summarize this clinical trial" }),
  );
  assert.equal(extraField.valid, false);
  assert.ok(extraField.errors.some((e) => e.includes("scrubbedPrompt")));
});

test("assertContentFree blocks all 5 CRITICAL-2 bypasses as well as free text and unallowlisted keys", () => {
  // Valid payload with handles, enums, and numbers under allowlisted numeric keys
  assert.doesNotThrow(() => {
    assertContentFree({
      taskDescriptor: makeValidDescriptor(),
      topic: LOOKUP_TOPICS[0],
      resultHandle: "$RESULT_1",
      contentHandle: "$DIGEST_1",
      status: "allowed",
      id: "call-1",
      call_id: "call-1-scrub_and_symmetry_mask",
      previous_interaction_id: "inter-argon-turn-1",
    });
  });

  // Rejects free-text prompt string
  assert.throws(
    () => assertContentFree({ content: "Patient Jane Doe visited clinic on 2026-04-12" }),
    ContentFreeEgressError,
  );

  // Rejects JSON-smuggled free text inside a string
  assert.throws(
    () => assertContentFree({ text: canonicalJson({ content: "leaked user prompt" }) }),
    ContentFreeEgressError,
  );

  // BYPASS 1: Duplicate-key, whitespace, Unicode-escape, non-canonical key order, and array smuggling in JSON strings
  assert.throws(
    () =>
      assertContentFree({
        text: '{"taskKind":"Patient Jane Doe SSN 123-45-6789","taskKind":"analyze"}',
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        text: '{  "taskKind": "analyze" }',
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        text: '{"\\u0074askKind":"analyze"}',
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        // Non-sorted keys (taskKind before inputHandle)
        text: '{"taskKind":"analyze","inputHandle":"$INPUT"}',
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        text: '["ok"]',
      }),
    ContentFreeEgressError,
  );
  // Nested JSON-in-JSON string is rejected even if inner JSON is canonical
  assert.throws(
    () =>
      assertContentFree({
        text: canonicalJson({
          text: canonicalJson({ taskKind: "analyze" }),
        }),
      }),
    ContentFreeEgressError,
  );

  // BYPASS 2: UTF-16LE, UTF-16BE, high-bit ASCII hex smuggling, and 0x hashes under non-hash keys
  const utf8HexSmuggled =
    "0x" + Buffer.from("Patient Jane Doe SSN 123-45-6789", "utf8").toString("hex");
  assert.equal(utf8HexSmuggled.length, 66);
  assert.throws(
    () => assertContentFree({ contentSha256: utf8HexSmuggled }),
    ContentFreeEgressError,
  );

  const utf16leSmuggled =
    "0x" + Buffer.from("Patient Jane Doe", "utf16le").toString("hex");
  assert.equal(utf16leSmuggled.length, 66);
  assert.throws(
    () => assertContentFree({ contentSha256: utf16leSmuggled }),
    ContentFreeEgressError,
  );

  const highBitSmuggled =
    "0x" +
    Buffer.from(
       Array.from(Buffer.from("Patient Jane Doe SSN 123-45-6789", "utf8"), (b) => b | 0x80),
    ).toString("hex");
  assert.equal(highBitSmuggled.length, 66);
  assert.throws(
    () => assertContentFree({ contentSha256: highBitSmuggled }),
    ContentFreeEgressError,
  );

  // Genuine SHA-256 hash rejected under non-hash keys (text, content, status)
  assert.throws(
    () =>
      assertContentFree({
        text: "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        content: "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      }),
    ContentFreeEgressError,
  );

  // BYPASS 3: Arbitrary snake_case English text in SAFE_CALL_ID_REGEX
  assert.throws(
    () => assertContentFree({ id: "call-patient_jane_doe_has_hiv_and_diabetes" }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ call_id: "tc-leaked_secret_diagnosis" }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ previous_interaction_id: "inter-bad_patient_record" }),
    ContentFreeEgressError,
  );

  // BYPASS 4: Numbers encoding text, floats, negative zero, large integers, and numbers under non-numeric keys
  assert.throws(
    () => assertContentFree({ content: [80, 97, 116, 105, 101, 110, 116] }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ content: 80 }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ inputTokenEstimate: 79559981709933 }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ inputTokenEstimate: 0.48656111 }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ inputTokenEstimate: -0 }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ EMAIL: 6 }),
    ContentFreeEgressError,
  );

  // BYPASS 5: Nested arrays, boolean/number arrays, unallowlisted array keys, depth cap, non-plain prototypes, and non-enumerable properties
  assert.throws(
    () => assertContentFree({ input: [[{ type: "text", text: "ok" }]] }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ input: [true, false, true] }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ allowedTools: [1, 2, 3] }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ content: ["ok"] }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        allowedTools: new Array(33).fill("scrub_and_symmetry_mask"),
      }),
    ContentFreeEgressError,
  );

  // Root primitives / arrays rejected
  assert.throws(() => assertContentFree("ok"), ContentFreeEgressError);
  assert.throws(() => assertContentFree(1024), ContentFreeEgressError);
  assert.throws(() => assertContentFree(true), ContentFreeEgressError);
  assert.throws(() => assertContentFree(["ok"]), ContentFreeEgressError);

  // Non-plain prototype rejected
  const protoObj = Object.create({ taskKind: "analyze" });
  protoObj.status = "ok";
  assert.throws(() => assertContentFree(protoObj), ContentFreeEgressError);

  // Non-enumerable property rejected via Object.getOwnPropertyNames
  const nonEnumObj = { status: "ok" };
  Object.defineProperty(nonEnumObj, "text", {
    value: "Patient Jane Doe",
    enumerable: false,
  });
  assert.throws(() => assertContentFree(nonEnumObj), ContentFreeEgressError);

  // Own __proto__ property rejected
  const ownProtoObj = JSON.parse('{"status":"ok","__proto__":{"text":"leaked"}}');
  assert.throws(() => assertContentFree(ownProtoObj), ContentFreeEgressError);

  // Depth > 8 rejected
  let deep = { status: "ok" };
  for (let i = 0; i < 10; i++) {
    deep = { result: deep };
  }
  assert.throws(() => assertContentFree(deep), ContentFreeEgressError);

  // =========================================================================
  // PASS-2 ADVERSARIAL CASES (IMPORTANT-1, IMPORTANT-2, MINOR-1 & HEX ROOT CAUSE)
  // =========================================================================

  // IMPORTANT-1.1: Numeric-only, boolean-only, object-only, and object-array keys reject string enums and handles
  assert.throws(
    () =>
      assertContentFree({
        EMAIL: "provider:tinfoil",
        SECRET: "attack:voltage-glitching",
        inputTokenEstimate: "$RESULT_42",
        background: "provider:venice-ai",
      }),
    ContentFreeEgressError,
  );
  assert.throws(() => assertContentFree({ EMAIL: "provider:tinfoil" }), ContentFreeEgressError);
  assert.throws(
    () => assertContentFree({ SECRET: "attack:voltage-glitching" }),
    ContentFreeEgressError,
  );
  assert.throws(() => assertContentFree({ inputTokenEstimate: "$RESULT_42" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ background: "provider:venice-ai" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ store: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ redactionCounts: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ verification: "$INPUT" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ input: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ tools: "$INPUT" }), ContentFreeEgressError);

  // IMPORTANT-1.2: Exclusive key categories in isContentFreeString (no fallthrough)
  assert.throws(() => assertContentFree({ contentSha256: "$INPUT" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ contentSha256: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ topDocSha256: "$DOC_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ receiptSha256: "$RECEIPT_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ id: "provider:tinfoil" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ call_id: "$RESULT_19" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ tool_call_id: "ok" }), ContentFreeEgressError);
  assert.throws(
    () => assertContentFree({ previous_interaction_id: "provider:tinfoil" }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ system_instruction: "provider:tinfoil" }),
    ContentFreeEgressError,
  );
  assert.throws(() => assertContentFree({ description: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ required: ["$RESULT_1"] }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ required: ["ok"] }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ inputHandle: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ outputHandle: "verified" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ resultHandle: "provider:tinfoil" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ topDocHandle: "ok" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ receiptHandle: "executed" }), ContentFreeEgressError);

  // IMPORTANT-1.3: Plain objects rejected under primitive-only keys
  assert.throws(() => assertContentFree({ text: { status: "ok" } }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ EMAIL: { status: "ok" } }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ contentSha256: { status: "ok" } }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ status: { status: "ok" } }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ inputHandle: { status: "ok" } }), ContentFreeEgressError);

  // IMPORTANT-2.1: Alternating high-bit (0x80) ASCII bypass
  const alternatingHighBitHex =
    "0x50e174e965ee74a04ae16ee520c46fe520d353ce20b132b32db435ad36b738b9";
  assert.throws(
    () => assertContentFree({ contentSha256: alternatingHighBitHex }),
    ContentFreeEgressError,
  );

  // IMPORTANT-2.2: Non-null control-byte separators (0x01..0x1f) + digits/punctuation bypass
  const controlByteSeparatorHex =
    "0x4a616e65446f65013132332d34352d02363738393a484903562b736563720421";
  assert.throws(
    () => assertContentFree({ contentSha256: controlByteSeparatorHex }),
    ContentFreeEgressError,
  );

  // Short hex defense-in-depth (<= 16 chars)
  const shortAsciiHex = "0x" + Buffer.from("Patient", "utf8").toString("hex");
  assert.ok(shortAsciiHex.length <= MAX_GOOGLE_BOUND_HEX_LENGTH);
  assert.throws(
    () => assertContentFree({ contentSha256: shortAsciiHex }, "$.googleBound"),
    ContentFreeEgressError,
  );
  assert.doesNotThrow(() => {
    assertContentFree({ contentSha256: "0x9f86d081884c" }, "$.googleBound");
  });

  // Any hex string > 16 chars is rejected in Google-bound payloads (even a genuine SHA-256 digest!)
  const genuineSha256 =
    "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  assert.throws(
    () => assertContentFree({ contentSha256: genuineSha256 }, "$.createRequest"),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ topDocSha256: genuineSha256 }, "$.followUpRequest(1)"),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree(
        { receiptSha256: genuineSha256 },
        "$.functionResult(anchor_arc_settlement_with_human_gate)",
      ),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        type: "function_result",
        call_id: "call-1",
        name: "scrub_and_symmetry_mask",
        result: canonicalJson({ status: "ok", contentSha256: genuineSha256 }),
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ contentSha256: "0x9f86d081884c7d65" }),
    ContentFreeEgressError,
  );

  // MINOR-1: LOOKUP_TOPICS accepted in search_atlas_hybrid_kb
  for (const lookupTopic of LOOKUP_TOPICS) {
    const validated = validateToolCallArguments("search_atlas_hybrid_kb", {
      topic: lookupTopic,
      inputHandle: "$INPUT",
      category: "provider",
    });
    assert.equal(validated.valid, true);
    assert.equal(validated.sanitizedArgs.topic, lookupTopic);
  }

  // Legitimate orchestrator request shapes and local handle mapping for digests
  const descriptor = makeValidDescriptor();
  assert.doesNotThrow(() => assertContentFree(descriptor, "$.taskDescriptor"));

  const createRequest = {
    model: GEMINI_4_ARGON_MODEL_ID,
    background: true,
    store: false,
    system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
    generation_config: {
      thinking_level: "medium",
      max_output_tokens: 131_072,
    },
    input: [{ type: "text", text: canonicalJson(descriptor) }],
    tools: ARGON_CONFIDENTIAL_TOOLS,
  };
  assert.doesNotThrow(() => assertContentFree(createRequest, "$.createRequest"));

  const digestState = createDigestHandleMapState();
  const rawToolResults = {
    scrub_and_symmetry_mask: {
      status: "ok",
      passed: true,
      outputHandle: "$RESULT_1",
      redactionCount: 3,
      mechanicalRedactionCount: 3,
      attestedRedactionCount: 0,
      bucketBytes: 4096,
      plaintextLeakCount: 0,
      contentSha256: genuineSha256,
    },
    verify_two_hop_enclave_and_quorum: {
      status: "verified",
      passed: true,
      providerId: "tinfoil",
      enclaveModel: "gemma4-31b",
      checksPassed: 7,
      checksTotal: 7,
      selfHealed: false,
      routerDigestHex: "0x4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
      enclaveMeasurementHex: "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    search_atlas_hybrid_kb: {
      status: "ok",
      outputHandle: "$RESULT_2",
      vectorEngine: "app-fallback",
      textEngine: "app-fallback",
      fusionEngine: "app-rrf",
      totalDocs: 16,
      matchingReceiptsCount: 0,
      topDocSha256: "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    },
    invoke_attested_enclave: {
      status: "completed",
      outputHandle: "$RESULT_3",
      enclaveModel: "gemma4-31b",
      outputTokenEstimate: 128,
      outputSha256: "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763",
      attested: true,
    },
    anchor_arc_settlement_with_human_gate: {
      status: "blocked_pending_human",
      requiresHumanApproval: true,
      humanApproved: false,
      stateChangedOnChain: false,
      receiptSha256: "0x5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
    },
  };

  const fnResults = [];
  let idx = 0;
  for (const [toolName, rawRes] of Object.entries(rawToolResults)) {
    idx += 1;
    assert.throws(
      () => assertContentFree(rawRes, `$.toolExecutor.result(${toolName})`),
      ContentFreeEgressError,
    );
    const googleSafe = replaceDigestsWithOpaqueHandles(rawRes, digestState);
    assert.equal(/0x[0-9a-f]{16,}/i.test(JSON.stringify(googleSafe)), false);
    assert.doesNotThrow(() => assertContentFree(googleSafe, `$.toolExecutor.result(${toolName})`));
    assert.doesNotThrow(() => assertContentFree(googleSafe, `$.toolResult(${toolName})`));
    const resultStep = {
      type: "function_result",
      call_id: `call-1-${idx}`,
      name: toolName,
      result: canonicalJson(googleSafe),
    };
    assert.doesNotThrow(() => assertContentFree(resultStep, `$.functionResult(${toolName})`));
    fnResults.push(resultStep);
  }
  assert.equal(digestState.byHandle["$DOC_1"], rawToolResults.search_atlas_hybrid_kb.topDocSha256);
  assert.equal(
    digestState.byHandle["$RECEIPT_1"],
    rawToolResults.anchor_arc_settlement_with_human_gate.receiptSha256,
  );

  const followUpRequest = {
    model: GEMINI_4_ARGON_MODEL_ID,
    background: true,
    store: false,
    previous_interaction_id: "inter-argon-turn-1",
    generation_config: {
      thinking_level: "medium",
      max_output_tokens: 131_072,
    },
    input: fnResults,
    tools: ARGON_CONFIDENTIAL_TOOLS,
  };
  assert.doesNotThrow(() => assertGoogleBoundMessage("followUpRequest", followUpRequest));
  assert.doesNotThrow(() => assertContentFree(followUpRequest, "$.followUpRequest(1)"));

  // =========================================================================
  // PASS-3 ADVERSARIAL CASES & CLOSED SCHEMA GATE (assertGoogleBoundMessage)
  // =========================================================================

  // Round 3 IMPORTANT-1: handle fallthrough under non-handle keys & A1Z26 spelling in allowedTools
  assert.throws(() => assertContentFree({ status: "$DOC_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ taskKind: "$RESULT_1" }), ContentFreeEgressError);
  assert.throws(
    () =>
      assertContentFree(
        {
          allowedTools: Array.from(
            "PATIENTJANEDOEHASHIVSECRET",
            (ch) => `$DOC_${ch.charCodeAt(0) - 64}`,
          ),
        },
        "$.createRequest",
      ),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        allowedTools: ["scrub_and_symmetry_mask", "scrub_and_symmetry_mask"],
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertContentFree({
        allowedTools: ["invoke_attested_enclave", "scrub_and_symmetry_mask"],
      }),
    ContentFreeEgressError,
  );
  assert.throws(() => assertContentFree({ allowedTools: [] }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ required: ["inputHandle"] }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ enum: ["ok", "verified"] }), ContentFreeEgressError);
  assert.throws(
    () =>
      assertContentFree({
        input: Array(16).fill({
          input: Array(16).fill({ enum: ["ok"] }),
        }),
      }),
    ContentFreeEgressError,
  );

  // Round 3 IMPORTANT-2: multi-key numeric packing, non-power-of-two buckets, sub-object key mixing
  const secret30 = "Patient Jane Doe SSN 123-45-67";
  const numericKeys15 = [
    "inputTokenEstimate",
    "max_output_tokens",
    "max_context_tokens",
    "max_tokens",
    "bucketQuantumBytes",
    "bucketBytes",
    "redactionCount",
    "mechanicalRedactionCount",
    "attestedRedactionCount",
    "plaintextLeakCount",
    "checksPassed",
    "checksTotal",
    "totalDocs",
    "matchingReceiptsCount",
    "outputTokenEstimate",
  ];
  const packedNumericPayload = {};
  for (let i = 0; i < numericKeys15.length; i++) {
    packedNumericPayload[numericKeys15[i]] =
      (secret30.charCodeAt(i * 2) << 8) | secret30.charCodeAt(i * 2 + 1);
  }
  assert.throws(
    () => assertContentFree(packedNumericPayload, "$.createRequest"),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertValidToolCall("scrub_and_symmetry_mask", {
        inputHandle: "$INPUT",
        bucketQuantumBytes: 18537,
      }),
    ToolPolicyViolationError,
  );
  assert.throws(() => assertContentFree({ bucketQuantumBytes: 18537 }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ bucketBytes: 18537 }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ inputTokenEstimate: 1500 }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ outputTokenEstimate: 1500 }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ max_output_tokens: 99999 }), ContentFreeEgressError);
  assert.throws(
    () =>
      assertContentFree(
        { redactionCounts: { status: "ok", max_output_tokens: 131072 } },
        "$.createRequest",
      ),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ verification: { status: "ok" } }),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ generation_config: { status: "ok" } }),
    ContentFreeEgressError,
  );

  // Round 3 IMPORTANT-3: replaceDigestsWithOpaqueHandles laundering & cross-prefix handles
  assert.throws(
    () =>
      replaceDigestsWithOpaqueHandles({
        status: "ok",
        topDocSha256: "Patient Jane Doe has HIV and diabetes (SSN 123-45-6789)",
      }),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      replaceDigestsWithOpaqueHandles({
        status: "ok",
        topDocHandle: "Patient Jane Doe",
        topDocSha256: rawToolResults.search_atlas_hybrid_kb.topDocSha256,
      }),
    ContentFreeEgressError,
  );
  const exhaustedState = createDigestHandleMapState();
  exhaustedState.counters.DOC = 16;
  assert.throws(
    () =>
      replaceDigestsWithOpaqueHandles(
        {
          status: "ok",
          topDocSha256: rawToolResults.search_atlas_hybrid_kb.topDocSha256,
        },
        exhaustedState,
      ),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$DIGEST_1",
        enclaveModel: "gemma4-31b",
      }),
    ToolPolicyViolationError,
  );
  assert.throws(
    () =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$DOC_1",
        enclaveModel: "gemma4-31b",
      }),
    ToolPolicyViolationError,
  );
  assert.throws(
    () =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$RESULT_17",
        enclaveModel: "gemma4-31b",
      }),
    ToolPolicyViolationError,
  );
  assert.throws(() => assertContentFree({ inputHandle: "$DOC_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ outputHandle: "$INPUT" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ topDocHandle: "$RESULT_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ receiptHandle: "$DOC_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ contentHandle: "$RESULT_1" }), ContentFreeEgressError);
  assert.throws(() => assertContentFree({ resultHandle: "$RESULT_17" }), ContentFreeEgressError);

  // Round 3 MINOR-1: short-hex ASCII smuggling, undefined values, empty objects
  assert.throws(
    () => assertContentFree({ contentSha256: "0x4849569a9b9c9d" }, "$.googleBound"),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ contentSha256: "0x48490156319a9b" }, "$.googleBound"),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertContentFree({ text: undefined, EMAIL: undefined }),
    ContentFreeEgressError,
  );
  assert.throws(() => assertContentFree({}), ContentFreeEgressError);

  // Closed schema gate: extra key, missing key, and out-of-range value rejected for every schema
  assert.doesNotThrow(() => assertGoogleBoundMessage("taskDescriptor", descriptor));
  assert.throws(
    () => assertGoogleBoundMessage("taskDescriptor", { ...descriptor, extra: "ok" }),
    ContentFreeEgressError,
  );
  const { taskKind: _omitTk, ...descNoTaskKind } = descriptor;
  void _omitTk;
  assert.throws(
    () => assertGoogleBoundMessage("taskDescriptor", descNoTaskKind),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertGoogleBoundMessage("taskDescriptor", { ...descriptor, inputTokenEstimate: 1000 }),
    ContentFreeEgressError,
  );

  assert.doesNotThrow(() => assertGoogleBoundMessage("createRequest", createRequest));
  assert.throws(
    () => assertGoogleBoundMessage("createRequest", { ...createRequest, extra: "ok" }),
    ContentFreeEgressError,
  );
  const { store: _omitSt, ...createNoStore } = createRequest;
  void _omitSt;
  assert.throws(
    () => assertGoogleBoundMessage("createRequest", createNoStore),
    ContentFreeEgressError,
  );
  assert.throws(
    () => assertGoogleBoundMessage("createRequest", { ...createRequest, store: true }),
    ContentFreeEgressError,
  );

  for (const step of fnResults) {
    assert.doesNotThrow(() => assertGoogleBoundMessage("functionResult", step));
    assert.throws(
      () => assertGoogleBoundMessage("functionResult", { ...step, extra: "ok" }),
      ContentFreeEgressError,
    );
    const { call_id: _omitCid, ...stepNoCallId } = step;
    void _omitCid;
    assert.throws(
      () => assertGoogleBoundMessage("functionResult", stepNoCallId),
      ContentFreeEgressError,
    );
    assert.throws(
      () => assertGoogleBoundMessage("functionResult", { ...step, call_id: "call-99" }),
      ContentFreeEgressError,
    );
  }

  assert.throws(
    () => assertGoogleBoundMessage("followUpRequest", { ...followUpRequest, extra: "ok" }),
    ContentFreeEgressError,
  );
  const { previous_interaction_id: _omitPrev, ...followUpNoPrev } = followUpRequest;
  void _omitPrev;
  assert.throws(
    () => assertGoogleBoundMessage("followUpRequest", followUpNoPrev),
    ContentFreeEgressError,
  );
  assert.throws(
    () =>
      assertGoogleBoundMessage("followUpRequest", {
        ...followUpRequest,
        previous_interaction_id: "inter-argon-turn-99",
      }),
    ContentFreeEgressError,
  );
});

test("Explicit CORE_KEY_SOURCE supports 'tinfoil' and 'boot', refuses missing/unknown values, and protects secretKey", async () => {
  const prevSource = process.env.CORE_KEY_SOURCE;
  const prevDir = process.env.TINFOIL_KEYS_DIR;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-core-keys-"));

  try {
    // 1. Missing or unknown CORE_KEY_SOURCE refuses to start
    delete process.env.CORE_KEY_SOURCE;
    resetKeyRingForTests();
    assert.throws(
      () => getKeyRing(),
      /Invalid or missing CORE_KEY_SOURCE/,
    );
    assert.throws(
      () => createCoreServer({ db: null }),
      /Invalid or missing CORE_KEY_SOURCE/,
    );
    process.env.CORE_KEY_SOURCE = "unknown-platform";
    assert.throws(
      () => getKeyRing(),
      /Invalid or missing CORE_KEY_SOURCE/,
    );

    // 2. CORE_KEY_SOURCE=tinfoil refuses to start when PEM files are missing (no silent fallback)
    process.env.CORE_KEY_SOURCE = "tinfoil";
    assert.throws(
      () => resetKeyRingForTests(tmpDir),
      /Missing attested Ed25519 key PEM files/,
    );

    // 3. CORE_KEY_SOURCE=tinfoil loads valid RFC 8410 PKCS#8 and SPKI PEM files
    const egressSeed = "11".repeat(32);
    const treeSeed = "22".repeat(32);
    writeTestAttestedKeyPemFiles(tmpDir, "egress-signing", egressSeed);
    writeTestAttestedKeyPemFiles(tmpDir, "tree-signing", treeSeed);

    const ring = resetKeyRingForTests({ keysDir: tmpDir, keySource: "tinfoil" });
    assert.equal(ring.keySource, "tinfoil");
    assert.equal(ring["egress-signing"].source, "attested-mount");
    assert.equal(ring["tree-signing"].source, "attested-mount");
    assert.ok(ring["egress-signing"].spkiHex.startsWith(ED25519_SPKI_PREFIX_HEX));
    assert.equal(
      spkiHexToRawPublicKeyHex(ring["egress-signing"].spkiHex),
      ring["egress-signing"].publicKeyHex,
    );
    // secretKey is non-enumerable
    assert.equal(Object.keys(ring["egress-signing"]).includes("secretKey"), false);
    assert.equal(JSON.stringify(ring["egress-signing"]).includes("secretKey"), false);
    assert.equal(ring["egress-signing"].secretKey.length, 32);

    // Rejects corrupted PKCS#8 prefix
    const badDir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-bad-keys-"));
    try {
      const { privateKey, publicKey } = fs;
      void privateKey;
      void publicKey;
      writeTestAttestedKeyPemFiles(badDir, "egress-signing", egressSeed);
      // Overwrite private_key.pem with public_key.pem content
      fs.copyFileSync(
        path.join(badDir, "egress-signing", "public_key.pem"),
        path.join(badDir, "egress-signing", "private_key.pem"),
      );
      assert.throws(
        () => loadAttestedKeyPair("egress-signing", { keysDir: badDir, keySource: "tinfoil" }),
      );
    } finally {
      fs.rmSync(badDir, { recursive: true, force: true });
    }

    // 4. CORE_KEY_SOURCE=boot generates in-memory keys and exposes sha256(canonical {egress, tree}) on GET /keys
    const bootRing = resetKeyRingForTests({ keySource: "boot" });
    assert.equal(bootRing.keySource, "boot");
    assert.equal(bootRing["egress-signing"].source, "ephemeral-boot");
    assert.equal(bootRing["tree-signing"].source, "ephemeral-boot");
    assert.equal(Object.keys(bootRing["egress-signing"]).includes("secretKey"), false);

    const pubResponse = getPublicKeysResponse(bootRing);
    assert.equal(pubResponse.ok, true);
    assert.equal(pubResponse.keySource, "boot");
    const expectedBindingHash = sha256Hex(
      canonicalJson({
        egress: pubResponse.egress.publicKeyHex,
        tree: pubResponse.tree.publicKeyHex,
      }),
    );
    assert.equal(pubResponse.keysDigest, expectedBindingHash);
    assert.equal(pubResponse.publicKeysSha256, expectedBindingHash);
    assert.equal(pubResponse.bindingSha256, expectedBindingHash);
    assert.equal(computePublicKeysBindingSha256(bootRing), expectedBindingHash);

    // Sign and verify a Gemini egress receipt with attested ring
    const outboundGeminiPayload = {
      model: "gemini-4-argon",
      background: true,
      store: false,
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
    assert.equal(verifyGeminiEgressReceipt(receipt, ring["egress-signing"].publicKeyHex).ok, true);

    // Tampered canonicalRequest fails verification
    const tampered = {
      ...receipt,
      canonicalRequest: receipt.canonicalRequest.replace("1024", "2048"),
    };
    assert.equal(verifyGeminiEgressReceipt(tampered).ok, false);

    // Sign and verify a transparency tree head against MongoDB transparency_log
    const leaves = [
      createVerificationLogEvent({
        index: 0,
        kind: "verification_event",
        nodeId: "tinfoil-router",
        ok: true,
        measurement: "9134838da8aa4e17",
        evidenceHash: "5233a27f1468f474",
        timestampSec: 1792886400,
      }),
      createVerificationLogEvent({
        index: 1,
        kind: "verification_event",
        nodeId: "kimi-k3",
        ok: true,
        measurement: "69c029108ac795b7",
        evidenceHash: "41068e0738e14ee7",
        timestampSec: 1792886400,
      }),
    ];
    const expectedRoot = bytesToHex(
      computeMerkleRootFromLeaves(leaves.map((l) => hexToBytes(l.leafHash))),
    ).toLowerCase();
    const mockDb = makeMockTransparencyDb(leaves);

    const sth = await verifyAndSignTreeHead(
      {
        treeSize: 2,
        rootHash: expectedRoot,
        timestampSec: 1792886400,
      },
      {
        keyPair: ring["tree-signing"],
        db: mockDb,
      },
    );
    assert.equal(sth.operatorPublicKey, ring["tree-signing"].publicKeyHex);
    assert.equal(verifySignedTreeHead(sth, ring["tree-signing"].publicKeyHex).ok, true);

    // Mismatched rootHash is rejected before signing
    await assert.rejects(
      () =>
        verifyAndSignTreeHead(
          {
            treeSize: 2,
            rootHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            timestampSec: 1792886400,
          },
          { keyPair: ring["tree-signing"], db: mockDb },
        ),
      TreeHeadStateVerificationError,
    );
  } finally {
    if (prevSource === undefined) {
      delete process.env.CORE_KEY_SOURCE;
    } else {
      process.env.CORE_KEY_SOURCE = prevSource;
    }
    if (prevDir === undefined) {
      delete process.env.TINFOIL_KEYS_DIR;
    } else {
      process.env.TINFOIL_KEYS_DIR = prevDir;
    }
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

test("HTTP server enforces CORS, timeouts, duplicate-key rejection, bearer auth + RFC 6962 log verification on sign-tree-head, and Gemini request options", async () => {
  let capturedCreateRequest = null;
  let capturedCreateOptions = null;

  const mockedGenaiClient = {
    interactions: {
      async create(req, options) {
        capturedCreateRequest = req;
        capturedCreateOptions = options;
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
              id: "call-untrusted_free_text_id_that_gets_sanitized",
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

  const leaves = [
    createVerificationLogEvent({
      index: 0,
      kind: "verification_event",
      nodeId: "tinfoil-router",
      ok: true,
      measurement: "9134838da8aa4e17",
      evidenceHash: "5233a27f1468f474",
      timestampSec: 1792886400,
    }),
  ];
  const validMerkleRoot = bytesToHex(
    computeMerkleRootFromLeaves(leaves.map((l) => hexToBytes(l.leafHash))),
  ).toLowerCase();
  const mockDb = makeMockTransparencyDb(leaves);
  const testOperatorToken = "operator-secret-token-2026";

  const server = createCoreServer({
    keySource: "tinfoil",
    keysDir: makeTinfoilTestKeysDir(),
    db: mockDb,
    operatorToken: testOperatorToken,
    timestampSec: 1792886400,
  });

  // Verify HTTP server timeouts (IMPORTANT-3)
  assert.equal(server.headersTimeout, 10_000);
  assert.equal(server.requestTimeout, 25_000);
  assert.equal(server.keepAliveTimeout, 5_000);
  assert.equal(server.timeout, 30_000);

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
    assert.equal(healthJson.keySource, "tinfoil");

    // 2. Disallowed CORS origin returns 403
    const badCorsRes = await fetch(`${baseUrl}/health`, {
      headers: { Origin: "https://attacker.example.com" },
    });
    assert.equal(badCorsRes.status, 403);
    assert.equal(badCorsRes.headers.get("access-control-allow-origin"), null);

    // 3. GET /keys returns public keys and canonical sha256 binding digest
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
    assert.equal(
      keysJson.publicKeysSha256,
      sha256Hex(
        canonicalJson({
          egress: keysJson.egress.publicKeyHex,
          tree: keysJson.tree.publicKeyHex,
        }),
      ),
    );

    // 4. GET /knowledge/corpus rejects query parameters and serves identical whole corpus without them
    const badCorpusQuery = await fetch(`${baseUrl}/knowledge/corpus?topic=tdx`);
    assert.equal(badCorpusQuery.status, 400);

    const corpusRes = await fetch(`${baseUrl}/knowledge/corpus`);
    assert.equal(corpusRes.status, 200);
    const corpusJson = await corpusRes.json();
    assert.equal(corpusJson.totalDocs, 16);
    assert.match(corpusJson.contentSha256, /^0x[0-9a-f]{64}$/);

    // 5. Duplicate JSON keys in raw HTTP request body are rejected with 400
    const dupKeyBody =
      '{"taskKind":"Patient Secret","taskKind":"analyze","inputHandle":"$INPUT","inputTokenEstimate":1024,"redactionCounts":{"TOTAL":1},"verification":{"mechanicalRedactionPassed":true},"allowedTools":["scrub_and_symmetry_mask"]}';
    const dupKeyRes = await fetch(`${baseUrl}/agent/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: dupKeyBody,
    });
    assert.equal(dupKeyRes.status, 400);

    // 6. POST /agent/plan without GEMINI_API_KEY returns 503 planner: "unavailable" + valid signed egressReceipt
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

    // 7. POST /transparency/sign-tree-head rejects unauthenticated or wrong Bearer token (401)
    const noAuthSthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        treeSize: 1,
        rootHash: validMerkleRoot,
        timestampSec: 1792886400,
      }),
    });
    assert.equal(noAuthSthRes.status, 401);

    const wrongAuthSthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer wrong-token",
      },
      body: JSON.stringify({
        treeSize: 1,
        rootHash: validMerkleRoot,
        timestampSec: 1792886400,
      }),
    });
    assert.equal(wrongAuthSthRes.status, 401);

    // 8. POST /transparency/sign-tree-head with valid Bearer token rejects forged rootHash (422) and malformed timestamp (400)
    const forgedRootRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testOperatorToken}`,
      },
      body: JSON.stringify({
        treeSize: 1,
        rootHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        timestampSec: 1792886400,
      }),
    });
    assert.equal(forgedRootRes.status, 422);

    const badSthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testOperatorToken}`,
      },
      body: JSON.stringify({
        treeSize: 1,
        rootHash: validMerkleRoot,
        timestampSec: 12345, // not divisible by 3600
      }),
    });
    assert.equal(badSthRes.status, 400);

    // 9. POST /transparency/sign-tree-head with valid Bearer token AND matching RFC 6962 Merkle root signs tree head
    const sthRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testOperatorToken}`,
      },
      body: JSON.stringify({
        treeSize: 1,
        rootHash: validMerkleRoot,
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

    // 10. Oversized POST body returns 413 with Connection: close
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
    keySource: "tinfoil",
    keysDir: makeTinfoilTestKeysDir(),
    db: null,
    genaiClient: mockedGenaiClient,
    timestampSec: 1792886400,
  });
  await new Promise((resolve) => serverWithGemini.listen(0, "127.0.0.1", resolve));
  const addr2 = serverWithGemini.address();
  const baseUrl2 = `http://127.0.0.1:${addr2.port}`;

  try {
    const keysRes2 = await fetch(`${baseUrl2}/keys`);
    const keysJson2 = await keysRes2.json();

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
    assert.equal(planJson.plan.steps[0].id, "call-1");
    // Invalid snake_case call.id from model was sanitized to fallback "call-2"
    assert.equal(planJson.plan.steps[1].id, "call-2");
    // Verify store: false and requestOptions were sent to client.interactions.create
    assert.equal(capturedCreateRequest.store, false);
    assert.equal(capturedCreateOptions.retries.strategy, "none");
    assert.equal(typeof capturedCreateOptions.timeout_ms, "number");
    assert.ok(capturedCreateOptions.fetch_options.signal instanceof AbortSignal);
    assert.equal(
      verifyGeminiEgressReceipt(
        planJson.egressReceipt,
        keysJson2.keys["egress-signing"].publicKeyHex,
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

test("HTTP server returns 422 on untrusted model tool policy violation, fails closed when CORE_OPERATOR_TOKEN is unset, 204 on OPTIONS preflight, and 404/405 on invalid routes/methods", async () => {
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
    keySource: "tinfoil",
    keysDir: makeTinfoilTestKeysDir(),
    db: null,
    operatorToken: "",
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

    // Sign-tree-head fails closed (401) when CORE_OPERATOR_TOKEN is unset/empty even if Authorization header is sent
    const unsetTokenRes = await fetch(`${baseUrl}/transparency/sign-tree-head`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer any-token",
      },
      body: JSON.stringify({
        treeSize: 0,
        rootHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        timestampSec: 1792886400,
      }),
    });
    assert.equal(unsetTokenRes.status, 401);

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
