import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "@/lib/transparency/log";
import {
  ALLOWED_PLANNER_TOOLS,
  ARGON_CONFIDENTIAL_TOOLS,
  assertContentFree,
  assertGoogleBoundMessage,
  assertValidToolCall,
  buildInteractionsCreatePayload,
  buildTaskDescriptor,
  callGeminiInteractionsEndpoint,
  callTinfoilPlannerToolLoop,
  ContentFreeEgressError,
  createDigestHandleMapState,
  GEMINI_4_ARGON_MODEL_ID,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  replaceDigestsWithOpaqueHandles,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  ToolPolicyViolationError,
  validateToolCallArguments,
  type GenAIInteractionsClientLike,
  type TinfoilPlannerClientLike,
} from "@/lib/gemini";

describe("Shared Content-Free Egress Firewall: Round 1 & Round 2 Adversarial Suite + Legitimate Orchestrator Shapes", () => {
  it("blocks all Round 1 CRITICAL-2 bypass classes (JSON-in-string, UTF-16/high-bit hex, snake_case call IDs, numeric encoding, nested arrays, prototypes, non-enumerable keys)", () => {
    // 1. JSON-in-string bypasses: duplicate keys, whitespace, \uXXXX escapes, non-sorted keys, arrays, depth-2 JSON
    expect(() =>
      assertContentFree({
        text: '{"taskKind":"Patient Jane Doe SSN 123-45-6789","taskKind":"analyze"}',
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: '{  "taskKind": "analyze" }',
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: '{"\\u0074askKind":"analyze"}',
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: '{"taskKind":"analyze","inputHandle":"$INPUT"}',
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: '["ok"]',
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: "[true,false,true]",
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        text: canonicalJson({
          text: canonicalJson({ taskKind: "analyze" }),
        }),
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({
        status: canonicalJson({ taskKind: "analyze" }),
      }),
    ).toThrow(ContentFreeEgressError);

    // 2. Round 1 Hex smuggling: UTF-8, UTF-16LE, UTF-16BE, all-high-bit, repeating, decimal digits, non-hash keys
    const utf8Hex = `0x${Buffer.from(
      "Patient Jane Doe SSN 123-45-6789",
      "utf8",
    ).toString("hex")}`;
    expect(() => assertContentFree({ contentSha256: utf8Hex })).toThrow(
      ContentFreeEgressError,
    );

    const utf16leHex = `0x${Buffer.from(
      "Patient Jane Doe",
      "utf16le",
    ).toString("hex")}`;
    expect(() => assertContentFree({ contentSha256: utf16leHex })).toThrow(
      ContentFreeEgressError,
    );

    const utf16beBytes: number[] = [];
    for (const ch of "Patient Jane Doe") {
      utf16beBytes.push(0x00, ch.charCodeAt(0));
    }
    const utf16beHex = `0x${Buffer.from(utf16beBytes).toString("hex")}`;
    expect(() => assertContentFree({ contentSha256: utf16beHex })).toThrow(
      ContentFreeEgressError,
    );

    const highBitHex = `0x${Buffer.from(
      Array.from(
        Buffer.from("Patient Jane Doe SSN 123-45-6789", "utf8"),
        (b) => b | 0x80,
      ),
    ).toString("hex")}`;
    expect(() => assertContentFree({ contentSha256: highBitHex })).toThrow(
      ContentFreeEgressError,
    );

    expect(() =>
      assertContentFree({ contentSha256: `0x${"12345678".repeat(8)}` }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({ contentSha256: `0x${"0000".repeat(16)}` }),
    ).toThrow(ContentFreeEgressError);

    // Genuine SHA-256 under non-hash keys
    const validSha256 =
      "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    expect(() => assertContentFree({ text: validSha256 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ content: validSha256 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ status: validSha256 })).toThrow(
      ContentFreeEgressError,
    );

    // 3. Round 1 SAFE_CALL_ID_REGEX snake_case English text
    expect(() =>
      assertContentFree({ id: "call-patient_jane_doe_has_hiv_and_diabetes" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ call_id: "tc-leaked_secret_diagnosis" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ tool_call_id: "call-confidential_patient_notes" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({
        previous_interaction_id: "inter-bad_patient_record",
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ id: "call-1000" })).toThrow(
      ContentFreeEgressError,
    );

    // 4. Round 1 Numbers encoding text & bounds
    expect(() =>
      assertContentFree({ content: [80, 97, 116, 105, 101, 110, 116] }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ content: 80 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ inputTokenEstimate: 79559981709933 }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ inputTokenEstimate: 0.48656111 }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ inputTokenEstimate: -0 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ inputTokenEstimate: -1 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ EMAIL: 6 })).toThrow(
      ContentFreeEgressError,
    );

    // 5. Round 1 Nested arrays, prototypes, non-enumerable properties, getters, symbols, custom toJSON, depth > 8
    expect(() =>
      assertContentFree({ input: [[{ type: "text", text: "ok" }]] }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ input: [true, false, true] }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ allowedTools: [1, 2, 3] }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ content: ["ok"] })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({
        allowedTools: new Array(33).fill("scrub_and_symmetry_mask"),
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() => assertContentFree("ok")).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree(1024)).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree(true)).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree(["ok"])).toThrow(ContentFreeEgressError);

    const protoObj = Object.create({ taskKind: "analyze" }) as Record<
      string,
      unknown
    >;
    protoObj.status = "ok";
    expect(() => assertContentFree(protoObj)).toThrow(ContentFreeEgressError);

    const nonEnumObj: Record<string, unknown> = { status: "ok" };
    Object.defineProperty(nonEnumObj, "text", {
      value: "Patient Jane Doe",
      enumerable: false,
    });
    expect(() => assertContentFree(nonEnumObj)).toThrow(ContentFreeEgressError);

    const getterObj: Record<string, unknown> = {};
    Object.defineProperty(getterObj, "status", {
      get() {
        return "ok";
      },
      enumerable: true,
    });
    expect(() => assertContentFree(getterObj)).toThrow(ContentFreeEgressError);

    const ownProtoObj = JSON.parse(
      '{"status":"ok","__proto__":{"text":"leaked"}}',
    ) as unknown;
    expect(() => assertContentFree(ownProtoObj)).toThrow(
      ContentFreeEgressError,
    );

    let deep: Record<string, unknown> = { status: "ok" };
    for (let i = 0; i < 10; i++) {
      deep = { result: deep };
    }
    expect(() => assertContentFree(deep)).toThrow(ContentFreeEgressError);
  });

  it("blocks all Round 2 IMPORTANT-1 key-context type confusion and isContentFreeString fallthrough bypasses", () => {
    // 1. Numeric-only and boolean-only keys must reject string enums and opaque handles
    expect(() =>
      assertContentFree({
        EMAIL: "provider:tinfoil",
        SECRET: "attack:voltage-glitching",
        inputTokenEstimate: "$RESULT_42",
        background: "provider:venice-ai",
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() => assertContentFree({ EMAIL: "provider:tinfoil" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ SECRET: "attack:voltage-glitching" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ inputTokenEstimate: "$RESULT_42" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ background: "provider:venice-ai" }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ store: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ passed: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );

    // Object-only and object-array keys must reject strings
    expect(() => assertContentFree({ redactionCounts: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ verification: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ metadata: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ input: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ tools: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );

    // 2. Exclusive key categories in isContentFreeString (no fallthrough to ALLOWED_CONTENT_FREE_ENUMS or OPAQUE_HANDLE_REGEX)
    expect(() => assertContentFree({ contentSha256: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ contentSha256: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ topDocSha256: "$DOC_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ receiptSha256: "$RECEIPT_1" })).toThrow(
      ContentFreeEgressError,
    );

    expect(() => assertContentFree({ id: "provider:tinfoil" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ call_id: "$RESULT_19" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ tool_call_id: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ previous_interaction_id: "provider:tinfoil" }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      assertContentFree({ system_instruction: "provider:tinfoil" }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ description: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ description: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );

    expect(() => assertContentFree({ required: ["$RESULT_1"] })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ required: ["ok"] })).toThrow(
      ContentFreeEgressError,
    );

    expect(() => assertContentFree({ inputHandle: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ outputHandle: "verified" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ resultHandle: "provider:tinfoil" }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ topDocHandle: "ok" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ receiptHandle: "executed" })).toThrow(
      ContentFreeEgressError,
    );

    // 3. Plain objects under primitive-only keys must be rejected
    expect(() => assertContentFree({ text: { status: "ok" } })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ EMAIL: { status: "ok" } })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ contentSha256: { status: "ok" } }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ status: { status: "ok" } })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ inputHandle: { status: "ok" } })).toThrow(
      ContentFreeEgressError,
    );
  });

  it("blocks all Round 2 IMPORTANT-2 hex smuggling bypasses (alternating high-bit 0x80 and control-byte 0x01..0x1f separators) and enforces <= 16-char hex cap on Google-bound payloads", () => {
    // PoC 1 from C1-review-2.md: Alternating high-bit (0x80) on odd bytes of "Patient Jane Doe SSN 123-45-6789"
    const alternatingHighBitHex =
      "0x50e174e965ee74a04ae16ee520c46fe520d353ce20b132b32db435ad36b738b9";
    expect(() =>
      assertContentFree({ contentSha256: alternatingHighBitHex }),
    ).toThrow(ContentFreeEgressError);

    // PoC 2 from C1-review-2.md: Control-byte separators (\x01..\x04) + digits/punctuation
    const controlByteSeparatorHex =
      "0x4a616e65446f65013132332d34352d02363738393a484903562b736563720421";
    expect(() =>
      assertContentFree({ contentSha256: controlByteSeparatorHex }),
    ).toThrow(ContentFreeEgressError);

    // Short control-byte-interleaved ASCII chunks (5-char chunks separated by control bytes)
    const shortChunkControlHex = `0x${Buffer.from(
      "Jane\x01Doe:\x02SSN=\x031234\x045678\x05\x9f\x86\xd0\x81\x88\x4c\x7d",
      "latin1",
    ).toString("hex")}`;
    expect(shortChunkControlHex).toHaveLength(66);
    expect(() =>
      assertContentFree({ contentSha256: shortChunkControlHex }),
    ).toThrow(ContentFreeEgressError);

    // Defense-in-depth on short hex (<= 16 chars): smuggled ASCII in short hex is rejected
    const shortAsciiHex = `0x${Buffer.from("Patient", "utf8").toString("hex")}`;
    expect(shortAsciiHex.length).toBeLessThanOrEqual(
      MAX_GOOGLE_BOUND_HEX_LENGTH,
    );
    expect(() =>
      assertContentFree({ contentSha256: shortAsciiHex }, "$.googleBound"),
    ).toThrow(ContentFreeEgressError);

    const shortUtf16Hex = `0x${Buffer.from("Jane", "utf16le")
      .subarray(0, 7)
      .toString("hex")}`;
    expect(shortUtf16Hex.length).toBeLessThanOrEqual(
      MAX_GOOGLE_BOUND_HEX_LENGTH,
    );
    expect(() =>
      assertContentFree({ contentSha256: shortUtf16Hex }, "$.googleBound"),
    ).toThrow(ContentFreeEgressError);

    // Short non-ASCII digest prefix <= 16 chars passes as defense-in-depth
    expect(() =>
      assertContentFree({ contentSha256: "0x9f86d081884c" }, "$.googleBound"),
    ).not.toThrow();

    // Any hex string > 16 chars is rejected in Google-bound payloads (even a genuine SHA-256 digest!)
    const genuineSha256 =
      "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    expect(() =>
      assertContentFree(
        { contentSha256: genuineSha256 },
        "$.createRequest",
      ),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree(
        { topDocSha256: genuineSha256 },
        "$.followUpRequest(1)",
      ),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree(
        { receiptSha256: genuineSha256 },
        "$.functionResult(anchor_arc_settlement_with_human_gate)",
      ),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree(
        { outputSha256: genuineSha256 },
        "$.toolResult(invoke_attested_enclave)",
      ),
    ).toThrow(ContentFreeEgressError);
    // Inside JSON-encoded string (e.g. function_result.result or input[0].text)
    expect(() =>
      assertContentFree({
        type: "function_result",
        call_id: "call-1",
        name: "scrub_and_symmetry_mask",
        result: canonicalJson({
          status: "ok",
          contentSha256: genuineSha256,
        }),
      }),
    ).toThrow(ContentFreeEgressError);

    // 18-char hex string (> 16 chars) is rejected everywhere
    expect(() =>
      assertContentFree({ contentSha256: "0x9f86d081884c7d65" }),
    ).toThrow(ContentFreeEgressError);
  });

  it("verifies MINOR-1: LOOKUP_TOPICS are accepted in search_atlas_hybrid_kb tool schema and argument validation", () => {
    const searchTool = ARGON_CONFIDENTIAL_TOOLS.find(
      (t) => t.name === "search_atlas_hybrid_kb",
    );
    expect(searchTool).toBeDefined();
    for (const lookupTopic of LOOKUP_TOPICS) {
      expect(searchTool?.parameters.properties.topic.enum).toContain(
        lookupTopic,
      );
      const validated = validateToolCallArguments("search_atlas_hybrid_kb", {
        topic: lookupTopic,
        inputHandle: "$INPUT",
        category: "provider",
      });
      expect(validated.valid).toBe(true);
      expect(validated.sanitizedArgs?.topic).toBe(lookupTopic);
      expect(() =>
        assertValidToolCall("search_atlas_hybrid_kb", { topic: lookupTopic }),
      ).not.toThrow();
    }
  });

  it("replaces hex digests with local opaque handles in Google-bound payloads and verifies every legitimate orchestrator request shape passes", async () => {
    // 1. TaskDescriptor shape
    const descriptor = buildTaskDescriptor({
      taskKind: "review",
      inputTokenEstimate: 1024,
      redactionCounts: { SECRET: 1, EMAIL: 2, TOTAL: 3 },
      verification: {
        mechanicalRedactionPassed: true,
        attestedPiiFilterVerified: true,
        bucketAligned4096: true,
        routerSevSnpVerified: true,
        enclaveTdxGpuVerified: true,
        hpkeKeyBound: true,
        sigstoreManifestVerified: true,
        arcRegistryVerified: true,
      },
      allowedTools: ALLOWED_PLANNER_TOOLS,
    });
    expect(() =>
      assertContentFree(descriptor, "$.taskDescriptor"),
    ).not.toThrow();

    // 2. InteractionsCreatePayload shape
    const payload = buildInteractionsCreatePayload({
      taskDescriptor: descriptor,
      thinkingLevel: "high",
      background: true,
      maxOutputTokens: 131_072,
    });
    expect(() =>
      assertContentFree(payload, "$.interactionsPayload"),
    ).not.toThrow();

    // 3. createRequest shape
    const createRequest = {
      model: GEMINI_4_ARGON_MODEL_ID,
      background: true,
      store: false,
      system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
      generation_config: {
        thinking_level: "high",
        max_output_tokens: 131_072,
      },
      input: [
        {
          type: "text",
          text: canonicalJson(descriptor),
        },
      ],
      tools: ARGON_CONFIDENTIAL_TOOLS,
    };
    expect(() =>
      assertContentFree(createRequest, "$.createRequest"),
    ).not.toThrow();

    // 4. All 5 orchestrator tool results: verify local digest-to-handle replacement strips all hex before reaching Google
    const digestState = createDigestHandleMapState();
    const rawToolResults: Record<string, Record<string, unknown>> = {
      scrub_and_symmetry_mask: {
        status: "ok",
        passed: true,
        outputHandle: "$RESULT_1",
        redactionCount: 4,
        mechanicalRedactionCount: 4,
        attestedRedactionCount: 0,
        bucketBytes: 4096,
        plaintextLeakCount: 0,
        contentSha256:
          "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      },
      verify_two_hop_enclave_and_quorum: {
        status: "verified",
        passed: true,
        providerId: "tinfoil",
        enclaveModel: "gemma4-31b",
        checksPassed: 7,
        checksTotal: 7,
        selfHealed: false,
        routerDigestHex:
          "0x4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        enclaveMeasurementHex:
          "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      search_atlas_hybrid_kb: {
        status: "ok",
        outputHandle: "$RESULT_2",
        vectorEngine: "app-fallback",
        textEngine: "app-fallback",
        fusionEngine: "app-rrf",
        totalDocs: 16,
        matchingReceiptsCount: 0,
        topDocSha256:
          "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      },
      invoke_attested_enclave: {
        status: "completed",
        outputHandle: "$RESULT_3",
        enclaveModel: "gemma4-31b",
        outputTokenEstimate: 128,
        outputSha256:
          "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763",
        attested: true,
      },
      anchor_arc_settlement_with_human_gate: {
        status: "blocked_pending_human",
        requiresHumanApproval: true,
        humanApproved: false,
        stateChangedOnChain: false,
        receiptSha256:
          "0x5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
      },
    };

    for (const [toolName, rawRes] of Object.entries(rawToolResults)) {
      // Unmigrated 64-char SHA-256 digests are rejected now that ALLOW_LEGACY_ORCHESTRATOR_SHA256_UNTIL_MIGRATED is false
      expect(() =>
        assertContentFree(rawRes, `$.toolExecutor.result(${toolName})`),
      ).toThrow(ContentFreeEgressError);

      // Google-bound replacement strips all 0x digests and substitutes opaque handles
      const googleSafe = replaceDigestsWithOpaqueHandles(rawRes, digestState);
      expect(JSON.stringify(googleSafe)).not.toMatch(/0x[0-9a-f]{16,}/);
      expect(() =>
        assertContentFree(googleSafe, `$.toolExecutor.result(${toolName})`),
      ).not.toThrow();
      expect(() =>
        assertContentFree(googleSafe, `$.toolResult(${toolName})`),
      ).not.toThrow();
    }

    expect(digestState.byHandle["$DIGEST_1"]).toBe(
      rawToolResults.scrub_and_symmetry_mask.contentSha256,
    );
    expect(digestState.byHandle["$ROUTER_1"]).toBe(
      rawToolResults.verify_two_hop_enclave_and_quorum.routerDigestHex,
    );
    expect(digestState.byHandle["$MEASUREMENT_1"]).toBe(
      rawToolResults.verify_two_hop_enclave_and_quorum.enclaveMeasurementHex,
    );
    expect(digestState.byHandle["$DOC_1"]).toBe(
      rawToolResults.search_atlas_hybrid_kb.topDocSha256,
    );
    expect(digestState.byHandle["$DIGEST_2"]).toBe(
      rawToolResults.invoke_attested_enclave.outputSha256,
    );
    expect(digestState.byHandle["$RECEIPT_1"]).toBe(
      rawToolResults.anchor_arc_settlement_with_human_gate.receiptSha256,
    );

    // 5. End-to-end callGeminiInteractionsEndpoint verifies zero hex strings > 16 chars reach Google
    const outboundRequestsToGoogle: Array<Record<string, unknown>> = [];
    let turn = 0;
    const mockClient: GenAIInteractionsClientLike = {
      interactions: {
        create: vi.fn(async (req: Record<string, unknown>) => {
          outboundRequestsToGoogle.push(req);
          const serialized = JSON.stringify(req);
          expect(serialized).not.toMatch(/0x[0-9a-f]{15,}/i);
          expect(() =>
            assertContentFree(req, "$.createRequest"),
          ).not.toThrow();

          turn += 1;
          if (turn === 1) {
            return {
              id: "inter-argon-turn-1",
              status: "requires_action",
              steps: [
                {
                  type: "function_call",
                  id: "call-1",
                  name: "search_atlas_hybrid_kb",
                  arguments: { topic: "provider:tinfoil" },
                },
                {
                  type: "function_call",
                  id: "call-2",
                  name: "anchor_arc_settlement_with_human_gate",
                  arguments: {
                    actionKind: "anchor_receipt",
                    resultHandle: "$RESULT_2",
                    humanApproved: false,
                  },
                },
              ],
            };
          }
          return {
            id: "inter-argon-turn-2",
            status: "completed",
            output_text: "Completed over opaque handles.",
          };
        }),
      },
    };

    const callResult = await callGeminiInteractionsEndpoint({
      payload,
      genaiClient: mockClient,
      toolExecutor: async (name) => rawToolResults[name],
    });

    expect(callResult.liveEndpointReached).toBe(true);
    expect(outboundRequestsToGoogle).toHaveLength(2);
    expect(callResult.resolvedDigestHandles).toEqual({
      $DOC_1: rawToolResults.search_atlas_hybrid_kb.topDocSha256,
      $RECEIPT_1:
        rawToolResults.anchor_arc_settlement_with_human_gate.receiptSha256,
    });
  });

  it("blocks all Round 3 adversarial bypasses (handle fallthrough, A1Z26 token-array spelling, multi-key numeric packing, non-power-of-two buckets, sub-object key mixing, replaceDigestsWithOpaqueHandles laundering, cross-prefix handles, short-hex ASCII, undefined values, and callTinfoilPlannerToolLoop echoing)", async () => {
    // 1. Round 3 IMPORTANT-1: $DOC_<n> / $RESULT_<n> handle fallthrough under non-handle keys and A1Z26 spelling in allowedTools
    expect(() => assertContentFree({ status: "$DOC_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ taskKind: "$RESULT_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree(
        {
          allowedTools: Array.from(
            "PATIENTJANEDOEHASHIVSECRET",
            (ch) => `$DOC_${ch.charCodeAt(0) - 64}`,
          ),
        },
        "$.createRequest",
      ),
    ).toThrow(ContentFreeEgressError);

    // Duplicate tools, non-canonical tool order, or non-tool enums in allowedTools
    expect(() =>
      assertContentFree({
        allowedTools: ["scrub_and_symmetry_mask", "scrub_and_symmetry_mask"],
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({
        allowedTools: [
          "invoke_attested_enclave",
          "scrub_and_symmetry_mask",
        ],
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({
        allowedTools: ["ok", "verified"],
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ allowedTools: [] })).toThrow(
      ContentFreeEgressError,
    );

    // required outside .parameters.required or with duplicates
    expect(() =>
      assertContentFree({ required: ["inputHandle"] }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({
        parameters: {
          required: ["inputHandle", "inputHandle"],
        },
      }),
    ).toThrow(ContentFreeEgressError);

    // enum outside .properties.<param>.enum or with duplicates
    expect(() => assertContentFree({ enum: ["ok", "verified"] })).toThrow(
      ContentFreeEgressError,
    );

    // Multiplicative array nesting (input -> input -> enum)
    expect(() =>
      assertContentFree({
        input: Array(16).fill({
          input: Array(16).fill({ enum: ["ok"] }),
        }),
      }),
    ).toThrow(ContentFreeEgressError);

    // 2. Round 3 IMPORTANT-2: Packing 30 bytes of ASCII across the 15 numeric keys in a single object
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
    const packedNumericPayload: Record<string, number> = {};
    for (let i = 0; i < numericKeys15.length; i++) {
      const c1 = secret30.charCodeAt(i * 2);
      const c2 = secret30.charCodeAt(i * 2 + 1);
      packedNumericPayload[numericKeys15[i]] = (c1 << 8) | c2;
    }
    expect(() =>
      assertContentFree(packedNumericPayload, "$.createRequest"),
    ).toThrow(ContentFreeEgressError);

    // Non-power-of-two bucketQuantumBytes, bucketBytes, inputTokenEstimate, outputTokenEstimate, max_output_tokens
    expect(() =>
      assertValidToolCall("scrub_and_symmetry_mask", {
        inputHandle: "$INPUT",
        bucketQuantumBytes: 18537,
      }),
    ).toThrow(ToolPolicyViolationError);
    expect(() => assertContentFree({ bucketQuantumBytes: 18537 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ bucketBytes: 18537 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ inputTokenEstimate: 1500 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ outputTokenEstimate: 1500 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ max_output_tokens: 99999 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ checksPassed: 17 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ checksTotal: 0 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ redactionCount: 65 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ plaintextLeakCount: 6 })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ max_tokens: 5000 })).toThrow(
      ContentFreeEgressError,
    );

    // Sub-object key-context mixing
    expect(() =>
      assertContentFree(
        { redactionCounts: { status: "ok", max_output_tokens: 131072 } },
        "$.createRequest",
      ),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ verification: { status: "ok" } }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ generation_config: { status: "ok" } }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ subagent_routing: { status: "ok" } }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ metadata: { status: "ok" } })).toThrow(
      ContentFreeEgressError,
    );

    // 3. Round 3 IMPORTANT-3: replaceDigestsWithOpaqueHandles rejects free text, invalid existing handles, and > 16 handles
    expect(() =>
      replaceDigestsWithOpaqueHandles({
        status: "ok",
        topDocSha256: "Patient Jane Doe has HIV and diabetes (SSN 123-45-6789)",
      }),
    ).toThrow(ContentFreeEgressError);

    expect(() =>
      replaceDigestsWithOpaqueHandles({
        status: "ok",
        topDocHandle: "Patient Jane Doe",
        topDocSha256:
          "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      }),
    ).toThrow(ContentFreeEgressError);

    const exhaustedState = createDigestHandleMapState();
    exhaustedState.counters.DOC = 16;
    expect(() =>
      replaceDigestsWithOpaqueHandles(
        {
          status: "ok",
          topDocSha256:
            "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        },
        exhaustedState,
      ),
    ).toThrow(ContentFreeEgressError);

    // Cross-prefix handle confusion & handle index > 16
    expect(() =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$DIGEST_1",
        enclaveModel: "gemma4-31b",
      }),
    ).toThrow(ToolPolicyViolationError);
    expect(() =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$DOC_1",
        enclaveModel: "gemma4-31b",
      }),
    ).toThrow(ToolPolicyViolationError);
    expect(() =>
      assertValidToolCall("invoke_attested_enclave", {
        inputHandle: "$RESULT_17",
        enclaveModel: "gemma4-31b",
      }),
    ).toThrow(ToolPolicyViolationError);
    expect(() => assertContentFree({ inputHandle: "$DOC_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ inputHandle: "$DIGEST_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ outputHandle: "$INPUT" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ topDocHandle: "$RESULT_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ receiptHandle: "$DOC_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ contentHandle: "$RESULT_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ routerHandle: "$DIGEST_1" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() =>
      assertContentFree({ enclaveMeasurementHandle: "$ROUTER_1" }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ resultHandle: "$RESULT_17" })).toThrow(
      ContentFreeEgressError,
    );
    expect(() => assertContentFree({ topDocHandle: "$DOC_17" })).toThrow(
      ContentFreeEgressError,
    );

    // 4. Round 3 MINOR-1: Short-hex (<= 16 chars) ASCII smuggling, undefined values, empty objects, and callTinfoilPlannerToolLoop validation
    expect(() =>
      assertContentFree({ contentSha256: "0x4849569a9b9c9d" }, "$.googleBound"),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ contentSha256: "0x48490156319a9b" }, "$.googleBound"),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ text: undefined, EMAIL: undefined }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertContentFree({ status: "ok", text: undefined }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({})).toThrow(ContentFreeEgressError);

    // callTinfoilPlannerToolLoop rejects missing fnName and non-object JSON arguments
    const badMissingFnClient: TinfoilPlannerClientLike = {
      chat: {
        completions: {
          create: vi.fn(async () => ({
            id: "chatcmpl-bad-1",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: null,
                  tool_calls: [
                    {
                      id: "tc-1",
                      type: "function",
                      function: { name: "", arguments: "{}" },
                    },
                  ],
                },
              },
            ],
          })),
        },
      },
    };
    await expect(
      callTinfoilPlannerToolLoop({
        model: "gemma4-31b",
        scrubbedPrompt: "Review [EMAIL_1]",
        tinfoilClient: badMissingFnClient,
        toolExecutor: async () => ({
          status: "ok",
          passed: true,
          outputHandle: "$RESULT_1",
          redactionCount: 1,
          mechanicalRedactionCount: 1,
          attestedRedactionCount: 0,
          bucketBytes: 4096,
          plaintextLeakCount: 0,
          contentHandle: "$DIGEST_1",
        }),
      }),
    ).rejects.toThrow(ToolPolicyViolationError);

    const badNonObjectArgsClient: TinfoilPlannerClientLike = {
      chat: {
        completions: {
          create: vi.fn(async () => ({
            id: "chatcmpl-bad-2",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: null,
                  tool_calls: [
                    {
                      id: "tc-1",
                      type: "function",
                      function: {
                        name: "scrub_and_symmetry_mask",
                        arguments: '"leaked_string_instead_of_object"',
                      },
                    },
                  ],
                },
              },
            ],
          })),
        },
      },
    };
    await expect(
      callTinfoilPlannerToolLoop({
        model: "gemma4-31b",
        scrubbedPrompt: "Review [EMAIL_1]",
        tinfoilClient: badNonObjectArgsClient,
        toolExecutor: async () => ({
          status: "ok",
          passed: true,
          outputHandle: "$RESULT_1",
          redactionCount: 1,
          mechanicalRedactionCount: 1,
          attestedRedactionCount: 0,
          bucketBytes: 4096,
          plaintextLeakCount: 0,
          contentHandle: "$DIGEST_1",
        }),
      }),
    ).rejects.toThrow(ToolPolicyViolationError);
  });

  it("enforces closed schema gate (assertGoogleBoundMessage): every real orchestrator message passes, and for each schema one extra key, one missing key, and one out-of-range value are rejected", () => {
    const validDescriptor = buildTaskDescriptor({
      taskKind: "review",
      inputTokenEstimate: 1024,
      redactionCounts: { SECRET: 1, EMAIL: 2, TOTAL: 3 },
      verification: {
        mechanicalRedactionPassed: true,
        attestedPiiFilterVerified: true,
        bucketAligned4096: true,
      },
      allowedTools: ALLOWED_PLANNER_TOOLS,
    });

    // 1. Schema: taskDescriptor
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", validDescriptor),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", {
        ...validDescriptor,
        extraKey: "ok",
      }),
    ).toThrow(ContentFreeEgressError);
    const { taskKind: _omitTaskKind, ...descriptorMissingKey } = validDescriptor;
    void _omitTaskKind;
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", descriptorMissingKey),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", {
        ...validDescriptor,
        inputTokenEstimate: 1000, // not power of two
      }),
    ).toThrow(ContentFreeEgressError);

    // 2. Schema: interactionsPayload
    const validPayload = buildInteractionsCreatePayload({
      taskDescriptor: validDescriptor,
      thinkingLevel: "medium",
      background: true,
      maxOutputTokens: 131_072,
    });
    expect(() =>
      assertGoogleBoundMessage("interactionsPayload", validPayload),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("interactionsPayload", {
        ...validPayload,
        extraKey: "ok",
      }),
    ).toThrow(ContentFreeEgressError);
    const { metadata: _omitMeta, ...payloadMissingKey } = validPayload;
    void _omitMeta;
    expect(() =>
      assertGoogleBoundMessage("interactionsPayload", payloadMissingKey),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertGoogleBoundMessage("interactionsPayload", {
        ...validPayload,
        max_output_tokens: 99_999,
      }),
    ).toThrow(ContentFreeEgressError);

    // 3. Schema: createRequest
    const validCreateRequest = {
      model: GEMINI_4_ARGON_MODEL_ID,
      background: true,
      store: false,
      system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
      generation_config: {
        thinking_level: "medium",
        max_output_tokens: 131_072,
      },
      input: [
        {
          type: "text",
          text: canonicalJson(validDescriptor),
        },
      ],
      tools: ARGON_CONFIDENTIAL_TOOLS,
    };
    expect(() =>
      assertGoogleBoundMessage("createRequest", validCreateRequest),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("createRequest", {
        ...validCreateRequest,
        extraKey: "ok",
      }),
    ).toThrow(ContentFreeEgressError);
    const { store: _omitStore, ...createMissingKey } = validCreateRequest;
    void _omitStore;
    expect(() =>
      assertGoogleBoundMessage("createRequest", createMissingKey),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertGoogleBoundMessage("createRequest", {
        ...validCreateRequest,
        store: true, // must be false
      }),
    ).toThrow(ContentFreeEgressError);

    // 4. Schema: toolCall (all 5 tools)
    const validToolCalls: Record<string, Record<string, unknown>> = {
      scrub_and_symmetry_mask: {
        inputHandle: "$INPUT",
        bucketQuantumBytes: 4096,
      },
      verify_two_hop_enclave_and_quorum: {
        providerId: "tinfoil",
        enclaveModel: "gemma4-31b",
      },
      search_atlas_hybrid_kb: {
        topic: "tinfoil_enclave",
        inputHandle: "$RESULT_1",
        category: "provider",
      },
      invoke_attested_enclave: {
        inputHandle: "$RESULT_1",
        enclaveModel: "kimi-k3",
        taskKind: "review",
      },
      anchor_arc_settlement_with_human_gate: {
        actionKind: "anchor_receipt",
        resultHandle: "$RESULT_3",
        humanApproved: false,
      },
    };
    const invalidToolCallOutOfRange: Record<string, Record<string, unknown>> = {
      scrub_and_symmetry_mask: {
        inputHandle: "$INPUT",
        bucketQuantumBytes: 3000,
      },
      verify_two_hop_enclave_and_quorum: {
        providerId: "tinfoil",
        enclaveModel: "unknown-model",
      },
      search_atlas_hybrid_kb: {
        topic: "tinfoil_enclave",
        inputHandle: "$DOC_1",
      },
      invoke_attested_enclave: {
        inputHandle: "$RESULT_17",
        enclaveModel: "kimi-k3",
      },
      anchor_arc_settlement_with_human_gate: {
        actionKind: "anchor_receipt",
        resultHandle: "$RECEIPT_1",
        humanApproved: false,
      },
    };

    for (const [toolName, validArgs] of Object.entries(validToolCalls)) {
      expect(() =>
        assertGoogleBoundMessage(`toolCall:${toolName}`, validArgs),
      ).not.toThrow();
      expect(() =>
        assertGoogleBoundMessage("toolCall", {
          id: "call-1",
          type: "function_call",
          name: toolName,
          arguments: validArgs,
        }),
      ).not.toThrow();
      // Extra key
      expect(() =>
        assertGoogleBoundMessage(`toolCall:${toolName}`, {
          ...validArgs,
          extraKey: "ok",
        }),
      ).toThrow(ContentFreeEgressError);
      // Missing required key
      expect(() =>
        assertGoogleBoundMessage(`toolCall:${toolName}`, {}),
      ).toThrow(ContentFreeEgressError);
      // Out-of-range value
      expect(() =>
        assertGoogleBoundMessage(
          `toolCall:${toolName}`,
          invalidToolCallOutOfRange[toolName],
        ),
      ).toThrow(ContentFreeEgressError);
    }

    // 5. Schema: toolResult (all 5 tools)
    const validToolResults: Record<string, Record<string, unknown>> = {
      scrub_and_symmetry_mask: {
        status: "ok",
        passed: true,
        outputHandle: "$RESULT_1",
        redactionCount: 4,
        mechanicalRedactionCount: 4,
        attestedRedactionCount: 0,
        bucketBytes: 4096,
        plaintextLeakCount: 0,
        contentHandle: "$DIGEST_1",
      },
      verify_two_hop_enclave_and_quorum: {
        status: "verified",
        passed: true,
        providerId: "tinfoil",
        enclaveModel: "gemma4-31b",
        checksPassed: 7,
        checksTotal: 7,
        routerHandle: "$ROUTER_1",
        enclaveMeasurementHandle: "$MEASUREMENT_1",
      },
      search_atlas_hybrid_kb: {
        status: "ok",
        outputHandle: "$RESULT_2",
        vectorEngine: "app-fallback",
        textEngine: "app-fallback",
        fusionEngine: "app-rrf",
        totalDocs: 16,
        matchingReceiptsCount: 0,
        topDocHandle: "$DOC_1",
      },
      invoke_attested_enclave: {
        status: "completed",
        outputHandle: "$RESULT_3",
        enclaveModel: "gemma4-31b",
        outputTokenEstimate: 128,
        outputDigestHandle: "$DIGEST_2",
        attested: true,
      },
      anchor_arc_settlement_with_human_gate: {
        status: "blocked_pending_human",
        requiresHumanApproval: true,
        humanApproved: false,
        stateChangedOnChain: false,
        receiptHandle: "$RECEIPT_1",
      },
    };
    const invalidToolResultOutOfRange: Record<string, Record<string, unknown>> = {
      scrub_and_symmetry_mask: {
        ...validToolResults.scrub_and_symmetry_mask,
        bucketBytes: 5000, // not power of two
      },
      verify_two_hop_enclave_and_quorum: {
        ...validToolResults.verify_two_hop_enclave_and_quorum,
        checksPassed: 99,
      },
      search_atlas_hybrid_kb: {
        ...validToolResults.search_atlas_hybrid_kb,
        topDocHandle: "$RESULT_2", // wrong handle prefix
      },
      invoke_attested_enclave: {
        ...validToolResults.invoke_attested_enclave,
        outputTokenEstimate: 100, // not power of two
      },
      anchor_arc_settlement_with_human_gate: {
        ...validToolResults.anchor_arc_settlement_with_human_gate,
        receiptHandle: "$RECEIPT_17", // index > 16
      },
    };

    for (const [toolName, validRes] of Object.entries(validToolResults)) {
      expect(() =>
        assertGoogleBoundMessage(`toolResult:${toolName}`, validRes),
      ).not.toThrow();
      expect(() =>
        assertGoogleBoundMessage("toolResult", validRes),
      ).not.toThrow();
      // Extra key
      expect(() =>
        assertGoogleBoundMessage(`toolResult:${toolName}`, {
          ...validRes,
          extraKey: "ok",
        }),
      ).toThrow(ContentFreeEgressError);
      // Missing key
      const firstKey = Object.keys(validRes)[0];
      const { [firstKey]: _omitted, ...resMissingKey } = validRes;
      void _omitted;
      expect(() =>
        assertGoogleBoundMessage(`toolResult:${toolName}`, resMissingKey),
      ).toThrow(ContentFreeEgressError);
      // Out-of-range value
      expect(() =>
        assertGoogleBoundMessage(
          `toolResult:${toolName}`,
          invalidToolResultOutOfRange[toolName],
        ),
      ).toThrow(ContentFreeEgressError);
    }

    // 6. Schema: functionResult
    const validFunctionResult = {
      type: "function_result",
      call_id: "call-1-1",
      name: "scrub_and_symmetry_mask",
      result: canonicalJson(validToolResults.scrub_and_symmetry_mask),
    };
    expect(() =>
      assertGoogleBoundMessage("functionResult", validFunctionResult),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("functionResult", {
        ...validFunctionResult,
        extraKey: "ok",
      }),
    ).toThrow(ContentFreeEgressError);
    const { call_id: _omitCallId, ...fnResultMissingKey } = validFunctionResult;
    void _omitCallId;
    expect(() =>
      assertGoogleBoundMessage("functionResult", fnResultMissingKey),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertGoogleBoundMessage("functionResult", {
        ...validFunctionResult,
        call_id: "call-99", // > 16
      }),
    ).toThrow(ContentFreeEgressError);

    // 7. Schema: followUpRequest
    const validFollowUpRequest = {
      model: GEMINI_4_ARGON_MODEL_ID,
      background: true,
      store: false,
      previous_interaction_id: "inter-argon-turn-1",
      generation_config: {
        thinking_level: "medium",
        max_output_tokens: 131_072,
      },
      input: [validFunctionResult],
      tools: ARGON_CONFIDENTIAL_TOOLS,
    };
    expect(() =>
      assertGoogleBoundMessage("followUpRequest", validFollowUpRequest),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("followUpRequest", {
        ...validFollowUpRequest,
        extraKey: "ok",
      }),
    ).toThrow(ContentFreeEgressError);
    const {
      previous_interaction_id: _omitPrevId,
      ...followUpMissingKey
    } = validFollowUpRequest;
    void _omitPrevId;
    expect(() =>
      assertGoogleBoundMessage("followUpRequest", followUpMissingKey),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertGoogleBoundMessage("followUpRequest", {
        ...validFollowUpRequest,
        previous_interaction_id: "inter-argon-turn-17", // > 16
      }),
    ).toThrow(ContentFreeEgressError);
  });

  // Round 4 MINOR-1, MINOR-2, MINOR-3 verification tests
  it("enforces Round 4 MINOR-1, MINOR-2, and MINOR-3 (allowedTools subset in assertValidToolCall and tool schemas, raw args validation for undefined keys, and coarse redaction/scrub buckets + sum invariant)", () => {
    // MINOR-1: assertValidToolCall enforces taskDescriptor.allowedTools subset
    const subsetTools = [
      "scrub_and_symmetry_mask",
      "invoke_attested_enclave",
    ] as const;
    expect(() =>
      assertValidToolCall(
        "scrub_and_symmetry_mask",
        { inputHandle: "$INPUT", bucketQuantumBytes: 4096 },
        subsetTools,
      ),
    ).not.toThrow();
    expect(() =>
      assertValidToolCall(
        "search_atlas_hybrid_kb",
        { topic: "tinfoil_enclave" },
        subsetTools,
      ),
    ).toThrow(ToolPolicyViolationError);

    // MINOR-1: createRequest and interactionsPayload accept any non-empty canonical subset of the 5 tools
    const subsetDescriptor = buildTaskDescriptor({
      taskKind: "review",
      inputTokenEstimate: 1024,
      redactionCounts: { SECRET: 1, TOTAL: 2 },
      verification: { mechanicalRedactionPassed: true },
      allowedTools: subsetTools,
    });
    const subsetToolDecls = ARGON_CONFIDENTIAL_TOOLS.filter((t) =>
      (subsetTools as readonly string[]).includes(t.name),
    );
    const fullPayload = buildInteractionsCreatePayload({
      taskDescriptor: subsetDescriptor,
      thinkingLevel: "medium",
      background: true,
      maxOutputTokens: 131_072,
    });
    expect(() =>
      assertGoogleBoundMessage("interactionsPayload", {
        ...fullPayload,
        tools: subsetToolDecls,
      }),
    ).not.toThrow();
    expect(() =>
      assertGoogleBoundMessage("createRequest", {
        model: GEMINI_4_ARGON_MODEL_ID,
        background: true,
        store: false,
        system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
        generation_config: {
          thinking_level: "medium",
          max_output_tokens: 131_072,
        },
        input: [{ type: "text", text: canonicalJson(subsetDescriptor) }],
        tools: subsetToolDecls,
      }),
    ).not.toThrow();
    // Non-canonical order or empty tools array is still rejected
    expect(() =>
      assertGoogleBoundMessage("createRequest", {
        model: GEMINI_4_ARGON_MODEL_ID,
        background: true,
        store: false,
        system_instruction: SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
        generation_config: {
          thinking_level: "medium",
          max_output_tokens: 131_072,
        },
        input: [{ type: "text", text: canonicalJson(subsetDescriptor) }],
        tools: [...subsetToolDecls].reverse(),
      }),
    ).toThrow(ContentFreeEgressError);

    // MINOR-2: validateToolCallArguments and assertValidToolCall validate raw args and reject undefined-valued keys
    const undefOptRes = validateToolCallArguments("search_atlas_hybrid_kb", {
      topic: "tinfoil_enclave",
      inputHandle: undefined,
    });
    expect(undefOptRes.valid).toBe(false);
    expect(() =>
      assertValidToolCall("search_atlas_hybrid_kb", {
        topic: "tinfoil_enclave",
        inputHandle: undefined,
      }),
    ).toThrow(ToolPolicyViolationError);

    // MINOR-3: TaskDescriptor.redactionCounts coarse buckets {0, 1, 2} (2 means "2 or more")
    expect(subsetDescriptor.redactionCounts.TOTAL).toBe(2);
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", {
        ...subsetDescriptor,
        redactionCounts: { SECRET: 1, TOTAL: 3 }, // > 2 rejected
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ TOTAL: 3 })).toThrow(
      ContentFreeEgressError,
    );

    // MINOR-3: scrub_and_symmetry_mask toolResult power-of-two buckets {0, 1, 2, 4, 8, 16, 32, 64} and sum invariant
    expect(() =>
      assertGoogleBoundMessage("toolResult:scrub_and_symmetry_mask", {
        status: "ok",
        passed: true,
        outputHandle: "$RESULT_1",
        redactionCount: 4,
        mechanicalRedactionCount: 4,
        attestedRedactionCount: 0,
        bucketBytes: 4096,
        plaintextLeakCount: 0,
        contentHandle: "$DIGEST_1",
      }),
    ).not.toThrow();
    // Non-power-of-two count (e.g. 3) is rejected
    expect(() =>
      assertGoogleBoundMessage("toolResult:scrub_and_symmetry_mask", {
        status: "ok",
        passed: true,
        outputHandle: "$RESULT_1",
        redactionCount: 3,
        mechanicalRedactionCount: 3,
        attestedRedactionCount: 0,
        bucketBytes: 4096,
        plaintextLeakCount: 0,
        contentHandle: "$DIGEST_1",
      }),
    ).toThrow(ContentFreeEgressError);
    expect(() => assertContentFree({ redactionCount: 3 })).toThrow(
      ContentFreeEgressError,
    );
    // Sum mismatch (redactionCount !== min(64, mechanicalRedactionCount + attestedRedactionCount)) is rejected
    expect(() =>
      assertGoogleBoundMessage("toolResult:scrub_and_symmetry_mask", {
        status: "ok",
        passed: true,
        outputHandle: "$RESULT_1",
        redactionCount: 8,
        mechanicalRedactionCount: 4,
        attestedRedactionCount: 0,
        bucketBytes: 4096,
        plaintextLeakCount: 0,
        contentHandle: "$DIGEST_1",
      }),
    ).toThrow(ContentFreeEgressError);
  });
});
