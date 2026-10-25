import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "@/lib/transparency/log";
import {
  ALLOWED_PLANNER_TOOLS,
  ARGON_CONFIDENTIAL_TOOLS,
  assertContentFree,
  assertValidToolCall,
  buildInteractionsCreatePayload,
  buildTaskDescriptor,
  callGeminiInteractionsEndpoint,
  ContentFreeEgressError,
  createDigestHandleMapState,
  GEMINI_4_ARGON_MODEL_ID,
  LOOKUP_TOPICS,
  MAX_GOOGLE_BOUND_HEX_LENGTH,
  replaceDigestsWithOpaqueHandles,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  validateToolCallArguments,
  type GenAIInteractionsClientLike,
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
        redactionCount: 3,
        mechanicalRedactionCount: 3,
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
      // Current orchestrator local assertion passes
      expect(() =>
        assertContentFree(rawRes, `$.toolExecutor.result(${toolName})`),
      ).not.toThrow();

      // Google-bound replacement strips all 0x digests and substitutes opaque handles
      const googleSafe = replaceDigestsWithOpaqueHandles(rawRes, digestState);
      expect(JSON.stringify(googleSafe)).not.toMatch(/0x[0-9a-f]{16,}/);
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
});
