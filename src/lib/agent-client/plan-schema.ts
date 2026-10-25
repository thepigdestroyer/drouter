import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  verifyConfidentialSpaceAttestation,
} from "@/lib/attestation/confidential-space";
import expectedCoreDigestsJson from "@/lib/attestation/expected-core-digests.json";
import {
  assertContentFree,
  assertGoogleBoundMessage,
  assertTaskDescriptorSchema,
} from "@/lib/gemini/egress-schemas";
import {
  ALLOWED_PLANNER_TOOLS,
  ARGON_CONFIDENTIAL_TOOLS,
  CLOSED_CALL_ID_REGEX,
  ContentFreeEgressError,
  GEMINI_4_ARGON_MODEL_ID,
  isPowerOfTwoInRange,
  MAX_PLANNER_STEPS,
  MAX_TOKEN_BUCKET,
  SPLIT_KNOWLEDGE_SYSTEM_INSTRUCTION,
  VALID_TASK_KINDS,
  type ClosedAgentPlan,
  type ClosedPlannerStep,
  type GeminiEgressReceipt,
  type PlannerToolName,
  type TaskDescriptor,
  type TaskKind,
} from "@/lib/gemini/shared";
import {
  canonicalJson,
  createVerificationLogEvent,
  verifyTransparencyProofBundleClient,
  type AuditStep,
} from "@/lib/transparency/log";

export const SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL =
  "Signed by the sealed Google computer (Google Confidential Space egress-signing key)" as const;

export const NEXT_SERVER_RECEIPT_LABEL =
  "Recorded by our server (sha256 appended to transparency log, signed by operator tree-head key)" as const;

const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

export function extractEd25519RawPublicKeyHex(rawKeyHex: string): string {
  const cleaned = String(rawKeyHex ?? "")
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
  if (cleaned.length === 88 && cleaned.startsWith(ED25519_SPKI_PREFIX_HEX)) {
    return cleaned.slice(ED25519_SPKI_PREFIX_HEX.length);
  }
  return cleaned;
}

export const COMMITTED_CORE_IMAGE_DIGESTS: readonly string[] =
  expectedCoreDigestsJson.digests;

export function getExpectedCoreImageDigests(
  override?: readonly string[],
): string[] {
  if (override && override.length > 0) {
    return override.map((d) => d.trim()).filter(Boolean);
  }
  return COMMITTED_CORE_IMAGE_DIGESTS.map((d) => d.trim()).filter(Boolean);
}

export const getExpectedCoreImageDigestsFromEnv = getExpectedCoreImageDigests;

/**
 * Fetches `/api/core/attestation` and verifies the Google Cloud Confidential Space
 * PKI attestation token using `verifyConfidentialSpaceAttestation` and the committed
 * expected container image digests from `src/lib/attestation/expected-core-digests.json`.
 * Returns the hardware-attested Ed25519 `keys.egress` public key in 64-char hex.
 */
export async function verifyCoreAttestationForEgressKey(opts?: {
  fetchFn?: typeof fetch;
  expectedImageDigests?: readonly string[];
  expectedAudience?: string;
  pinnedRootCaPem?: string;
  nowSec?: number;
}): Promise<string> {
  const fetchImpl = opts?.fetchFn ?? globalThis.fetch;
  const expectedImageDigests = getExpectedCoreImageDigests(
    opts?.expectedImageDigests,
  );
  if (expectedImageDigests.length === 0) {
    throw new Error(
      "Missing expected Confidential Space image digests in expected-core-digests.json.",
    );
  }

  const res = await fetchImpl("/api/core/attestation", {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(
      `Failed to fetch /api/core/attestation (HTTP ${res.status}).`,
    );
  }

  const data = (await res.json()) as Record<string, unknown> | null;
  if (!data || typeof data !== "object") {
    throw new Error("Invalid JSON returned by /api/core/attestation.");
  }

  const token = typeof data.token === "string" ? data.token.trim() : "";
  const rawKeys =
    data.keys && typeof data.keys === "object" && !Array.isArray(data.keys)
      ? (data.keys as Record<string, unknown>)
      : null;
  const egressHex = extractEd25519RawPublicKeyHex(String(rawKeys?.egress ?? ""));
  const treeHex = extractEd25519RawPublicKeyHex(String(rawKeys?.tree ?? ""));
  const tlsCertPem =
    typeof data.tlsCertPem === "string" ? data.tlsCertPem : undefined;
  const tlsSpkiSha256 =
    typeof data.tlsSpkiSha256 === "string" ? data.tlsSpkiSha256 : undefined;

  const verification = await verifyConfidentialSpaceAttestation({
    token,
    keys: {
      egress: egressHex,
      tree: treeHex,
    },
    tlsCertificatePemOrDer: tlsCertPem,
    tlsSpkiSha256,
    expectedAudience:
      opts?.expectedAudience ?? DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    expectedImageDigests,
    pinnedRootCaPem: opts?.pinnedRootCaPem,
    nowSec: opts?.nowSec,
  });

  if (!verification.ok || !verification.keys?.egress) {
    const failedIds = verification.checks
      .filter((c) => !c.passed)
      .map((c) => c.id)
      .join(", ");
    throw new Error(
      `Confidential Space attestation verification failed (${failedIds || "unverified"}).`,
    );
  }

  return extractEd25519RawPublicKeyHex(verification.keys.egress);
}

export function sha256HexLower(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text))).toLowerCase();
}

/**
 * Scans a syntactically valid RFC 8259 JSON string and throws `SyntaxError`
 * if any JSON object contains duplicate keys (including Unicode-escaped equivalents).
 */
export function assertNoDuplicateJsonKeys(jsonText: string): void {
  const stack: Array<{ type: "object"; keys: Set<string> } | { type: "array" }> = [];
  let i = 0;
  const len = jsonText.length;

  while (i < len) {
    const ch = jsonText[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    if (ch === "{") {
      stack.push({ type: "object", keys: new Set<string>() });
      i += 1;
      continue;
    }
    if (ch === "[") {
      stack.push({ type: "array" });
      i += 1;
      continue;
    }
    if (ch === "}" || ch === "]") {
      stack.pop();
      i += 1;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i += 1;
      while (i < len) {
        const c = jsonText[i];
        if (c === "\\") {
          i += 2;
          continue;
        }
        if (c === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      const rawStringLiteral = jsonText.slice(start, i);
      let j = i;
      while (
        j < len &&
        (jsonText[j] === " " ||
          jsonText[j] === "\t" ||
          jsonText[j] === "\n" ||
          jsonText[j] === "\r")
      ) {
        j += 1;
      }
      const top = stack[stack.length - 1];
      if (top && top.type === "object" && jsonText[j] === ":") {
        const decodedKey = String(JSON.parse(rawStringLiteral));
        if (top.keys.has(decodedKey)) {
          throw new SyntaxError(`Duplicate JSON object key: ${decodedKey}`);
        }
        top.keys.add(decodedKey);
      }
      continue;
    }
    i += 1;
  }
}

function assertStrictPlainObject(
  value: unknown,
  path: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.prototype.toString.call(value) !== "[object Object]"
  ) {
    throw new ContentFreeEgressError(String(value), path);
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new ContentFreeEgressError("<non_plain_prototype>", path);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new ContentFreeEgressError("<symbol_property>", path);
  }
  const rec = value as Record<string, unknown>;
  if (typeof rec.toJSON === "function") {
    throw new ContentFreeEgressError("<custom_toJSON>", path);
  }
  const ownKeys = Object.getOwnPropertyNames(rec);
  if (ownKeys.length === 0) {
    throw new ContentFreeEgressError("<empty_object>", path);
  }
  for (const k of ownKeys) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
    const desc = Object.getOwnPropertyDescriptor(rec, k);
    if (!desc || !("value" in desc) || desc.enumerable !== true) {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
    if (desc.value === undefined) {
      throw new ContentFreeEgressError("undefined", `${path}.${k}`);
    }
  }
  return rec;
}

function assertExactKeys(
  obj: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  path: string,
): void {
  const allowed = new Set<string>([...requiredKeys, ...optionalKeys]);
  const ownKeys = Object.getOwnPropertyNames(obj);
  for (const k of ownKeys) {
    if (!allowed.has(k)) {
      throw new ContentFreeEgressError(k, `${path}.${k}`);
    }
  }
  for (const req of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(obj, req)) {
      throw new ContentFreeEgressError(`<missing:${req}>`, `${path}.${req}`);
    }
  }
}

/**
 * Validates `descriptor` against `assertGoogleBoundMessage("taskDescriptor")` and `assertContentFree`,
 * then builds the exact closed-schema `createRequest` for Google Gemini (`client.interactions.create`).
 */
export function buildGeminiCreateRequestFromDescriptor(descriptor: unknown): {
  validatedDescriptor: TaskDescriptor;
  createRequest: Record<string, unknown>;
  canonicalRequest: string;
  requestSha256: string;
} {
  assertGoogleBoundMessage("taskDescriptor", descriptor, "$.taskDescriptor");
  assertContentFree(descriptor, "$.taskDescriptor");
  const validatedDescriptor = assertTaskDescriptorSchema(
    descriptor,
    "$.taskDescriptor",
  );

  const tools = ARGON_CONFIDENTIAL_TOOLS.filter((t) =>
    validatedDescriptor.allowedTools.includes(t.name),
  );

  const createRequest: Record<string, unknown> = {
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
        text: canonicalJson(validatedDescriptor),
      },
    ],
    tools,
  };

  assertGoogleBoundMessage("createRequest", createRequest, "$.createRequest");
  assertContentFree(createRequest, "$.createRequest");

  const canonicalRequest = canonicalJson(createRequest);
  const requestSha256 = sha256HexLower(canonicalRequest);

  return {
    validatedDescriptor,
    createRequest,
    canonicalRequest,
    requestSha256,
  };
}

/**
 * Closed-schema validator for the plan returned by `POST /api/gemini/plan` or `/api/core/agent/plan`.
 * Rejects extra keys, missing keys, unknown tools, or invalid tool call arguments.
 */
export function assertClosedPlanSchema(
  plan: unknown,
  allowedToolsSubset: readonly string[] = ALLOWED_PLANNER_TOOLS,
  path = "$.plan",
): ClosedAgentPlan {
  const obj = assertStrictPlainObject(plan, path);
  assertExactKeys(
    obj,
    [
      "taskKind",
      "inputHandle",
      "inputTokenEstimate",
      "steps",
      "toolCalls",
      "summary",
    ],
    [],
    path,
  );

  if (
    typeof obj.taskKind !== "string" ||
    !(VALID_TASK_KINDS as readonly string[]).includes(obj.taskKind)
  ) {
    throw new ContentFreeEgressError(String(obj.taskKind), `${path}.taskKind`);
  }

  if (obj.inputHandle !== "$INPUT") {
    throw new ContentFreeEgressError(
      String(obj.inputHandle),
      `${path}.inputHandle`,
    );
  }

  if (!isPowerOfTwoInRange(obj.inputTokenEstimate, 1, MAX_TOKEN_BUCKET)) {
    throw new ContentFreeEgressError(
      String(obj.inputTokenEstimate),
      `${path}.inputTokenEstimate`,
    );
  }

  if (
    !Array.isArray(obj.steps) ||
    obj.steps.length === 0 ||
    obj.steps.length > MAX_PLANNER_STEPS ||
    !Array.isArray(obj.toolCalls) ||
    obj.toolCalls.length !== obj.steps.length
  ) {
    throw new ContentFreeEgressError("<invalid_steps_or_toolCalls>", path);
  }

  if (
    typeof obj.summary !== "string" ||
    obj.summary.trim().length === 0 ||
    obj.summary.length > 512 ||
    /[\u0000-\u001f\u007f\u2013\u2014]/.test(obj.summary)
  ) {
    throw new ContentFreeEgressError(String(obj.summary), `${path}.summary`);
  }

  const validatedSteps: ClosedPlannerStep[] = [];
  const validatedToolCalls: ClosedAgentPlan["toolCalls"] = [];

  for (let idx = 0; idx < obj.steps.length; idx++) {
    const stepObj = assertStrictPlainObject(
      obj.steps[idx],
      `${path}.steps[${idx}]`,
    );
    assertExactKeys(
      stepObj,
      ["step", "id", "tool", "arguments"],
      [],
      `${path}.steps[${idx}]`,
    );

    if (stepObj.step !== idx + 1) {
      throw new ContentFreeEgressError(
        String(stepObj.step),
        `${path}.steps[${idx}].step`,
      );
    }

    if (
      typeof stepObj.id !== "string" ||
      !CLOSED_CALL_ID_REGEX.test(stepObj.id)
    ) {
      throw new ContentFreeEgressError(
        String(stepObj.id),
        `${path}.steps[${idx}].id`,
      );
    }

    const toolName = stepObj.tool;
    if (
      typeof toolName !== "string" ||
      !(ALLOWED_PLANNER_TOOLS as readonly string[]).includes(toolName) ||
      !allowedToolsSubset.includes(toolName)
    ) {
      throw new ContentFreeEgressError(
        String(toolName),
        `${path}.steps[${idx}].tool`,
      );
    }

    const stepToolCallShape = {
      id: stepObj.id,
      type: "function_call" as const,
      name: toolName,
      arguments: stepObj.arguments,
    };
    assertGoogleBoundMessage(
      "toolCall",
      stepToolCallShape,
      `${path}.steps[${idx}]`,
    );
    assertContentFree(stepToolCallShape, `${path}.steps[${idx}]`);

    const tcObj = assertStrictPlainObject(
      obj.toolCalls[idx],
      `${path}.toolCalls[${idx}]`,
    );
    assertExactKeys(
      tcObj,
      ["id", "name", "arguments"],
      ["type"],
      `${path}.toolCalls[${idx}]`,
    );
    if (tcObj.id !== stepObj.id || tcObj.name !== toolName) {
      throw new ContentFreeEgressError(
        "<step_toolCall_mismatch>",
        `${path}.toolCalls[${idx}]`,
      );
    }
    const tcShape = {
      id: tcObj.id,
      type: "function_call" as const,
      name: tcObj.name,
      arguments: tcObj.arguments,
    };
    assertGoogleBoundMessage(
      "toolCall",
      tcShape,
      `${path}.toolCalls[${idx}]`,
    );
    assertContentFree(tcShape, `${path}.toolCalls[${idx}]`);

    if (canonicalJson(tcObj.arguments) !== canonicalJson(stepObj.arguments)) {
      throw new ContentFreeEgressError(
        "<step_arguments_mismatch>",
        `${path}.toolCalls[${idx}].arguments`,
      );
    }

    validatedSteps.push({
      step: idx + 1,
      id: stepObj.id,
      tool: toolName as PlannerToolName,
      arguments: stepObj.arguments as Record<string, unknown>,
    });

    validatedToolCalls.push({
      id: stepObj.id,
      name: toolName as PlannerToolName,
      arguments: stepObj.arguments as Record<string, unknown>,
    });
  }

  return {
    taskKind: obj.taskKind as TaskKind,
    inputHandle: "$INPUT",
    inputTokenEstimate: obj.inputTokenEstimate,
    steps: validatedSteps,
    toolCalls: validatedToolCalls,
    summary: obj.summary,
  };
}

/**
 * Canonical signing payload for a sealed Google computer (`deroute-core`) Gemini egress receipt:
 * `canonicalJson({ sha256, epochHourSec, kind: "gemini-egress" })`
 */
export function geminiEgressSigningPayload(params: {
  sha256: string;
  epochHourSec: number;
}): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      sha256: String(params.sha256).toLowerCase(),
      epochHourSec: params.epochHourSec,
      kind: "gemini-egress",
    }),
  );
}

/**
 * Verifies a `GeminiEgressReceipt` (both for `"sealed-google-computer"` and `"next-server"` signers):
 * 1. `canonicalRequest` is canonical JSON and passes `assertGoogleBoundMessage("createRequest")` + `assertContentFree`.
 * 2. `sha256(canonicalRequest) === receipt.sha256`.
 * 3. When `expectedDescriptor` is provided, `receipt.sha256` and `receipt.canonicalRequest` must equal
 *    `buildGeminiCreateRequestFromDescriptor(expectedDescriptor)`.
 * 4. `epochHourSec` is a positive integer divisible by 3600.
 * 5. For `"sealed-google-computer"`, requires `expectedPublicKeyHex` (from a verified `/api/core/attestation`,
 *    never from the receipt itself) and verifies the Ed25519 signature over `geminiEgressSigningPayload`.
 * 6. For `"next-server"`, verifies the operator tree-head Ed25519 signature over `treeHeadSigningPayload`.
 */
export function verifyEgressReceiptClient(
  rawReceipt: unknown,
  expectedPublicKeyHex?: string,
  expectedDescriptor?: unknown,
): {
  ok: boolean;
  detail: string;
  receipt?: GeminiEgressReceipt;
} {
  try {
    if (!rawReceipt || typeof rawReceipt !== "object" || Array.isArray(rawReceipt)) {
      return { ok: false, detail: "Receipt must be a non-null object." };
    }
    const rec = rawReceipt as Record<string, unknown>;
    const canonicalRequest =
      typeof rec.canonicalRequest === "string" ? rec.canonicalRequest : "";
    if (!canonicalRequest) {
      return { ok: false, detail: "Missing canonicalRequest string." };
    }
    const sha256Digest =
      typeof rec.sha256 === "string" ? rec.sha256.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(sha256Digest)) {
      return { ok: false, detail: "Invalid sha256 hex digest." };
    }
    if (rec.kind !== "gemini-egress") {
      return { ok: false, detail: `Invalid receipt kind '${String(rec.kind)}'.` };
    }
    const epochHourSec = rec.epochHourSec;
    if (
      typeof epochHourSec !== "number" ||
      !Number.isInteger(epochHourSec) ||
      epochHourSec <= 0 ||
      epochHourSec % 3600 !== 0
    ) {
      return {
        ok: false,
        detail: "epochHourSec must be a positive integer divisible by 3600.",
      };
    }

    const signer: "sealed-google-computer" | "next-server" =
      rec.signer === "next-server" || rec.keyId === "operator-tree-head"
        ? "next-server"
        : "sealed-google-computer";

    if (signer === "sealed-google-computer" && !expectedPublicKeyHex) {
      return {
        ok: false,
        detail:
          "Sealed-computer receipt requires an attested expectedPublicKeyHex from /api/core/attestation.",
      };
    }

    const pubHex = extractEd25519RawPublicKeyHex(
      signer === "sealed-google-computer"
        ? String(expectedPublicKeyHex ?? "")
        : String(expectedPublicKeyHex ?? rec.publicKey ?? ""),
    );
    const recPubHex = extractEd25519RawPublicKeyHex(String(rec.publicKey ?? ""));
    if (!/^[0-9a-f]{64}$/.test(pubHex) || recPubHex !== pubHex) {
      return { ok: false, detail: "Invalid or mismatched Ed25519 public key." };
    }

    const sigHex = String(rec.signature ?? "")
      .replace(/^0x/i, "")
      .toLowerCase();
    if (!/^[0-9a-f]{128}$/.test(sigHex)) {
      return { ok: false, detail: "Invalid Ed25519 signature hex." };
    }

    const computedSha256 = sha256HexLower(canonicalRequest);
    if (computedSha256 !== sha256Digest) {
      return {
        ok: false,
        detail: "canonicalRequest SHA-256 does not match receipt.sha256.",
      };
    }

    if (expectedDescriptor !== undefined) {
      const expectedReq =
        buildGeminiCreateRequestFromDescriptor(expectedDescriptor);
      if (
        sha256Digest !== expectedReq.requestSha256 ||
        canonicalRequest !== expectedReq.canonicalRequest
      ) {
        return {
          ok: false,
          detail:
            "Receipt sha256 or canonicalRequest does not match the caller's TaskDescriptor.",
        };
      }
    }

    let parsedRequest: unknown;
    try {
      parsedRequest = JSON.parse(canonicalRequest);
    } catch {
      return { ok: false, detail: "canonicalRequest is not valid JSON." };
    }

    if (canonicalJson(parsedRequest) !== canonicalRequest) {
      return {
        ok: false,
        detail: "canonicalRequest is not in canonical JSON form.",
      };
    }

    try {
      assertGoogleBoundMessage(
        "createRequest",
        parsedRequest,
        "$.canonicalRequest",
      );
      assertContentFree(parsedRequest, "$.canonicalRequest");
    } catch (err) {
      return {
        ok: false,
        detail:
          err instanceof Error
            ? err.message
            : "canonicalRequest failed closed schema gate.",
      };
    }

    if (signer === "sealed-google-computer") {
      const payload = geminiEgressSigningPayload({
        sha256: sha256Digest,
        epochHourSec,
      });
      const sigValid = ed25519.verify(
        hexToBytes(sigHex),
        payload,
        hexToBytes(pubHex),
      );
      if (!sigValid) {
        return {
          ok: false,
          detail: "Ed25519 signature verification failed on sealed-computer egress receipt.",
        };
      }
      const normalized: GeminiEgressReceipt = {
        canonicalRequest,
        sha256: sha256Digest,
        epochHourSec,
        kind: "gemini-egress",
        signer: "sealed-google-computer",
        signerLabel:
          typeof rec.signerLabel === "string" && rec.signerLabel.trim()
            ? rec.signerLabel.trim()
            : SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
        signature: sigHex,
        publicKey: pubHex,
        ...(typeof rec.spkiPublicKey === "string"
          ? { spkiPublicKey: rec.spkiPublicKey }
          : {}),
        keyId: "egress-signing",
        ...(rec.transparencyLog && typeof rec.transparencyLog === "object"
          ? {
              transparencyLog:
                rec.transparencyLog as GeminiEgressReceipt["transparencyLog"],
            }
          : {}),
      };
      return {
        ok: true,
        detail:
          "Sealed Google computer egress receipt SHA-256, closed schema, and Ed25519 signature verified.",
        receipt: normalized,
      };
    }

    // signer === "next-server": verify leaf commitment to receipt.sha256, RFC 6962 inclusion proof, and signed tree head
    const tLog =
      rec.transparencyLog && typeof rec.transparencyLog === "object"
        ? (rec.transparencyLog as Record<string, unknown>)
        : null;
    if (
      !tLog ||
      typeof tLog.treeSize !== "number" ||
      typeof tLog.rootHash !== "string" ||
      !/^[0-9a-f]{64}$/i.test(tLog.rootHash) ||
      typeof tLog.leafHash !== "string" ||
      !/^[0-9a-f]{64}$/i.test(tLog.leafHash) ||
      typeof tLog.leafIndex !== "number" ||
      !Array.isArray(tLog.auditPath)
    ) {
      return {
        ok: false,
        detail: "Server-recorded receipt is missing valid transparencyLog inclusion proof metadata.",
      };
    }

    const expectedLeafEvent = createVerificationLogEvent({
      index: tLog.leafIndex,
      kind: "verification_event",
      nodeId: "tinfoil-router",
      nodeKind: "tinfoil",
      ok: true,
      measurement: sha256Digest,
      evidenceHash: sha256Digest,
      timestampSec: epochHourSec,
    });
    const actualLeafHash = tLog.leafHash.toLowerCase();
    if (actualLeafHash !== expectedLeafEvent.leafHash.toLowerCase()) {
      return {
        ok: false,
        detail:
          "Server-recorded receipt leafHash does not commit to receipt.sha256.",
      };
    }

    const auditPath: AuditStep[] = [];
    for (const step of tLog.auditPath) {
      if (
        !step ||
        typeof step !== "object" ||
        ((step as { side?: unknown }).side !== "left" &&
          (step as { side?: unknown }).side !== "right") ||
        typeof (step as { hash?: unknown }).hash !== "string" ||
        !/^[0-9a-f]{64}$/i.test((step as { hash: string }).hash)
      ) {
        return {
          ok: false,
          detail: "Invalid auditPath step in server-recorded receipt.",
        };
      }
      auditPath.push({
        side: (step as { side: "left" | "right" }).side,
        hash: (step as { hash: string }).hash.toLowerCase(),
      });
    }

    const proofVerification = verifyTransparencyProofBundleClient({
      sth: {
        treeSize: tLog.treeSize,
        rootHash: tLog.rootHash.toLowerCase(),
        timestampSec: epochHourSec,
        operatorPublicKey: pubHex,
        signature: sigHex,
      },
      expectedOperatorPublicKey: pubHex,
      inclusionProof: {
        leafHash: actualLeafHash,
        root: tLog.rootHash.toLowerCase(),
        auditPath,
        leafIndex: tLog.leafIndex,
        treeSize: tLog.treeSize,
      },
    });
    if (!proofVerification.ok) {
      return {
        ok: false,
        detail: proofVerification.detail,
      };
    }

    const normalized: GeminiEgressReceipt = {
      canonicalRequest,
      sha256: sha256Digest,
      epochHourSec,
      kind: "gemini-egress",
      signer: "next-server",
      signerLabel:
        typeof rec.signerLabel === "string" && rec.signerLabel.trim()
          ? rec.signerLabel.trim()
          : NEXT_SERVER_RECEIPT_LABEL,
      signature: sigHex,
      publicKey: pubHex,
      keyId: "operator-tree-head",
      transparencyLog: {
        leafIndex: tLog.leafIndex,
        leafHash: actualLeafHash,
        treeSize: tLog.treeSize,
        rootHash: tLog.rootHash.toLowerCase(),
        auditPath,
        operatorPublicKey: pubHex,
        treeHeadSignature: sigHex,
      },
    };
    return {
      ok: true,
      detail:
        "Server-recorded egress receipt SHA-256, closed schema, RFC 6962 leaf inclusion proof, and transparency log tree-head signature verified.",
      receipt: normalized,
    };
  } catch {
    return { ok: false, detail: "Failed to verify Gemini egress receipt." };
  }
}
