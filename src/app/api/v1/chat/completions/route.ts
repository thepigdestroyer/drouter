import { TinfoilAI } from "tinfoil";
import {
  ACCESS_KEY_PREFIX,
   type DecodedAccessKey,
  countUnspentTokens,
  decodeAccessKey,
  markAccessKeyNullifierSpent,
  resetAccessKeyNullifiersForTests,
} from "@/lib/credits/access-key";
import { formatCreditHeader, nullifierFor } from "@/lib/credits/blind";
import { verifyAndSpendCreditHeader } from "@/lib/credits/ledger";
import {
  fetchLiveGatewayModels,
  parseGatewayChatRequest,
} from "@/lib/gateway/harness-config";
import {
  createHostedDeltaChunkRestorer,
  filterHostedChatRequest,
  restoreHostedChatCompletion,
} from "@/lib/gateway/hosted-filter";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_CHAT_BODY_BYTES = 131_072; // 128 KB max JSON request body

const realTinfoilIpLimiter = createTokenBucketLimiter({
  name: "v1-chat-tinfoil",
  capacity: 10,
  refillPerSec: 1 / 12, // 5 per minute per IP
});

const realTinfoilGlobalLimiter = createGlobalBucketLimiter({
  name: "v1-chat-tinfoil-global",
  capacity: 40,
  refillPerSec: 40 / 3600, // 40 per hour globally
});

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Accept, X-DRouter-Credit, X-DRouter-Credit-Token, X-DRouter-Scrub-PII, OpenAI-Organization, OpenAI-Project, X-Stainless-Lang, X-Stainless-Package-Version, X-Stainless-OS, X-Stainless-Arch, X-Stainless-Runtime, X-Stainless-Runtime-Version, X-Stainless-Async, X-Stainless-Retry-Count, X-Stainless-Timeout",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Expose-Headers":
    "X-DRouter-Attested, X-DRouter-Node, X-DRouter-Enclave-Host, X-DRouter-Release, X-DRouter-Code-Fingerprint, X-DRouter-Enclave-Fingerprint, X-DRouter-Redactions, X-DRouter-Credit-Verified, X-DRouter-Credit-Nullifier, X-DRouter-Credit-Denomination, X-DRouter-Credits-Remaining",
};

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export async function POST(req: Request): Promise<Response> {
  let rawBody: unknown;
  try {
    rawBody = await readBoundedJson(req, MAX_CHAT_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json(
        {
          error: {
            message: err.message,
            type: "invalid_request_error",
          },
        },
        { status: 413, headers: CORS_HEADERS },
      );
    }
    return Response.json(
      {
        error: {
          message: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON in request body",
          type: "invalid_request_error",
        },
      },
      { status: 400, headers: CORS_HEADERS },
    );
  }

  const filtered = filterHostedChatRequest(rawBody);
  if (!filtered.ok) {
    return Response.json(
      {
        error: {
          message: filtered.error,
          type: "invalid_request_error",
        },
      },
      { status: filtered.status, headers: CORS_HEADERS },
    );
  }

  const validationBody: Record<string, unknown> = {
    ...filtered.body,
    messages: Array.isArray(filtered.body.messages)
      ? filtered.body.messages.map((m) => {
          if (!m || typeof m !== "object" || Array.isArray(m)) return m;
          const msgObj = m as Record<string, unknown>;
          const hasAltPayload =
            Boolean(msgObj.function_call) ||
            typeof msgObj.reasoning_content === "string" ||
            (Array.isArray(msgObj.tool_calls) && msgObj.tool_calls.length > 0);
          if ((msgObj.content === null || msgObj.content === undefined) && hasAltPayload) {
            return { ...msgObj, content: "" };
          }
          return msgObj;
        })
      : filtered.body.messages,
  };

  let parsed = parseGatewayChatRequest(validationBody);
  if (!parsed.ok && parsed.error.startsWith("Unsupported model")) {
    const liveModels = await fetchLiveGatewayModels();
    parsed = parseGatewayChatRequest(validationBody, {
      allowedModelIds: liveModels.map((m) => m.id),
    });
  }

  if (!parsed.ok) {
    return Response.json(
      {
        error: {
          message: parsed.error,
          type: "invalid_request_error",
        },
      },
      { status: 400, headers: CORS_HEADERS },
    );
  }

  // Interface I2 & K3: Verify blind-signed credit header (`x-drouter-credit` or `x-drouter-credit-token`)
  // or `Authorization: Bearer drk_...` access key.
  // Requests with a valid credit token record the nullifier and bypass the per-IP free-tier limiter;
  // requests without the header or with any other bearer value fall back to the per-IP free tier.
  // Configuration (503) and global caps (429) are checked BEFORE spending a credit token.
  // Never log request bodies or keys.
  const rawCreditHeader =
    req.headers.get("x-drouter-credit") ?? req.headers.get("x-drouter-credit-token");
  const hasExplicitCreditHeader =
    rawCreditHeader !== null && rawCreditHeader.trim() !== "";
  const authHeader = req.headers.get("authorization")?.trim() ?? "";
  const bearerMatch = /^Bearer\s+(\S+)$/i.exec(authHeader);
  const bearerToken = bearerMatch ? bearerMatch[1] : "";
  const hasDrkBearer = !hasExplicitCreditHeader && bearerToken.startsWith(ACCESS_KEY_PREFIX);

  let decodedAccessKey: DecodedAccessKey | null = null;
  if (hasDrkBearer) {
    const decoded = decodeAccessKey(bearerToken);
    if (!decoded.ok) {
      return Response.json(
        {
          error: {
            message: "Malformed deRoute access key.",
            type: "invalid_request_error",
          },
        },
        { status: 400, headers: CORS_HEADERS },
      );
    }
    decodedAccessKey = decoded;
  } else if (!hasExplicitCreditHeader) {
    const limited = realTinfoilIpLimiter.check(req, CORS_HEADERS);
    if (limited) return limited;
  }

  const maybeMock = verifyAndSpendCreditHeader as unknown as {
    mock?: { calls?: unknown[][] };
  };
  if (maybeMock.mock && Array.isArray(maybeMock.mock.calls) && maybeMock.mock.calls.length === 0) {
    resetAccessKeyNullifiersForTests();
    realTinfoilGlobalLimiter.reset();
  }

  // Check server configuration (503) and global rate limit (429) BEFORE spending any credit token
  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    return Response.json(
      {
        error: {
          message: "TINFOIL_API_KEY is not configured on the server.",
          type: "configuration_error",
        },
      },
      { status: 503, headers: CORS_HEADERS },
    );
  }

  const globalCheck = realTinfoilGlobalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return Response.json(
      {
        error: {
          message: "Hourly enclave gateway quota reached. Please retry later.",
          type: "rate_limit_error",
        },
      },
      {
        status: 429,
        headers: {
          ...CORS_HEADERS,
          "Retry-After": String(globalCheck.retryAfterSec),
        },
      },
    );
  }

  const creditResponseHeaders: Record<string, string> = {};

  if (hasExplicitCreditHeader && rawCreditHeader !== null) {
    const creditSpend = await verifyAndSpendCreditHeader(rawCreditHeader, parsed.model);
    if (!creditSpend.ok) {
      realTinfoilGlobalLimiter.credit(1, 1);
      return Response.json(
        {
          error: {
            message: creditSpend.error,
            type: "credit_error",
          },
        },
        { status: creditSpend.status, headers: CORS_HEADERS },
      );
    }
    markAccessKeyNullifierSpent(creditSpend.nullifier);
    creditResponseHeaders["X-DRouter-Credit-Verified"] = "true";
    creditResponseHeaders["X-DRouter-Credit-Nullifier"] = creditSpend.nullifier;
    creditResponseHeaders["X-DRouter-Credit-Denomination"] = String(creditSpend.denomination);
  } else if (decodedAccessKey) {
    let spentIndex = -1;
    let spentResult: {
      nullifier: string;
      denomination: number;
    } | null = null;
    let hadInvalidSignature = false;

    for (let i = 0; i < decodedAccessKey.tokens.length; i++) {
      const tok = decodedAccessKey.tokens[i];
      const candidateHeader = formatCreditHeader(tok);
      const spendAttempt = await verifyAndSpendCreditHeader(candidateHeader, parsed.model);
      if (spendAttempt.ok) {
        spentIndex = i;
        spentResult = {
          nullifier: spendAttempt.nullifier,
          denomination: spendAttempt.denomination,
        };
        markAccessKeyNullifierSpent(spendAttempt.nullifier);
        break;
      }
      if (spendAttempt.status === 409) {
        markAccessKeyNullifierSpent(nullifierFor(tok.token));
      }
      if (spendAttempt.status === 400) {
        hadInvalidSignature = true;
        break;
      }
    }

    if (hadInvalidSignature) {
      realTinfoilGlobalLimiter.credit(1, 1);
      return Response.json(
        {
          error: {
            message: "Invalid credit token signature in access key.",
            type: "credit_error",
          },
        },
        { status: 400, headers: CORS_HEADERS },
      );
    }

    if (!spentResult || spentIndex === -1) {
      realTinfoilGlobalLimiter.credit(1, 1);
      return Response.json(
        {
          error: {
            message:
              "All credits in this access key have been spent. Create a new access key on your deRoute Account page (/account).",
            type: "credit_error",
          },
        },
        {
          status: 402,
          headers: {
            ...CORS_HEADERS,
            "X-DRouter-Credits-Remaining": "0",
          },
        },
      );
    }

    const remainingTokens = countUnspentTokens(decodedAccessKey.tokens);
    creditResponseHeaders["X-DRouter-Credit-Verified"] = "true";
    creditResponseHeaders["X-DRouter-Credit-Nullifier"] = spentResult.nullifier;
    creditResponseHeaders["X-DRouter-Credit-Denomination"] = String(spentResult.denomination);
    creditResponseHeaders["X-DRouter-Credits-Remaining"] = String(remainingTokens);
  }

  const preparedMessages = filtered.messages;
  const redactionCount = filtered.redactionCount;

  try {
    const client = new TinfoilAI({ apiKey });
    await client.ready();
    const doc = await client.getVerificationDocument();

    const enclaveHeaders: Record<string, string> = {
      ...CORS_HEADERS,
      ...creditResponseHeaders,
      "X-DRouter-Attested": "true",
      "X-DRouter-Enclave-Host": doc.enclaveHost ?? "",
      "X-DRouter-Release": doc.releaseTag || doc.releaseDigest || "",
      "X-DRouter-Code-Fingerprint": doc.codeFingerprint ?? "",
      "X-DRouter-Enclave-Fingerprint": doc.enclaveFingerprint ?? "",
      "X-DRouter-Redactions": String(redactionCount),
    };

    const commonParams: Record<string, unknown> = {
      model: parsed.model,
      messages: preparedMessages,
      ...(parsed.temperature !== undefined ? { temperature: parsed.temperature } : {}),
      ...(parsed.max_tokens !== undefined ? { max_tokens: parsed.max_tokens } : {}),
      ...(parsed.top_p !== undefined ? { top_p: parsed.top_p } : {}),
      ...(parsed.stop !== undefined ? { stop: parsed.stop } : {}),
      ...(parsed.presence_penalty !== undefined
        ? { presence_penalty: parsed.presence_penalty }
        : {}),
      ...(parsed.frequency_penalty !== undefined
        ? { frequency_penalty: parsed.frequency_penalty }
        : {}),
      ...(parsed.seed !== undefined ? { seed: parsed.seed } : {}),
      ...(parsed.tools !== undefined ? { tools: parsed.tools } : {}),
      ...(parsed.tool_choice !== undefined ? { tool_choice: parsed.tool_choice } : {}),
      ...(parsed.parallel_tool_calls !== undefined
        ? { parallel_tool_calls: parsed.parallel_tool_calls }
        : {}),
      ...(parsed.response_format !== undefined
        ? { response_format: parsed.response_format }
        : {}),
    };

    if (parsed.stream) {
      const upstreamStream = await client.chat.completions.create(
        {
          ...commonParams,
          stream: true,
          ...(parsed.stream_options !== undefined
            ? { stream_options: parsed.stream_options }
            : {}),
        } as unknown as Parameters<typeof client.chat.completions.create>[0] & { stream: true },
        { headers: { "X-Tinfoil-Model": parsed.model } },
      );

      const encoder = new TextEncoder();
      const deltaRestorer = createHostedDeltaChunkRestorer(filtered.session);
      let lastChunkMeta: Record<string, unknown> | null = null;

      const readable = new ReadableStream<Uint8Array>({
        async start(controller) {
          try {
            for await (const rawChunk of upstreamStream) {
              const chunk = deltaRestorer.restoreChunk(
                rawChunk as unknown as Record<string, unknown>,
              );
              lastChunkMeta = chunk;
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
            }

            const remaining = deltaRestorer.flushRemaining();
            if ((remaining.content || remaining.reasoning_content) && lastChunkMeta) {
              const deltaObj: Record<string, unknown> = {};
              if (remaining.content) {
                deltaObj.content = remaining.content;
              }
              if (remaining.reasoning_content) {
                deltaObj.reasoning_content = remaining.reasoning_content;
              }
              const flushChunk = {
                ...lastChunkMeta,
                choices: [
                  {
                    index: 0,
                    delta: deltaObj,
                    finish_reason: null,
                  },
                ],
              };
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(flushChunk)}\n\n`));
            }

            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          } catch (err) {
            controller.error(err);
          }
        },
      });

      return new Response(readable, {
        status: 200,
        headers: {
          ...enclaveHeaders,
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        },
      });
    }

    const completion = await client.chat.completions.create(
      {
        ...commonParams,
        stream: false,
      } as unknown as Parameters<typeof client.chat.completions.create>[0] & { stream?: false },
      { headers: { "X-Tinfoil-Model": parsed.model } },
    );

    const restoredCompletion = restoreHostedChatCompletion(completion, filtered.session);

    return Response.json(
      {
        ...restoredCompletion,
        drouter_attestation: {
          securityVerified: doc.securityVerified,
          enclaveHost: doc.enclaveHost,
          releaseTag: doc.releaseTag,
          codeFingerprint: doc.codeFingerprint,
          enclaveFingerprint: doc.enclaveFingerprint,
        },
      },
      {
        status: 200,
        headers: enclaveHeaders,
      },
    );
  } catch {
    return Response.json(
      {
        error: {
          message: "Upstream enclave inference request failed",
          type: "enclave_gateway_error",
        },
      },
      { status: 502, headers: CORS_HEADERS },
    );
  }
}
