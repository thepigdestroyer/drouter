import { TinfoilAI } from "tinfoil";
import { verifyAndSpendCreditHeader } from "@/lib/credits/ledger";
import {
  fetchLiveGatewayModels,
  parseGatewayChatRequest,
} from "@/lib/gateway/harness-config";
import { createSessionScrubber, type SessionScrubber } from "@/lib/privacy/scrubber";
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
    "X-DRouter-Attested, X-DRouter-Node, X-DRouter-Enclave-Host, X-DRouter-Release, X-DRouter-Code-Fingerprint, X-DRouter-Enclave-Fingerprint, X-DRouter-Redactions, X-DRouter-Credit-Verified, X-DRouter-Credit-Nullifier, X-DRouter-Credit-Denomination",
};

function createChunkRestorer(scrubber: SessionScrubber | null) {
  let pending = "";
  return {
    push(chunkText: string): string {
      if (!scrubber) return chunkText;
      pending += chunkText;
      const openIdx = pending.lastIndexOf("[");
      const closeIdx = pending.lastIndexOf("]");
      if (openIdx !== -1 && openIdx > closeIdx && pending.length - openIdx < 24) {
        const ready = pending.slice(0, openIdx);
        pending = pending.slice(openIdx);
        return scrubber.restore(ready);
      }
      const out = scrubber.restore(pending);
      pending = "";
      return out;
    },
    flush(): string {
      if (!pending) return "";
      const out = scrubber ? scrubber.restore(pending) : pending;
      pending = "";
      return out;
    },
  };
}

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

  let parsed = parseGatewayChatRequest(rawBody);
  if (!parsed.ok && parsed.error.startsWith("Unsupported model")) {
    const liveModels = await fetchLiveGatewayModels();
    parsed = parseGatewayChatRequest(rawBody, {
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

  // Interface I2: Verify blind-signed credit header (`x-drouter-credit` or `x-drouter-credit-token`)
  // Requests with a valid credit token record the nullifier and bypass the per-IP free-tier limiter;
  // requests without the header fall back to the per-IP free tier. Global caps always apply.
  const rawCreditHeader =
    req.headers.get("x-drouter-credit") ?? req.headers.get("x-drouter-credit-token");
  const creditResponseHeaders: Record<string, string> = {};

  if (rawCreditHeader !== null && rawCreditHeader.trim() !== "") {
    const creditSpend = await verifyAndSpendCreditHeader(rawCreditHeader, parsed.model);
    if (!creditSpend.ok) {
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
    creditResponseHeaders["X-DRouter-Credit-Verified"] = "true";
    creditResponseHeaders["X-DRouter-Credit-Nullifier"] = creditSpend.nullifier;
    creditResponseHeaders["X-DRouter-Credit-Denomination"] = String(creditSpend.denomination);

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
            ...creditResponseHeaders,
            "Retry-After": String(globalCheck.retryAfterSec),
          },
        },
      );
    }
  } else {
    const limited = realTinfoilIpLimiter.check(req, CORS_HEADERS);
    if (limited) return limited;
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
          headers: { ...CORS_HEADERS, "Retry-After": String(globalCheck.retryAfterSec) },
        },
      );
    }
  }

  // Server-side PII scrubbing is enabled by default unless explicitly disabled via header or body
  const headerScrub = req.headers.get("x-drouter-scrub-pii")?.trim().toLowerCase();
  const bodyRecord = rawBody as Record<string, unknown>;
  const explicitDisableScrub =
    headerScrub === "0" ||
    headerScrub === "false" ||
    bodyRecord.scrubPii === false ||
    bodyRecord.scrub_pii === false;
  const shouldScrub = !explicitDisableScrub;
  const scrubber = shouldScrub ? createSessionScrubber() : null;

  const preparedMessages = parsed.messages.map((m) => {
    const scrubbedContent =
      typeof m.content === "string"
        ? scrubber
          ? scrubber.scrub(m.content).scrubbed
          : m.content
        : m.content;

    const scrubbedToolCalls =
      m.tool_calls && m.tool_calls.length > 0
        ? m.tool_calls.map((tc) => ({
            ...tc,
            function: {
              ...tc.function,
              arguments:
                scrubber && typeof tc.function.arguments === "string"
                  ? scrubber.scrub(tc.function.arguments).scrubbed
                  : tc.function.arguments,
            },
          }))
        : undefined;

    return {
      role: m.role,
      content: scrubbedContent,
      ...(m.name ? { name: m.name } : {}),
      ...(m.tool_call_id ? { tool_call_id: m.tool_call_id } : {}),
      ...(scrubbedToolCalls ? { tool_calls: scrubbedToolCalls } : {}),
    };
  });

  const redactionCount = scrubber ? scrubber.entries().length : 0;

  // Real Tinfoil enclave path
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
      const restorer = createChunkRestorer(scrubber);
      let lastChunkMeta: Record<string, unknown> | null = null;

      const readable = new ReadableStream<Uint8Array>({
        async start(controller) {
          try {
            for await (const rawChunk of upstreamStream) {
              const chunk = structuredClone(rawChunk) as unknown as Record<string, unknown>;
              lastChunkMeta = chunk;
              const choices = Array.isArray(chunk.choices)
                ? (chunk.choices as Array<Record<string, unknown>>)
                : [];
              const firstDelta =
                choices[0]?.delta && typeof choices[0].delta === "object"
                  ? (choices[0].delta as Record<string, unknown>)
                  : null;

              if (firstDelta) {
                if (typeof firstDelta.content === "string" && firstDelta.content.length > 0) {
                  firstDelta.content = restorer.push(firstDelta.content);
                }
                if (scrubber && Array.isArray(firstDelta.tool_calls)) {
                  firstDelta.tool_calls = (
                    firstDelta.tool_calls as Array<Record<string, unknown>>
                  ).map((tc) => {
                    const fn =
                      tc?.function && typeof tc.function === "object"
                        ? (tc.function as Record<string, unknown>)
                        : null;
                    if (fn && typeof fn.arguments === "string") {
                      return {
                        ...tc,
                        function: {
                          ...fn,
                          arguments: scrubber.restore(fn.arguments),
                        },
                      };
                    }
                    return tc;
                  });
                }
              }

              controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
            }

            const tail = restorer.flush();
            if (tail && lastChunkMeta) {
              const flushChunk = {
                ...lastChunkMeta,
                choices: [
                  {
                    index: 0,
                    delta: { content: tail },
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

    const choices = Array.isArray(completion.choices)
      ? completion.choices.map((c) => {
          if (!scrubber || !c?.message) return c;
          const nextMsg = { ...c.message } as Record<string, unknown>;
          if (typeof nextMsg.content === "string") {
            nextMsg.content = scrubber.restore(nextMsg.content);
          }
          if (Array.isArray(nextMsg.tool_calls)) {
            nextMsg.tool_calls = (nextMsg.tool_calls as Array<Record<string, unknown>>).map(
              (tc) => {
                const fn =
                  tc?.function && typeof tc.function === "object"
                    ? (tc.function as Record<string, unknown>)
                    : null;
                if (fn && typeof fn.arguments === "string") {
                  return {
                    ...tc,
                    function: {
                      ...fn,
                      arguments: scrubber.restore(fn.arguments),
                    },
                  };
                }
                return tc;
              },
            );
          }
          return {
            ...c,
            message: nextMsg,
          };
        })
      : completion.choices;

    return Response.json(
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
