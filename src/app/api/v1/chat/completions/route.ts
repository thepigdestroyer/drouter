import { TinfoilAI } from "tinfoil";
import { parseGatewayChatRequest } from "@/lib/gateway/harness-config";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import { openSimSession } from "@/lib/sim/client";
import { nodeClose, nodeHello, nodeKeyshare, nodeTurn } from "@/lib/sim/node";
import { simRoots } from "@/lib/sim/roots";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, X-DRouter-Scrub-PII, X-DRouter-Credit-Token",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Expose-Headers":
    "X-DRouter-Attested, X-DRouter-Node, X-DRouter-Enclave-Host, X-DRouter-Release, X-DRouter-Code-Fingerprint, X-DRouter-Enclave-Fingerprint",
};

const inProcessSimFetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(typeof input === "string" ? input : input.toString(), "http://in-process.drouter");
  const parts = url.pathname.split("/").filter(Boolean); // ["api", "sim", ...]
  if (parts[2] === "roots") {
    return Response.json(simRoots());
  }
  const simId = decodeURIComponent(parts[2] ?? "sim-1");
  const action = parts[3];
  const body = init?.body ? JSON.parse(String(init.body)) : {};

  if (action === "hello") {
    return Response.json(nodeHello(simId, body));
  }
  if (action === "keyshare") {
    return Response.json(nodeKeyshare(simId, body));
  }
  if (action === "turn") {
    return Response.json(nodeTurn(simId, body));
  }
  if (action === "close") {
    return Response.json(nodeClose(simId, body));
  }
  return Response.json({ error: "not found" }, { status: 404 });
}) as typeof fetch;

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export async function POST(req: Request): Promise<Response> {
  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return Response.json(
      {
        error: {
          message: "Invalid JSON in request body",
          type: "invalid_request_error",
        },
      },
      { status: 400, headers: CORS_HEADERS },
    );
  }

  const parsed = parseGatewayChatRequest(rawBody);
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

  const headerScrub = req.headers.get("x-drouter-scrub-pii");
  const shouldScrub =
    parsed.scrubPii || headerScrub === "1" || headerScrub?.toLowerCase() === "true";
  const scrubber = shouldScrub ? createSessionScrubber() : null;

  const preparedMessages = parsed.messages.map((m) => ({
    role: m.role,
    content: scrubber ? scrubber.scrub(m.content).scrubbed : m.content,
  }));

  if (parsed.model === "sim-echo-1") {
    if (!process.env.SIM_HARDWARE_SEED) {
      process.env.SIM_HARDWARE_SEED =
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
    }
    const simId = "sim-1";
    const session = await openSimSession("http://in-process.drouter", simId, {
      fetch: inProcessSimFetch,
    });

    const lastUserMsg =
      [...preparedMessages].reverse().find((m) => m.role === "user")?.content ??
      preparedMessages[preparedMessages.length - 1]?.content ??
      "";

    const simHeaders: Record<string, string> = {
      ...CORS_HEADERS,
      "X-DRouter-Attested": "simulated-sev-snp",
      "X-DRouter-Node": simId,
    };

    const completionId = `chatcmpl-sim-${Date.now()}`;
    const created = Math.floor(Date.now() / 1000);

    if (parsed.stream) {
      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        async start(controller) {
          try {
            for await (const rawChunk of session.send(lastUserMsg)) {
              const content = scrubber ? scrubber.restore(rawChunk) : rawChunk;
              const chunkPayload = {
                id: completionId,
                object: "chat.completion.chunk",
                created,
                model: "sim-echo-1",
                choices: [
                  {
                    index: 0,
                    delta: { content },
                    finish_reason: null,
                  },
                ],
              };
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunkPayload)}\n\n`));
            }

            await session.close();

            const stopPayload = {
              id: completionId,
              object: "chat.completion.chunk",
              created,
              model: "sim-echo-1",
              choices: [
                {
                  index: 0,
                  delta: {},
                  finish_reason: "stop",
                },
              ],
            };
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(stopPayload)}\n\n`));
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          } catch (err) {
            controller.error(err);
          }
        },
      });

      return new Response(stream, {
        status: 200,
        headers: {
          ...simHeaders,
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        },
      });
    }

    let fullText = "";
    for await (const chunk of session.send(lastUserMsg)) {
      fullText += chunk;
    }
    const popReceipt = await session.close();
    const restoredText = scrubber ? scrubber.restore(fullText) : fullText;

    return Response.json(
      {
        id: completionId,
        object: "chat.completion",
        created,
        model: "sim-echo-1",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: restoredText,
            },
            finish_reason: "stop",
          },
        ],
        usage: {
          prompt_tokens: new TextEncoder().encode(lastUserMsg).length,
          completion_tokens: new TextEncoder().encode(restoredText).length,
          total_tokens:
            new TextEncoder().encode(lastUserMsg).length +
            new TextEncoder().encode(restoredText).length,
        },
        drouter_attestation: {
          securityVerified: session.checks.every((c) => c.status !== "fail"),
          enclaveHost: `${simId}.sim.drouter.internal`,
          nodeId: simId,
          checks: session.checks,
          evidence: session.evidence,
          popReceipt,
        },
      },
      {
        status: 200,
        headers: simHeaders,
      },
    );
  }

  // Real Tinfoil enclave path
  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    return Response.json(
      {
        error: {
          message:
            "TINFOIL_API_KEY is not configured on the server. Use model 'sim-echo-1' for simulated enclave testing or configure TINFOIL_API_KEY.",
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
      "X-DRouter-Attested": "true",
      "X-DRouter-Enclave-Host": doc.enclaveHost ?? "",
      "X-DRouter-Release": doc.releaseTag || doc.releaseDigest || "",
      "X-DRouter-Code-Fingerprint": doc.codeFingerprint ?? "",
      "X-DRouter-Enclave-Fingerprint": doc.enclaveFingerprint ?? "",
      "Access-Control-Expose-Headers":
        "X-DRouter-Attested, X-DRouter-Enclave-Host, X-DRouter-Release, X-DRouter-Code-Fingerprint, X-DRouter-Enclave-Fingerprint",
    };

    if (parsed.stream) {
      const upstreamStream = await client.chat.completions.create({
        model: parsed.model,
        messages: preparedMessages,
        stream: true,
        ...(parsed.temperature !== undefined ? { temperature: parsed.temperature } : {}),
        ...(parsed.max_tokens !== undefined ? { max_tokens: parsed.max_tokens } : {}),
      });

      const encoder = new TextEncoder();
      const readable = new ReadableStream<Uint8Array>({
        async start(controller) {
          try {
            for await (const chunk of upstreamStream) {
              if (scrubber && chunk?.choices?.[0]?.delta?.content) {
                chunk.choices[0].delta.content = scrubber.restore(
                  chunk.choices[0].delta.content,
                );
              }
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
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

    const completion = await client.chat.completions.create({
      model: parsed.model,
      messages: preparedMessages,
      stream: false,
      ...(parsed.temperature !== undefined ? { temperature: parsed.temperature } : {}),
      ...(parsed.max_tokens !== undefined ? { max_tokens: parsed.max_tokens } : {}),
    });

    const choices = Array.isArray(completion.choices)
      ? completion.choices.map((c) => {
          if (scrubber && typeof c?.message?.content === "string") {
            return {
              ...c,
              message: {
                ...c.message,
                content: scrubber.restore(c.message.content),
              },
            };
          }
          return c;
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
  } catch (err) {
    return Response.json(
      {
        error: {
          message: err instanceof Error ? err.message : String(err),
          type: "enclave_gateway_error",
        },
      },
      { status: 502, headers: CORS_HEADERS },
    );
  }
}
