import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST as postRelayHopAttest } from "@/app/api/relay/[relayId]/attestation/route";
import { POST as postRelayHop } from "@/app/api/relay/[relayId]/v1/[...path]/route";
import { POST as postRelayAttest } from "@/app/api/relay/attestation/route";
import { POST as postRelay } from "@/app/api/relay/v1/[...path]/route";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import {
  isAllowedEnclave,
  resolveRelayUpstreamUrl,
  TINFOIL_PII_FILTER_HOST,
  validateRelayPath,
} from "@/lib/relay";

describe("Oblivious Relay Routing for pii-filter.tinfoil.sh and Standard Enclaves", () => {
  const prevApiKey = process.env.TINFOIL_API_KEY;
  const prevStub = process.env.DROUTER_STUB_UPSTREAM;

  beforeEach(() => {
    resetRateLimitStateForTests();
    process.env.TINFOIL_API_KEY = "test-operator-key";
    delete process.env.DROUTER_STUB_UPSTREAM;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (prevApiKey === undefined) {
      delete process.env.TINFOIL_API_KEY;
    } else {
      process.env.TINFOIL_API_KEY = prevApiKey;
    }
    if (prevStub === undefined) {
      delete process.env.DROUTER_STUB_UPSTREAM;
    } else {
      process.env.DROUTER_STUB_UPSTREAM = prevStub;
    }
  });

  it("validates redact path and resolves pii-filter.tinfoil.sh to https://pii-filter.tinfoil.sh/redact while keeping router/model enclaves on /v1/*", () => {
    expect(TINFOIL_PII_FILTER_HOST).toBe("pii-filter.tinfoil.sh");
    expect(isAllowedEnclave("https://pii-filter.tinfoil.sh")).toBe(true);
    expect(validateRelayPath(["redact"])).toBe("redact");
    expect(validateRelayPath(["chat", "completions"])).toBe("chat/completions");

    const piiUrl = new URL("https://pii-filter.tinfoil.sh");
    expect(resolveRelayUpstreamUrl(piiUrl, "redact")).toBe(
      "https://pii-filter.tinfoil.sh/redact",
    );
    expect(resolveRelayUpstreamUrl(piiUrl, "chat/completions")).toBe(
      "https://pii-filter.tinfoil.sh/redact",
    );
    expect(resolveRelayUpstreamUrl(piiUrl, "models")).toBeNull();
    expect(resolveRelayUpstreamUrl(piiUrl, "embeddings")).toBeNull();

    const routerUrl = new URL("https://inference.tinfoil.sh");
    expect(resolveRelayUpstreamUrl(routerUrl, "chat/completions")).toBe(
      "https://inference.tinfoil.sh/v1/chat/completions",
    );
    expect(resolveRelayUpstreamUrl(routerUrl, "embeddings")).toBe(
      "https://inference.tinfoil.sh/v1/embeddings",
    );
    expect(resolveRelayUpstreamUrl(routerUrl, "redact")).toBeNull();
  });

  it("forwards encrypted pii-filter requests through /api/relay/v1/redact and /api/relay/[relayId]/v1/redact to https://pii-filter.tinfoil.sh/redact without reading plaintext", async () => {
    const capturedUpstream: Array<{
      url: string;
      headers: Headers;
      bodyBytes: Uint8Array;
    }> = [];

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const headers = new Headers(init?.headers);
        const rawBody = init?.body as unknown as Uint8Array;
        capturedUpstream.push({
          url,
          headers,
          bodyBytes:
            rawBody instanceof Uint8Array
              ? rawBody
              : new Uint8Array(await new Response(init?.body).arrayBuffer()),
        });
        return new Response(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), {
          status: 200,
          headers: {
            "content-type": "application/octet-stream",
            "ehbp-response-nonce": "11".repeat(16),
          },
        });
      }),
    );

    const hpkeCiphertext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const req1 = new Request("http://localhost:3000/api/relay/v1/redact", {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "x-tinfoil-enclave-url": "https://pii-filter.tinfoil.sh",
        "x-tinfoil-model": "pii-filter",
        "ehbp-encapsulated-key": "aa".repeat(32),
      },
      body: hpkeCiphertext,
    });
    const res1 = await postRelay(req1, {
      params: Promise.resolve({ path: ["redact"] }),
    });
    expect(res1.status).toBe(200);
    expect(res1.headers.get("ehbp-response-nonce")).toBe("11".repeat(16));
    expect(new Uint8Array(await res1.arrayBuffer())).toEqual(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );

    const req2 = new Request(
      "http://localhost:3000/api/relay/relay-eu-zurich/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-tinfoil-enclave-url": "https://pii-filter.tinfoil.sh",
          "x-tinfoil-model": "pii-filter",
          "ehbp-encapsulated-key": "bb".repeat(32),
        },
        body: hpkeCiphertext,
      },
    );
    const res2 = await postRelayHop(req2, {
      params: Promise.resolve({
        relayId: "relay-eu-zurich",
        path: ["chat", "completions"],
      }),
    });
    expect(res2.status).toBe(200);
    expect(res2.headers.get("x-drouter-relay-hop")).toBe("relay-eu-zurich");

    expect(capturedUpstream).toHaveLength(2);
    expect(capturedUpstream[0].url).toBe("https://pii-filter.tinfoil.sh/redact");
    expect(capturedUpstream[0].headers.get("authorization")).toBe(
      "Bearer test-operator-key",
    );
    expect(capturedUpstream[0].headers.get("ehbp-encapsulated-key")).toBe(
      "aa".repeat(32),
    );
    expect(capturedUpstream[0].bodyBytes).toEqual(hpkeCiphertext);

    expect(capturedUpstream[1].url).toBe("https://pii-filter.tinfoil.sh/redact");
    expect(capturedUpstream[1].headers.get("ehbp-encapsulated-key")).toBe(
      "bb".repeat(32),
    );
  });

  it("rejects mismatched enclave/path pairs and arbitrary non-Tinfoil hosts", async () => {
    // 1. /redact is rejected for non-pii-filter enclaves
    const badRedactHostReq = new Request(
      "http://localhost:3000/api/relay/v1/redact",
      {
        method: "POST",
        headers: {
          "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
          "ehbp-encapsulated-key": "aa".repeat(32),
        },
        body: "ciphertext",
      },
    );
    const res1 = await postRelay(badRedactHostReq, {
      params: Promise.resolve({ path: ["redact"] }),
    });
    expect(res1.status).toBe(400);

    // 2. /embeddings is rejected for pii-filter.tinfoil.sh
    const badPiiPathReq = new Request(
      "http://localhost:3000/api/relay/v1/embeddings",
      {
        method: "POST",
        headers: {
          "x-tinfoil-enclave-url": "https://pii-filter.tinfoil.sh",
          "ehbp-encapsulated-key": "aa".repeat(32),
        },
        body: "ciphertext",
      },
    );
    const res2 = await postRelay(badPiiPathReq, {
      params: Promise.resolve({ path: ["embeddings"] }),
    });
    expect(res2.status).toBe(400);

    // 3. Arbitrary host is rejected
    const arbitraryHostReq = new Request(
      "http://localhost:3000/api/relay/v1/redact",
      {
        method: "POST",
        headers: {
          "x-tinfoil-enclave-url": "https://evil.example.com",
          "ehbp-encapsulated-key": "aa".repeat(32),
        },
        body: "ciphertext",
      },
    );
    const res3 = await postRelay(arbitraryHostReq, {
      params: Promise.resolve({ path: ["redact"] }),
    });
    expect(res3.status).toBe(400);
  });

  it("relays attestation bundle POST for pii-filter.tinfoil.sh and tinfoilsh/confidential-pii-cpu", async () => {
    let upstreamUrl = "";
    let upstreamBody = "";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        upstreamUrl = String(input);
        upstreamBody = typeof init?.body === "string" ? init.body : "";
        return new Response(
          JSON.stringify({ domain: "pii-filter.tinfoil.sh" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const attReq = new Request("http://localhost:3000/api/relay/attestation", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        enclaveUrl: "https://pii-filter.tinfoil.sh",
        repo: "tinfoilsh/confidential-pii-cpu",
      }),
    });
    const attRes = await postRelayAttest(attReq);
    expect(attRes.status).toBe(200);
    expect(upstreamUrl).toBe("https://atc.tinfoil.sh/attestation");
    expect(JSON.parse(upstreamBody)).toEqual({
      enclaveUrl: "https://pii-filter.tinfoil.sh",
      repo: "tinfoilsh/confidential-pii-cpu",
    });

    const hopAttReq = new Request(
      "http://localhost:3000/api/relay/relay-us-virginia/attestation",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enclaveUrl: "https://pii-filter.tinfoil.sh",
          repo: "tinfoilsh/confidential-pii-cpu",
        }),
      },
    );
    const hopAttRes = await postRelayHopAttest(hopAttReq, {
      params: Promise.resolve({ relayId: "relay-us-virginia" }),
    });
    expect(hopAttRes.status).toBe(200);
    expect(hopAttRes.headers.get("x-drouter-relay-hop")).toBe(
      "relay-us-virginia",
    );
  });

  it("exercises the full browser-to-relay attestedPiiFilter flow end-to-end against POST /api/relay/v1/[...path] with mocked upstream https://pii-filter.tinfoil.sh/redact", async () => {
    const {
      attestedPiiFilter,
      clearAttestedPiiFilterCacheForTests,
      setAttestedPiiSecureClientFactoryForTests,
    } = await import("@/lib/privacy/attested-filter");

    clearAttestedPiiFilterCacheForTests();
    const upstreamCalls: Array<{
      url: string;
      headers: Headers;
      bodyText: string;
    }> = [];

    // Mock global fetch so POST /api/relay/v1/... forwards to our mocked upstream enclave
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const headers = new Headers(init?.headers);
        const rawBody = init?.body as unknown as Uint8Array;
        const bodyBytes =
          rawBody instanceof Uint8Array
            ? rawBody
            : new Uint8Array(await new Response(init?.body).arrayBuffer());
        upstreamCalls.push({
          url,
          headers,
          bodyText: new TextDecoder().decode(bodyBytes),
        });
        return new Response(
          JSON.stringify({
            redacted_text: "Discuss trial with <PRIVATE_PERSON>.",
            summary: { span_count: 1 },
            detected_spans: [
              {
                label: "private_person",
                start: 19,
                end: 29,
                text: "Cousin Leo",
                placeholder: "<PRIVATE_PERSON>",
              },
            ],
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "ehbp-response-nonce": "22".repeat(16),
            },
          },
        );
      }),
    );

    try {
      setAttestedPiiSecureClientFactoryForTests((opts) => {
        const baseURL = String(opts.baseURL);
        const enclaveURL = String(opts.enclaveURL);
        const mockTransport = {
          fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
            const targetUrl = new URL(String(input), baseURL);
            const pathSegs = targetUrl.pathname
              .replace(/^\/api\/relay\/v1\//, "")
              .split("/")
              .filter(Boolean);
            const reqHeaders = new Headers(init?.headers);
            reqHeaders.set("x-tinfoil-enclave-url", enclaveURL);
            reqHeaders.set("ehbp-encapsulated-key", "33".repeat(32));
            const relayReq = new Request(targetUrl.toString(), {
              method: init?.method ?? "POST",
              headers: reqHeaders,
              body: init?.body,
            });
            return postRelay(relayReq, {
              params: Promise.resolve({ path: pathSegs }),
            });
          },
        };
        const clientObj = {
          _transport: mockTransport,
          ready: async () => {},
          getVerificationDocument: () => ({
            securityVerified: true,
            enclaveHost: "pii-filter.tinfoil.sh",
          }),
          fetch: (input: RequestInfo | URL, init?: RequestInit) =>
            clientObj._transport.fetch(input, init),
        };
        return clientObj;
      });

      const res = await attestedPiiFilter("Discuss trial with Cousin Leo.", {
        useRelay: true,
        relayOrigin: "https://drouter.example",
        includeSpans: true,
      });

      expect(res.verified).toBe(true);
      expect(res.redactionCount).toBe(1);
      expect(res.text).toBe("Discuss trial with <PRIVATE_PERSON>.");
      expect(upstreamCalls).toHaveLength(1);
      expect(upstreamCalls[0].url).toBe("https://pii-filter.tinfoil.sh/redact");
      expect(upstreamCalls[0].headers.get("authorization")).toBe(
        "Bearer test-operator-key",
      );
      expect(upstreamCalls[0].headers.get("x-tinfoil-model")).toBe("pii-filter");
      expect(new TextEncoder().encode(upstreamCalls[0].bodyText).byteLength).toBe(
        4096,
      );
      expect(JSON.parse(upstreamCalls[0].bodyText)).toEqual({
        text: "Discuss trial with Cousin Leo.",
      });
    } finally {
      setAttestedPiiSecureClientFactoryForTests(null);
      clearAttestedPiiFilterCacheForTests();
    }
  });
});
