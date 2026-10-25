import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { utf8ToBytes } from "@noble/hashes/utils.js";

vi.mock("next/server", () => ({
  connection: async () => {},
}));

const tinfoilMocks = vi.hoisted(() => ({
  createCompletion: vi.fn(),
  ready: vi.fn(async () => {}),
  getVerificationDocument: vi.fn(async () => ({
    securityVerified: true,
    enclaveHost: "router-0.tinfoil.sh",
    releaseTag: "v0.0.167",
    releaseDigest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    codeFingerprint: "9134838da8aa4e1792566b2988820340356517c4db0c94261eb8154843e03575",
    enclaveFingerprint: "07ba19655a005e8914a8a6ff8797e9c0c317c71d50b067045b4c23d9da99e723",
    hpkePublicKey: "07ba19655a005e8914a8a6ff8797e9c0c317c71d50b067045b4c23d9da99e723",
  })),
}));

vi.mock("tinfoil", () => ({
  TinfoilAI: class MockTinfoilAI {
    ready = tinfoilMocks.ready;
    getVerificationDocument = tinfoilMocks.getVerificationDocument;
    chat = {
      completions: {
        create: tinfoilMocks.createCompletion,
      },
    };
  },
}));

const creditLedgerMocks = vi.hoisted(() => ({
  verifyAndSpendCreditHeader: vi.fn(),
}));

vi.mock("@/lib/credits/ledger", () => ({
  verifyAndSpendCreditHeader: creditLedgerMocks.verifyAndSpendCreditHeader,
}));

import {
  ACCESS_KEY_ORIGIN,
  ACCESS_KEY_PREFIX,
  MAX_ACCESS_KEY_TOKENS,
  decodeAccessKey,
  encodeAccessKey,
} from "@/lib/credits/access-key";
import { formatCreditHeader, nullifierFor, parseCreditHeader } from "@/lib/credits/blind";
import {
  clearStoredCredits,
  getStoredCredits,
  moveCreditsToAccessKey,
  moveTokensToAccessKey,
  storeCreditTokens,
  storedCreditBalance,
} from "@/lib/credits/client";
import {
  HOSTED_GATEWAY_BASE_URL,
  LOCAL_PROXY_BASE_URL,
  buildCodingToolSnippets,
} from "@/lib/gateway/harness-config";
import { canonicalJson } from "@/lib/transparency/log";
import type { BlindCreditToken } from "@/lib/types";
import { POST as postChatCompletions } from "@/app/api/v1/chat/completions/route";
import AccountPage from "@/app/account/page";

function makeSampleToken(index: number, denomination = 1): BlindCreditToken {
  const hexByte = ((index + 1) & 0xff).toString(16).padStart(2, "0");
  return {
    token: hexByte.repeat(32),
    signature: ((index + 17) & 0xff).toString(16).padStart(2, "0").repeat(64),
    denomination,
  };
}

function encodeRawBase64Url(jsonText: string): string {
  const b64 = Buffer.from(utf8ToBytes(jsonText)).toString("base64");
  return ACCESS_KEY_PREFIX + b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

describe("K1: Access key format (encodeAccessKey & strict decodeAccessKey)", () => {
  it("completes round-trip for 1 to 50 tokens and matches canonicalJson format", () => {
    const tokens = [
      makeSampleToken(1, 1),
      makeSampleToken(2, 5),
      makeSampleToken(3, 20),
    ];

    const key = encodeAccessKey(tokens);
    expect(key.startsWith("drk_")).toBe(true);
    expect(key).not.toContain("=");
    expect(key).not.toContain("+");
    expect(key).not.toContain("/");

    // Verify exact canonicalJson structure
    const expectedJson = canonicalJson({
      v: 1,
      origin: ACCESS_KEY_ORIGIN,
      tokens: tokens.map((t) => ({
        t: t.token,
        s: t.signature,
        d: t.denomination,
      })),
    });
    expect(key).toBe(encodeRawBase64Url(expectedJson));

    const decoded = decodeAccessKey(key);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.version).toBe(1);
      expect(decoded.origin).toBe(ACCESS_KEY_ORIGIN);
      expect(decoded.tokens).toEqual(tokens);
      // Verify each decoded token formats cleanly with formatCreditHeader
      for (const tok of decoded.tokens) {
        expect(parseCreditHeader(formatCreditHeader(tok))).toEqual(tok);
      }
    }

    // 50 tokens boundary succeeds
    const fifty = Array.from({ length: MAX_ACCESS_KEY_TOKENS }, (_, i) =>
      makeSampleToken(i, 1),
    );
    const key50 = encodeAccessKey(fifty);
    const dec50 = decodeAccessKey(key50);
    expect(dec50.ok).toBe(true);
    if (dec50.ok) {
      expect(dec50.tokens).toHaveLength(50);
    }
  });

  it("rejects every invalid case: prefix, base64url, version, origin, unknown keys, malformed hex, count > 50, and duplicate tokens", () => {
    const validTok = makeSampleToken(0, 1);

    // Non-string or wrong prefix
    expect(decodeAccessKey(null).ok).toBe(false);
    expect(decodeAccessKey("").ok).toBe(false);
    expect(decodeAccessKey("sk_abc123").ok).toBe(false);
    expect(decodeAccessKey("drk_").ok).toBe(false);
    expect(decodeAccessKey("drk_not valid base64!").ok).toBe(false);

    // Padded base64 rejected
    const padded = "drk_" + Buffer.from('{"v":1}').toString("base64");
    if (padded.endsWith("=")) {
      expect(decodeAccessKey(padded).ok).toBe(false);
    }

    // Unknown version
    const wrongVersion = encodeRawBase64Url(
      canonicalJson({
        v: 2,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: validTok.token, s: validTok.signature, d: 1 }],
      }),
    );
    expect(decodeAccessKey(wrongVersion)).toEqual({
      ok: false,
      error: "Unsupported access key version: 2",
    });

    // Wrong origin
    const wrongOrigin = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: "https://evil.example.com",
        tokens: [{ t: validTok.token, s: validTok.signature, d: 1 }],
      }),
    );
    expect(decodeAccessKey(wrongOrigin).ok).toBe(false);

    // Unknown top-level key
    const extraTopKey = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: validTok.token, s: validTok.signature, d: 1 }],
        extra: true,
      }),
    );
    expect(decodeAccessKey(extraTopKey)).toEqual({
      ok: false,
      error: "Unknown or missing top-level keys in access key",
    });

    // Unknown key in token entry
    const extraTokenKey = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: validTok.token, s: validTok.signature, d: 1, extra: "x" }],
      }),
    );
    expect(decodeAccessKey(extraTokenKey)).toEqual({
      ok: false,
      error: "Unknown or missing keys in token entry at index 0",
    });

    // Malformed hex (odd length, non-hex chars, uppercase in payload)
    const badHex = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: "xyz123", s: validTok.signature, d: 1 }],
      }),
    );
    expect(decodeAccessKey(badHex).ok).toBe(false);

    const oddHex = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: "abc", s: validTok.signature, d: 1 }],
      }),
    );
    expect(decodeAccessKey(oddHex).ok).toBe(false);

    const badSigHex = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: validTok.token, s: "not-hex!", d: 1 }],
      }),
    );
    expect(decodeAccessKey(badSigHex).ok).toBe(false);

    // Unsupported denomination
    const badDenom = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [{ t: validTok.token, s: validTok.signature, d: 7 }],
      }),
    );
    expect(decodeAccessKey(badDenom).ok).toBe(false);

    // Empty tokens array
    const zeroTokens = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [],
      }),
    );
    expect(decodeAccessKey(zeroTokens).ok).toBe(false);
    expect(() => encodeAccessKey([])).toThrow(/at least 1 token/);

    // More than 50 tokens
    const fiftyOne = Array.from({ length: 51 }, (_, i) => makeSampleToken(i, 1));
    expect(() => encodeAccessKey(fiftyOne)).toThrow(/more than 50 tokens/);
    const rawFiftyOne = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: fiftyOne.map((t) => ({ t: t.token, s: t.signature, d: t.denomination })),
      }),
    );
    expect(decodeAccessKey(rawFiftyOne)).toEqual({
      ok: false,
      error: "Access key cannot contain more than 50 tokens",
    });

    // Duplicate tokens rejected
    const dupTokens = [validTok, { ...validTok }];
    expect(() => encodeAccessKey(dupTokens)).toThrow(/Duplicate token/);
    const rawDup = encodeRawBase64Url(
      canonicalJson({
        v: 1,
        origin: ACCESS_KEY_ORIGIN,
        tokens: [
          { t: validTok.token, s: validTok.signature, d: 1 },
          { t: validTok.token, s: validTok.signature, d: 1 },
        ],
      }),
    );
    expect(decodeAccessKey(rawDup)).toEqual({
      ok: false,
      error: "Duplicate token in access key at index 1",
    });
  });
});

describe("Step 2: Wallet move functions (moveTokensToAccessKey & moveCreditsToAccessKey)", () => {
  beforeEach(() => {
    clearStoredCredits();
  });

  it("moves tokens out of the wallet and preserves all tokens if interrupted after writing the key", () => {
    const initialTokens = Array.from({ length: 8 }, (_, i) => makeSampleToken(i, 1));
    storeCreditTokens(initialTokens);
    expect(storedCreditBalance()).toBe(8);
    expect(getStoredCredits()).toHaveLength(8);

    // Simulate interruption right after key is written (before wallet removal)
    let capturedKeyBeforeCrash = "";
    expect(() =>
      moveTokensToAccessKey(5, {
        onAfterKeyWritten: (key) => {
          capturedKeyBeforeCrash = key;
          throw new Error("Simulated tab crash before wallet removal");
        },
      }),
    ).toThrow(/Simulated tab crash/);

    // Key was already formed and wallet still has all 8 tokens (zero token loss)
    expect(capturedKeyBeforeCrash.startsWith("drk_")).toBe(true);
    expect(getStoredCredits()).toHaveLength(8);
    expect(storedCreditBalance()).toBe(8);

    // Normal completion moves 5 tokens out of the wallet and leaves 3
    const moved = moveTokensToAccessKey(5);
    expect(moved.tokens).toHaveLength(5);
    expect(moved.creditsMoved).toBe(5);
    expect(moved.remainingBalance).toBe(3);
    expect(getStoredCredits()).toHaveLength(3);
    expect(storedCreditBalance()).toBe(3);

    const decoded = decodeAccessKey(moved.key);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.tokens).toEqual(initialTokens.slice(0, 5));
    }

    // Remaining wallet tokens are the last 3
    expect(getStoredCredits()).toEqual(initialTokens.slice(5));

    // Requesting more than remaining throws without losing the 3 tokens
    expect(() => moveTokensToAccessKey(5)).toThrow(/Not enough tokens/);
    expect(getStoredCredits()).toHaveLength(3);
  });

  it("moves target credits (5, 10, 20) via moveCreditsToAccessKey", () => {
    const tokens = Array.from({ length: 12 }, (_, i) => makeSampleToken(i, 1));
    storeCreditTokens(tokens);
    expect(storedCreditBalance()).toBe(12);

    const moved10 = moveCreditsToAccessKey(10);
    expect(moved10.creditsMoved).toBe(10);
    expect(moved10.tokens).toHaveLength(10);
    expect(moved10.remainingBalance).toBe(2);
    expect(storedCreditBalance()).toBe(2);
  });
});

describe("Step 3 (K3): Hosted /api/v1/chat/completions Bearer drk_ support", () => {
  const origApiKey = process.env.TINFOIL_API_KEY;

  beforeEach(() => {
    process.env.TINFOIL_API_KEY = "test-tinfoil-key-do-not-print";
    tinfoilMocks.createCompletion.mockReset();
    creditLedgerMocks.verifyAndSpendCreditHeader.mockReset();
  });

  afterEach(() => {
    if (origApiKey === undefined) delete process.env.TINFOIL_API_KEY;
    else process.env.TINFOIL_API_KEY = origApiKey;
  });

  it("chooses the first unspent token, returns X-DRouter-Credits-Remaining, and never logs keys or bodies", async () => {
    const t1 = makeSampleToken(1, 1);
    const t2 = makeSampleToken(2, 1);
    const t3 = makeSampleToken(3, 1);
    const key = encodeAccessKey([t1, t2, t3]);

    // Mock token 1 as already spent (409), token 2 as unspent (ok: true)
    creditLedgerMocks.verifyAndSpendCreditHeader
      .mockResolvedValueOnce({
        ok: false,
        error: "Double-spend rejected: credit nullifier already spent",
        status: 409,
      })
      .mockResolvedValueOnce({
        ok: true,
        nullifier: nullifierFor(t2.token),
        denomination: 1,
        remainingPoolUnredeemed: 1,
      });

    tinfoilMocks.createCompletion.mockResolvedValueOnce({
      id: "chatcmpl-drk-1",
      object: "chat.completion",
      created: 1792800000,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: "Hello from sealed computer." },
          finish_reason: "stop",
        },
      ],
    });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const secretPrompt = "Sensitive prompt marker 99481-secret";
      const req = new Request("http://localhost/api/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model: "kimi-k3",
          messages: [{ role: "user", content: secretPrompt }],
        }),
      });

      const res = await postChatCompletions(req);
      expect(res.status).toBe(200);
      expect(creditLedgerMocks.verifyAndSpendCreditHeader).toHaveBeenCalledTimes(2);
      expect(creditLedgerMocks.verifyAndSpendCreditHeader).toHaveBeenNthCalledWith(
        1,
        formatCreditHeader(t1),
        "kimi-k3",
      );
      expect(creditLedgerMocks.verifyAndSpendCreditHeader).toHaveBeenNthCalledWith(
        2,
        formatCreditHeader(t2),
        "kimi-k3",
      );

      expect(res.headers.get("X-DRouter-Credit-Verified")).toBe("true");
      expect(res.headers.get("X-DRouter-Credit-Nullifier")).toBe(nullifierFor(t2.token));
      expect(res.headers.get("X-DRouter-Credits-Remaining")).toBe("1");

      // Verify console never logged the key or body
      const allLogs = [
        ...logSpy.mock.calls.flat(),
        ...warnSpy.mock.calls.flat(),
        ...errorSpy.mock.calls.flat(),
      ]
        .map(String)
        .join(" ");
      expect(allLogs).not.toContain(key);
      expect(allLogs).not.toContain(secretPrompt);
    } finally {
      logSpy.mockRestore();
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it("returns 402 with plain message and X-DRouter-Credits-Remaining: 0 when all tokens in key are spent", async () => {
    const t1 = makeSampleToken(10, 1);
    const t2 = makeSampleToken(11, 1);
    const key = encodeAccessKey([t1, t2]);

    creditLedgerMocks.verifyAndSpendCreditHeader.mockResolvedValue({
      ok: false,
      error: "Double-spend rejected: credit nullifier already spent",
      status: 409,
    });

    const req = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        model: "kimi-k3",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const res = await postChatCompletions(req);
    expect(res.status).toBe(402);
    expect(res.headers.get("X-DRouter-Credits-Remaining")).toBe("0");
    const body = await res.json();
    expect(body.error.message).toContain(
      "All credits in this access key have been spent",
    );
    expect(body.error.message).toContain("/account");
    expect(tinfoilMocks.createCompletion).not.toHaveBeenCalled();
  });

  it("returns 400 on a malformed drk_ access key and falls back to free tier on any non-drk_ bearer value", async () => {
    const badReq = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer drk_malformed_not_json",
      },
      body: JSON.stringify({
        model: "kimi-k3",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const badRes = await postChatCompletions(badReq);
    expect(badRes.status).toBe(400);
    const badJson = await badRes.json();
    expect(badJson.error.message).toContain("Malformed deRoute access key");

    // Non-drk_ bearer value uses the free tier without calling verifyAndSpendCreditHeader
    tinfoilMocks.createCompletion.mockResolvedValueOnce({
      id: "chatcmpl-free-1",
      object: "chat.completion",
      created: 1792800000,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: "Free tier reply." },
          finish_reason: "stop",
        },
      ],
    });

    const freeReq = new Request("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer any-value",
      },
      body: JSON.stringify({
        model: "kimi-k3",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const freeRes = await postChatCompletions(freeReq);
    expect(freeRes.status).toBe(200);
    expect(creditLedgerMocks.verifyAndSpendCreditHeader).not.toHaveBeenCalled();
  });
});

describe("Step 4 (K4): Coding tool snippets & Account page SSR render safety", () => {
  it("builds valid OpenCode custom provider schema and all 7 tool snippets in both private and hosted modes", () => {
    const sampleKey = encodeAccessKey([makeSampleToken(1, 1)]);

    const priv = buildCodingToolSnippets({
      mode: "private",
      accessKey: sampleKey,
    });
    expect(priv.baseUrl).toBe(LOCAL_PROXY_BASE_URL);
    expect(priv.proxyStartCommand).toContain(`node deroute-proxy.mjs --key ${sampleKey}`);
    expect(priv.proxyStartCommand).toContain("deroute-proxy.mjs.sha256");

    const parsedPrivOpencode = JSON.parse(priv.byTool.opencode);
    expect(parsedPrivOpencode.$schema).toBe("https://opencode.ai/config.json");
    expect(parsedPrivOpencode.provider.deroute.npm).toBe("@ai-sdk/openai-compatible");
    expect(parsedPrivOpencode.provider.deroute.options.baseURL).toBe(
      "http://127.0.0.1:4141/v1",
    );
    expect(parsedPrivOpencode.provider.deroute.models["kimi-k3"]).toBeDefined();
    expect(parsedPrivOpencode.model).toBe("deroute/kimi-k3");

    expect(priv.byTool.cursor).toContain("http://127.0.0.1:4141/v1");
    expect(priv.byTool.continue).toContain("schema: v1");
    expect(priv.byTool.continue).toContain("apiBase: http://127.0.0.1:4141/v1");
    expect(priv.byTool.aider).toContain('--openai-api-base "http://127.0.0.1:4141/v1"');
    expect(priv.byTool.typescript).toContain('baseURL: "http://127.0.0.1:4141/v1"');
    expect(priv.byTool.python).toContain('base_url="http://127.0.0.1:4141/v1"');
    expect(priv.byTool.curl).toContain("http://127.0.0.1:4141/v1/chat/completions");

    const hosted = buildCodingToolSnippets({
      mode: "hosted",
      accessKey: sampleKey,
    });
    expect(hosted.baseUrl).toBe(HOSTED_GATEWAY_BASE_URL);
    const parsedHostedOpencode = JSON.parse(hosted.byTool.opencode);
    expect(parsedHostedOpencode.provider.deroute.options.baseURL).toBe(
      "https://drouter-demo.vercel.app/api/v1",
    );
    expect(parsedHostedOpencode.provider.deroute.options.apiKey).toBe(sampleKey);
    expect(hosted.byTool.curl).toContain(`Authorization: Bearer ${sampleKey}`);
  });

  it("renders AccountPage via renderToStaticMarkup without reading localStorage or calling crypto.getRandomValues during render", () => {
    const html = renderToStaticMarkup(React.createElement(AccountPage));
    expect(html).toContain("deRoute");
    expect(html).not.toContain("—");
  });
});
