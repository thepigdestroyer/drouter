import { beforeEach, describe, expect, it } from "vitest";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  getDailySalt,
  hashClientIp,
  readBoundedBytes,
  readBoundedJson,
  resetRateLimitStateForTests,
} from "@/lib/ratelimit";
import {
  isAllowedEnclave,
  isAllowedRelayModel,
  isValidRelayId,
  pickHeaders,
  validateRelayPath,
} from "@/lib/relay";
import { POST as postRelay } from "@/app/api/relay/v1/[...path]/route";
import { POST as postRelayHop } from "@/app/api/relay/[relayId]/v1/[...path]/route";
import { POST as postAnchor } from "@/app/api/anchor/route";

describe("Privacy-Preserving Per-IP Token Bucket Limiter", () => {
  beforeEach(() => {
    resetRateLimitStateForTests();
  });

  it("hashes client IP with a daily rotating random salt and never exposes the raw IP", () => {
    const rawIp = "203.0.113.42";
    const t0 = 1_760_000_000_000;
    const hash1 = hashClientIp(rawIp, "test-ns", t0);
    const hash2 = hashClientIp(rawIp, "test-ns", t0);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    expect(hash1).not.toContain(rawIp);

    // Different namespace yields a distinct unlinkable hash
    const diffNs = hashClientIp(rawIp, "other-ns", t0);
    expect(diffNs).not.toBe(hash1);

    // Advancing by 24 hours rotates the in-memory daily salt and changes the hash
    const saltDay0 = getDailySalt(t0);
    const saltDay1 = getDailySalt(t0 + 86_400_000);
    expect(saltDay1).not.toBe(saltDay0);
    const hashNextDay = hashClientIp(rawIp, "test-ns", t0 + 86_400_000);
    expect(hashNextDay).not.toBe(hash1);
  });

  it("enforces token bucket capacity, returns 429 with Retry-After, and refills over time", async () => {
    let clock = 1_000_000;
    const limiter = createTokenBucketLimiter({
      name: "unit-bucket",
      capacity: 3,
      refillPerSec: 0.5, // 1 token per 2 seconds
      now: () => clock,
    });

    const makeReq = (ip: string) =>
      new Request("http://localhost/api/test", {
        headers: { "x-forwarded-for": ip },
      });

    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();
    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();
    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();

    // 4th request from same IP is rate limited
    const blocked = limiter.check(makeReq("198.51.100.10"));
    expect(blocked).not.toBeNull();
    expect(blocked?.status).toBe(429);
    expect(blocked?.headers.get("Retry-After")).toBe("2");
    const json = await blocked!.json();
    expect(json.retryAfterSec).toBe(2);

    // Other IP is unaffected
    expect(limiter.check(makeReq("198.51.100.99"))).toBeNull();

    // Advance clock by 2 seconds -> 1 token refilled
    clock += 2000;
    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();
    expect(limiter.check(makeReq("198.51.100.10"))?.status).toBe(429);

    // Crediting tokens back into the caller's bucket raises limits up to 4x capacity
    limiter.credit(makeReq("198.51.100.10"), 4, 4);
    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();
    expect(limiter.check(makeReq("198.51.100.10"))).toBeNull();
  });

  it("enforces global bucket limits across all callers and supports crediting", () => {
    let clock = 5_000_000;
    const globalLimiter = createGlobalBucketLimiter({
      name: "global-unit",
      capacity: 2,
      refillPerSec: 1,
      now: () => clock,
    });

    expect(globalLimiter.consume(1).allowed).toBe(true);
    expect(globalLimiter.consume(1).allowed).toBe(true);
    const third = globalLimiter.consume(1);
    expect(third.allowed).toBe(false);
    expect(third.retryAfterSec).toBe(1);

    clock += 1000;
    expect(globalLimiter.consume(1).allowed).toBe(true);
    globalLimiter.credit(2, 4);
    expect(globalLimiter.consume(2).allowed).toBe(true);
  });
});

describe("Bounded Body Readers (DoS Protection)", () => {
  it("readBoundedBytes rejects payloads exceeding maxBytes via Content-Length or stream size", async () => {
    const smallReq = new Request("http://localhost/api/test", {
      method: "POST",
      body: "hello",
    });
    const bytes = await readBoundedBytes(smallReq, 16);
    expect(new TextDecoder().decode(bytes)).toBe("hello");

    const bigReq = new Request("http://localhost/api/test", {
      method: "POST",
      body: "x".repeat(1024),
    });
    await expect(readBoundedBytes(bigReq, 128)).rejects.toBeInstanceOf(BodyTooLargeError);
  });

  it("readBoundedJson parses valid JSON and throws InvalidJsonBodyError on malformed JSON", async () => {
    const okReq = new Request("http://localhost/api/test", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
    });
    expect(await readBoundedJson(okReq, 1024)).toEqual({ ok: true });

    const badReq = new Request("http://localhost/api/test", {
      method: "POST",
      body: "{bad json",
    });
    await expect(readBoundedJson(badReq, 1024)).rejects.toBeInstanceOf(InvalidJsonBodyError);
  });
});

describe("Relay SSRF, Path Traversal, Header Injection & Open-Proxy Defenses", () => {
  it("isAllowedEnclave blocks SSRF vectors (non-HTTPS, custom ports, credentials, paths, query strings, foreign hosts)", () => {
    expect(isAllowedEnclave("https://inference.tinfoil.sh")).toBe(true);
    expect(isAllowedEnclave("https://router-0.tinfoil.sh")).toBe(true);
    expect(isAllowedEnclave("https://kimi-k3-inf14.tinfoil.containers.tinfoil.dev")).toBe(true);

    // Blocked SSRF attempts
    expect(isAllowedEnclave("http://inference.tinfoil.sh")).toBe(false);
    expect(isAllowedEnclave("https://inference.tinfoil.sh:8443")).toBe(false);
    expect(isAllowedEnclave("https://user:pass@inference.tinfoil.sh")).toBe(false);
    expect(isAllowedEnclave("https://inference.tinfoil.sh/admin")).toBe(false);
    expect(isAllowedEnclave("https://inference.tinfoil.sh?foo=bar")).toBe(false);
    expect(isAllowedEnclave("https://inference.tinfoil.sh#frag")).toBe(false);
    expect(isAllowedEnclave("https://evil-tinfoil.sh")).toBe(false);
    expect(isAllowedEnclave("https://tinfoil.sh.evil.com")).toBe(false);
    expect(isAllowedEnclave("https://169.254.169.254")).toBe(false);
    expect(isAllowedEnclave("https://localhost")).toBe(false);
    expect(isAllowedEnclave("//evil.com")).toBe(false);
  });

  it("validateRelayPath enforces strict v1 endpoint allowlist and blocks traversal/injection", () => {
    expect(validateRelayPath(["chat", "completions"])).toBe("chat/completions");
    expect(validateRelayPath(["models"])).toBe("models");
    expect(validateRelayPath(["embeddings"])).toBe("embeddings");

    // Traversal and unapproved paths rejected
    expect(validateRelayPath(["..", "admin"])).toBeNull();
    expect(validateRelayPath(["%2e%2e", "secret"])).toBeNull();
    expect(validateRelayPath(["chat", "..", "completions"])).toBeNull();
    expect(validateRelayPath(["chat\\completions"])).toBeNull();
    expect(validateRelayPath(["chat/completions"])).toBeNull();
    expect(validateRelayPath(["internal", "metrics"])).toBeNull();
    expect(validateRelayPath(["chat", "completions\0"])).toBeNull();
    expect(validateRelayPath([])).toBeNull();
  });

  it("isValidRelayId and isAllowedRelayModel reject traversal and unknown models", () => {
    expect(isValidRelayId("relay-eu-zurich")).toBe(true);
    expect(isValidRelayId("../etc/passwd")).toBe(false);
    expect(isValidRelayId("relay/evil")).toBe(false);
    expect(isValidRelayId("a".repeat(40))).toBe(false);

    expect(isAllowedRelayModel("kimi-k3")).toBe(true);
    expect(isAllowedRelayModel("glm-5-3")).toBe(true);
    expect(isAllowedRelayModel(null)).toBe(true);
    expect(isAllowedRelayModel("evil-model-9000")).toBe(false);
    expect(isAllowedRelayModel("kimi-k3\r\nX-Injected: 1")).toBe(false);
  });

  it("pickHeaders strips headers with control characters or oversized values", () => {
    const src = new Headers();
    src.set("content-type", "application/octet-stream");
    src.set("x-tinfoil-model", "kimi-k3");
    src.set("accept", "x".repeat(600)); // exceeds 512 chars
    const picked = pickHeaders(src, ["content-type", "x-tinfoil-model", "accept"]);
    expect(picked.get("content-type")).toBe("application/octet-stream");
    expect(picked.get("x-tinfoil-model")).toBe("kimi-k3");
    expect(picked.get("accept")).toBeNull();
  });

  it("Relay route rejects unencrypted open-proxy requests lacking ehbp-encapsulated-key or targeting disallowed paths", async () => {
    // 1. Disallowed path
    const badPathReq = new Request("http://localhost/api/relay/v1/admin/config", {
      method: "POST",
      headers: {
        "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
        "ehbp-encapsulated-key": "00".repeat(32),
      },
      body: "encrypted-bytes",
    });
    const res1 = await postRelay(badPathReq, { params: Promise.resolve({ path: ["admin", "config"] }) });
    expect(res1.status).toBe(400);

    // 2. Missing ehbp-encapsulated-key (plaintext open-proxy attempt)
    const noEhbpReq = new Request("http://localhost/api/relay/v1/chat/completions", {
      method: "POST",
      headers: {
        "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
      },
      body: JSON.stringify({ model: "kimi-k3", messages: [{ role: "user", content: "free tokens" }] }),
    });
    const res2 = await postRelay(noEhbpReq, { params: Promise.resolve({ path: ["chat", "completions"] }) });
    expect(res2.status).toBe(400);
    const errJson = await res2.json();
    expect(errJson.error).toContain("EHBP");

    // 3. Invalid relayId in hop route
    const badHopReq = new Request("http://localhost/api/relay/..%2Fevil/v1/chat/completions", {
      method: "POST",
      headers: {
        "x-tinfoil-enclave-url": "https://inference.tinfoil.sh",
        "ehbp-encapsulated-key": "00".repeat(32),
      },
      body: "encrypted-bytes",
    });
    const res3 = await postRelayHop(badHopReq, {
      params: Promise.resolve({ relayId: "../evil", path: ["chat", "completions"] }),
    });
    expect(res3.status).toBe(400);
  });

  it("Arc anchor route rejects unregistered nodeIds before touching the verifier wallet", async () => {
    const fakeNodeReq = new Request("http://localhost/api/anchor", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        receiptHash: `0x${"a".repeat(64)}`,
        nodeId: `0x${"b".repeat(64)}`, // not one of the 4 registered nodes
      }),
    });
    const res = await postAnchor(fakeNodeReq);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("registered node");
  });
});
