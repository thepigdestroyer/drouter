import { connection } from "next/server";
import { coarsenToHour, logReceipt, logVerification, mongoConfigured, recentActivity } from "@/lib/db";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const HEX = /^(0x)?[0-9a-fA-F]{1,256}$/;
const CHECK_STATUS = new Set(["pass", "fail", "skip"]);
const MAX_LOG_BODY_BYTES = 16_384; // 16 KB
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const FORBIDDEN_BODY_KEYS = [
  "prompt",
  "prompts",
  "completion",
  "completions",
  "messages",
  "message",
  "ip",
  "clientIp",
  "userAgent",
  "user_agent",
  "email",
  "headers",
];

const getLimiter = createTokenBucketLimiter({
  name: "log-get",
  capacity: 60,
  refillPerSec: 2,
});

const postIpLimiter = createTokenBucketLimiter({
  name: "log-post-ip",
  capacity: 20,
  refillPerSec: 20 / 60,
});

const postGlobalLimiter = createGlobalBucketLimiter({
  name: "log-post-global",
  capacity: 200,
  refillPerSec: 200 / 3600,
});

function str(value: unknown, max = 200): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.includes("\0")) {
    return null;
  }
  if (EMAIL_RE.test(value) || IPV4_RE.test(value)) {
    return null;
  }
  return value;
}

/** Public transparency log: recent verifications, receipts and relay totals. */
export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }
  return Response.json(await recentActivity());
}

/**
 * Accepts only whitelisted, non-sensitive fields. Anything else in the body is dropped, so this
 * endpoint cannot be used to store prompts, outputs, IPs, user agents, or emails.
 */
export async function POST(request: Request) {
  const limited = postIpLimiter.check(request);
  if (limited) return limited;

  let body: Record<string, unknown>;
  try {
    const parsed = await readBoundedJson(request, MAX_LOG_BODY_BYTES);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Response.json({ error: "Invalid JSON object" }, { status: 400 });
    }
    body = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON" },
      { status: 400 },
    );
  }

  for (const forbidden of FORBIDDEN_BODY_KEYS) {
    if (forbidden in body) {
      return Response.json(
        { error: `Transparency log rejects sensitive field '${forbidden}'` },
        { status: 400 },
      );
    }
  }

  const globalCheck = postGlobalLimiter.consume(1);
  if (!globalCheck.allowed) {
    return Response.json(
      { error: "Transparency log write quota exceeded", retryAfterSec: globalCheck.retryAfterSec },
      { status: 429, headers: { "Retry-After": String(globalCheck.retryAfterSec) } },
    );
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1" || !mongoConfigured()) {
    return Response.json({ stored: false, reason: "MongoDB not configured" });
  }

  const coarsenedNow = coarsenToHour(new Date());

  if (body.type === "verification") {
    const nodeId = str(body.nodeId, 80);
    const nodeName = str(body.nodeName, 80);
    const kind = body.kind === "tinfoil" || body.kind === "sim" ? body.kind : null;
    const measurement = str(body.measurement, 300) ?? "";
    const evidenceHash = str(body.evidenceHash, 80);
    const checks = Array.isArray(body.checks)
      ? body.checks
          .filter((c): c is { id: string; status: "pass" | "fail" | "skip" } =>
            typeof c === "object" && c !== null && typeof c.id === "string" && c.id.length <= 8 && CHECK_STATUS.has(c.status),
          )
          .map((c) => ({ id: c.id, status: c.status }))
          .slice(0, 12)
      : [];
    if (!nodeId || !nodeName || !kind || !evidenceHash || !HEX.test(evidenceHash)) {
      return Response.json({ error: "Invalid verification event" }, { status: 400 });
    }
    const stored = await logVerification({
      nodeId,
      nodeName,
      kind,
      ok: body.ok === true,
      checks,
      measurement,
      evidenceHash,
      releaseDigest: str(body.releaseDigest, 100) ?? undefined,
      enclaveHost: str(body.enclaveHost, 100) ?? undefined,
      at: coarsenedNow,
    });
    return Response.json({ stored });
  }

  if (body.type === "receipt") {
    const nodeId = str(body.nodeId, 80);
    const receiptHash = str(body.receiptHash, 80);
    if (!nodeId || !receiptHash || !HEX.test(receiptHash)) {
      return Response.json({ error: "Invalid receipt event" }, { status: 400 });
    }
    const anchorTx = str(body.anchorTx, 80);
    const stored = await logReceipt({
      nodeId,
      receiptHash,
      signatureVerified: body.signatureVerified === true,
      anchorTx: anchorTx && HEX.test(anchorTx) ? anchorTx : null,
      at: coarsenedNow,
    });
    return Response.json({ stored });
  }

  return Response.json({ error: "Unknown event type" }, { status: 400 });
}
