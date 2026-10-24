import { connection } from "next/server";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createGlobalBucketLimiter,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import {
  computeVerifierFingerprint,
  type VerifierSubmissionClaim,
} from "@/lib/transparency/log";
import {
  getPersistedTransparencyLog,
  getVerifierSubmissionsSummary,
  submitIndependentVerification,
} from "@/lib/transparency/store";

const verificationsGetLimiter = createTokenBucketLimiter({
  name: "transparency-verifications-get",
  capacity: 120,
  refillPerSec: 4,
});

const verificationsPostIpLimiter = createTokenBucketLimiter({
  name: "transparency-verifications-post-ip",
  capacity: 10,
  refillPerSec: 10 / 60,
});

const verificationsPostKeyLimiter = createTokenBucketLimiter({
  name: "transparency-verifications-post-key",
  capacity: 6,
  refillPerSec: 6 / 3600,
});

const verificationsPostGlobalLimiter = createGlobalBucketLimiter({
  name: "transparency-verifications-post-global",
  capacity: 60,
  refillPerSec: 60 / 3600,
});

const MAX_VERIFICATION_BODY_BYTES = 32_768;

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = verificationsGetLimiter.check(request);
    if (limited) return limited;
  }

  let limit = 20;
  if (request) {
    try {
      const url = new URL(request.url, "http://localhost");
      const raw = url.searchParams.get("limit");
      if (raw !== null && raw.trim() !== "") {
        const parsed = Number(raw);
        if (Number.isInteger(parsed) && parsed > 0) {
          limit = Math.min(parsed, 100);
        }
      }
    } catch {
      // Ignore malformed URL query
    }
  }

  const [summary, persistedLog] = await Promise.all([
    getVerifierSubmissionsSummary({ limit }),
    getPersistedTransparencyLog(),
  ]);

  return Response.json({
    ok: true,
    persisted: summary.persisted,
    distinctVerifierCount: summary.distinctVerifierCount,
    totalSubmissions: summary.totalSubmissions,
    recentSubmissions: summary.recentSubmissions,
    operatorPublicKey: persistedLog.operatorPublicKey,
    signedTreeHead: persistedLog.signedTreeHead,
  });
}

export async function POST(request: Request) {
  const ipLimited = verificationsPostIpLimiter.check(request);
  if (ipLimited) return ipLimited;

  let body: Record<string, unknown>;
  try {
    const parsed = await readBoundedJson(request, MAX_VERIFICATION_BODY_BYTES);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Response.json({ ok: false, error: "Invalid JSON object" }, { status: 400 });
    }
    body = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ ok: false, error: err.message }, { status: 413 });
    }
    return Response.json(
      { ok: false, error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON" },
      { status: 400 },
    );
  }

  const publicKey = typeof body.publicKey === "string" ? body.publicKey.trim() : "";
  const signature = typeof body.signature === "string" ? body.signature.trim() : "";
  const claim = body.claim as VerifierSubmissionClaim | undefined;

  if (!publicKey || !signature || !claim || typeof claim !== "object") {
    return Response.json(
      { ok: false, error: "publicKey, signature, and claim object are required" },
      { status: 400 },
    );
  }

  let fingerprint = "";
  try {
    fingerprint = computeVerifierFingerprint(publicKey);
  } catch {
    return Response.json(
      { ok: false, error: "Invalid Ed25519 publicKey hex (expected 64 hex characters)" },
      { status: 400 },
    );
  }

  const keyLimit = verificationsPostKeyLimiter.consume(fingerprint, 1);
  if (!keyLimit.allowed) {
    return Response.json(
      {
        ok: false,
        error: "Verifier key rate limit exceeded",
        retryAfterSec: keyLimit.retryAfterSec,
      },
      { status: 429, headers: { "Retry-After": String(keyLimit.retryAfterSec) } },
    );
  }

  const globalLimit = verificationsPostGlobalLimiter.consume(1);
  if (!globalLimit.allowed) {
    return Response.json(
      {
        ok: false,
        error: "Verification submission quota exceeded",
        retryAfterSec: globalLimit.retryAfterSec,
      },
      { status: 429, headers: { "Retry-After": String(globalLimit.retryAfterSec) } },
    );
  }

  const result = await submitIndependentVerification({
    publicKey,
    signature,
    claim,
    anchorOnArc: false,
  });

  if (!result.ok) {
    return Response.json(
      {
        ok: false,
        error: result.error,
        ...(result.mismatches ? { mismatches: result.mismatches } : {}),
      },
      { status: result.status },
    );
  }

  return Response.json({
    ok: true,
    persisted: result.persisted,
    verifierFingerprint: result.verifierFingerprint,
    epochHourSec: result.epochHourSec,
    submission: result.submission,
    distinctVerifierCount: result.distinctVerifierCount,
    totalSubmissions: result.totalSubmissions,
    event: result.event,
    inclusionProof: result.inclusionProof,
    consistencyProof: result.consistencyProof,
    signedTreeHead: result.signedTreeHead,
    operatorPublicKey: result.operatorPublicKey,
  });
}
