import { connection, NextResponse } from "next/server";
import {
  BodyTooLargeError,
  createTokenBucketLimiter,
  readBoundedBytes,
} from "@/lib/ratelimit";
import {
  authorizeThresholdKeyRelease,
  combineShares,
  splitSecret,
} from "@/lib/threshold/shamir";

const MAX_THRESHOLD_BODY_BYTES = 8192;

const thresholdLimiter = createTokenBucketLimiter({
  name: "threshold-route",
  capacity: 60,
  refillPerSec: 2,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = thresholdLimiter.check(request);
    if (limited) return limited;
  }

  const sessionId = "sess-threshold-demo-01";
  const chipId = "H200-SXM-NV-0042";
  const k = 3;
  const n = 5;

  const release = authorizeThresholdKeyRelease({
    sessionId,
    chipId,
    measurementOk: true,
    registryActive: true,
    notFlagged: true,
    k,
    n,
  });

  const sampleShares = release.reconstructedKeyHex
    ? splitSecret(release.reconstructedKeyHex, k, n, "0102030405060708")
    : [];

  const subsetVerifications =
    sampleShares.length >= 5
      ? [
          {
            indices: [1, 2, 3],
            matches:
              combineShares(
                [sampleShares[0], sampleShares[1], sampleShares[2]],
                k
              ) === release.reconstructedKeyHex,
          },
          {
            indices: [2, 4, 5],
            matches:
              combineShares(
                [sampleShares[1], sampleShares[3], sampleShares[4]],
                k
              ) === release.reconstructedKeyHex,
          },
          {
            indices: [1, 3, 5],
            matches:
              combineShares(
                [sampleShares[0], sampleShares[2], sampleShares[4]],
                k
              ) === release.reconstructedKeyHex,
          },
        ]
      : [];

  return NextResponse.json({
    ...release,
    sessionId,
    chipId,
    subsetVerifications,
  });
}

export async function POST(request: Request) {
  const limited = thresholdLimiter.check(request);
  if (limited) return limited;

  let body: Record<string, unknown> = {};
  try {
    const rawBytes = await readBoundedBytes(request, MAX_THRESHOLD_BODY_BYTES);
    if (rawBytes.byteLength > 0) {
      const parsed = JSON.parse(new TextDecoder().decode(rawBytes));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      body = parsed as Record<string, unknown>;
    }
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const sessionId =
    typeof body.sessionId === "string" && body.sessionId.trim().length > 0
      ? body.sessionId.trim().slice(0, 128)
      : "sess-threshold-custom";
  const chipId =
    typeof body.chipId === "string" && body.chipId.trim().length > 0
      ? body.chipId.trim().slice(0, 128)
      : "H200-SXM-NV-0042";
  const measurementOk =
    typeof body.measurementOk === "boolean" ? body.measurementOk : true;
  const registryActive =
    typeof body.registryActive === "boolean" ? body.registryActive : true;
  const notFlagged =
    typeof body.notFlagged === "boolean" ? body.notFlagged : true;
  const rawK = typeof body.k === "number" && Number.isInteger(body.k) ? body.k : 3;
  const rawN = typeof body.n === "number" && Number.isInteger(body.n) ? body.n : 5;
  if (rawK < 2 || rawN > 16 || rawK > rawN) {
    return NextResponse.json(
      { error: "Threshold parameters must satisfy 2 <= k <= n <= 16" },
      { status: 400 },
    );
  }
  const k = rawK;
  const n = rawN;

  const result = authorizeThresholdKeyRelease({
    sessionId,
    chipId,
    measurementOk,
    registryActive,
    notFlagged,
    k,
    n,
  });

  return NextResponse.json(result, {
    status: result.released ? 200 : 403,
  });
}
