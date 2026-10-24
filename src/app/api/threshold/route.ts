import { connection, NextResponse } from "next/server";
import {
  authorizeThresholdKeyRelease,
  combineShares,
  splitSecret,
} from "@/lib/threshold/shamir";

export async function GET() {
  await connection();

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
  let body: Record<string, unknown> = {};
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }

  const sessionId =
    typeof body.sessionId === "string" && body.sessionId.trim().length > 0
      ? body.sessionId.trim()
      : "sess-threshold-custom";
  const chipId =
    typeof body.chipId === "string" && body.chipId.trim().length > 0
      ? body.chipId.trim()
      : "H200-SXM-NV-0042";
  const measurementOk =
    typeof body.measurementOk === "boolean" ? body.measurementOk : true;
  const registryActive =
    typeof body.registryActive === "boolean" ? body.registryActive : true;
  const notFlagged =
    typeof body.notFlagged === "boolean" ? body.notFlagged : true;
  const k = typeof body.k === "number" ? body.k : 3;
  const n = typeof body.n === "number" ? body.n : 5;

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
