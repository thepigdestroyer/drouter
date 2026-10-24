import { NextRequest, NextResponse, connection } from "next/server";
import {
  FORENSIC_PROOF_SCHEMA,
  verifyForensicProofBundleOffline,
  type ForensicProofBundle,
} from "@/lib/forensics/bundle";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import { simRoots } from "@/lib/sim/roots";

const MAX_FORENSICS_BODY_BYTES = 262_144; // 256 KB max proof bundle size

const forensicsLimiter = createTokenBucketLimiter({
  name: "forensics-route",
  capacity: 60,
  refillPerSec: 2,
});

function getPinnedSimNodePublicKeys(): Record<string, string> {
  try {
    if (!process.env.SIM_HARDWARE_SEED) {
      return {};
    }
    const roots = simRoots();
    const map: Record<string, string> = {};
    for (const n of roots.nodes) {
      map[n.simId] = n.identityPublicKey;
    }
    return map;
  } catch {
    return {};
  }
}

export async function GET(request?: NextRequest) {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = forensicsLimiter.check(request);
    if (limited) return limited;
  }

  return NextResponse.json({
    schema: FORENSIC_PROOF_SCHEMA,
    pinnedNodePublicKeys: getPinnedSimNodePublicKeys(),
  });
}

export async function POST(request: NextRequest) {
  const limited = forensicsLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<{
      bundle?: ForensicProofBundle;
      expectedClientPublicKeyHex?: string;
      expectedPopSignerPublicKeyHex?: string;
      requirePinnedOrigin?: boolean;
    }>(request, MAX_FORENSICS_BODY_BYTES);

    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const bundle: ForensicProofBundle =
      "schema" in body
        ? (body as unknown as ForensicProofBundle)
        : (body.bundle as ForensicProofBundle);

    if (!bundle || typeof bundle !== "object") {
      return NextResponse.json(
        { error: "Missing forensic proof bundle payload" },
        { status: 400 },
      );
    }

    const pinnedNodePublicKeys = getPinnedSimNodePublicKeys();
    const verification = verifyForensicProofBundleOffline(bundle, {
      expectedClientPublicKeyHex: body.expectedClientPublicKeyHex,
      expectedPopSignerPublicKeyHex: body.expectedPopSignerPublicKeyHex,
      pinnedNodePublicKeys,
      requirePinnedOrigin: body.requirePinnedOrigin,
    });

    return NextResponse.json(
      {
        ...verification,
        pinnedNodePublicKeysChecked: Object.keys(pinnedNodePublicKeys),
      },
      { status: verification.valid ? 200 : 422 },
    );
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    const message =
      err instanceof InvalidJsonBodyError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Forensic proof verification failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
