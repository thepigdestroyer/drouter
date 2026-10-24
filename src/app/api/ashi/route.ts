import { NextRequest, NextResponse, connection } from "next/server";
import {
  FHE_SCOPE_DISCLOSURE,
  getPublicScoringMatrix,
  runLiveFheLinearRoundTrip,
  serverEvaluateEncryptedLinearScores,
  type FheEncryptedRequestPayload,
} from "@/lib/ashi/fhe";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";
import {
  buildMeasuredTiersCatalog,
  KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
  type SourcedTierCatalogEntry,
} from "@/lib/tiers/catalog";

const ashiGetLimiter = createTokenBucketLimiter({
  name: "ashi-get",
  capacity: 120,
  refillPerSec: 4,
});

const ashiPostLimiter = createTokenBucketLimiter({
  name: "ashi-post",
  capacity: 40,
  refillPerSec: 1,
});

export interface PlatformTierComparisonEntry {
  tier: "Tier A" | "Tier A+" | "Tier B" | "Tier C";
  name: string;
  architecture: string;
  trustBoundary: string;
  physicalInterposerResistant: boolean;
  routingPrivacy: string;
  throughputTokPerSec: number | null;
  usdPerMillionOutputTokens: number | null;
  maxContextTokens: number;
  maxContextSource: string;
  measuredEvalLatencyMs: number | null;
  throughputOpsPerSec: number | null;
  metricsSource: string;
  sessionStateFootprint: string;
}

function toComparisonEntry(
  entry: SourcedTierCatalogEntry,
): PlatformTierComparisonEntry {
  return {
    tier: entry.tier,
    name: entry.name,
    architecture: entry.architecture,
    trustBoundary: entry.trustBoundary,
    physicalInterposerResistant: entry.physicalInterposerResistant,
    routingPrivacy: entry.routingPrivacy,
    throughputTokPerSec: entry.throughputTokPerSec,
    usdPerMillionOutputTokens: entry.usdPerMillionOutputTokens,
    maxContextTokens: entry.maxContextTokens,
    maxContextSource: entry.maxContextSource,
    measuredEvalLatencyMs: entry.measuredEvalLatencyMs,
    throughputOpsPerSec: entry.throughputOpsPerSec,
    metricsSource: entry.metricsSource,
    sessionStateFootprint: entry.sessionStateFootprint,
  };
}

export async function GET(request?: NextRequest) {
  try {
    await connection();
  } catch {
    // Allow direct handler invocation in unit tests outside Next.js request AsyncLocalStorage
  }
  if (request) {
    const limited = ashiGetLimiter.check(request);
    if (limited) return limited;
  }

  // Run a real measured CKKS homomorphic linear classification round trip via node-seal WASM
  const liveFhe = await runLiveFheLinearRoundTrip();
  const catalog = await buildMeasuredTiersCatalog({
    fheMeasurement: liveFhe,
  });

  const tierComparison: PlatformTierComparisonEntry[] =
    catalog.entries.map(toComparisonEntry);

  const publicMatrix = getPublicScoringMatrix();

  return NextResponse.json({
    fheScopeDisclosure: FHE_SCOPE_DISCLOSURE,
    liveFhe,
    publicScoringMatrix: {
      dimensions: publicMatrix.dimensions,
      numClasses: publicMatrix.numClasses,
      blockStride: publicMatrix.blockStride,
      matrixDigestSha256: publicMatrix.matrixDigestSha256,
      classes: publicMatrix.classes.map((c) => ({
        id: c.id,
        label: c.label,
        description: c.description,
        bias: c.bias,
      })),
    },
    kimiK3MaxContextTokens: KIMI_K3_ENCLAVE_MAX_CONTEXT_TOKENS,
    tierComparison,
  });
}

/**
 * POST /api/ashi
 * Zero-plaintext FHE evaluation endpoint:
 * - Accepts ONLY `ciphertextBase64`, `relinKeysBase64`, `galoisKeysBase64` (and optional `publicKeyBase64`).
 * - Rejects any request containing `secretKey`, `secretKeyBase64`, `plaintext`, `text`, or `prompt`
 *   so the server NEVER sees plaintext or secret keys.
 * - Computes homomorphic 4x128 linear classification dot products (`W * Enc(x) + b`) and
 *   homomorphic squared L2 norm (`sum(x_i^2)`) using `node-seal` 7.0.0 WASM and returns the encrypted result ciphertexts.
 */
export async function POST(request: Request) {
  const limited = ashiPostLimiter.check(request);
  if (limited) return limited;

  try {
    // Galois keys + relin keys + ciphertext in zstd base64 are ~1.6 MB total; cap body at 4 MB.
    const body = await readBoundedJson<Record<string, unknown>>(
      request,
      4 * 1024 * 1024,
    );

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return NextResponse.json(
        { error: "FHE request body must be a JSON object" },
        { status: 400 },
      );
    }

    // Strict zero-plaintext / zero-secret-key enforcement on the server
    const forbiddenFields = [
      "secretKey",
      "secretKeyBase64",
      "plaintext",
      "text",
      "prompt",
      "vector128",
    ] as const;
    for (const field of forbiddenFields) {
      if (body[field] !== undefined) {
        return NextResponse.json(
          {
            error: `Privacy violation rejected: server FHE endpoint must never receive "${field}". Encrypt locally on the client and send only ciphertextBase64, relinKeysBase64, and galoisKeysBase64.`,
          },
          { status: 400 },
        );
      }
    }

    const payload: FheEncryptedRequestPayload = {
      ciphertextBase64:
        typeof body.ciphertextBase64 === "string" ? body.ciphertextBase64 : "",
      publicKeyBase64:
        typeof body.publicKeyBase64 === "string"
          ? body.publicKeyBase64
          : undefined,
      relinKeysBase64:
        typeof body.relinKeysBase64 === "string" ? body.relinKeysBase64 : "",
      galoisKeysBase64:
        typeof body.galoisKeysBase64 === "string" ? body.galoisKeysBase64 : "",
    };

    if (
      !payload.ciphertextBase64 ||
      !payload.relinKeysBase64 ||
      !payload.galoisKeysBase64
    ) {
      return NextResponse.json(
        {
          error:
            "Missing required FHE fields: ciphertextBase64, relinKeysBase64, and galoisKeysBase64 are required.",
        },
        { status: 400 },
      );
    }

    const evaluation = await serverEvaluateEncryptedLinearScores(payload);
    return NextResponse.json(evaluation, { status: 200 });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    if (err instanceof InvalidJsonBodyError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    const message =
      err instanceof Error ? err.message : "FHE homomorphic evaluation failed";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
