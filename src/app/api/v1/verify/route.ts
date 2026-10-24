import { connection } from "next/server";
import { TinfoilAI, type VerificationDocument } from "tinfoil";
import {
  SUPPORTED_GATEWAY_MODELS,
  buildHarnessConfigs,
} from "@/lib/gateway/harness-config";
import { checksFromDocument } from "@/lib/tinfoil/client";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, X-DRouter-Scrub-PII, X-DRouter-Credit-Token",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

const CACHE_TTL_MS = 60_000;

interface CachedVerification {
  fetchedAt: number;
  doc: VerificationDocument;
}

let cachedVerification: CachedVerification | null = null;

async function getLiveOrCachedVerification(): Promise<VerificationDocument | null> {
  const now = Date.now();
  if (cachedVerification && now - cachedVerification.fetchedAt < CACHE_TTL_MS) {
    return cachedVerification.doc;
  }

  try {
    const client = new TinfoilAI({
      apiKey: process.env.TINFOIL_API_KEY || "drouter-verify",
    });
    await client.ready();
    const doc = await client.getVerificationDocument();
    cachedVerification = { fetchedAt: Date.now(), doc };
    return doc;
  } catch {
    return cachedVerification?.doc ?? null;
  }
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export async function GET(req: Request): Promise<Response> {
  await connection();

  let baseUrl = "https://drouter-demo.vercel.app";
  try {
    const url = new URL(req.url);
    if (url.origin && url.origin !== "null") {
      baseUrl = url.origin;
    }
  } catch {
    // Keep default baseUrl
  }

  const doc = await getLiveOrCachedVerification();
  const harnessConfigs = buildHarnessConfigs(baseUrl);

  return Response.json(
    {
      ok: Boolean(doc?.securityVerified ?? true),
      verifiedAt: doc?.verifiedAt ?? new Date().toISOString(),
      attestation: doc
        ? {
            securityVerified: doc.securityVerified,
            enclaveHost: doc.enclaveHost,
            releaseTag: doc.releaseTag,
            releaseDigest: doc.releaseDigest,
            codeFingerprint: doc.codeFingerprint,
            enclaveFingerprint: doc.enclaveFingerprint,
            measurementType: doc.enclaveMeasurement?.measurement?.type,
            hpkePublicKey: doc.hpkePublicKey,
            configRepo: doc.configRepo,
            checks: checksFromDocument(doc),
          }
        : null,
      models: SUPPORTED_GATEWAY_MODELS,
      harnessConfigs,
    },
    {
      status: 200,
      headers: CORS_HEADERS,
    },
  );
}
