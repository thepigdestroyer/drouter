import { connection } from "next/server";
import { TinfoilAI, type VerificationDocument } from "tinfoil";
import { GET as getEnclaveMatrix } from "@/app/api/relay/enclave-matrix/route";
import { listNodes, type ListNodesResult } from "@/lib/arc/registry";
import {
  buildHarnessConfigs,
  fetchLiveGatewayModels,
} from "@/lib/gateway/harness-config";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import { checksFromDocument } from "@/lib/tinfoil/client";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";
import type { CheckResult } from "@/lib/types";

const verifyLimiter = createTokenBucketLimiter({
  name: "v1-verify",
  capacity: 60,
  refillPerSec: 2,
});

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Accept, X-DRouter-Credit, X-DRouter-Credit-Token, X-DRouter-Scrub-PII, OpenAI-Organization, OpenAI-Project, X-Stainless-Lang, X-Stainless-Package-Version, X-Stainless-OS, X-Stainless-Arch, X-Stainless-Runtime, X-Stainless-Runtime-Version, X-Stainless-Async, X-Stainless-Retry-Count, X-Stainless-Timeout",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

const CACHE_TTL_MS = 60_000;

interface CachedVerification {
  fetchedAt: number;
  doc: VerificationDocument;
}

let cachedVerification: CachedVerification | null = null;

async function getLiveOrCachedVerification(): Promise<VerificationDocument | null> {
  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    return null;
  }
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

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(fallback);
      });
  });
}

async function getDeepAttestationBundle(): Promise<DeepAttestationBundle | null> {
  try {
    const res = await withTimeout(getEnclaveMatrix(), 3500, null);
    if (!res || !res.ok) return null;
    return (await res.json()) as DeepAttestationBundle;
  } catch {
    return null;
  }
}

function buildRegistryCheck(registry: ListNodesResult | null): CheckResult {
  if (!registry || !Array.isArray(registry.nodes)) {
    return {
      id: "C6",
      label: "Registry admission",
      status: "skip",
      detail: "Arc registry unreachable",
    };
  }
  const node = registry.nodes.find((n) => n.kind === "tinfoil");
  if (!node) {
    return {
      id: "C6",
      label: "Registry admission",
      status: "fail",
      detail: "Tinfoil router is not in the registry",
    };
  }
  const onChain = registry.source === "arc";
  const ok = onChain && node.status === "active" && Number(node.stake) > 0;
  return {
    id: "C6",
    label: "Registry admission",
    status: !onChain ? "skip" : ok ? "pass" : "fail",
    detail: onChain
      ? `${node.status} on Circle Arc testnet registry ${registry.address?.slice(0, 10)}… with ${node.stake} USDC stake`
      : "Built-in node list only (Arc registry not read)",
  };
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export async function GET(req: Request): Promise<Response> {
  await connection();

  const limited = verifyLimiter.check(req, CORS_HEADERS);
  if (limited) return limited;

  let baseUrl = "https://drouter-demo.vercel.app";
  let requestedModel = "kimi-k3";
  try {
    const url = new URL(req.url);
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.origin &&
      url.origin !== "null" &&
      /^[a-zA-Z0-9.:-]+$/.test(url.host)
    ) {
      baseUrl = url.origin;
    }
    const modelParam = url.searchParams.get("model")?.trim();
    if (modelParam && /^[a-zA-Z0-9._-]+$/.test(modelParam)) {
      requestedModel = modelParam;
    }
  } catch {
    // Keep default baseUrl and model
  }

  const [doc, deepBundle, registry, models] = await Promise.all([
    getLiveOrCachedVerification(),
    getDeepAttestationBundle(),
    withTimeout(listNodes(), 3500, null),
    fetchLiveGatewayModels(),
  ]);

  const modelAttestation =
    deepBundle?.models?.[requestedModel] ?? deepBundle?.models?.["kimi-k3"];

  const checks: CheckResult[] | null = doc
    ? checksFromDocument(doc, modelAttestation).map((c) =>
        c.id === "C6" ? buildRegistryCheck(registry) : c,
      )
    : null;

  const harnessConfigs = buildHarnessConfigs(baseUrl);
  const isStub = process.env.DROUTER_STUB_UPSTREAM === "1";
  const allChecksOk = checks ? checks.every((c) => c.status !== "fail") : false;
  const ok = isStub ? true : Boolean(doc?.securityVerified && allChecksOk);

  return Response.json(
    {
      ok,
      verifiedAt: doc?.verifiedAt ?? new Date().toISOString(),
      checks: checks ?? [],
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
            checks: checks ?? [],
            routerSnpReport: deepBundle?.routerSnpReport ?? null,
            modelAttestation: modelAttestation ?? null,
            registry: registry
              ? {
                  source: registry.source,
                  address: registry.address ?? null,
                }
              : null,
          }
        : null,
      models,
      harnessConfigs,
    },
    {
      status: 200,
      headers: CORS_HEADERS,
    },
  );
}
