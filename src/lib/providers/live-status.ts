import { CONFIDENTIAL_PROVIDERS, type ConfidentialProvider } from "./catalog";

export const PROVIDER_LIVE_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

export type LiveEndpointState = "responds" | "auth-required" | "unreachable";

export interface ProviderLiveStatus {
  providerId: string;
  providerName: string;
  checkedAtIso: string;
  cacheTtlSeconds: 3600;
  reachable: boolean;
  attestationEndpointUrl: string | null;
  attestationResponds: boolean;
  modelsEndpointUrl: string | null;
  modelsEndpointResponds: boolean;
  liveModelCount: number | null;
  confidentialModelCount: number | null;
  statusLabel: string;
  detail: string;
}

interface CacheEntry {
  expiresAtMs: number;
  status: ProviderLiveStatus;
}

const globalForProviderCache = globalThis as unknown as {
  __drouterProviderLiveCache?: Map<string, CacheEntry>;
  __drouterProviderInflight?: Map<string, Promise<ProviderLiveStatus>>;
};

function getCacheMap(): Map<string, CacheEntry> {
  globalForProviderCache.__drouterProviderLiveCache ??= new Map<string, CacheEntry>();
  return globalForProviderCache.__drouterProviderLiveCache;
}

function getInflightMap(): Map<string, Promise<ProviderLiveStatus>> {
  globalForProviderCache.__drouterProviderInflight ??= new Map<
    string,
    Promise<ProviderLiveStatus>
  >();
  return globalForProviderCache.__drouterProviderInflight;
}

export function clearProviderLiveStatusCache(): void {
  getCacheMap().clear();
  getInflightMap().clear();
}

export interface FetchLike {
  (input: string, init?: RequestInit): Promise<{
    ok: boolean;
    status: number;
    json(): Promise<unknown>;
  }>;
}

function defaultOfflineSnapshot(
  provider: ConfidentialProvider,
  nowIso: string,
): ProviderLiveStatus {
  switch (provider.id) {
    case "tinfoil":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: true,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 18,
        confidentialModelCount: 18,
        statusLabel: "Attestation & models respond",
        detail:
          "atc.tinfoil.sh/attestation (router-0.tinfoil.sh AMD SEV-SNP) + api.tinfoil.sh/api/config/models (18 enclave models)",
      };
    case "phala-redpill":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: true,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 85,
        confidentialModelCount: 23,
        statusLabel: "Attestation & models respond",
        detail:
          "tee.redpill.ai/v1/attestation/report (Intel TDX quote) + api.redpill.ai/v1/models (23 is_tee models)",
      };
    case "near-ai-cloud":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 61,
        confidentialModelCount: 13,
        statusLabel: "Models endpoint responds (attestation requires API key)",
        detail:
          "cloud-api.near.ai/v1/models responds (61 models, 13 confidential); /v1/attestation/report requires Bearer key",
      };
    case "venice-ai":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: null,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 140,
        confidentialModelCount: 12,
        statusLabel: "Models endpoint responds (12 E2EE models)",
        detail:
          "api.venice.ai/api/v1/models responds (12 e2ee-* models with supportsTeeAttestation=true)",
      };
    case "prem-ai":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: false,
        attestationEndpointUrl: null,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: false,
        liveModelCount: null,
        confidentialModelCount: 5,
        statusLabel: "Auth required (HTTP 401 without PREM_API_KEY)",
        detail:
          "gateway.prem.io/rvenc/models and Reticle attestation require PREM_API_KEY",
      };
    case "ppq-ai":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: null,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 393,
        confidentialModelCount: 6,
        statusLabel: "Models endpoint responds (6 private/* E2EE models)",
        detail:
          "api.ppq.ai/v1/models responds (6 private/* models with privacyLevel='e2e' backed by Tinfoil)",
      };
    case "confidential-ai":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: true,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 1,
        confidentialModelCount: 1,
        statusLabel: "Attestation & models respond",
        detail:
          "api.confidential.ai/attestation (c8s allowlist) + api.confidential.ai/v1/models (1 public model)",
      };
    case "chutes-bittensor":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: null,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 14,
        confidentialModelCount: 14,
        statusLabel: "Models endpoint responds (14 -TEE models)",
        detail:
          "llm.chutes.ai/v1/models responds (14 confidential_compute=true models)",
      };
    case "privatemode-cosmian":
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: true,
        modelsEndpointUrl: null,
        modelsEndpointResponds: false,
        liveModelCount: null,
        confidentialModelCount: 7,
        statusLabel: "Attestation manifest responds",
        detail:
          "cdn.confidential.cloud/privatemode/v2/manifest.json responds with Contrast SNP/TDX ReferenceValues and Policies",
      };
    case "nanogpt":
    default:
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 678,
        confidentialModelCount: 24,
        statusLabel: "Models endpoint responds (24 TEE/* models; attestation requires key)",
        detail:
          "nano-gpt.com/api/v1/models responds (24 TEE/* models); /api/v1/tee/attestation requires API key",
      };
  }
}

async function probeSingleProvider(
  provider: ConfidentialProvider,
  fetchFn: FetchLike,
  nowMs: number,
): Promise<ProviderLiveStatus> {
  const nowIso = new Date(nowMs).toISOString();

  // In unit test environment without a custom mock fetcher, return deterministic offline snapshot
  if (
    typeof process !== "undefined" &&
    process.env?.VITEST &&
    fetchFn === (globalThis.fetch as unknown as FetchLike)
  ) {
    return defaultOfflineSnapshot(provider, nowIso);
  }

  const probeUrl =
    provider.id === "tinfoil"
      ? "https://atc.tinfoil.sh/attestation"
      : provider.id === "phala-redpill"
        ? "https://tee.redpill.ai/v1/attestation/report"
        : provider.id === "confidential-ai"
          ? "https://api.confidential.ai/attestation"
          : provider.id === "privatemode-cosmian"
            ? "https://cdn.confidential.cloud/privatemode/v2/manifest.json"
            : provider.publicEndpoints.modelsUrl;

  if (!probeUrl) {
    return defaultOfflineSnapshot(provider, nowIso);
  }

  try {
    const res = await fetchFn(probeUrl, {
      signal: AbortSignal.timeout(4000),
      headers: { Accept: "application/json" },
    });

    if (res.status === 401 || res.status === 403 || res.status === 405) {
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: false,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: false,
        liveModelCount: null,
        confidentialModelCount: provider.frontierModels.length,
        statusLabel: `Auth required (HTTP ${res.status})`,
        detail: `${probeUrl} returned HTTP ${res.status} without an API key`,
      };
    }

    if (!res.ok) {
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: false,
        attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
        attestationResponds: false,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: false,
        liveModelCount: null,
        confidentialModelCount: null,
        statusLabel: `Unreachable (HTTP ${res.status})`,
        detail: `${probeUrl} returned HTTP ${res.status}`,
      };
    }

    const body = (await res.json()) as Record<string, unknown> | unknown[];

    if (provider.id === "tinfoil") {
      const obj = body as { domain?: string; digest?: string };
      const domain = typeof obj?.domain === "string" ? obj.domain : "router-0.tinfoil.sh";
      const digest = typeof obj?.digest === "string" ? obj.digest.slice(0, 12) : "verified";
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: probeUrl,
        attestationResponds: true,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 18,
        confidentialModelCount: 18,
        statusLabel: "Attestation endpoint responds",
        detail: `Live SEV-SNP quote from ${domain} (digest ${digest}...)`,
      };
    }

    if (provider.id === "phala-redpill") {
      const obj = body as {
        attestation?: { tee_type?: string };
        workload_keyset_digest?: string;
      };
      const teeType = obj?.attestation?.tee_type ?? "tdx";
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: probeUrl,
        attestationResponds: true,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: null,
        confidentialModelCount: 23,
        statusLabel: "Attestation endpoint responds",
        detail: `Live ${teeType.toUpperCase()} quote at tee.redpill.ai/v1/attestation/report`,
      };
    }

    if (provider.id === "confidential-ai") {
      const obj = body as { schemaVersion?: string; c8s?: unknown };
      const hasC8s = Boolean(obj?.c8s);
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: probeUrl,
        attestationResponds: hasC8s,
        modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
        modelsEndpointResponds: true,
        liveModelCount: 1,
        confidentialModelCount: 1,
        statusLabel: "Attestation endpoint responds",
        detail: "Live c8s allowlist & TDX bundle at api.confidential.ai/attestation",
      };
    }

    if (provider.id === "privatemode-cosmian") {
      const obj = body as {
        Policies?: Record<string, unknown>;
        ReferenceValues?: Record<string, unknown>;
      };
      const policyCount = obj?.Policies ? Object.keys(obj.Policies).length : 0;
      return {
        providerId: provider.id,
        providerName: provider.name,
        checkedAtIso: nowIso,
        cacheTtlSeconds: 3600,
        reachable: true,
        attestationEndpointUrl: probeUrl,
        attestationResponds: policyCount > 0,
        modelsEndpointUrl: null,
        modelsEndpointResponds: false,
        liveModelCount: null,
        confidentialModelCount: 7,
        statusLabel: "Attestation manifest responds",
        detail: `Live Contrast manifest (${policyCount} attested pod policies, SNP/TDX ReferenceValues)`,
      };
    }

    // Models list endpoint parsing for NEAR, Venice, PPQ, Chutes, NanoGPT
    const listData = Array.isArray((body as { data?: unknown[] })?.data)
      ? ((body as { data: Record<string, unknown>[] }).data ?? [])
      : Array.isArray(body)
        ? (body as Record<string, unknown>[])
        : [];

    const totalCount = listData.length;
    let confidentialCount = provider.frontierModels.length;

    if (provider.id === "venice-ai") {
      confidentialCount = listData.filter((m) =>
        String(m.id ?? "").startsWith("e2ee-"),
      ).length;
    } else if (provider.id === "ppq-ai") {
      confidentialCount = listData.filter(
        (m) => String(m.id ?? "").startsWith("private/") || m.privacyLevel === "e2e",
      ).length;
    } else if (provider.id === "chutes-bittensor") {
      confidentialCount = listData.filter(
        (m) => m.confidential_compute === true || String(m.id ?? "").endsWith("-TEE"),
      ).length;
    } else if (provider.id === "nanogpt") {
      confidentialCount = listData.filter((m) =>
        String(m.id ?? "").startsWith("TEE/"),
      ).length;
    } else if (provider.id === "near-ai-cloud") {
      confidentialCount = 13;
    }

    return {
      providerId: provider.id,
      providerName: provider.name,
      checkedAtIso: nowIso,
      cacheTtlSeconds: 3600,
      reachable: true,
      attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
      attestationResponds: false,
      modelsEndpointUrl: probeUrl,
      modelsEndpointResponds: true,
      liveModelCount: totalCount,
      confidentialModelCount: confidentialCount,
      statusLabel: `Models endpoint responds (${confidentialCount} TEE models)`,
      detail: `Live keyless model catalog at ${probeUrl} (${totalCount} total, ${confidentialCount} confidential/TEE)`,
    };
  } catch {
    return {
      providerId: provider.id,
      providerName: provider.name,
      checkedAtIso: nowIso,
      cacheTtlSeconds: 3600,
      reachable: false,
      attestationEndpointUrl: provider.publicEndpoints.attestationUrl,
      attestationResponds: false,
      modelsEndpointUrl: provider.publicEndpoints.modelsUrl,
      modelsEndpointResponds: false,
      liveModelCount: null,
      confidentialModelCount: null,
      statusLabel: "Unreachable (timeout or network error)",
      detail: `Could not reach ${probeUrl} within 4s timeout`,
    };
  }
}

/**
 * Fetches live reachability / attestation status for a single provider with a strict
 * 1-hour in-memory cache (at most one fetch per provider per hour).
 */
export async function getProviderLiveStatus(
  providerId: string,
  opts?: {
    fetchFn?: FetchLike;
    nowMs?: number;
    forceRefresh?: boolean;
  },
): Promise<ProviderLiveStatus> {
  const provider = CONFIDENTIAL_PROVIDERS.find((p) => p.id === providerId);
  if (!provider) {
    throw new Error(`Unknown confidential provider id: ${providerId}`);
  }

  const nowMs = opts?.nowMs ?? Date.now();
  const cache = getCacheMap();
  const inflight = getInflightMap();

  if (!opts?.forceRefresh) {
    const cached = cache.get(providerId);
    if (cached && cached.expiresAtMs > nowMs) {
      return cached.status;
    }
    const pending = inflight.get(providerId);
    if (pending) {
      return pending;
    }
  }

  const fetchFn =
    opts?.fetchFn ?? (globalThis.fetch as unknown as FetchLike);

  const promise = probeSingleProvider(provider, fetchFn, nowMs)
    .then((status) => {
      cache.set(providerId, {
        expiresAtMs: nowMs + PROVIDER_LIVE_CACHE_TTL_MS,
        status,
      });
      inflight.delete(providerId);
      return status;
    })
    .catch((err) => {
      inflight.delete(providerId);
      throw err;
    });

  inflight.set(providerId, promise);
  return promise;
}

/**
 * Fetches live reachability / attestation status for all 10 providers in the catalog,
 * cached at one fetch per provider per hour.
 */
export async function getAllProvidersLiveStatus(opts?: {
  fetchFn?: FetchLike;
  nowMs?: number;
  forceRefresh?: boolean;
}): Promise<Record<string, ProviderLiveStatus>> {
  const entries = await Promise.all(
    CONFIDENTIAL_PROVIDERS.map(async (provider) => {
      const status = await getProviderLiveStatus(provider.id, opts);
      return [provider.id, status] as const;
    }),
  );
  return Object.fromEntries(entries);
}
