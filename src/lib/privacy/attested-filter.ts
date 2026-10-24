import { mechanicalRedact } from "./mechanical";

export const TINFOIL_PII_FILTER_MODEL_ID = "pii-filter" as const;
export const TINFOIL_PII_FILTER_ENCLAVE_URL = "https://pii-filter.tinfoil.sh" as const;
export const TINFOIL_PII_FILTER_REDACT_URL = "https://pii-filter.tinfoil.sh/redact" as const;
export const TINFOIL_PII_FILTER_CONFIG_REPO = "tinfoilsh/confidential-pii-cpu" as const;

export interface AttestedPiiDetectedSpan {
  label: string;
  start: number;
  end: number;
  text: string;
  placeholder: string;
}

export interface AttestedPiiFilterResult {
  text: string;
  redactionCount: number;
  model: string;
  verified: boolean;
}

export interface AttestedPiiFilterOptions {
  apiKey?: string;
  customTerms?: string[];
}

export interface AttestedPiiSecureClientLike {
  ready(): Promise<void>;
  getVerificationDocument():
    | {
        securityVerified?: boolean;
        enclaveHost?: string;
        releaseTag?: string;
      }
    | Promise<{
        securityVerified?: boolean;
        enclaveHost?: string;
        releaseTag?: string;
      }>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  reset?(): void;
}

interface TinfoilPiiRedactWireResponse {
  schema_version?: number;
  summary?: {
    output_mode?: string;
    span_count?: number;
    by_label?: Record<string, number>;
    decoded_mismatch?: boolean;
  };
  text?: string;
  detected_spans?: AttestedPiiDetectedSpan[];
  redacted_text?: string;
  warning?: string | null;
}

interface CachedVerifiedPiiClient {
  client: AttestedPiiSecureClientLike;
  enclaveHost: string;
  releaseTag?: string;
  securityVerified: boolean;
}

const globalForAttestedPii = globalThis as unknown as {
  __drouterVerifiedPiiClientPromise?: Promise<CachedVerifiedPiiClient>;
  __drouterAttestedPiiResultCache?: Map<string, AttestedPiiFilterResult>;
  __drouterTestPiiSecureClient?: AttestedPiiSecureClientLike | null;
};

function getResultCache(): Map<string, AttestedPiiFilterResult> {
  if (!globalForAttestedPii.__drouterAttestedPiiResultCache) {
    globalForAttestedPii.__drouterAttestedPiiResultCache = new Map<
      string,
      AttestedPiiFilterResult
    >();
  }
  return globalForAttestedPii.__drouterAttestedPiiResultCache;
}

export function setAttestedPiiFilterClientForTests(
  client: AttestedPiiSecureClientLike | null,
): void {
  globalForAttestedPii.__drouterTestPiiSecureClient = client;
  globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
}

export function clearAttestedPiiFilterCacheForTests(): void {
  globalForAttestedPii.__drouterAttestedPiiResultCache?.clear();
  globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
}

function resolveTinfoilApiKey(explicitKey?: string): string | null {
  if (explicitKey && explicitKey.trim().length > 0) {
    return explicitKey.trim();
  }
  if (typeof process !== "undefined" && process.env?.TINFOIL_API_KEY) {
    const trimmed = process.env.TINFOIL_API_KEY.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

function buildMechanicalFallback(
  text: string,
  customTerms?: string[],
): AttestedPiiFilterResult {
  const d3 = mechanicalRedact(text, { customTerms });
  return {
    text: d3.text,
    redactionCount: d3.redactions.length,
    model: TINFOIL_PII_FILTER_MODEL_ID,
    verified: false,
  };
}

async function getVerifiedPiiSecureClient(): Promise<CachedVerifiedPiiClient> {
  if (globalForAttestedPii.__drouterTestPiiSecureClient) {
    const mockClient = globalForAttestedPii.__drouterTestPiiSecureClient;
    await mockClient.ready();
    const doc = await mockClient.getVerificationDocument();
    return {
      client: mockClient,
      enclaveHost: doc?.enclaveHost || "pii-filter.tinfoil.sh",
      releaseTag: doc?.releaseTag,
      securityVerified: Boolean(doc?.securityVerified),
    };
  }

  if (!globalForAttestedPii.__drouterVerifiedPiiClientPromise) {
    globalForAttestedPii.__drouterVerifiedPiiClientPromise = (async () => {
      // Dynamic import ensures the tinfoil SDK never enters client bundles
      const { SecureClient } = await import("tinfoil");
      const client = new SecureClient({
        enclaveURL: TINFOIL_PII_FILTER_ENCLAVE_URL,
        configRepo: TINFOIL_PII_FILTER_CONFIG_REPO,
      });
      await client.ready();
      const doc = client.getVerificationDocument();
      return {
        client: client as unknown as AttestedPiiSecureClientLike,
        enclaveHost: doc?.enclaveHost || "pii-filter.tinfoil.sh",
        releaseTag: doc?.releaseTag,
        securityVerified: Boolean(doc?.securityVerified),
      };
    })().catch((err) => {
      globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
      throw err;
    });
  }

  return globalForAttestedPii.__drouterVerifiedPiiClientPromise;
}

/**
 * Attested second-pass PII filter (D4).
 *
 * Server-only: dynamically imports the `tinfoil` SDK (`SecureClient`) and calls
 * Tinfoil's live `pii-filter` enclave (`https://pii-filter.tinfoil.sh/redact`,
 * verified against `tinfoilsh/confidential-pii-cpu`) over HPKE/EHBP so raw text
 * is only ever decrypted inside a hardware-attested AMD SEV-SNP enclave.
 *
 * If called in a browser, without `TINFOIL_API_KEY`, when `DROUTER_STUB_UPSTREAM=1`,
 * or when the enclave is unreachable or fails attestation verification, falls back
 * cleanly to deterministic `mechanicalRedact` (D3) and sets `verified: false`.
 */
export async function attestedPiiFilter(
  text: string,
  opts?: AttestedPiiFilterOptions,
): Promise<AttestedPiiFilterResult> {
  if (!text || text.trim().length === 0) {
    return {
      text: text ?? "",
      redactionCount: 0,
      model: TINFOIL_PII_FILTER_MODEL_ID,
      verified: false,
    };
  }

  // Never execute server enclave calls from a browser environment
  if (typeof window !== "undefined" && !globalForAttestedPii.__drouterTestPiiSecureClient) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  if (
    typeof process !== "undefined" &&
    process.env?.DROUTER_STUB_UPSTREAM === "1" &&
    !globalForAttestedPii.__drouterTestPiiSecureClient
  ) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  const cache = getResultCache();
  if (!globalForAttestedPii.__drouterTestPiiSecureClient) {
    const cached = cache.get(text);
    if (cached && cached.verified) {
      return cached;
    }
  }

  const apiKey = resolveTinfoilApiKey(opts?.apiKey);
  if (!apiKey && !globalForAttestedPii.__drouterTestPiiSecureClient) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  try {
    const verifiedSession = await getVerifiedPiiSecureClient();
    if (!verifiedSession.securityVerified) {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const res = await verifiedSession.client.fetch(TINFOIL_PII_FILTER_REDACT_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey ?? "test-token"}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text }),
    });

    if (!res.ok) {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const payload = (await res.json()) as TinfoilPiiRedactWireResponse;
    if (!payload || typeof payload.redacted_text !== "string") {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const spanCount = Array.isArray(payload.detected_spans)
      ? payload.detected_spans.length
      : typeof payload.summary?.span_count === "number"
        ? payload.summary.span_count
        : 0;

    const result: AttestedPiiFilterResult = {
      text: payload.redacted_text,
      redactionCount: Math.max(0, spanCount),
      model: TINFOIL_PII_FILTER_MODEL_ID,
      verified: true,
    };

    if (!globalForAttestedPii.__drouterTestPiiSecureClient) {
      cache.set(text, result);
    }

    return result;
  } catch {
    globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
    return buildMechanicalFallback(text, opts?.customTerms);
  }
}
