import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { padJsonPayloadToBucket } from "@/lib/relay";
import { mechanicalRedact } from "./mechanical";

export const TINFOIL_PII_FILTER_MODEL_ID = "pii-filter" as const;
export const TINFOIL_PII_FILTER_ENCLAVE_URL = "https://pii-filter.tinfoil.sh" as const;
export const TINFOIL_PII_FILTER_REDACT_URL = "https://pii-filter.tinfoil.sh/redact" as const;
export const TINFOIL_PII_FILTER_CONFIG_REPO = "tinfoilsh/confidential-pii-cpu" as const;
export const MAX_ATTESTED_PII_CACHE_ENTRIES = 256 as const;

export function hashAttestedPiiInputSha256(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

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
  detectedSpans?: AttestedPiiDetectedSpan[];
}

export interface AttestedPiiFilterOptions {
  apiKey?: string;
  customTerms?: string[];
  useRelay?: boolean;
  relayOrigin?: string;
  includeSpans?: boolean;
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
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
}

interface CachedVerifiedPiiClient {
  client: AttestedPiiSecureClientLike;
  enclaveHost: string;
  releaseTag?: string;
  securityVerified: boolean;
  viaRelay: boolean;
}

const globalForAttestedPii = globalThis as unknown as {
  __drouterVerifiedPiiClientPromise?: Promise<CachedVerifiedPiiClient>;
  __drouterVerifiedPiiRelayClientPromise?: Promise<CachedVerifiedPiiClient>;
  __drouterAttestedPiiResultCache?: Map<string, AttestedPiiFilterResult>;
  __drouterTestPiiSecureClient?: AttestedPiiSecureClientLike | null;
  __drouterTestPiiSecureClientFactory?:
    | ((opts: Record<string, unknown>) => AttestedPiiSecureClientLike)
    | null;
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

function setBoundedResultCacheEntry(
  cache: Map<string, AttestedPiiFilterResult>,
  digestKey: string,
  value: AttestedPiiFilterResult,
  maxEntries: number = MAX_ATTESTED_PII_CACHE_ENTRIES,
): void {
  if (cache.has(digestKey)) {
    cache.delete(digestKey);
  }
  while (cache.size >= maxEntries) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey === undefined) break;
    cache.delete(oldestKey);
  }
  cache.set(digestKey, value);
}

export function setAttestedPiiFilterClientForTests(
  client: AttestedPiiSecureClientLike | null,
): void {
  globalForAttestedPii.__drouterTestPiiSecureClient = client;
  globalForAttestedPii.__drouterAttestedPiiResultCache?.clear();
  globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
  globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = undefined;
}

export function setAttestedPiiSecureClientFactoryForTests(
  factory:
    | ((opts: Record<string, unknown>) => AttestedPiiSecureClientLike)
    | null,
): void {
  globalForAttestedPii.__drouterTestPiiSecureClientFactory = factory;
  globalForAttestedPii.__drouterAttestedPiiResultCache?.clear();
  globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
  globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = undefined;
}

export function clearAttestedPiiFilterCacheForTests(): void {
  globalForAttestedPii.__drouterAttestedPiiResultCache?.clear();
  globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
  globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = undefined;
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

async function getVerifiedPiiSecureClient(opts?: {
  useRelay?: boolean;
  relayOrigin?: string;
}): Promise<CachedVerifiedPiiClient> {
  if (globalForAttestedPii.__drouterTestPiiSecureClient) {
    const mockClient = globalForAttestedPii.__drouterTestPiiSecureClient;
    await mockClient.ready();
    const doc = await mockClient.getVerificationDocument();
    return {
      client: mockClient,
      enclaveHost: doc?.enclaveHost ?? "",
      releaseTag: doc?.releaseTag,
      securityVerified: Boolean(doc?.securityVerified),
      viaRelay: Boolean(opts?.useRelay) || typeof window !== "undefined",
    };
  }

  const viaRelay =
    Boolean(opts?.useRelay) || typeof window !== "undefined";

  if (viaRelay) {
    if (!globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise) {
      globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = (async () => {
        const origin =
          opts?.relayOrigin ??
          (typeof window !== "undefined" && window.location?.origin
            ? window.location.origin
            : "https://localhost");
        const baseURL = `${origin}/api/relay/v1/`;
        const attestationBundleURL = origin.startsWith("https://")
          ? `${origin}/api/relay`
          : undefined;

        const clientOptions = {
          baseURL,
          enclaveURL: TINFOIL_PII_FILTER_ENCLAVE_URL,
          configRepo: TINFOIL_PII_FILTER_CONFIG_REPO,
          attestationBundleURL,
        };

        const client = globalForAttestedPii.__drouterTestPiiSecureClientFactory
          ? globalForAttestedPii.__drouterTestPiiSecureClientFactory(
              clientOptions,
            )
          : new (await import("tinfoil")).SecureClient(clientOptions);

        await client.ready();
        const doc = await client.getVerificationDocument();

        // Wrap internal transport fetch to pad JSON payloads to 4096-byte power-of-two buckets,
        // attach X-Tinfoil-Model: pii-filter before HPKE sealing, and strip any SDK-injected
        // user_cache_secret (which pii-filter's strict /redact schema rejects with HTTP 422).
        const internalTransport = (
          client as unknown as {
            _transport?: {
              fetch: (
                input: RequestInfo | URL,
                init?: RequestInit,
              ) => Promise<Response>;
            };
          }
        )._transport;

        if (internalTransport && typeof internalTransport.fetch === "function") {
          const origFetch = internalTransport.fetch.bind(internalTransport);
          internalTransport.fetch = async (
            input: RequestInfo | URL,
            init?: RequestInit,
          ) => {
            const headers = new Headers(init?.headers);
            if (!headers.has("X-Tinfoil-Model")) {
              headers.set("X-Tinfoil-Model", TINFOIL_PII_FILTER_MODEL_ID);
            }
            const normalizedUrl =
              typeof input === "string"
                ? input === "chat/completions" ||
                  input.endsWith("/chat/completions")
                  ? input.replace(/chat\/completions$/, "redact")
                  : input
                : input;
            let nextBody = init?.body;
            if (typeof nextBody === "string") {
              try {
                const parsed = JSON.parse(nextBody) as Record<string, unknown>;
                if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
                  const textField =
                    typeof parsed.text === "string"
                      ? parsed.text
                      : Array.isArray(parsed.messages) &&
                          typeof (
                            parsed.messages[0] as
                              | { content?: unknown }
                              | undefined
                          )?.content === "string"
                        ? String(
                            (parsed.messages[0] as { content: string }).content,
                          )
                        : "";
                  const { paddedJson } = padJsonPayloadToBucket(
                    JSON.stringify({ text: textField }),
                    4096,
                  );
                  nextBody = paddedJson;
                }
              } catch {
                // Non-JSON body; leave unchanged.
              }
            }
            return origFetch(normalizedUrl, {
              ...init,
              headers,
              body: nextBody,
            });
          };
        }

        return {
          client: client as unknown as AttestedPiiSecureClientLike,
          enclaveHost: doc?.enclaveHost ?? "",
          releaseTag: doc?.releaseTag,
          securityVerified: Boolean(doc?.securityVerified),
          viaRelay: true,
        };
      })().catch((err) => {
        globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = undefined;
        throw err;
      });
    }
    return globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise;
  }

  if (!globalForAttestedPii.__drouterVerifiedPiiClientPromise) {
    globalForAttestedPii.__drouterVerifiedPiiClientPromise = (async () => {
      const { SecureClient } = await import("tinfoil");
      const client = new SecureClient({
        enclaveURL: TINFOIL_PII_FILTER_ENCLAVE_URL,
        configRepo: TINFOIL_PII_FILTER_CONFIG_REPO,
      });
      await client.ready();
      const doc = client.getVerificationDocument();
      return {
        client: client as unknown as AttestedPiiSecureClientLike,
        enclaveHost: doc?.enclaveHost ?? "",
        releaseTag: doc?.releaseTag,
        securityVerified: Boolean(doc?.securityVerified),
        viaRelay: false,
      };
    })().catch((err) => {
      globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
      throw err;
    });
  }

  return globalForAttestedPii.__drouterVerifiedPiiClientPromise;
}

function parsePiiFilterWirePayload(
  payload: TinfoilPiiRedactWireResponse | null,
): {
  redactedText: string;
  spanCount: number;
  detectedSpans?: AttestedPiiDetectedSpan[];
} | null {
  if (!payload || typeof payload !== "object") return null;

  if (typeof payload.redacted_text === "string") {
    const detectedSpans = Array.isArray(payload.detected_spans)
      ? payload.detected_spans
      : undefined;
    const spanCount = detectedSpans
      ? detectedSpans.length
      : typeof payload.summary?.span_count === "number"
        ? payload.summary.span_count
        : (payload.redacted_text.match(/<PRIVATE_[A-Z0-9_]+>/g) ?? []).length;
    return {
      redactedText: payload.redacted_text,
      spanCount: Math.max(0, spanCount),
      detectedSpans,
    };
  }

  const chatContent = payload.choices?.[0]?.message?.content;
  if (typeof chatContent === "string" && chatContent.trim().length > 0) {
    try {
      const inner = JSON.parse(chatContent) as TinfoilPiiRedactWireResponse;
      if (inner && typeof inner.redacted_text === "string") {
        return parsePiiFilterWirePayload(inner);
      }
    } catch {
      // Plain text completion from pii-filter model
    }
    const tagMatches = chatContent.match(/<PRIVATE_[A-Z0-9_]+>/g) ?? [];
    return {
      redactedText: chatContent,
      spanCount: tagMatches.length,
    };
  }

  return null;
}

/**
 * Attested second-pass PII filter (D4).
 *
 * Usable both from the browser through the oblivious relay (`/api/relay/v1/...`,
 * without any API key in the browser) and on the server. Calls Tinfoil's
 * `pii-filter` enclave over HPKE/EHBP so text is only ever decrypted inside a
 * hardware-attested enclave.
 *
 * When the enclave or relay is unreachable or fails attestation verification,
 * falls back cleanly to deterministic `mechanicalRedact` (D3) and sets `verified: false`.
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

  if (
    typeof process !== "undefined" &&
    process.env?.DROUTER_STUB_UPSTREAM === "1" &&
    !globalForAttestedPii.__drouterTestPiiSecureClient
  ) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  const isBrowserOrRelay =
    Boolean(opts?.useRelay) || typeof window !== "undefined";

  // In Vitest unit tests without a mock client or live browser window, avoid network calls when useRelay is set
  if (
    isBrowserOrRelay &&
    typeof window === "undefined" &&
    typeof process !== "undefined" &&
    process.env?.VITEST === "true" &&
    !globalForAttestedPii.__drouterTestPiiSecureClient &&
    !globalForAttestedPii.__drouterTestPiiSecureClientFactory &&
    !opts?.relayOrigin
  ) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  const cache = getResultCache();
  const cacheKey = hashAttestedPiiInputSha256(text);
  if (!opts?.includeSpans) {
    const cached = cache.get(cacheKey);
    if (cached && cached.verified) {
      cache.delete(cacheKey);
      cache.set(cacheKey, cached);
      return cached;
    }
  }

  const apiKey = resolveTinfoilApiKey(opts?.apiKey);
  if (
    !isBrowserOrRelay &&
    !apiKey &&
    !globalForAttestedPii.__drouterTestPiiSecureClient
  ) {
    return buildMechanicalFallback(text, opts?.customTerms);
  }

  try {
    const verifiedSession = await getVerifiedPiiSecureClient({
      useRelay: isBrowserOrRelay,
      relayOrigin: opts?.relayOrigin,
    });
    // Only the attested pii-filter enclave may receive text for the second pass.
    if (
      !verifiedSession.securityVerified ||
      verifiedSession.enclaveHost !== new URL(TINFOIL_PII_FILTER_ENCLAVE_URL).host
    ) {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const res = verifiedSession.viaRelay
      ? await verifiedSession.client.fetch("chat/completions", {
          method: "POST",
          headers: {
            Authorization: "Bearer drouter-demo",
            "Content-Type": "application/json",
            "X-Tinfoil-Model": TINFOIL_PII_FILTER_MODEL_ID,
          },
          body: padJsonPayloadToBucket(
            JSON.stringify({
              text,
              model: TINFOIL_PII_FILTER_MODEL_ID,
              messages: [{ role: "user", content: text }],
              stream: false,
            }),
            4096,
          ).paddedJson,
        })
      : await verifiedSession.client.fetch(TINFOIL_PII_FILTER_REDACT_URL, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey ?? "test-token"}`,
            "Content-Type": "application/json",
          },
          body: padJsonPayloadToBucket(JSON.stringify({ text }), 4096)
            .paddedJson,
        });

    if (!res.ok) {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const rawPayload = (await res.json()) as TinfoilPiiRedactWireResponse;
    const parsed = parsePiiFilterWirePayload(rawPayload);
    if (!parsed) {
      return buildMechanicalFallback(text, opts?.customTerms);
    }

    const result: AttestedPiiFilterResult = {
      text: parsed.redactedText,
      redactionCount: parsed.spanCount,
      model: TINFOIL_PII_FILTER_MODEL_ID,
      verified: true,
      ...(opts?.includeSpans && parsed.detectedSpans
        ? { detectedSpans: parsed.detectedSpans }
        : {}),
    };

    if (!opts?.includeSpans) {
      setBoundedResultCacheEntry(cache, cacheKey, result);
    }

    return result;
  } catch {
    globalForAttestedPii.__drouterVerifiedPiiClientPromise = undefined;
    globalForAttestedPii.__drouterVerifiedPiiRelayClientPromise = undefined;
    return buildMechanicalFallback(text, opts?.customTerms);
  }
}
