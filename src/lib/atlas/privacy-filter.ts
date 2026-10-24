import { mechanicalRedact as realMechanicalRedact } from "@/lib/privacy/mechanical";
import { attestedPiiFilter as realAttestedPiiFilter } from "@/lib/privacy/attested-filter";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { createSessionScrubber } from "@/lib/privacy/scrubber";

export interface MechanicalRedactionItem {
  kind: string;
  placeholder: string;
}

export interface MechanicalRedactResult {
  text: string;
  redactions: MechanicalRedactionItem[];
  restore(s: string): string;
}

export type MechanicalRedactFn = (
  text: string,
  opts?: { customTerms?: string[] },
) => MechanicalRedactResult;

export interface AttestedPiiFilterResult {
  text: string;
  redactionCount: number;
  model: string;
  verified: boolean;
}

export type AttestedPiiFilterFn = (text: string) => Promise<AttestedPiiFilterResult>;

export interface AtlasQueryRedactionReport {
  /** Which redaction filter ran before the query left the enclave boundary for MongoDB. */
  filterRan: "mechanical+attested" | "mechanical-only";
  filtersApplied: Array<"mechanical" | "attested-pii-filter">;
  /** Total count of redacted spans across D3 and D4 (counts only; query text is never stored or logged). */
  totalRedactions: number;
  /** Redaction counts grouped by category/kind (counts only). */
  countsByKind: Record<string, number>;
  mechanical: {
    ran: true;
    redactionCount: number;
    countsByKind: Record<string, number>;
  };
  attested: {
    ran: boolean;
    verified: boolean;
    model: string;
    redactionCount: number;
    fallbackToMechanicalOnly: boolean;
    note: string;
  };
}

const globalForAtlasPrivacy = globalThis as unknown as {
  __drouterTestMechanicalRedactor?: MechanicalRedactFn | null;
  __drouterTestAttestedPiiFilter?: AttestedPiiFilterFn | null;
  __drouterCleanD4DigestCache?: Map<string, { model: string; verified: boolean }>;
};

function getCleanD4DigestCache(): Map<string, { model: string; verified: boolean }> {
  if (!globalForAtlasPrivacy.__drouterCleanD4DigestCache) {
    globalForAtlasPrivacy.__drouterCleanD4DigestCache = new Map();
  }
  return globalForAtlasPrivacy.__drouterCleanD4DigestCache;
}

export function setAtlasMechanicalRedactorForTests(fn: MechanicalRedactFn | null): void {
  globalForAtlasPrivacy.__drouterTestMechanicalRedactor = fn;
}

export function setAtlasAttestedPiiFilterForTests(fn: AttestedPiiFilterFn | null): void {
  globalForAtlasPrivacy.__drouterTestAttestedPiiFilter = fn;
}

export function clearAtlasPrivacyCachesForTests(): void {
  globalForAtlasPrivacy.__drouterCleanD4DigestCache?.clear();
}

export function hashTextSha256Hex(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

/**
 * Technical domain phrases in the confidential computing corpus that use Title Case
 * but are hardware/protocol terms rather than person names.
 */
const TECHNICAL_TITLE_CASE_ALLOWLIST = new Set<string>([
  "trusted execution",
  "trusted execution environment",
  "trusted execution environments",
  "confidential computing",
  "confidential inference",
  "confidentialinference",
  "confidential vm",
  "confidential vms",
  "confidential mode",
  "memory bus",
  "memory bus interposition",
  "memory bus interposer",
  "active memory",
  "active memory interposer",
  "vector search",
  "atlas search",
  "atlas vector",
  "atlas vector search",
  "hybrid search",
  "reciprocal rank",
  "reciprocal rank fusion",
  "rank fusion",
  "blind signature",
  "blind signatures",
  "rsa blind",
  "chaumian rsa",
  "secret sharing",
  "circle arc",
  "arc testnet",
  "fault injection",
  "voltage glitching",
  "voltage fault",
  "ciphertext hiding",
  "ciphertext side",
  "reverse map",
  "reverse map table",
  "serial presence",
  "serial presence detect",
  "serial voltage",
  "extended page",
  "extended page table",
  "secure extended",
  "fabric link",
  "fabric link replay",
  "link replay",
  "replay test",
  "fabric link replay test",
  "phala cloud",
  "prem ai",
  "near ai",
  "confidential ai",
  "edgeless systems",
  "voxtral small",
  "voxtral mini",
  "whisper large",
  "deepgram nova",
  "llama",
  "gemma",
  "kimi",
  "deepseek",
  "nemotron",
  "blackwell",
  "hopper",
  "turin",
  "genoa",
  "milan",
  "sigstore rekor",
  "encrypted http",
  "attested tls",
  "gateway attestation",
  "on-chain attestation",
  "channel binding",
  "route binding",
  "source provenance",
  "workload identity",
]);

function computeShannonEntropy(token: string): number {
  if (!token) return 0;
  const counts = new Map<string, number>();
  for (let i = 0; i < token.length; i++) {
    const ch = token[i];
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = token.length;
  for (const c of counts.values()) {
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isHighEntropySecretToken(token: string): boolean {
  const cleaned = token.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
  if (cleaned.length < 16) return false;
  // Ignore existing placeholders like [SECRET_1]
  if (/^\[[A-Z0-9_]+\]$/.test(token)) return false;
  // Ignore hyphenated lowercase technical identifiers (e.g., pqc-hybrid-ml-kem-768)
  if (/^[a-z]+(?:-[a-z0-9]{1,8})+$/.test(cleaned) && !/\d{4,}/.test(cleaned)) {
    return false;
  }
  const hasLower = /[a-z]/.test(cleaned);
  const hasUpper = /[A-Z]/.test(cleaned);
  const hasDigit = /\d/.test(cleaned);
  const classCount = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0);
  const isHexLike = /^[0-9a-fA-F]{20,}$/.test(cleaned);
  if (!isHexLike && classCount < 2) return false;
  if (!hasDigit && classCount < 3) return false;
  const entropy = computeShannonEntropy(cleaned);
  return entropy >= 3.75;
}



async function resolveMechanicalRedactFn(): Promise<MechanicalRedactFn> {
  if (globalForAtlasPrivacy.__drouterTestMechanicalRedactor) {
    return globalForAtlasPrivacy.__drouterTestMechanicalRedactor;
  }
  return realMechanicalRedact as MechanicalRedactFn;
}

async function resolveAttestedPiiFilterFn(): Promise<AttestedPiiFilterFn | null> {
  if (globalForAtlasPrivacy.__drouterTestAttestedPiiFilter !== undefined) {
    return globalForAtlasPrivacy.__drouterTestAttestedPiiFilter;
  }
  return realAttestedPiiFilter as AttestedPiiFilterFn;
}

/**
 * Runs D3 (`mechanicalRedact`) and, on the server when available, D4 (`attestedPiiFilter`)
 * before any query or text leaves the enclave boundary for MongoDB Atlas.
 * Never logs or stores raw query text. Returns the redacted text and a counts-only report.
 */
export async function redactForAtlasBoundary(
  rawText: string,
  opts?: {
    customTerms?: string[];
    skipAttestedPass?: boolean;
  },
): Promise<{
  text: string;
  redaction: AtlasQueryRedactionReport;
}> {
  const mechanicalFn = await resolveMechanicalRedactFn();
  let d3Result: MechanicalRedactResult;
  // Fail closed: if the mechanical filter throws, the query is rejected, never sent unfiltered.
  d3Result = mechanicalFn(rawText || "", opts);

  const mechanicalCountsByKind: Record<string, number> = {};
  for (const item of d3Result.redactions) {
    const k = (item.kind || "REDACTED").toUpperCase();
    mechanicalCountsByKind[k] = (mechanicalCountsByKind[k] ?? 0) + 1;
  }
  const mechanicalRedactionCount = d3Result.redactions.length;

  const combinedCountsByKind: Record<string, number> = { ...mechanicalCountsByKind };
  let finalText = d3Result.text;
  let attestedRan = false;
  let attestedVerified = false;
  let attestedModel = "pii-filter";
  let attestedRedactionCount = 0;
  let fallbackToMechanicalOnly = true;
  let attestedNote =
    "Attested pii-filter unavailable; fell back to deterministic mechanicalRedact (D3) only.";

  const shouldAttemptAttested =
    !opts?.skipAttestedPass &&
    (Boolean(globalForAtlasPrivacy.__drouterTestAttestedPiiFilter) ||
      Boolean(process.env.TINFOIL_API_KEY?.trim()));

  if (shouldAttemptAttested && finalText.trim().length > 0) {
    const d3Digest = hashTextSha256Hex(finalText);
    const cleanDigestCache = getCleanD4DigestCache();
    const cachedClean =
      !globalForAtlasPrivacy.__drouterTestAttestedPiiFilter
        ? cleanDigestCache.get(d3Digest)
        : undefined;

    if (cachedClean) {
      attestedRan = true;
      attestedVerified = cachedClean.verified;
      attestedModel = cachedClean.model;
      attestedRedactionCount = 0;
      fallbackToMechanicalOnly = false;
      attestedNote =
        "Attested enclave second pass (pii-filter) verified 0 additional PII spans after D3.";
    } else {
      const attestedFn = await resolveAttestedPiiFilterFn();
      if (attestedFn) {
        try {
          const d4Result = await attestedFn(finalText);
          if (d4Result && d4Result.verified && typeof d4Result.text === "string") {
            attestedRan = true;
            attestedVerified = true;
            attestedModel = d4Result.model || "pii-filter";
            attestedRedactionCount = Math.max(0, Number(d4Result.redactionCount ?? 0));
            finalText = d4Result.text;
            fallbackToMechanicalOnly = false;
            if (attestedRedactionCount > 0) {
              combinedCountsByKind.ATTESTED_PII =
                (combinedCountsByKind.ATTESTED_PII ?? 0) + attestedRedactionCount;
            } else if (!globalForAtlasPrivacy.__drouterTestAttestedPiiFilter) {
              cleanDigestCache.set(d3Digest, {
                model: attestedModel,
                verified: true,
              });
            }
            attestedNote =
              "Attested enclave second pass (pii-filter) verified and completed.";
          } else {
            attestedModel = d4Result?.model || "pii-filter";
            attestedNote =
              "Attested pii-filter did not verify enclave security; fell back to deterministic mechanicalRedact (D3) only.";
          }
        } catch {
          attestedNote =
            "Attested pii-filter call failed or unreachable; fell back to deterministic mechanicalRedact (D3) only.";
        }
      }
    }
  }

  const totalRedactions = mechanicalRedactionCount + attestedRedactionCount;
  const filterRan: "mechanical+attested" | "mechanical-only" =
    attestedRan && attestedVerified ? "mechanical+attested" : "mechanical-only";
  const filtersApplied: Array<"mechanical" | "attested-pii-filter"> =
    filterRan === "mechanical+attested"
      ? ["mechanical", "attested-pii-filter"]
      : ["mechanical"];

  return {
    text: finalText,
    redaction: {
      filterRan,
      filtersApplied,
      totalRedactions,
      countsByKind: combinedCountsByKind,
      mechanical: {
        ran: true,
        redactionCount: mechanicalRedactionCount,
        countsByKind: mechanicalCountsByKind,
      },
      attested: {
        ran: attestedRan,
        verified: attestedVerified,
        model: attestedModel,
        redactionCount: attestedRedactionCount,
        fallbackToMechanicalOnly,
        note: attestedNote,
      },
    },
  };
}

/**
 * Removes bracketed redaction placeholders (e.g. `[EMAIL_1]`, `[SECRET_1]`, `[REDACTED]`)
 * when computing lexical/vector similarity scores so placeholder tokens do not dilute
 * relevance on the remaining non-PII technical search terms.
 */
export function stripRedactionPlaceholdersForScoring(redactedText: string): string {
  const stripped = (redactedText || "")
    .replace(/\[[A-Z0-9_]+(?:_\d+)?\]/gi, " ")
    .replace(/<REDACTED[^>]*>/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  return stripped || "confidential enclave";
}
