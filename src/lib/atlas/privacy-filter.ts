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

/**
 * Built-in fail-closed deterministic mechanical redaction filter matching D3.
 * Used if `@/lib/privacy/mechanical` is not yet available on disk; delegates to
 * `@/lib/privacy/mechanical` when present.
 */
export function fallbackMechanicalRedact(
  input: string,
  opts?: { customTerms?: string[] },
): MechanicalRedactResult {
  if (!input) {
    return {
      text: "",
      redactions: [],
      restore: (s: string) => s,
    };
  }

  const restoreMap = new Map<string, string>();
  const redactions: MechanicalRedactionItem[] = [];
  const counters: Record<string, number> = {};

  const allocatePlaceholder = (kind: string, original: string): string => {
    const normKind = kind.toUpperCase();
    counters[normKind] = (counters[normKind] ?? 0) + 1;
    const placeholder = `[${normKind}_${counters[normKind]}]`;
    restoreMap.set(placeholder, original);
    redactions.push({ kind: normKind, placeholder });
    return placeholder;
  };

  // Pass 1: Existing deterministic scrubber (SECRET, EMAIL, PHONE, IP, ACCT, ENTITY + customTerms)
  const scrubber = createSessionScrubber(opts?.customTerms ?? []);
  const pass1 = scrubber.scrub(input);
  let working = pass1.scrubbed;
  for (const rep of pass1.replacements) {
    const orig = scrubber.restore(rep.placeholder);
    restoreMap.set(rep.placeholder, orig);
    redactions.push({ kind: rep.kind, placeholder: rep.placeholder });
    const m = /^\[([A-Z]+)_(\d+)\]$/.exec(rep.placeholder);
    if (m) {
      const k = m[1];
      const n = Number(m[2]);
      counters[k] = Math.max(counters[k] ?? 0, n);
    }
  }

  const replaceOutsidePlaceholders = (
    text: string,
    regex: RegExp,
    kind: string,
    validate?: (match: string) => boolean,
  ): string => {
    const placeholderSplitRe = /(\[[A-Z0-9_]+_\d+\])/g;
    const parts = text.split(placeholderSplitRe);
    return parts
      .map((part) => {
        if (/^\[[A-Z0-9_]+_\d+\]$/.test(part)) return part;
        const re = new RegExp(regex.source, regex.flags);
        return part.replace(re, (m) => {
          if (validate && !validate(m)) return m;
          return allocatePlaceholder(kind, m);
        });
      })
      .join("");
  };

  // Pass 2: URLs and domains
  working = replaceOutsidePlaceholders(
    working,
    /\bhttps?:\/\/[^\s"'<>)\]]+/gi,
    "URL",
  );
  working = replaceOutsidePlaceholders(
    working,
    /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|sh|ai|dev|app|co|uk|eu|de|fr|jp|cn|ch|nl|se|no|fi|dk|ca|au|nz|info|biz|me|xyz|tech|cloud|local|internal)\b(?:\.[a-zA-Z]{2,3})?(?:\/[^\s"'<>)\]]*)?/gi,
    "URL",
  );

  // Pass 3: Street-address patterns (including lowercase/mixed case not caught by pass 1)
  working = replaceOutsidePlaceholders(
    working,
    /\b\d{1,6}[A-Za-z]?\s+(?:[A-Za-z0-9.'-]+\s+){1,4}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Square|Sq\.?|Circle|Cir\.?|Parkway|Pkwy\.?|Highway|Hwy\.?|Crescent|Cres\.?|Close|Grove|Gardens|Mews)\b/gi,
    "ADDRESS",
  );

  // Pass 4: Dates (ISO YYYY-MM-DD, slash/dot/hyphen dates including 2020+, and month-name dates)
  working = replaceOutsidePlaceholders(
    working,
    /\b(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])\b/g,
    "DATE",
  );
  working = replaceOutsidePlaceholders(
    working,
    /\b(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}\b/g,
    "DATE",
  );
  working = replaceOutsidePlaceholders(
    working,
    /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}\b/gi,
    "DATE",
  );
  working = replaceOutsidePlaceholders(
    working,
    /\b\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?),?\s+(?:19|20)\d{2}\b/gi,
    "DATE",
  );

  // Pass 5: Capitalized multi-word name sequences (e.g. "Jane Doe", "Dr. Robert Smith")
  working = replaceOutsidePlaceholders(
    working,
    /\b(?:(?:Dr|Mr|Mrs|Ms|Prof|Sir|Lady)\.?\s+)?[A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){1,3}\b/g,
    "NAME",
    (candidate) => {
      const norm = candidate.replace(/\s+/g, " ").trim().toLowerCase();
      if (TECHNICAL_TITLE_CASE_ALLOWLIST.has(norm)) return false;
      const words = norm.split(" ");
      if (words.every((w) => TECHNICAL_TITLE_CASE_ALLOWLIST.has(w))) return false;
      return true;
    },
  );

  // Pass 6: Any token with 4+ consecutive digits
  working = replaceOutsidePlaceholders(
    working,
    /\b[A-Za-z0-9_.:/-]*\d{4,}[A-Za-z0-9_.:/-]*\b/g,
    "DIGITS",
  );

  // Pass 7: High-entropy tokens (Shannon entropy threshold)
  working = replaceOutsidePlaceholders(
    working,
    /\b[A-Za-z0-9_+=/.-]{16,}\b/g,
    "ENTROPY",
    (token) => isHighEntropySecretToken(token),
  );

  const restore = (s: string): string => {
    if (!s || restoreMap.size === 0) return s;
    return s.replace(/\[[A-Z0-9_]+_\d+\]/g, (tok) => restoreMap.get(tok) ?? tok);
  };

  return {
    text: working,
    redactions,
    restore,
  };
}

let cachedB2MechanicalMod: { mechanicalRedact?: MechanicalRedactFn } | null = null;
let cachedB2AttestedMod: { attestedPiiFilter?: AttestedPiiFilterFn } | null = null;

async function resolveMechanicalRedactFn(): Promise<MechanicalRedactFn> {
  if (globalForAtlasPrivacy.__drouterTestMechanicalRedactor) {
    return globalForAtlasPrivacy.__drouterTestMechanicalRedactor;
  }
  if (cachedB2MechanicalMod?.mechanicalRedact) {
    return cachedB2MechanicalMod.mechanicalRedact;
  }
  try {
    const relPath = "../privacy/" + "mechanical";
    const mod = (await import(relPath)) as { mechanicalRedact?: MechanicalRedactFn };
    if (typeof mod?.mechanicalRedact === "function") {
      cachedB2MechanicalMod = mod;
      return mod.mechanicalRedact;
    }
  } catch {
    // Module not yet created by B2 or unavailable; use deterministic fail-closed fallback
  }
  return fallbackMechanicalRedact;
}

async function resolveAttestedPiiFilterFn(): Promise<AttestedPiiFilterFn | null> {
  if (globalForAtlasPrivacy.__drouterTestAttestedPiiFilter !== undefined) {
    return globalForAtlasPrivacy.__drouterTestAttestedPiiFilter;
  }
  if (cachedB2AttestedMod?.attestedPiiFilter) {
    return cachedB2AttestedMod.attestedPiiFilter;
  }
  try {
    const relPath = "../privacy/" + "attested-filter";
    const mod = (await import(relPath)) as { attestedPiiFilter?: AttestedPiiFilterFn };
    if (typeof mod?.attestedPiiFilter === "function") {
      cachedB2AttestedMod = mod;
      return mod.attestedPiiFilter;
    }
  } catch {
    // Module not yet created by B2 or unavailable
  }
  return null;
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
  try {
    d3Result = mechanicalFn(rawText || "", opts);
  } catch {
    // Fail closed if external redactor throws
    d3Result = fallbackMechanicalRedact(rawText || "", opts);
  }

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
