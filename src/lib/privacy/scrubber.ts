import type { ScrubResult } from "@/lib/types";

export type PiiKind = "SECRET" | "EMAIL" | "PHONE" | "IP" | "ACCT" | "ENTITY";

export interface ScrubberEntry {
  placeholder: string;
  kind: PiiKind;
  preview: string;
}

export interface SessionScrubber {
  scrub(text: string): ScrubResult;
  restore(text: string): string;
  entries(): ScrubberEntry[];
  addCustomTerm(term: string): void;
  clear(): void;
}

interface StoredMapping {
  placeholder: string;
  kind: PiiKind;
  original: string;
  preview: string;
}

interface CandidateSpan {
  start: number;
  end: number;
  kind: PiiKind;
  raw: string;
  canonicalKey: string;
}

const PLACEHOLDER_RE = /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY)_\d+\]/g;
const RESTORE_PLACEHOLDER_RE = /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY)_\d+\]/gi;

/**
 * Zero-width / invisible formatting characters that attackers insert to split PII/secrets.
 */
const ZERO_WIDTH_CODE_UNITS = new Set<number>([
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x180e, // Mongolian vowel separator
  0x200b, // zero-width space
  0x200c, // zero-width non-joiner
  0x200d, // zero-width joiner
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0xfeff, // zero-width no-break space / BOM
]);

/**
 * Common Cyrillic/Greek single-code-unit homoglyphs plus typographic punctuation/spaces
 * mapped 1-to-1 to canonical ASCII so index maps remain exact.
 */
const HOMOGLYPH_MAP: Readonly<Record<string, string>> = {
  "\u00a0": " ", // non-breaking space
  "\u2009": " ", // thin space
  "\u202f": " ", // narrow no-break space
  "\u2010": "-", // hyphen
  "\u2011": "-", // non-breaking hyphen
  "\u2012": "-", // figure dash
  "\u2013": "-", // en dash
  "\u2014": "-", // em dash
  "\u2212": "-", // minus sign
  "\u2018": "'", // left single quotation mark
  "\u2019": "'", // right single quotation mark
  "\u02bc": "'", // modifier letter apostrophe
  "\u201c": '"', // left double quotation mark
  "\u201d": '"', // right double quotation mark
  "\u0430": "a", // Cyrillic small a
  "\u0435": "e", // Cyrillic small ie
  "\u0456": "i", // Cyrillic small byelorussian-ukrainian i
  "\u0458": "j", // Cyrillic small je
  "\u043e": "o", // Cyrillic small o
  "\u0440": "p", // Cyrillic small er
  "\u0441": "c", // Cyrillic small es
  "\u0445": "x", // Cyrillic small ha
  "\u0443": "y", // Cyrillic small u
  "\u0455": "s", // Cyrillic small dze
  "\u0410": "A", // Cyrillic capital A
  "\u0412": "B", // Cyrillic capital VE
  "\u0415": "E", // Cyrillic capital IE
  "\u0406": "I", // Cyrillic capital I
  "\u0408": "J", // Cyrillic capital JE
  "\u041a": "K", // Cyrillic capital KA
  "\u041c": "M", // Cyrillic capital EM
  "\u041d": "H", // Cyrillic capital EN
  "\u041e": "O", // Cyrillic capital O
  "\u0420": "P", // Cyrillic capital ER
  "\u0421": "C", // Cyrillic capital ES
  "\u0422": "T", // Cyrillic capital TE
  "\u0425": "X", // Cyrillic capital HA
  "\u0405": "S", // Cyrillic capital DZE
  "\u03b1": "a", // Greek small alpha
  "\u03bf": "o", // Greek small omicron
  "\u03c1": "p", // Greek small rho
  "\u0391": "A", // Greek capital Alpha
  "\u0392": "B", // Greek capital Beta
  "\u0395": "E", // Greek capital Epsilon
  "\u0397": "H", // Greek capital Eta
  "\u0399": "I", // Greek capital Iota
  "\u039a": "K", // Greek capital Kappa
  "\u039c": "M", // Greek capital Mu
  "\u039d": "N", // Greek capital Nu
  "\u039f": "O", // Greek capital Omicron
  "\u03a1": "P", // Greek capital Rho
  "\u03a4": "T", // Greek capital Tau
  "\u03a7": "X", // Greek capital Chi
};

/**
 * Strips zero-width characters and folds fullwidth ASCII + Cyrillic/Greek homoglyphs
 * to canonical ASCII while maintaining an exact index map back to `text`.
 */
function normalizeWithIndexMap(text: string): {
  normalized: string;
  mapToOriginal: number[];
} {
  const chars: string[] = [];
  const mapToOriginal: number[] = [];

  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (ZERO_WIDTH_CODE_UNITS.has(code)) {
      continue;
    }
    let ch = text[i];
    // Fullwidth ASCII variants (U+FF01..U+FF5E -> 0x21..0x7E)
    if (code >= 0xff01 && code <= 0xff5e) {
      ch = String.fromCharCode(code - 0xfee0);
    } else if (ch in HOMOGLYPH_MAP) {
      ch = HOMOGLYPH_MAP[ch];
    }
    chars.push(ch);
    mapToOriginal.push(i);
  }

  return {
    normalized: chars.join(""),
    mapToOriginal,
  };
}

const SECRET_PATTERNS: RegExp[] = [
  // PEM private key blocks (multi-line or single header line)
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*/g,
  // JSON Web Tokens (JWTs: header.payload.signature)
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // Labeled AWS secret access keys and session tokens
  /\b(?:aws_secret_access_key|aws_secret_key|secret_access_key|aws_session_token)\s*[:=]\s*["']?[A-Za-z0-9/+=]{24,64}["']?/gi,
  // Slack incoming webhook URLs
  /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g,
  // Bearer tokens
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/g,
  // API keys split across newlines or multi-space/digit chunks
  /\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\d{2}-|sid\d{2}-)?|live-|test-)?|(?:sk|rk|pk)_(?:live|test)_|whsec_|tk_(?:live_|test_)?|tf_(?:live_|test_)?|tinfoil_(?:live_|test_)?|gh[pousr]_|github_pat_|xox[baprs]-|xapp-\d-|AIza|GOCSPX-|ya29\.)[A-Za-z0-9_.-]{2,}(?:(?:\r?\n[ \t]*|[ \t]{2,})[A-Za-z0-9_.-]{4,}|[ \t]+(?=[A-Za-z0-9_.-]*\d)[A-Za-z0-9_.-]{4,})+\b/g,
  // Standard contiguous API keys and cloud access keys:
  // OpenAI (sk-, sk-proj-, sk-svcacct-, sk-admin-), Anthropic (sk-ant-),
  // Google (AIza..., GOCSPX-..., ya29....), AWS (AKIA/ASIA/ABIA/ACCA/AIDA/AROA),
  // GitHub (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), Stripe (sk_live_/sk_test_/rk_live_/rk_test_/pk_live_/pk_test_/whsec_),
  // Slack (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-/xapp-/xoxe.xoxp-), Tinfoil (tk_/tf_/tinfoil_)
  /\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\d{2}-|sid\d{2}-)?|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|(?:sk|rk|pk)-(?:live|test)-[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\.[0-9A-Za-z._-]{12,})\b/g,
];

const BASE64_CANDIDATE_RE = /\b[A-Za-z0-9+/]{16,}={0,2}\b/g;

const DECODED_SECRET_CHECK_RE =
  /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\.[0-9A-Za-z._-]{12,}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}))/;

function isBase64WrappedSecret(raw: string): boolean {
  if (raw.length < 16 || raw.length % 4 === 1) return false;
  try {
    let decoded = "";
    if (typeof Buffer !== "undefined") {
      decoded = Buffer.from(raw, "base64").toString("utf8");
    } else if (typeof globalThis.atob === "function") {
      decoded = globalThis.atob(raw);
    }
    if (!decoded || decoded.length < 10) return false;
    return DECODED_SECRET_CHECK_RE.test(decoded);
  } catch {
    return false;
  }
}

/**
 * Validates a payment card number (13..19 digits) using the ISO/IEC 7812 Luhn check.
 */
export function isValidLuhn(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^0+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

const IBAN_COUNTRY_CODES = new Set([
  "AD", "AE", "AL", "AT", "AZ", "BA", "BE", "BG", "BH", "BI", "BR", "BY",
  "CH", "CR", "CY", "CZ", "DE", "DK", "DO", "EE", "EG", "ES", "FI", "FO",
  "FR", "GB", "GE", "GI", "GL", "GR", "GT", "HR", "HU", "IE", "IL", "IQ",
  "IS", "IT", "JO", "KW", "KZ", "LB", "LC", "LI", "LT", "LU", "LV", "LY",
  "MC", "MD", "ME", "MK", "MR", "MT", "MU", "NL", "NO", "PK", "PL", "PS",
  "PT", "QA", "RO", "RS", "RU", "SA", "SC", "SD", "SE", "SI", "SK", "SM",
  "SO", "ST", "SV", "TL", "TN", "TR", "UA", "VA", "VG", "XK",
]);

/**
 * Validates an IBAN string using ISO 13616 structure and ISO 7064 Mod-97-10 check.
 */
export function isValidIbanMod97(raw: string): boolean {
  const cleaned = raw.replace(/[\s-]/g, "").toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(cleaned)) return false;
  if (!IBAN_COUNTRY_CODES.has(cleaned.slice(0, 2))) return false;

  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      remainder = (remainder * 10 + (code - 48)) % 97;
    } else if (code >= 65 && code <= 90) {
      const val = code - 55;
      remainder = (remainder * 100 + val) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const ACCT_PATTERNS: RegExp[] = [
  // 0x Ethereum/EVM wallet address (40 hex chars)
  /\b0x[a-fA-F0-9]{40}\b/g,
  // US Social Security Number (SSN: XXX-XX-XXXX)
  /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  // UK National Insurance Number (including HMRC test prefix QQ, e.g. QQ 12 34 56 C or AB 12 34 56 C)
  /\b[A-CEGHJ-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
  // Explicit UK NHS number (labeled or 3-3-4 format)
  /\bNHS(?:\s*(?:No\.?|Number|#|:))?\s*\d{3}[\s-]?\d{3}[\s-]?\d{4}\b/gi,
  // Labeled passport numbers (US, UK, EU, Commonwealth, ICAO)
  /\bpassport(?:\s*(?:no\.?|number|num|id|#))?\s*[:#-]?\s*[A-Z0-9]{6,12}\b/gi,
  // ICAO Machine Readable Zone (MRZ) passport lines
  /\bP<[A-Z]{3}[A-Z0-9<]{10,40}\b/g,
  // Standard national passport formats (US NextGen 1 letter + 8 digits, UK/EU/CA 2 letters + 7 digits, FR 2 digits + 2 letters + 5 digits)
  /\b(?:[A-Z]\d{8}|[A-Z]{2}\d{7}|\d{2}[A-Z]{2}\d{5})\b/g,
  // Labeled bank account or routing numbers
  /\b(?:account|acct|routing)(?:\s*(?:no\.?|number|num|#))?\s*[:#]?\s*\d{6,17}\b/gi,
];

const IBAN_CANDIDATE_PATTERN =
  /\b[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]{4}){2,7}(?:[ -]?[A-Za-z0-9]{1,4})?\b/g;

const CREDIT_CARD_CANDIDATE_PATTERN =
  /\b(?:\d{4}[ -]){3}\d{1,7}\b|\b\d{4}[ -]\d{6}[ -]\d{4,5}\b|\b\d{13,19}\b/g;

const IP_PATTERN =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

const ENTITY_PII_PATTERNS: RegExp[] = [
  // Street addresses with optional directional, apartment/suite/unit/flat, city, and state/ZIP or UK postcode
  /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][a-zA-Z0-9.'-]*\s+){1,4}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Square|Sq\.?|Circle|Cir\.?|Parkway|Pkwy\.?|Highway|Hwy\.?|Crescent|Cres\.?|Close|Grove|Gardens|Mews)\b(?:[.,]?\s*(?:NW|NE|SW|SE|N|S|E|W)\b)?(?:[.,]?\s*(?:Apt|Apartment|Suite|Ste|Unit|Flat|Floor|Fl|Bldg|Building)\.?\s*#?[A-Za-z0-9-]+)?(?:,\s*[A-Z][a-zA-Z .'-]{1,28}(?:,\s*(?:[A-Z]{2}\s+\d{5}(?:-\d{4})?|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\s*[0-9][ABD-HJLNP-UW-Z]{2}))?)?/g,
  // PO Box addresses
  /\bP\.?O\.?\s*Box\s+\d{1,8}\b/gi,
  // UK Postcodes (BS 7666 outward + inward code, plus GIR 0AA)
  /\b(?:GIR\s?0AA|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\s+[0-9][ABD-HJLNP-UW-Z]{2}|(?:[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])[0-9][ABD-HJLNP-UW-Z]{2})\b/gi,
  // Labeled Dates of Birth (any format)
  /\b(?:DOB|D\.O\.B\.|Date\s+of\s+Birth|Born(?:\s+on)?|Birthdate|Birthday)\s*(?:[:=-]|is|was)?\s*(?:\d{4}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}|\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?),?\s+(?:19|20)\d{2})\b/gi,
  // Unlabeled birth-year dates (1900..2019 in ISO, US, UK/EU slash/dot/hyphen, or month-name format)
  /\b(?:(?:19\d{2}|20[01]\d)[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19\d{2}|20[01]\d)|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19\d{2}|20[01]\d)|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19\d{2}|20[01]\d)|\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?),?\s+(?:19\d{2}|20[01]\d))\b/gi,
];

const PHONE_PATTERNS: RegExp[] = [
  // International or domestic with optional +CC / 00CC, optional trunk (0), area code, subscriber blocks, and optional extension
  /(?:(?:\+|00)\d{1,3}[\s./-]?)?(?:\(0\)[\s./-]?)?(?:\(\d{1,5}\)[\s./-]?|\b\d{2,5}[\s./-])\d{2,5}[\s./-]\d{2,6}(?:[\s./-]\d{2,6}){0,2}(?:\s*(?:ext\.?|extension|x)\s*\d{1,6})?\b/gi,
  // 2-digit European/French style (5 pairs of 2 digits, e.g. 01 42 68 55 00 or 06.12.34.56.78 or +33 1 42 68 55 00)
  /(?:(?:\+|00)\d{1,3}[\s.-]?)?\b\d{1,2}(?:[\s.-]\d{2}){4}\b/g,
  // UK/EU 2-block national numbers (e.g. 07911 123456, 01632 960123, 030 / 12345678)
  /\b0\d{2,4}\s*[/\s.-]\s*\d{5,8}\b/g,
  // International + or 00 followed by 2..5 blocks of digits
  /(?:\+|\b00)\d{1,3}(?:[\s.-]?\(0\))?(?:[\s.-]?\d{2,6}){2,5}(?:\s*(?:ext\.?|extension|x)\s*\d{1,6})?\b/gi,
  // Contiguous + followed by 10-15 digits, or bare 10-11 digit phone numbers
  /\+\d{10,15}\b|\b\d{10,11}\b/g,
];

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function maskPreview(value: string, kind: PiiKind): string {
  const trimmed = value.trim();
  if (kind === "EMAIL") {
    const atIdx = trimmed.indexOf("@");
    if (atIdx > 0) {
      const local = trimmed.slice(0, atIdx);
      const domain = trimmed.slice(atIdx);
      const visible = local.slice(0, Math.min(2, Math.max(1, local.length - 1)));
      return `${visible}***${domain}`;
    }
  }
  if (trimmed.length <= 4) {
    return `${trimmed.slice(0, 1)}***`;
  }
  if (trimmed.length <= 8) {
    return `${trimmed.slice(0, 2)}***${trimmed.slice(-1)}`;
  }
  return `${trimmed.slice(0, 3)}***${trimmed.slice(-2)}`;
}

function canonicalKeyFor(kind: PiiKind, raw: string): string {
  const trimmed = raw.trim();
  switch (kind) {
    case "EMAIL":
    case "ENTITY":
      return `${kind}:${trimmed.replace(/\s+/g, " ").toLowerCase()}`;
    case "ACCT":
      if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
        return `${kind}:${trimmed.toLowerCase()}`;
      }
      return `${kind}:${trimmed.replace(/[\s-]/g, "").toUpperCase()}`;
    case "PHONE":
      return `${kind}:${trimmed.replace(/[\s.()/+-]/g, "").toLowerCase()}`;
    case "SECRET":
    case "IP":
    default:
      return `${kind}:${trimmed}`;
  }
}

export function createSessionScrubber(initialCustomTerms: string[] = []): SessionScrubber {
  const customTerms = new Map<string, string>(); // lowercase -> canonical original
  const byKey = new Map<string, StoredMapping>();
  const byPlaceholder = new Map<string, StoredMapping>();
  const reservedLiterals = new Set<string>();
  const counters: Record<PiiKind, number> = {
    SECRET: 0,
    EMAIL: 0,
    PHONE: 0,
    IP: 0,
    ACCT: 0,
    ENTITY: 0,
  };

  function addCustomTerm(term: string): void {
    const cleaned = term.trim();
    if (!cleaned) return;
    const { normalized } = normalizeWithIndexMap(cleaned);
    const lower = normalized.toLowerCase();
    if (!customTerms.has(lower)) {
      customTerms.set(lower, cleaned);
    }
  }

  for (const t of initialCustomTerms) {
    addCustomTerm(t);
  }

  function getOrCreatePlaceholder(kind: PiiKind, raw: string, canonicalKey: string): StoredMapping {
    const existing = byKey.get(canonicalKey);
    if (existing) {
      return existing;
    }
    let placeholder = "";
    do {
      counters[kind] += 1;
      placeholder = `[${kind}_${counters[kind]}]`;
    } while (byPlaceholder.has(placeholder) || reservedLiterals.has(placeholder));

    const { normalized: normRaw } = normalizeWithIndexMap(raw.trim());
    const original =
      kind === "ENTITY" ? (customTerms.get(normRaw.toLowerCase()) ?? raw) : raw;
    const mapping: StoredMapping = {
      placeholder,
      kind,
      original,
      preview: maskPreview(original, kind),
    };
    byKey.set(canonicalKey, mapping);
    byPlaceholder.set(placeholder, mapping);
    return mapping;
  }

  function collectSpans(text: string): CandidateSpan[] {
    const { normalized, mapToOriginal } = normalizeWithIndexMap(text);
    if (!normalized) return [];

    const occupied: { start: number; end: number }[] = [];

    const overlaps = (start: number, end: number): boolean =>
      occupied.some((s) => start < s.end && end > s.start);

    const candidates: CandidateSpan[] = [];

    // Protect any existing literal placeholders already in the user text.
    PLACEHOLDER_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PLACEHOLDER_RE.exec(text)) !== null) {
      const lit = m[0];
      const start = m.index;
      const end = start + lit.length;
      occupied.push({ start, end });
      if (byPlaceholder.has(lit)) {
        candidates.push({
          start,
          end,
          kind: "ENTITY",
          raw: lit,
          canonicalKey: `LITERAL_COLLISION:${lit}`,
        });
      } else {
        reservedLiterals.add(lit);
      }
    }

    const addMatches = (
      regex: RegExp,
      kind: PiiKind,
      validate?: (normRaw: string, normStart: number, fullNormText: string) => boolean,
    ) => {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(normalized)) !== null) {
        const normRaw = match[0];
        if (!normRaw) {
          re.lastIndex += 1;
          continue;
        }
        const normStart = match.index;
        const normEnd = normStart + normRaw.length;
        const origStart = mapToOriginal[normStart];
        const origEnd = mapToOriginal[normEnd - 1] + 1;
        if (overlaps(origStart, origEnd)) continue;
        if (validate && !validate(normRaw, normStart, normalized)) continue;
        occupied.push({ start: origStart, end: origEnd });
        const raw = text.slice(origStart, origEnd);
        candidates.push({
          start: origStart,
          end: origEnd,
          kind,
          raw,
          canonicalKey: canonicalKeyFor(kind, normRaw),
        });
      }
    };

    // 1. Secrets / API keys / tokens / PEM / JWT
    for (const pat of SECRET_PATTERNS) {
      addMatches(pat, "SECRET");
    }

    // 1b. Base64-wrapped secrets (only when decoded payload contains a known secret format)
    addMatches(BASE64_CANDIDATE_RE, "SECRET", (normRaw) => isBase64WrappedSecret(normRaw));

    // 2. Email addresses
    addMatches(EMAIL_PATTERN, "EMAIL");

    // 3. Account & government identifiers: 0x wallets, SSNs, UK NI, NHS, passports, labeled accounts
    for (const pat of ACCT_PATTERNS) {
      addMatches(pat, "ACCT");
    }

    // 3b. IBANs (Mod-97 valid or uppercase valid country code + structure)
    addMatches(IBAN_CANDIDATE_PATTERN, "ACCT", (normRaw) => {
      const cleaned = normRaw.replace(/[\s-]/g, "");
      if (cleaned.length < 15 || cleaned.length > 34) return false;
      const country = cleaned.slice(0, 2).toUpperCase();
      if (!IBAN_COUNTRY_CODES.has(country)) return false;
      const digitCount = (cleaned.match(/\d/g) ?? []).length;
      if (digitCount < 6) return false;
      if (isValidIbanMod97(cleaned)) return true;
      return /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(cleaned);
    });

    // 3c. Credit card numbers validated by Luhn check
    addMatches(CREDIT_CARD_CANDIDATE_PATTERN, "ACCT", (normRaw) => isValidLuhn(normRaw));

    // 4. IPv4 addresses
    addMatches(IP_PATTERN, "IP");

    // 5. Custom terms (ENTITY), longest first
    if (customTerms.size > 0) {
      const sortedTerms = [...customTerms.keys()].sort((a, b) => b.length - a.length);
      for (const normTerm of sortedTerms) {
        const escaped = escapeRegExp(normTerm);
        const startsWithWord = /^\w/.test(normTerm);
        const endsWithWord = /\w$/.test(normTerm);
        const pattern = `${startsWithWord ? "\\b" : ""}${escaped}${endsWithWord ? "\\b" : ""}`;
        addMatches(new RegExp(pattern, "gi"), "ENTITY");
      }
    }

    // 6. Structured Entity PII: street addresses, PO boxes, UK postcodes, dates of birth
    for (const pat of ENTITY_PII_PATTERNS) {
      addMatches(pat, "ENTITY");
    }

    // 7. Phone numbers (>= 10 and <= 15 subscriber digits, not preceded by word/dot/slash)
    for (const pat of PHONE_PATTERNS) {
      addMatches(pat, "PHONE", (normRaw, normStart, fullNorm) => {
        const mainPart = normRaw.replace(/(?:ext\.?|extension|x)\s*\d{1,6}$/i, "");
        const digits = mainPart.replace(/\D/g, "");
        if (digits.length < 10 || digits.length > 15) return false;
        if (normStart > 0) {
          const prev = fullNorm[normStart - 1];
          if (/[A-Za-z0-9_./-]/.test(prev)) return false;
        }
        return true;
      });
    }

    candidates.sort((a, b) => a.start - b.start);
    return candidates;
  }

  function scrub(text: string): ScrubResult {
    if (!text) {
      return { scrubbed: text, replacements: [] };
    }
    const spans = collectSpans(text);
    if (spans.length === 0) {
      return { scrubbed: text, replacements: [] };
    }

    const replacements: { placeholder: string; kind: string }[] = [];
    let out = "";
    let cursor = 0;

    for (const span of spans) {
      out += text.slice(cursor, span.start);
      const mapping = getOrCreatePlaceholder(span.kind, span.raw, span.canonicalKey);
      out += mapping.placeholder;
      replacements.push({
        placeholder: mapping.placeholder,
        kind: mapping.kind,
      });
      cursor = span.end;
    }
    out += text.slice(cursor);

    return { scrubbed: out, replacements };
  }

  function restore(text: string): string {
    if (!text || byPlaceholder.size === 0) return text;
    return text.replace(RESTORE_PLACEHOLDER_RE, (token) => {
      const entry = byPlaceholder.get(token.toUpperCase());
      return entry ? entry.original : token;
    });
  }

  function entries(): ScrubberEntry[] {
    return [...byPlaceholder.values()].map(({ placeholder, kind, preview }) => ({
      placeholder,
      kind,
      preview,
    }));
  }

  function clear(): void {
    byKey.clear();
    byPlaceholder.clear();
    reservedLiterals.clear();
    counters.SECRET = 0;
    counters.EMAIL = 0;
    counters.PHONE = 0;
    counters.IP = 0;
    counters.ACCT = 0;
    counters.ENTITY = 0;
  }

  return {
    scrub,
    restore,
    entries,
    addCustomTerm,
    clear,
  };
}
