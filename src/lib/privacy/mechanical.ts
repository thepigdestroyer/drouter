import {
  isValidIbanMod97,
  isValidLuhn,
  type SessionScrubber,
} from "./scrubber";

export type MechanicalRedactionKind =
  | "SECRET"
  | "EMAIL"
  | "PHONE"
  | "IP"
  | "ACCT"
  | "ENTITY"
  | "URL"
  | "ADDRESS"
  | "DATE"
  | "NAME"
  | "DIGITS"
  | "ENTROPY";

export interface MechanicalRedaction {
  kind: string;
  placeholder: string;
}

export interface MechanicalRedactOptions {
  customTerms?: string[];
  scrubber?: SessionScrubber;
}

export interface MechanicalRedactResult {
  text: string;
  redactions: Array<{ kind: string; placeholder: string }>;
  restore(s: string): string;
}

interface CandidateSpan {
  start: number;
  end: number;
  kind: MechanicalRedactionKind;
  raw: string;
  canonicalKey: string;
}

const EXISTING_PLACEHOLDER_RE =
  /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY|[A-Z0-9_]+)_\d+\]|<PRIVATE_[A-Z0-9_]+>/g;
const RESTORE_PLACEHOLDER_RE =
  /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\d+\]/gi;

/**
 * Zero-width, bidi control, variation selector, and invisible formatting code units
 * that attackers insert to split PII/secrets or bypass regex token boundaries.
 */
const ZERO_WIDTH_CODE_UNITS = new Set<number>([
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x061c, // Arabic letter mark
  0x115f, // Hangul choseong filler
  0x1160, // Hangul jungseong filler
  0x17b4, // Khmer vowel inherent aq
  0x17b5, // Khmer vowel inherent aa
  0x180b, // Mongolian free variation selector 1
  0x180c, // Mongolian free variation selector 2
  0x180d, // Mongolian free variation selector 3
  0x180e, // Mongolian vowel separator
  0x200b, // zero-width space
  0x200c, // zero-width non-joiner
  0x200d, // zero-width joiner
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x202a, // left-to-right embedding
  0x202b, // right-to-left embedding
  0x202c, // pop directional formatting
  0x202d, // left-to-right override
  0x202e, // right-to-left override
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0x2066, // left-to-right isolate
  0x2067, // right-to-left isolate
  0x2068, // first strong isolate
  0x2069, // pop directional isolate
  0x206a, // inhibit symmetric swapping
  0x206b, // activate symmetric swapping
  0x206c, // inhibit arabic form shaping
  0x206d, // activate arabic form shaping
  0x206e, // national digit shapes
  0x206f, // nominal digit shapes
  0xfeff, // zero-width no-break space / BOM
  0xffa0, // halfwidth Hangul filler
]);

function isZeroWidthOrVariationSelector(code: number): boolean {
  if (ZERO_WIDTH_CODE_UNITS.has(code)) return true;
  if (code >= 0xfe00 && code <= 0xfe0f) return true; // Variation selectors VS1..VS16
  return false;
}

function isCombiningDiacritic(code: number): boolean {
  return code >= 0x0300 && code <= 0x036f;
}

/**
 * Common Cyrillic/Greek single-code-unit homoglyphs, superscripts/subscripts/circled digits,
 * and typographic punctuation/spaces mapped 1-to-1 to canonical ASCII.
 */
const HOMOGLYPH_MAP: Readonly<Record<string, string>> = {
  "\u00a0": " ", // non-breaking space
  "\u1680": " ",
  "\u2000": " ",
  "\u2001": " ",
  "\u2002": " ",
  "\u2003": " ",
  "\u2004": " ",
  "\u2005": " ",
  "\u2006": " ",
  "\u2007": " ",
  "\u2008": " ",
  "\u2009": " ", // thin space
  "\u200a": " ",
  "\u202f": " ", // narrow no-break space
  "\u205f": " ",
  "\u3000": " ", // ideographic space
  "\u2010": "-", // hyphen
  "\u2011": "-", // non-breaking hyphen
  "\u2012": "-", // figure dash
  "\u2013": "-", // en dash
  "\u2014": "-", // em dash
  "\u2015": "-", // horizontal bar
  "\u2212": "-", // minus sign
  "\u2018": "'", // left single quotation mark
  "\u2019": "'", // right single quotation mark
  "\u02bc": "'", // modifier letter apostrophe
  "\u201c": '"', // left double quotation mark
  "\u201d": '"', // right double quotation mark
  // Superscript digits
  "\u2070": "0",
  "\u00b9": "1",
  "\u00b2": "2",
  "\u00b3": "3",
  "\u2074": "4",
  "\u2075": "5",
  "\u2076": "6",
  "\u2077": "7",
  "\u2078": "8",
  "\u2079": "9",
  // Subscript digits
  "\u2080": "0",
  "\u2081": "1",
  "\u2082": "2",
  "\u2083": "3",
  "\u2084": "4",
  "\u2085": "5",
  "\u2086": "6",
  "\u2087": "7",
  "\u2088": "8",
  "\u2089": "9",
  // Circled digits
  "\u24ea": "0",
  "\u2460": "1",
  "\u2461": "2",
  "\u2462": "3",
  "\u2463": "4",
  "\u2464": "5",
  "\u2465": "6",
  "\u2466": "8", // wait: fix mapping below
  // Nordic / Polish stroke letters that do not decompose via NFKD
  "\u00d8": "O",
  "\u00f8": "o",
  "\u0141": "L",
  "\u0142": "l",
  "\u0110": "D",
  "\u0111": "d",
  // Cyrillic lookalikes
  "\u0430": "a",
  "\u0435": "e",
  "\u0456": "i",
  "\u0458": "j",
  "\u043e": "o",
  "\u0440": "p",
  "\u0441": "c",
  "\u0445": "x",
  "\u0443": "y",
  "\u0455": "s",
  "\u0410": "A",
  "\u0412": "B",
  "\u0415": "E",
  "\u0406": "I",
  "\u0408": "J",
  "\u041a": "K",
  "\u041c": "M",
  "\u041d": "H",
  "\u041e": "O",
  "\u0420": "P",
  "\u0421": "C",
  "\u0422": "T",
  "\u0425": "X",
  "\u0405": "S",
  // Greek lookalikes
  "\u03b1": "a",
  "\u03bf": "o",
  "\u03c1": "p",
  "\u03bd": "v",
  "\u0391": "A",
  "\u0392": "B",
  "\u0395": "E",
  "\u0397": "H",
  "\u0399": "I",
  "\u039a": "K",
  "\u039c": "M",
  "\u039d": "N",
  "\u039f": "O",
  "\u03a1": "P",
  "\u03a4": "T",
  "\u03a7": "X",
  "\u0396": "Z",
};

/**
 * Maps Mathematical Alphanumeric Symbols (U+1D400..U+1D7FF) to ASCII letters/digits.
 */
function foldMathAlphanumericCodePoint(cp: number): string | null {
  // Mathematical bold/double-struck/sans/monospace digits: U+1D7CE..U+1D7FF (5 sets of 10)
  if (cp >= 0x1d7ce && cp <= 0x1d7ff) {
    const digit = (cp - 0x1d7ce) % 10;
    return String.fromCharCode(48 + digit);
  }
  // Mathematical Latin alphabets: U+1D400..U+1D6A3 (13 sets of 52 letters: 26 upper + 26 lower)
  if (cp >= 0x1d400 && cp <= 0x1d6a3) {
    const offset = (cp - 0x1d400) % 52;
    if (offset < 26) {
      return String.fromCharCode(65 + offset);
    }
    return String.fromCharCode(97 + (offset - 26));
  }
  return null;
}

/**
 * Strips zero-width/bidi/variation characters, absorbs combining diacritics, and folds
 * fullwidth ASCII, mathematical symbols, accented Latin, and Cyrillic/Greek homoglyphs
 * to canonical ASCII while maintaining an exact start and end index map back to `text`.
 */
export function normalizeWithIndexMap(text: string): {
  normalized: string;
  mapToOriginal: number[];
  mapToOriginalEnd: number[];
} {
  const chars: string[] = [];
  const mapToOriginal: number[] = [];
  const mapToOriginalEnd: number[] = [];

  let i = 0;
  while (i < text.length) {
    const code = text.charCodeAt(i);

    if (isZeroWidthOrVariationSelector(code) || isCombiningDiacritic(code)) {
      if (isCombiningDiacritic(code) && mapToOriginalEnd.length > 0) {
        mapToOriginalEnd[mapToOriginalEnd.length - 1] = i + 1;
      }
      i += 1;
      continue;
    }

    let ch = text[i];
    let step = 1;

    // Check UTF-16 surrogate pair for Mathematical Alphanumeric Symbols (U+1D400..U+1D7FF)
    if (code === 0xd835 && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        const cp = ((code - 0xd800) << 10) + (low - 0xdc00) + 0x10000;
        const foldedMath = foldMathAlphanumericCodePoint(cp);
        if (foldedMath) {
          ch = foldedMath;
          step = 2;
        }
      }
    } else if (code >= 0xff01 && code <= 0xff5e) {
      // Fullwidth ASCII variants (U+FF01..U+FF5E -> 0x21..0x7E)
      ch = String.fromCharCode(code - 0xfee0);
    } else if (code >= 0x2460 && code <= 0x2468) {
      // Circled digits ①..⑨
      ch = String.fromCharCode(49 + (code - 0x2460));
    } else if (ch in HOMOGLYPH_MAP) {
      ch = HOMOGLYPH_MAP[ch];
    } else if (code >= 0x00c0 && code <= 0x024f) {
      // Precomposed accented Latin letters (e.g. é -> e, Ö -> O, ñ -> n)
      const base = ch.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
      if (base.length === 1) {
        ch = base;
      }
    }

    const origStart = i;
    let origEnd = i + step;
    while (origEnd < text.length && isCombiningDiacritic(text.charCodeAt(origEnd))) {
      origEnd += 1;
    }

    chars.push(ch);
    mapToOriginal.push(origStart);
    mapToOriginalEnd.push(origEnd);
    i = origEnd;
  }

  return {
    normalized: chars.join(""),
    mapToOriginal,
    mapToOriginalEnd,
  };
}

/**
 * Computes Shannon entropy in bits per character for a string token.
 */
export function computeShannonEntropy(token: string): number {
  if (!token || token.length === 0) return 0;
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

/**
 * Deterministic high-entropy token classifier (no ML models).
 * Flags random tokens, unlabeled keys, hashes, base64/base58 strings, and
 * consonant-dense random lowercase tokens while avoiding false positives on
 * normal English words.
 */
export function isHighEntropyToken(token: string): boolean {
  const cleaned = token.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
  if (cleaned.length < 12) return false;
  // Never flag existing bracketed placeholders like [SECRET_1]
  if (/^\[[A-Z0-9_]+\]$/.test(token)) return false;

  // Ignore known hyphenated lowercase technical identifiers without 4+ digits (e.g. pqc-hybrid-ml-kem-768)
  if (/^[a-z]+(?:-[a-z0-9]{1,8})+$/.test(cleaned) && !/\d{4,}/.test(cleaned)) {
    return false;
  }

  const hasLower = /[a-z]/.test(cleaned);
  const hasUpper = /[A-Z]/.test(cleaned);
  const hasDigit = /\d/.test(cleaned);
  const hasSymbol = /[_+=/~@#$%^&*-]/.test(cleaned);
  const classCount =
    (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

  const entropy = computeShannonEntropy(cleaned);

  // Hexadecimal hashes / keys >= 16 chars
  if (/^[0-9a-fA-F]{16,}$/.test(cleaned) && entropy >= 2.8) {
    return true;
  }

  // 3+ character classes (e.g. upper + lower + digit/symbol) of length >= 12
  if (cleaned.length >= 12 && classCount >= 3 && (hasDigit || hasSymbol) && entropy >= 3.25) {
    return true;
  }

  // 2+ character classes including digits or symbols of length >= 15
  if (cleaned.length >= 15 && classCount >= 2 && (hasDigit || hasSymbol) && entropy >= 3.5) {
    return true;
  }

  // Mixed upper + lower (camelCase/base58/base64 without digits) of length >= 16 with multiple uppercase transitions
  if (cleaned.length >= 16 && hasLower && hasUpper) {
    const upperCount = (cleaned.match(/[A-Z]/g) ?? []).length;
    if (upperCount >= 3 && entropy >= 3.65) {
      return true;
    }
  }

  // Single-class alpha string of length >= 16 that is non-linguistic (5+ consecutive consonants or very high entropy)
  if (cleaned.length >= 16 && /^[A-Za-z]+$/.test(cleaned)) {
    const lower = cleaned.toLowerCase();
    const hasFiveConsonants = /[bcdfghjklmnpqrstvwxz]{5,}/.test(lower);
    const vowelCount = (lower.match(/[aeiouy]/g) ?? []).length;
    const vowelRatio = vowelCount / lower.length;
    if ((hasFiveConsonants && entropy >= 3.5) || (vowelRatio < 0.2 && entropy >= 3.5) || entropy >= 3.95) {
      return true;
    }
  }

  return false;
}

const SECRET_PATTERNS: RegExp[] = [
  // PEM private key blocks (multi-line or single header line)
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*/g,
  // JSON Web Tokens (JWTs: header.payload.signature)
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // Database & broker connection URLs with credentials
  /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|mysql|amqp|amqps):\/\/[^\s"'<>)\]]+/gi,
  // Labeled secrets, passwords, API keys, and tokens
  /\b(?:aws_secret_access_key|aws_secret_key|secret_access_key|aws_session_token|api[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|password|passwd|passphrase)\s*[:=]\s*["']?[A-Za-z0-9/_+~@#$%^&*.-]{6,128}["']?/gi,
  // Slack incoming webhook URLs
  /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g,
  // Bearer tokens
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/g,
  // Character-by-character spaced API keys (e.g. "s k - p r o j - a b c d 1 2 3 4")
  /\b(?:s\s+k\s*-\s*(?:p\s+r\s+o\s+j\s*-\s*|a\s+n\s+t\s*-\s*|l\s+i\s+v\s+e\s*-\s*|t\s+e\s+s\s+t\s*-\s*)?|g\s+h\s+[pousr]\s*_\s*|t\s+[kf]\s*_\s*(?:l\s+i\s+v\s+e\s*_\s*)?|A\s+K\s+I\s+A\s+|A\s+S\s+I\s+A\s+|A\s+I\s+z\s+a\s+)(?:[A-Za-z0-9_-]\s+){4,}[A-Za-z0-9_-]\b/g,
  // API keys split across newlines or spaces/tabs
  /\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\d{2}-|sid\d{2}-)?|live-|test-)?|(?:sk|rk|pk)_(?:live|test)_|whsec_|tk_(?:live_|test_)?|tf_(?:live_|test_)?|tinfoil_(?:live_|test_)?|gh[pousr]_|github_pat_|xox[baprs]-|xapp-\d-|AIza|GOCSPX-|ya29\.|hf_|npm_)[A-Za-z0-9_.-]{2,}(?:(?:\r?\n[ \t]*|[ \t]{2,})[A-Za-z0-9_.-]{3,}|[ \t]+(?=[A-Za-z0-9_.-]*\d)[A-Za-z0-9_.-]{3,})+\b/g,
  // Standard contiguous API keys and cloud access keys:
  // OpenAI, Anthropic, Google, AWS, GitHub, Stripe, Slack, Tinfoil, HuggingFace, npm, SendGrid
  /\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\d{2}-|sid\d{2}-)?|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|(?:sk|rk|pk)-(?:live|test)-[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\.[0-9A-Za-z._-]{12,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
];

const BASE64_CANDIDATE_RE = /\b[A-Za-z0-9+/]{16,}={0,2}\b/g;

const DECODED_SECRET_CHECK_RE =
  /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\.[0-9A-Za-z._-]{12,}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}|password\s*[:=]|secret\s*[:=]))/i;

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

const EMAIL_PATTERNS: RegExp[] = [
  // Standard email address
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  // Obfuscated or split email address (e.g., alice [at] acme [dot] com or alice @ acme . org)
  /\b[A-Za-z0-9._%+-]+(?:\s*@\s*|\s*(?:\[\s*at\s*\]|\(\s*at\s*\))\s*)[A-Za-z0-9-]+(?:\s*(?:\.|\[\s*dot\s*\]|\(\s*dot\s*\))\s*[A-Za-z0-9-]+)*\s*(?:\.|\[\s*dot\s*\]|\(\s*dot\s*\))\s*(?:com|org|net|edu|gov|mil|io|sh|ai|dev|app|co|uk|us|eu|de|fr|jp|cn|ch|nl|se|no|fi|dk|ca|au|nz|info|biz|me|xyz|tech|cloud)\b/gi,
];

const URL_PATTERNS: RegExp[] = [
  // Full URLs with scheme
  /\b(?:https?|wss?|s?ftp|file):\/\/[^\s"'<>)\]]+/gi,
  // www. URLs
  /\bwww\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?::\d{2,5})?(?:\/[^\s"'<>)\]]*)?/gi,
  // Bare domains with recognized TLDs and optional port/path
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|io|sh|ai|dev|app|co|uk|us|eu|de|fr|jp|cn|ch|nl|se|no|fi|dk|ca|au|nz|in|br|it|es|pl|ru|kr|sg|hk|tw|il|ae|za|mx|ar|cl|info|biz|me|xyz|tech|cloud|online|site|store|local|internal|corp|lan|onion|eth|crypto|test|example|invalid)\b(?:\.[a-zA-Z]{2,3})?(?::\d{2,5})?(?:\/[^\s"'<>)\]]*)?/gi,
];

const IBAN_COUNTRY_CODES = new Set([
  "AD", "AE", "AL", "AT", "AZ", "BA", "BE", "BG", "BH", "BI", "BR", "BY",
  "CH", "CR", "CY", "CZ", "DE", "DK", "DO", "EE", "EG", "ES", "FI", "FO",
  "FR", "GB", "GE", "GI", "GL", "GR", "GT", "HR", "HU", "IE", "IL", "IQ",
  "IS", "IT", "JO", "KW", "KZ", "LB", "LC", "LI", "LT", "LU", "LV", "LY",
  "MC", "MD", "ME", "MK", "MR", "MT", "MU", "NL", "NO", "PK", "PL", "PS",
  "PT", "QA", "RO", "RS", "RU", "SA", "SC", "SD", "SE", "SI", "SK", "SM",
  "SO", "ST", "SV", "TL", "TN", "TR", "UA", "VA", "VG", "XK",
]);

const ACCT_PATTERNS: RegExp[] = [
  // 0x Ethereum/EVM wallet address (40 hex chars)
  /\b0x[a-fA-F0-9]{40}\b/g,
  // Bitcoin bech32 / base58 addresses
  /\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  // US Social Security Number (SSN: XXX-XX-XXXX or spaced/dotted or labeled)
  /\b(?!000|666|9\d\d)\d{3}[-.](?!00)\d{2}[-.](?!0000)\d{4}\b/g,
  /\bSSN\s*[:#=-]?\s*\d{3}[\s.-]*\d{2}[\s.-]*\d{4}\b/gi,
  // UK National Insurance Number
  /\b[A-CEGHJ-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
  // Explicit UK NHS number
  /\bNHS(?:\s*(?:No\.?|Number|#|:))?\s*\d{3}[\s-]?\d{3}[\s-]?\d{4}\b/gi,
  // Labeled passport numbers
  /\bpassport(?:\s*(?:no\.?|number|num|id|#))?\s*[:#-]?\s*[A-Z0-9]{6,12}\b/gi,
  // ICAO Machine Readable Zone (MRZ) passport lines
  /\bP<[A-Z]{3}[A-Z0-9<]{10,40}\b/g,
  // Standard national passport formats
  /\b(?:[A-Z]\d{8}|[A-Z]{2}\d{7}|\d{2}[A-Z]{2}\d{5})\b/g,
  // Labeled bank account or routing numbers
  /\b(?:account|acct|routing)(?:\s*(?:no\.?|number|num|#))?\s*[:#]?\s*\d{6,17}\b/gi,
];

const IBAN_CANDIDATE_PATTERN =
  /\b[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]{4}){2,7}(?:[ -]?[A-Za-z0-9]{1,4})?\b/g;

const CREDIT_CARD_CANDIDATE_PATTERN =
  /\b(?:\d{4}[ -]){3}\d{1,7}\b|\b\d{4}[ -]\d{6}[ -]\d{4,5}\b|\b\d{13,19}\b/g;

const IP_PATTERNS: RegExp[] = [
  // IPv4 with optional port
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b/g,
  // IPv6 full or compressed
  /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5}\b/g,
];

const ADDRESS_PATTERNS: RegExp[] = [
  // Street addresses with house number, 1..4 street name words (excluding prepositions/bare numbers), street suffix, optional directional, unit/apt/suite, and city/state/postal code
  /\b\d{1,6}[A-Za-z]?(?:-\d{1,4})?\s+(?:(?!at\b|on\b|in\b|to\b|for\b|from\b|with\b|by\b|and\b|or\b)(?:\d{1,4}(?:st|nd|rd|th)|[A-Za-z][A-Za-z.'-]{0,22})\s+){1,4}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Square|Sq\.?|Circle|Cir\.?|Parkway|Pkwy\.?|Highway|Hwy\.?|Crescent|Cres\.?|Close|Grove|Gardens|Mews|Alley|Trail|Trl\.?|Pike|Plaza|Walk|Row|Path)\b(?:[.,]?\s*(?:NW|NE|SW|SE|N|S|E|W|North|South|East|West)\b)?(?:[.,]?\s*(?:Apt|Apartment|Suite|Ste|Unit|Flat|Floor|Fl|Bldg|Building|Room|Rm)\.?\s*#?[A-Za-z0-9-]+|\s+#\d+[A-Za-z]?)?(?:,\s*[A-Z][a-zA-Z .'-]{1,28}(?:,\s*(?:[A-Z]{2}\s+\d{5}(?:-\d{4})?|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\s*[0-9][ABD-HJLNP-UW-Z]{2}))?)?/gi,
  // PO Box addresses
  /\bP\.?\s*O\.?\s*Box\s+#?\d{1,8}\b/gi,
  // UK Postcodes (BS 7666 outward + inward code, plus GIR 0AA)
  /\b(?:GIR\s?0AA|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\s+[0-9][ABD-HJLNP-UW-Z]{2}|(?:[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])[0-9][ABD-HJLNP-UW-Z]{2})\b/gi,
  // US State + ZIP+4
  /\b[A-Z]{2}\s+\d{5}-\d{4}\b/g,
];

const DATE_PATTERNS: RegExp[] = [
  // Labeled Dates of Birth / Dates
  /\b(?:DOB|D\.O\.B\.|Date\s+of\s+Birth|Born(?:\s+on)?|Birthdate|Birthday)\s*(?:[:=-]|is|was)?\s*(?:\d{4}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:\d{4}|\d{2})|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:\d{4}|\d{2})|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?,?\s+\d{4})\b/gi,
  // ISO 8601 dates & timestamps (YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD with optional time)
  /\b(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
  // Slash, dot, or hyphen numeric dates (DD/MM/YYYY, MM/DD/YYYY, DD.MM.YYYY, MM-DD-YY)
  /\b(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:(?:19|20)\d{2}|\d{2})\b/g,
  /\b(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:(?:19|20)\d{2}|\d{2})\b/g,
  // Month name + day (+ optional year): e.g. "March 15, 1984", "Oct 24, 2026", "Jan. 5th"
  /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+(?:19|20)\d{2})?\b/gi,
  // Day + Month name (+ year): e.g. "15 March 2024", "15th of March, 1984"
  /\b\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?(?:,?\s+(?:19|20)\d{2})\b/gi,
];

const PHONE_PATTERNS: RegExp[] = [
  // International or domestic with optional +CC / 00CC, optional trunk (0), area code, subscriber blocks, and optional extension
  /(?:(?:\+|00)\d{1,3}[\s./-]?)?(?:\(0\)[\s./-]?)?(?:\(\d{1,5}\)[\s./-]?|\b\d{2,5}[\s./-])\d{2,5}[\s./-]\d{2,6}(?:[\s./-]\d{2,6}){0,2}(?:\s*(?:ext\.?|extension|x)\s*\d{1,6})?\b/gi,
  // 2-digit European/French style (5 pairs of 2 digits)
  /(?:(?:\+|00)\d{1,3}[\s.-]?)?\b\d{1,2}(?:[\s.-]\d{2}){4}\b/g,
  // UK/EU 2-block national numbers (e.g. 07911 123456, 01632 960123, 030 / 12345678)
  /\b0\d{2,4}\s*[/\s.-]\s*\d{5,8}\b/g,
  // International + or 00 followed by 2..5 blocks of digits
  /(?:\+|\b00)\d{1,3}(?:[\s.-]?\(0\))?(?:[\s.-]?\d{2,6}){2,5}(?:\s*(?:ext\.?|extension|x)\s*\d{1,6})?\b/gi,
  // Contiguous + followed by 10-15 digits, or bare 10-11 digit phone numbers
  /\+\d{10,15}\b|\b\d{10,11}\b/g,
];

// Local 7-digit US/CA phone numbers (e.g., 555-867-5309 -> 555-0199)
const LOCAL_SEVEN_DIGIT_PHONE_RE = /\b[2-9]\d{2}-\d{4}\b/g;

/**
 * Sentence-leading function words, imperatives, and prepositions that may precede a
 * capitalized name at the start of a sentence (e.g. "Please contact Jane Doe", "When Alice met Bob").
 */
const SENTENCE_STARTER_NON_NAMES = new Set<string>([
  "a", "an", "the", "in", "on", "at", "to", "from", "for", "with", "by", "of",
  "as", "if", "when", "while", "where", "why", "how", "what", "who", "which",
  "this", "that", "these", "those", "it", "he", "she", "we", "they", "you",
  "my", "our", "your", "his", "her", "their", "its", "and", "but", "or", "so",
  "yet", "nor", "because", "although", "though", "since", "unless", "until",
  "before", "after", "during", "between", "among", "within", "without", "under",
  "over", "above", "below", "across", "through", "against", "however", "therefore",
  "furthermore", "moreover", "meanwhile", "nevertheless", "otherwise", "instead",
  "please", "call", "contact", "email", "send", "ask", "tell", "meet", "see",
  "hello", "hi", "dear", "hey", "thanks", "thank", "audit", "verify", "check",
  "review", "summarize", "analyze", "draft", "report", "update", "forward",
  "confirming", "confirm", "inspect", "list", "allow", "ensure", "note",
]);

/**
 * Technical domain phrases in the confidential computing corpus that use Title Case
 * in architecture headings/queries but are hardware/protocol terms rather than person names.
 */
const TECHNICAL_TITLE_CASE_ALLOWLIST = new Set<string>([
  "trusted execution",
  "trusted execution environment",
  "trusted execution environments",
  "confidential computing",
  "confidential inference",
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
  "riser attack",
  "phala cloud",
  "prem ai",
  "near ai",
  "confidential ai",
  "edgeless systems",
  "voxtral small",
  "voxtral mini",
  "whisper large",
  "deepgram nova",
  "sigstore rekor",
  "encrypted http",
  "attested tls",
  "gateway attestation",
  "on-chain attestation",
  "channel binding",
  "route binding",
  "source provenance",
  "workload identity",
  "northvale institute",
  "atlas cellular unit",
  "atlas cellular",
  "cellular unit",
]);

const TECHNICAL_SINGLE_WORDS = new Set<string>([
  "trusted",
  "execution",
  "environment",
  "confidential",
  "computing",
  "inference",
  "memory",
  "interposer",
  "vector",
  "hybrid",
  "search",
  "reciprocal",
  "fusion",
  "tinfoil",
  "intel",
  "circle",
  "arc",
  "testnet",
  "mongodb",
  "atlas",
  "northvale",
  "institute",
  "cellular",
  "unit",
  "phase",
]);

const HONORIFIC_RE = /^(?:Dr|Mr|Mrs|Ms|Mx|Prof|Professor|Sir|Lady|Dame|Rev|Capt|Col|Gen|Sgt|Sen|Rep|Gov)\.?$/;

const LABELED_NAME_PATTERN = new RegExp(
  `\\b(?:[Nn]ame|[Pp]atient|[Cc]lient|[Cc]ustomer|[Aa]pplicant|[Bb]eneficiary|[Rr]ecipient|[Ee]mployee)\\s*[:=-]\\s*([A-Z][A-Za-z'-]{1,25}(?:\\s+[A-Z][A-Za-z'-]{1,25}){0,2})\\b`,
  "g",
);

const NAME_WORD_SRC =
  "(?:(?:Mc|Mac|O'|D')[A-Z][a-z]{1,25}|[A-Z][a-z]{1,25}(?:[-'][A-Z]?[a-z]{1,25})*)";

const HONORIFIC_NAME_PATTERN = new RegExp(
  `\\b(?:Dr|Mr|Mrs|Ms|Mx|Prof|Professor|Sir|Lady|Dame|Rev|Capt|Col|Gen|Sgt|Sen|Rep|Gov)\\.?\\s+${NAME_WORD_SRC}(?:\\s+(?:(?:(?:de|del|da|di|du|von|van|der|den|bin|ibn|al|el|la|le)\\s+){1,2})?${NAME_WORD_SRC}){0,3}(?:\\s*,?\\s*(?:Jr\\.?|Sr\\.?|II|III|IV|Ph\\.?D\\.?|M\\.?D\\.?|Esq\\.?))?\\b`,
  "g",
);

const MULTI_WORD_NAME_PATTERN = new RegExp(
  `\\b${NAME_WORD_SRC}(?:\\s+(?:(?:(?:de|del|da|di|du|von|van|der|den|bin|ibn|al|el|la|le)\\s+){1,2})?${NAME_WORD_SRC}){1,3}(?:\\s*,?\\s*(?:Jr\\.?|Sr\\.?|II|III|IV|Ph\\.?D\\.?|M\\.?D\\.?|Esq\\.?))?\\b`,
  "g",
);

const FOUR_PLUS_DIGITS_PATTERNS: RegExp[] = [
  // Token containing 4+ consecutive digits (including currency, IDs, years, build numbers, port numbers)
  /[£$€¥]?[A-Za-z0-9_./:#=-]*\d{4,}[A-Za-z0-9_./:#=-]*/g,
  // Comma-formatted numbers with 4+ total digits (e.g. $125,000.00, 10,000, 1,234)
  /[£$€¥]?\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b/g,
  // Split digit sequences (4+ digit groups separated by spaces/dots/dashes, e.g. "4 8 2 9" or "12 34 56 78")
  /\b\d{1,3}(?:[ \t.-]+\d{1,3}){3,}\b/g,
];

const HIGH_ENTROPY_CANDIDATE_RE = /\b[A-Za-z0-9_+=/~@#$%^&*-]{12,}\b/g;

// Character-by-character split tokens (4+ single-char tokens separated by spaces, e.g. "J a n e   D o e" or "s k - 1 2 3 4")
const CHAR_SPLIT_TOKEN_RE = /\b[A-Za-z0-9@._+-](?:[ \t]+[A-Za-z0-9@._+-]){3,}\b/g;

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function trimTrailingPunctuation(raw: string): number {
  let trimCount = 0;
  while (
    trimCount < raw.length &&
    /[.,;:!?)\]]/.test(raw[raw.length - 1 - trimCount])
  ) {
    trimCount += 1;
  }
  return trimCount;
}

/**
 * Deterministic, browser-safe, fail-closed mechanical redaction filter (D3).
 *
 * Redacts everything caught by the session scrubber plus:
 * - capitalized multi-word name sequences (`NAME`)
 * - any token with 4+ consecutive digits (`DIGITS`)
 * - high-entropy tokens exceeding the Shannon entropy threshold (`ENTROPY`)
 * - URLs and bare domains (`URL`)
 * - street-address patterns, PO boxes, and postcodes (`ADDRESS`)
 * - dates in ISO, numeric, and month-name formats (`DATE`)
 * - Unicode homoglyphs, fullwidth/mathematical symbols, zero-width characters, and split tokens.
 *
 * Reversible via `restore(s)`.
 */
export function mechanicalRedact(
  text: string,
  opts?: MechanicalRedactOptions,
): MechanicalRedactResult {
  if (!text) {
    return {
      text: text ?? "",
      redactions: [],
      restore: (s: string) => s,
    };
  }

  // If the caller supplied a SessionScrubber instance, register customTerms on it
  if (opts?.scrubber && opts.customTerms) {
    for (const term of opts.customTerms) {
      opts.scrubber.addCustomTerm(term);
    }
  }

  const { normalized, mapToOriginal, mapToOriginalEnd } = normalizeWithIndexMap(text);
  if (!normalized) {
    return {
      text: "",
      redactions: [
        {
          kind: "ENTROPY",
          placeholder: "[ENTROPY_1]",
        },
      ],
      restore: (s: string) => s.replace(/\[ENTROPY_1\]/gi, text),
    };
  }

  const customTerms = new Map<string, string>();
  for (const term of opts?.customTerms ?? []) {
    const cleaned = term.trim();
    if (!cleaned) continue;
    const { normalized: normTerm } = normalizeWithIndexMap(cleaned);
    if (normTerm) {
      customTerms.set(normTerm.toLowerCase(), cleaned);
    }
  }

  const occupied: Array<{ start: number; end: number }> = [];
  const overlaps = (start: number, end: number): boolean =>
    occupied.some((s) => start < s.end && end > s.start);

  const reservedLiterals = new Set<string>();
  const byKey = new Map<string, { placeholder: string; kind: MechanicalRedactionKind; original: string }>();
  const byPlaceholder = new Map<string, { placeholder: string; kind: MechanicalRedactionKind; original: string }>();
  const counters: Record<MechanicalRedactionKind, number> = {
    SECRET: 0,
    EMAIL: 0,
    PHONE: 0,
    IP: 0,
    ACCT: 0,
    ENTITY: 0,
    URL: 0,
    ADDRESS: 0,
    DATE: 0,
    NAME: 0,
    DIGITS: 0,
    ENTROPY: 0,
  };

  const candidates: CandidateSpan[] = [];

  // 0. Protect any literal placeholders already present in `text`
  EXISTING_PLACEHOLDER_RE.lastIndex = 0;
  let litMatch: RegExpExecArray | null;
  while ((litMatch = EXISTING_PLACEHOLDER_RE.exec(text)) !== null) {
    const lit = litMatch[0];
    const start = litMatch.index;
    const end = start + lit.length;
    occupied.push({ start, end });
    reservedLiterals.add(lit.toUpperCase());
  }

  const addSpanFromNormalizedRange = (
    normStart: number,
    normEnd: number,
    kind: MechanicalRedactionKind,
    keySuffix?: string,
  ): void => {
    if (normStart < 0 || normEnd <= normStart || normEnd > mapToOriginal.length) {
      return;
    }
    const origStart = mapToOriginal[normStart];
    const origEnd = mapToOriginalEnd[normEnd - 1];
    if (origEnd <= origStart || overlaps(origStart, origEnd)) {
      return;
    }
    const raw = text.slice(origStart, origEnd);
    occupied.push({ start: origStart, end: origEnd });
    candidates.push({
      start: origStart,
      end: origEnd,
      kind,
      raw,
      canonicalKey: `${kind}:${keySuffix ?? raw}`,
    });
  };

  const addMatches = (
    regex: RegExp,
    kind: MechanicalRedactionKind,
    options?: {
      trimTrailingPunct?: boolean;
      validate?: (normRaw: string, normStart: number, fullNorm: string) => boolean;
      adjustRange?: (normRaw: string, normStart: number, normEnd: number) => { start: number; end: number } | null;
    },
  ): void => {
    const re = new RegExp(regex.source, regex.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(normalized)) !== null) {
      let normRaw = match[0];
      if (!normRaw) {
        re.lastIndex += 1;
        continue;
      }
      let normStart = match.index;
      let normEnd = normStart + normRaw.length;

      if (options?.trimTrailingPunct) {
        const trimLen = trimTrailingPunctuation(normRaw);
        if (trimLen > 0 && trimLen < normRaw.length) {
          normEnd -= trimLen;
          normRaw = normalized.slice(normStart, normEnd);
        }
      }

      if (options?.adjustRange) {
        const adjusted = options.adjustRange(normRaw, normStart, normEnd);
        if (!adjusted || adjusted.end <= adjusted.start) continue;
        normStart = adjusted.start;
        normEnd = adjusted.end;
        normRaw = normalized.slice(normStart, normEnd);
      }

      if (options?.validate && !options.validate(normRaw, normStart, normalized)) {
        continue;
      }

      addSpanFromNormalizedRange(normStart, normEnd, kind);
    }
  };

  // 1. Custom terms (ENTITY), longest first, so explicit caller terms take top priority
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

  // 2. Secrets / API keys / PEM / JWT / connection URLs / split keys
  for (const pat of SECRET_PATTERNS) {
    addMatches(pat, "SECRET", { trimTrailingPunct: true });
  }
  addMatches(BASE64_CANDIDATE_RE, "SECRET", {
    validate: (normRaw) => isBase64WrappedSecret(normRaw),
  });

  // 3. Emails (standard + split/obfuscated)
  for (const pat of EMAIL_PATTERNS) {
    addMatches(pat, "EMAIL", { trimTrailingPunct: true });
  }

  // 4. URLs and domains
  for (const pat of URL_PATTERNS) {
    addMatches(pat, "URL", { trimTrailingPunct: true });
  }

  // 5. Account & government identifiers (0x wallets, BTC, SSNs, UK NI, NHS, passports, IBANs, Luhn cards)
  for (const pat of ACCT_PATTERNS) {
    addMatches(pat, "ACCT", { trimTrailingPunct: true });
  }
  addMatches(IBAN_CANDIDATE_PATTERN, "ACCT", {
    validate: (normRaw) => {
      const cleaned = normRaw.replace(/[\s-]/g, "");
      if (cleaned.length < 15 || cleaned.length > 34) return false;
      const country = cleaned.slice(0, 2).toUpperCase();
      if (!IBAN_COUNTRY_CODES.has(country)) return false;
      const digitCount = (cleaned.match(/\d/g) ?? []).length;
      if (digitCount < 6) return false;
      if (isValidIbanMod97(cleaned)) return true;
      return /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(cleaned);
    },
  });
  addMatches(CREDIT_CARD_CANDIDATE_PATTERN, "ACCT", {
    validate: (normRaw) => isValidLuhn(normRaw),
  });

  // 6. IP addresses (IPv4 and IPv6)
  for (const pat of IP_PATTERNS) {
    addMatches(pat, "IP");
  }

  // 7. Street addresses, PO Boxes, UK postcodes, State + ZIP+4
  for (const pat of ADDRESS_PATTERNS) {
    addMatches(pat, "ADDRESS", { trimTrailingPunct: true });
  }

  // 8. Dates (labeled, ISO, numeric slash/dot/hyphen, and month-name dates)
  for (const pat of DATE_PATTERNS) {
    addMatches(pat, "DATE", { trimTrailingPunct: true });
  }

  // 9. Phone numbers (international, domestic, and 7-digit local numbers)
  for (const pat of PHONE_PATTERNS) {
    addMatches(pat, "PHONE", {
      trimTrailingPunct: true,
      validate: (normRaw, normStart, fullNorm) => {
        const mainPart = normRaw.replace(/(?:ext\.?|extension|x)\s*\d{1,6}$/i, "");
        const digits = mainPart.replace(/\D/g, "");
        if (digits.length < 10 || digits.length > 15) return false;
        if (normStart > 0) {
          const prev = fullNorm[normStart - 1];
          if (/[A-Za-z0-9_./-]/.test(prev)) return false;
        }
        return true;
      },
    });
  }
  addMatches(LOCAL_SEVEN_DIGIT_PHONE_RE, "PHONE", {
    validate: (_normRaw, normStart, fullNorm) => {
      if (normStart > 0 && /[A-Za-z0-9_./-]/.test(fullNorm[normStart - 1])) {
        return false;
      }
      return true;
    },
  });

  // 10. Names: labeled names, honorific names, and capitalized multi-word name sequences
  {
    const re = new RegExp(LABELED_NAME_PATTERN.source, LABELED_NAME_PATTERN.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(normalized)) !== null) {
      const nameGroup = m[1];
      if (!nameGroup) continue;
      const groupOffset = m[0].lastIndexOf(nameGroup);
      if (groupOffset < 0) continue;
      const nStart = m.index + groupOffset;
      const nEnd = nStart + nameGroup.length;
      addSpanFromNormalizedRange(nStart, nEnd, "NAME");
    }
  }

  addMatches(HONORIFIC_NAME_PATTERN, "NAME", {
    trimTrailingPunct: true,
  });

  addMatches(MULTI_WORD_NAME_PATTERN, "NAME", {
    trimTrailingPunct: true,
    adjustRange: (normRaw, normStart, normEnd) => {
      // Strip leading sentence-starter function words (e.g. "Please", "When", "In", "Call")
      const tokens = normRaw.split(/\s+/);
      let dropCount = 0;
      while (
        dropCount < tokens.length &&
        SENTENCE_STARTER_NON_NAMES.has(tokens[dropCount].toLowerCase().replace(/[^a-z]/g, ""))
      ) {
        dropCount += 1;
      }
      const remaining = tokens.slice(dropCount);
      if (remaining.length < 2) {
        if (remaining.length === 1 && dropCount > 0 && HONORIFIC_RE.test(tokens[dropCount - 1])) {
          dropCount -= 1;
        } else {
          return null;
        }
      }
      let newStart = normStart;
      for (let k = 0; k < dropCount; k++) {
        const idx = normalized.indexOf(tokens[k], newStart);
        if (idx >= 0) {
          newStart = idx + tokens[k].length;
          while (newStart < normEnd && /\s/.test(normalized[newStart])) {
            newStart += 1;
          }
        }
      }
      const candidateSlice = normalized.slice(newStart, normEnd).trim();
      const lowerCandidate = candidateSlice.replace(/\s+/g, " ").toLowerCase();
      if (TECHNICAL_TITLE_CASE_ALLOWLIST.has(lowerCandidate)) {
        return null;
      }
      const words = lowerCandidate.split(" ");
      if (words.every((w) => TECHNICAL_SINGLE_WORDS.has(w))) {
        return null;
      }
      // Require at least 2 words containing lowercase letters (not pure acronyms)
      const capWordsWithLower = candidateSlice
        .split(/\s+/)
        .filter((w) => /^[A-Z]/.test(w) && /[a-z]/.test(w));
      if (capWordsWithLower.length < 2) {
        return null;
      }
      return { start: newStart, end: normEnd };
    },
  });

  // 11. Any token with 4+ consecutive digits, comma-grouped 4+ digit numbers, or split digit sequences
  for (const pat of FOUR_PLUS_DIGITS_PATTERNS) {
    addMatches(pat, "DIGITS", {
      trimTrailingPunct: true,
      validate: (normRaw) => {
        const digitsOnly = normRaw.replace(/\D/g, "");
        return digitsOnly.length >= 4;
      },
    });
  }

  // 12. High-entropy tokens (Shannon entropy threshold) and character-by-character split tokens
  addMatches(HIGH_ENTROPY_CANDIDATE_RE, "ENTROPY", {
    trimTrailingPunct: true,
    validate: (normRaw) => isHighEntropyToken(normRaw),
  });

  addMatches(CHAR_SPLIT_TOKEN_RE, "ENTROPY", {
    trimTrailingPunct: true,
  });

  if (candidates.length === 0) {
    return {
      text,
      redactions: [],
      restore: (s: string) => s,
    };
  }

  candidates.sort((a, b) => a.start - b.start);

  const getOrCreatePlaceholder = (span: CandidateSpan): { placeholder: string; kind: MechanicalRedactionKind } => {
    const existing = byKey.get(span.canonicalKey);
    if (existing) {
      return existing;
    }
    let placeholder = "";
    do {
      counters[span.kind] += 1;
      placeholder = `[${span.kind}_${counters[span.kind]}]`;
    } while (
      byPlaceholder.has(placeholder.toUpperCase()) ||
      reservedLiterals.has(placeholder.toUpperCase())
    );

    const mapping = {
      placeholder,
      kind: span.kind,
      original: span.raw,
    };
    byKey.set(span.canonicalKey, mapping);
    byPlaceholder.set(placeholder.toUpperCase(), mapping);
    return mapping;
  };

  const redactions: Array<{ kind: string; placeholder: string }> = [];
  let out = "";
  let cursor = 0;

  for (const span of candidates) {
    out += text.slice(cursor, span.start);
    const mapping = getOrCreatePlaceholder(span);
    out += mapping.placeholder;
    redactions.push({
      kind: mapping.kind,
      placeholder: mapping.placeholder,
    });
    cursor = span.end;
  }
  out += text.slice(cursor);

  const restore = (s: string): string => {
    if (!s || byPlaceholder.size === 0) return s;
    return s.replace(RESTORE_PLACEHOLDER_RE, (token) => {
      const entry = byPlaceholder.get(token.toUpperCase());
      return entry ? entry.original : token;
    });
  };

  return {
    text: out,
    redactions,
    restore,
  };
}
