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

const SECRET_PATTERNS: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/g,
  /\b(?:sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{8,}|tk_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,})\b/g,
];

const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const ACCT_PATTERNS: RegExp[] = [
  // 0x Ethereum/EVM wallet address (40 hex chars)
  /\b0x[a-fA-F0-9]{40}\b/g,
  // IBAN (2 letters + 2 check digits + 11..30 alphanumeric chars, optional spaces)
  /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g,
  // Credit card numbers (13-19 digits, spaced/dashed in groups of 4 or contiguous)
  /\b(?:\d{4}[ -]){3}\d{1,4}\b|\b\d{13,19}\b/g,
];

const IP_PATTERN =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

const PHONE_PATTERNS: RegExp[] = [
  // International or formatted US/UK phone numbers
  /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\b\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,6}(?:[\s.-]\d{1,4})?\b/g,
  // International + phone with 1 or 2 space-separated blocks (e.g. +44 7911 123456 or +14155550199)
  /\+\d{1,3}(?:[\s.-]?\d{2,6}){2,4}\b/g,
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
      return `${kind}:${trimmed.toLowerCase()}`;
    case "ACCT":
      if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
        return `${kind}:${trimmed.toLowerCase()}`;
      }
      return `${kind}:${trimmed.replace(/[\s-]/g, "").toUpperCase()}`;
    case "PHONE":
      return `${kind}:${trimmed.replace(/[\s.()-]/g, "")}`;
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
    const lower = cleaned.toLowerCase();
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
    counters[kind] += 1;
    const placeholder = `[${kind}_${counters[kind]}]`;
    const original =
      kind === "ENTITY" ? (customTerms.get(raw.trim().toLowerCase()) ?? raw) : raw;
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
    const occupied: { start: number; end: number }[] = [];

    const overlaps = (start: number, end: number): boolean =>
      occupied.some((s) => start < s.end && end > s.start);

    // Protect any existing placeholders already in the text
    PLACEHOLDER_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PLACEHOLDER_RE.exec(text)) !== null) {
      occupied.push({ start: m.index, end: m.index + m[0].length });
    }

    const candidates: CandidateSpan[] = [];

    const addMatches = (
      regex: RegExp,
      kind: PiiKind,
      validate?: (raw: string, start: number, fullText: string) => boolean,
    ) => {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        const raw = match[0];
        const start = match.index;
        const end = start + raw.length;
        if (overlaps(start, end)) continue;
        if (validate && !validate(raw, start, text)) continue;
        occupied.push({ start, end });
        candidates.push({
          start,
          end,
          kind,
          raw,
          canonicalKey: canonicalKeyFor(kind, raw),
        });
      }
    };

    // 1. Secrets / API keys / tokens
    for (const pat of SECRET_PATTERNS) {
      addMatches(pat, "SECRET");
    }

    // 2. Email addresses
    addMatches(EMAIL_PATTERN, "EMAIL");

    // 3. Account identifiers: 0x wallets, IBANs, credit cards
    for (const pat of ACCT_PATTERNS) {
      addMatches(pat, "ACCT");
    }

    // 4. IPv4 addresses
    addMatches(IP_PATTERN, "IP");

    // 5. Phone numbers (>= 10 and <= 15 digits, not preceded by word/dot/slash)
    for (const pat of PHONE_PATTERNS) {
      addMatches(pat, "PHONE", (raw, start, full) => {
        const digits = raw.replace(/\D/g, "");
        if (digits.length < 10 || digits.length > 15) return false;
        if (start > 0) {
          const prev = full[start - 1];
          if (/[A-Za-z0-9_./-]/.test(prev)) return false;
        }
        return true;
      });
    }

    // 6. Custom terms (ENTITY), longest first
    if (customTerms.size > 0) {
      const sortedTerms = [...customTerms.values()].sort((a, b) => b.length - a.length);
      for (const term of sortedTerms) {
        const escaped = escapeRegExp(term);
        const startsWithWord = /^\w/.test(term);
        const endsWithWord = /\w$/.test(term);
        const pattern = `${startsWithWord ? "\\b" : ""}${escaped}${endsWithWord ? "\\b" : ""}`;
        addMatches(new RegExp(pattern, "gi"), "ENTITY");
      }
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
    return text.replace(PLACEHOLDER_RE, (token) => {
      const entry = byPlaceholder.get(token);
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
