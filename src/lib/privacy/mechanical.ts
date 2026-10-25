import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
  type RegexRuleSpec,
} from "./mechanical-ruleset";
import type { SessionScrubber } from "./scrubber";

export type MechanicalRedactionKind =
  | "MARKED"
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

export interface MechanicalSessionEntry {
  placeholder: string;
  kind: MechanicalRedactionKind;
  original: string;
}

export interface MechanicalSession {
  redact(
    text: string,
    opts?: Omit<MechanicalRedactOptions, "session">,
  ): MechanicalRedactResult;
  restore(text: string): string;
  addCustomTerm(term: string): void;
  entries(): MechanicalSessionEntry[];
  clear(): void;
  clone(): MechanicalSession;
}

export interface MechanicalRedactOptions {
  customTerms?: string[];
  scrubber?: SessionScrubber;
  session?: MechanicalSession;
  ruleset?: MechanicalRuleset;
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
  existingPlaceholder?: string;
  emptyRemoval?: boolean;
}

interface MechanicalSessionState {
  readonly customTerms: Map<string, string>;
  readonly byKey: Map<string, MechanicalSessionEntry>;
  readonly byPlaceholder: Map<string, MechanicalSessionEntry>;
  readonly reservedLiterals: Set<string>;
  readonly counters: Record<MechanicalRedactionKind, number>;
}

function createEmptyCounters(): Record<MechanicalRedactionKind, number> {
  return {
    MARKED: 0,
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
}

function createSessionState(): MechanicalSessionState {
  return {
    customTerms: new Map<string, string>(),
    byKey: new Map<string, MechanicalSessionEntry>(),
    byPlaceholder: new Map<string, MechanicalSessionEntry>(),
    reservedLiterals: new Set<string>(),
    counters: createEmptyCounters(),
  };
}

const sessionStateMap = new WeakMap<
  MechanicalSession,
  MechanicalSessionState
>();
const scrubberStateMap = new WeakMap<
  SessionScrubber,
  MechanicalSessionState
>();

function compileRuleSpec(spec: RegexRuleSpec): RegExp {
  return new RegExp(spec.source, spec.flags);
}

function isZeroWidthOrVariationSelector(
  code: number,
  ruleset: MechanicalRuleset,
): boolean {
  const { zeroWidthCodeUnits, variationSelectorRange } =
    ruleset.unicodeNormalization;
  if (zeroWidthCodeUnits.includes(code)) return true;
  if (
    code >= variationSelectorRange[0] &&
    code <= variationSelectorRange[1]
  ) {
    return true;
  }
  return false;
}

function isCombiningDiacritic(
  code: number,
  ruleset: MechanicalRuleset,
): boolean {
  const [minCode, maxCode] =
    ruleset.unicodeNormalization.combiningDiacriticRange;
  return code >= minCode && code <= maxCode;
}

function foldMathAlphanumericCodePoint(
  cp: number,
  ruleset: MechanicalRuleset,
): string | null {
  const {
    mathDigitCodePointRange,
    mathDigitModulus,
    mathAlphaCodePointRange,
    mathAlphaSetSize,
    mathAlphaUpperCount,
    asciiDigitZeroCode,
    asciiUpperACode,
    asciiLowerACode,
  } = ruleset.unicodeNormalization;

  if (
    cp >= mathDigitCodePointRange[0] &&
    cp <= mathDigitCodePointRange[1]
  ) {
    const digit = (cp - mathDigitCodePointRange[0]) % mathDigitModulus;
    return String.fromCharCode(asciiDigitZeroCode + digit);
  }
  if (
    cp >= mathAlphaCodePointRange[0] &&
    cp <= mathAlphaCodePointRange[1]
  ) {
    const offset = (cp - mathAlphaCodePointRange[0]) % mathAlphaSetSize;
    if (offset < mathAlphaUpperCount) {
      return String.fromCharCode(asciiUpperACode + offset);
    }
    return String.fromCharCode(asciiLowerACode + (offset - mathAlphaUpperCount));
  }
  return null;
}

/**
 * Strips zero-width/bidi/variation characters, absorbs combining diacritics, and folds
 * fullwidth ASCII, mathematical symbols, accented Latin, and Cyrillic/Greek homoglyphs
 * to canonical ASCII while maintaining an exact start and end index map back to `text`.
 */
export function normalizeWithIndexMap(
  text: string,
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): {
  normalized: string;
  mapToOriginal: number[];
  mapToOriginalEnd: number[];
} {
  const chars: string[] = [];
  const mapToOriginal: number[] = [];
  const mapToOriginalEnd: number[] = [];
  const normCfg = ruleset.unicodeNormalization;
  const combiningStripRe = compileRuleSpec(
    normCfg.combiningDiacriticStripPattern,
  );

  let i = 0;
  while (i < text.length) {
    const code = text.charCodeAt(i);

    if (
      isZeroWidthOrVariationSelector(code, ruleset) ||
      isCombiningDiacritic(code, ruleset)
    ) {
      if (isCombiningDiacritic(code, ruleset) && mapToOriginalEnd.length > 0) {
        mapToOriginalEnd[mapToOriginalEnd.length - 1] = i + 1;
      }
      i += 1;
      continue;
    }

    let ch = text[i];
    let step = 1;

    if (code === normCfg.mathSurrogateHigh && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if (
        low >= normCfg.mathSurrogateLowRange[0] &&
        low <= normCfg.mathSurrogateLowRange[1]
      ) {
        const cp =
          ((code - normCfg.utf16HighSurrogateBase) << 10) +
          (low - normCfg.utf16LowSurrogateBase) +
          normCfg.utf16SupplementaryPlaneOffset;
        const foldedMath = foldMathAlphanumericCodePoint(cp, ruleset);
        if (foldedMath) {
          ch = foldedMath;
          step = 2;
        }
      }
    } else if (
      code >= normCfg.fullwidthAsciiRange[0] &&
      code <= normCfg.fullwidthAsciiRange[1]
    ) {
      ch = String.fromCharCode(code - normCfg.fullwidthAsciiDelta);
    } else if (
      code >= normCfg.circledDigitRange[0] &&
      code <= normCfg.circledDigitRange[1]
    ) {
      ch = String.fromCharCode(
        normCfg.circledDigitBaseCode + (code - normCfg.circledDigitRange[0]),
      );
    } else if (ch in normCfg.homoglyphMap) {
      ch = normCfg.homoglyphMap[ch];
    } else if (
      code >= normCfg.precomposedLatinRange[0] &&
      code <= normCfg.precomposedLatinRange[1]
    ) {
      const base = ch.normalize("NFKD").replace(combiningStripRe, "");
      if (base.length === 1) {
        ch = base;
      }
    }

    const origStart = i;
    let origEnd = i + step;
    while (
      origEnd < text.length &&
      isCombiningDiacritic(text.charCodeAt(origEnd), ruleset)
    ) {
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
 * All regexes and thresholds come from `MECHANICAL_RULESET`.
 */
export function isHighEntropyToken(
  token: string,
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): boolean {
  const ent = ruleset.entropyRules;
  const cleaned = token.replace(compileRuleSpec(ent.trimNonAlnumPattern), "");
  if (cleaned.length < ent.minLength) return false;
  if (compileRuleSpec(ruleset.placeholderPatterns.bracketedToken).test(token)) {
    return false;
  }

  if (
    compileRuleSpec(ent.hyphenatedTechIdPattern).test(cleaned) &&
    !compileRuleSpec(ent.fourDigitsPattern).test(cleaned)
  ) {
    return false;
  }

  const hasLower = compileRuleSpec(ent.lowerClassPattern).test(cleaned);
  const hasUpper = compileRuleSpec(ent.upperClassPattern).test(cleaned);
  const hasDigit = compileRuleSpec(ent.digitClassPattern).test(cleaned);
  const hasSymbol = compileRuleSpec(ent.symbolClassPattern).test(cleaned);
  const classCount =
    (hasLower ? 1 : 0) +
    (hasUpper ? 1 : 0) +
    (hasDigit ? 1 : 0) +
    (hasSymbol ? 1 : 0);

  const entropy = computeShannonEntropy(cleaned);

  if (
    compileRuleSpec(ent.hexCandidatePattern).test(cleaned) &&
    entropy >= ent.hexMinEntropy
  ) {
    return true;
  }

  if (
    cleaned.length >= ent.threeClassMinLength &&
    classCount >= ent.threeClassMinClasses &&
    (hasDigit || hasSymbol) &&
    entropy >= ent.threeClassMinEntropy
  ) {
    return true;
  }

  if (
    cleaned.length >= ent.twoClassMinLength &&
    classCount >= ent.twoClassMinClasses &&
    (hasDigit || hasSymbol) &&
    entropy >= ent.twoClassMinEntropy
  ) {
    return true;
  }

  if (cleaned.length >= ent.mixedCaseMinLength && hasLower && hasUpper) {
    const upperCount = (
      cleaned.match(compileRuleSpec(ent.upperClassPattern)) ?? []
    ).length;
    if (
      upperCount >= ent.mixedCaseMinUpperCount &&
      entropy >= ent.mixedCaseMinEntropy
    ) {
      return true;
    }
  }

  if (
    cleaned.length >= ent.singleAlphaMinLength &&
    compileRuleSpec(ent.alphaOnlyPattern).test(cleaned)
  ) {
    const lower = cleaned.toLowerCase();
    const hasFiveConsonants = compileRuleSpec(
      ent.fiveConsonantsPattern,
    ).test(lower);
    const vowelCount = (
      lower.match(compileRuleSpec(ent.vowelPattern)) ?? []
    ).length;
    const vowelRatio = vowelCount / lower.length;
    if (
      (hasFiveConsonants && entropy >= ent.singleAlphaConsonantMinEntropy) ||
      (vowelRatio < ent.singleAlphaMaxVowelRatio &&
        entropy >= ent.singleAlphaLowVowelMinEntropy) ||
      entropy >= ent.singleAlphaExtremeEntropy
    ) {
      return true;
    }
  }

  return false;
}

function isBase64WrappedSecret(
  raw: string,
  ruleset: MechanicalRuleset,
): boolean {
  const {
    base64MinRawLength,
    base64InvalidRemainder,
    base64MinDecodedLength,
  } = ruleset.thresholds;
  if (
    raw.length < base64MinRawLength ||
    raw.length % 4 === base64InvalidRemainder
  ) {
    return false;
  }
  try {
    let decoded = "";
    if (typeof Buffer !== "undefined") {
      decoded = Buffer.from(raw, "base64").toString("utf8");
    } else if (typeof globalThis.atob === "function") {
      decoded = globalThis.atob(raw);
    }
    if (!decoded || decoded.length < base64MinDecodedLength) return false;
    return compileRuleSpec(ruleset.patterns.decodedSecretCheck).test(decoded);
  } catch {
    return false;
  }
}

/**
 * Validates a payment card number using the ISO/IEC 7812 Luhn check.
 * Every regex and numeric bound is read from `ruleset`.
 */
export function isValidLuhn(
  raw: string,
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): boolean {
  const digits = raw.replace(compileRuleSpec(ruleset.patterns.nonDigitsStrip), "");
  const {
    luhnMinDigits,
    luhnMaxDigits,
    luhnDoubleSubtract,
    luhnModulus,
  } = ruleset.thresholds;
  if (digits.length < luhnMinDigits || digits.length > luhnMaxDigits) {
    return false;
  }
  if (compileRuleSpec(ruleset.patterns.allZerosPattern).test(digits)) {
    return false;
  }

  const zeroCode = ruleset.unicodeNormalization.asciiDigitZeroCode;
  const maxDigit =
    ruleset.unicodeNormalization.asciiDigitNineCode - zeroCode;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - zeroCode;
    if (d < 0 || d > maxDigit) return false;
    if (shouldDouble) {
      d *= 2;
      if (d > maxDigit) d -= luhnDoubleSubtract;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % luhnModulus === 0;
}

/**
 * Validates an IBAN string using ISO 13616 structure and ISO 7064 Mod-97-10 check.
 * Every regex, country code list, and numeric bound is read from `ruleset`.
 */
export function isValidIbanMod97(
  raw: string,
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): boolean {
  const cleaned = raw
    .replace(compileRuleSpec(ruleset.patterns.ibanStripSeparators), "")
    .toUpperCase();
  const {
    ibanMinLength,
    ibanMaxLength,
    ibanHeaderSliceLength,
    ibanLetterOffset,
    ibanModulus,
    ibanExpectedRemainder,
  } = ruleset.thresholds;
  if (cleaned.length < ibanMinLength || cleaned.length > ibanMaxLength) {
    return false;
  }
  if (!compileRuleSpec(ruleset.patterns.ibanStructuralFallback).test(cleaned)) {
    return false;
  }
  if (!ruleset.wordLists.ibanCountryCodes.includes(cleaned.slice(0, 2))) {
    return false;
  }

  const {
    asciiDigitZeroCode,
    asciiDigitNineCode,
    asciiUpperACode,
    asciiUpperZCode,
  } = ruleset.unicodeNormalization;
  const rearranged =
    cleaned.slice(ibanHeaderSliceLength) +
    cleaned.slice(0, ibanHeaderSliceLength);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= asciiDigitZeroCode && code <= asciiDigitNineCode) {
      remainder =
        (remainder * 10 + (code - asciiDigitZeroCode)) % ibanModulus;
    } else if (code >= asciiUpperACode && code <= asciiUpperZCode) {
      const val = code - ibanLetterOffset;
      remainder = (remainder * 100 + val) % ibanModulus;
    } else {
      return false;
    }
  }
  return remainder === ibanExpectedRemainder;
}

function escapeRegExp(str: string, ruleset: MechanicalRuleset): string {
  return str.replace(
    compileRuleSpec(ruleset.patterns.regexSpecialCharsEscape),
    "\\$&",
  );
}

function trimTrailingPunctuation(
  raw: string,
  ruleset: MechanicalRuleset,
): number {
  const punctRe = compileRuleSpec(
    ruleset.placeholderPatterns.trailingPunctuationCharClass,
  );
  let trimCount = 0;
  while (
    trimCount < raw.length &&
    punctRe.test(raw[raw.length - 1 - trimCount])
  ) {
    trimCount += 1;
  }
  return trimCount;
}

function addCustomTermToState(
  state: MechanicalSessionState,
  term: string,
  ruleset: MechanicalRuleset,
): void {
  const cleaned = term.trim();
  if (!cleaned) return;
  const { normalized: normTerm } = normalizeWithIndexMap(cleaned, ruleset);
  if (normTerm) {
    state.customTerms.set(normTerm.toLowerCase(), cleaned);
  }
}

function resolveSessionState(
  opts?: MechanicalRedactOptions,
): MechanicalSessionState {
  if (opts?.session) {
    let existing = sessionStateMap.get(opts.session);
    if (!existing) {
      existing = createSessionState();
      sessionStateMap.set(opts.session, existing);
    }
    return existing;
  }
  if (opts?.scrubber) {
    let existing = scrubberStateMap.get(opts.scrubber);
    if (!existing) {
      existing = createSessionState();
      scrubberStateMap.set(opts.scrubber, existing);
    }
    return existing;
  }
  return createSessionState();
}

/**
 * Creates a multi-turn mechanical redaction session whose original-to-placeholder
 * map persists across calls in one chat so the same original always maps to the
 * same placeholder and different originals never collide.
 */
export function createMechanicalSession(
  initialCustomTerms: string[] = [],
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): MechanicalSession {
  const state = createSessionState();
  for (const term of initialCustomTerms) {
    addCustomTermToState(state, term, ruleset);
  }

  const restorePlaceholderRe = compileRuleSpec(
    ruleset.placeholderPatterns.restorePlaceholder,
  );

  const session: MechanicalSession = {
    redact(
      text: string,
      opts?: Omit<MechanicalRedactOptions, "session">,
    ): MechanicalRedactResult {
      return mechanicalRedact(text, {
        ...opts,
        ruleset: opts?.ruleset ?? ruleset,
        session,
      });
    },
    restore(text: string): string {
      if (!text || state.byPlaceholder.size === 0) return text;
      return text.replace(restorePlaceholderRe, (token) => {
        const entry = state.byPlaceholder.get(token.toUpperCase());
        return entry ? entry.original : token;
      });
    },
    addCustomTerm(term: string): void {
      addCustomTermToState(state, term, ruleset);
    },
    entries(): MechanicalSessionEntry[] {
      return [...state.byPlaceholder.values()].map(
        ({ placeholder, kind, original }) => ({
          placeholder,
          kind,
          original,
        }),
      );
    },
    clear(): void {
      state.customTerms.clear();
      state.byKey.clear();
      state.byPlaceholder.clear();
      state.reservedLiterals.clear();
      const emptyCounters = createEmptyCounters();
      for (const k of Object.keys(emptyCounters) as MechanicalRedactionKind[]) {
        state.counters[k] = 0;
      }
      for (const term of initialCustomTerms) {
        addCustomTermToState(state, term, ruleset);
      }
    },
    clone(): MechanicalSession {
      const cloned = createMechanicalSession(initialCustomTerms, ruleset);
      const clonedState = sessionStateMap.get(cloned);
      if (clonedState) {
        clonedState.customTerms.clear();
        for (const [k, v] of state.customTerms.entries()) {
          clonedState.customTerms.set(k, v);
        }
        for (const [k, v] of state.byKey.entries()) {
          const entryCopy = { ...v };
          clonedState.byKey.set(k, entryCopy);
          clonedState.byPlaceholder.set(entryCopy.placeholder.toUpperCase(), entryCopy);
        }
        for (const lit of state.reservedLiterals) {
          clonedState.reservedLiterals.add(lit);
        }
        for (const k of Object.keys(state.counters) as MechanicalRedactionKind[]) {
          clonedState.counters[k] = state.counters[k];
        }
      }
      return cloned;
    },
  };

  sessionStateMap.set(session, state);
  return session;
}

/**
 * Deterministic, browser-safe, fail-closed mechanical redaction filter (D3).
 *
 * Reads all rules from `MECHANICAL_RULESET` in `mechanical-ruleset.ts`.
 * Reversible via `restore(s)`.
 */
export function mechanicalRedact(
  text: string,
  opts?: MechanicalRedactOptions,
): MechanicalRedactResult {
  const ruleset = opts?.ruleset ?? MECHANICAL_RULESET;
  const state = resolveSessionState(opts);

  if (opts?.scrubber && opts.customTerms) {
    for (const term of opts.customTerms) {
      opts.scrubber.addCustomTerm(term);
    }
  }

  const restorePlaceholderRe = compileRuleSpec(
    ruleset.placeholderPatterns.restorePlaceholder,
  );
  const restore = (s: string): string => {
    if (!s || state.byPlaceholder.size === 0) return s;
    return s.replace(restorePlaceholderRe, (token) => {
      const entry = state.byPlaceholder.get(token.toUpperCase());
      return entry ? entry.original : token;
    });
  };

  if (!text) {
    return {
      text: text ?? "",
      redactions: [],
      restore,
    };
  }

  const { normalized, mapToOriginal, mapToOriginalEnd } = normalizeWithIndexMap(
    text,
    ruleset,
  );
  if (!normalized) {
    const fallbackPlaceholder =
      ruleset.placeholderPatterns.defaultFallbackPlaceholder;
    const fallbackRestoreRe = compileRuleSpec(
      ruleset.placeholderPatterns.defaultFallbackRestorePattern,
    );
    return {
      text: "",
      redactions: [
        {
          kind: "ENTROPY",
          placeholder: fallbackPlaceholder,
        },
      ],
      restore: (s: string) => restore(s).replace(fallbackRestoreRe, text),
    };
  }

  const customTerms = new Map<string, string>(state.customTerms);
  for (const term of opts?.customTerms ?? []) {
    const cleaned = term.trim();
    if (!cleaned) continue;
    const { normalized: normTerm } = normalizeWithIndexMap(cleaned, ruleset);
    if (normTerm) {
      customTerms.set(normTerm.toLowerCase(), cleaned);
    }
  }

  const occupied: Array<{ start: number; end: number }> = [];
  const overlaps = (start: number, end: number): boolean =>
    occupied.some((s) => start < s.end && end > s.start);

  const { reservedLiterals, byKey, byPlaceholder, counters } = state;

  const candidates: CandidateSpan[] = [];

  // 0a. Explicit user markers (e.g. ££...££) from ruleset.markerRule: runs FIRST and fails closed
  const { openMarker, closeMarker, kind: markerKind } = ruleset.markerRule;
  if (openMarker && closeMarker) {
    let searchFrom = 0;
    while (searchFrom < text.length) {
      const openIdx = text.indexOf(openMarker, searchFrom);
      if (openIdx === -1) break;
      const contentStart = openIdx + openMarker.length;
      const closeIdx = text.indexOf(closeMarker, contentStart);
      if (closeIdx === -1) {
        // Fail closed: unclosed opening marker hides everything to the end of the message
        const spanStart = openIdx;
        const spanEnd = text.length;
        const innerRaw = text.slice(contentStart, spanEnd);
        occupied.push({ start: spanStart, end: spanEnd });
        if (!innerRaw) {
          candidates.push({
            start: spanStart,
            end: spanEnd,
            kind: markerKind,
            raw: "",
            canonicalKey: "",
            emptyRemoval: true,
          });
        } else {
          const { normalized: normInner } = normalizeWithIndexMap(
            innerRaw,
            ruleset,
          );
          const normKey = (normInner || innerRaw).toLowerCase();
          candidates.push({
            start: spanStart,
            end: spanEnd,
            kind: markerKind,
            raw: innerRaw,
            canonicalKey: `${markerKind}:${normKey}`,
          });
        }
        break;
      } else {
        const spanStart = openIdx;
        const spanEnd = closeIdx + closeMarker.length;
        const innerRaw = text.slice(contentStart, closeIdx);
        occupied.push({ start: spanStart, end: spanEnd });
        if (!innerRaw) {
          candidates.push({
            start: spanStart,
            end: spanEnd,
            kind: markerKind,
            raw: "",
            canonicalKey: "",
            emptyRemoval: true,
          });
        } else {
          const { normalized: normInner } = normalizeWithIndexMap(
            innerRaw,
            ruleset,
          );
          const normKey = (normInner || innerRaw).toLowerCase();
          candidates.push({
            start: spanStart,
            end: spanEnd,
            kind: markerKind,
            raw: innerRaw,
            canonicalKey: `${markerKind}:${normKey}`,
          });
        }
        searchFrom = spanEnd;
      }
    }
  }

  // 0b. Protect any literal placeholders already present in `text`
  const existingPlaceholderRe = compileRuleSpec(
    ruleset.placeholderPatterns.existingPlaceholder,
  );
  let litMatch: RegExpExecArray | null;
  while ((litMatch = existingPlaceholderRe.exec(text)) !== null) {
    const lit = litMatch[0];
    const start = litMatch.index;
    const end = start + lit.length;
    if (overlaps(start, end)) continue;
    occupied.push({ start, end });
    const upperLit = lit.toUpperCase();
    if (byPlaceholder.has(upperLit)) {
      candidates.push({
        start,
        end,
        kind: "ENTITY",
        raw: lit,
        canonicalKey: `LITERAL_COLLISION:${upperLit}`,
      });
    } else {
      reservedLiterals.add(upperLit);
    }
  }

  // 0c. Re-hide known values already hidden in the session (longest first, single pass)
  if (opts?.session && ruleset.sessionKnownValues.enabled) {
    const knownCfg = ruleset.sessionKnownValues;
    const cjkRe = compileRuleSpec(knownCfg.cjkPattern);
    const startsWithWordRe = compileRuleSpec(
      ruleset.patterns.startsWithWordChar,
    );
    const endsWithWordRe = compileRuleSpec(ruleset.patterns.endsWithWordChar);

    const sessionEntries = opts.session.entries();
    const eligibleEntries: Array<{
      trimmed: string;
      key: string;
      placeholder: string;
      kind: MechanicalRedactionKind;
    }> = [];
    const byKeyOrOriginal = new Map<
      string,
      { placeholder: string; kind: MechanicalRedactionKind }
    >();

    for (const entry of sessionEntries) {
      const trimmed = entry.original.trim();
      if (!trimmed) continue;
      if (existingPlaceholderRe.test(trimmed)) {
        existingPlaceholderRe.lastIndex = 0;
        continue;
      }
      existingPlaceholderRe.lastIndex = 0;
      const minLen = cjkRe.test(trimmed)
        ? knownCfg.minLengthCjk
        : knownCfg.minLength;
      if (trimmed.length < minLen) continue;
      const lookupKey = knownCfg.caseInsensitive
        ? trimmed.toLowerCase()
        : trimmed;
      if (!byKeyOrOriginal.has(lookupKey)) {
        const item = {
          trimmed,
          key: lookupKey,
          placeholder: entry.placeholder,
          kind: entry.kind,
        };
        byKeyOrOriginal.set(lookupKey, {
          placeholder: entry.placeholder,
          kind: entry.kind,
        });
        eligibleEntries.push(item);
      }
    }

    if (eligibleEntries.length > 0) {
      eligibleEntries.sort((a, b) => b.trimmed.length - a.trimmed.length);
      const patternSources = eligibleEntries.map((item) => {
        const escaped = escapeRegExp(item.trimmed, ruleset);
        if (!knownCfg.wordBoundaryAscii) {
          return escaped;
        }
        const prefix = startsWithWordRe.test(item.trimmed) ? "\\b" : "";
        const suffix = endsWithWordRe.test(item.trimmed) ? "\\b" : "";
        return `${prefix}${escaped}${suffix}`;
      });
      const knownRe = compileRuleSpec({
        source: patternSources.join("|"),
        flags: knownCfg.caseInsensitive ? "gi" : "g",
      });
      let knownMatch: RegExpExecArray | null;
      while ((knownMatch = knownRe.exec(text)) !== null) {
        const rawMatch = knownMatch[0];
        if (!rawMatch) {
          knownRe.lastIndex += 1;
          continue;
        }
        const mStart = knownMatch.index;
        const mEnd = mStart + rawMatch.length;
        if (overlaps(mStart, mEnd)) continue;
        const matchKey = knownCfg.caseInsensitive
          ? rawMatch.toLowerCase()
          : rawMatch;
        const target = byKeyOrOriginal.get(matchKey);
        if (!target) continue;
        occupied.push({ start: mStart, end: mEnd });
        candidates.push({
          start: mStart,
          end: mEnd,
          kind: target.kind,
          raw: rawMatch,
          canonicalKey: "",
          existingPlaceholder: target.placeholder,
        });
      }
    }
  }

  const addSpanFromNormalizedRange = (
    normStart: number,
    normEnd: number,
    kind: MechanicalRedactionKind,
    keySuffix?: string,
    trimTrailingPunct?: boolean,
  ): void => {
    if (
      normStart < 0 ||
      normEnd <= normStart ||
      normEnd > mapToOriginal.length
    ) {
      return;
    }
    const origStart = mapToOriginal[normStart];
    const origEnd = mapToOriginalEnd[normEnd - 1];
    if (origEnd <= origStart) {
      return;
    }
    if (!overlaps(origStart, origEnd)) {
      const raw = text.slice(origStart, origEnd);
      const normSlice = normalized.slice(normStart, normEnd);
      const defaultKey =
        kind === "SECRET" || kind === "ENTROPY"
          ? normSlice
          : normSlice.toLowerCase();
      occupied.push({ start: origStart, end: origEnd });
      candidates.push({
        start: origStart,
        end: origEnd,
        kind,
        raw,
        canonicalKey: `${kind}:${keySuffix ?? defaultKey}`,
      });
      return;
    }

    // If the range overlaps one or more explicit MARKED spans (and no other occupied spans),
    // redact the non-overlapping normalized sub-ranges around the marked spans so wrapping a
    // substring inside a URL/path/secret with ££...££ still hides the surrounding token.
    const overlapping = occupied.filter(
      (s) => origStart < s.end && origEnd > s.start,
    );
    const allOverlappingAreMarked = overlapping.every((s) =>
      candidates.some(
        (c) => c.kind === "MARKED" && c.start === s.start && c.end === s.end,
      ),
    );
    if (!allOverlappingAreMarked) {
      return;
    }

    let subStart = normStart;
    while (subStart < normEnd) {
      while (
        subStart < normEnd &&
        overlaps(mapToOriginal[subStart], mapToOriginalEnd[subStart])
      ) {
        subStart += 1;
      }
      if (subStart >= normEnd) break;
      let subEnd = subStart + 1;
      while (
        subEnd < normEnd &&
        !overlaps(mapToOriginal[subEnd], mapToOriginalEnd[subEnd])
      ) {
        subEnd += 1;
      }
      let trimmedEnd = subEnd;
      if (trimTrailingPunct) {
        const subRaw = normalized.slice(subStart, trimmedEnd);
        const trimLen = trimTrailingPunctuation(subRaw, ruleset);
        if (trimLen > 0 && trimLen < subRaw.length) {
          trimmedEnd -= trimLen;
        }
      }
      if (trimmedEnd > subStart) {
        const segOrigStart = mapToOriginal[subStart];
        const segOrigEnd = mapToOriginalEnd[trimmedEnd - 1];
        if (segOrigEnd > segOrigStart && !overlaps(segOrigStart, segOrigEnd)) {
          const segRaw = text.slice(segOrigStart, segOrigEnd);
          const segNorm = normalized.slice(subStart, trimmedEnd);
          const segKey =
            kind === "SECRET" || kind === "ENTROPY"
              ? segNorm
              : segNorm.toLowerCase();
          occupied.push({ start: segOrigStart, end: segOrigEnd });
          candidates.push({
            start: segOrigStart,
            end: segOrigEnd,
            kind,
            raw: segRaw,
            canonicalKey: `${kind}:${segKey}`,
          });
        }
      }
      subStart = subEnd;
    }
  };

  const addMatches = (
    spec: RegexRuleSpec,
    kind: MechanicalRedactionKind,
    options?: {
      trimTrailingPunct?: boolean;
      keySuffix?: string;
      validate?: (
        normRaw: string,
        normStart: number,
        fullNorm: string,
      ) => boolean;
      adjustRange?: (
        normRaw: string,
        normStart: number,
        normEnd: number,
      ) => { start: number; end: number } | null;
    },
  ): void => {
    const re = compileRuleSpec(spec);
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
        const trimLen = trimTrailingPunctuation(normRaw, ruleset);
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

      if (
        options?.validate &&
        !options.validate(normRaw, normStart, normalized)
      ) {
        continue;
      }

      addSpanFromNormalizedRange(
        normStart,
        normEnd,
        kind,
        options?.keySuffix,
        options?.trimTrailingPunct,
      );
    }
  };

  // 1. Custom terms (ENTITY), longest first, so explicit caller terms take top priority
  if (customTerms.size > 0) {
    const startsWithWordRe = compileRuleSpec(
      ruleset.patterns.startsWithWordChar,
    );
    const endsWithWordRe = compileRuleSpec(ruleset.patterns.endsWithWordChar);
    const sortedTerms = [...customTerms.keys()].sort(
      (a, b) => b.length - a.length,
    );
    for (const normTerm of sortedTerms) {
      const escaped = escapeRegExp(normTerm, ruleset);
      const startsWithWord = startsWithWordRe.test(normTerm);
      const endsWithWord = endsWithWordRe.test(normTerm);
      const source = `${startsWithWord ? "\\b" : ""}${escaped}${endsWithWord ? "\\b" : ""}`;
      addMatches({ source, flags: "gi" }, "ENTITY", {
        keySuffix: normTerm,
      });
    }
  }

  // 2. Secrets / API keys / PEM / JWT / connection URLs / split keys
  for (const pat of ruleset.patterns.secret) {
    addMatches(pat, "SECRET", { trimTrailingPunct: true });
  }
  addMatches(ruleset.patterns.base64Candidate, "SECRET", {
    validate: (normRaw) => isBase64WrappedSecret(normRaw, ruleset),
  });

  // 3. Emails (standard + split/obfuscated)
  for (const pat of ruleset.patterns.email) {
    addMatches(pat, "EMAIL", { trimTrailingPunct: true });
  }

  // 4. URLs and domains
  for (const pat of ruleset.patterns.url) {
    addMatches(pat, "URL", { trimTrailingPunct: true });
  }

  // 5. Account & government identifiers (0x wallets, BTC, SSNs, UK NI, NHS, passports, IBANs, Luhn cards)
  for (const pat of ruleset.patterns.acct) {
    addMatches(pat, "ACCT", { trimTrailingPunct: true });
  }
  const ibanCountries = new Set(ruleset.wordLists.ibanCountryCodes);
  const ibanStripRe = compileRuleSpec(ruleset.patterns.ibanStripSeparators);
  const ibanFallbackRe = compileRuleSpec(
    ruleset.patterns.ibanStructuralFallback,
  );
  const digitsGlobalRe = compileRuleSpec(ruleset.patterns.digitsMatchGlobal);
  addMatches(ruleset.patterns.ibanCandidate, "ACCT", {
    validate: (normRaw) => {
      const cleaned = normRaw.replace(ibanStripRe, "");
      if (
        cleaned.length < ruleset.thresholds.ibanMinLength ||
        cleaned.length > ruleset.thresholds.ibanMaxLength
      ) {
        return false;
      }
      const country = cleaned.slice(0, 2).toUpperCase();
      if (!ibanCountries.has(country)) return false;
      const digitCount = (cleaned.match(digitsGlobalRe) ?? []).length;
      if (digitCount < ruleset.thresholds.ibanMinDigits) return false;
      if (isValidIbanMod97(cleaned, ruleset)) return true;
      return ibanFallbackRe.test(cleaned);
    },
  });
  addMatches(ruleset.patterns.creditCardCandidate, "ACCT", {
    validate: (normRaw) => isValidLuhn(normRaw, ruleset),
  });

  // 6. IP addresses (IPv4 and IPv6)
  for (const pat of ruleset.patterns.ip) {
    addMatches(pat, "IP");
  }

  // 7. Street addresses, PO Boxes, UK postcodes, State + ZIP+4
  for (const pat of ruleset.patterns.address) {
    addMatches(pat, "ADDRESS", { trimTrailingPunct: true });
  }

  // 8. Dates (labeled, ISO, numeric slash/dot/hyphen, and month-name dates)
  for (const pat of ruleset.patterns.date) {
    addMatches(pat, "DATE", { trimTrailingPunct: true });
  }

  // 9. Phone numbers (international, domestic, and 7-digit local numbers)
  const phoneExtStripRe = compileRuleSpec(
    ruleset.patterns.phoneExtensionStrip,
  );
  const phonePrecedingRe = compileRuleSpec(
    ruleset.patterns.phonePrecedingBoundary,
  );
  const nonDigitsStripRe = compileRuleSpec(ruleset.patterns.nonDigitsStrip);
  for (const pat of ruleset.patterns.phone) {
    addMatches(pat, "PHONE", {
      trimTrailingPunct: true,
      validate: (normRaw, normStart, fullNorm) => {
        const mainPart = normRaw.replace(phoneExtStripRe, "");
        const digits = mainPart.replace(nonDigitsStripRe, "");
        if (
          digits.length < ruleset.thresholds.phoneMinDigits ||
          digits.length > ruleset.thresholds.phoneMaxDigits
        ) {
          return false;
        }
        if (normStart > 0) {
          const prev = fullNorm[normStart - 1];
          if (phonePrecedingRe.test(prev)) return false;
        }
        return true;
      },
    });
  }
  addMatches(ruleset.patterns.localSevenDigitPhone, "PHONE", {
    validate: (_normRaw, normStart, fullNorm) => {
      if (normStart > 0 && phonePrecedingRe.test(fullNorm[normStart - 1])) {
        return false;
      }
      return true;
    },
  });

  // 10. Names: labeled names, honorific names, and capitalized multi-word name sequences
  {
    const re = compileRuleSpec(ruleset.patterns.labeledName);
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

  addMatches(ruleset.patterns.honorificName, "NAME", {
    trimTrailingPunct: true,
  });

  const sentenceStarterSet = new Set(
    ruleset.wordLists.sentenceStarterNonNames,
  );
  const technicalAllowlistSet = new Set(
    ruleset.wordLists.technicalTitleCaseAllowlist,
  );
  const technicalSingleWordSet = new Set(
    ruleset.wordLists.technicalSingleWords,
  );
  const honorificRe = compileRuleSpec(ruleset.patterns.honorificToken);
  const whitespaceSplitRe = compileRuleSpec(ruleset.patterns.whitespaceSplit);
  const singleWsRe = compileRuleSpec(ruleset.patterns.singleWhitespaceChar);
  const nonLowerAlphaStripRe = compileRuleSpec(
    ruleset.patterns.nonLowerAlphaStrip,
  );
  const startsWithUpperRe = compileRuleSpec(
    ruleset.patterns.startsWithUpperAlpha,
  );
  const containsLowerRe = compileRuleSpec(ruleset.patterns.containsLowerAlpha);

  addMatches(ruleset.patterns.multiWordName, "NAME", {
    trimTrailingPunct: true,
    adjustRange: (normRaw, normStart, normEnd) => {
      const tokens = normRaw.split(whitespaceSplitRe);
      let dropCount = 0;
      while (
        dropCount < tokens.length &&
        sentenceStarterSet.has(
          tokens[dropCount].toLowerCase().replace(nonLowerAlphaStripRe, ""),
        )
      ) {
        dropCount += 1;
      }
      const remaining = tokens.slice(dropCount);
      if (remaining.length < ruleset.thresholds.minMultiWordNameTokens) {
        if (
          remaining.length === 1 &&
          dropCount > 0 &&
          honorificRe.test(tokens[dropCount - 1])
        ) {
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
          while (newStart < normEnd && singleWsRe.test(normalized[newStart])) {
            newStart += 1;
          }
        }
      }
      const candidateSlice = normalized.slice(newStart, normEnd).trim();
      const lowerCandidate = candidateSlice
        .replace(whitespaceSplitRe, " ")
        .toLowerCase();
      if (technicalAllowlistSet.has(lowerCandidate)) {
        return null;
      }
      const words = lowerCandidate.split(" ");
      if (words.every((w) => technicalSingleWordSet.has(w))) {
        return null;
      }
      const capWordsWithLower = candidateSlice
        .split(whitespaceSplitRe)
        .filter((w) => startsWithUpperRe.test(w) && containsLowerRe.test(w));
      if (capWordsWithLower.length < ruleset.thresholds.minCapWordsWithLower) {
        return null;
      }
      return { start: newStart, end: normEnd };
    },
  });

  // 11. Any token with 4+ consecutive digits, comma-grouped 4+ digit numbers, or split digit sequences
  for (const pat of ruleset.patterns.fourPlusDigits) {
    addMatches(pat, "DIGITS", {
      trimTrailingPunct: true,
      validate: (normRaw) => {
        const digitsOnly = normRaw.replace(nonDigitsStripRe, "");
        return digitsOnly.length >= ruleset.thresholds.minDigitsTokenCount;
      },
    });
  }

  // 12. High-entropy tokens (Shannon entropy threshold) and character-by-character split tokens
  addMatches(ruleset.patterns.highEntropyCandidate, "ENTROPY", {
    trimTrailingPunct: true,
    validate: (normRaw) => isHighEntropyToken(normRaw, ruleset),
  });

  addMatches(ruleset.patterns.charSplitToken, "ENTROPY", {
    trimTrailingPunct: true,
  });

  if (candidates.length === 0) {
    return {
      text,
      redactions: [],
      restore,
    };
  }

  candidates.sort((a, b) => a.start - b.start);

  const getOrCreatePlaceholder = (
    span: CandidateSpan,
  ): { placeholder: string; kind: MechanicalRedactionKind } => {
    if (span.existingPlaceholder) {
      const existingByPh = byPlaceholder.get(
        span.existingPlaceholder.toUpperCase(),
      );
      if (existingByPh) {
        return existingByPh;
      }
      return {
        placeholder: span.existingPlaceholder,
        kind: span.kind,
      };
    }
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

    const original =
      span.kind === "ENTITY"
        ? (customTerms.get(span.canonicalKey.slice(7)) ?? span.raw)
        : span.raw;
    const mapping = {
      placeholder,
      kind: span.kind,
      original,
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
    if (!span.emptyRemoval) {
      const mapping = getOrCreatePlaceholder(span);
      out += mapping.placeholder;
      redactions.push({
        kind: mapping.kind,
        placeholder: mapping.placeholder,
      });
    }
    cursor = span.end;
  }
  out += text.slice(cursor);

  return {
    text: out,
    redactions,
    restore,
  };
}
