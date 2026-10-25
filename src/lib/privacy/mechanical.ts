import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
  type RegexRuleSpec,
} from "./mechanical-ruleset";
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
}

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

  if (!text) {
    return {
      text: text ?? "",
      redactions: [],
      restore: (s: string) => s,
    };
  }

  if (opts?.scrubber && opts.customTerms) {
    for (const term of opts.customTerms) {
      opts.scrubber.addCustomTerm(term);
    }
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
      restore: (s: string) => s.replace(fallbackRestoreRe, text),
    };
  }

  const customTerms = new Map<string, string>();
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

  const reservedLiterals = new Set<string>();
  const byKey = new Map<
    string,
    { placeholder: string; kind: MechanicalRedactionKind; original: string }
  >();
  const byPlaceholder = new Map<
    string,
    { placeholder: string; kind: MechanicalRedactionKind; original: string }
  >();
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
  const existingPlaceholderRe = compileRuleSpec(
    ruleset.placeholderPatterns.existingPlaceholder,
  );
  let litMatch: RegExpExecArray | null;
  while ((litMatch = existingPlaceholderRe.exec(text)) !== null) {
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
    if (
      normStart < 0 ||
      normEnd <= normStart ||
      normEnd > mapToOriginal.length
    ) {
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
    spec: RegexRuleSpec,
    kind: MechanicalRedactionKind,
    options?: {
      trimTrailingPunct?: boolean;
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

      addSpanFromNormalizedRange(normStart, normEnd, kind);
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
      addMatches({ source, flags: "gi" }, "ENTITY");
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
      if (isValidIbanMod97(cleaned)) return true;
      return ibanFallbackRe.test(cleaned);
    },
  });
  addMatches(ruleset.patterns.creditCardCandidate, "ACCT", {
    validate: (normRaw) => isValidLuhn(normRaw),
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
      restore: (s: string) => s,
    };
  }

  candidates.sort((a, b) => a.start - b.start);

  const getOrCreatePlaceholder = (
    span: CandidateSpan,
  ): { placeholder: string; kind: MechanicalRedactionKind } => {
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

  const restorePlaceholderRe = compileRuleSpec(
    ruleset.placeholderPatterns.restorePlaceholder,
  );
  const restore = (s: string): string => {
    if (!s || byPlaceholder.size === 0) return s;
    return s.replace(restorePlaceholderRe, (token) => {
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
