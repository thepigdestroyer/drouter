/**
 * Serialisable mechanical redaction filter rule set (E2).
 *
 * All pattern sources, flags, thresholds, character code bounds, word lists,
 * and homoglyph tables live here so `rulesetFingerprint()` can hash the entire
 * canonical JSON representation and browsers can verify that the running filter
 * matches the published version anchored on Arc.
 */

export interface RegexRuleSpec {
  source: string;
  flags: string;
}

export interface ExplicitMarkerRuleSpec {
  openMarker: string;
  closeMarker: string;
  kind: "MARKED";
}

export interface MechanicalRuleset {
  version: string;
  markerRule: ExplicitMarkerRuleSpec;
  placeholderPatterns: {
    existingPlaceholder: RegexRuleSpec;
    restorePlaceholder: RegexRuleSpec;
    bracketedToken: RegexRuleSpec;
    defaultFallbackPlaceholder: string;
    defaultFallbackRestorePattern: RegexRuleSpec;
    trailingPunctuationCharClass: RegexRuleSpec;
  };
  unicodeNormalization: {
    zeroWidthCodeUnits: readonly number[];
    variationSelectorRange: readonly [number, number];
    combiningDiacriticRange: readonly [number, number];
    combiningDiacriticStripPattern: RegexRuleSpec;
    mathSurrogateHigh: number;
    mathSurrogateLowRange: readonly [number, number];
    utf16HighSurrogateBase: number;
    utf16LowSurrogateBase: number;
    utf16SupplementaryPlaneOffset: number;
    mathDigitCodePointRange: readonly [number, number];
    mathDigitModulus: number;
    mathAlphaCodePointRange: readonly [number, number];
    mathAlphaSetSize: number;
    mathAlphaUpperCount: number;
    asciiDigitZeroCode: number;
    asciiDigitNineCode: number;
    asciiUpperACode: number;
    asciiUpperZCode: number;
    asciiLowerACode: number;
    fullwidthAsciiRange: readonly [number, number];
    fullwidthAsciiDelta: number;
    circledDigitRange: readonly [number, number];
    circledDigitBaseCode: number;
    precomposedLatinRange: readonly [number, number];
    homoglyphMap: Readonly<Record<string, string>>;
  };
  entropyRules: {
    trimNonAlnumPattern: RegexRuleSpec;
    hyphenatedTechIdPattern: RegexRuleSpec;
    fourDigitsPattern: RegexRuleSpec;
    lowerClassPattern: RegexRuleSpec;
    upperClassPattern: RegexRuleSpec;
    digitClassPattern: RegexRuleSpec;
    symbolClassPattern: RegexRuleSpec;
    hexCandidatePattern: RegexRuleSpec;
    alphaOnlyPattern: RegexRuleSpec;
    fiveConsonantsPattern: RegexRuleSpec;
    vowelPattern: RegexRuleSpec;
    minLength: number;
    hexMinEntropy: number;
    threeClassMinLength: number;
    threeClassMinClasses: number;
    threeClassMinEntropy: number;
    twoClassMinLength: number;
    twoClassMinClasses: number;
    twoClassMinEntropy: number;
    mixedCaseMinLength: number;
    mixedCaseMinUpperCount: number;
    mixedCaseMinEntropy: number;
    singleAlphaMinLength: number;
    singleAlphaConsonantMinEntropy: number;
    singleAlphaMaxVowelRatio: number;
    singleAlphaLowVowelMinEntropy: number;
    singleAlphaExtremeEntropy: number;
  };
  patterns: {
    secret: readonly RegexRuleSpec[];
    base64Candidate: RegexRuleSpec;
    decodedSecretCheck: RegexRuleSpec;
    email: readonly RegexRuleSpec[];
    url: readonly RegexRuleSpec[];
    acct: readonly RegexRuleSpec[];
    ibanCandidate: RegexRuleSpec;
    ibanStripSeparators: RegexRuleSpec;
    ibanStructuralFallback: RegexRuleSpec;
    creditCardCandidate: RegexRuleSpec;
    allZerosPattern: RegexRuleSpec;
    ip: readonly RegexRuleSpec[];
    address: readonly RegexRuleSpec[];
    date: readonly RegexRuleSpec[];
    phone: readonly RegexRuleSpec[];
    phoneExtensionStrip: RegexRuleSpec;
    phonePrecedingBoundary: RegexRuleSpec;
    localSevenDigitPhone: RegexRuleSpec;
    labeledName: RegexRuleSpec;
    honorificToken: RegexRuleSpec;
    honorificName: RegexRuleSpec;
    multiWordName: RegexRuleSpec;
    fourPlusDigits: readonly RegexRuleSpec[];
    highEntropyCandidate: RegexRuleSpec;
    charSplitToken: RegexRuleSpec;
    regexSpecialCharsEscape: RegexRuleSpec;
    startsWithWordChar: RegexRuleSpec;
    endsWithWordChar: RegexRuleSpec;
    nonDigitsStrip: RegexRuleSpec;
    digitsMatchGlobal: RegexRuleSpec;
    whitespaceSplit: RegexRuleSpec;
    singleWhitespaceChar: RegexRuleSpec;
    nonLowerAlphaStrip: RegexRuleSpec;
    startsWithUpperAlpha: RegexRuleSpec;
    containsLowerAlpha: RegexRuleSpec;
  };
  thresholds: {
    base64MinRawLength: number;
    base64InvalidRemainder: number;
    base64MinDecodedLength: number;
    ibanMinLength: number;
    ibanMaxLength: number;
    ibanMinDigits: number;
    ibanHeaderSliceLength: number;
    ibanLetterOffset: number;
    ibanModulus: number;
    ibanExpectedRemainder: number;
    luhnMinDigits: number;
    luhnMaxDigits: number;
    luhnDoubleSubtract: number;
    luhnModulus: number;
    phoneMinDigits: number;
    phoneMaxDigits: number;
    minMultiWordNameTokens: number;
    minCapWordsWithLower: number;
    minDigitsTokenCount: number;
  };
  wordLists: {
    ibanCountryCodes: readonly string[];
    sentenceStarterNonNames: readonly string[];
    technicalTitleCaseAllowlist: readonly string[];
    technicalSingleWords: readonly string[];
  };
}

const NAME_WORD_SRC =
  "(?:(?:Mc|Mac|O'|D')[A-Z][a-z]{1,25}|[A-Z][a-z]{1,25}(?:[-'][A-Z]?[a-z]{1,25})*)";

export const MECHANICAL_RULESET: MechanicalRuleset = {
  version: "1.0.3",
  markerRule: {
    openMarker: "££",
    closeMarker: "££",
    kind: "MARKED",
  },
  placeholderPatterns: {
    existingPlaceholder: {
      source:
        "\\[(?:MARKED|SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY|[A-Z0-9_]+)_\\d+\\]|<PRIVATE_[A-Z0-9_]+>",
      flags: "g",
    },
    restorePlaceholder: {
      source:
        "\\[(?:MARKED|SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\\d+\\]",
      flags: "gi",
    },
    bracketedToken: {
      source: "^\\[[A-Z0-9_]+\\]$",
      flags: "",
    },
    defaultFallbackPlaceholder: "[ENTROPY_1]",
    defaultFallbackRestorePattern: {
      source: "\\[ENTROPY_1\\]",
      flags: "gi",
    },
    trailingPunctuationCharClass: {
      source: "[.,;:!?)\\]]",
      flags: "",
    },
  },
  unicodeNormalization: {
    zeroWidthCodeUnits: [
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
    ],
    variationSelectorRange: [0xfe00, 0xfe0f],
    combiningDiacriticRange: [0x0300, 0x036f],
    combiningDiacriticStripPattern: {
      source: "[\\u0300-\\u036f]",
      flags: "g",
    },
    mathSurrogateHigh: 0xd835,
    mathSurrogateLowRange: [0xdc00, 0xdfff],
    utf16HighSurrogateBase: 0xd800,
    utf16LowSurrogateBase: 0xdc00,
    utf16SupplementaryPlaneOffset: 0x10000,
    mathDigitCodePointRange: [0x1d7ce, 0x1d7ff],
    mathDigitModulus: 10,
    mathAlphaCodePointRange: [0x1d400, 0x1d6a3],
    mathAlphaSetSize: 52,
    mathAlphaUpperCount: 26,
    asciiDigitZeroCode: 48,
    asciiDigitNineCode: 57,
    asciiUpperACode: 65,
    asciiUpperZCode: 90,
    asciiLowerACode: 97,
    fullwidthAsciiRange: [0xff01, 0xff5e],
    fullwidthAsciiDelta: 0xfee0,
    circledDigitRange: [0x2460, 0x2468],
    circledDigitBaseCode: 49,
    precomposedLatinRange: [0x00c0, 0x024f],
    homoglyphMap: {
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
      // Circled digit zero (1..9 are handled by circledDigitRange)
      "\u24ea": "0",
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
    },
  },
  entropyRules: {
    trimNonAlnumPattern: {
      source: "^[^A-Za-z0-9]+|[^A-Za-z0-9]+$",
      flags: "g",
    },
    hyphenatedTechIdPattern: {
      source: "^[a-z]+(?:-[a-z0-9]{1,8})+$",
      flags: "",
    },
    fourDigitsPattern: {
      source: "\\d{4,}",
      flags: "",
    },
    lowerClassPattern: {
      source: "[a-z]",
      flags: "",
    },
    upperClassPattern: {
      source: "[A-Z]",
      flags: "g",
    },
    digitClassPattern: {
      source: "\\d",
      flags: "",
    },
    symbolClassPattern: {
      source: "[_+=/~@#$%^&*-]",
      flags: "",
    },
    hexCandidatePattern: {
      source: "^[0-9a-fA-F]{16,}$",
      flags: "",
    },
    alphaOnlyPattern: {
      source: "^[A-Za-z]+$",
      flags: "",
    },
    fiveConsonantsPattern: {
      source: "[bcdfghjklmnpqrstvwxz]{5,}",
      flags: "",
    },
    vowelPattern: {
      source: "[aeiouy]",
      flags: "g",
    },
    minLength: 12,
    hexMinEntropy: 2.8,
    threeClassMinLength: 12,
    threeClassMinClasses: 3,
    threeClassMinEntropy: 3.25,
    twoClassMinLength: 15,
    twoClassMinClasses: 2,
    twoClassMinEntropy: 3.5,
    mixedCaseMinLength: 16,
    mixedCaseMinUpperCount: 3,
    mixedCaseMinEntropy: 3.65,
    singleAlphaMinLength: 16,
    singleAlphaConsonantMinEntropy: 3.5,
    singleAlphaMaxVowelRatio: 0.2,
    singleAlphaLowVowelMinEntropy: 3.5,
    singleAlphaExtremeEntropy: 3.95,
  },
  patterns: {
    secret: [
      {
        source:
          "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\\r\\n]*",
        flags: "g",
      },
      {
        source:
          "\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:postgres(?:ql)?|mongodb(?:\\+srv)?|redis|rediss|mysql|amqp|amqps):\\/\\/[^\\s\"'<>)\\]]+",
        flags: "gi",
      },
      {
        source:
          "\\b(?:aws_secret_access_key|aws_secret_key|secret_access_key|aws_session_token|api[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|password|passwd|passphrase)\\s*[:=]\\s*[\"']?[A-Za-z0-9/_+~@#$%^&*.-]{6,128}[\"']?",
        flags: "gi",
      },
      {
        source:
          "https:\\/\\/hooks\\.slack\\.com\\/services\\/T[A-Za-z0-9_]+\\/B[A-Za-z0-9_]+\\/[A-Za-z0-9_]+",
        flags: "g",
      },
      {
        source: "\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:s\\s+k\\s*-\\s*(?:p\\s+r\\s+o\\s+j\\s*-\\s*|a\\s+n\\s+t\\s*-\\s*|l\\s+i\\s+v\\s+e\\s*-\\s*|t\\s+e\\s+s\\s+t\\s*-\\s*)?|g\\s+h\\s+[pousr]\\s*_\\s*|t\\s+[kf]\\s*_\\s*(?:l\\s+i\\s+v\\s+e\\s*_\\s*)?|A\\s+K\\s+I\\s+A\\s+|A\\s+S\\s+I\\s+A\\s+|A\\s+I\\s+z\\s+a\\s+)(?:[A-Za-z0-9_-]\\s+){4,}[A-Za-z0-9_-]\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\\d{2}-|sid\\d{2}-)?|live-|test-)?|(?:sk|rk|pk)_(?:live|test)_|whsec_|tk_(?:live_|test_)?|tf_(?:live_|test_)?|tinfoil_(?:live_|test_)?|gh[pousr]_|github_pat_|xox[baprs]-|xapp-\\d-|AIza|GOCSPX-|ya29\\.|hf_|npm_)[A-Za-z0-9_.-]{2,}(?:(?:\\r?\\n[ \\t]*|[ \\t]{2,})[A-Za-z0-9_.-]{3,}|[ \\t]+(?=[A-Za-z0-9_.-]*\\d)[A-Za-z0-9_.-]{3,})+\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-(?:api\\d{2}-|sid\\d{2}-)?|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|(?:sk|rk|pk)-(?:live|test)-[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xoxe\\.xox[bp]-[A-Za-z0-9-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\\.[0-9A-Za-z._-]{12,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,})\\b",
        flags: "g",
      },
    ],
    base64Candidate: {
      source: "\\b[A-Za-z0-9+/]{16,}={0,2}\\b",
      flags: "g",
    },
    decodedSecretCheck: {
      source:
        "(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\\b(?:sk-(?:proj-|svcacct-|admin-|None-|ant-|live-|test-)?[A-Za-z0-9_-]{8,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9_]{8,}|(?:tk|tf|tinfoil)_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,}|xapp-\\d-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]{12,}|ya29\\.[0-9A-Za-z._-]{12,}|Bearer\\s+[A-Za-z0-9._~+/=-]{8,}|eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}|password\\s*[:=]|secret\\s*[:=]))",
      flags: "i",
    },
    email: [
      {
        source: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
        flags: "g",
      },
      {
        source:
          "\\b[A-Za-z0-9._%+-]+(?:\\s*@\\s*|\\s*(?:\\[\\s*at\\s*\\]|\\(\\s*at\\s*\\))\\s*)[A-Za-z0-9-]+(?:\\s*(?:\\.|\\[\\s*dot\\s*\\]|\\(\\s*dot\\s*\\))\\s*[A-Za-z0-9-]+)*\\s*(?:\\.|\\[\\s*dot\\s*\\]|\\(\\s*dot\\s*\\))\\s*(?:com|org|net|edu|gov|mil|io|sh|ai|dev|app|co|uk|us|eu|de|fr|jp|cn|ch|nl|se|no|fi|dk|ca|au|nz|info|biz|me|xyz|tech|cloud)\\b",
        flags: "gi",
      },
    ],
    url: [
      {
        source: "\\b(?:https?|wss?|s?ftp|file):\\/\\/[^\\s\"'<>)\\]]+",
        flags: "gi",
      },
      {
        source:
          "(?:(?<![A-Za-z0-9_.-])\\/(?:Users|home)\\/[A-Za-z0-9._-]+(?:\\/[^\\s\"'<>)\\],;:]*)?|\\b[A-Za-z]:[\\\\/](?:[Uu]sers|USERS)[\\\\/][A-Za-z0-9._-]+(?:[\\\\/][^\\s\"'<>)\\],;:]*)?)",
        flags: "g",
      },
      {
        source:
          "\\bwww\\.[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+(?::\\d{2,5})?(?:\\/[^\\s\"'<>)\\]]*)?",
        flags: "gi",
      },
      {
        source:
          "\\b(?:ip-\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}|ec2-\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}|gke-[a-zA-Z0-9-]+|aks-[a-zA-Z0-9-]+|eks-[a-zA-Z0-9-]+)(?:\\.[a-zA-Z0-9-]+)+(?::\\d{2,5})?(?:\\/[^\\s\"'<>)\\]]*)?",
        flags: "gi",
      },
      {
        source:
          "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(?:com|org|net|edu|gov|mil|int|io|sh|ai|dev|app|co|uk|us|eu|de|fr|jp|cn|ch|nl|se|no|fi|dk|ca|au|nz|in|br|it|es|pl|ru|kr|sg|hk|tw|il|ae|za|mx|ar|cl|info|biz|me|xyz|tech|cloud|online|site|store|local|internal|corp|lan|intranet|localdomain|priv|arpa|onion|eth|crypto|test|example|invalid)\\b(?:\\.[a-zA-Z]{2,3})?(?::\\d{2,5})?(?:\\/[^\\s\"'<>)\\]]*)?",
        flags: "gi",
      },
    ],
    acct: [
      {
        source: "\\b0x[a-fA-F0-9]{40}\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?!000|666|9\\d\\d)\\d{3}[-.](?!00)\\d{2}[-.](?!0000)\\d{4}\\b",
        flags: "g",
      },
      {
        source:
          "\\bSSN\\s*[:#=-]?\\s*\\d{3}[\\s.-]*\\d{2}[\\s.-]*\\d{4}\\b",
        flags: "gi",
      },
      {
        source: "\\b[A-CEGHJ-TW-Z]{2}\\s?\\d{2}\\s?\\d{2}\\s?\\d{2}\\s?[A-D]\\b",
        flags: "gi",
      },
      {
        source:
          "\\bNHS(?:\\s*(?:No\\.?|Number|#|:))?\\s*\\d{3}[\\s-]?\\d{3}[\\s-]?\\d{4}\\b",
        flags: "gi",
      },
      {
        source:
          "\\bpassport(?:\\s*(?:no\\.?|number|num|id|#))?\\s*[:#-]?\\s*[A-Z0-9]{6,12}\\b",
        flags: "gi",
      },
      {
        source: "\\bP<[A-Z]{3}[A-Z0-9<]{10,40}\\b",
        flags: "g",
      },
      {
        source: "\\b(?:[A-Z]\\d{8}|[A-Z]{2}\\d{7}|\\d{2}[A-Z]{2}\\d{5})\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:account|acct|routing)(?:\\s*(?:no\\.?|number|num|#))?\\s*[:#]?\\s*\\d{6,17}\\b",
        flags: "gi",
      },
    ],
    ibanCandidate: {
      source:
        "\\b[A-Za-z]{2}\\d{2}(?:[ -]?[A-Za-z0-9]{4}){2,7}(?:[ -]?[A-Za-z0-9]{1,4})?\\b",
      flags: "g",
    },
    ibanStripSeparators: {
      source: "[\\s-]",
      flags: "g",
    },
    ibanStructuralFallback: {
      source: "^[A-Z]{2}\\d{2}[A-Z0-9]{11,30}$",
      flags: "",
    },
    creditCardCandidate: {
      source:
        "\\b(?:\\d{4}[ -]){3}\\d{1,7}\\b|\\b\\d{4}[ -]\\d{6}[ -]\\d{4,5}\\b|\\b\\d{13,19}\\b",
      flags: "g",
    },
    allZerosPattern: {
      source: "^0+$",
      flags: "",
    },
    ip: [
      {
        source:
          "(?<![0-9a-fA-F]:|[0-9a-fA-F])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})(?:%[0-9a-zA-Z]{1,16})?(?!:[0-9a-fA-F:]|[0-9a-fA-F])",
        flags: "gi",
      },
      {
        source:
          "(?<!\\d\\.|\\d)(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?::\\d{1,5})?(?!\\.\\d|\\d)\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\\b|\\b(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\\b|\\b[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\b",
        flags: "g",
      },
    ],
    address: [
      {
        source:
          "\\b\\d{1,6}[A-Za-z]?(?:-\\d{1,4})?\\s+(?:(?!at\\b|on\\b|in\\b|to\\b|for\\b|from\\b|with\\b|by\\b|and\\b|or\\b)(?:\\d{1,4}(?:st|nd|rd|th)|[A-Za-z][A-Za-z.'-]{0,22})\\s+){1,4}(?:Street|St\\.?|Avenue|Ave\\.?|Road|Rd\\.?|Boulevard|Blvd\\.?|Lane|Ln\\.?|Drive|Dr\\.?|Court|Ct\\.?|Way|Place|Pl\\.?|Terrace|Ter\\.?|Square|Sq\\.?|Circle|Cir\\.?|Parkway|Pkwy\\.?|Highway|Hwy\\.?|Crescent|Cres\\.?|Close|Grove|Gardens|Mews|Alley|Trail|Trl\\.?|Pike|Plaza|Walk|Row|Path)\\b(?:[.,]?\\s*(?:NW|NE|SW|SE|N|S|E|W|North|South|East|West)\\b)?(?:[.,]?\\s*(?:Apt|Apartment|Suite|Ste|Unit|Flat|Floor|Fl|Bldg|Building|Room|Rm)\\.?\\s*#?[A-Za-z0-9-]+|\\s+#\\d+[A-Za-z]?)?(?:,\\s*[A-Z][a-zA-Z .'-]{1,28}(?:,\\s*(?:[A-Z]{2}\\s+\\d{5}(?:-\\d{4})?|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\\s*[0-9][ABD-HJLNP-UW-Z]{2}))?)?",
        flags: "gi",
      },
      {
        source: "\\bP\\.?\\s*O\\.?\\s*Box\\s+#?\\d{1,8}\\b",
        flags: "gi",
      },
      {
        source:
          "\\b(?:GIR\\s?0AA|(?:[A-PR-UWYZ][0-9]{1,2}|[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])\\s+[0-9][ABD-HJLNP-UW-Z]{2}|(?:[A-PR-UWYZ][A-HK-Y][0-9]{1,2}|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRV-Y])[0-9][ABD-HJLNP-UW-Z]{2})\\b",
        flags: "gi",
      },
      {
        source: "\\b[A-Z]{2}\\s+\\d{5}-\\d{4}\\b",
        flags: "g",
      },
    ],
    date: [
      {
        source:
          "\\b(?:DOB|D\\.O\\.B\\.|Date\\s+of\\s+Birth|Born(?:\\s+on)?|Birthdate|Birthday)\\s*(?:[:=-]|is|was)?\\s*(?:\\d{4}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\d|3[01])|(?:0?[1-9]|[12]\\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:\\d{4}|\\d{2})|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\d|3[01])[-/.](?:\\d{4}|\\d{2})|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{4}|\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\.?,?\\s+\\d{4})\\b",
        flags: "gi",
      },
      {
        source:
          "\\b(?:19|20)\\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\d|3[01])(?:[T\\s]\\d{2}:\\d{2}(?::\\d{2}(?:\\.\\d{1,9})?)?(?:Z|[+-]\\d{2}:?\\d{2})?)?\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:0?[1-9]|[12]\\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/](?:(?:19|20)\\d{2}|\\d{2})\\b|\\b(?:0?[1-9]|[12]\\d|3[01])\\.(?:0?[1-9]|1[0-2])\\.(?:19|20)\\d{2}\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\\d|3[01])[-/](?:(?:19|20)\\d{2}|\\d{2})\\b|\\b(?:0?[1-9]|1[0-2])\\.(?:0?[1-9]|[12]\\d|3[01])\\.(?:19|20)\\d{2}\\b",
        flags: "g",
      },
      {
        source:
          "\\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?(?:,?\\s+(?:19|20)\\d{2})?\\b",
        flags: "gi",
      },
      {
        source:
          "\\b\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\.?(?:,?\\s+(?:19|20)\\d{2})\\b",
        flags: "gi",
      },
    ],
    phone: [
      {
        source:
          "(?:(?:\\+|00)\\d{1,3}[\\s./-]?)?(?:\\(0\\)[\\s./-]?)?(?:\\(\\d{1,5}\\)[\\s./-]?|\\b\\d{2,5}[\\s./-])\\d{2,5}[\\s./-]\\d{2,6}(?:[\\s./-]\\d{2,6}){0,2}(?:\\s*(?:ext\\.?|extension|x)\\s*\\d{1,6})?\\b",
        flags: "gi",
      },
      {
        source: "(?:(?:\\+|00)\\d{1,3}[\\s.-]?)?\\b\\d{1,2}(?:[\\s.-]\\d{2}){4}\\b",
        flags: "g",
      },
      {
        source: "\\b0\\d{2,4}\\s*[/\\s.-]\\s*\\d{5,8}\\b",
        flags: "g",
      },
      {
        source:
          "(?:\\+|\\b00)\\d{1,3}(?:[\\s.-]?\\(0\\))?(?:[\\s.-]?\\d{2,6}){2,5}(?:\\s*(?:ext\\.?|extension|x)\\s*\\d{1,6})?\\b",
        flags: "gi",
      },
      {
        source: "\\+\\d{10,15}\\b|\\b\\d{10,11}\\b",
        flags: "g",
      },
    ],
    phoneExtensionStrip: {
      source: "(?:ext\\.?|extension|x)\\s*\\d{1,6}$",
      flags: "i",
    },
    phonePrecedingBoundary: {
      source: "[A-Za-z0-9_./-]",
      flags: "",
    },
    localSevenDigitPhone: {
      source: "\\b[2-9]\\d{2}-\\d{4}\\b",
      flags: "g",
    },
    labeledName: {
      source: `\\b(?:[Nn]ame|[Pp]atient|[Cc]lient|[Cc]ustomer|[Aa]pplicant|[Bb]eneficiary|[Rr]ecipient|[Ee]mployee)\\s*[:=-]\\s*([A-Z][A-Za-z'-]{1,25}(?:\\s+[A-Z][A-Za-z'-]{1,25}){0,2})\\b`,
      flags: "g",
    },
    honorificToken: {
      source:
        "^(?:Dr|Mr|Mrs|Ms|Mx|Prof|Professor|Sir|Lady|Dame|Rev|Capt|Col|Gen|Sgt|Sen|Rep|Gov)\\.?$",
      flags: "",
    },
    honorificName: {
      source: `\\b(?:Dr|Mr|Mrs|Ms|Mx|Prof|Professor|Sir|Lady|Dame|Rev|Capt|Col|Gen|Sgt|Sen|Rep|Gov)\\.?\\s+${NAME_WORD_SRC}(?:\\s+(?:(?:(?:de|del|da|di|du|von|van|der|den|bin|ibn|al|el|la|le)\\s+){1,2})?${NAME_WORD_SRC}){0,3}(?:\\s*,?\\s*(?:Jr\\.?|Sr\\.?|II|III|IV|Ph\\.?D\\.?|M\\.?D\\.?|Esq\\.?))?\\b`,
      flags: "g",
    },
    multiWordName: {
      source: `\\b${NAME_WORD_SRC}(?:\\s+(?:(?:(?:de|del|da|di|du|von|van|der|den|bin|ibn|al|el|la|le)\\s+){1,2})?${NAME_WORD_SRC}){1,3}(?:\\s*,?\\s*(?:Jr\\.?|Sr\\.?|II|III|IV|Ph\\.?D\\.?|M\\.?D\\.?|Esq\\.?))?\\b`,
      flags: "g",
    },
    fourPlusDigits: [
      {
        source: "[£$€¥]?[A-Za-z0-9_./:#=-]*\\d{4,}[A-Za-z0-9_./:#=-]*",
        flags: "g",
      },
      {
        source: "[£$€¥]?\\b\\d{1,3}(?:,\\d{3})+(?:\\.\\d+)?\\b",
        flags: "g",
      },
      {
        source: "\\b\\d{1,3}(?:[ \\t.-]+\\d{1,3}){3,}\\b",
        flags: "g",
      },
    ],
    highEntropyCandidate: {
      source: "\\b[A-Za-z0-9_+=/~@#$%^&*-]{12,}\\b",
      flags: "g",
    },
    charSplitToken: {
      source: "\\b[A-Za-z0-9@._+-](?:[ \\t]+[A-Za-z0-9@._+-]){3,}\\b",
      flags: "g",
    },
    regexSpecialCharsEscape: {
      source: "[.*+?^${}()|[\\]\\\\]",
      flags: "g",
    },
    startsWithWordChar: {
      source: "^\\w",
      flags: "",
    },
    endsWithWordChar: {
      source: "\\w$",
      flags: "",
    },
    nonDigitsStrip: {
      source: "\\D",
      flags: "g",
    },
    digitsMatchGlobal: {
      source: "\\d",
      flags: "g",
    },
    whitespaceSplit: {
      source: "\\s+",
      flags: "g",
    },
    singleWhitespaceChar: {
      source: "\\s",
      flags: "",
    },
    nonLowerAlphaStrip: {
      source: "[^a-z]",
      flags: "g",
    },
    startsWithUpperAlpha: {
      source: "^[A-Z]",
      flags: "",
    },
    containsLowerAlpha: {
      source: "[a-z]",
      flags: "",
    },
  },
  thresholds: {
    base64MinRawLength: 16,
    base64InvalidRemainder: 1,
    base64MinDecodedLength: 10,
    ibanMinLength: 15,
    ibanMaxLength: 34,
    ibanMinDigits: 6,
    ibanHeaderSliceLength: 4,
    ibanLetterOffset: 55,
    ibanModulus: 97,
    ibanExpectedRemainder: 1,
    luhnMinDigits: 13,
    luhnMaxDigits: 19,
    luhnDoubleSubtract: 9,
    luhnModulus: 10,
    phoneMinDigits: 10,
    phoneMaxDigits: 15,
    minMultiWordNameTokens: 2,
    minCapWordsWithLower: 2,
    minDigitsTokenCount: 4,
  },
  wordLists: {
    ibanCountryCodes: [
      "AD", "AE", "AL", "AT", "AZ", "BA", "BE", "BG", "BH", "BI", "BR", "BY",
      "CH", "CR", "CY", "CZ", "DE", "DK", "DO", "EE", "EG", "ES", "FI", "FO",
      "FR", "GB", "GE", "GI", "GL", "GR", "GT", "HR", "HU", "IE", "IL", "IQ",
      "IS", "IT", "JO", "KW", "KZ", "LB", "LC", "LI", "LT", "LU", "LV", "LY",
      "MC", "MD", "ME", "MK", "MR", "MT", "MU", "NL", "NO", "PK", "PL", "PS",
      "PT", "QA", "RO", "RS", "RU", "SA", "SC", "SD", "SE", "SI", "SK", "SM",
      "SO", "ST", "SV", "TL", "TN", "TR", "UA", "VA", "VG", "XK",
    ],
    sentenceStarterNonNames: [
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
      "confirming", "confirm", "inspect", "list", "allow", "ensure", "note", "add",
    ],
    technicalTitleCaseAllowlist: [
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
      "program files",
      "windows defender",
      "system volume",
      "system volume information",
    ],
    technicalSingleWords: [
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
    ],
  },
};
