export interface StylometricFeatures {
  ukSpellingCount: number;
  typographicPunctuationCount: number;
  doubleSpaceCount: number;
  greetingSignoffDetected: boolean;
  avgWordsPerSentence: number;
  lexicalTypeTokenRatio: number;
}

export interface StylometricFingerprintAnalysis {
  uniquenessRiskScore: number;
  features: StylometricFeatures;
}

export interface StylometricNormalizationResult {
  normalized: string;
  changesApplied: string[];
  riskBefore: number;
  riskAfter: number;
}

/**
 * Dictionary of British/Commonwealth spellings mapped to standard US English equivalents.
 */
const UK_TO_US_SPELLINGS: Record<string, string> = {
  // Core prompt examples & inflections
  colour: "color",
  colours: "colors",
  coloured: "colored",
  colouring: "coloring",
  colourful: "colorful",
  colourless: "colorless",
  discolour: "discolor",
  discoloured: "discolored",
  multicoloured: "multicolored",

  optimise: "optimize",
  optimises: "optimizes",
  optimised: "optimized",
  optimising: "optimizing",
  optimisation: "optimization",
  optimisations: "optimizations",
  optimiser: "optimizer",
  optimisers: "optimizers",

  analyse: "analyze",
  analyses: "analyzes",
  analysed: "analyzed",
  analysing: "analyzing",
  analyser: "analyzer",
  analysers: "analyzers",

  paralyse: "paralyze",
  paralyses: "paralyzes",
  paralysed: "paralyzed",
  paralysing: "paralyzing",

  catalyse: "catalyze",
  catalyses: "catalyzes",
  catalysed: "catalyzed",
  catalysing: "catalyzing",

  behaviour: "behavior",
  behaviours: "behaviors",
  behavioural: "behavioral",
  behaviourism: "behaviorism",
  misbehaviour: "misbehavior",

  centre: "center",
  centres: "centers",
  centred: "centered",
  centring: "centering",
  epicentre: "epicenter",

  defence: "defense",
  defences: "defenses",
  defenceless: "defenseless",

  offence: "offense",
  offences: "offenses",

  pretence: "pretense",
  pretences: "pretenses",

  licence: "license",
  licences: "licenses",

  catalogue: "catalog",
  catalogues: "catalogs",
  catalogued: "cataloged",
  cataloguing: "cataloging",

  dialogue: "dialog",
  dialogues: "dialogs",
  monologue: "monolog",
  monologues: "monologs",
  analogue: "analog",
  analogues: "analogs",
  prologue: "prolog",
  epilogue: "epilog",

  programme: "program",
  programmes: "programs",

  // Additional -our -> -or words
  favour: "favor",
  favours: "favors",
  favoured: "favored",
  favouring: "favoring",
  favourable: "favorable",
  favourably: "favorably",
  favourite: "favorite",
  favourites: "favorites",
  honour: "honor",
  honours: "honors",
  honoured: "honored",
  honouring: "honoring",
  honourable: "honorable",
  labour: "labor",
  labours: "labors",
  laboured: "labored",
  labouring: "laboring",
  labourer: "laborer",
  labourers: "laborers",
  neighbour: "neighbor",
  neighbours: "neighbors",
  neighbouring: "neighboring",
  neighbourhood: "neighborhood",
  neighbourhoods: "neighborhoods",
  flavour: "flavor",
  flavours: "flavors",
  flavoured: "flavored",
  flavouring: "flavoring",
  flavourless: "flavorless",
  humour: "humor",
  humours: "humors",
  humoured: "humored",
  humourless: "humorless",
  rumour: "rumor",
  rumours: "rumors",
  rumoured: "rumored",
  valour: "valor",
  vigour: "vigor",
  endeavour: "endeavor",
  endeavours: "endeavors",
  endeavoured: "endeavored",
  endeavouring: "endeavoring",
  harbour: "harbor",
  harbours: "harbors",
  harboured: "harbored",
  harbouring: "harboring",
  vapour: "vapor",
  vapours: "vapors",
  odour: "odor",
  odours: "odors",
  odourless: "odorless",
  savour: "savor",
  savours: "savors",
  savoured: "savored",
  savouring: "savoring",
  savoury: "savory",
  splendour: "splendor",
  armour: "armor",
  armoured: "armored",
  armoury: "armory",
  candour: "candor",
  clamour: "clamor",
  demeanour: "demeanor",
  fervour: "fervor",
  parlour: "parlor",
  rancour: "rancor",
  rigour: "rigor",
  rigours: "rigors",
  succour: "succor",
  tumour: "tumor",
  tumours: "tumors",

  // Additional -ise / -isation -> -ize / -ization words
  organise: "organize",
  organises: "organizes",
  organised: "organized",
  organising: "organizing",
  organisation: "organization",
  organisations: "organizations",
  organisational: "organizational",
  realise: "realize",
  realises: "realizes",
  realised: "realized",
  realising: "realizing",
  realisation: "realization",
  recognise: "recognize",
  recognises: "recognizes",
  recognised: "recognized",
  recognising: "recognizing",
  prioritise: "prioritize",
  prioritises: "prioritizes",
  prioritised: "prioritized",
  prioritising: "prioritizing",
  prioritisation: "prioritization",
  standardise: "standardize",
  standardises: "standardizes",
  standardised: "standardized",
  standardising: "standardizing",
  standardisation: "standardization",
  authorise: "authorize",
  authorises: "authorizes",
  authorised: "authorized",
  authorising: "authorizing",
  authorisation: "authorization",
  unauthorised: "unauthorized",
  utilise: "utilize",
  utilises: "utilizes",
  utilised: "utilized",
  utilising: "utilizing",
  utilisation: "utilization",
  customise: "customize",
  customises: "customizes",
  customised: "customized",
  customising: "customizing",
  customisation: "customization",
  summarise: "summarize",
  summarises: "summarizes",
  summarised: "summarized",
  summarising: "summarizing",
  apologise: "apologize",
  apologises: "apologizes",
  apologised: "apologized",
  apologising: "apologizing",
  emphasise: "emphasize",
  emphasises: "emphasizes",
  emphasised: "emphasized",
  emphasising: "emphasizing",
  minimise: "minimize",
  minimises: "minimizes",
  minimised: "minimized",
  minimising: "minimizing",
  maximise: "maximize",
  maximises: "maximizes",
  maximised: "maximized",
  maximising: "maximizing",
  normalise: "normalize",
  normalises: "normalizes",
  normalised: "normalized",
  normalising: "normalizing",
  normalisation: "normalization",
  synchronise: "synchronize",
  synchronises: "synchronizes",
  synchronised: "synchronized",
  synchronising: "synchronizing",
  synchronisation: "synchronization",
  initialise: "initialize",
  initialises: "initializes",
  initialised: "initialized",
  initialising: "initializing",
  initialisation: "initialization",
  centralise: "centralize",
  centralised: "centralized",
  decentralise: "decentralize",
  decentralised: "decentralized",
  tokenise: "tokenize",
  tokenised: "tokenized",
  tokenising: "tokenizing",
  tokenisation: "tokenization",
  anonymise: "anonymize",
  anonymised: "anonymized",
  anonymising: "anonymizing",
  anonymisation: "anonymization",
  memorise: "memorize",
  memorised: "memorized",
  criticise: "criticize",
  criticised: "criticized",
  specialise: "specialize",
  specialised: "specialized",
  specialising: "specializing",
  specialisation: "specialization",
  visualise: "visualize",
  visualised: "visualized",
  visualising: "visualizing",
  visualisation: "visualization",

  // Additional -re -> -er and Commonwealth variants
  theatre: "theater",
  theatres: "theaters",
  metre: "meter",
  metres: "meters",
  kilometre: "kilometer",
  kilometres: "kilometers",
  centimetre: "centimeter",
  centimetres: "centimeters",
  millimetre: "millimeter",
  millimetres: "millimeters",
  litre: "liter",
  litres: "liters",
  fibre: "fiber",
  fibres: "fibers",
  calibre: "caliber",
  sombre: "somber",
  spectre: "specter",
  lustre: "luster",
  meagre: "meager",
  manoeuvre: "maneuver",
  manoeuvres: "maneuvers",
  manoeuvred: "maneuvered",
  manoeuvring: "maneuvering",

  // Double-L and distinct regional vocabulary/orthography
  travelling: "traveling",
  travelled: "traveled",
  traveller: "traveler",
  travellers: "travelers",
  cancelled: "canceled",
  cancelling: "canceling",
  labelled: "labeled",
  labelling: "labeling",
  modelled: "modeled",
  modelling: "modeling",
  signalled: "signaled",
  signalling: "signaling",
  counsellor: "counselor",
  counsellors: "counselors",
  counselling: "counseling",
  fuelled: "fueled",
  fuelling: "fueling",
  artefact: "artifact",
  artefacts: "artifacts",
  grey: "gray",
  aluminium: "aluminum",
  cheque: "check",
  cheques: "checks",
  sceptical: "skeptical",
  sceptic: "skeptic",
  sceptics: "skeptics",
  scepticism: "skepticism",
  plough: "plow",
  tyre: "tire",
  tyres: "tires",
  kerb: "curb",
  kerbs: "curbs",
  mould: "mold",
  moulds: "molds",
  moulded: "molded",
  moulding: "molding",
  smoulder: "smolder",
  smouldering: "smoldering",
  moustache: "mustache",
  pyjamas: "pajamas",
  draught: "draft",
  draughts: "drafts",
  paediatric: "pediatric",
  orthopaedic: "orthopedic",
  anaemia: "anemia",
  anaesthesia: "anesthesia",
  leukaemia: "leukemia",
  diarrhoea: "diarrhea",
  oestrogen: "estrogen",
  foetus: "fetus",
  haemoglobin: "hemoglobin",
  whilst: "while",
  amongst: "among",
};

const UK_WORDS_REGEX = new RegExp(
  `\\b(${Object.keys(UK_TO_US_SPELLINGS).join("|")})\\b`,
  "gi"
);

/**
 * Idiosyncratic contractions mapped to neutral expanded forms.
 */
const IDIOSYNCRATIC_CONTRACTIONS: Record<string, string> = {
  "shan't": "shall not",
  "needn't": "need not",
  "mustn't": "must not",
  "oughtn't": "ought not",
  "mightn't": "might not",
  "daren't": "dare not",
  "ain't": "is not",
  "y'all": "you all",
  "'tis": "it is",
  "'twas": "it was",
};

const CONTRACTION_KEYS_ESCAPED = Object.keys(IDIOSYNCRATIC_CONTRACTIONS).map(
  (k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
);
const IDIOSYNCRATIC_CONTRACTIONS_REGEX = new RegExp(
  `(?:\\b|(?<='))(${CONTRACTION_KEYS_ESCAPED.join("|")})\\b`,
  "gi"
);

/**
 * Typographic punctuation characters (curly quotes, primes, guillemets, em/en dashes, ellipsis).
 */
const TYPOGRAPHIC_PUNCTUATION_REGEX =
  /[\u2018\u2019\u201A\u201B\u2032\u02BC\u201C\u201D\u201E\u201F\u00AB\u00BB\u2033\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2026]/g;

/**
 * Double or multiple consecutive horizontal spaces.
 */
const DOUBLE_SPACE_REGEX = /[ \t]{2,}/g;

/**
 * Personal greetings and sign-off patterns that leak author habits or device metadata.
 */
const SIGNOFF_PATTERNS: RegExp[] = [
  // Mobile / client footers anywhere in text
  /\bSent from my (?:iPhone|iPad|Galaxy|Pixel|Android|Mac|mobile device|BlackBerry)\b\.?/gi,
  /\bSent from (?:Outlook for (?:iOS|Android)|Proton Mail|Yahoo Mail)\b\.?/gi,
  /\bGet Outlook for (?:iOS|Android)\b\.?/gi,
  // Sign-off phrases (with optional trailing comma/exclamation and optional short name at end of text or line)
  /(?:^|\n|\s)\b(?:Best regards|Kind regards|Warm regards|Warmest regards|Regards|Best wishes|All the best|Yours sincerely|Yours faithfully|Yours truly|Many thanks|Thanks in advance)\s*[,!.]?(?:\s*\n\s*[A-Z][A-Za-z.' -]{1,28}(?=\s*(?:$|\n)))?/gi,
  /(?:^|\n|\s)\bCheers\s*[,!](?:\s*\n\s*[A-Z][A-Za-z.' -]{1,28}(?=\s*(?:$|\n)))?/gi,
  /(?:^|\n)\s*\b(?:Best|Sincerely|Cordially|Respectfully|Warmly|Cheers)\s*[,!](?:\s*\n\s*[A-Z][A-Za-z.' -]{1,28})?\s*(?=$|\n)/gi,
  // Opening greetings at the start of the message
  /^\s*(?:Dear\s+[A-Za-z0-9 ._-]{1,30}|Hi\s+there|Hello\s+there|Hey\s+there|Hi\s+team|Hello\s+team|Good\s+(?:morning|afternoon|evening)|Greetings)\s*[,!]\s*/i,
];

function applyCasePattern(sourceWord: string, replacementLower: string): string {
  if (sourceWord.toUpperCase() === sourceWord && sourceWord.length > 1) {
    return replacementLower.toUpperCase();
  }
  if (
    sourceWord[0] &&
    sourceWord[0] === sourceWord[0].toUpperCase() &&
    sourceWord.slice(1) === sourceWord.slice(1).toLowerCase()
  ) {
    return replacementLower.charAt(0).toUpperCase() + replacementLower.slice(1);
  }
  return replacementLower;
}

function detectGreetingOrSignoff(text: string): boolean {
  for (const pattern of SIGNOFF_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    if (re.test(text)) {
      return true;
    }
  }
  return false;
}

/**
 * Analyzes a text prompt for stylometric writing-fingerprint features and returns
 * a composite uniqueness risk score (0..100) alongside the extracted feature vector.
 */
export function analyzeStylometricFingerprint(
  text: string
): StylometricFingerprintAnalysis {
  if (!text || !text.trim()) {
    return {
      uniquenessRiskScore: 0,
      features: {
        ukSpellingCount: 0,
        typographicPunctuationCount: 0,
        doubleSpaceCount: 0,
        greetingSignoffDetected: false,
        avgWordsPerSentence: 0,
        lexicalTypeTokenRatio: 0,
      },
    };
  }

  // 1. UK / Commonwealth spelling count
  const ukMatches = text.match(new RegExp(UK_WORDS_REGEX.source, "gi"));
  const ukSpellingCount = ukMatches ? ukMatches.length : 0;

  // 2. Typographic punctuation count
  const typoMatches = text.match(
    new RegExp(TYPOGRAPHIC_PUNCTUATION_REGEX.source, "g")
  );
  const typographicPunctuationCount = typoMatches ? typoMatches.length : 0;

  // 3. Double-space count
  const doubleSpaceMatches = text.match(new RegExp(DOUBLE_SPACE_REGEX.source, "g"));
  const doubleSpaceCount = doubleSpaceMatches ? doubleSpaceMatches.length : 0;

  // 4. Greeting / sign-off habit detection
  const greetingSignoffDetected = detectGreetingOrSignoff(text);

  // 5. Idiosyncratic contractions (normalized curly apostrophes first for detection)
  const asciiApostropheText = text.replace(/[\u2018\u2019\u201B\u2032\u02BC]/g, "'");
  const contractionMatches = asciiApostropheText.match(
    new RegExp(IDIOSYNCRATIC_CONTRACTIONS_REGEX.source, "gi")
  );
  const contractionCount = contractionMatches ? contractionMatches.length : 0;

  // 6. Sentence & lexical statistics
  const words = asciiApostropheText.match(/[A-Za-z0-9]+(?:'[A-Za-z0-9]+)*/g) ?? [];
  const sentences = text
    .split(/[.!?]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const sentenceCount = words.length > 0 ? Math.max(1, sentences.length) : 0;

  const avgWordsPerSentence =
    sentenceCount > 0 ? Number((words.length / sentenceCount).toFixed(2)) : 0;

  const uniqueWordCount = new Set(words.map((w) => w.toLowerCase())).size;
  const lexicalTypeTokenRatio =
    words.length > 0 ? Number((uniqueWordCount / words.length).toFixed(4)) : 0;

  // Compute sentence-length burstiness (coefficient of variation across sentences)
  let burstinessBonus = 0;
  if (sentences.length >= 2) {
    const sentenceWordLengths = sentences.map(
      (s) => (s.match(/[A-Za-z0-9]+/g) ?? []).length
    );
    const mean =
      sentenceWordLengths.reduce((acc, n) => acc + n, 0) /
      sentenceWordLengths.length;
    if (mean > 0) {
      const variance =
        sentenceWordLengths.reduce((acc, n) => acc + Math.pow(n - mean, 2), 0) /
        sentenceWordLengths.length;
      const stdDev = Math.sqrt(variance);
      if (stdDev > 12) {
        burstinessBonus = Math.min(10, Math.round((stdDev - 12) * 0.8));
      }
    }
  }

  // Composite uniqueness risk score (0..100)
  const ukScore = Math.min(36, ukSpellingCount * 9);
  const typoScore = Math.min(24, typographicPunctuationCount * 6);
  const spaceScore = Math.min(18, doubleSpaceCount * 6);
  const signoffScore = greetingSignoffDetected ? 18 : 0;
  const contractionScore = Math.min(12, contractionCount * 6);

  const rawRisk =
    ukScore +
    typoScore +
    spaceScore +
    signoffScore +
    contractionScore +
    burstinessBonus;

  const uniquenessRiskScore = Math.min(100, Math.max(0, rawRisk));

  return {
    uniquenessRiskScore,
    features: {
      ukSpellingCount,
      typographicPunctuationCount,
      doubleSpaceCount,
      greetingSignoffDetected,
      avgWordsPerSentence,
      lexicalTypeTokenRatio,
    },
  };
}

/**
 * Normalizes a user prompt to remove stylometric writing-fingerprint tells:
 * - Converts UK/Commonwealth spellings to US English
 * - Replaces curly quotes, em/en-dashes, and ellipses with ASCII punctuation
 * - Collapses double/multiple spaces
 * - Strips personal greetings, sign-offs, and mobile signatures
 * - Expands idiosyncratic contractions
 */
export function normalizeStylometry(
  text: string
): StylometricNormalizationResult {
  const before = analyzeStylometricFingerprint(text);
  if (!text || !text.trim()) {
    return {
      normalized: text,
      changesApplied: [],
      riskBefore: before.uniquenessRiskScore,
      riskAfter: before.uniquenessRiskScore,
    };
  }

  let working = text;
  const changesApplied: string[] = [];

  // 1. Replace typographic spaces & punctuation with neutral ASCII equivalents
  const nonBreakingSpaceRe = /[\u00A0\u202F\u2009\u2002\u2003]/g;
  if (nonBreakingSpaceRe.test(working)) {
    working = working.replace(nonBreakingSpaceRe, " ");
  }

  const typoCheckRe = new RegExp(TYPOGRAPHIC_PUNCTUATION_REGEX.source, "g");
  const typoFound = working.match(typoCheckRe);
  if (typoFound && typoFound.length > 0) {
    working = working
      .replace(/[\u2018\u2019\u201A\u201B\u2032\u02BC]/g, "'")
      .replace(/[\u201C\u201D\u201E\u201F\u00AB\u00BB\u2033]/g, '"')
      .replace(/\s*[\u2013\u2014\u2015]\s*/g, " - ")
      .replace(/[\u2010\u2011\u2012\u2212]/g, "-")
      .replace(/\u2026/g, "...");
    changesApplied.push(
      `Replaced ${typoFound.length} typographic punctuation mark(s) (curly quotes/dashes) with neutral ASCII`
    );
  }

  // 2. Strip personal greetings, sign-offs, and device footers
  const strippedSignoffs: string[] = [];
  for (let pass = 0; pass < 3; pass++) {
    let changedInPass = false;
    for (const pattern of SIGNOFF_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      working = working.replace(re, (match) => {
        const cleaned = match.trim();
        if (cleaned) {
          strippedSignoffs.push(cleaned.replace(/\s+/g, " "));
          changedInPass = true;
        }
        return match.startsWith("\n") ? "\n" : " ";
      });
    }
    if (!changedInPass) break;
  }

  if (strippedSignoffs.length > 0) {
    changesApplied.push(
      `Stripped personal greeting/sign-off (${strippedSignoffs.join("; ")})`
    );
  }

  // 3. Normalize UK/Commonwealth spellings to US English
  const ukReplacedPairs: string[] = [];
  working = working.replace(UK_WORDS_REGEX, (match) => {
    const lower = match.toLowerCase();
    const usTarget = UK_TO_US_SPELLINGS[lower];
    if (!usTarget) return match;
    const replacement = applyCasePattern(match, usTarget);
    ukReplacedPairs.push(`${match} -> ${replacement}`);
    return replacement;
  });

  if (ukReplacedPairs.length > 0) {
    for (const pair of ukReplacedPairs) {
      changesApplied.push(`Normalized UK/Commonwealth spelling: ${pair}`);
    }
  }

  // 4. Normalize idiosyncratic contractions
  const contractionsReplaced: string[] = [];
  working = working.replace(IDIOSYNCRATIC_CONTRACTIONS_REGEX, (match) => {
    const lower = match.toLowerCase();
    const target = IDIOSYNCRATIC_CONTRACTIONS[lower];
    if (!target) return match;
    const replacement = applyCasePattern(match, target);
    contractionsReplaced.push(`${match} -> ${replacement}`);
    return replacement;
  });

  if (contractionsReplaced.length > 0) {
    changesApplied.push(
      `Expanded idiosyncratic contraction(s): ${contractionsReplaced.join(", ")}`
    );
  }

  // 5. Collapse double/multiple horizontal spaces and clean up whitespace
  const hadDoubleSpaces =
    before.features.doubleSpaceCount > 0 || DOUBLE_SPACE_REGEX.test(working);
  working = working
    .replace(/[ \t]{2,}/g, " ")
    .replace(/[ \t]+([,.;:!?])/g, "$1")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (hadDoubleSpaces) {
    changesApplied.push("Collapsed double/multiple spaces into single spaces");
  }

  const after = analyzeStylometricFingerprint(working);

  return {
    normalized: working,
    changesApplied,
    riskBefore: before.uniquenessRiskScore,
    riskAfter: after.uniquenessRiskScore,
  };
}
