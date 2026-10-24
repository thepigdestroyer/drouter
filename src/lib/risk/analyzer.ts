export type PrivacyRiskLevel = "low" | "moderate" | "high" | "critical";

export type PrivacyRiskCategory =
  | "credentials"
  | "pii"
  | "financial"
  | "medical"
  | "infrastructure"
  | "temporal"
  | "first-person-context";

export interface PrivacyRiskFinding {
  category: PrivacyRiskCategory;
  severity: number;
  matchedPreview: string;
  recommendation: string;
}

export interface PrivacyRiskAssessment {
  score: number;
  level: PrivacyRiskLevel;
  findings: PrivacyRiskFinding[];
}

export interface PapillonGeneralizationResult {
  generalizedPrompt: string;
  localContextVault: Record<string, string>;
  riskBefore: number;
  riskAfter: number;
}

interface DetectionRule {
  category: PrivacyRiskCategory;
  severity: number;
  pattern: RegExp;
  recommendation: string;
  maskPreview?: boolean;
}

const DETECTION_RULES: DetectionRule[] = [
  // 1. Credentials & secret keys
  {
    category: "credentials",
    severity: 45,
    pattern:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g,
    recommendation:
      "Strip PEM private keys immediately and rotate compromised key material before querying any remote model.",
    maskPreview: true,
  },
  {
    category: "credentials",
    severity: 40,
    pattern:
      /\b(?:sk-[A-Za-z0-9_-]{8,}|tk_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    recommendation:
      "Replace live API tokens and cloud access keys with <CREDENTIAL_REDACTED> before sending off-device.",
    maskPreview: true,
  },
  // 2. Personal Identifiers (PII)
  {
    category: "pii",
    severity: 25,
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    recommendation:
      "Generalize personal or corporate email addresses into symbolic placeholders.",
  },
  {
    category: "pii",
    severity: 30,
    pattern:
      /\b(?:\d{3}-\d{2}-\d{4}|[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D])\b/g,
    recommendation:
      "Remove government identification numbers (SSN / National Insurance) prior to external inference.",
    maskPreview: true,
  },
  {
    category: "pii",
    severity: 20,
    pattern:
      /(?:\+\d{1,3}[\s.-]?)?\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}\b|\b(?:\+\d{1,2}[\s.-])?\d{3}-\d{3}-\d{4}\b/g,
    recommendation:
      "Remove direct telephone numbers from prompts sent to remote providers.",
  },
  // 3. Internal Infrastructure
  {
    category: "infrastructure",
    severity: 28,
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ssh):\/\/[^\s"'<>]+/gi,
    recommendation:
      "Replace internal database or SSH connection URIs with <TARGET_SYSTEM>.",
  },
  {
    category: "infrastructure",
    severity: 22,
    pattern:
      /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b/g,
    recommendation:
      "Abstract RFC1918 private IPv4 addresses into symbolic network identifiers.",
  },
  {
    category: "infrastructure",
    severity: 20,
    pattern:
      /\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:internal|corp|lan|intranet|private)(?::\d{2,5})?\b/gi,
    recommendation:
      "Replace internal corporate hostnames (.internal, .corp) with <TARGET_SYSTEM>.",
  },
  // 4. Financial
  {
    category: "financial",
    severity: 20,
    pattern:
      /(?:\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?:\s?(?:million|billion|k|M|B))?\b|\b(?:USD|EUR|GBP)\s?\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?\b|\baccount\s*#?\s*\d{6,16}\b)/gi,
    recommendation:
      "Replace specific monetary figures and account numbers with symbolic variables like <AMOUNT_A>.",
  },
  // 5. Medical / Clinical
  {
    category: "medical",
    severity: 24,
    pattern:
      /\b(?:my\s+patient|patient(?:'s)?|diagnosis|diagnosed\s+with|dosage|mg\/kg|mg\/day|biopsy|ICD-(?:9|10)(?:-[A-Z0-9.]+)?|oncology|chemotherapy|pathology\s+report)\b/gi,
    recommendation:
      "Generalize clinical and patient-specific disclosures into <PATIENT_COHORT> or abstract medical inquiry terms.",
  },
  // 6. Temporal (Specific Dates)
  {
    category: "temporal",
    severity: 12,
    pattern:
      /\b(?:\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])|(?:0?[1-9]|1[0-2])\/(?:0?[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+(?:19|20)\d{2})\b/gi,
    recommendation:
      "Replace exact dates and timestamps with relative symbolic markers such as <DATE_T0>.",
  },
  // 7. First-person biographical / organizational context
  {
    category: "first-person-context",
    severity: 15,
    pattern:
      /\b(?:my\s+company|our\s+company|my\s+patient|our\s+proprietary|my\s+employer|my\s+startup|my\s+salary|my\s+medical|my\s+diagnosis|our\s+internal|my\s+client)\b/gi,
    recommendation:
      "Rewrite first-person organizational or biographical framing as a general, third-person technical question.",
  },
];

function formatMatchedPreview(raw: string, mask?: boolean): string {
  const trimmed = raw.trim();
  if (!mask || trimmed.length <= 10) {
    return trimmed.length > 48 ? `${trimmed.slice(0, 45)}...` : trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

function scoreToLevel(score: number): PrivacyRiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "moderate";
  return "low";
}

/**
 * Evaluates a user prompt for client-side privacy exposure risk across 7 categories.
 * Returns a 0..100 risk score, qualitative level, and specific findings.
 */
export function scorePromptPrivacyRisk(prompt: string): PrivacyRiskAssessment {
  if (!prompt || !prompt.trim()) {
    return { score: 0, level: "low", findings: [] };
  }

  const findings: PrivacyRiskFinding[] = [];
  const seenCategoryPreviews = new Set<string>();

  for (const rule of DETECTION_RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match: RegExpExecArray | null = regex.exec(prompt);
    while (match !== null) {
      const rawMatch = match[0];
      const preview = formatMatchedPreview(rawMatch, rule.maskPreview);
      const dedupeKey = `${rule.category}:${rawMatch.toLowerCase()}`;

      if (!seenCategoryPreviews.has(dedupeKey)) {
        seenCategoryPreviews.add(dedupeKey);
        findings.push({
          category: rule.category,
          severity: rule.severity,
          matchedPreview: preview,
          recommendation: rule.recommendation,
        });
      }
      match = regex.exec(prompt);
    }
  }

  const rawScore = findings.reduce((sum, item) => sum + item.severity, 0);
  const distinctCategories = new Set(findings.map((f) => f.category)).size;
  const multiVectorBonus = distinctCategories >= 4 ? 10 : distinctCategories >= 3 ? 5 : 0;
  const score = findings.length === 0 ? 0 : Math.min(100, rawScore + multiVectorBonus);

  return {
    score,
    level: scoreToLevel(score),
    findings,
  };
}

function assignVaultToken(
  vault: Record<string, string>,
  reverseVault: Map<string, string>,
  rawValue: string,
  primaryToken: string,
  indexedPrefix: string,
  counterRef: { count: number }
): string {
  const existing = reverseVault.get(rawValue);
  if (existing) return existing;

  counterRef.count += 1;
  const token =
    counterRef.count === 1
      ? `<${primaryToken}>`
      : `<${indexedPrefix}${counterRef.count}>`;
  vault[token] = rawValue;
  reverseVault.set(rawValue, token);
  return token;
}

/**
 * PAPILLON-inspired prompt generalizer:
 * Rewrites first-person/company-specific framing and strips credentials, PII,
 * internal hosts/IPs, clinical details, monetary amounts, and dates into
 * symbolic tokens stored in `localContextVault`.
 */
export function generalizePromptPapillon(
  prompt: string
): PapillonGeneralizationResult {
  const beforeAssessment = scorePromptPrivacyRisk(prompt);
  const localContextVault: Record<string, string> = {};
  const reverseVault = new Map<string, string>();

  let working = prompt;

  const credCounter = { count: 0 };
  const targetCounter = { count: 0 };
  const piiCounter = { count: 0 };
  const amountCounter = { count: 0 };
  const dateCounter = { count: 0 };
  const patientCounter = { count: 0 };
  const contextCounter = { count: 0 };

  // 1. Replace PEM blocks & API credentials -> <CREDENTIAL_REDACTED>
  working = working.replace(
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "CREDENTIAL_REDACTED",
        "CREDENTIAL_REDACTED_",
        credCounter
      )
  );

  working = working.replace(
    /\b(?:sk-[A-Za-z0-9_-]{8,}|tk_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "CREDENTIAL_REDACTED",
        "CREDENTIAL_REDACTED_",
        credCounter
      )
  );

  // 2. Replace Infrastructure URIs, private IPs, and internal hostnames -> <TARGET_SYSTEM>
  working = working.replace(
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ssh):\/\/[^\s"'<>]+/gi,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "TARGET_SYSTEM",
        "TARGET_SYSTEM_",
        targetCounter
      )
  );

  working = working.replace(
    /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "TARGET_SYSTEM",
        "TARGET_SYSTEM_",
        targetCounter
      )
  );

  working = working.replace(
    /\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:internal|corp|lan|intranet|private)(?::\d{2,5})?\b/gi,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "TARGET_SYSTEM",
        "TARGET_SYSTEM_",
        targetCounter
      )
  );

  // 3. Replace PII (emails, SSN/NI, phone numbers) -> <PII_REDACTED>
  working = working.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "PII_REDACTED",
        "PII_REDACTED_",
        piiCounter
      )
  );

  working = working.replace(
    /\b(?:\d{3}-\d{2}-\d{4}|[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D])\b/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "PII_REDACTED",
        "PII_REDACTED_",
        piiCounter
      )
  );

  working = working.replace(
    /(?:\+\d{1,3}[\s.-]?)?\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}\b|\b(?:\+\d{1,2}[\s.-])?\d{3}-\d{3}-\d{4}\b/g,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "PII_REDACTED",
        "PII_REDACTED_",
        piiCounter
      )
  );

  // 4. Replace Financial amounts / account numbers -> <AMOUNT_A>, <AMOUNT_B>, ...
  working = working.replace(
    /(?:\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?:\s?(?:million|billion|k|M|B))?\b|\b(?:USD|EUR|GBP)\s?\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?\b|\baccount\s*#?\s*\d{6,16}\b)/gi,
    (match) => {
      const existing = reverseVault.get(match);
      if (existing) return existing;
      const suffix = String.fromCharCode(65 + Math.min(amountCounter.count, 25));
      amountCounter.count += 1;
      const token = `<AMOUNT_${suffix}>`;
      localContextVault[token] = match;
      reverseVault.set(match, token);
      return token;
    }
  );

  // 5. Replace Dates -> <DATE_T0>, <DATE_T1>, ...
  working = working.replace(
    /\b(?:\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])|(?:0?[1-9]|1[0-2])\/(?:0?[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+(?:19|20)\d{2})\b/gi,
    (match) => {
      const existing = reverseVault.get(match);
      if (existing) return existing;
      const index = dateCounter.count;
      dateCounter.count += 1;
      const token = `<DATE_T${index}>`;
      localContextVault[token] = match;
      reverseVault.set(match, token);
      return token;
    }
  );

  // 6. Replace Medical / Clinical disclosures -> <PATIENT_COHORT>
  working = working.replace(
    /\b(?:my\s+patient|patient(?:'s)?|diagnosis|diagnosed\s+with|dosage|mg\/kg|mg\/day|biopsy|ICD-(?:9|10)(?:-[A-Z0-9.]+)?|oncology|chemotherapy|pathology\s+report)\b/gi,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "PATIENT_COHORT",
        "CLINICAL_TERM_",
        patientCounter
      )
  );

  // 7. Rewrite First-person organizational/biographical disclosures -> <ORG_ENTITY>
  working = working.replace(
    /\b(?:my\s+company|our\s+company|our\s+proprietary|my\s+employer|my\s+startup|my\s+salary|my\s+medical|my\s+diagnosis|our\s+internal|my\s+client)\b/gi,
    (match) =>
      assignVaultToken(
        localContextVault,
        reverseVault,
        match,
        "ORG_ENTITY",
        "ORG_ENTITY_",
        contextCounter
      )
  );

  const afterAssessment = scorePromptPrivacyRisk(working);

  return {
    generalizedPrompt: working,
    localContextVault,
    riskBefore: beforeAssessment.score,
    riskAfter: afterAssessment.score,
  };
}

/**
 * Substitutes symbolic PAPILLON variables in the remote model's response
 * back to the user's private local context values on-device.
 */
export function rehydratePapillonAnswer(
  answer: string,
  localContextVault: Record<string, string>
): string {
  if (!answer || !localContextVault) {
    return answer;
  }

  let rehydrated = answer;
  const entries = Object.entries(localContextVault).sort(
    (a, b) => b[0].length - a[0].length
  );

  for (const [symbol, originalValue] of entries) {
    const normalizedSymbol =
      symbol.startsWith("<") && symbol.endsWith(">")
        ? symbol
        : `<${symbol}>`;
    rehydrated = rehydrated.split(normalizedSymbol).join(originalValue);
    if (normalizedSymbol !== symbol) {
      rehydrated = rehydrated.split(symbol).join(originalValue);
    }
  }

  return rehydrated;
}
