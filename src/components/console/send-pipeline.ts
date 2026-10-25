import { getActiveCustomScrubTerms } from "@/lib/auth/vault";
import { nullifierFor, parseCreditHeader } from "@/lib/credits/blind";
import {
  storeCreditTokens,
  storedCreditBalance,
  takeCreditHeader,
} from "@/lib/credits/client";
import { preparePrompt, type PreparedPrompt } from "@/lib/pipeline";
import {
  evaluateLocalFilterFingerprint,
  type PublishedFilterFingerprint,
} from "@/lib/privacy/fingerprint";
import type { MechanicalRuleset } from "@/lib/privacy/mechanical-ruleset";
import type { SessionScrubber } from "@/lib/privacy/scrubber";

export interface MessagePrivacyReport {
  redactions: Array<{ kind: string; placeholder: string }>;
  bucketBytes: number;
  riskBefore: number;
  riskAfter: number;
  styleChanges: number;
  customTermsCount: number;
  creditAttached: boolean;
  creditNullifier: string | null;
  outboundPreview: string;
}

export interface PrepareTurnOptions {
  scrubEnabled?: boolean;
  normalizeStyle?: boolean;
  scrubber?: SessionScrubber;
  customTermsOverride?: string[];
  rulesetOverride?: MechanicalRuleset;
  publishedFingerprintOverride?: PublishedFilterFingerprint;
}

export class FilterFingerprintMismatchError extends Error {
  readonly computedFingerprint: string;
  readonly publishedFingerprint: string | null;

  constructor(
    message: string,
    computedFingerprint: string,
    publishedFingerprint: string | null,
  ) {
    super(message);
    this.name = "FilterFingerprintMismatchError";
    this.computedFingerprint = computedFingerprint;
    this.publishedFingerprint = publishedFingerprint;
  }
}

export function assertFilterFingerprintAllowsSend(opts?: {
  ruleset?: MechanicalRuleset;
  published?: PublishedFilterFingerprint;
}): void {
  const status = evaluateLocalFilterFingerprint({
    ruleset: opts?.ruleset,
    published: opts?.published,
  });
  if (status.blockingSend) {
    throw new FilterFingerprintMismatchError(
      status.blockReason ??
        "Sending is blocked because the personal-detail filter running in this browser does not match the published version in the public receipt book.",
      status.computedFingerprint,
      status.publishedFingerprint,
    );
  }
}

export interface PreparedTurn {
  prepared: PreparedPrompt;
  outboundText: string;
  creditHeader: string | null;
  creditBalanceAfter: number;
  report: MessagePrivacyReport;
  restore(modelText: string): string;
}

/**
 * Runs the client-side prompt preparation pipeline for a draft (without consuming credits).
 */
export function previewDraftPrivacy(
  draftText: string,
  opts?: PrepareTurnOptions,
): {
  prepared: PreparedPrompt;
  customTerms: string[];
} {
  const customTerms = opts?.customTermsOverride ?? getActiveCustomScrubTerms();
  const prepared = preparePrompt(draftText, {
    customTerms,
    normalizeStyle: Boolean(opts?.normalizeStyle),
    scrubber: opts?.scrubber,
  });
  return { prepared, customTerms };
}

/**
 * Runs `preparePrompt` (including active custom scrub terms from the vault and optional
 * style normalization) on a historical user message that was resumed without `wireContent`.
 */
export function prepareHistoricalTurnText(
  rawText: string,
  opts?: PrepareTurnOptions,
): string {
  const customTerms = opts?.customTermsOverride ?? getActiveCustomScrubTerms();
  return preparePrompt(rawText, {
    customTerms,
    normalizeStyle: Boolean(opts?.normalizeStyle),
    scrubber: opts?.scrubber,
  }).outboundText;
}

/**
 * Restores an unspent `x-drouter-credit` header token back into local wallet storage
 * if a turn fails before any reply tokens arrive.
 */
export function restoreUnspentCreditHeader(creditHeader: string | null): number {
  if (!creditHeader) return storedCreditBalance();
  try {
    const parsed = parseCreditHeader(creditHeader);
    if (parsed) {
      storeCreditTokens([parsed]);
    }
  } catch {
    // Ignore malformed header
  }
  return storedCreditBalance();
}

/**
 * Executes the real send preparation path before each message:
 * 1. Reads active custom scrub terms from the unlocked vault (`getActiveCustomScrubTerms()`).
 * 2. Calls `preparePrompt` (`@/lib/pipeline`) to scrub PII/secrets/custom terms,
 *    optionally normalize stylometry, score privacy risk before/after, and compute bucket bytes.
 * 3. Always uses `preparePrompt`'s `outboundText` so raw unscrubbed text is never sent.
 * 4. Takes one unspent blind-signed credit header via `takeCreditHeader()` (`@/lib/credits/client`)
 *    when available in local storage.
 */
export async function prepareOutboundTurn(
  rawText: string,
  opts?: PrepareTurnOptions,
): Promise<PreparedTurn> {
  assertFilterFingerprintAllowsSend({
    ruleset: opts?.rulesetOverride,
    published: opts?.publishedFingerprintOverride,
  });

  const customTerms = opts?.customTermsOverride ?? getActiveCustomScrubTerms();

  const prepared = preparePrompt(rawText, {
    customTerms,
    normalizeStyle: Boolean(opts?.normalizeStyle),
    scrubber: opts?.scrubber,
  });

  const outboundText = prepared.outboundText;

  let creditHeader: string | null = null;
  let creditNullifier: string | null = null;
  try {
    creditHeader = await takeCreditHeader();
    if (creditHeader) {
      const parsedToken = parseCreditHeader(creditHeader);
      if (parsedToken?.token) {
        creditNullifier = nullifierFor(parsedToken.token);
      }
    }
  } catch {
    creditHeader = null;
  }

  const creditBalanceAfter = storedCreditBalance();

  const report: MessagePrivacyReport = {
    redactions: prepared.report.redactions,
    bucketBytes: prepared.bucketBytes,
    riskBefore: prepared.report.riskBefore,
    riskAfter: prepared.report.riskAfter,
    styleChanges: prepared.report.styleChanges,
    customTermsCount: customTerms.length,
    creditAttached: Boolean(creditHeader),
    creditNullifier,
    outboundPreview: outboundText,
  };

  return {
    prepared,
    outboundText,
    creditHeader,
    creditBalanceAfter,
    report,
    restore(modelText: string): string {
      return prepared.restore(modelText);
    },
  };
}
