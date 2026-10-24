import { getActiveCustomScrubTerms } from "@/lib/auth/vault";
import { nullifierFor, parseCreditHeader } from "@/lib/credits/blind";
import {
  storedCreditBalance,
  takeCreditHeader,
} from "@/lib/credits/client";
import { preparePrompt, type PreparedPrompt } from "@/lib/pipeline";
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
 * Executes the real send preparation path before each message:
 * 1. Reads active custom scrub terms from the unlocked vault (`getActiveCustomScrubTerms()`).
 * 2. Calls `preparePrompt` (`@/lib/pipeline`) to scrub PII/secrets/custom terms,
 *    optionally normalize stylometry, score privacy risk before/after, and compute bucket bytes.
 * 3. Takes one unspent blind-signed credit header via `takeCreditHeader()` (`@/lib/credits/client`)
 *    when available in local storage.
 */
export async function prepareOutboundTurn(
  rawText: string,
  opts?: PrepareTurnOptions,
): Promise<PreparedTurn> {
  const scrubEnabled = opts?.scrubEnabled ?? true;
  const customTerms = opts?.customTermsOverride ?? getActiveCustomScrubTerms();

  const prepared = preparePrompt(rawText, {
    customTerms,
    normalizeStyle: Boolean(opts?.normalizeStyle),
    scrubber: opts?.scrubber,
  });

  const outboundText = scrubEnabled ? prepared.outboundText : rawText;

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
    redactions: scrubEnabled ? prepared.report.redactions : [],
    bucketBytes: prepared.bucketBytes,
    riskBefore: prepared.report.riskBefore,
    riskAfter: scrubEnabled
      ? prepared.report.riskAfter
      : prepared.report.riskBefore,
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
      if (!scrubEnabled) return modelText;
      return prepared.restore(modelText);
    },
  };
}
