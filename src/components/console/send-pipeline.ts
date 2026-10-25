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
import {
  createMechanicalSession,
  type MechanicalSession,
} from "@/lib/privacy/mechanical";
import type { MechanicalRuleset } from "@/lib/privacy/mechanical-ruleset";
import type { SessionScrubber } from "@/lib/privacy/scrubber";
import type { ChatMessage } from "@/components/session";

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
  session?: MechanicalSession;
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
    ...(opts?.ruleset !== undefined ? { ruleset: opts.ruleset } : {}),
    ...(opts?.published !== undefined ? { published: opts.published } : {}),
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
    mechanical: true,
    session: opts?.session ? opts.session.clone() : undefined,
    scrubber: opts?.scrubber,
    ruleset: opts?.rulesetOverride,
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
    mechanical: true,
    session: opts?.session,
    scrubber: opts?.scrubber,
    ruleset: opts?.rulesetOverride,
  }).outboundText;
}

/**
 * Gives every earlier message the exact text to resend. Messages that kept
 * their original wire text reuse it; any other message, including AI replies
 * shown with hidden details put back, is filtered again with the session so
 * only placeholders leave the device.
 */
export function prepareHistoryForWire(
  messages: readonly ChatMessage[],
  opts?: PrepareTurnOptions,
): ChatMessage[] {
  return messages.map((m) => {
    if (m.wireContent) return m;
    let wire = prepareHistoricalTurnText(m.content, {
      ...opts,
      normalizeStyle: m.role === "user" && Boolean(opts?.normalizeStyle),
    });
    // Values hidden earlier in this conversation (for example text you wrapped
    // in ££) stay hidden even when a reply repeats them without markers.
    const known = (opts?.session?.entries() ?? [])
      .filter((e) => e.original.trim().length >= 3)
      .sort((a, b) => b.original.length - a.original.length);
    for (const e of known) {
      wire = wire.split(e.original).join(e.placeholder);
    }
    return { ...m, wireContent: wire };
  });
}

/**
 * Rebuilds a `MechanicalSession` in chronological order from restored conversation
 * messages so later turns keep consistent placeholders and can restore historical placeholders.
 */
export function rebuildMechanicalSessionFromMessages(
  messages: ReadonlyArray<{ role: "user" | "assistant"; content: string }>,
  opts?: PrepareTurnOptions,
): MechanicalSession {
  const session = opts?.session ?? createMechanicalSession();
  session.clear();
  for (const m of messages) {
    if (m.role === "user") {
      prepareHistoricalTurnText(m.content, {
        ...opts,
        session,
      });
    }
  }
  return session;
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
    mechanical: true,
    session: opts?.session,
    scrubber: opts?.scrubber,
    ruleset: opts?.rulesetOverride,
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
