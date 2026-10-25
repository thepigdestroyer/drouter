import type { ScrubResult } from "@/lib/types";
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
import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
} from "@/lib/privacy/mechanical-ruleset";
import type { SessionScrubber } from "@/lib/privacy/scrubber";
import type { ActiveSession, ChatMessage } from "@/components/session";
import { rehideKnownValues } from "@/lib/privacy/rehide-known";

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
 * their original wire text pass it through `rehideKnownValues` so newly hidden
 * session values never leak; any other message, including AI replies shown with
 * hidden details put back or resumed messages without `wireContent`, is
 * filtered again with the session so only placeholders leave the device.
 */
export function prepareHistoryForWire(
  messages: readonly ChatMessage[],
  opts?: PrepareTurnOptions,
): ChatMessage[] {
  return messages.map((m) => {
    if (m.wireContent) {
      return {
        ...m,
        wireContent: rehideKnownValues(m.wireContent, opts?.session),
      };
    }
    const wire = prepareHistoricalTurnText(m.content, {
      ...opts,
      normalizeStyle: m.role === "user" && Boolean(opts?.normalizeStyle),
    });
    // Values hidden earlier in this conversation (for example text you wrapped
    // in ££) stay hidden even when a reply repeats them without markers.
    return { ...m, wireContent: rehideKnownValues(wire, opts?.session) };
  });
}

/**
 * Strips `wireContent` and `privacyReport` before freezing/saving or upon
 * resuming a conversation so resumed chats are always re-filtered from scratch
 * against the active ruleset, style settings, and vault custom terms.
 */
export function stripWireContentFromMessages(
  messages: readonly ChatMessage[],
): ChatMessage[] {
  return messages.map(({ role, content }) => ({
    role,
    content,
  }));
}

/**
 * Rebuilds a `MechanicalSession` in chronological order from restored conversation
 * messages (including assistant messages with `normalizeStyle: false`) so later
 * turns keep consistent placeholders and can restore historical placeholders.
 */
export function rebuildMechanicalSessionFromMessages(
  messages: ReadonlyArray<{ role: "user" | "assistant"; content: string }>,
  opts?: PrepareTurnOptions,
): MechanicalSession {
  const session = opts?.session ?? createMechanicalSession();
  session.clear();
  for (const m of messages) {
    prepareHistoricalTurnText(m.content, {
      ...opts,
      normalizeStyle: m.role === "user" && Boolean(opts?.normalizeStyle),
      session,
    });
  }
  return session;
}

/**
 * Scans a completed assistant reply for literal `[KIND_N]` tokens that are not
 * active placeholders in `session` and reserves them so subsequent user turns
 * cannot allocate a colliding placeholder.
 */
export function reserveAssistantLiteralPlaceholders(
  wireReply: string,
  session?: MechanicalSession,
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): string[] {
  if (!wireReply || !session) return [];
  const existingRe = new RegExp(
    ruleset.placeholderPatterns.existingPlaceholder.source,
    ruleset.placeholderPatterns.existingPlaceholder.flags,
  );
  const knownPlaceholders = new Set(
    session.entries().map((e) => e.placeholder.toUpperCase()),
  );
  const literalsToReserve: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = existingRe.exec(wireReply)) !== null) {
    const token = match[0].toUpperCase();
    if (!knownPlaceholders.has(token) && !literalsToReserve.includes(token)) {
      literalsToReserve.push(token);
    }
  }
  if (literalsToReserve.length > 0) {
    session.redact(literalsToReserve.join(" "), { ruleset });
  }
  return literalsToReserve;
}

/**
 * Clears the chat messages, privacy badges, and mechanical session when the
 * vault locks or the user signs out so private conversation state does not stay
 * on screen or collide with a wiped session.
 */
export function applyVaultSignOutReset(state: {
  session?: MechanicalSession | null;
  setMessages?: (messages: ChatMessage[]) => void;
  setLastScrubbed?: (scrubbed: ScrubResult | null) => void;
  setLastPrivacyReport?: (report: MessagePrivacyReport | null) => void;
}): ChatMessage[] {
  state.session?.clear();
  state.setMessages?.([]);
  state.setLastScrubbed?.(null);
  state.setLastPrivacyReport?.(null);
  return [];
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

export interface ExecuteSendTurnParams {
  text: string;
  messages: readonly ChatMessage[];
  model: string;
  activeSession: Pick<ActiveSession, "send">;
  mechanicalSession: MechanicalSession;
  scrubEnabled?: boolean;
  normalizeStyle?: boolean;
  onPrepared?: (info: {
    turnPrepared: PreparedTurn;
    displayHistory: ChatMessage[];
    wireHistory: ChatMessage[];
  }) => void;
  onStreamDelta?: (info: {
    wireReply: string;
    restoredReply: string;
    messagesWithReply: ChatMessage[];
  }) => void;
}

export type ExecuteSendTurnResult =
  | {
      ok: true;
      messages: ChatMessage[];
      wireHistory: ChatMessage[];
      wireReply: string;
      restoredReply: string;
      turnPrepared: PreparedTurn;
      mechanicalSession: MechanicalSession;
      reservedLiterals: string[];
    }
  | {
      ok: false;
      error: Error;
      failedBeforeFirstToken: boolean;
      messages: ChatMessage[];
      restoredInput: string;
      creditBalanceAfterRollback: number | null;
      mechanicalSession: MechanicalSession;
    };

/**
 * Orchestrates a chat turn:
 * 1. Clones `mechanicalSession` so it can be restored if sending fails before the first token (M2).
 * 2. Runs `prepareOutboundTurn` BEFORE `prepareHistoryForWire` so new ££...££ markers or
 *    custom terms are registered in the session before history is re-hidden (C5).
 * 3. Streams from `activeSession.send(wireHistory, model, ...)` and restores placeholders live.
 * 4. Reserves any literal `[KIND_N]` tokens in the completed assistant reply that are not
 *    session placeholders (M3).
 * 5. Rolls back `messages`, `mechanicalSession`, and unspent credits if the turn fails before
 *    the first token (M2).
 */
export async function executeSendTurn(
  params: ExecuteSendTurnParams,
): Promise<ExecuteSendTurnResult> {
  const {
    text,
    messages,
    model,
    activeSession,
    mechanicalSession,
    scrubEnabled,
    normalizeStyle,
    onPrepared,
    onStreamDelta,
  } = params;

  const sessionSnapshot = mechanicalSession.clone();

  let turnPrepared: PreparedTurn;
  let preparedHistoryMessages: ChatMessage[];
  try {
    turnPrepared = await prepareOutboundTurn(text, {
      scrubEnabled,
      normalizeStyle,
      session: mechanicalSession,
    });

    preparedHistoryMessages = prepareHistoryForWire(messages, {
      normalizeStyle,
      session: mechanicalSession,
    });
  } catch (e) {
    const error =
      e instanceof Error
        ? e
        : new Error("Could not prepare your message right now.");
    return {
      ok: false,
      error,
      failedBeforeFirstToken: true,
      messages: [...messages],
      restoredInput: text,
      creditBalanceAfterRollback: null,
      mechanicalSession: sessionSnapshot,
    };
  }

  const userMsg: ChatMessage = {
    role: "user",
    content: text,
    wireContent: turnPrepared.outboundText,
    privacyReport: turnPrepared.report,
  };

  const displayHistory: ChatMessage[] = [...preparedHistoryMessages, userMsg];
  const wireHistory: ChatMessage[] = displayHistory.map((m) => ({
    role: m.role,
    content: m.wireContent ?? m.content,
    wireContent: m.wireContent ?? m.content,
  }));

  onPrepared?.({
    turnPrepared,
    displayHistory,
    wireHistory,
  });

  let wireReply = "";
  let restoredReply = "";
  let messagesWithReply: ChatMessage[] = [
    ...displayHistory,
    { role: "assistant", content: "" },
  ];

  try {
    for await (const delta of activeSession.send(wireHistory, model, {
      creditHeader: turnPrepared.creditHeader,
    })) {
      wireReply += delta;
      restoredReply = turnPrepared.restore(wireReply);
      messagesWithReply = [
        ...displayHistory,
        {
          role: "assistant",
          content: restoredReply,
          wireContent: wireReply,
        },
      ];
      onStreamDelta?.({
        wireReply,
        restoredReply,
        messagesWithReply,
      });
    }
    const reservedLiterals = reserveAssistantLiteralPlaceholders(
      wireReply,
      mechanicalSession,
    );
    return {
      ok: true,
      messages: messagesWithReply,
      wireHistory,
      wireReply,
      restoredReply,
      turnPrepared,
      mechanicalSession,
      reservedLiterals,
    };
  } catch (e) {
    const error =
      e instanceof Error
        ? e
        : new Error("Could not get a reply right now.");
    if (!wireReply) {
      let refundedBalance: number | null = null;
      if (turnPrepared.creditHeader) {
        refundedBalance = restoreUnspentCreditHeader(turnPrepared.creditHeader);
      }
      return {
        ok: false,
        error,
        failedBeforeFirstToken: true,
        messages: [...messages],
        restoredInput: text,
        creditBalanceAfterRollback: refundedBalance,
        mechanicalSession: sessionSnapshot,
      };
    }
    reserveAssistantLiteralPlaceholders(wireReply, mechanicalSession);
    return {
      ok: false,
      error,
      failedBeforeFirstToken: false,
      messages: messagesWithReply,
      restoredInput: "",
      creditBalanceAfterRollback: null,
      mechanicalSession,
    };
  }
}
