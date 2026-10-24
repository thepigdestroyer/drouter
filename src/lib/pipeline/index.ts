import {
  createSessionScrubber,
  type SessionScrubber,
} from "../privacy/scrubber";
import { padPayloadToBucket } from "../privacy/padding";
import { scorePromptPrivacyRisk } from "../risk/analyzer";
import { normalizeStylometry } from "../stylometry/normalizer";
import { createDecoyBundle, type DecoyBundle } from "../chaff/decoys";

export interface PreparedPrompt {
  outboundText: string;
  bucketBytes: number;
  report: {
    redactions: Array<{ kind: string; placeholder: string }>;
    riskBefore: number;
    riskAfter: number;
    styleChanges: number;
  };
  restore(modelText: string): string;
  paddedBytes?: Uint8Array;
  decoyBundle?: DecoyBundle;
}

export interface PreparePromptOptions {
  customTerms?: string[];
  normalizeStyle?: boolean;
  scrubber?: SessionScrubber;
  decoyCount?: number;
}

const REDACTION_RISK_WEIGHTS: Readonly<Record<string, number>> = {
  SECRET: 40,
  ACCT: 30,
  EMAIL: 25,
  PHONE: 20,
  IP: 22,
  ENTITY: 18,
};

/**
 * Browser-safe prompt preparation pipeline (Interface I1).
 * Composes the session PII/secret scrubber (with custom terms),
 * privacy risk analyzer, optional stylometry normalization,
 * bucket wire padding, and optional k-anonymity chaff generation.
 */
export function preparePrompt(
  text: string,
  opts?: PreparePromptOptions,
): PreparedPrompt {
  const inputText = text ?? "";
  const customTerms = opts?.customTerms ?? [];
  const scrubber = opts?.scrubber ?? createSessionScrubber(customTerms);
  if (opts?.scrubber && customTerms.length > 0) {
    for (const term of customTerms) {
      scrubber.addCustomTerm(term);
    }
  }

  // 1. Scrub PII, secrets, account identifiers, and custom terms first so
  //    stylometry normalization never alters secret/entity substrings.
  const scrubResult = scrubber.scrub(inputText);
  const redactions: Array<{ kind: string; placeholder: string }> =
    scrubResult.replacements.map((r) => ({
      kind: r.kind,
      placeholder: r.placeholder,
    }));

  // 2. Optionally normalize stylometric fingerprint on the scrubbed text.
  let outboundText = scrubResult.scrubbed;
  let styleChanges = 0;
  if (opts?.normalizeStyle) {
    const styleResult = normalizeStylometry(outboundText);
    outboundText = styleResult.normalized;
    styleChanges = styleResult.changesApplied.length;
  }

  // 3. Evaluate privacy risk before and after preparation.
  const baseRiskBefore = scorePromptPrivacyRisk(inputText).score;
  const baseRiskAfter = scorePromptPrivacyRisk(outboundText).score;

  // Ensure any custom term or scrubber-only redaction is reflected in riskBefore.
  const redactionFloor = redactions.reduce(
    (sum, r) => sum + (REDACTION_RISK_WEIGHTS[r.kind] ?? 15),
    0,
  );
  const riskBefore = Math.min(100, Math.max(baseRiskBefore, redactionFloor));
  const riskAfter = Math.min(riskBefore, baseRiskAfter);

  // 4. Pad outbound payload to its power-of-two token bucket.
  const { paddedBytes, bucketBytes } = padPayloadToBucket(outboundText);

  // 5. Optional additive chaff / decoy bundle generation when requested via opts.decoyCount.
  const decoyBundle =
    opts?.decoyCount && opts.decoyCount > 1
      ? createDecoyBundle(outboundText, opts.decoyCount)
      : undefined;

  return {
    outboundText,
    bucketBytes,
    report: {
      redactions,
      riskBefore,
      riskAfter,
      styleChanges,
    },
    restore(modelText: string): string {
      if (!modelText) return modelText;
      return scrubber.restore(modelText);
    },
    ...(paddedBytes ? { paddedBytes } : {}),
    ...(decoyBundle ? { decoyBundle } : {}),
  };
}
