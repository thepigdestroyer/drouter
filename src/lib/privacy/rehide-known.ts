import type { MechanicalSession } from "@/lib/privacy/mechanical";
import { MECHANICAL_RULESET } from "@/lib/privacy/mechanical-ruleset";

const PLACEHOLDER = new RegExp(
  MECHANICAL_RULESET.placeholderPatterns.existingPlaceholder.source,
  MECHANICAL_RULESET.placeholderPatterns.existingPlaceholder.flags,
);
const CJK_RE = new RegExp(
  MECHANICAL_RULESET.sessionKnownValues.cjkPattern.source,
  MECHANICAL_RULESET.sessionKnownValues.cjkPattern.flags,
);
const STARTS_WITH_WORD_RE = new RegExp(
  MECHANICAL_RULESET.patterns.startsWithWordChar.source,
  MECHANICAL_RULESET.patterns.startsWithWordChar.flags,
);
const ENDS_WITH_WORD_RE = new RegExp(
  MECHANICAL_RULESET.patterns.endsWithWordChar.source,
  MECHANICAL_RULESET.patterns.endsWithWordChar.flags,
);
const ESCAPE_RE = new RegExp(
  MECHANICAL_RULESET.patterns.regexSpecialCharsEscape.source,
  MECHANICAL_RULESET.patterns.regexSpecialCharsEscape.flags,
);

function escapeRegExp(s: string): string {
  return s.replace(ESCAPE_RE, "\\$&");
}

function isPlaceholderToken(s: string): boolean {
  PLACEHOLDER.lastIndex = 0;
  const hit = PLACEHOLDER.test(s);
  PLACEHOLDER.lastIndex = 0;
  return hit;
}

/**
 * Replaces values this session already hid (for example text wrapped in ££
 * that a reply repeats without markers) with their placeholders, ignoring
 * capitalisation. Runs in one pass and never touches text inside an existing
 * placeholder.
 */
export function rehideKnownValues(
  text: string,
  session: MechanicalSession | undefined,
): string {
  const knownCfg = MECHANICAL_RULESET.sessionKnownValues;
  if (!session || !text || !knownCfg.enabled) return text;

  const eligible: Array<{
    trimmed: string;
    key: string;
    placeholder: string;
  }> = [];
  const byOriginal = new Map<string, string>();

  for (const e of session.entries()) {
    const trimmed = e.original.trim();
    if (!trimmed) continue;
    if (isPlaceholderToken(trimmed)) continue;
    const minLen = CJK_RE.test(trimmed)
      ? knownCfg.minLengthCjk
      : knownCfg.minLength;
    if (trimmed.length < minLen) continue;
    const key = knownCfg.caseInsensitive ? trimmed.toLowerCase() : trimmed;
    if (!byOriginal.has(key)) {
      byOriginal.set(key, e.placeholder);
      eligible.push({ trimmed, key, placeholder: e.placeholder });
    }
  }

  if (eligible.length === 0) return text;
  eligible.sort((a, b) => b.trimmed.length - a.trimmed.length);

  const patternSources = eligible.map((item) => {
    const escaped = escapeRegExp(item.trimmed);
    if (!knownCfg.wordBoundaryAscii) return escaped;
    const prefix = STARTS_WITH_WORD_RE.test(item.trimmed) ? "\\b" : "";
    const suffix = ENDS_WITH_WORD_RE.test(item.trimmed) ? "\\b" : "";
    return `${prefix}${escaped}${suffix}`;
  });

  const pattern = new RegExp(
    patternSources.join("|"),
    knownCfg.caseInsensitive ? "gi" : "g",
  );
  const rehide = (segment: string) =>
    segment.replace(pattern, (m) => {
      const lookup = knownCfg.caseInsensitive ? m.toLowerCase() : m;
      return byOriginal.get(lookup) ?? m;
    });

  let out = "";
  let last = 0;
  for (const m of text.matchAll(PLACEHOLDER)) {
    const at = m.index ?? 0;
    out += rehide(text.slice(last, at)) + m[0];
    last = at + m[0].length;
  }
  return out + rehide(text.slice(last));
}
