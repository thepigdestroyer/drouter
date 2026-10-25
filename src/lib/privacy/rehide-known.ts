import type { MechanicalSession } from "@/lib/privacy/mechanical";

const PLACEHOLDER = /\[[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_\d+\]/g;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
  if (!session || !text) return text;
  const known = session
    .entries()
    .filter((e) => e.original.trim().length >= 3)
    .sort((a, b) => b.original.length - a.original.length);
  if (known.length === 0) return text;

  const byOriginal = new Map<string, string>();
  for (const e of known) {
    const key = e.original.toLowerCase();
    if (!byOriginal.has(key)) byOriginal.set(key, e.placeholder);
  }
  const pattern = new RegExp(
    known.map((e) => escapeRegExp(e.original)).join("|"),
    "gi",
  );
  const rehide = (segment: string) =>
    segment.replace(pattern, (m) => byOriginal.get(m.toLowerCase()) ?? m);

  let out = "";
  let last = 0;
  for (const m of text.matchAll(PLACEHOLDER)) {
    const at = m.index ?? 0;
    out += rehide(text.slice(last, at)) + m[0];
    last = at + m[0].length;
  }
  return out + rehide(text.slice(last));
}
