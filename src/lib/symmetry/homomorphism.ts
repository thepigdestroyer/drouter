export type SymmetryKind = "date" | "currency" | "entity";

export interface AppliedMask {
  kind: SymmetryKind;
  original: string;
  masked: string;
}

export interface SymmetryTransformOptions {
  dateShiftDays?: number;
  numericScaleFactor?: number;
  customEntities?: Record<string, string>;
}

export interface SymmetryParameters {
  dateShiftDays: number;
  numericScaleFactor: number;
  entityMap: Record<string, string>;
}

export interface SymmetryTransform {
  transform(text: string): {
    transformed: string;
    applied: AppliedMask[];
  };
  untransform(text: string): string;
  parameters(): SymmetryParameters;
}

const DEFAULT_ENTITIES: Record<string, string> = {
  "Project Hyperion": "Project Halcyon",
  "Acme Bio": "Northwind Labs",
  "Dr. Aris Thorne": "Dr. Clara Vance",
};

const ISO_DATE_RE = /\b(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b/g;

// Matches currency tokens like $1,200.50, £45,000, €10,000, USD 5000, EUR 1,250.00
const CURRENCY_RE =
  /(?:([$£€¥])(\s*)(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?|\b(USD|EUR|GBP|CAD|AUD|CHF|JPY)(\s+)(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?\b)/g;

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseIsoDateUtc(iso: string): Date | null {
  const parts = iso.split("-");
  if (parts.length !== 3) return null;
  const year = Number(parts[0]);
  const month = Number(parts[1]);
  const day = Number(parts[2]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
    return null;
  }
  const dt = new Date(Date.UTC(year, month - 1, day));
  if (
    dt.getUTCFullYear() !== year ||
    dt.getUTCMonth() !== month - 1 ||
    dt.getUTCDate() !== day
  ) {
    return null;
  }
  return dt;
}

function formatIsoDateUtc(dt: Date): string {
  const y = dt.getUTCFullYear().toString().padStart(4, "0");
  const m = (dt.getUTCMonth() + 1).toString().padStart(2, "0");
  const d = dt.getUTCDate().toString().padStart(2, "0");
  return `${y}-${m}-${d}`;
}

export function shiftIsoDate(iso: string, deltaDays: number): string {
  const dt = parseIsoDateUtc(iso);
  if (!dt) return iso;
  const shiftedMs = dt.getTime() + deltaDays * 86_400_000;
  return formatIsoDateUtc(new Date(shiftedMs));
}

function addCommas(intPart: string): string {
  return intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatScaledCurrency(
  prefix: string,
  sep: string,
  intRaw: string,
  fracRaw: string | undefined,
  factor: number,
): string {
  const hasCommas = intRaw.includes(",");
  const cleanNumberStr = `${intRaw.replace(/,/g, "")}${fracRaw !== undefined ? `.${fracRaw}` : ""}`;
  const numericValue = Number(cleanNumberStr);
  if (!Number.isFinite(numericValue)) {
    return `${prefix}${sep}${intRaw}${fracRaw !== undefined ? `.${fracRaw}` : ""}`;
  }

  const scaled = Math.round(numericValue * factor * 100) / 100;
  const hadDecimals = fracRaw !== undefined;
  const decimalsCount = hadDecimals ? fracRaw.length : 0;
  const hasNonZeroCents = Math.abs(scaled - Math.round(scaled)) > 1e-6;

  let formattedNum: string;
  if (hadDecimals) {
    const fixed = scaled.toFixed(Math.max(2, decimalsCount));
    const [iPart, dPart] = fixed.split(".");
    const useCommas = hasCommas || Number(iPart) >= 1000;
    formattedNum = `${useCommas ? addCommas(iPart) : iPart}.${dPart}`;
  } else if (hasNonZeroCents) {
    const fixed = scaled.toFixed(2);
    const [iPart, dPart] = fixed.split(".");
    const useCommas = hasCommas || Number(iPart) >= 1000;
    formattedNum = `${useCommas ? addCommas(iPart) : iPart}.${dPart}`;
  } else {
    const iPart = Math.round(scaled).toString();
    const useCommas = hasCommas;
    formattedNum = useCommas ? addCommas(iPart) : iPart;
  }

  return `${prefix}${sep}${formattedNum}`;
}

interface SpanReplacement {
  start: number;
  end: number;
  kind: SymmetryKind;
  original: string;
  masked: string;
}

function defaultRandomInt(min: number, max: number): number {
  const range = max - min + 1;
  if (range <= 1) return min;
  if (
    typeof globalThis.crypto === "undefined" ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new Error("CSPRNG unavailable: crypto.getRandomValues is required");
  }
  const maxUint32PlusOne = 0x100000000;
  const limit = maxUint32PlusOne - (maxUint32PlusOne % range);
  const arr = new Uint32Array(1);
  let sample = 0;
  do {
    globalThis.crypto.getRandomValues(arr);
    sample = arr[0];
  } while (sample >= limit);
  return min + (sample % range);
}

const NICE_SCALE_FACTORS = [1.5, 2, 2.5, 4, 5, 8, 10];

export function createSymmetryTransform(
  opts: SymmetryTransformOptions = {},
): SymmetryTransform {
  if (opts.dateShiftDays !== undefined && !Number.isFinite(opts.dateShiftDays)) {
    throw new Error("dateShiftDays must be a finite number");
  }
  if (
    opts.numericScaleFactor !== undefined &&
    (!Number.isFinite(opts.numericScaleFactor) || opts.numericScaleFactor <= 0)
  ) {
    throw new Error("numericScaleFactor must be a positive finite number");
  }

  const dateShiftDays =
    opts.dateShiftDays !== undefined
      ? Math.trunc(opts.dateShiftDays)
      : defaultRandomInt(17, 89);

  const numericScaleFactor =
    opts.numericScaleFactor !== undefined
      ? opts.numericScaleFactor
      : NICE_SCALE_FACTORS[defaultRandomInt(0, NICE_SCALE_FACTORS.length - 1)];

  const entityMap: Record<string, string> = {
    ...DEFAULT_ENTITIES,
    ...(opts.customEntities ?? {}),
  };

  // Validate bijectivity: two distinct original entities must not map to the same masked alias
  const seenAliases = new Map<string, string>();
  for (const [orig, alias] of Object.entries(entityMap)) {
    const cleanOrig = orig.trim();
    const cleanAlias = alias.trim();
    if (!cleanOrig || !cleanAlias) continue;
    const lowerAlias = cleanAlias.toLowerCase();
    const existingOrig = seenAliases.get(lowerAlias);
    if (existingOrig && existingOrig.toLowerCase() !== cleanOrig.toLowerCase()) {
      throw new Error(
        `Non-bijective entity mapping: "${existingOrig}" and "${cleanOrig}" both map to "${cleanAlias}"`,
      );
    }
    seenAliases.set(lowerAlias, cleanOrig);
  }

  const exactMaskedCurrencyToOriginal = new Map<string, string[]>();
  const exactMaskedEntityToOriginal = new Map<string, string>();

  // Build sorted pairs for forward and reverse entity replacement (longest match first)
  const forwardEntities = Object.entries(entityMap)
    .filter(([orig, alias]) => orig.trim().length > 0 && alias.trim().length > 0)
    .sort((a, b) => b[0].length - a[0].length);

  const reverseEntities = Object.entries(entityMap)
    .filter(([orig, alias]) => orig.trim().length > 0 && alias.trim().length > 0)
    .map(([orig, alias]) => [alias, orig] as const)
    .sort((a, b) => b[0].length - a[0].length);

  function collectForwardSpans(text: string): SpanReplacement[] {
    const spans: SpanReplacement[] = [];

    const overlaps = (start: number, end: number): boolean =>
      spans.some((s) => start < s.end && end > s.start);

    // 1. Entities (longest first, case-insensitive match preserving configured alias)
    for (const [orig, alias] of forwardEntities) {
      const escaped = escapeRegExp(orig);
      const startsWord = /^\w/.test(orig);
      const endsWord = /\w$/.test(orig);
      const re = new RegExp(
        `${startsWord ? "\\b" : ""}${escaped}${endsWord ? "\\b" : ""}`,
        "gi",
      );
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (overlaps(start, end)) continue;
        spans.push({
          start,
          end,
          kind: "entity",
          original: m[0],
          masked: alias,
        });
      }
    }

    // 2. ISO Dates (YYYY-MM-DD)
    {
      const re = new RegExp(ISO_DATE_RE.source, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const raw = m[0];
        const start = m.index;
        const end = start + raw.length;
        if (overlaps(start, end)) continue;
        if (!parseIsoDateUtc(raw)) continue;
        const masked = shiftIsoDate(raw, dateShiftDays);
        spans.push({
          start,
          end,
          kind: "date",
          original: raw,
          masked,
        });
      }
    }

    // 3. Currency values
    {
      const re = new RegExp(CURRENCY_RE.source, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const raw = m[0];
        const start = m.index;
        const end = start + raw.length;
        if (overlaps(start, end)) continue;

        const symPrefix = m[1];
        const symSep = m[2];
        const symInt = m[3];
        const symFrac = m[4];

        const codePrefix = m[5];
        const codeSep = m[6];
        const codeInt = m[7];
        const codeFrac = m[8];

        const masked =
          symPrefix !== undefined
            ? formatScaledCurrency(symPrefix, symSep, symInt, symFrac, numericScaleFactor)
            : formatScaledCurrency(codePrefix, codeSep, codeInt, codeFrac, numericScaleFactor);

        spans.push({
          start,
          end,
          kind: "currency",
          original: raw,
          masked,
        });
      }
    }

    spans.sort((a, b) => a.start - b.start);
    return spans;
  }

  function transform(text: string): {
    transformed: string;
    applied: AppliedMask[];
  } {
    if (!text) {
      return { transformed: text, applied: [] };
    }
    const spans = collectForwardSpans(text);
    if (spans.length === 0) {
      return { transformed: text, applied: [] };
    }

    const applied: AppliedMask[] = [];
    let out = "";
    let cursor = 0;

    for (const s of spans) {
      out += text.slice(cursor, s.start);
      out += s.masked;
      if (s.kind === "currency") {
        const list = exactMaskedCurrencyToOriginal.get(s.masked) ?? [];
        list.push(s.original);
        exactMaskedCurrencyToOriginal.set(s.masked, list);
      } else if (s.kind === "entity") {
        exactMaskedEntityToOriginal.set(s.masked.toLowerCase(), s.original);
      }
      applied.push({
        kind: s.kind,
        original: s.original,
        masked: s.masked,
      });
      cursor = s.end;
    }
    out += text.slice(cursor);

    return { transformed: out, applied };
  }

  function untransform(text: string): string {
    if (!text) return text;

    const spans: { start: number; end: number; replacement: string }[] = [];
    const overlaps = (start: number, end: number): boolean =>
      spans.some((s) => start < s.end && end > s.start);

    // 1. Reverse entity aliases
    for (const [alias, orig] of reverseEntities) {
      const escaped = escapeRegExp(alias);
      const startsWord = /^\w/.test(alias);
      const endsWord = /\w$/.test(alias);
      const re = new RegExp(
        `${startsWord ? "\\b" : ""}${escaped}${endsWord ? "\\b" : ""}`,
        "gi",
      );
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (overlaps(start, end)) continue;
        const exactOrig = exactMaskedEntityToOriginal.get(m[0].toLowerCase()) ?? orig;
        spans.push({ start, end, replacement: exactOrig });
      }
    }

    // 2. Reverse ISO Dates (-dateShiftDays)
    {
      const re = new RegExp(ISO_DATE_RE.source, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const raw = m[0];
        const start = m.index;
        const end = start + raw.length;
        if (overlaps(start, end)) continue;
        if (!parseIsoDateUtc(raw)) continue;
        spans.push({
          start,
          end,
          replacement: shiftIsoDate(raw, -dateShiftDays),
        });
      }
    }

    // 3. Reverse Currency Scaling (1 / numericScaleFactor)
    {
      const invFactor = 1 / numericScaleFactor;
      const currencyCursor = new Map<string, number>();
      const re = new RegExp(CURRENCY_RE.source, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const raw = m[0];
        const start = m.index;
        const end = start + raw.length;
        if (overlaps(start, end)) continue;

        const exactCurrencyList = exactMaskedCurrencyToOriginal.get(raw);
        if (exactCurrencyList !== undefined && exactCurrencyList.length > 0) {
          const idx = currencyCursor.get(raw) ?? 0;
          const exactCurrency =
            exactCurrencyList[Math.min(idx, exactCurrencyList.length - 1)];
          currencyCursor.set(raw, idx + 1);
          spans.push({ start, end, replacement: exactCurrency });
          continue;
        }

        const symPrefix = m[1];
        const symSep = m[2];
        const symInt = m[3];
        const symFrac = m[4];

        const codePrefix = m[5];
        const codeSep = m[6];
        const codeInt = m[7];
        const codeFrac = m[8];

        const replacement =
          symPrefix !== undefined
            ? formatScaledCurrency(symPrefix, symSep, symInt, symFrac, invFactor)
            : formatScaledCurrency(codePrefix, codeSep, codeInt, codeFrac, invFactor);

        spans.push({ start, end, replacement });
      }
    }

    if (spans.length === 0) return text;
    spans.sort((a, b) => a.start - b.start);

    let out = "";
    let cursor = 0;
    for (const s of spans) {
      out += text.slice(cursor, s.start);
      out += s.replacement;
      cursor = s.end;
    }
    out += text.slice(cursor);
    return out;
  }

  function parameters(): SymmetryParameters {
    return {
      dateShiftDays,
      numericScaleFactor,
      entityMap: { ...entityMap },
    };
  }

  return {
    transform,
    untransform,
    parameters,
  };
}
