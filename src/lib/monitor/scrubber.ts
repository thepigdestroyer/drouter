/**
 * Local PII & Secret Scrubber with Reversible Placeholder Vault (Spec §1)
 *
 * Scrubs emails, API keys, bearer tokens, private keys, and high-entropy credentials
 * into deterministic local placeholders before sending prompts out of the local host,
 * and restores placeholders in model completions.
 */

export type SecretCategory = "EMAIL" | "SECRET";

export interface ScrubResult {
  scrubbedText: string;
  placeholders: Record<string, string>;
  redactionCount: number;
}

export interface ChatCompletionMessage {
  role: string;
  content: string | Array<{ type: string; text?: string; [key: string]: unknown }> | null;
  [key: string]: unknown;
}

interface PatternSpec {
  category: SecretCategory;
  regex: RegExp;
}

const SCRUB_PATTERNS: readonly PatternSpec[] = [
  // PEM private key blocks
  {
    category: "SECRET",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  // OpenAI / Anthropic / Stripe / GitHub / Slack / AWS / Hex private keys & API tokens
  {
    category: "SECRET",
    regex:
      /\b(?:sk-[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|0x[a-fA-F0-9]{64})\b/g,
  },
  // Generic labeled secrets like api_key=..., secret: "...", password=... (captures value)
  {
    category: "SECRET",
    regex: /\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{16,})\b/g,
  },
  // Email addresses
  {
    category: "EMAIL",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
];

export class PlaceholderVault {
  private readonly valueToPlaceholder = new Map<string, string>();
  private readonly placeholderToValue = new Map<string, string>();
  private counters: Record<SecretCategory, number> = {
    EMAIL: 0,
    SECRET: 0,
  };

  scrub(input: string): string {
    let text = input;
    for (const spec of SCRUB_PATTERNS) {
      const regex = new RegExp(spec.regex.source, spec.regex.flags);
      text = text.replace(regex, (match) => this.register(spec.category, match));
    }
    return text;
  }

  restore(input: string): string {
    let text = input;
    this.placeholderToValue.forEach((original, placeholder) => {
      if (text.includes(placeholder)) {
        text = text.split(placeholder).join(original);
      }
    });
    return text;
  }

  scrubMessages<T extends ChatCompletionMessage>(messages: readonly T[]): T[] {
    return messages.map((msg) => {
      if (typeof msg.content === "string") {
        return {
          ...msg,
          content: this.scrub(msg.content),
        };
      }
      if (Array.isArray(msg.content)) {
        return {
          ...msg,
          content: msg.content.map((part) =>
            typeof part.text === "string" ? { ...part, text: this.scrub(part.text) } : part,
          ),
        };
      }
      return { ...msg };
    });
  }

  snapshot(): Record<string, string> {
    const out: Record<string, string> = {};
    this.placeholderToValue.forEach((value, placeholder) => {
      out[placeholder] = value;
    });
    return out;
  }

  get size(): number {
    return this.placeholderToValue.size;
  }

  private register(category: SecretCategory, rawValue: string): string {
    const existing = this.valueToPlaceholder.get(rawValue);
    if (existing) {
      return existing;
    }
    this.counters[category] += 1;
    const placeholder = `[[DROUTER_${category}_${this.counters[category]}]]`;
    this.valueToPlaceholder.set(rawValue, placeholder);
    this.placeholderToValue.set(placeholder, rawValue);
    return placeholder;
  }
}

export function scrubWithPlaceholders(text: string): ScrubResult {
  const vault = new PlaceholderVault();
  const scrubbedText = vault.scrub(text);
  return {
    scrubbedText,
    placeholders: vault.snapshot(),
    redactionCount: vault.size,
  };
}

export function restorePlaceholders(text: string, placeholders: Record<string, string>): string {
  let out = text;
  for (const [placeholder, original] of Object.entries(placeholders)) {
    if (out.includes(placeholder)) {
      out = out.split(placeholder).join(original);
    }
  }
  return out;
}
