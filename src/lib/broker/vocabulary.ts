import { LOOKUP_TOPICS, type LookupTopic } from "@/lib/gemini/interactions";

export { LOOKUP_TOPICS, type LookupTopic };

export type LookupIntent = {
  kind: "topic";
  topic: LookupTopic;
};

const LOOKUP_TOPIC_SET: ReadonlySet<string> = new Set<string>(LOOKUP_TOPICS);

export class LookupIntentValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LookupIntentValidationError";
  }
}

function isStrictPlainObject(value: unknown): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.prototype.toString.call(value) !== "[object Object]"
  ) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Validates that `x` is strictly `{ kind: "topic", topic }` where `topic` is an
 * allowlisted literal in `LOOKUP_TOPICS`.
 * Rejects extra fields, prototype/symbol properties, getters, free text, and unknown topics.
 */
export function validateLookupIntent(x: unknown): LookupIntent {
  if (!isStrictPlainObject(x)) {
    throw new LookupIntentValidationError(
      "Invalid lookup intent: expected a plain object of shape { kind: \"topic\", topic }.",
    );
  }

  if (Object.getOwnPropertySymbols(x).length > 0) {
    throw new LookupIntentValidationError(
      "Invalid lookup intent: symbol properties are not permitted.",
    );
  }

  const ownKeys = Object.getOwnPropertyNames(x);
  if (ownKeys.length !== 2) {
    throw new LookupIntentValidationError(
      `Invalid lookup intent: expected exactly keys ["kind", "topic"], got [${ownKeys.join(", ")}].`,
    );
  }

  for (const key of ownKeys) {
    if (key !== "kind" && key !== "topic") {
      throw new LookupIntentValidationError(
        `Invalid lookup intent: unexpected field "${key}". Extra fields and free text are rejected.`,
      );
    }
    const desc = Object.getOwnPropertyDescriptor(x, key);
    if (!desc || !("value" in desc) || desc.enumerable !== true) {
      throw new LookupIntentValidationError(
        `Invalid lookup intent: property "${key}" must be an enumerable data property.`,
      );
    }
  }

  const rawKind = x.kind;
  if (typeof rawKind !== "string" || rawKind !== "topic") {
    throw new LookupIntentValidationError(
      `Invalid lookup intent: kind must be "topic", got ${JSON.stringify(rawKind)}.`,
    );
  }

  const rawTopic = x.topic;
  if (typeof rawTopic !== "string" || rawTopic.length === 0) {
    throw new LookupIntentValidationError(
      "Invalid lookup intent: topic must be a non-empty string in LOOKUP_TOPICS.",
    );
  }

  if (!LOOKUP_TOPIC_SET.has(rawTopic)) {
    throw new LookupIntentValidationError(
      `Invalid lookup intent: topic ${JSON.stringify(rawTopic)} is not in LOOKUP_TOPICS.`,
    );
  }

  return {
    kind: "topic",
    topic: rawTopic as LookupTopic,
  };
}
