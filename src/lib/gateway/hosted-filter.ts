import {
  createMechanicalSession,
  type MechanicalSession,
} from "@/lib/privacy/mechanical";
import { rehideKnownValues } from "@/lib/privacy/rehide-known";
import { preparePrompt, type PreparedPrompt } from "@/lib/pipeline";

export const UNSUPPORTED_MEDIA_ERROR_MESSAGE =
  "images, audio and files are not supported yet";

const UNSUPPORTED_MEDIA_PART_TYPES = new Set([
  "image",
  "image_url",
  "input_image",
  "audio",
  "input_audio",
  "audio_url",
  "file",
  "input_file",
  "file_url",
  "document",
  "video",
  "video_url",
  "input_video",
  "media",
]);

const UNSUPPORTED_MEDIA_PART_KEYS = [
  "image_url",
  "input_image",
  "image",
  "audio",
  "input_audio",
  "audio_url",
  "file",
  "input_file",
  "file_url",
  "file_data",
  "file_id",
  "inline_data",
  "inlineData",
  "fileData",
] as const;

const NON_TEXT_STRUCTURAL_KEYS = new Set([
  "type",
  "id",
  "tool_call_id",
  "tool_use_id",
  "role",
  "index",
  "finish_reason",
  "object",
  "model",
  "cache_control",
]);

export class HostedUnsupportedMediaError extends Error {
  readonly status = 400;

  constructor(message: string = UNSUPPORTED_MEDIA_ERROR_MESSAGE) {
    super(message);
    this.name = "HostedUnsupportedMediaError";
  }
}

function isMediaTypeToken(rawType: string): boolean {
  const normalized = rawType.trim().toLowerCase();
  if (!normalized) return false;
  if (UNSUPPORTED_MEDIA_PART_TYPES.has(normalized)) return true;
  return /(?:^|[_-\s/])(?:image|audio|file|video|document)(?:$|[_-\s/])/i.test(
    normalized,
  );
}

/**
 * Recursively inspects a content part or nested array/object for any image, audio, or file payload.
 */
export function containsUnsupportedMediaPart(node: unknown): boolean {
  if (!node || typeof node !== "object") {
    return false;
  }
  if (Array.isArray(node)) {
    return node.some((item) => containsUnsupportedMediaPart(item));
  }

  const obj = node as Record<string, unknown>;
  if (typeof obj.type === "string" && isMediaTypeToken(obj.type)) {
    return true;
  }

  for (const key of UNSUPPORTED_MEDIA_PART_KEYS) {
    if (obj[key] !== undefined && obj[key] !== null) {
      return true;
    }
  }

  if (obj.source && typeof obj.source === "object" && !Array.isArray(obj.source)) {
    const src = obj.source as Record<string, unknown>;
    if (
      src.type === "base64" ||
      src.type === "url" ||
      src.type === "file" ||
      typeof src.media_type === "string" ||
      typeof src.mediaType === "string"
    ) {
      return true;
    }
  }

  for (const [k, v] of Object.entries(obj)) {
    if (k === "cache_control") continue;
    if (v && typeof v === "object" && containsUnsupportedMediaPart(v)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks whether a single message object contains any image, audio, or file parts.
 */
export function messageContainsUnsupportedMedia(msg: unknown): boolean {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
    return false;
  }
  const obj = msg as Record<string, unknown>;

  for (const key of UNSUPPORTED_MEDIA_PART_KEYS) {
    if (obj[key] !== undefined && obj[key] !== null) {
      return true;
    }
  }
  if (Array.isArray(obj.files) && obj.files.length > 0) {
    return true;
  }
  if (Array.isArray(obj.attachments) && obj.attachments.length > 0) {
    return true;
  }

  if (obj.content !== undefined && obj.content !== null && typeof obj.content === "object") {
    if (containsUnsupportedMediaPart(obj.content)) {
      return true;
    }
  }

  return false;
}

function mapContentNodeStrings(
  node: unknown,
  transform: (text: string) => string,
): unknown {
  if (typeof node === "string") {
    return transform(node);
  }
  if (Array.isArray(node)) {
    return node.map((item) => mapContentNodeStrings(item, transform));
  }
  if (node && typeof node === "object") {
    const obj = node as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key === "user" || key === "metadata") {
        continue;
      }
      if (NON_TEXT_STRUCTURAL_KEYS.has(key)) {
        out[key] = value;
      } else if (typeof value === "string") {
        out[key] = transform(value);
      } else if (value && typeof value === "object") {
        out[key] = mapContentNodeStrings(value, transform);
      } else {
        out[key] = value;
      }
    }
    return out;
  }
  return node;
}

function mapSingleMessageStrings(
  msg: Record<string, unknown>,
  transform: (text: string) => string,
): Record<string, unknown> {
  const next: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(msg)) {
    if (key === "user" || key === "metadata") {
      continue;
    }
    next[key] = value;
  }

  if (typeof next.name === "string") {
    next.name = transform(next.name);
  }

  if (typeof next.content === "string") {
    next.content = transform(next.content);
  } else if (next.content && typeof next.content === "object") {
    next.content = mapContentNodeStrings(next.content, transform);
  }

  if (Array.isArray(next.tool_calls)) {
    next.tool_calls = next.tool_calls.map((tc) => {
      if (!tc || typeof tc !== "object" || Array.isArray(tc)) return tc;
      const tcObj = { ...(tc as Record<string, unknown>) };
      if (tcObj.function && typeof tcObj.function === "object" && !Array.isArray(tcObj.function)) {
        const fnObj = { ...(tcObj.function as Record<string, unknown>) };
        if (typeof fnObj.arguments === "string") {
          fnObj.arguments = transform(fnObj.arguments);
        } else if (fnObj.arguments !== undefined && fnObj.arguments !== null) {
          fnObj.arguments = transform(JSON.stringify(fnObj.arguments));
        }
        tcObj.function = fnObj;
      }
      return tcObj;
    });
  }

  if (
    next.function_call &&
    typeof next.function_call === "object" &&
    !Array.isArray(next.function_call)
  ) {
    const fnCall = { ...(next.function_call as Record<string, unknown>) };
    if (typeof fnCall.arguments === "string") {
      fnCall.arguments = transform(fnCall.arguments);
    } else if (fnCall.arguments !== undefined && fnCall.arguments !== null) {
      fnCall.arguments = transform(JSON.stringify(fnCall.arguments));
    }
    next.function_call = fnCall;
  }

  if (typeof next.reasoning_content === "string") {
    next.reasoning_content = transform(next.reasoning_content);
  }

  return next;
}

export interface HostedFilterSuccess {
  ok: true;
  body: Record<string, unknown>;
  messages: Array<Record<string, unknown>>;
  session: MechanicalSession;
  redactionCount: number;
  restore(text: string): string;
}

export interface HostedFilterError {
  ok: false;
  status: 400;
  error: string;
}

export type HostedFilterResult = HostedFilterSuccess | HostedFilterError;

export interface HostedFilterOptions {
  customTerms?: string[];
  session?: MechanicalSession;
}

/**
 * Filters an array of chat messages in two passes using a per-request `createMechanicalSession()`:
 * 1. First pass runs `session.redact(text)` over every message (all roles including
 *    system/developer/tool/function/user/assistant), `name`, `content` strings and every
 *    text field in content-part arrays recursively, `tool_calls[].function.arguments`,
 *    `function_call.arguments`, and `reasoning_content`, while refusing image/audio/file parts
 *    with HTTP 400 and dropping `user` and `metadata`.
 * 2. Second pass runs `rehideKnownValues(text, session)` over all filtered text so values
 *    marked with `££` later in the conversation are hidden in earlier unmarked mentions too.
 */
export function filterHostedMessages(
  messages: readonly unknown[],
  opts?: HostedFilterOptions,
):
  | {
      ok: true;
      messages: Array<Record<string, unknown>>;
      session: MechanicalSession;
      redactionCount: number;
      restore(text: string): string;
    }
  | HostedFilterError {
  for (const msg of messages) {
    if (messageContainsUnsupportedMedia(msg)) {
      return {
        ok: false,
        status: 400,
        error: UNSUPPORTED_MEDIA_ERROR_MESSAGE,
      };
    }
  }

  const session = opts?.session ?? createMechanicalSession(opts?.customTerms ?? []);

  // Pass 1: Mechanical redaction across every message and every text-bearing field
  const pass1Messages = messages.map((rawMsg) => {
    if (!rawMsg || typeof rawMsg !== "object" || Array.isArray(rawMsg)) {
      return {} as Record<string, unknown>;
    }
    return mapSingleMessageStrings(rawMsg as Record<string, unknown>, (text) => {
      return session.redact(text).text;
    });
  });

  // Pass 2: Re-hide known values (such as ££marked££ terms introduced in later turns) everywhere
  const pass2Messages = pass1Messages.map((msg) =>
    mapSingleMessageStrings(msg, (text) => rehideKnownValues(text, session)),
  );

  return {
    ok: true,
    messages: pass2Messages,
    session,
    redactionCount: session.entries().length,
    restore: (text: string) => session.restore(text),
  };
}

/**
 * Filters a full hosted chat completions request body:
 * - Drops top-level `user` and `metadata`
 * - Rejects any image/audio/file content parts with HTTP 400
 * - Runs two-pass mechanical redaction + `rehideKnownValues` across all messages
 */
export function filterHostedChatRequest(
  rawBody: unknown,
  opts?: HostedFilterOptions,
): HostedFilterResult {
  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    return {
      ok: false,
      status: 400,
      error: "Request body must be a JSON object",
    };
  }

  const record = rawBody as Record<string, unknown>;
  const rawMessages = Array.isArray(record.messages) ? record.messages : [];

  const filteredMessages = filterHostedMessages(rawMessages, opts);
  if (!filteredMessages.ok) {
    return filteredMessages;
  }

  const nextBody: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (key === "user" || key === "metadata") {
      continue;
    }
    nextBody[key] = value;
  }
  nextBody.messages = filteredMessages.messages;

  return {
    ok: true,
    body: nextBody,
    messages: filteredMessages.messages,
    session: filteredMessages.session,
    redactionCount: filteredMessages.redactionCount,
    restore: filteredMessages.restore,
  };
}

export interface HostedStreamRestorer {
  push(chunk: string): string;
  flush(): string;
}

/**
 * Chunk-safe stream restorer for `[KIND_N]` mechanical placeholders split across SSE chunks.
 */
export function createHostedStreamRestorer(
  session: Pick<MechanicalSession, "restore"> | null | undefined,
): HostedStreamRestorer {
  let pending = "";
  const candidatePrefixRe = /^\[+?[A-Za-z0-9_]*$/;

  return {
    push(chunk: string): string {
      if (!chunk) return "";
      if (!session) return chunk;
      pending += chunk;

      const lastOpen = pending.lastIndexOf("[");
      if (lastOpen !== -1) {
        const closeAfter = pending.indexOf("]", lastOpen + 1);
        if (closeAfter === -1) {
          const tail = pending.slice(lastOpen);
          if (tail.length <= 40 && candidatePrefixRe.test(tail)) {
            const ready = pending.slice(0, lastOpen);
            pending = tail;
            return ready ? session.restore(ready) : "";
          }
        }
      }

      const out = session.restore(pending);
      pending = "";
      return out;
    },
    flush(): string {
      if (!pending) return "";
      const out = session ? session.restore(pending) : pending;
      pending = "";
      return out;
    },
  };
}

/**
 * Restores placeholders in a non-streaming chat completion response (`message.content`,
 * `tool_calls[].function.arguments`, `function_call.arguments`, and `reasoning_content`).
 */
export function restoreHostedChatCompletion<T>(
  completion: T,
  session: Pick<MechanicalSession, "restore"> | null | undefined,
): T {
  if (!session || !completion || typeof completion !== "object") {
    return completion;
  }

  const compRecord = completion as unknown as Record<string, unknown>;
  if (!Array.isArray(compRecord.choices)) {
    return completion;
  }

  const restoreFn = (text: string): string => session.restore(text);

  const restoredChoices = compRecord.choices.map((choice) => {
    if (!choice || typeof choice !== "object" || Array.isArray(choice)) {
      return choice;
    }
    const cObj = { ...(choice as Record<string, unknown>) };
    if (cObj.message && typeof cObj.message === "object" && !Array.isArray(cObj.message)) {
      cObj.message = mapSingleMessageStrings(
        cObj.message as Record<string, unknown>,
        restoreFn,
      );
    }
    return cObj;
  });

  return {
    ...compRecord,
    choices: restoredChoices,
  } as unknown as T;
}

/**
 * Restores placeholders in a single streaming SSE chunk delta (`delta.content`,
 * `delta.reasoning_content`, `delta.tool_calls[].function.arguments`, and `delta.function_call.arguments`)
 * using chunk-safe restorers.
 */
export function createHostedDeltaChunkRestorer(
  session: Pick<MechanicalSession, "restore"> | null | undefined,
) {
  const contentRestorer = createHostedStreamRestorer(session);
  const reasoningRestorer = createHostedStreamRestorer(session);
  const toolArgRestorers = new Map<string, HostedStreamRestorer>();
  const fnCallRestorer = createHostedStreamRestorer(session);

  const getToolRestorer = (key: string): HostedStreamRestorer => {
    let r = toolArgRestorers.get(key);
    if (!r) {
      r = createHostedStreamRestorer(session);
      toolArgRestorers.set(key, r);
    }
    return r;
  };

  return {
    contentRestorer,
    reasoningRestorer,
    restoreChunk(rawChunk: Record<string, unknown>): Record<string, unknown> {
      const chunk = structuredClone(rawChunk);
      if (!session) return chunk;

      const choices = Array.isArray(chunk.choices)
        ? (chunk.choices as Array<Record<string, unknown>>)
        : [];

      for (const choice of choices) {
        const delta =
          choice?.delta && typeof choice.delta === "object" && !Array.isArray(choice.delta)
            ? (choice.delta as Record<string, unknown>)
            : null;
        if (!delta) continue;

        if (typeof delta.content === "string" && delta.content.length > 0) {
          delta.content = contentRestorer.push(delta.content);
        } else if (Array.isArray(delta.content)) {
          delta.content = mapContentNodeStrings(delta.content, (s) => session.restore(s));
        }

        if (
          typeof delta.reasoning_content === "string" &&
          delta.reasoning_content.length > 0
        ) {
          delta.reasoning_content = reasoningRestorer.push(delta.reasoning_content);
        }

        if (Array.isArray(delta.tool_calls)) {
          delta.tool_calls = (delta.tool_calls as Array<Record<string, unknown>>).map(
            (tc, idx) => {
              if (!tc || typeof tc !== "object") return tc;
              const fn =
                tc.function && typeof tc.function === "object"
                  ? (tc.function as Record<string, unknown>)
                  : null;
              if (fn && typeof fn.arguments === "string") {
                const key = String(tc.index ?? tc.id ?? idx);
                return {
                  ...tc,
                  function: {
                    ...fn,
                    arguments: getToolRestorer(key).push(fn.arguments),
                  },
                };
              }
              return tc;
            },
          );
        }

        if (
          delta.function_call &&
          typeof delta.function_call === "object" &&
          !Array.isArray(delta.function_call)
        ) {
          const fnCall = delta.function_call as Record<string, unknown>;
          if (typeof fnCall.arguments === "string") {
            delta.function_call = {
              ...fnCall,
              arguments: fnCallRestorer.push(fnCall.arguments),
            };
          }
        }
      }

      return chunk;
    },
    flushRemaining(): {
      content: string;
      reasoning_content: string;
    } {
      return {
        content: contentRestorer.flush(),
        reasoning_content: reasoningRestorer.flush(),
      };
    },
  };
}

/**
 * Prepares a compartment prompt on the server using a per-request `createMechanicalSession()`
 * and a second pass of `rehideKnownValues` so `POST /api/compartment` uses the published
 * mechanical filter instead of the legacy session scrubber.
 */
export function prepareHostedCompartmentPrompt(
  rawPrompt: string,
  opts?: {
    customTerms?: string[];
    normalizeStyle?: boolean;
  },
): PreparedPrompt {
  const customTerms = Array.isArray(opts?.customTerms) ? opts.customTerms : [];
  const session = createMechanicalSession(customTerms);
  const prepared = preparePrompt(rawPrompt, {
    customTerms,
    normalizeStyle: Boolean(opts?.normalizeStyle),
    mechanical: true,
    session,
  });
  const outboundText = rehideKnownValues(prepared.outboundText, session);
  return {
    ...prepared,
    outboundText,
    restore(modelText: string): string {
      return session.restore(modelText);
    },
  };
}
