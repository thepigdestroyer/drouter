import { utf8ToBytes } from "@noble/hashes/utils.js";

export const SANDBOX_ISOLATION_MODE = "vercel-sandbox-firecracker" as const;
export const SANDBOX_DESCRIPTION =
  "Vercel Sandbox is an isolated Firecracker microVM, not a hardware-attested enclave." as const;

export type SandboxLanguage = "python" | "python3" | "node" | "javascript";

export const MAX_SANDBOX_CODE_CHARS = 8_192;
export const MAX_SANDBOX_OUTPUT_BYTES = 16_384;
export const DEFAULT_SANDBOX_TIMEOUT_MS = 30_000;
export const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
export const SMALLEST_SANDBOX_VCPUS = 1;

export interface LiveSandboxRunOptions {
  language?: SandboxLanguage;
  code: string;
  timeoutMs?: number;
  commandTimeoutMs?: number;
  maxOutputBytes?: number;
}

export interface LiveSandboxRunResult {
  isolation: typeof SANDBOX_ISOLATION_MODE;
  description: typeof SANDBOX_DESCRIPTION;
  sandboxId: string;
  sandboxName: string;
  language: "python3" | "node";
  filePath: string;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  exitCode: number;
  durationMs: number;
  vcpus: number;
  memoryMb: number;
  stopped: boolean;
}

export interface SandboxCapabilities {
  isolation: typeof SANDBOX_ISOLATION_MODE;
  description: typeof SANDBOX_DESCRIPTION;
  hardwareAttested: false;
  tee: false;
  sdkPackage: "@vercel/sandbox";
  sdkVersion: "3.9.0";
  supportedLanguages: readonly ["python3", "node"];
  resources: {
    vcpus: number;
    memoryMb: number;
    timeoutMs: number;
    commandTimeoutMs: number;
  };
  limits: {
    maxBodyBytes: number;
    maxCodeChars: number;
    maxOutputBytes: number;
    maxConcurrentExecutions: number;
  };
  envPassedToSandbox: false;
}

export function getSandboxCapabilities(opts?: {
  maxBodyBytes?: number;
  maxConcurrentExecutions?: number;
}): SandboxCapabilities {
  return {
    isolation: SANDBOX_ISOLATION_MODE,
    description: SANDBOX_DESCRIPTION,
    hardwareAttested: false,
    tee: false,
    sdkPackage: "@vercel/sandbox",
    sdkVersion: "3.9.0",
    supportedLanguages: ["python3", "node"],
    resources: {
      vcpus: SMALLEST_SANDBOX_VCPUS,
      memoryMb: SMALLEST_SANDBOX_VCPUS * 2048,
      timeoutMs: DEFAULT_SANDBOX_TIMEOUT_MS,
      commandTimeoutMs: DEFAULT_COMMAND_TIMEOUT_MS,
    },
    limits: {
      maxBodyBytes: opts?.maxBodyBytes ?? 16_384,
      maxCodeChars: MAX_SANDBOX_CODE_CHARS,
      maxOutputBytes: MAX_SANDBOX_OUTPUT_BYTES,
      maxConcurrentExecutions: opts?.maxConcurrentExecutions ?? 2,
    },
    envPassedToSandbox: false,
  };
}

export function normalizeSandboxLanguage(
  language?: string
): "python3" | "node" {
  const normalized = (language ?? "python3").trim().toLowerCase();
  if (normalized === "python" || normalized === "python3" || normalized === "py") {
    return "python3";
  }
  if (
    normalized === "node" ||
    normalized === "nodejs" ||
    normalized === "javascript" ||
    normalized === "js"
  ) {
    return "node";
  }
  throw new Error(
    `Unsupported sandbox language "${language}". Supported languages: python3, node.`
  );
}

export function capOutputText(
  raw: string,
  maxBytes: number = MAX_SANDBOX_OUTPUT_BYTES
): { text: string; truncated: boolean } {
  const encoded = utf8ToBytes(raw);
  if (encoded.byteLength <= maxBytes) {
    return { text: raw, truncated: false };
  }
  const sliced = encoded.slice(0, maxBytes);
  const decoded = new TextDecoder("utf-8", { fatal: false }).decode(sliced);
  return { text: decoded, truncated: true };
}
