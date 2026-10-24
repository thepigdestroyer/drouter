import type { CheckResult, PopReceipt } from "@/lib/types";
import type { EvidenceSummary } from "./types";

export interface SimSession {
  simId: string;
  sessionId: Uint8Array;
  checks: CheckResult[];
  evidence: EvidenceSummary;
  send(message: string): AsyncGenerator<string, void, void>;
  close(): Promise<PopReceipt>;
}

export interface OpenSimOptions {
  fetch?: typeof fetch;
  onCheck?: (check: CheckResult) => void;
  now?: () => number;
}

/**
 * Retained only as a compile-safe stub while UI files (`src/components/session.ts`) are updated.
 * Delete after UI cleanup.
 */
export async function openSimSession(
  _baseUrl: string,
  simId: string,
  _opts: OpenSimOptions = {},
): Promise<SimSession> {
  throw new Error(
    `Simulated practice node "${simId}" has been removed; connect to an attested Tinfoil enclave instead.`,
  );
}
