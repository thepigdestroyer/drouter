import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { arcTestnet } from "viem/chains";
import { canonicalJson } from "@/lib/transparency/log";
import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
} from "./mechanical-ruleset";
import publishedFingerprintRaw from "./published-fingerprint.json";

export const ARC_TESTNET_CHAIN_ID = 5042002;
export const ARC_TESTNET_EXPLORER = "https://explorer.testnet.arc.io";
export const ARC_PUBLIC_RPC_URL: string =
  arcTestnet.rpcUrls.default.http[0] || "https://rpc.testnet.arc.network";

export interface PublishedFilterFingerprint {
  version: string;
  fingerprint: string | null;
  anchorTx: string | null;
  chainId?: number | null;
  anchoredAt?: string | null;
}

export type FilterFingerprintState =
  | "checking"
  | "not-published"
  | "match"
  | "mismatch"
  | "receipt-missing";

export interface FilterFingerprintStatus {
  state: FilterFingerprintState;
  version: string;
  computedFingerprint: string;
  publishedFingerprint: string | null;
  anchorTx: string | null;
  anchorUrl: string | null;
  anchorReceiptHash: string;
  arcReceiptVerified: boolean | null;
  blockingSend: boolean;
  plainSummary: string;
  blockReason: string | null;
}

export interface VerifyFilterFingerprintOptions {
  ruleset?: MechanicalRuleset;
  published?: PublishedFilterFingerprint;
  rpcUrl?: string;
  fetchImpl?: typeof fetch;
}

let testOverrideStatus: FilterFingerprintStatus | null = null;
let testOverrideOptions: VerifyFilterFingerprintOptions | null = null;

export function setFilterFingerprintStatusForTests(
  status: FilterFingerprintStatus | null,
): void {
  testOverrideStatus = status;
}

export function getFilterFingerprintStatusOverrideForTests(): FilterFingerprintStatus | null {
  return testOverrideStatus;
}

export function setFilterFingerprintVerifyOptionsForTests(
  opts: VerifyFilterFingerprintOptions | null,
): void {
  testOverrideOptions = opts;
}

export function getFilterFingerprintVerifyOptionsForTests(): VerifyFilterFingerprintOptions | null {
  return testOverrideOptions;
}

export function getPublishedFilterFingerprint(): PublishedFilterFingerprint {
  const raw = publishedFingerprintRaw as Partial<PublishedFilterFingerprint>;
  return {
    version:
      typeof raw.version === "string" && raw.version.length > 0
        ? raw.version
        : MECHANICAL_RULESET.version,
    fingerprint:
      typeof raw.fingerprint === "string" && raw.fingerprint.length > 0
        ? raw.fingerprint
        : null,
    anchorTx:
      typeof raw.anchorTx === "string" && raw.anchorTx.length > 0
        ? raw.anchorTx
        : null,
    chainId: typeof raw.chainId === "number" ? raw.chainId : null,
    anchoredAt: typeof raw.anchoredAt === "string" ? raw.anchoredAt : null,
  };
}

/**
 * Computes `0x` + lowercase sha256 hex of `canonicalJson(ruleset)`.
 * Browser-safe and deterministic across Node and browser runtimes.
 */
export function rulesetFingerprint(
  ruleset: MechanicalRuleset = MECHANICAL_RULESET,
): `0x${string}` {
  const canonical = canonicalJson(ruleset);
  const digest = bytesToHex(sha256(utf8ToBytes(canonical))).toLowerCase();
  return `0x${digest}`;
}

/**
 * Computes the 32-byte receipt hash anchored on the Arc registry:
 * `keccak256("deroute-filter:" + version + ":" + fingerprint)`
 */
export function computeFilterAnchorReceiptHash(
  version: string = MECHANICAL_RULESET.version,
  fingerprint: string = rulesetFingerprint(MECHANICAL_RULESET),
): `0x${string}` {
  const payload = `deroute-filter:${version}:${fingerprint.toLowerCase()}`;
  const digest = bytesToHex(keccak_256(utf8ToBytes(payload))).toLowerCase();
  return `0x${digest}`;
}

export function arcExplorerTxUrl(txHash: string): string {
  return `${ARC_TESTNET_EXPLORER}/tx/${txHash}`;
}

/**
 * Checks that `txHash` exists and succeeded (`status === "0x1"`) on the public Arc RPC
 * using a read-only `eth_getTransactionReceipt` JSON-RPC call.
 */
export async function checkArcTransactionReceipt(
  txHash: string,
  opts?: {
    rpcUrl?: string;
    fetchImpl?: typeof fetch;
  },
): Promise<{
  exists: boolean;
  succeeded: boolean;
  blockNumber: string | null;
  rawReceipt: Record<string, unknown> | null;
  error?: string;
}> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    return {
      exists: false,
      succeeded: false,
      blockNumber: null,
      rawReceipt: null,
      error: "Invalid transaction hash format",
    };
  }

  const doFetch = opts?.fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") {
    return {
      exists: false,
      succeeded: false,
      blockNumber: null,
      rawReceipt: null,
      error: "fetch is not available",
    };
  }

  const rpcUrl = opts?.rpcUrl ?? ARC_PUBLIC_RPC_URL;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6_000);
  try {
    const res = await doFetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getTransactionReceipt",
        params: [txHash],
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      return {
        exists: false,
        succeeded: false,
        blockNumber: null,
        rawReceipt: null,
        error: `Arc RPC returned HTTP ${res.status}`,
      };
    }

    const json = (await res.json()) as {
      result?: Record<string, unknown> | null;
      error?: { message?: string };
    };

    if (json.error) {
      return {
        exists: false,
        succeeded: false,
        blockNumber: null,
        rawReceipt: null,
        error: json.error.message || "Arc RPC error",
      };
    }

    const receipt = json.result ?? null;
    if (!receipt || typeof receipt !== "object") {
      return {
        exists: false,
        succeeded: false,
        blockNumber: null,
        rawReceipt: null,
      };
    }

    const statusHex =
      typeof receipt.status === "string"
        ? receipt.status.toLowerCase()
        : "0x1";
    const succeeded = statusHex === "0x1" || statusHex === "1";
    const blockNumber =
      typeof receipt.blockNumber === "string" ? receipt.blockNumber : null;

    return {
      exists: true,
      succeeded,
      blockNumber,
      rawReceipt: receipt,
    };
  } catch (e) {
    return {
      exists: false,
      succeeded: false,
      blockNumber: null,
      rawReceipt: null,
      error: (e as Error).message || "Arc RPC request failed",
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Evaluates the local rule-set fingerprint against `published-fingerprint.json`
 * (without network I/O) and returns a synchronous status snapshot.
 */
export function evaluateLocalFilterFingerprint(
  opts?: Pick<VerifyFilterFingerprintOptions, "ruleset" | "published">,
): FilterFingerprintStatus {
  if (testOverrideStatus) {
    return testOverrideStatus;
  }
  const mergedOpts = { ...testOverrideOptions, ...opts };
  const ruleset = mergedOpts.ruleset ?? MECHANICAL_RULESET;
  const published = mergedOpts.published ?? getPublishedFilterFingerprint();
  const computed = rulesetFingerprint(ruleset);
  const version = ruleset.version;
  const anchorReceiptHash = computeFilterAnchorReceiptHash(version, computed);
  const pubFp =
    typeof published.fingerprint === "string" &&
    published.fingerprint.trim().length > 0
      ? published.fingerprint.trim().toLowerCase()
      : null;
  const anchorTx =
    typeof published.anchorTx === "string" &&
    published.anchorTx.trim().length > 0
      ? published.anchorTx.trim()
      : null;
  const anchorUrl = anchorTx ? arcExplorerTxUrl(anchorTx) : null;

  if (!pubFp) {
    return {
      state: "not-published",
      version,
      computedFingerprint: computed,
      publishedFingerprint: null,
      anchorTx,
      anchorUrl,
      anchorReceiptHash,
      arcReceiptVerified: null,
      blockingSend: false,
      plainSummary: `Personal-detail filter v${version}: not yet published`,
      blockReason: null,
    };
  }

  if (
    computed.toLowerCase() !== pubFp ||
    published.version !== version
  ) {
    return {
      state: "mismatch",
      version,
      computedFingerprint: computed,
      publishedFingerprint: pubFp,
      anchorTx,
      anchorUrl,
      anchorReceiptHash,
      arcReceiptVerified: null,
      blockingSend: true,
      plainSummary: `Personal-detail filter v${version}: does not match the published version`,
      blockReason:
        "Sending is blocked because the personal-detail filter running in this browser does not match the published version in the public receipt book.",
    };
  }

  return {
    state: "match",
    version,
    computedFingerprint: computed,
    publishedFingerprint: pubFp,
    anchorTx,
    anchorUrl,
    anchorReceiptHash,
    arcReceiptVerified: null,
    blockingSend: false,
    plainSummary: `Personal-detail filter v${version}: matches the published version`,
    blockReason: null,
  };
}

/**
 * Full browser verification:
 * 1. Recomputes `rulesetFingerprint(ruleset)` locally.
 * 2. Compares against `published-fingerprint.json`.
 * 3. When a published fingerprint and `anchorTx` are present and match, checks
 *    the transaction receipt on Arc via `eth_getTransactionReceipt`.
 */
export async function verifyFilterFingerprint(
  opts?: VerifyFilterFingerprintOptions,
): Promise<FilterFingerprintStatus> {
  if (testOverrideStatus) {
    return testOverrideStatus;
  }
  const mergedOpts = { ...testOverrideOptions, ...opts };
  const local = evaluateLocalFilterFingerprint(mergedOpts);

  if (local.state === "not-published" || local.state === "mismatch") {
    return local;
  }

  if (!local.anchorTx) {
    return {
      ...local,
      state: "receipt-missing",
      arcReceiptVerified: false,
      plainSummary: `Personal-detail filter v${local.version}: matches the published version (public receipt pending)`,
    };
  }

  const receiptCheck = await checkArcTransactionReceipt(local.anchorTx, {
    rpcUrl: mergedOpts.rpcUrl,
    fetchImpl: mergedOpts.fetchImpl,
  });

  if (!receiptCheck.exists || !receiptCheck.succeeded) {
    return {
      ...local,
      state: "receipt-missing",
      arcReceiptVerified: false,
      plainSummary: `Personal-detail filter v${local.version}: matches the published version (public receipt could not be confirmed right now)`,
    };
  }

  return {
    ...local,
    state: "match",
    arcReceiptVerified: true,
    plainSummary: `Personal-detail filter v${local.version}: matches the published version`,
  };
}
