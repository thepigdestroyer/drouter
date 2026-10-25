/**
 * deRoute Downloadable Local Private Proxy (K2)
 *
 * Usage:
 *   node deroute-proxy.mjs [--key drk_...] [--port 4141] [--upstream https://drouter-demo.vercel.app]
 *   DEROUTE_ACCESS_KEY=drk_... node deroute-proxy.mjs
 */

import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { bytesToHex } from "@noble/hashes/utils.js";
import { TinfoilAI, type VerificationDocument } from "tinfoil";
import { decodeAccessKey } from "@/lib/credits/access-key";
import { formatCreditHeader, nullifierFor } from "@/lib/credits/blind";
import {
  CHAT_GATEWAY_MODEL_IDS,
  SUPPORTED_GATEWAY_MODELS,
  TINFOIL_PROXY_WELL_KNOWN_URL,
  fetchLiveGatewayModels,
  isChatCapableGatewayModel,
  type GatewayModelSpec,
} from "@/lib/gateway/harness-config";
import {
  evaluateLocalFilterFingerprint,
  rulesetFingerprint,
  type PublishedFilterFingerprint,
} from "@/lib/privacy/fingerprint";
import {
  createMechanicalSession,
  type MechanicalSession,
} from "@/lib/privacy/mechanical";
import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
} from "@/lib/privacy/mechanical-ruleset";
import { padJsonPayloadToBucket } from "@/lib/relay";
import type { BlindCreditToken, CheckResult } from "@/lib/types";

export const DEFAULT_PORT = 4141;
export const DEFAULT_UPSTREAM = "https://drouter-demo.vercel.app";
export const DEFAULT_MODEL = "kimi-k3";
export const CHAT_MODEL_ALLOWLIST = CHAT_GATEWAY_MODEL_IDS;
export const MAX_REQUEST_BODY_BYTES = 262_144;

export function defaultSpentFilePath(): string {
  return (
    process.env.DEROUTE_SPENT_PATH ||
    path.join(os.homedir(), ".config", "deroute", "spent.json")
  );
}

// ============================================================================
// 1. Startup Filter Fingerprint Verification
// ============================================================================

export interface StartupFingerprintCheckResult {
  version: string;
  fingerprint: `0x${string}`;
  publishedVersion: string;
  publishedFingerprint: string;
}

export function verifyProxyFilterFingerprint(opts?: {
  ruleset?: MechanicalRuleset;
  published?: PublishedFilterFingerprint;
  expectedFingerprint?: string;
}): StartupFingerprintCheckResult {
  const ruleset = opts?.ruleset ?? MECHANICAL_RULESET;
  const computed = rulesetFingerprint(ruleset);
  const status = evaluateLocalFilterFingerprint({
    ...(opts?.ruleset !== undefined ? { ruleset: opts.ruleset } : {}),
    ...(opts?.published !== undefined ? { published: opts.published } : {}),
  });

  if (opts?.expectedFingerprint) {
    const cleanExpected = opts.expectedFingerprint.trim().toLowerCase();
    if (computed.toLowerCase() !== cleanExpected) {
      throw new Error(
        `Refusing to start: local filter fingerprint (${computed}) differs from expected fingerprint (${cleanExpected}).`,
      );
    }
  }

  if (status.state !== "match" || !status.publishedFingerprint) {
    throw new Error(
      `Refusing to start: local personal-detail filter (v${status.version}, fingerprint ${status.computedFingerprint}) differs from published filter (fingerprint ${status.publishedFingerprint ?? "unpublished"}).`,
    );
  }

  return {
    version: status.version,
    fingerprint: computed,
    publishedVersion: status.version,
    publishedFingerprint: status.publishedFingerprint,
  };
}

// ============================================================================
// 2. Spent Nullifier Store & Access Key Token Rotation (~/.config/deroute/spent.json)
// ============================================================================

export interface SpentTokenResult {
  creditHeader: string | null;
  nullifier: string | null;
  denomination: number | null;
  remaining: number;
  usedFreeTier: boolean;
}

export class SpentNullifierStore {
  readonly filePath: string;
  private readonly spent = new Set<string>();
  private readonly tokens: BlindCreditToken[];

  constructor(opts?: {
    filePath?: string;
    accessKey?: string | null;
    expectedOrigin?: string;
  }) {
    this.filePath = path.resolve(opts?.filePath ?? defaultSpentFilePath());
    this.loadFromDisk();

    const rawKey = opts?.accessKey ? opts.accessKey.trim() : "";
    if (rawKey) {
      const decoded = opts?.expectedOrigin
        ? decodeAccessKey(rawKey, opts.expectedOrigin)
        : decodeAccessKey(rawKey);
      if (!decoded.ok) {
        throw new Error(`Invalid access key: ${decoded.error}`);
      }
      this.tokens = decoded.tokens;
    } else {
      this.tokens = [];
    }

    this.persistToDisk();
  }

  private loadFromDisk(): void {
    if (!fs.existsSync(this.filePath)) {
      return;
    }
    try {
      const raw = fs.readFileSync(this.filePath, "utf8").trim();
      if (!raw) return;
      const parsed = JSON.parse(raw) as unknown;
      let list: unknown[] = [];
      if (Array.isArray(parsed)) {
        list = parsed;
      } else if (parsed && typeof parsed === "object") {
        const obj = parsed as Record<string, unknown>;
        if (Array.isArray(obj.spentNullifiers)) {
          list = obj.spentNullifiers;
        } else if (Array.isArray(obj.nullifiers)) {
          list = obj.nullifiers;
        }
      }
      for (const item of list) {
        if (typeof item === "string" && /^[0-9a-fA-F]{64}$/.test(item.trim())) {
          this.spent.add(item.trim().toLowerCase());
        }
      }
    } catch {
      // If corrupted, preserve existing in-memory set and overwrite on next save
    }
  }

  private persistToDisk(): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const payload = JSON.stringify(
      {
        version: 1,
        spentNullifiers: [...this.spent],
      },
      null,
      2,
    );
    const tmpPath = `${this.filePath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, `${payload}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      fs.chmodSync(tmpPath, 0o600);
    } catch {
      // Ignore chmod errors on platforms without POSIX permissions
    }
    fs.renameSync(tmpPath, this.filePath);
    try {
      fs.chmodSync(this.filePath, 0o600);
    } catch {
      // Ignore chmod errors on platforms without POSIX permissions
    }
  }

  hasKey(): boolean {
    return this.tokens.length > 0;
  }

  remainingCount(): number {
    this.loadFromDisk();
    let count = 0;
    for (const token of this.tokens) {
      const nullifier = nullifierFor(token.token).toLowerCase();
      if (!this.spent.has(nullifier)) {
        count += 1;
      }
    }
    return count;
  }

  spendNextToken(): SpentTokenResult {
    this.loadFromDisk();

    for (const token of this.tokens) {
      const nullifier = nullifierFor(token.token).toLowerCase();
      if (!this.spent.has(nullifier)) {
        this.spent.add(nullifier);
        this.persistToDisk();
        const remaining = this.tokens.filter(
          (t) => !this.spent.has(nullifierFor(t.token).toLowerCase()),
        ).length;
        return {
          creditHeader: formatCreditHeader(token),
          nullifier,
          denomination: token.denomination,
          remaining,
          usedFreeTier: false,
        };
      }
    }

    return {
      creditHeader: null,
      nullifier: null,
      denomination: null,
      remaining: 0,
      usedFreeTier: true,
    };
  }

  spentNullifiers(): string[] {
    this.loadFromDisk();
    return [...this.spent];
  }
}

// ============================================================================
// 3. Session-Stable Mechanical Redaction & Stream-Safe Restoration
// ============================================================================

export interface ProxyChatMessage {
  role: string;
  content?: unknown;
  [key: string]: unknown;
}

export function redactConversationMessages(
  messages: readonly ProxyChatMessage[],
  session: MechanicalSession,
): {
  messages: ProxyChatMessage[];
  redactionsCount: number;
} {
  let redactionsCount = 0;

  const redactString = (text: string): string => {
    const res = session.redact(text);
    redactionsCount += res.redactions.length;
    return res.text;
  };

  const out = messages.map((msg) => {
    if (!msg || typeof msg !== "object") return msg;
    const role = typeof msg.role === "string" ? msg.role.toLowerCase() : "";
    const shouldRedact =
      role === "user" || role === "assistant" || role === "tool";
    if (!shouldRedact) {
      return { ...msg };
    }

    const nextMsg: ProxyChatMessage = { ...msg };

    if (typeof msg.content === "string") {
      nextMsg.content = redactString(msg.content);
    } else if (Array.isArray(msg.content)) {
      nextMsg.content = msg.content.map((part) => {
        if (typeof part === "string") {
          return redactString(part);
        }
        if (part && typeof part === "object") {
          const partObj = part as Record<string, unknown>;
          const nextPart: Record<string, unknown> = { ...partObj };
          if (typeof partObj.text === "string") {
            nextPart.text = redactString(partObj.text);
          }
          if (typeof partObj.content === "string") {
            nextPart.content = redactString(partObj.content);
          }
          if (typeof partObj.input_text === "string") {
            nextPart.input_text = redactString(partObj.input_text);
          }
          return nextPart;
        }
        return part;
      });
    }

    if (role === "assistant" && Array.isArray(msg.tool_calls)) {
      nextMsg.tool_calls = msg.tool_calls.map((tc) => {
        if (!tc || typeof tc !== "object") return tc;
        const tcObj = tc as Record<string, unknown>;
        const fnObj =
          tcObj.function && typeof tcObj.function === "object"
            ? (tcObj.function as Record<string, unknown>)
            : null;
        if (fnObj && typeof fnObj.arguments === "string") {
          return {
            ...tcObj,
            function: {
              ...fnObj,
              arguments: redactString(fnObj.arguments),
            },
          };
        }
        return { ...tcObj };
      });
    }

    return nextMsg;
  });

  return { messages: out, redactionsCount };
}

export interface StreamRestorer {
  push(chunk: string): string;
  flush(): string;
}

/**
 * Restores mechanical filter placeholders (`[KIND_N]`) across arbitrary SSE chunk boundaries.
 * Holds back any trailing unclosed `[` prefix that could be part of a placeholder until the
 * closing `]` arrives or the stream ends.
 */
export function createMechanicalStreamRestorer(
  session: Pick<MechanicalSession, "restore"> | null | undefined,
): StreamRestorer {
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

// ============================================================================
// 4. Seven Seal Checks (C1-C7) & Attested Tinfoil Session via deRoute Relay
// ============================================================================

export interface EnclaveMatrixModelEntry {
  repo?: string;
  tag?: string;
  status?: string;
  healthyHosts?: number;
  configuredHosts?: number;
  verifiedHosts?: number;
  measurement?: string;
  measurementRegisters?: string[];
  dmVerityRootHash?: string;
  weightRepoCommit?: string;
  weightMpkHash?: string;
  vmShape?: {
    gpus?: number;
    cpus?: number;
    memoryMb?: number;
  };
}

export interface EnclaveMatrixPayload {
  routerHost?: string;
  routerConfigRepo?: string;
  routerReleaseDigest?: string;
  routerSnpChain?: {
    verified?: boolean;
    error?: string;
  };
  models?: Record<string, EnclaveMatrixModelEntry>;
}

export interface ProxyWellKnownTable {
  models?: Record<
    string,
    {
      repo?: string;
      tag?: string;
      measurement?: {
        type?: string;
        registers?: string[];
      };
      verification?: {
        configured?: number;
        verified?: number;
        healthy?: number;
      };
    }
  >;
}

export interface RegistryPayload {
  source?: string;
  address?: string;
  minStake?: string;
  nodes?: Array<{
    kind?: string;
    status?: string;
    stake?: string | number;
  }>;
}

export function evaluateSevenSealChecks(params: {
  doc: Partial<VerificationDocument> & {
    securityVerified?: boolean;
    checks?: CheckResult[];
    snpChainVerification?: { verified?: boolean; error?: string };
  };
  matrix?: EnclaveMatrixPayload | null;
  proxyTable?: ProxyWellKnownTable | null;
  registry?: RegistryPayload | null;
  model?: string;
}): CheckResult[] {
  const { doc, matrix, proxyTable, registry, model = DEFAULT_MODEL } = params;

  if (Array.isArray(doc?.checks) && doc.checks.length > 0) {
    return doc.checks;
  }

  const steps = (doc?.steps ?? {}) as Record<
    string,
    { status?: string; error?: string } | undefined
  >;
  const hasStepsObject = Boolean(doc?.steps && Object.keys(steps).length > 0);

  const stepToStatus = (
    step: { status?: string; error?: string } | undefined,
  ): "pass" | "fail" => {
    if (!hasStepsObject || !step) return "fail";
    return step.status === "success" ? "pass" : "fail";
  };

  const snpChain = doc?.snpChainVerification ?? matrix?.routerSnpChain;
  const c1Status: "pass" | "fail" =
    snpChain && snpChain.verified === false
      ? "fail"
      : stepToStatus(steps.verifyEnclave);

  const c2Status: "pass" | "fail" =
    steps.fetchDigest && steps.fetchDigest.status === "failed"
      ? "fail"
      : stepToStatus(steps.verifyCode);

  const c3Status: "pass" | "fail" = stepToStatus(steps.verifyCertificate);
  const c4Status: "pass" | "fail" = stepToStatus(steps.compareMeasurements);

  // Resolve model enclave record for C5 and C7 (never fall back to another model's record)
  const mAtt = matrix?.models?.[model];
  const pMod = proxyTable?.models?.[model];

  let c5Status: "pass" | "fail" = "fail";
  let c5Detail = `Model ${model} not found in enclave attestation matrix`;
  let c7Status: "pass" | "fail" = "fail";
  let c7Detail = `Model ${model} manifest not found in enclave attestation matrix`;

  if (mAtt) {
    const healthy = mAtt.healthyHosts ?? 0;
    const configured = mAtt.configuredHosts ?? 1;
    const available = mAtt.status !== "unavailable" && healthy > 0;
    c5Status = available ? "pass" : "fail";
    c5Detail = available
      ? `${mAtt.vmShape?.gpus ?? 1} confidential GPUs (${healthy}/${configured} hosts healthy)`
      : `Model ${model} has no healthy confidential GPU hosts (${healthy}/${configured})`;

    const rootOrReg =
      mAtt.dmVerityRootHash ||
      mAtt.measurementRegisters?.[0] ||
      mAtt.measurement ||
      "";
    const hasPin = Boolean(mAtt.repo && rootOrReg);
    c7Status = available && hasPin ? "pass" : "fail";
    c7Detail = hasPin
      ? `Pinned ${mAtt.weightRepoCommit ?? mAtt.repo} on dm-verity root ${String(rootOrReg).slice(0, 16)}...`
      : `Missing pinned model measurement or dm-verity root for ${model}`;
  } else if (pMod) {
    const healthy = pMod.verification?.healthy ?? 0;
    const configured = pMod.verification?.configured ?? 1;
    const reg0 = pMod.measurement?.registers?.[0] ?? "";
    c5Status = healthy > 0 ? "pass" : "fail";
    c5Detail =
      healthy > 0
        ? `Confidential GPU pool healthy (${healthy}/${configured} hosts)`
        : `No healthy confidential GPU hosts for ${model}`;
    c7Status = healthy > 0 && Boolean(pMod.repo && reg0) ? "pass" : "fail";
    c7Detail =
      pMod.repo && reg0
        ? `Pinned ${pMod.repo}@${pMod.tag ?? "latest"} (${reg0.slice(0, 16)}...)`
        : `Missing measurement register for ${model}`;
  } else {
    c5Status = "fail";
    c5Detail = `Model ${model} not found in enclave attestation matrix`;
    c7Status = "fail";
    c7Detail = `Model ${model} manifest not found in enclave attestation matrix`;
  }

  let c6Status: "pass" | "fail" = "fail";
  let c6Detail = "Registry verification unavailable or failed";
  if (registry && Array.isArray(registry.nodes)) {
    const node = registry.nodes.find((n) => n.kind === "tinfoil");
    if (!node) {
      c6Status = "fail";
      c6Detail = "Tinfoil router is not present in registry";
    } else if (registry.source === "arc") {
      const ok = node.status === "active" && Number(node.stake) > 0;
      c6Status = ok ? "pass" : "fail";
      c6Detail = ok
        ? `Active on Arc registry with ${node.stake} USDC stake`
        : `Inactive or unstaked on Arc registry (status=${String(node.status)}, stake=${String(node.stake)})`;
    } else {
      const ok = node.status === "active";
      c6Status = ok ? "pass" : "fail";
      c6Detail = ok
        ? "Active in fallback node list"
        : `Node status is ${String(node.status)}`;
    }
  }

  return [
    {
      id: "C1",
      label: "Hardware signature chain",
      status: c1Status,
      detail:
        c1Status === "pass"
          ? `AMD SEV-SNP report verified (${doc?.enclaveMeasurement?.measurement?.type ?? "sev-snp"})`
          : steps.verifyEnclave?.error ||
            snpChain?.error ||
            "Hardware signature chain verification failed",
    },
    {
      id: "C2",
      label: "Approved software",
      status: c2Status,
      detail:
        c2Status === "pass"
          ? `Signed release ${doc?.releaseTag ?? doc?.releaseDigest?.slice(0, 12) ?? "verified"} in Sigstore Rekor`
          : steps.verifyCode?.error ||
            steps.fetchDigest?.error ||
            "Software release verification failed",
    },
    {
      id: "C3",
      label: "HPKE key bound to enclave report",
      status: c3Status,
      detail:
        c3Status === "pass"
          ? "HPKE public key committed in attestation report; request encrypted to enclave"
          : steps.verifyCertificate?.error || "HPKE certificate binding failed",
    },
    {
      id: "C4",
      label: "Running code = released code",
      status: c4Status,
      detail:
        c4Status === "pass"
          ? "Launch measurement matches signed release predicate"
          : steps.compareMeasurements?.error ||
            "Launch measurement does not match signed release",
    },
    {
      id: "C5",
      label: "Router-attested confidential GPU pool",
      status: c5Status,
      detail: c5Detail,
    },
    {
      id: "C6",
      label: "Registry admission",
      status: c6Status,
      detail: c6Detail,
    },
    {
      id: "C7",
      label: "Manifest-pinned model & dm-verity root",
      status: c7Status,
      detail: c7Detail,
    },
  ];
}

export function assertSevenSealChecksPass(
  doc: Partial<VerificationDocument> & {
    securityVerified?: boolean;
    checks?: CheckResult[];
  },
  checks: readonly CheckResult[],
): void {
  if (!doc || doc.securityVerified !== true) {
    const failedCheck = checks.find((c) => c.status === "fail");
    if (failedCheck) {
      throw new Error(
        `Seal check ${failedCheck.id} (${failedCheck.label}) failed: ${failedCheck.detail}`,
      );
    }
    throw new Error(
      "Enclave attestation verification failed: securityVerified is not true",
    );
  }

  if (checks.length < 7) {
    throw new Error(
      `Enclave attestation verification incomplete: expected 7 checks (C1-C7), got ${checks.length}`,
    );
  }

  const failed = checks.find((c) => c.status === "fail");
  if (failed) {
    throw new Error(
      `Seal check ${failed.id} (${failed.label}) failed: ${failed.detail}`,
    );
  }
}

const httpRelayRewriteMap = new Map<string, string>();
const transportPaddedClients = new WeakSet<object>();
let fetchInterceptorInstalled = false;

function ensureHttpRelayInterceptor(): void {
  if (fetchInterceptorInstalled) return;
  fetchInterceptorInstalled = true;
  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const urlStr =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    for (const [virtualOrigin, realUpstream] of httpRelayRewriteMap.entries()) {
      if (urlStr.startsWith(virtualOrigin)) {
        const rewritten = `${realUpstream}${urlStr.slice(virtualOrigin.length)}`;
        return origFetch(rewritten, init);
      }
    }
    return origFetch(input, init);
  };
}

function attachBucketPaddingToReadyClient(client: unknown): void {
  if (!client || typeof client !== "object") return;
  if (transportPaddedClients.has(client)) return;
  const internalTransport = (
    client as {
      secureClient?: {
        _transport?: {
          fetch?: (
            input: RequestInfo | URL,
            init?: RequestInit,
          ) => Promise<Response>;
        };
      };
    }
  ).secureClient?._transport;
  if (!internalTransport || typeof internalTransport.fetch !== "function") {
    return;
  }
  transportPaddedClients.add(client);
  const origFetch = internalTransport.fetch.bind(internalTransport);
  internalTransport.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    let nextInit = init;
    if (nextInit && typeof nextInit.body === "string") {
      try {
        const parsed = JSON.parse(nextInit.body) as Record<string, unknown>;
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const { paddedJson } = padJsonPayloadToBucket(JSON.stringify(parsed));
          nextInit = { ...nextInit, body: paddedJson };
        }
      } catch {
        // Leave non-JSON body unchanged
      }
    }
    return origFetch(input, nextInit);
  };
}

export function createAttestedRelayClient(upstream = DEFAULT_UPSTREAM): TinfoilAI {
  const cleanUpstream = upstream.replace(/\/+$/, "");
  let attestationBundleURL = `${cleanUpstream}/api/relay`;

  if (cleanUpstream.startsWith("http://")) {
    ensureHttpRelayInterceptor();
    const u = new URL(cleanUpstream);
    const virtualOrigin = `https://local-relay-${u.hostname.replace(/[^a-zA-Z0-9-]/g, "-")}-${u.port || "80"}.drouter.internal`;
    httpRelayRewriteMap.set(virtualOrigin, cleanUpstream);
    attestationBundleURL = `${virtualOrigin}/api/relay`;
  }

  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const userCacheSecret = bytesToHex(secretBytes);

  return new TinfoilAI({
    bearerToken: "drouter-anonymous",
    baseURL: `${cleanUpstream}/api/relay/v1/`,
    attestationBundleURL,
    userCacheSecret,
  });
}

// ============================================================================
// 5. Chat Model Allowlist Intersection for GET /v1/models
// ============================================================================

export async function fetchAllowedChatModels(opts?: {
  fetchImpl?: typeof fetch;
  forceRefresh?: boolean;
}): Promise<GatewayModelSpec[]> {
  const liveModels = await fetchLiveGatewayModels({
    fetchImpl: opts?.fetchImpl,
    forceRefresh: opts?.forceRefresh ?? Boolean(opts?.fetchImpl),
  });

  const intersected = liveModels.filter((m) => isChatCapableGatewayModel(m.id));
  if (intersected.length > 0) {
    return intersected;
  }

  return SUPPORTED_GATEWAY_MODELS.filter((m) => isChatCapableGatewayModel(m.id));
}

// ============================================================================
// 6. Localhost Security & HTTP Server
// ============================================================================

export function isLoopbackAddress(address: string | undefined | null): boolean {
  if (!address) return false;
  const clean = address.trim().toLowerCase();
  if (!clean) return false;
  return (
    clean === "127.0.0.1" ||
    clean === "::1" ||
    clean === "::ffff:127.0.0.1" ||
    clean === "localhost"
  );
}

export function isLocalhostHostHeader(host: string | undefined): boolean {
  if (!host) return false;
  const clean = host.trim().toLowerCase();
  if (!clean) return false;
  return /^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(clean);
}

export function isAllowedLocalOrigin(origin: string | undefined): boolean {
  return !origin;
}

function readBoundedJsonBody(
  req: http.IncomingMessage,
  maxBytes = MAX_REQUEST_BODY_BYTES,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let aborted = false;

    req.on("data", (chunk: Buffer | string) => {
      if (aborted) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.byteLength;
      if (totalBytes > maxBytes) {
        aborted = true;
        reject(new Error("Request body exceeds maximum size limit"));
        return;
      }
      chunks.push(buf);
    });

    req.on("end", () => {
      if (aborted) return;
      try {
        const raw = Buffer.concat(chunks).toString("utf8").trim();
        if (!raw) {
          resolve({});
          return;
        }
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          reject(new Error("Request body must be a JSON object"));
          return;
        }
        resolve(parsed as Record<string, unknown>);
      } catch {
        reject(new Error("Invalid JSON request body"));
      }
    });

    req.on("error", () => {
      if (!aborted) {
        aborted = true;
        reject(new Error("Failed to read request stream"));
      }
    });
  });
}

function sendJsonResponse(
  res: http.ServerResponse,
  statusCode: number,
  payload: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": String(Buffer.byteLength(body)),
    ...extraHeaders,
  });
  res.end(body);
}

function sanitizeErrorText(rawMessage: string): string {
  // Never leak drk_ keys or long hex tokens in error strings
  return rawMessage
    .replace(/\bdrk_[A-Za-z0-9_-]+/g, "[REDACTED_KEY]")
    .replace(/\b[0-9a-fA-F]{64,}\b/g, "[REDACTED_HEX]");
}

export interface DerouteProxyClientLike {
  ready(): Promise<void>;
  getVerificationDocument(): Promise<
    Partial<VerificationDocument> & {
      securityVerified?: boolean;
      checks?: CheckResult[];
    }
  >;
  chat: {
    completions: {
      create(
        body: Record<string, unknown>,
        options?: { headers?: Record<string, string> },
      ): Promise<unknown>;
    };
  };
}

export interface CreateDerouteProxyOptions {
  upstream?: string;
  accessKey?: string | null;
  spentFilePath?: string;
  ruleset?: MechanicalRuleset;
  published?: PublishedFilterFingerprint;
  expectedFingerprint?: string;
  clientFactory?: (upstream: string) => DerouteProxyClientLike;
  fetchImpl?: typeof fetch;
  stderr?: (line: string) => void;
  stdout?: (line: string) => void;
}

export interface DerouteProxyServerHandle {
  server: http.Server;
  session: MechanicalSession;
  spentStore: SpentNullifierStore;
  filterInfo: StartupFingerprintCheckResult;
}

export function createDerouteProxyServer(
  opts?: CreateDerouteProxyOptions,
): DerouteProxyServerHandle {
  const filterInfo = verifyProxyFilterFingerprint({
    ruleset: opts?.ruleset,
    published: opts?.published,
    expectedFingerprint: opts?.expectedFingerprint,
  });

  const rawKey =
    opts?.accessKey !== undefined
      ? opts.accessKey
      : process.env.DEROUTE_ACCESS_KEY ?? null;

  const spentStore = new SpentNullifierStore({
    filePath: opts?.spentFilePath,
    accessKey: rawKey,
  });

  const ruleset = opts?.ruleset ?? MECHANICAL_RULESET;
  const session = createMechanicalSession([], ruleset);
  const normalizedUpstream = (opts?.upstream || DEFAULT_UPSTREAM).replace(
    /\/+$/,
    "",
  );
  const doFetch = opts?.fetchImpl ?? globalThis.fetch;
  const writeStderr =
    opts?.stderr ?? ((line: string) => process.stderr.write(`${line}\n`));

  const createClient: (upstream: string) => DerouteProxyClientLike =
    opts?.clientFactory ??
    ((u: string) =>
      createAttestedRelayClient(u) as unknown as DerouteProxyClientLike);

  async function openVerifiedEnclaveSession(model: string): Promise<{
    client: DerouteProxyClientLike;
    doc: Partial<VerificationDocument> & {
      securityVerified?: boolean;
      checks?: CheckResult[];
    };
    checks: CheckResult[];
  }> {
    const client = createClient(normalizedUpstream);
    await client.ready();
    attachBucketPaddingToReadyClient(client);
    const doc = await client.getVerificationDocument();

    let matrix: EnclaveMatrixPayload | null = null;
    let proxyTable: ProxyWellKnownTable | null = null;
    let registry: RegistryPayload | null = null;

    if (!Array.isArray(doc?.checks) && opts?.fetchImpl !== undefined) {
      const [mRes, pRes, rRes] = await Promise.all([
        doFetch(`${normalizedUpstream}/api/relay/enclave-matrix`)
          .then((r) => (r.ok ? (r.json() as Promise<EnclaveMatrixPayload>) : null))
          .catch(() => null),
        doFetch(TINFOIL_PROXY_WELL_KNOWN_URL)
          .then((r) => (r.ok ? (r.json() as Promise<ProxyWellKnownTable>) : null))
          .catch(() => null),
        doFetch(`${normalizedUpstream}/api/registry`)
          .then((r) => (r.ok ? (r.json() as Promise<RegistryPayload>) : null))
          .catch(() => null),
      ]);
      matrix = mRes;
      proxyTable = pRes;
      registry = rRes;
    } else if (!Array.isArray(doc?.checks) && !opts?.clientFactory) {
      const [mRes, pRes, rRes] = await Promise.all([
        doFetch(`${normalizedUpstream}/api/relay/enclave-matrix`)
          .then((r) => (r.ok ? (r.json() as Promise<EnclaveMatrixPayload>) : null))
          .catch(() => null),
        doFetch(TINFOIL_PROXY_WELL_KNOWN_URL)
          .then((r) => (r.ok ? (r.json() as Promise<ProxyWellKnownTable>) : null))
          .catch(() => null),
        doFetch(`${normalizedUpstream}/api/registry`)
          .then((r) => (r.ok ? (r.json() as Promise<RegistryPayload>) : null))
          .catch(() => null),
      ]);
      matrix = mRes;
      proxyTable = pRes;
      registry = rRes;
    }

    const checks = evaluateSevenSealChecks({
      doc,
      matrix,
      proxyTable,
      registry,
      model,
    });
    assertSevenSealChecksPass(doc, checks);

    return { client, doc, checks };
  }

  const server = http.createServer(async (req, res) => {
    const remoteAddress = req.socket?.remoteAddress;
    if (!isLoopbackAddress(remoteAddress)) {
      sendJsonResponse(res, 403, {
        error: {
          message: "Connections are only accepted from localhost (127.0.0.1).",
          type: "forbidden",
        },
      });
      return;
    }

    if (!isLocalhostHostHeader(req.headers.host)) {
      sendJsonResponse(res, 403, {
        error: {
          message: "Invalid Host header: only localhost is permitted.",
          type: "forbidden",
        },
      });
      return;
    }

    const originHeader =
      typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    const secFetchSiteHeader = req.headers["sec-fetch-site"];
    const secFetchSite =
      typeof secFetchSiteHeader === "string"
        ? secFetchSiteHeader.trim().toLowerCase()
        : Array.isArray(secFetchSiteHeader)
          ? String(secFetchSiteHeader[0] ?? "").trim().toLowerCase()
          : undefined;
    if (
      !isAllowedLocalOrigin(originHeader) ||
      (secFetchSite !== undefined && secFetchSite !== "none")
    ) {
      sendJsonResponse(res, 403, {
        error: {
          message: "Cross-origin requests from browser origins are forbidden.",
          type: "forbidden",
        },
      });
      return;
    }

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "GET" && url.pathname === "/health") {
      sendJsonResponse(res, 200, {
        ok: true,
        service: "deroute-proxy",
        upstream: normalizedUpstream,
        filterVersion: filterInfo.version,
        filterFingerprint: filterInfo.fingerprint,
        creditsRemaining: spentStore.remainingCount(),
      });
      return;
    }

    if (
      req.method === "GET" &&
      (url.pathname === "/v1/models" || url.pathname === "/api/v1/models")
    ) {
      const models = await fetchAllowedChatModels({
        fetchImpl: opts?.fetchImpl,
      });
      sendJsonResponse(res, 200, {
        object: "list",
        data: models.map((m) => ({
          id: m.id,
          object: "model",
          created: m.created ?? 1792800000,
          owned_by: m.provider,
          enclave_attested: m.enclave_attested,
          ...(m.repo ? { repo: m.repo } : {}),
          ...(m.tag ? { tag: m.tag } : {}),
          ...(m.predicate ? { predicate: m.predicate } : {}),
          ...(m.healthy_hosts !== undefined
            ? { healthy_hosts: m.healthy_hosts }
            : {}),
          ...(m.configured_hosts !== undefined
            ? { configured_hosts: m.configured_hosts }
            : {}),
          ...(m.verified_hosts !== undefined
            ? { verified_hosts: m.verified_hosts }
            : {}),
        })),
      });
      return;
    }

    if (
      req.method === "POST" &&
      (url.pathname === "/v1/chat/completions" ||
        url.pathname === "/api/v1/chat/completions")
    ) {
      const contentType = (req.headers["content-type"] ?? "").toLowerCase();
      if (!contentType.includes("application/json")) {
        sendJsonResponse(res, 415, {
          error: {
            message: "POST /v1/chat/completions requires Content-Type: application/json",
            type: "invalid_request_error",
          },
        });
        return;
      }

      let body: Record<string, unknown>;
      try {
        body = await readBoundedJsonBody(req);
      } catch (err) {
        sendJsonResponse(res, 400, {
          error: {
            message:
              err instanceof Error
                ? sanitizeErrorText(err.message)
                : "Invalid JSON request body",
            type: "invalid_request_error",
          },
        });
        return;
      }

      if (!Array.isArray(body.messages) || body.messages.length === 0) {
        sendJsonResponse(res, 400, {
          error: {
            message: "Request body must include a non-empty messages array",
            type: "invalid_request_error",
          },
        });
        return;
      }

      const rawModel =
        typeof body.model === "string" && body.model.trim()
          ? body.model.trim()
          : DEFAULT_MODEL;
      const model = rawModel.replace(/^(?:deroute|drouter|openai)\//i, "");

      if (!isChatCapableGatewayModel(model)) {
        sendJsonResponse(res, 400, {
          error: {
            message: `Unsupported chat model "${model}". Allowed chat models: ${CHAT_MODEL_ALLOWLIST.join(", ")}`,
            type: "invalid_request_error",
          },
        });
        return;
      }

      let verifiedSession;
      try {
        verifiedSession = await openVerifiedEnclaveSession(model);
      } catch (err) {
        const msg =
          err instanceof Error ? sanitizeErrorText(err.message) : String(err);
        writeStderr(`[deroute-proxy] Refusing request: ${msg}`);
        sendJsonResponse(res, 502, {
          error: {
            message: `Enclave seal verification failed: ${msg}`,
            type: "attestation_error",
          },
        });
        return;
      }

      const { messages: redactedMessages, redactionsCount } =
        redactConversationMessages(
          body.messages as ProxyChatMessage[],
          session,
        );

      const tokenSpend = spentStore.spendNextToken();
      if (tokenSpend.usedFreeTier) {
        writeStderr(
          "[deroute-proxy] Access key credits exhausted (0 remaining); falling back to free tier.",
        );
      }

      const upstreamHeaders: Record<string, string> = {
        "X-Tinfoil-Model": model,
        ...(tokenSpend.creditHeader
          ? { "x-drouter-credit": tokenSpend.creditHeader }
          : {}),
      };

      const responseHeaders: Record<string, string> = {
        "X-DRouter-Attested": "true",
        "X-DRouter-Filter-Version": filterInfo.version,
        "X-DRouter-Filter-Fingerprint": filterInfo.fingerprint,
        "X-DRouter-Redactions": String(redactionsCount),
        "X-DRouter-Credits-Remaining": String(tokenSpend.remaining),
        ...(verifiedSession.doc?.enclaveHost
          ? { "X-DRouter-Enclave-Host": String(verifiedSession.doc.enclaveHost) }
          : {}),
      };

      try {
        if (body.stream) {
          const stream = (await verifiedSession.client.chat.completions.create(
            {
              ...body,
              model,
              messages: redactedMessages,
              stream: true,
            },
            { headers: upstreamHeaders },
          )) as AsyncIterable<Record<string, unknown>>;

          res.writeHead(200, {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
            ...responseHeaders,
          });

          const restorer = createMechanicalStreamRestorer(session);
          let lastChunkTemplate: Record<string, unknown> | null = null;

          for await (const chunk of stream) {
            lastChunkTemplate = chunk;
            const choices = Array.isArray(chunk?.choices)
              ? (chunk.choices as Array<{
                  delta?: { content?: string };
                  [key: string]: unknown;
                }>)
              : [];
            const delta = choices[0]?.delta?.content ?? "";
            if (!delta) {
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              continue;
            }
            const restoredDelta = restorer.push(delta);
            if (restoredDelta) {
              const outChunk = structuredClone(chunk) as {
                choices: Array<{ delta: { content: string } }>;
              };
              outChunk.choices[0].delta.content = restoredDelta;
              res.write(`data: ${JSON.stringify(outChunk)}\n\n`);
            }
          }

          const tail = restorer.flush();
          if (tail) {
            const flushChunk = lastChunkTemplate
              ? (structuredClone(lastChunkTemplate) as {
                  choices?: Array<{ delta?: { content?: string } }>;
                })
              : {
                  id: "chatcmpl-deroute-flush",
                  object: "chat.completion.chunk",
                  choices: [{ index: 0, delta: { content: tail } }],
                };
            if (flushChunk.choices?.[0]?.delta) {
              flushChunk.choices[0].delta.content = tail;
            } else {
              flushChunk.choices = [{ delta: { content: tail } }];
            }
            res.write(`data: ${JSON.stringify(flushChunk)}\n\n`);
          }

          res.write("data: [DONE]\n\n");
          res.end();
          return;
        }

        const completion = (await verifiedSession.client.chat.completions.create(
          {
            ...body,
            model,
            messages: redactedMessages,
            stream: false,
          },
          { headers: upstreamHeaders },
        )) as Record<string, unknown>;

        const rawChoices = Array.isArray(completion?.choices)
          ? (completion.choices as Array<{
              message?: { content?: unknown; [key: string]: unknown };
              [key: string]: unknown;
            }>)
          : [];

        const restoredChoices = rawChoices.map((choice) => {
          if (!choice?.message || typeof choice.message !== "object") {
            return choice;
          }
          const nextMessage: Record<string, unknown> = { ...choice.message };
          if (typeof choice.message.content === "string") {
            nextMessage.content = session.restore(choice.message.content);
          }
          if (Array.isArray(choice.message.tool_calls)) {
            nextMessage.tool_calls = choice.message.tool_calls.map((tc) => {
              if (!tc || typeof tc !== "object") return tc;
              const tcObj = tc as Record<string, unknown>;
              const fnObj =
                tcObj.function && typeof tcObj.function === "object"
                  ? (tcObj.function as Record<string, unknown>)
                  : null;
              if (fnObj && typeof fnObj.arguments === "string") {
                return {
                  ...tcObj,
                  function: {
                    ...fnObj,
                    arguments: session.restore(fnObj.arguments),
                  },
                };
              }
              return { ...tcObj };
            });
          }
          return {
            ...choice,
            message: nextMessage,
          };
        });

        sendJsonResponse(
          res,
          200,
          {
            ...completion,
            choices: restoredChoices,
          },
          responseHeaders,
        );
      } catch (err) {
        const msg =
          err instanceof Error
            ? sanitizeErrorText(err.message)
            : "Upstream enclave request failed";
        sendJsonResponse(
          res,
          502,
          {
            error: {
              message: `Upstream enclave request failed: ${msg}`,
              type: "upstream_error",
            },
          },
          responseHeaders,
        );
      }
      return;
    }

    sendJsonResponse(res, 404, {
      error: {
        message: `Not found: ${req.method} ${url.pathname}`,
        type: "not_found_error",
      },
    });
  });

  return {
    server,
    session,
    spentStore,
    filterInfo,
  };
}

// ============================================================================
// 7. CLI Argument Parser & Entrypoint
// ============================================================================

export interface ParsedProxyCliArgs {
  port: number;
  host: string;
  upstream: string;
  accessKey: string | null;
  spentFilePath: string;
  expectedFingerprint?: string;
  help: boolean;
}

export function parseProxyCliArgs(
  argv: readonly string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
): ParsedProxyCliArgs {
  let port = Number(env.DEROUTE_PROXY_PORT || env.DROUTER_PROXY_PORT || DEFAULT_PORT);
  let host = "127.0.0.1";
  let upstream = env.DEROUTE_UPSTREAM || env.DROUTER_UPSTREAM || DEFAULT_UPSTREAM;
  let accessKey: string | null = env.DEROUTE_ACCESS_KEY || null;
  let spentFilePath = env.DEROUTE_SPENT_PATH || defaultSpentFilePath();
  let expectedFingerprint = env.DEROUTE_EXPECTED_FINGERPRINT || undefined;
  let help = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--port" && argv[i + 1]) {
      port = Number(argv[i + 1]);
      i += 1;
    } else if (arg.startsWith("--port=")) {
      port = Number(arg.slice("--port=".length));
    } else if (arg === "--host" && argv[i + 1]) {
      host = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--host=")) {
      host = arg.slice("--host=".length);
    } else if (arg === "--upstream" && argv[i + 1]) {
      upstream = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--upstream=")) {
      upstream = arg.slice("--upstream=".length);
    } else if (arg === "--key" && argv[i + 1]) {
      accessKey = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--key=")) {
      accessKey = arg.slice("--key=".length);
    } else if (arg === "--spent-path" && argv[i + 1]) {
      spentFilePath = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--spent-path=")) {
      spentFilePath = arg.slice("--spent-path=".length);
    } else if (arg === "--expected-fingerprint" && argv[i + 1]) {
      expectedFingerprint = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--expected-fingerprint=")) {
      expectedFingerprint = arg.slice("--expected-fingerprint=".length);
    }
  }

  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port number: ${String(port)}`);
  }

  upstream = upstream.replace(/\/+$/, "");
  return {
    port,
    host,
    upstream,
    accessKey,
    spentFilePath,
    expectedFingerprint,
    help,
  };
}

export function formatProxyHelpText(): string {
  return [
    "deroute-proxy - Local private OpenAI-compatible enclave proxy",
    "",
    "Usage:",
    "  node deroute-proxy.mjs [--key drk_...] [--port 4141] [--upstream https://drouter-demo.vercel.app]",
    "",
    "Options:",
    `  --key <drk_...>       Access key from /account (or set DEROUTE_ACCESS_KEY)`,
    `  --port <number>       Local port on 127.0.0.1 (default: ${DEFAULT_PORT})`,
    `  --upstream <url>      deRoute relay origin (default: ${DEFAULT_UPSTREAM})`,
    "  --spent-path <path>   Path to spent nullifier file (default: ~/.config/deroute/spent.json)",
    "  --help, -h            Show this help message",
    "",
    "Endpoints:",
    "  GET  http://127.0.0.1:<port>/v1/models",
    "  POST http://127.0.0.1:<port>/v1/chat/completions",
  ].join("\n");
}

export async function startDerouteProxy(
  opts?: CreateDerouteProxyOptions & {
    port?: number;
    host?: string;
  },
): Promise<{
  server: http.Server;
  port: number;
  host: string;
  filterInfo: StartupFingerprintCheckResult;
  close: () => Promise<void>;
}> {
  const host = opts?.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    throw new Error(
      `Refusing to bind to non-localhost address "${host}". Only 127.0.0.1 is permitted.`,
    );
  }
  const bindHost = host === "localhost" ? "127.0.0.1" : host;
  const requestedPort = opts?.port ?? DEFAULT_PORT;

  const handle = createDerouteProxyServer(opts);
  const writeStdout =
    opts?.stdout ?? ((line: string) => process.stdout.write(`${line}\n`));

  writeStdout(
    `[deroute-proxy] Personal-detail filter v${handle.filterInfo.version} verified (fingerprint: ${handle.filterInfo.fingerprint})`,
  );

  return new Promise((resolve, reject) => {
    const onError = (err: Error) => {
      reject(err);
    };
    handle.server.once("error", onError);
    handle.server.listen(requestedPort, bindHost, () => {
      handle.server.removeListener("error", onError);
      const addr = handle.server.address();
      const actualPort =
        addr && typeof addr === "object" ? addr.port : requestedPort;
      writeStdout(
        `[deroute-proxy] Listening on http://127.0.0.1:${actualPort}/v1 (credits remaining: ${handle.spentStore.remainingCount()})`,
      );
      resolve({
        server: handle.server,
        port: actualPort,
        host: bindHost,
        filterInfo: handle.filterInfo,
        close: () =>
          new Promise<void>((resClose, rejClose) =>
            handle.server.close((err) => (err ? rejClose(err) : resClose())),
          ),
      });
    });
  });
}

async function runCli(): Promise<void> {
  const args = parseProxyCliArgs(process.argv.slice(2), process.env);
  if (args.help) {
    process.stdout.write(`${formatProxyHelpText()}\n`);
    return;
  }

  await startDerouteProxy({
    port: args.port,
    host: args.host,
    upstream: args.upstream,
    accessKey: args.accessKey,
    spentFilePath: args.spentFilePath,
    expectedFingerprint: args.expectedFingerprint,
  });
}

const isMain = (() => {
  try {
    if (!process.argv[1]) return false;
    const resolvedArg = fs.existsSync(process.argv[1])
      ? fs.realpathSync(process.argv[1])
      : path.resolve(process.argv[1]);
    const resolvedMeta = fs.existsSync( new URL(import.meta.url) )
      ? fs.realpathSync(new URL(import.meta.url))
      : path.resolve(new URL(import.meta.url).pathname);
    return resolvedArg === resolvedMeta;
  } catch {
    return Boolean(
      process.argv[1] &&
        import.meta.url === pathToFileURL(process.argv[1]).href,
    );
  }
})();

if (isMain) {
  runCli().catch((err) => {
    const msg =
      err instanceof Error ? sanitizeErrorText(err.message) : String(err);
    process.stderr.write(`[deroute-proxy] Error: ${msg}\n`);
    process.exit(1);
  });
}
