import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { FreezeReceipt } from "@/lib/types";

/**
 * secp256k1 field prime: P = 2^256 - 2^32 - 977
 */
export const SHAMIR_PRIME = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
);

export const REGIONAL_CHECKERS = [
  { checkerId: "checker-zurich", region: "ch-zurich-1" },
  { checkerId: "checker-frankfurt", region: "de-frankfurt-1" },
  { checkerId: "checker-virginia", region: "us-virginia-1" },
  { checkerId: "checker-tokyo", region: "jp-tokyo-1" },
  { checkerId: "checker-reykjavik", region: "is-reykjavik-1" },
] as const;

export interface ShamirShare {
  index: number;
  yHex: string;
  commitmentHex: string;
}

export interface ThresholdCheckerApproval {
  checkerId: string;
  region: string;
  approved: boolean;
  share?: { index: number; yHex: string };
  signatureHex: string;
  publicKeyHex: string;
}

export interface AuthorizeThresholdKeyReleaseParams {
  sessionId: string;
  chipId: string;
  measurementOk: boolean;
  registryActive: boolean;
  notFlagged: boolean;
  k?: number;
  n?: number;
}

export interface AuthorizeThresholdKeyReleaseResult {
  released: boolean;
  k: number;
  n: number;
  approvals: ThresholdCheckerApproval[];
  reconstructedKeyHex?: string;
  reason: string;
  simulatedQuorum: true;
  quorumDisclosure: string;
}

/**
 * Portable Shamir share string format: `drouter-share-v1:<purpose>:<k>-of-<n>:<index>:<yHex>:<commitmentHex>`
 * Suitable for distributing a 3-of-5 recovery quorum for a client's `freezeSecretHex` or `vaultKeyHex`.
 */
export interface DistributedCustodyShare extends ShamirShare {
  format: "drouter-custody-share-v1";
  purpose: "freeze-secret" | "vault-export-key";
  k: number;
  n: number;
  handleId: string;
  portableToken: string;
}

export interface SplitFreezeReceiptSharesResult {
  blobId: string;
  sessionIdHex: string;
  createdAt: number;
  k: number;
  n: number;
  shares: DistributedCustodyShare[];
}

export interface SplitVaultKeySharesResult {
  vaultId: string;
  k: number;
  n: number;
  shares: DistributedCustodyShare[];
}

export const THRESHOLD_CHECKER_DISCLOSURE =
  "Simulated regional checker quorum: all 5 regional checker Ed25519 keys are derived from the server's SIM_HARDWARE_SEED in this single-operator deployment. For genuine client-side custody without trusting a single server, use splitFreezeSecretIntoShares() or splitVaultKeyIntoShares() to distribute 3-of-5 Shamir shares to independent custodians.";

let ephemeralThresholdFallbackSeed: Uint8Array | null = null;

function getServerThresholdSeedBytes(): Uint8Array {
  const raw =
    (typeof process !== "undefined" && process.env?.THRESHOLD_CHECKER_SEED) ||
    (typeof process !== "undefined" && process.env?.SIM_HARDWARE_SEED);
  if (typeof raw === "string" && raw.trim().length > 0) {
    const clean = raw.trim().replace(/^0x/i, "");
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length >= 32 && clean.length % 2 === 0) {
      return hexToBytes(clean);
    }
    return utf8ToBytes(raw.trim());
  }
  if (!ephemeralThresholdFallbackSeed) {
    ephemeralThresholdFallbackSeed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(ephemeralThresholdFallbackSeed);
  }
  return ephemeralThresholdFallbackSeed;
}

function mod(a: bigint, p: bigint = SHAMIR_PRIME): bigint {
  const r = a % p;
  return r >= BigInt(0) ? r : r + p;
}

function modAdd(a: bigint, b: bigint, p: bigint = SHAMIR_PRIME): bigint {
  return mod(a + b, p);
}

function modSub(a: bigint, b: bigint, p: bigint = SHAMIR_PRIME): bigint {
  return mod(a - b, p);
}

function modMul(a: bigint, b: bigint, p: bigint = SHAMIR_PRIME): bigint {
  return mod(a * b, p);
}

function modInv(a: bigint, p: bigint = SHAMIR_PRIME): bigint {
  let t = BigInt(0);
  let newT = BigInt(1);
  let r = p;
  let newR = mod(a, p);

  if (newR === BigInt(0)) {
    throw new Error("Cannot invert zero in GF(P)");
  }

  while (newR !== BigInt(0)) {
    const quotient = r / newR;
    const nextT = t - quotient * newT;
    t = newT;
    newT = nextT;

    const nextR = r - quotient * newR;
    r = newR;
    newR = nextR;
  }

  if (r > BigInt(1)) {
    throw new Error("Element is not invertible in GF(P)");
  }

  return t < BigInt(0) ? t + p : t;
}

function normalizeHex(hex: string): string {
  const clean = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean)) {
    throw new Error("Invalid hex string");
  }
  return clean;
}

function formatFieldElementHex(value: bigint): string {
  return mod(value).toString(16).padStart(64, "0");
}

function constantTimeEqualHex(a: string, b: string): boolean {
  const cleanA = a.toLowerCase();
  const cleanB = b.toLowerCase();
  const maxLen = Math.max(cleanA.length, cleanB.length);
  let diff = cleanA.length ^ cleanB.length;
  for (let i = 0; i < maxLen; i++) {
    const codeA = i < cleanA.length ? cleanA.charCodeAt(i) : 0;
    const codeB = i < cleanB.length ? cleanB.charCodeAt(i) : 0;
    diff |= codeA ^ codeB;
  }
  return diff === 0;
}

/**
 * Rejection-samples a uniform nonzero field element in [1, P - 1].
 * When `seedHex` is omitted, uses CSPRNG (`crypto.getRandomValues`) directly.
 * When `seedHex` is provided, expands deterministic counter blocks via SHA-256 without mixing the secret.
 */
function sampleNonZeroCoefficient(degree: number, seedHex?: string): bigint {
  let attempt = 0;
  while (true) {
    let rawBytes: Uint8Array;
    if (seedHex !== undefined) {
      rawBytes = sha256(
        utf8ToBytes(`drouter:shamir:coeff:v2:${seedHex}:${degree}:${attempt}`)
      );
    } else {
      rawBytes = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rawBytes);
    }
    const candidate = BigInt("0x" + bytesToHex(rawBytes));
    rawBytes.fill(0);
    if (candidate >= BigInt(1) && candidate < SHAMIR_PRIME) {
      return candidate;
    }
    attempt++;
  }
}

export function computeShareCommitment(index: number, yHex: string): string {
  return bytesToHex(sha256(utf8ToBytes(`${index}:${yHex.toLowerCase()}`)));
}

export function verifyShareCommitment(share: ShamirShare): boolean {
  if (!share || !Number.isInteger(share.index) || share.index <= 0) {
    return false;
  }
  if (typeof share.yHex !== "string" || typeof share.commitmentHex !== "string") {
    return false;
  }
  const expected = computeShareCommitment(share.index, share.yHex);
  return constantTimeEqualHex(expected, share.commitmentHex);
}

/**
 * Splits a 32-byte hex secret into `n` Shamir shares with reconstruction threshold `k`
 * over GF(P), evaluating a degree `k - 1` polynomial f(x) at x = 1..n with f(0) = secret.
 * Throws if `secret` >= P or exceeds 32 bytes so secrets are never silently truncated mod P.
 */
export function splitSecret(
  secretHex: string,
  k: number,
  n: number,
  seedHex?: string
): ShamirShare[] {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k || n > 255) {
    throw new Error(`Invalid threshold parameters: k=${k}, n=${n}`);
  }

  if (typeof secretHex !== "string") {
    throw new Error("Secret must be a hex string");
  }
  const cleanSecret = normalizeHex(secretHex);
  if (cleanSecret.length === 0 || cleanSecret.length > 64) {
    throw new Error(`Secret hex length out of bounds: expected 1..64 hex chars, got ${cleanSecret.length}`);
  }
  const rawSecret = BigInt("0x" + cleanSecret);
  if (rawSecret >= SHAMIR_PRIME) {
    throw new Error("Secret value exceeds GF(P) field prime and cannot be represented losslessly");
  }
  const secretScalar = rawSecret;

  const cleanSeed = seedHex !== undefined ? normalizeHex(seedHex) : undefined;

  // Polynomial coefficients: coefficients[0] = f(0) = secret, coefficients[1..k-1] uniform in [1, P-1]
  const coefficients: bigint[] = [secretScalar];
  for (let degree = 1; degree < k; degree++) {
    coefficients.push(sampleNonZeroCoefficient(degree, cleanSeed));
  }

  const shares: ShamirShare[] = [];
  for (let index = 1; index <= n; index++) {
    const x = BigInt(index);
    let xPow = BigInt(1);
    let y = BigInt(0);

    for (let j = 0; j < coefficients.length; j++) {
      y = modAdd(y, modMul(coefficients[j], xPow));
      xPow = modMul(xPow, x);
    }

    const yHex = formatFieldElementHex(y);
    const commitmentHex = computeShareCommitment(index, yHex);
    shares.push({ index, yHex, commitmentHex });
  }

  return shares;
}

/**
 * Reconstructs the 32-byte hex secret using Lagrange interpolation at x = 0 modulo P.
 * Enforces `shares.length >= k`, positive unique x indices in [1, P-1], and valid y elements in [0, P-1].
 */
export function combineShares(
  shares: { index: number; yHex: string; commitmentHex?: string }[],
  k: number
): string {
  if (!Number.isInteger(k) || k < 1 || k > 255) {
    throw new Error(`Invalid threshold k=${k}`);
  }
  if (!Array.isArray(shares) || shares.length < k) {
    throw new Error(
      `Insufficient shares to reconstruct secret: got ${Array.isArray(shares) ? shares.length : 0}, required at least k=${k}`
    );
  }

  const seenIndices = new Set<number>();
  for (const s of shares) {
    if (!s || !Number.isInteger(s.index) || s.index <= 0 || BigInt(s.index) >= SHAMIR_PRIME) {
      throw new Error(`Invalid share index: ${s?.index}`);
    }
    if (seenIndices.has(s.index)) {
      throw new Error(`Duplicate share index: ${s.index}`);
    }
    seenIndices.add(s.index);

    if (typeof s.yHex !== "string") {
      throw new Error("Share yHex must be a string");
    }
    const cleanY = normalizeHex(s.yHex);
    if (cleanY.length > 64 || BigInt("0x" + cleanY) >= SHAMIR_PRIME) {
      throw new Error("Share yHex exceeds GF(P) field prime");
    }
    if (
      typeof s.commitmentHex === "string" &&
      !constantTimeEqualHex(computeShareCommitment(s.index, cleanY.padStart(64, "0")), s.commitmentHex)
    ) {
      throw new Error(`Share commitment mismatch at index ${s.index}`);
    }
  }

  const subset = shares.slice(0, k);
  let secret = BigInt(0);

  for (let i = 0; i < subset.length; i++) {
    const xi = BigInt(subset[i].index);
    const yi = BigInt("0x" + normalizeHex(subset[i].yHex));

    let numerator = BigInt(1);
    let denominator = BigInt(1);

    for (let j = 0; j < subset.length; j++) {
      if (i === j) continue;
      const xj = BigInt(subset[j].index);
      // Evaluating Lagrange basis polynomial L_i(0): (0 - x_j) / (x_i - x_j)
      numerator = modMul(numerator, mod(-xj));
      denominator = modMul(denominator, modSub(xi, xj));
    }

    const lagrangeBasis = modMul(numerator, modInv(denominator));
    secret = modAdd(secret, modMul(yi, lagrangeBasis));
  }

  return formatFieldElementHex(secret);
}

/**
 * Clamps a 32-byte key into the secp256k1 field GF(P) if needed, or validates that it fits losslessly.
 * Note: P = 2^256 - 2^32 - 977, so > 99.9999999% of random 256-bit keys are already < P.
 */
function ensureFieldCompatibleSecretHex(secretHex: string): string {
  const clean = normalizeHex(secretHex);
  if (clean.length !== 64) {
    throw new Error("Expected a 32-byte (64 hex character) secret key");
  }
  const value = BigInt("0x" + clean);
  if (value >= SHAMIR_PRIME) {
    throw new Error("Secret key value exceeds GF(P) field prime; regenerate or re-derive key");
  }
  return clean;
}

function encodePortableShareToken(params: {
  purpose: "freeze-secret" | "vault-export-key";
  handleId: string;
  k: number;
  n: number;
  share: ShamirShare;
}): string {
  return [
    "drouter-share-v1",
    params.purpose,
    params.handleId,
    `${params.k}-of-${params.n}`,
    String(params.share.index),
    params.share.yHex,
    params.share.commitmentHex,
  ].join(":");
}

export function parsePortableShareToken(token: string): DistributedCustodyShare {
  if (typeof token !== "string") {
    throw new Error("Share token must be a string");
  }
  const parts = token.trim().split(":");
  if (parts.length !== 7 || parts[0] !== "drouter-share-v1") {
    throw new Error("Invalid drouter-share-v1 portable share token format");
  }
  const [, purposeRaw, handleId, quorumSpec, indexStr, yHexRaw, commitmentRaw] = parts;
  if (purposeRaw !== "freeze-secret" && purposeRaw !== "vault-export-key") {
    throw new Error(`Unsupported share token purpose: ${purposeRaw}`);
  }
  const match = /^(\d+)-of-(\d+)$/.exec(quorumSpec);
  if (!match) {
    throw new Error(`Invalid quorum specification in share token: ${quorumSpec}`);
  }
  const k = Number(match[1]);
  const n = Number(match[2]);
  const index = Number(indexStr);
  const yHex = normalizeHex(yHexRaw).padStart(64, "0");
  const commitmentHex = normalizeHex(commitmentRaw).padStart(64, "0");

  const share: DistributedCustodyShare = {
    format: "drouter-custody-share-v1",
    purpose: purposeRaw,
    handleId,
    k,
    n,
    index,
    yHex,
    commitmentHex,
    portableToken: token.trim(),
  };

  if (!verifyShareCommitment(share)) {
    throw new Error(`Share commitment verification failed for share index ${index}`);
  }

  return share;
}

/**
 * Real product custody helper #1: Splits a Frozen Session's `freezeSecretHex` (from `FreezeReceipt`)
 * into `k`-of-`n` (default 3-of-5) Shamir shares so a user can distribute session recovery across
 * independent devices or team members and shred the single local secret.
 */
export function splitFreezeSecretIntoShares(
  receipt: Pick<FreezeReceipt, "blobId" | "freezeSecretHex" | "sessionIdHex" | "createdAt">,
  options?: { k?: number; n?: number }
): SplitFreezeReceiptSharesResult {
  const k = options?.k ?? 3;
  const n = options?.n ?? 5;
  const secretHex = ensureFieldCompatibleSecretHex(receipt.freezeSecretHex);
  const rawShares = splitSecret(secretHex, k, n);

  const shares: DistributedCustodyShare[] = rawShares.map((s) => ({
    ...s,
    format: "drouter-custody-share-v1",
    purpose: "freeze-secret",
    k,
    n,
    handleId: receipt.blobId,
    portableToken: encodePortableShareToken({
      purpose: "freeze-secret",
      handleId: receipt.blobId,
      k,
      n,
      share: s,
    }),
  }));

  return {
    blobId: receipt.blobId,
    sessionIdHex: receipt.sessionIdHex,
    createdAt: receipt.createdAt,
    k,
    n,
    shares,
  };
}

/**
 * Reconstructs a `freezeSecretHex` from at least `k` (default 3) distributed Shamir shares or portable tokens.
 */
export function recoverFreezeSecretFromShares(
  sharesOrTokens: Array<ShamirShare | DistributedCustodyShare | string>,
  k = 3
): { blobId?: string; freezeSecretHex: string } {
  const parsedShares: Array<ShamirShare & { handleId?: string; k?: number }> = sharesOrTokens.map(
    (item) => {
      if (typeof item === "string") {
        return parsePortableShareToken(item);
      }
      return item;
    }
  );
  const effectiveK = parsedShares[0]?.k ?? k;
  const handleIds = new Set(
    parsedShares.map((s) => s.handleId).filter((id): id is string => typeof id === "string" && id.length > 0)
  );
  if (handleIds.size > 1) {
    throw new Error("Cannot combine Shamir shares belonging to different frozen blobIds");
  }
  const freezeSecretHex = combineShares(parsedShares, effectiveK);
  const blobId = handleIds.size === 1 ? [...handleIds][0] : undefined;
  return { blobId, freezeSecretHex };
}

/**
 * Real product custody helper #2: Splits a Client Vault's 256-bit `vaultKeyHex` into `k`-of-`n`
 * (default 3-of-5) Shamir shares so an exported `.drouter-vault.json` bundle can be recovered
 * by a threshold quorum without storing the passphrase in a single place.
 */
export function splitVaultKeyIntoShares(
  vault: { vaultId: string; vaultKeyHex: string },
  options?: { k?: number; n?: number }
): SplitVaultKeySharesResult {
  const k = options?.k ?? 3;
  const n = options?.n ?? 5;
  const secretHex = ensureFieldCompatibleSecretHex(vault.vaultKeyHex);
  const rawShares = splitSecret(secretHex, k, n);

  const shares: DistributedCustodyShare[] = rawShares.map((s) => ({
    ...s,
    format: "drouter-custody-share-v1",
    purpose: "vault-export-key",
    k,
    n,
    handleId: vault.vaultId,
    portableToken: encodePortableShareToken({
      purpose: "vault-export-key",
      handleId: vault.vaultId,
      k,
      n,
      share: s,
    }),
  }));

  return {
    vaultId: vault.vaultId,
    k,
    n,
    shares,
  };
}

/**
 * Reconstructs a 256-bit `vaultKeyHex` from at least `k` (default 3) Shamir shares or portable tokens.
 */
export function recoverVaultKeyFromShares(
  sharesOrTokens: Array<ShamirShare | DistributedCustodyShare | string>,
  k = 3
): { vaultId?: string; vaultKeyHex: string } {
  const parsedShares: Array<ShamirShare & { handleId?: string; k?: number }> = sharesOrTokens.map(
    (item) => {
      if (typeof item === "string") {
        return parsePortableShareToken(item);
      }
      return item;
    }
  );
  const effectiveK = parsedShares[0]?.k ?? k;
  const handleIds = new Set(
    parsedShares.map((s) => s.handleId).filter((id): id is string => typeof id === "string" && id.length > 0)
  );
  if (handleIds.size > 1) {
    throw new Error("Cannot combine Shamir shares belonging to different vaultIds");
  }
  const vaultKeyHex = combineShares(parsedShares, effectiveK);
  const vaultId = handleIds.size === 1 ? [...handleIds][0] : undefined;
  return { vaultId, vaultKeyHex };
}

function deriveCheckerKeypair(checkerId: string): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const seed = hkdf(
    sha256,
    getServerThresholdSeedBytes(),
    utf8ToBytes("drouter/threshold-checker-salt/v1"),
    utf8ToBytes(`drouter/threshold-checker-ed25519/v1/${checkerId}`),
    32
  );
  const { secretKey, publicKey } = ed25519.keygen(seed);
  return {
    secretKey,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
  };
}

function buildCheckerStatement(params: {
  sessionId: string;
  chipId: string;
  checkerId: string;
  region: string;
  approved: boolean;
  shareIndex?: number;
  commitmentHex?: string;
}): Uint8Array {
  const canonical = [
    "drouter:threshold-key-release:v1",
    params.sessionId,
    params.chipId,
    params.checkerId,
    params.region,
    params.approved ? "APPROVED" : "REFUSED",
    params.shareIndex !== undefined ? String(params.shareIndex) : "none",
    params.commitmentHex ?? "none",
  ].join("|");
  return utf8ToBytes(canonical);
}

/**
 * Simulated regional checker quorum: evaluates TEE measurement, on-chain registry status,
 * and non-flagged status before releasing Ed25519-signed Shamir shares.
 * Explicitly labelled `simulatedQuorum: true` because all regional checker keys are derived
 * on this server from `SIM_HARDWARE_SEED`.
 */
export function authorizeThresholdKeyRelease(
  params: AuthorizeThresholdKeyReleaseParams
): AuthorizeThresholdKeyReleaseResult {
  const k = params.k ?? 3;
  const n = params.n ?? 5;
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k || n > 255) {
    throw new Error(`Invalid threshold parameters: k=${k}, n=${n}`);
  }
  if (typeof params.sessionId !== "string" || !params.sessionId.trim()) {
    throw new Error("sessionId must be a non-empty string");
  }
  if (typeof params.chipId !== "string" || !params.chipId.trim()) {
    throw new Error("chipId must be a non-empty string");
  }

  const checkers = Array.from({ length: n }, (_, idx) => {
    if (idx < REGIONAL_CHECKERS.length) {
      return REGIONAL_CHECKERS[idx];
    }
    return {
      checkerId: `checker-region-${idx + 1}`,
      region: `global-region-${idx + 1}`,
    };
  });

  const serverSeed = getServerThresholdSeedBytes();

  // Derive target 32-byte key in GF(P) using HKDF over server secret + session parameters
  const rawKeyBytes = hkdf(
    sha256,
    serverSeed,
    utf8ToBytes("drouter/threshold-master-key-salt/v1"),
    utf8ToBytes(`drouter:threshold-master-key:v1:${params.sessionId}:${params.chipId}`),
    32
  );
  let keyScalar = BigInt("0x" + bytesToHex(rawKeyBytes));
  if (keyScalar >= SHAMIR_PRIME || keyScalar === BigInt(0)) {
    keyScalar = (keyScalar % (SHAMIR_PRIME - BigInt(1))) + BigInt(1);
  }
  const expectedKeyHex = formatFieldElementHex(keyScalar);

  const polySeedBytes = hkdf(
    sha256,
    serverSeed,
    utf8ToBytes("drouter/threshold-poly-seed-salt/v1"),
    utf8ToBytes(`drouter:threshold-poly-seed:v1:${params.sessionId}:${params.chipId}`),
    32
  );
  const polySeedHex = bytesToHex(polySeedBytes);

  const allShares = splitSecret(expectedKeyHex, k, n, polySeedHex);
  const checksPass =
    Boolean(params.measurementOk) &&
    Boolean(params.registryActive) &&
    Boolean(params.notFlagged);

  const approvals: ThresholdCheckerApproval[] = [];
  const releasedShares: { index: number; yHex: string }[] = [];

  for (let i = 0; i < n; i++) {
    const checker = checkers[i];
    const share = allShares[i];
    const keypair = deriveCheckerKeypair(checker.checkerId);

    const approved = checksPass;
    const statement = buildCheckerStatement({
      sessionId: params.sessionId,
      chipId: params.chipId,
      checkerId: checker.checkerId,
      region: checker.region,
      approved,
      shareIndex: approved ? share.index : undefined,
      commitmentHex: approved ? share.commitmentHex : undefined,
    });

    const signatureHex = bytesToHex(ed25519.sign(statement, keypair.secretKey));

    if (approved) {
      const releasedShare = { index: share.index, yHex: share.yHex };
      releasedShares.push(releasedShare);
      approvals.push({
        checkerId: checker.checkerId,
        region: checker.region,
        approved: true,
        share: releasedShare,
        signatureHex,
        publicKeyHex: keypair.publicKeyHex,
      });
    } else {
      approvals.push({
        checkerId: checker.checkerId,
        region: checker.region,
        approved: false,
        signatureHex,
        publicKeyHex: keypair.publicKeyHex,
      });
    }
  }

  if (releasedShares.length < k) {
    const failedChecks: string[] = [];
    if (!params.measurementOk) failedChecks.push("measurementOk=false");
    if (!params.registryActive) failedChecks.push("registryActive=false");
    if (!params.notFlagged) failedChecks.push("notFlagged=false");

    return {
      released: false,
      k,
      n,
      approvals,
      reason:
        failedChecks.length > 0
          ? `Threshold key release refused by regional checkers (${failedChecks.join(", ")}); released ${releasedShares.length}/${k} required shares.`
          : `Insufficient checker approvals (${releasedShares.length}/${k}).`,
      simulatedQuorum: true,
      quorumDisclosure: THRESHOLD_CHECKER_DISCLOSURE,
    };
  }

  const reconstructedKeyHex = combineShares(releasedShares.slice(0, k), k);
  if (!constantTimeEqualHex(reconstructedKeyHex, expectedKeyHex)) {
    return {
      released: false,
      k,
      n,
      approvals,
      reason: "Reconstructed key did not match expected session key commitment.",
      simulatedQuorum: true,
      quorumDisclosure: THRESHOLD_CHECKER_DISCLOSURE,
    };
  }

  return {
    released: true,
    k,
    n,
    approvals,
    reconstructedKeyHex,
    reason: `Simulated regional quorum satisfied (${releasedShares.length}/${n} regional checkers >= ${k}); 32-byte key reconstructed via Lagrange interpolation over GF(P).`,
    simulatedQuorum: true,
    quorumDisclosure: THRESHOLD_CHECKER_DISCLOSURE,
  };
}
