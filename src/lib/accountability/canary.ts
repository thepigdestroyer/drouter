import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export type CanaryDecoyKind = "api-key" | "wallet-seed" | "webhook";

export interface CanarySession {
  sessionId: string;
  honeytoken: string;
  decoyKind: CanaryDecoyKind;
  salt: string;
  commitment: string;
  promptPreview: string;
}

export interface CanaryRevealInput {
  honeytoken: string;
  salt: string;
  nodeIdentityPk: string;
  epoch: number;
  commitment: string;
  stakeUsdc: number;
}

export interface CanaryLeakVerdict {
  valid: boolean;
  slashUsdc: number;
  reporterBountyUsdc: number;
  compensationPoolUsdc: number;
  reason: string;
}

const DECOY_KINDS: readonly CanaryDecoyKind[] = ["api-key", "wallet-seed", "webhook"];

export function computeCanaryCommitment(
  honeytoken: string,
  salt: string,
  nodeIdentityPk: string,
  epoch: number,
): string {
  const preimage = `${honeytoken}|${salt}|${nodeIdentityPk}|${String(epoch)}`;
  return bytesToHex(sha256(utf8ToBytes(preimage)));
}

export function createCanarySession(
  nodeId: string,
  nodeIdentityPk: string,
  epoch: number,
  seedHex?: string,
): CanarySession {
  const baseMaterial = `${nodeId}|${nodeIdentityPk}|${String(epoch)}|${seedHex ?? "drouter-canary-default"}`;
  const sessionDigest = bytesToHex(sha256(utf8ToBytes(`session|${baseMaterial}`)));
  const tokenDigest = bytesToHex(sha256(utf8ToBytes(`token|${baseMaterial}`)));
  const salt = bytesToHex(sha256(utf8ToBytes(`salt|${baseMaterial}`)));

  const kindIndex = parseInt(sessionDigest.slice(0, 2), 16) % DECOY_KINDS.length;
  const decoyKind = DECOY_KINDS[kindIndex];

  let honeytoken: string;
  let promptPreview: string;

  if (decoyKind === "api-key") {
    honeytoken = `sk-live-drouter-${tokenDigest.slice(0, 32)}`;
    promptPreview = `Please audit this production authorization header for rotation compliance: Authorization: Bearer ${honeytoken}`;
  } else if (decoyKind === "wallet-seed") {
    honeytoken = `xprv9s21ZrQH143K-${tokenDigest.slice(0, 32)}`;
    promptPreview = `Verify the BIP-32 derivation path for treasury extended key ${honeytoken} without logging the key.`;
  } else {
    honeytoken = `https://hooks.drouter.internal/canary/${tokenDigest.slice(0, 24)}`;
    promptPreview = `Format a JSON webhook payload to POST incident alerts to ${honeytoken} with retry backoff.`;
  }

  const commitment = computeCanaryCommitment(honeytoken, salt, nodeIdentityPk, epoch);

  return {
    sessionId: `canary-${sessionDigest.slice(0, 16)}`,
    honeytoken,
    decoyKind,
    salt,
    commitment,
    promptPreview,
  };
}

export function verifyCanaryLeak(reveal: CanaryRevealInput): CanaryLeakVerdict {
  if (!reveal.honeytoken || !reveal.salt || !reveal.nodeIdentityPk || !reveal.commitment) {
    return {
      valid: false,
      slashUsdc: 0,
      reporterBountyUsdc: 0,
      compensationPoolUsdc: 0,
      reason: "Invalid canary reveal: missing honeytoken, salt, nodeIdentityPk, or commitment",
    };
  }

  if (!Number.isFinite(reveal.stakeUsdc) || reveal.stakeUsdc <= 0) {
    return {
      valid: false,
      slashUsdc: 0,
      reporterBountyUsdc: 0,
      compensationPoolUsdc: 0,
      reason: "Invalid canary reveal: stakeUsdc must be positive",
    };
  }

  const expectedCommitment = computeCanaryCommitment(
    reveal.honeytoken,
    reveal.salt,
    reveal.nodeIdentityPk,
    reveal.epoch,
  );

  if (expectedCommitment.toLowerCase() !== reveal.commitment.toLowerCase()) {
    return {
      valid: false,
      slashUsdc: 0,
      reporterBountyUsdc: 0,
      compensationPoolUsdc: 0,
      reason:
        "Canary commitment mismatch: sha256(honeytoken|salt|nodeIdentityPk|epoch) does not match pre-committed hash",
    };
  }

  const slashUsdc = reveal.stakeUsdc;
  const reporterBountyUsdc = Number((slashUsdc * 0.1).toFixed(6));
  const compensationPoolUsdc = Number((slashUsdc * 0.9).toFixed(6));

  return {
    valid: true,
    slashUsdc,
    reporterBountyUsdc,
    compensationPoolUsdc,
    reason:
      "Canary honeytoken leak verified against on-chain commitment: 100% stake slashed (10% reporter bounty, 90% user compensation pool)",
  };
}
