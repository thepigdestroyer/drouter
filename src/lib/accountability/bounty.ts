import { p384 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { getSimHardwareSeed } from "./manifest";

export const FORBIDDEN_PREFIX_HEX = bytesToHex(
  sha256(utf8ToBytes("drouter/forbidden-report-data/v1")),
);

/**
 * Minimum stake enforced by the deployed DRouterRegistry contract on Arc Testnet
 * (0.01 USDC = 10_000_000_000_000_000 wei, 18 decimals). Live callers read the actual
 * staked balance from `getNode(id).stake` or `minStake()` on chain.
 */
export const DEFAULT_OPERATOR_STAKE_USDC = 0.01;

export interface KeyCompromiseClaim {
  nodeId: string;
  chipId: string;
  measurement: string;
  reportDataHex: string;
  signatureHex: string;
  vcekPublicKeyHex: string;
}

export interface KeyCompromiseVerdict {
  valid: boolean;
  slashUsdc: number;
  submitterBountyUsdc: number;
  reason: string;
}

function deriveDemoBountyVcek(nodeId: string): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
} {
  // Derived from the server secret so outsiders cannot forge a "compromise proof".
  const keyMaterial = hkdf(
    sha256,
    getSimHardwareSeed(),
    undefined,
    utf8ToBytes(`drouter/bounty-demo-vcek/v1/${nodeId}`),
    72,
  );
  const secretKey = p384.utils.randomSecretKey(keyMaterial);
  const publicKey = p384.getPublicKey(keyMaterial ? secretKey : secretKey);
  return { secretKey, publicKey };
}

function buildClaimMessage(
  chipId: string,
  measurement: string,
  reportDataHex: string,
): Uint8Array {
  return utf8ToBytes(`${chipId}|${measurement}|${reportDataHex}`);
}

export function createCompromiseClaimForDemo(
  nodeId: string,
  chipId: string,
  approvedMeasurement: string,
): KeyCompromiseClaim {
  const { secretKey, publicKey } = deriveDemoBountyVcek(nodeId);
  const suffixHex = bytesToHex(
    sha256(utf8ToBytes(`bounty-demo-suffix/${nodeId}/${chipId}`)),
  );
  const reportDataHex = `${FORBIDDEN_PREFIX_HEX}${suffixHex}`;
  const msg = buildClaimMessage(chipId, approvedMeasurement, reportDataHex);
  const sig = p384.sign(msg, secretKey);

  return {
    nodeId,
    chipId,
    measurement: approvedMeasurement,
    reportDataHex,
    signatureHex: bytesToHex(sig),
    vcekPublicKeyHex: bytesToHex(publicKey),
  };
}

export function verifyKeyCompromiseBounty(
  claim: KeyCompromiseClaim,
  approvedMeasurement: string,
  stakeUsdc: number = DEFAULT_OPERATOR_STAKE_USDC,
): KeyCompromiseVerdict {
  if (claim.measurement !== approvedMeasurement) {
    return {
      valid: false,
      slashUsdc: 0,
      submitterBountyUsdc: 0,
      reason: `Measurement mismatch: claim measurement (${claim.measurement.slice(0, 18)}...) does not match approved measurement (${approvedMeasurement.slice(0, 18)}...)`,
    };
  }

  if (!claim.reportDataHex.toLowerCase().startsWith(FORBIDDEN_PREFIX_HEX.toLowerCase())) {
    return {
      valid: false,
      slashUsdc: 0,
      submitterBountyUsdc: 0,
      reason: `REPORT_DATA does not begin with FORBIDDEN_PREFIX_HEX (${FORBIDDEN_PREFIX_HEX.slice(0, 16)}...)`,
    };
  }

  let sigValid = false;
  try {
    const sigBytes = hexToBytes(claim.signatureHex);
    const pubKeyBytes = hexToBytes(claim.vcekPublicKeyHex);
    const msg = buildClaimMessage(claim.chipId, claim.measurement, claim.reportDataHex);
    sigValid = p384.verify(sigBytes, msg, pubKeyBytes, { lowS: false });
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    return {
      valid: false,
      slashUsdc: 0,
      submitterBountyUsdc: 0,
      reason: "Invalid P-384 VCEK ECDSA signature over (chipId | measurement | reportDataHex)",
    };
  }

  const slashUsdc = Number(stakeUsdc.toFixed(6));

  return {
    valid: true,
    slashUsdc,
    // DRouterRegistry.slash(id, to) transfers 100% of the node's staked USDC to `to`;
    // partial percentage bounty splits are not enforced by the contract.
    submitterBountyUsdc: 0,
    reason: `Valid key-compromise proof: approved measurement and forbidden REPORT_DATA prefix signed by chip VCEK; ${slashUsdc} USDC on-chain stake eligible for full slash via DRouterRegistry`,
  };
}
