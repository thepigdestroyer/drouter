import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { computeShannonEntropyBitsPerByte } from "@/lib/custody/probe-audit";
import { modInverse, modPow, gcd } from "@/lib/credits/blind";

export type MemoryBusMode = "naive-cpu-xts" | "drouter-gpu-hbm";

export interface MemoryBusCellBlock {
  index: number;
  row: number;
  col: number;
  bit: 0 | 1;
  plaintextLabel: string;
  cipherBlockHex: string;
  nonceHex: string;
  matchesFirstActiveBlock: boolean;
  matchesFirstIdleBlock: boolean;
  reconstructedBit: 0 | 1 | null;
}

export interface MemoryBusProbeResult {
  mode: MemoryBusMode;
  grid: Array<0 | 1>;
  blocks: MemoryBusCellBlock[];
  repeatedBlocks: number;
  uniqueBlocks: number;
  entropyBitsPerByte: number;
  leakRatePct: number;
  reconstructedGrid: Array<0 | 1 | null>;
  summary: string;
}

export const DEFAULT_HEART_GRID: Array<0 | 1> = [
  0, 1, 1, 0,
  1, 1, 1, 1,
  0, 1, 1, 0,
  0, 0, 1, 0,
];

export const PRESET_GRIDS: Record<string, { label: string; description: string; grid: Array<0 | 1> }> = {
  vaultKey: {
    label: "Key silhouette",
    description: "A 4x4 token bitmap crossing the memory bus during prompt prefill.",
    grid: [
      0, 1, 1, 0,
      1, 1, 1, 1,
      0, 1, 1, 0,
      0, 0, 1, 0,
    ],
  },
  checker: {
    label: "Alternating cadence",
    description: "Repeated YES / NO structured medical classification blocks.",
    grid: [
      1, 0, 1, 0,
      0, 1, 0, 1,
      1, 0, 1, 0,
      0, 1, 0, 1,
    ],
  },
  beacon: {
    label: "Corner frame",
    description: "System prompt framing with repeated padding cells in the center.",
    grid: [
      1, 1, 1, 1,
      1, 0, 0, 1,
      1, 0, 0, 1,
      1, 1, 1, 1,
    ],
  },
};

function normalizeGridInput(input?: Array<number | boolean> | string): Array<0 | 1> {
  if (!input) {
    return [...DEFAULT_HEART_GRID];
  }
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (PRESET_GRIDS[trimmed]) {
      return [...PRESET_GRIDS[trimmed].grid];
    }
    const bytes = utf8ToBytes(trimmed || "drouter");
    const out: Array<0 | 1> = [];
    for (let i = 0; i < 16; i++) {
      const b = bytes[i % bytes.length];
      out.push(((b >> (i % 8)) & 1) === 1 ? 1 : 0);
    }
    if (!out.some((v) => v === 1)) {
      out[0] = 1;
      out[5] = 1;
    }
    return out;
  }
  const out: Array<0 | 1> = [];
  for (let i = 0; i < 16; i++) {
    const raw = input[i];
    out.push(raw ? 1 : 0);
  }
  return out;
}

/**
 * Exhibit 01: The $900 Memory-Bus Probe (TEE.fail)
 *
 * In "naive-cpu-xts" mode, deterministic tweak/ECB-like memory encryption without a fresh
 * per-write nonce maps identical 16-byte plaintext blocks at the same slot family to identical
 * 16-byte ciphertext blocks. An attacker with a passive interposer reconstructs 100% of the pattern.
 *
 * In "drouter-gpu-hbm" mode, active weights and KV pages stay inside on-package GPU HBM and
 * any bus transfer uses a fresh monotonic 96-bit AES-256-GCM nonce per write. Every 16-byte block
 * is unique, Shannon entropy exceeds 7.8 bits/byte, and pattern reconstruction leaks 0%.
 */
export function tapMemoryBus(
  gridOrInput: Array<number | boolean> | string = DEFAULT_HEART_GRID,
  mode: MemoryBusMode = "naive-cpu-xts"
): MemoryBusProbeResult {
  const grid = normalizeGridInput(gridOrInput);
  const key = sha256(utf8ToBytes("drouter/exhibit-01/session-traffic-key-v1"));

  const activePlaintext = utf8ToBytes("SECRET_CELL_ON!!"); // 16 bytes
  const idlePlaintext = utf8ToBytes("PADDING_CELL_OFF"); // 16 bytes

  const blocks: MemoryBusCellBlock[] = [];
  const dmaFrames: Uint8Array[] = [];

  // Precompute deterministic static blocks for naive CPU XTS replay at identical memory line tweak
  const staticNonce = new Uint8Array(12);
  staticNonce.set(utf8ToBytes("STATIC_TWEAK"));
  const naiveActiveBlock = gcm(key, staticNonce).encrypt(activePlaintext).subarray(0, 16);
  const naiveIdleBlock = gcm(key, staticNonce).encrypt(idlePlaintext).subarray(0, 16);
  const naiveActiveHex = bytesToHex(naiveActiveBlock);
  const naiveIdleHex = bytesToHex(naiveIdleBlock);

  for (let i = 0; i < 16; i++) {
    const bit = grid[i];
    const row = Math.floor(i / 4);
    const col = i % 4;
    const label = bit === 1 ? "SECRET_CELL_ON!!" : "PADDING_CELL_OFF";

    if (mode === "naive-cpu-xts") {
      const blockBytes = bit === 1 ? naiveActiveBlock : naiveIdleBlock;
      const cipherBlockHex = bit === 1 ? naiveActiveHex : naiveIdleHex;
      dmaFrames.push(blockBytes);
      blocks.push({
        index: i,
        row,
        col,
        bit,
        plaintextLabel: label,
        cipherBlockHex,
        nonceHex: bytesToHex(staticNonce),
        matchesFirstActiveBlock: bit === 1,
        matchesFirstIdleBlock: bit === 0,
        reconstructedBit: bit,
      });
    } else {
      // dRouter GPU HBM custody: monotonic 96-bit nonce per transfer + 256-byte encrypted DMA frame
      const nonce = new Uint8Array(12);
      nonce.set(utf8ToBytes("HBM1"), 0);
      const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
      view.setUint32(4, 1, false);
      view.setUint32(8, i + 1, false);

      const pagePayload = new Uint8Array(256);
      const cellBytes = bit === 1 ? activePlaintext : idlePlaintext;
      for (let offset = 0; offset < 256; offset += 16) {
        pagePayload.set(cellBytes, offset);
      }

      const aad = utf8ToBytes(`drouter:hbm-dma:cell:${i}`);
      const encryptedFrame = gcm(key, nonce, aad).encrypt(pagePayload);
      dmaFrames.push(encryptedFrame);

      const first16 = encryptedFrame.subarray(0, 16);
      blocks.push({
        index: i,
        row,
        col,
        bit,
        plaintextLabel: label,
        cipherBlockHex: bytesToHex(first16),
        nonceHex: bytesToHex(nonce),
        matchesFirstActiveBlock: false,
        matchesFirstIdleBlock: false,
        reconstructedBit: null,
      });
    }
  }

  const seenHex = new Set<string>();
  let repeatedBlocks = 0;
  for (const b of blocks) {
    if (seenHex.has(b.cipherBlockHex)) {
      repeatedBlocks += 1;
    } else {
      seenHex.add(b.cipherBlockHex);
    }
  }

  const totalBytes = dmaFrames.reduce((sum, f) => sum + f.byteLength, 0);
  const combinedBusStream = new Uint8Array(totalBytes);
  let offset = 0;
  for (const frame of dmaFrames) {
    combinedBusStream.set(frame, offset);
    offset += frame.byteLength;
  }

  const entropyBitsPerByte = computeShannonEntropyBitsPerByte(combinedBusStream);
  const leakRatePct = mode === "naive-cpu-xts" ? 100 : 0;
  const reconstructedGrid = blocks.map((b) => b.reconstructedBit);

  const summary =
    mode === "naive-cpu-xts"
      ? `Physical DDR5 interposer observed ${repeatedBlocks} duplicate 16-byte ciphertext blocks and reconstructed 100% of the 4x4 silhouette.`
      : `On-package GPU HBM custody with per-transfer monotonic AES-256-GCM nonces produced 0 duplicate blocks (${entropyBitsPerByte.toFixed(2)} bits/byte entropy) and 0% pattern leakage.`;

  return {
    mode,
    grid,
    blocks,
    repeatedBlocks,
    uniqueBlocks: seenHex.size,
    entropyBitsPerByte,
    leakRatePct,
    reconstructedGrid,
    summary,
  };
}

/**
 * Exhibit 02: The Carbon-Paper Blind Credit
 *
 * Uses an exact RSA blind signature modulus (n = 3233, e = 17, d = 2753) by default
 * or custom RSA parameters so players can inspect every integer step by hand while also
 * verifying full mathematical unlinkability across all 3! = 6 bank permutations.
 */
export interface BlindEnvelopeParams {
  t?: number | bigint;
  r?: number | bigint;
  n?: number | bigint;
  e?: number | bigint;
  d?: number | bigint;
}

export interface BankPurchaseTranscript {
  id: string;
  buyerWallet: string;
  blinded: bigint;
  blindedHex: string;
  blindSignature: bigint;
}

export interface BankSpentToken {
  id: string;
  sessionLabel: string;
  t: bigint;
  s: bigint;
  signatureValid: boolean;
}

export interface BankPermutationProof {
  permutation: [number, number, number];
  mappingSummary: string;
  impliedBlindingFactors: [bigint, bigint, bigint];
  allConsistent: boolean;
}

export interface BlindEnvelopeRoundResult {
  n: bigint;
  e: bigint;
  d: bigint;
  t: bigint;
  r: bigint;
  rInv: bigint;
  blinded: bigint;
  sPrime: bigint;
  s: bigint;
  recomputedFromSignature: bigint;
  signatureValid: boolean;
  unlinkable: boolean;
  validPermutationsCount: number;
  purchases: BankPurchaseTranscript[];
  spentTokens: BankSpentToken[];
  permutations: BankPermutationProof[];
  explanation: string;
}

const DEFAULT_TOY_RSA = {
  // p = 61, q = 53 -> n = 3233, phi = 3120, e = 17, d = 2753
  n: BigInt(3233),
  e: BigInt(17),
  d: BigInt(2753),
};

function normalizeCoprime(value: bigint, n: bigint, fallback: bigint): bigint {
  let candidate = ((value % n) + n) % n;
  if (candidate <= BigInt(1)) {
    candidate = fallback;
  }
  while (gcd(candidate, n) !== BigInt(1)) {
    candidate = (candidate + BigInt(1)) % n;
    if (candidate <= BigInt(1)) {
      candidate = BigInt(2);
    }
  }
  return candidate;
}

export function blindEnvelopeRound(
  params: BlindEnvelopeParams | number | bigint = {},
  maybeR?: number | bigint
): BlindEnvelopeRoundResult {
  const normalizedParams: BlindEnvelopeParams =
    typeof params === "number" || typeof params === "bigint"
      ? { t: params, r: maybeR }
      : params;

  const n = normalizedParams.n !== undefined ? BigInt(normalizedParams.n) : DEFAULT_TOY_RSA.n;
  const e = normalizedParams.e !== undefined ? BigInt(normalizedParams.e) : DEFAULT_TOY_RSA.e;
  const d = normalizedParams.d !== undefined ? BigInt(normalizedParams.d) : DEFAULT_TOY_RSA.d;

  const rawT = normalizedParams.t !== undefined ? BigInt(normalizedParams.t) : BigInt(42);
  const rawR = normalizedParams.r !== undefined ? BigInt(normalizedParams.r) : BigInt(19);

  const t = normalizeCoprime(rawT, n, BigInt(42));
  const r = normalizeCoprime(rawR, n, BigInt(19));

  // Step 1: User blinds token t with carbon-paper factor r: blinded = t * r^e mod n
  const rPowE = modPow(r, e, n);
  const blinded = (t * rPowE) % n;

  // Step 2: Bank signs the blinded envelope without seeing t: s' = blinded^d mod n
  const sPrime = modPow(blinded, d, n);

  // Step 3: User peels off the carbon paper using r^-1 mod n: s = s' * r^-1 mod n
  const rInv = modInverse(r, n);
  const s = (sPrime * rInv) % n;

  // Step 4: Any enclave verifies s^e mod n == t
  const recomputedFromSignature = modPow(s, e, n);
  const signatureValid = recomputedFromSignature === t;

  // Step 5: Build the 3-wallet "Play as the Bank" unlinkability challenge
  const secondT = normalizeCoprime(t + BigInt(29), n, BigInt(71));
  const thirdT = normalizeCoprime(t + BigInt(67), n, BigInt(109));
  const secondR = normalizeCoprime(r + BigInt(12), n, BigInt(31));
  const thirdR = normalizeCoprime(r + BigInt(24), n, BigInt(43));

  const realTriples = [
    {
      wallet: "0xA1ce...901 (Alice)",
      sessionLabel: "Anonymous Session #1",
      tVal: t,
      rVal: r,
    },
    {
      wallet: "0xB0b0...442 (Bob)",
      sessionLabel: "Anonymous Session #2",
      tVal: secondT,
      rVal: secondR,
    },
    {
      wallet: "0xCa70...778 (Carol)",
      sessionLabel: "Anonymous Session #3",
      tVal: thirdT,
      rVal: thirdR,
    },
  ];

  const purchases: BankPurchaseTranscript[] = realTriples.map((item, idx) => {
    const b = (item.tVal * modPow(item.rVal, e, n)) % n;
    const sp = modPow(b, d, n);
    return {
      id: `purchase-${idx + 1}`,
      buyerWallet: item.wallet,
      blinded: b,
      blindedHex: "0x" + b.toString(16).padStart(4, "0"),
      blindSignature: sp,
    };
  });

  // Present spent tokens in rotated order so the UI has a non-trivial display
  const rotatedIndices = [1, 2, 0];
  const spentTokens: BankSpentToken[] = rotatedIndices.map((sourceIdx, displayIdx) => {
    const source = realTriples[sourceIdx];
    const sig = modPow(source.tVal, d, n);
    return {
      id: `spend-${displayIdx + 1}`,
      sessionLabel: `Enclave Spend #${displayIdx + 1}`,
      t: source.tVal,
      s: sig,
      signatureValid: modPow(sig, e, n) === source.tVal,
    };
  });

  // Test all 6 permutations of (purchase_0, purchase_1, purchase_2) -> (spend_p0, spend_p1, spend_p2)
  const allPerms: Array<[number, number, number]> = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ];

  const permutations: BankPermutationProof[] = allPerms.map((perm) => {
    const impliedRs: [bigint, bigint, bigint] = [BigInt(0), BigInt(0), BigInt(0)];
    let allConsistent = true;

    for (let i = 0; i < 3; i++) {
      const purchase = purchases[i];
      const spend = spentTokens[perm[i]];
      // In RSA blind signatures, for ANY (blinded_i, s'_i) and ANY valid (t_j, s_j),
      // r_ij = s'_i * s_j^-1 mod n satisfies t_j * (r_ij)^e == s_j^e * (s'_i / s_j)^e == (s'_i)^e == blinded_i (mod n)
      const sInv = modInverse(spend.s, n);
      const rImplied = (purchase.blindSignature * sInv) % n;
      impliedRs[i] = rImplied;

      const checkBlinded = (spend.t * modPow(rImplied, e, n)) % n;
      if (checkBlinded !== purchase.blinded || !spend.signatureValid) {
        allConsistent = false;
      }
    }

    return {
      permutation: perm,
      mappingSummary: `Buyer 1 -> Spend #${perm[0] + 1}, Buyer 2 -> Spend #${perm[1] + 1}, Buyer 3 -> Spend #${perm[2] + 1}`,
      impliedBlindingFactors: impliedRs,
      allConsistent,
    };
  });

  const validPermutationsCount = permutations.filter((p) => p.allConsistent).length;
  const unlinkable =
    signatureValid &&
    spentTokens.every((st) => st.signatureValid) &&
    validPermutationsCount === 6;

  return {
    n,
    e,
    d,
    t,
    r,
    rInv,
    blinded,
    sPrime,
    s,
    recomputedFromSignature,
    signatureValid,
    unlinkable,
    validPermutationsCount,
    purchases,
    spentTokens,
    permutations,
    explanation:
      "Every one of the 6 possible buyer-to-session assignments has an exact, valid blinding factor r_ij that satisfies blinded_i = t_j * r_ij^e mod n. Even with unbounded compute, the bank has zero information about which buyer spent which credit.",
  };
}

/**
 * Exhibit 03: Spot the Forged Enclave
 */
export type CandidateNodeId = "node-alpha" | "node-bravo" | "node-charlie";

export interface EnclaveRegisterCheck {
  id: string;
  label: string;
  registerName: string;
  observedValue: string;
  expectedValue: string;
  passed: boolean;
}

export interface CandidateEnclaveNode {
  id: CandidateNodeId;
  name: string;
  region: string;
  hardwareLabel: string;
  amdVcekValid: boolean;
  policyHex: string;
  policyDebugAllowed: boolean;
  dmVerityRootHash: string;
  sigstoreExpectedRootHash: string;
  dmVerityMatchesSigstore: boolean;
  confidentialGpusOnline: number;
  confidentialGpusRequired: number;
  spdmMeasurementsValid: boolean;
  quorumSignatures: number;
  quorumThreshold: number;
  isAuthentic: boolean;
  defectCode: "NONE" | "SEV_POLICY_DEBUG_BIT_19" | "DM_VERITY_ROOT_MISMATCH";
  defectHeadline: string;
  defectExplanation: string;
  checks: EnclaveRegisterCheck[];
}

export interface NodeEvaluationResult {
  chosenNodeId: CandidateNodeId;
  correct: boolean;
  authenticNodeId: CandidateNodeId;
  chosenNode: CandidateEnclaveNode;
  verdictHeadline: string;
  caughtRegister: string;
  explanation: string;
}

export const EXPECTED_SIGSTORE_ROOT_HASH =
  "0x8f94e2c17b604d3aa910e58c427f3b19c0d8e4a1627384950a1b2c3d4e5f6071";

export const TAMPERED_BACKDOOR_ROOT_HASH =
  "0xdeadbeef7b604d3aa910e58c427f3b19c0d8e4a1627384950a1b2c3d4e5f9999";

export function judgeCandidateNodes(): CandidateEnclaveNode[] {
  const nodeAlpha: CandidateEnclaveNode = {
    id: "node-alpha",
    name: "Node Alpha · us-east-va-1",
    region: "Ashburn, VA",
    hardwareLabel: "AMD EPYC Genoa + 8x H100 CC",
    amdVcekValid: true,
    policyHex: "0x00000000000b0000", // Bit 19 (0x80000) is SET!
    policyDebugAllowed: true,
    dmVerityRootHash: EXPECTED_SIGSTORE_ROOT_HASH,
    sigstoreExpectedRootHash: EXPECTED_SIGSTORE_ROOT_HASH,
    dmVerityMatchesSigstore: true,
    confidentialGpusOnline: 8,
    confidentialGpusRequired: 8,
    spdmMeasurementsValid: true,
    quorumSignatures: 5,
    quorumThreshold: 7,
    isAuthentic: false,
    defectCode: "SEV_POLICY_DEBUG_BIT_19",
    defectHeadline: "Rejected: SEV-SNP guest policy bit 19 (DEBUG) is set to 1",
    defectExplanation:
      "The hardware signature from AMD is genuine, and the container image hash matches Sigstore, but the host operator booted the VM with GUEST_POLICY[19] = 1. That single bit allows the hypervisor to invoke SNP_DBG_DECRYPT and read plaintext enclave memory.",
    checks: [
      {
        id: "vcek",
        label: "AMD Genoa VCEK hardware signature",
        registerName: "ATT_REPORT.SIGNATURE",
        observedValue: "Valid ECDSA P-384 chain to AMD Root",
        expectedValue: "Valid ECDSA P-384 chain to AMD Root",
        passed: true,
      },
      {
        id: "debug-bit",
        label: "SEV-SNP guest policy debug bit",
        registerName: "ATT_REPORT.POLICY[19]",
        observedValue: "1 (DEBUG_ALLOWED / 0x0b0000)",
        expectedValue: "0 (DEBUG_DISABLED / 0x030000)",
        passed: false,
      },
      {
        id: "dm-verity",
        label: "Rootfs dm-verity Merkle root vs Sigstore log",
        registerName: "INITRD.DM_VERITY_ROOT",
        observedValue: EXPECTED_SIGSTORE_ROOT_HASH.slice(0, 18) + "...",
        expectedValue: EXPECTED_SIGSTORE_ROOT_HASH.slice(0, 18) + "...",
        passed: true,
      },
      {
        id: "gpu-cc",
        label: "8x NVIDIA H100 Confidential Compute SPDM",
        registerName: "GPU_SPDM.CC_MODE",
        observedValue: "8 / 8 active (PCIe DOE encrypted)",
        expectedValue: "8 / 8 active (PCIe DOE encrypted)",
        passed: true,
      },
      {
        id: "quorum",
        label: "Independent monitor quorum co-signatures",
        registerName: "TRANSPARENCY.QUORUM",
        observedValue: "5 of 7 verifier signatures",
        expectedValue: ">= 5 of 7 verifier signatures",
        passed: true,
      },
    ],
  };

  const nodeBravo: CandidateEnclaveNode = {
    id: "node-bravo",
    name: "Node Bravo · eu-central-fra-2",
    region: "Frankfurt, DE",
    hardwareLabel: "AMD EPYC Genoa + 8x H100 CC",
    amdVcekValid: true,
    policyHex: "0x0000000000030000",
    policyDebugAllowed: false,
    dmVerityRootHash: TAMPERED_BACKDOOR_ROOT_HASH,
    sigstoreExpectedRootHash: EXPECTED_SIGSTORE_ROOT_HASH,
    dmVerityMatchesSigstore: false,
    confidentialGpusOnline: 8,
    confidentialGpusRequired: 8,
    spdmMeasurementsValid: true,
    quorumSignatures: 5,
    quorumThreshold: 7,
    isAuthentic: false,
    defectCode: "DM_VERITY_ROOT_MISMATCH",
    defectHeadline: "Rejected: dm-verity root hash does not match the Sigstore build log",
    defectExplanation:
      "Hardware debug is properly disabled, so the host cannot peek from outside. However, the operator booted a modified container image whose dm-verity root hash (0xdeadbeef...) differs from the reproducible build anchored in Sigstore. A modified image could log prompts from inside the enclave.",
    checks: [
      {
        id: "vcek",
        label: "AMD Genoa VCEK hardware signature",
        registerName: "ATT_REPORT.SIGNATURE",
        observedValue: "Valid ECDSA P-384 chain to AMD Root",
        expectedValue: "Valid ECDSA P-384 chain to AMD Root",
        passed: true,
      },
      {
        id: "debug-bit",
        label: "SEV-SNP guest policy debug bit",
        registerName: "ATT_REPORT.POLICY[19]",
        observedValue: "0 (DEBUG_DISABLED / 0x030000)",
        expectedValue: "0 (DEBUG_DISABLED / 0x030000)",
        passed: true,
      },
      {
        id: "dm-verity",
        label: "Rootfs dm-verity Merkle root vs Sigstore log",
        registerName: "INITRD.DM_VERITY_ROOT",
        observedValue: TAMPERED_BACKDOOR_ROOT_HASH.slice(0, 18) + "...",
        expectedValue: EXPECTED_SIGSTORE_ROOT_HASH.slice(0, 18) + "...",
        passed: false,
      },
      {
        id: "gpu-cc",
        label: "8x NVIDIA H100 Confidential Compute SPDM",
        registerName: "GPU_SPDM.CC_MODE",
        observedValue: "8 / 8 active (PCIe DOE encrypted)",
        expectedValue: "8 / 8 active (PCIe DOE encrypted)",
        passed: true,
      },
      {
        id: "quorum",
        label: "Independent monitor quorum co-signatures",
        registerName: "TRANSPARENCY.QUORUM",
        observedValue: "5 of 7 verifier signatures",
        expectedValue: ">= 5 of 7 verifier signatures",
        passed: true,
      },
    ],
  };

  const nodeCharlie: CandidateEnclaveNode = {
    id: "node-charlie",
    name: "Node Charlie · us-west-ore-3",
    region: "Boardman, OR",
    hardwareLabel: "AMD EPYC Genoa + 8x H100 CC",
    amdVcekValid: true,
    policyHex: "0x0000000000030000",
    policyDebugAllowed: false,
    dmVerityRootHash: EXPECTED_SIGSTORE_ROOT_HASH,
    sigstoreExpectedRootHash: EXPECTED_SIGSTORE_ROOT_HASH,
    dmVerityMatchesSigstore: true,
    confidentialGpusOnline: 8,
    confidentialGpusRequired: 8,
    spdmMeasurementsValid: true,
    quorumSignatures: 6,
    quorumThreshold: 7,
    isAuthentic: true,
    defectCode: "NONE",
    defectHeadline: "Verified: All 7 hardware and transparency invariants passed",
    defectExplanation:
      "Node Charlie carries a genuine AMD Genoa VCEK signature, enforces POLICY[19] = 0 (debug off, SMT controlled), boots the exact dm-verity root hash published in the Sigstore transparency log, binds 8 Confidential H100 GPUs over SPDM, and holds 6/7 quorum signatures.",
    checks: [
      {
        id: "vcek",
        label: "AMD Genoa VCEK hardware signature",
        registerName: "ATT_REPORT.SIGNATURE",
        observedValue: "Valid ECDSA P-384 chain to AMD Root",
        expectedValue: "Valid ECDSA P-384 chain to AMD Root",
        passed: true,
      },
      {
        id: "debug-bit",
        label: "SEV-SNP guest policy debug bit",
        registerName: "ATT_REPORT.POLICY[19]",
        observedValue: "0 (DEBUG_DISABLED / 0x030000)",
        expectedValue: "0 (DEBUG_DISABLED / 0x030000)",
        passed: true,
      },
      {
        id: "dm-verity",
        label: "Rootfs dm-verity Merkle root vs Sigstore log",
        registerName: "INITRD.DM_VERITY_ROOT",
        observedValue: EXPECTED_SIGSTORE_ROOT_HASH.slice(0, 18) + "...",
        expectedValue: EXPECTED_SIGSTORE_ROOT_HASH.slice(0, 18) + "...",
        passed: true,
      },
      {
        id: "gpu-cc",
        label: "8x NVIDIA H100 Confidential Compute SPDM",
        registerName: "GPU_SPDM.CC_MODE",
        observedValue: "8 / 8 active (PCIe DOE encrypted)",
        expectedValue: "8 / 8 active (PCIe DOE encrypted)",
        passed: true,
      },
      {
        id: "quorum",
        label: "Independent monitor quorum co-signatures",
        registerName: "TRANSPARENCY.QUORUM",
        observedValue: "6 of 7 verifier signatures",
        expectedValue: ">= 5 of 7 verifier signatures",
        passed: true,
      },
    ],
  };

  return [nodeAlpha, nodeBravo, nodeCharlie];
}

export function evaluateNodeChoice(
  chosenNodeId: CandidateNodeId | string,
  nodes: CandidateEnclaveNode[] = judgeCandidateNodes()
): NodeEvaluationResult {
  const authenticNode = nodes.find((n) => n.isAuthentic) ?? nodes[2];
  const chosenNode = nodes.find((n) => n.id === chosenNodeId) ?? nodes[0];
  const correct = chosenNode.isAuthentic;

  const failedCheck = chosenNode.checks.find((c) => !c.passed);
  const caughtRegister = failedCheck ? failedCheck.registerName : "ALL_REGISTERS_CLEAN";

  return {
    chosenNodeId: chosenNode.id,
    correct,
    authenticNodeId: authenticNode.id,
    chosenNode,
    verdictHeadline: chosenNode.defectHeadline,
    caughtRegister,
    explanation: chosenNode.defectExplanation,
  };
}

/**
 * Exhibit 04: Pop the Bubble Before the Subpoena
 */
export type SubpoenaAction = "freeze" | "pop" | "shred-secret" | "host-ram-dump";

export interface SubpoenaForensicState {
  actionsExecuted: SubpoenaAction[];
  gpuPagesZeroed: boolean;
  gpuActiveBytesRemaining: number;
  gpuHexPreview: string;
  hostDumpReadableBytes: number;
  hostDumpHexPreview: string;
  freezeBlobSavedInMongo: boolean;
  userFreezeSecretPresent: boolean;
  cloudBlobDecryptableWithUserKey: boolean;
  cloudBlobDecryptableByServer: false;
  subpoenaYieldSummary: string;
  timelineLog: string[];
}

export function simulateSubpoenaPop(
  actionsInput: SubpoenaAction | SubpoenaAction[] = []
): SubpoenaForensicState {
  const actions: SubpoenaAction[] = Array.isArray(actionsInput)
    ? [...actionsInput]
    : [actionsInput];

  // Initial live enclave session state: 4096 bytes of active prompt + KV pages inside GPU HBM
  const sensitivePrompt =
    "CONFIDENTIAL_MERGER_TERM_SHEET: TARGET=ACME_BIO; OFFER=$4.2B; BOARD_VOTE=PENDING;";
  const sensitiveBytes = utf8ToBytes(sensitivePrompt);

  const gpuHbmBuffer = new Uint8Array(4096);
  for (let i = 0; i < 4096; i++) {
    gpuHbmBuffer[i] = sensitiveBytes[i % sensitiveBytes.length];
  }

  // Client-held 256-bit freeze secret K_freeze (never transmitted to the server or MongoDB)
  const userFreezeKey = new Uint8Array(32);
  userFreezeKey.set(sha256(utf8ToBytes("user-device-only-k-freeze-secret-v1")));
  const freezeNonce = utf8ToBytes("freeze-iv-01"); // 12 bytes
  const freezeAad = utf8ToBytes("mongodb:encrypted_sessions:blob_v1");

  let gpuPagesZeroed = false;
  let freezeBlobCiphertext: Uint8Array | null = null;
  let userFreezeSecretPresent = true;
  let hostDumpReadableBytes = 0;
  const timelineLog: string[] = [
    "Session live: 4,096 bytes of active context resident inside on-package GPU HBM.",
  ];

  for (const action of actions) {
    if (action === "freeze") {
      if (!gpuPagesZeroed && userFreezeSecretPresent) {
        freezeBlobCiphertext = gcm(userFreezeKey, freezeNonce, freezeAad).encrypt(gpuHbmBuffer);
        timelineLog.push(
          "Freeze executed: Context sealed in browser with client-only K_freeze (AES-256-GCM) and stored as opaque ciphertext in MongoDB Atlas."
        );
      } else if (gpuPagesZeroed) {
        timelineLog.push(
          "Freeze skipped: Enclave bubble was already popped and zeroed before freeze."
        );
      } else {
        timelineLog.push(
          "Freeze failed: Local K_freeze secret was already shredded on the client."
        );
      }
    } else if (action === "pop") {
      gpuHbmBuffer.fill(0);
      gpuPagesZeroed = true;
      timelineLog.push(
        "Bubble popped: Ephemeral session keys and all 4,096 bytes of GPU HBM staging and KV cache pages overwritten with 0x00."
      );
    } else if (action === "shred-secret") {
      userFreezeKey.fill(0);
      userFreezeSecretPresent = false;
      timelineLog.push(
        "Client secret shredded: User wiped K_freeze from their device. Any MongoDB ciphertext blob is now permanently undecryptable by anyone."
      );
    } else if (action === "host-ram-dump") {
      // Host hypervisor / subpoena dump inspects CPU DRAM and PCIe bounce buffers.
      // Because plaintext stayed inside GPU HBM (and is 0x00 after pop), host RAM reveals 0 plaintext bytes.
      hostDumpReadableBytes = 0;
      timelineLog.push(
        gpuPagesZeroed
          ? "Subpoena forensic dump: Host DRAM contains only high-entropy ciphertext frames and GPU HBM pages read back as all-zero (0x00). 0 readable bytes recovered."
          : "Subpoena forensic dump: Host CPU DRAM contains only AES-256-GCM encrypted bounce frames (0 readable plaintext bytes). Enclave HBM remains isolated by hardware."
      );
    }
  }

  let gpuActiveBytesRemaining = 0;
  for (let i = 0; i < gpuHbmBuffer.byteLength; i++) {
    if (gpuHbmBuffer[i] !== 0) {
      gpuActiveBytesRemaining += 1;
    }
  }

  // Test whether the cloud blob in MongoDB can be decrypted with the current user key
  let cloudBlobDecryptableWithUserKey = false;
  if (freezeBlobCiphertext !== null && userFreezeSecretPresent) {
    try {
      const recovered = gcm(userFreezeKey, freezeNonce, freezeAad).decrypt(freezeBlobCiphertext);
      cloudBlobDecryptableWithUserKey = recovered.byteLength === 4096;
    } catch {
      cloudBlobDecryptableWithUserKey = false;
    }
  }

  const gpuHexPreview = bytesToHex(gpuHbmBuffer.subarray(0, 16));
  const hostCipherSample = gcm(
    sha256(utf8ToBytes("ephemeral-bus-key")),
    utf8ToBytes("bus-nonce-99")
  ).encrypt(utf8ToBytes("ENCRYPTED_PCIE!!")).subarray(0, 16);

  const subpoenaYieldSummary =
    gpuPagesZeroed && !cloudBlobDecryptableWithUserKey
      ? "Total cryptographic amnesia: Enclave HBM is 0x00 and no decryptable cloud backup exists."
      : gpuPagesZeroed && cloudBlobDecryptableWithUserKey
        ? "Server yields 0 bytes: Enclave HBM is 0x00 and MongoDB holds only an opaque AES-256-GCM blob that requires your local K_freeze key."
        : "Enclave still holds live HBM pages; click Pop to zeroize the hardware bubble before closing your session.";

  return {
    actionsExecuted: actions,
    gpuPagesZeroed,
    gpuActiveBytesRemaining,
    gpuHexPreview,
    hostDumpReadableBytes,
    hostDumpHexPreview: bytesToHex(hostCipherSample),
    freezeBlobSavedInMongo: freezeBlobCiphertext !== null,
    userFreezeSecretPresent,
    cloudBlobDecryptableWithUserKey,
    cloudBlobDecryptableByServer: false,
    subpoenaYieldSummary,
    timelineLog,
  };
}
