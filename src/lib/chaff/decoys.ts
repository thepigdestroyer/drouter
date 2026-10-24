import { BASE_BUCKET_TOKENS, bucketForTokens, estimateTokens } from "../privacy/padding";

export const DECOY_DOMAINS = [
  "systems engineering",
  "molecular biology",
  "quantitative finance",
  "contract law",
  "distributed systems",
  "compiler optimization",
] as const;

export type DecoyDomain = (typeof DECOY_DOMAINS)[number];

export interface DecoySlot {
  slotIndex: number;
  isDecoy: boolean;
  domain: string;
  prompt: string;
  paddedBucketBytes: number;
  jitterMs: number;
}

export interface DecoyBundle {
  k: number;
  realSlotIndex: number;
  entropyBits: number;
  adversaryGuessProbability: number;
  slots: DecoySlot[];
  extractRealReply<T>(replies: T[]): T;
}

const DOMAIN_PROMPT_TEMPLATES: Record<DecoyDomain, readonly string[]> = {
  "systems engineering": [
    "Analyze the thermal dissipation budget and PCIe Gen5 lane bifurcation trade-offs for a dual-socket EPYC 9654 chassis operating under sustained 400W TDP per socket in a 2U rackmount enclosure.",
    "Derive the reliability block diagram and mean time between failures (MTBF) for a triple-modular redundant flight control actuator bus with active cross-strapping and cold-spare switching latency under 2 ms.",
    "Evaluate NVMe-oF over RDMA RoCEv2 congestion notification parameters (DCQCN) when saturating a 200GbE leaf-spine fabric with 64KB random read I/O workloads.",
  ],
  "molecular biology": [
    "Explain how Western blot transfer efficiency changes with PVDF versus nitrocellulose membrane pore size for proteins above 200 kDa.",
    "Explain the allosteric conformational transition of the F1Fo-ATP synthase rotary catalytic mechanism under proton-motive force disequilibrium in mammalian mitochondrial cristae.",
    "Design a multiplexed RT-qPCR primer and hydrolysis probe panel for quantifying single-nucleotide splice variants in the BRCA1 RING domain while preventing primer-dimer amplification.",
  ],
  "quantitative finance": [
    "Formulate the Heston stochastic volatility calibration objective under risk-neutral measure for short-dated S&P 500 variance swaps with jump-diffusion tail corrections.",
    "Derive the optimal execution trajectory under an Almgren-Chriss market impact model with temporary power-law slippage and intraday order-book resilience decay.",
    "Compute the credit valuation adjustment (CVA) sensitivities and wrong-way risk exposure for a cross-currency basis swap portfolio under a Hull-White two-factor interest rate model.",
  ],
  "contract law": [
    "Draft a mutual indemnification and limitation of liability carve-out clause for a cross-border SaaS data processing addendum governed by Delaware law and GDPR Article 28 processor obligations.",
    "Analyze the enforceability of an intellectual property background-license reservation and derivative works assignment provision in a joint technology development agreement under New York commercial precedent.",
    "Evaluate material adverse effect (MAE) definition exclusions and specific performance remedies in a reverse triangular merger agreement subject to antitrust divestiture covenants.",
  ],
  "distributed systems": [
    "Prove linearizability preservation during leader lease transfer in a multi-group Raft consensus cluster when network partitions isolate a minority quorum with asymmetric clock drift.",
    "Design a conflict-free replicated data type (CRDT) state-based causal sequence for collaborative document editing with bounded tombstones and epoch-based garbage collection.",
    "Analyze tail-latency amplification in a fan-out microservice graph using hedged requests and adaptive token-bucket load shedding under bimodal service-time distributions.",
  ],
  "compiler optimization": [
    "Explain how polyhedral loop nest transformation and tile-size selection interact with AVX-512 register pressure and L1 data cache associativity in dense matrix multiplication kernels.",
    "Construct an SSA-based sparse conditional constant propagation (SCCP) lattice transfer function that simultaneously resolves unreachable control-flow edges and phi-node congruence classes.",
    "Compare graph-coloring Chaitin-Briggs register allocation with linear-scan allocation on SSA form when compiling high-arity closures with frequent safepoint spill slots.",
  ],
};

const utf8Encoder = new TextEncoder();

/**
 * Cryptographically secure random 32-bit unsigned integer via Web Crypto API.
 */
function csprngUint32(): number {
  const buf = new Uint32Array(1);
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(buf);
    return buf[0];
  }
  throw new Error("CSPRNG unavailable: globalThis.crypto.getRandomValues is required");
}

/**
 * Unbiased uniform random integer in `[0, maxExclusive)` using rejection sampling.
 */
export function csprngRandomInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error(`maxExclusive must be a positive integer, got ${maxExclusive}`);
  }
  if (maxExclusive === 1) return 0;

  const maxUint32PlusOne = 0x100000000; // 2^32
  const limit = maxUint32PlusOne - (maxUint32PlusOne % maxExclusive);
  let sample = csprngUint32();
  while (sample >= limit) {
    sample = csprngUint32();
  }
  return sample % maxExclusive;
}

/**
 * Uniform open-interval float in `(0, 1)` from CSPRNG for exponential sampling.
 */
function csprngUniformOpen01(): number {
  // Map [0, 2^32 - 1] into (0, 1) strictly away from 0 and 1
  return (csprngUint32() + 0.5) / 0x100000000;
}

/**
 * Sample an exponential inter-arrival delay (`-meanMs * ln(1 - U)`), rounded to 2 decimal places.
 */
export function sampleExponentialJitterMs(meanMs = 35): number {
  const u = csprngUniformOpen01();
  const sample = -meanMs * Math.log(1 - u);
  return Math.max(1, Math.round(sample * 100) / 100);
}

/**
 * CSPRNG Fisher-Yates in-place shuffle.
 */
export function csprngShuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = csprngRandomInt(i + 1);
    const tmp = items[i];
    items[i] = items[j];
    items[j] = tmp;
  }
  return items;
}

/**
 * Compute wire-padded bucket size in bytes (`2^j * 1,024` tokens * 4 bytes/token).
 */
export function computePaddedBucketBytes(prompt: string): {
  bucketTokens: number;
  paddedBucketBytes: number;
} {
  const tokens = estimateTokens(prompt);
  const bucket = bucketForTokens(tokens);
  const bucketTokens = Math.max(BASE_BUCKET_TOKENS, bucket.bucketTokens);
  return {
    bucketTokens,
    paddedBucketBytes: bucketTokens * 4,
  };
}

/**
 * Build a believable decoy prompt for `domain` whose token estimate lands in the same
 * `targetBucketTokens` power-of-two bucket (`2^j * 1,024` tokens) as the real prompt.
 */
function synthesizeBucketMatchedDecoyPrompt(
  domain: DecoyDomain,
  targetBucketTokens: number,
  variantIndex: number,
): string {
  const templates = DOMAIN_PROMPT_TEMPLATES[domain];
  const basePrompt = templates[variantIndex % templates.length];

  if (targetBucketTokens <= BASE_BUCKET_TOKENS) {
    return basePrompt;
  }

  // Target token count inside the lower half of the target bucket so it resolves to `targetBucketTokens`
  const minTokensForBucket = Math.floor(targetBucketTokens / 2) + 8;
  const minBytesForBucket = minTokensForBucket * 4;
  const currentBytes = utf8Encoder.encode(basePrompt).byteLength;

  if (currentBytes >= minBytesForBucket) {
    return basePrompt;
  }

  const supplementalClauses = templates.join(" Furthermore, provide quantitative sensitivity bounds and formal verification invariants. ");
  let expanded = basePrompt;
  let appendixIndex = 1;
  while (utf8Encoder.encode(expanded).byteLength < minBytesForBucket) {
    expanded += `\n[Context Block ${appendixIndex} - ${domain}]: ${supplementalClauses}`;
    appendixIndex += 1;
  }

  // Ensure we did not overshoot `targetBucketTokens` in UTF-8 bytes
  const maxBytesForBucket = targetBucketTokens * 4;
  const encodedBytes = utf8Encoder.encode(expanded);
  if (encodedBytes.byteLength > maxBytesForBucket) {
    expanded = new TextDecoder().decode(encodedBytes.subarray(0, maxBytesForBucket - 16));
  }

  return expanded;
}

/**
 * Generates a k-anonymity decoy bundle containing the real prompt and `k - 1`
 * domain-diverse decoy prompts matched to the real prompt's `2^j * 1,024` token bucket,
 * shuffled with a CSPRNG Fisher-Yates permutation.
 */
export function createDecoyBundle(realPrompt: string, k = 4): DecoyBundle {
  if (!Number.isInteger(k) || k < 1) {
    throw new Error(`Anonymity set size k must be an integer >= 1, got ${k}`);
  }

  const { bucketTokens, paddedBucketBytes } = computePaddedBucketBytes(realPrompt);

  // Pick diverse decoy domains using a CSPRNG-shuffled rotation
  const shuffledDomains = csprngShuffle([...DECOY_DOMAINS]);

  interface UnassignedCandidate {
    isDecoy: boolean;
    domain: string;
    prompt: string;
  }

  const candidates: UnassignedCandidate[] = [
    {
      isDecoy: false,
      domain: "user",
      prompt: realPrompt,
    },
  ];

  for (let i = 0; i < k - 1; i++) {
    const domain = shuffledDomains[i % shuffledDomains.length];
    const variantOffset = csprngRandomInt(DOMAIN_PROMPT_TEMPLATES[domain].length);
    const decoyPrompt = synthesizeBucketMatchedDecoyPrompt(domain, bucketTokens, variantOffset + i);
    candidates.push({
      isDecoy: true,
      domain,
      prompt: decoyPrompt,
    });
  }

  // Shuffle all k candidates with CSPRNG Fisher-Yates
  csprngShuffle(candidates);

  let realSlotIndex = -1;
  let cumulativeJitterMs = 0;

  const slots: DecoySlot[] = candidates.map((candidate, idx) => {
    if (!candidate.isDecoy) {
      realSlotIndex = idx;
    }
    const interArrivalMs = idx === 0 ? 0 : sampleExponentialJitterMs(35);
    cumulativeJitterMs = Math.round((cumulativeJitterMs + interArrivalMs) * 100) / 100;

    return {
      slotIndex: idx,
      isDecoy: candidate.isDecoy,
      domain: candidate.domain,
      prompt: candidate.prompt,
      paddedBucketBytes,
      jitterMs: cumulativeJitterMs,
    };
  });

  const adversaryGuessProbability = 1 / k;
  const rawEntropy = k === 1 ? 0 : Math.log2(k);
  const entropyBits = Math.round(rawEntropy * 1e6) / 1e6;

  return {
    k,
    realSlotIndex,
    entropyBits,
    adversaryGuessProbability,
    slots,
    extractRealReply<T>(replies: T[]): T {
      if (!Array.isArray(replies) || replies.length < k || realSlotIndex < 0 || realSlotIndex >= replies.length) {
        throw new Error(
          `Expected at least ${k} replies to extract slot ${realSlotIndex}, got ${Array.isArray(replies) ? replies.length : "non-array"}`,
        );
      }
      return replies[realSlotIndex];
    },
  };
}
