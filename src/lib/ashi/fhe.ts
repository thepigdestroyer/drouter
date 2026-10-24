import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { embedDocumentText, normalizeVectorL2 } from "@/lib/atlas/embeddings";

/**
 * Real CKKS Fully Homomorphic Encryption (FHE) linear classifier & dot-product engine
 * backed by Microsoft SEAL 4.1.2 (compiled to WebAssembly via `node-seal` 7.0.0).
 *
 * Explicit scope disclosure:
 * - This module executes a real, cryptographically sound CKKS homomorphic computation
 *   (4-class encrypted linear classifier + encrypted L2-norm check over a 128-dimensional
 *   embedding vector) where the server NEVER sees plaintext or secret keys.
 */

export const FHE_SCOPE_DISCLOSURE =
  "Tier C (node-seal 7.0.0 / Microsoft SEAL 4.1.2 WASM) executes a real CKKS homomorphic linear classifier (4x128 matrix-vector dot products + encrypted squared L2 norm) over a 128-d embedding where the server never sees plaintext or the secret key." as const;

export const FHE_SCHEME = "CKKS" as const;
export const FHE_POLY_MODULUS_DEGREE = 4096 as const;
export const FHE_SECURITY_LEVEL_BITS = 128 as const;
export const FHE_COEFF_MODULUS_BITS = [40, 28, 41] as const;
export const FHE_SCALE_BITS = 28 as const;
export const FHE_SCALE = Math.pow(2, FHE_SCALE_BITS);
// The FHE classifier is a fixed 128-d model, independent of the search embedding size.
export const FHE_VECTOR_DIM = 128;

/** Folds a local embedding of any length into the 128-d FHE input space and L2-normalizes it. */
export function toFheVector(vec: readonly number[]): number[] {
  if (vec.length === FHE_VECTOR_DIM) return Array.from(vec);
  const folded = new Array<number>(FHE_VECTOR_DIM).fill(0);
  for (let i = 0; i < vec.length; i++) folded[i % FHE_VECTOR_DIM] += vec[i];
  return normalizeVectorL2(folded);
}
export const FHE_BLOCK_STRIDE = 256 as const; // Power-of-two slot stride (>= 2 * 128) preventing wrap-around contamination during rotation-sum
export const FHE_ROTATION_STEPS = [1, 2, 4, 8, 16, 32, 64] as const;

export interface FheScoringClassSpec {
  id:
    | "hardware-bus-interposer-defense"
    | "enclave-remote-attestation"
    | "cryptographic-fhe-mpc-routing"
    | "onchain-accountability-slashing";
  label: string;
  description: string;
  anchorText: string;
  bias: number;
}

export const FHE_SCORING_CLASSES: readonly FheScoringClassSpec[] = [
  {
    id: "hardware-bus-interposer-defense",
    label: "Hardware Memory-Bus & Interposer Defense",
    description:
      "TEE.fail DDR5 riser probing, AES-XTS static IV leaks, soldered HBM/LPDDR5X allowlists, and SPDM 1.2 TEE-IO device binding.",
    anchorText:
      "tee.fail interposer ddr5 memory bus dimm aes-xts static iv ddrop cipherleaks voltpillager riser-proof soldered memory spdm 1.2 tdisp tee-io monotonic nonce aes-256-gcm zeroization hbm wipe",
    bias: 0.12,
  },
  {
    id: "enclave-remote-attestation",
    label: "Hardware Enclave & Remote Attestation",
    description:
      "AMD SEV-SNP VCEK quotes, Intel TDX DCAP Quote v4, 8x NVIDIA H100/B200 Confidential Computing GPUs, HPKE RFC 9180, and Sigstore Rekor.",
    anchorText:
      "amd sev-snp vcek milan genoa turin intel tdx dcap mrtd rtmr quote v4 8x gpu b200 h100 nvidia cc confidential computing hpke rfc 9180 ehbp ml-kem-768 sigstore rekor dm-verity",
    bias: 0.08,
  },
  {
    id: "cryptographic-fhe-mpc-routing",
    label: "Zero-Silicon-Trust FHE & Oblivious Routing",
    description:
      "CKKS homomorphic encryption, RLWE ciphertext evaluation, Galois key rotations, OHTTP metadata stripping, and blind-signed credits.",
    anchorText:
      "zero knowledge halo2 plonky3 fhe mpc 3pc speculative split ashi ohttp rfc 9458 oblivious http chaff decoy traffic rsa blind credit nullifier stylometry pii scrubber compartment",
    bias: 0.15,
  },
  {
    id: "onchain-accountability-slashing",
    label: "On-Chain Registry, Canary Traps & Economic Slashing",
    description:
      "Circle Arc Testnet attestation anchoring, canary honeytoken traps, Wald SPRT model downgrade detection, and operator share caps.",
    anchorText:
      "circle arc blockchain on-chain attestation usdc settlement contract anchor canary trap honeypot bounty slashing stake operator cap sprt wald sequential latency audit shamir threshold",
    bias: 0.05,
  },
] as const;

export interface PublicScoringMatrix {
  dimensions: number;
  numClasses: number;
  blockStride: number;
  classes: {
    id: FheScoringClassSpec["id"];
    label: string;
    description: string;
    bias: number;
    weights: number[];
  }[];
  matrixDigestSha256: string;
}

let cachedScoringMatrix: PublicScoringMatrix | null = null;

/**
 * Builds the deterministic public 4x128 scoring matrix W and bias vector b
 * used by the server to evaluate encrypted dot products `W * Enc(x) + b`.
 */
export function getPublicScoringMatrix(): PublicScoringMatrix {
  if (cachedScoringMatrix) {
    return cachedScoringMatrix;
  }

  const classes = FHE_SCORING_CLASSES.map((spec) => {
    const emb = embedDocumentText(spec.anchorText);
    return {
      id: spec.id,
      label: spec.label,
      description: spec.description,
      bias: spec.bias,
      weights: toFheVector(emb.vector),
    };
  });

  const canonical = JSON.stringify({
    dimensions: FHE_VECTOR_DIM,
    blockStride: FHE_BLOCK_STRIDE,
    classes: classes.map((c) => ({
      id: c.id,
      bias: c.bias,
      weights: c.weights,
    })),
  });
  const matrixDigestSha256 = bytesToHex(sha256(utf8ToBytes(canonical)));

  cachedScoringMatrix = {
    dimensions: FHE_VECTOR_DIM,
    numClasses: classes.length,
    blockStride: FHE_BLOCK_STRIDE,
    classes,
    matrixDigestSha256,
  };

  return cachedScoringMatrix;
}

/**
 * Computes the reference plaintext linear classifier scores `W * x + b` and squared L2 norm
 * so clients/tests can verify the homomorphic decryption accuracy.
 */
export function computePlaintextReferenceScores(vector128: readonly number[]): {
  scores: { id: FheScoringClassSpec["id"]; label: string; score: number }[];
  predictedClassId: FheScoringClassSpec["id"];
  squaredL2Norm: number;
} {
  if (vector128.length !== FHE_VECTOR_DIM) {
    throw new Error(
      `Expected ${FHE_VECTOR_DIM}-d vector, got length ${vector128.length}`,
    );
  }

  const matrix = getPublicScoringMatrix();
  let squaredL2Norm = 0;
  for (let i = 0; i < FHE_VECTOR_DIM; i++) {
    squaredL2Norm += vector128[i] * vector128[i];
  }

  const scores = matrix.classes.map((cls) => {
    let dot = cls.bias;
    for (let i = 0; i < FHE_VECTOR_DIM; i++) {
      dot += cls.weights[i] * vector128[i];
    }
    return {
      id: cls.id,
      label: cls.label,
      score: Number(dot.toFixed(6)),
    };
  });

  let best = scores[0];
  for (const s of scores) {
    if (s.score > best.score) {
      best = s;
    }
  }

  return {
    scores,
    predictedClassId: best.id,
    squaredL2Norm: Number(squaredL2Norm.toFixed(6)),
  };
}

type SealMainModule = Awaited<ReturnType<typeof import("node-seal")["default"]>>;

interface SealRuntimeBundle {
  seal: SealMainModule;
  context: InstanceType<SealMainModule["SEALContext"]>;
  wasmInitMs: number;
}

let sealRuntimePromise: Promise<SealRuntimeBundle> | null = null;

/**
 * Lazily initializes the Microsoft SEAL WebAssembly runtime and CKKS SEALContext
 * via dynamic import so Next.js builds and server/client bundles stay clean.
 */
export async function getSealRuntime(): Promise<SealRuntimeBundle> {
  if (!sealRuntimePromise) {
    sealRuntimePromise = (async () => {
      const t0 = performance.now();
      const mod = await import("node-seal");
      const SEAL = mod.default;
      const seal = await SEAL();
      const encParms = new seal.EncryptionParameters(seal.SchemeType.ckks);
      encParms.setPolyModulusDegree(FHE_POLY_MODULUS_DEGREE);
      const bitSizes = Int32Array.from(FHE_COEFF_MODULUS_BITS);
      const coeffModulus = seal.CoeffModulus.Create(
        FHE_POLY_MODULUS_DEGREE,
        bitSizes,
      );
      encParms.setCoeffModulus(coeffModulus);
      const context = new seal.SEALContext(
        encParms,
        true,
        seal.SecLevelType.tc128,
      );
      coeffModulus.delete();
      encParms.delete();
      if (!context.parametersSet()) {
        throw new Error("SEAL CKKS parameters failed validation");
      }
      const wasmInitMs = Number((performance.now() - t0).toFixed(2));
      return { seal, context, wasmInitMs };
    })();
  }
  return sealRuntimePromise;
}

export interface FheClientKeyMaterial {
  /** Secret key stays strictly with the client; NEVER transmitted to the server. */
  secretKeyBase64: string;
  publicKeyBase64: string;
  relinKeysBase64: string;
  galoisKeysBase64: string;
  keyGenLatencyMs: number;
  sizesBytes: {
    publicKeyBytes: number;
    relinKeysBytes: number;
    galoisKeysBytes: number;
  };
}

export interface FheEncryptedRequestPayload {
  ciphertextBase64: string;
  publicKeyBase64?: string;
  relinKeysBase64: string;
  galoisKeysBase64: string;
}

export interface FheClientEncryptionBundle {
  /** Payload safe to transmit to the untrusted FHE server (contains zero plaintext and no secret key). */
  requestPayload: FheEncryptedRequestPayload;
  /** Client-only secret key for decrypting the server's response ciphertext. */
  secretKeyBase64: string;
  /** Local 128-d input vector that was encrypted (kept locally for verification). */
  inputVector128: number[];
  embeddingModel: string;
  timingsMs: {
    wasmInitMs: number;
    keyGenMs: number;
    encodeAndEncryptMs: number;
  };
  sizesBytes: {
    ciphertextBytes: number;
    publicKeyBytes: number;
    relinKeysBytes: number;
    galoisKeysBytes: number;
  };
}

export interface FheServerEvaluationResult {
  scheme: typeof FHE_SCHEME;
  polyModulusDegree: typeof FHE_POLY_MODULUS_DEGREE;
  securityLevelBits: typeof FHE_SECURITY_LEVEL_BITS;
  coeffModulusBits: readonly number[];
  scaleBits: typeof FHE_SCALE_BITS;
  scopeDisclosure: string;
  serverSawPlaintext: false;
  serverSawSecretKey: false;
  resultCiphertextBase64: string;
  normCiphertextBase64: string;
  matrixDigestSha256: string;
  timingsMs: {
    wasmInitMs: number;
    deserializeKeysAndCiphertextMs: number;
    homomorphicLinearClassifyMs: number;
    homomorphicNormSquareMs: number;
    serializeResultMs: number;
    totalServerEvalMs: number;
  };
  sizesBytes: {
    inputCiphertextBytes: number;
    relinKeysBytes: number;
    galoisKeysBytes: number;
    resultCiphertextBytes: number;
    normCiphertextBytes: number;
  };
}

export interface FheDecryptedResult {
  scores: {
    id: FheScoringClassSpec["id"];
    label: string;
    fheScore: number;
    plaintextExpectedScore?: number;
    absError?: number;
  }[];
  predictedClassId: FheScoringClassSpec["id"];
  predictedClassLabel: string;
  fheSquaredL2Norm: number;
  expectedSquaredL2Norm?: number;
  normAbsError?: number;
  maxScoreAbsError?: number;
  decryptLatencyMs: number;
}

function base64ByteLength(b64: string): number {
  const clean = b64.trim();
  if (!clean) return 0;
  let padding = 0;
  if (clean.endsWith("==")) padding = 2;
  else if (clean.endsWith("=")) padding = 1;
  return Math.floor((clean.length * 3) / 4) - padding;
}

/**
 * Client-side helper: generates a fresh CKKS keypair + relinearization keys + Galois rotation keys,
 * and encrypts a 128-d vector (or text embedded locally into 128-d) replicated across 4 class blocks.
 * The secret key is returned separately for client decryption and is excluded from `requestPayload`.
 */
export async function clientEncryptVector128(
  input: { text?: string; vector128?: readonly number[] },
  existingKeys?: FheClientKeyMaterial,
): Promise<FheClientEncryptionBundle> {
  const { seal, context, wasmInitMs } = await getSealRuntime();

  let vector128: number[];
  let embeddingModel = "caller-supplied-128d";
  if (input.vector128 && input.vector128.length === FHE_VECTOR_DIM) {
    vector128 = Array.from(input.vector128);
  } else {
    const emb = embedDocumentText(
      input.text ??
        "Verify AMD SEV-SNP and SPDM 1.2 TEE-IO riser-proof memory protection against DDR5 bus interposers.",
    );
    vector128 = toFheVector(emb.vector);
    embeddingModel = `${emb.model} folded to ${FHE_VECTOR_DIM}-d`;
  }

  let secretKeyBase64: string;
  let publicKeyBase64: string;
  let relinKeysBase64: string;
  let galoisKeysBase64: string;
  let keyGenMs = 0;

  const publicKey = new seal.PublicKey();

  try {
    if (existingKeys) {
      secretKeyBase64 = existingKeys.secretKeyBase64;
      publicKeyBase64 = existingKeys.publicKeyBase64;
      relinKeysBase64 = existingKeys.relinKeysBase64;
      galoisKeysBase64 = existingKeys.galoisKeysBase64;
      keyGenMs = existingKeys.keyGenLatencyMs;
      publicKey.loadFromBase64(context, publicKeyBase64);
    } else {
      const tKey0 = performance.now();
      const keyGen = new seal.KeyGenerator(context);
      const secretKey = keyGen.secretKey();
      const pubSer = keyGen.createPublicKeySerializable();
      const relinSer = keyGen.createRelinKeysSerializable();
      const galoisSteps = Int32Array.from(FHE_ROTATION_STEPS);
      const galoisSer = keyGen.createGaloisKeysSerializableWithSteps(galoisSteps);

      secretKeyBase64 = secretKey.saveToBase64(seal.ComprModeType.zstd);
      publicKeyBase64 = pubSer.saveToBase64(seal.ComprModeType.zstd);
      relinKeysBase64 = relinSer.saveToBase64(seal.ComprModeType.zstd);
      galoisKeysBase64 = galoisSer.saveToBase64(seal.ComprModeType.zstd);

      pubSer.delete();
      relinSer.delete();
      galoisSer.delete();
      secretKey.delete();
      keyGen.delete();

      publicKey.loadFromBase64(context, publicKeyBase64);
      keyGenMs = Number((performance.now() - tKey0).toFixed(2));
    }

    const tEnc0 = performance.now();
    const encoder = new seal.CKKSEncoder(context);
    const encryptor = new seal.Encryptor(context, publicKey);
    const slotCount = encoder.slotCount(); // 2048 slots for N=4096

    // Replicate the 128-d vector across 4 disjoint blocks of stride 256 slots
    // so all 4 class dot products can be evaluated in parallel in a single ciphertext.
    const packedSlots = new Float64Array(slotCount);
    for (let c = 0; c < FHE_SCORING_CLASSES.length; c++) {
      const offset = c * FHE_BLOCK_STRIDE;
      for (let i = 0; i < FHE_VECTOR_DIM; i++) {
        packedSlots[offset + i] = vector128[i];
      }
    }

    const pt = new seal.Plaintext();
    encoder.encode(packedSlots, FHE_SCALE, pt);
    const ctSer = encryptor.encryptSerializable(pt);
    const ciphertextBase64 = ctSer.saveToBase64(seal.ComprModeType.zstd);

    ctSer.delete();
    pt.delete();
    encryptor.delete();
    encoder.delete();

    const encodeAndEncryptMs = Number((performance.now() - tEnc0).toFixed(2));

    const ciphertextBytes = base64ByteLength(ciphertextBase64);
    const publicKeyBytes = base64ByteLength(publicKeyBase64);
    const relinKeysBytes = base64ByteLength(relinKeysBase64);
    const galoisKeysBytes = base64ByteLength(galoisKeysBase64);

    return {
      requestPayload: {
        ciphertextBase64,
        publicKeyBase64,
        relinKeysBase64,
        galoisKeysBase64,
      },
      secretKeyBase64,
      inputVector128: vector128,
      embeddingModel,
      timingsMs: {
        wasmInitMs,
        keyGenMs,
        encodeAndEncryptMs,
      },
      sizesBytes: {
        ciphertextBytes,
        publicKeyBytes,
        relinKeysBytes,
        galoisKeysBytes,
      },
    };
  } finally {
    publicKey.delete();
  }
}

/**
 * Server-side homomorphic evaluation:
 * Receives ONLY `ciphertextBase64`, `relinKeysBase64`, and `galoisKeysBase64` (never the secret key or plaintext).
 * Computes:
 * 1. Encrypted 4-class linear classifier `W * Enc(x) + b` via CKKS `multiplyPlain`, `rescaleToNextInplace`,
 *    7 log2(128) Galois `rotateVector` + `addInplace` steps, and bias `addPlainInplace`.
 * 2. Encrypted squared L2 norm `sum(x_i^2)` via ciphertext-ciphertext `square`, `relinearizeInplace`
 *    (using the client's relinearization keys), `rescaleToNextInplace`, and Galois rotation-sums.
 */
export async function serverEvaluateEncryptedLinearScores(
  payload: FheEncryptedRequestPayload,
): Promise<FheServerEvaluationResult> {
  if (
    !payload ||
    typeof payload.ciphertextBase64 !== "string" ||
    !payload.ciphertextBase64.trim()
  ) {
    throw new Error("Missing required ciphertextBase64 in FHE request");
  }
  if (
    typeof payload.relinKeysBase64 !== "string" ||
    !payload.relinKeysBase64.trim()
  ) {
    throw new Error("Missing required relinKeysBase64 in FHE request");
  }
  if (
    typeof payload.galoisKeysBase64 !== "string" ||
    !payload.galoisKeysBase64.trim()
  ) {
    throw new Error("Missing required galoisKeysBase64 in FHE request");
  }

  const { seal, context, wasmInitMs } = await getSealRuntime();
  const matrix = getPublicScoringMatrix();

  const tTotal0 = performance.now();
  const tDeser0 = performance.now();

  const srvCt = new seal.Ciphertext();
  const srvRelin = new seal.RelinKeys();
  const srvGal = new seal.GaloisKeys();
  const encoder = new seal.CKKSEncoder(context);
  const evaluator = new seal.Evaluator(context);

  const outCt = new seal.Ciphertext();
  const rotCt = new seal.Ciphertext();
  const sqCt = new seal.Ciphertext();
  const wPt = new seal.Plaintext();
  const bPt = new seal.Plaintext();

  try {
    srvCt.loadFromBase64(context, payload.ciphertextBase64);
    srvRelin.loadFromBase64(context, payload.relinKeysBase64);
    srvGal.loadFromBase64(context, payload.galoisKeysBase64);

    const deserializeKeysAndCiphertextMs = Number(
      (performance.now() - tDeser0).toFixed(2),
    );

    const slotCount = encoder.slotCount();

    // 1. Homomorphic 4x128 Linear Classification: W * Enc(x) + b
    const tLin0 = performance.now();
    const wPacked = new Float64Array(slotCount);
    for (let c = 0; c < matrix.classes.length; c++) {
      const offset = c * FHE_BLOCK_STRIDE;
      const weights = matrix.classes[c].weights;
      for (let i = 0; i < FHE_VECTOR_DIM; i++) {
        wPacked[offset + i] = weights[i];
      }
    }

    encoder.encode(wPacked, FHE_SCALE, wPt);
    evaluator.multiplyPlain(srvCt, wPt, outCt);
    evaluator.rescaleToNextInplace(outCt);

    for (const step of FHE_ROTATION_STEPS) {
      evaluator.rotateVector(outCt, step, srvGal, rotCt);
      evaluator.addInplace(outCt, rotCt);
    }

    // Add public per-class bias at the rescaled level & scale
    const bPacked = new Float64Array(slotCount);
    for (let c = 0; c < matrix.classes.length; c++) {
      bPacked[c * FHE_BLOCK_STRIDE] = matrix.classes[c].bias;
    }
    encoder.encode(bPacked, outCt.scale(), bPt);
    evaluator.plainModSwitchToInplace(bPt, outCt.parmsId());
    evaluator.addPlainInplace(outCt, bPt);

    const homomorphicLinearClassifyMs = Number(
      (performance.now() - tLin0).toFixed(2),
    );

    // 2. Homomorphic non-linear degree-2 L2 norm check: Enc(x) * Enc(x) + Relinearize + Rescale + Rotate-Sum
    const tNorm0 = performance.now();
    evaluator.square(srvCt, sqCt);
    evaluator.relinearizeInplace(sqCt, srvRelin);
    evaluator.rescaleToNextInplace(sqCt);
    for (const step of FHE_ROTATION_STEPS) {
      evaluator.rotateVector(sqCt, step, srvGal, rotCt);
      evaluator.addInplace(sqCt, rotCt);
    }
    const homomorphicNormSquareMs = Number(
      (performance.now() - tNorm0).toFixed(2),
    );

    // 3. Serialize encrypted outputs
    const tSer0 = performance.now();
    const resultCiphertextBase64 = outCt.saveToBase64(seal.ComprModeType.zstd);
    const normCiphertextBase64 = sqCt.saveToBase64(seal.ComprModeType.zstd);
    const serializeResultMs = Number((performance.now() - tSer0).toFixed(2));
    const totalServerEvalMs = Number((performance.now() - tTotal0).toFixed(2));

    return {
      scheme: FHE_SCHEME,
      polyModulusDegree: FHE_POLY_MODULUS_DEGREE,
      securityLevelBits: FHE_SECURITY_LEVEL_BITS,
      coeffModulusBits: FHE_COEFF_MODULUS_BITS,
      scaleBits: FHE_SCALE_BITS,
      scopeDisclosure: FHE_SCOPE_DISCLOSURE,
      serverSawPlaintext: false,
      serverSawSecretKey: false,
      resultCiphertextBase64,
      normCiphertextBase64,
      matrixDigestSha256: matrix.matrixDigestSha256,
      timingsMs: {
        wasmInitMs,
        deserializeKeysAndCiphertextMs,
        homomorphicLinearClassifyMs,
        homomorphicNormSquareMs,
        serializeResultMs,
        totalServerEvalMs,
      },
      sizesBytes: {
        inputCiphertextBytes: base64ByteLength(payload.ciphertextBase64),
        relinKeysBytes: base64ByteLength(payload.relinKeysBase64),
        galoisKeysBytes: base64ByteLength(payload.galoisKeysBase64),
        resultCiphertextBytes: base64ByteLength(resultCiphertextBase64),
        normCiphertextBytes: base64ByteLength(normCiphertextBase64),
      },
    };
  } finally {
    bPt.delete();
    wPt.delete();
    sqCt.delete();
    rotCt.delete();
    outCt.delete();
    evaluator.delete();
    encoder.delete();
    srvGal.delete();
    srvRelin.delete();
    srvCt.delete();
  }
}

/**
 * Client-side decryption helper: uses the client's private `secretKeyBase64` to decrypt
 * `resultCiphertextBase64` and `normCiphertextBase64` and compare against optional plaintext reference.
 */
export async function clientDecryptEvaluationResult(params: {
  secretKeyBase64: string;
  resultCiphertextBase64: string;
  normCiphertextBase64: string;
  referenceVector128?: readonly number[];
}): Promise<FheDecryptedResult> {
  const { seal, context } = await getSealRuntime();
  const matrix = getPublicScoringMatrix();

  const t0 = performance.now();
  const secretKey = new seal.SecretKey();
  const resCt = new seal.Ciphertext();
  const normCt = new seal.Ciphertext();
  const resPt = new seal.Plaintext();
  const normPt = new seal.Plaintext();
  let decryptor: InstanceType<SealMainModule["Decryptor"]> | null = null;
  let encoder: InstanceType<SealMainModule["CKKSEncoder"]> | null = null;

  try {
    secretKey.loadFromBase64(context, params.secretKeyBase64);
    resCt.loadFromBase64(context, params.resultCiphertextBase64);
    normCt.loadFromBase64(context, params.normCiphertextBase64);

    decryptor = new seal.Decryptor(context, secretKey);
    encoder = new seal.CKKSEncoder(context);

    decryptor.decrypt(resCt, resPt);
    const decodedScores = encoder.decodeFloat64(resPt) as Float64Array;

    decryptor.decrypt(normCt, normPt);
    const decodedNorm = encoder.decodeFloat64(normPt) as Float64Array;

    const reference =
      params.referenceVector128 &&
      params.referenceVector128.length === FHE_VECTOR_DIM
        ? computePlaintextReferenceScores(params.referenceVector128)
        : null;

    let maxScoreAbsError = 0;
    const scores = matrix.classes.map((cls, idx) => {
      const fheScore = Number(decodedScores[idx * FHE_BLOCK_STRIDE].toFixed(6));
      const expected = reference?.scores[idx]?.score;
      const absError =
        expected !== undefined
          ? Number(Math.abs(fheScore - expected).toFixed(6))
          : undefined;
      if (absError !== undefined && absError > maxScoreAbsError) {
        maxScoreAbsError = absError;
      }
      return {
        id: cls.id,
        label: cls.label,
        fheScore,
        ...(expected !== undefined ? { plaintextExpectedScore: expected } : {}),
        ...(absError !== undefined ? { absError } : {}),
      };
    });

    let best = scores[0];
    for (const s of scores) {
      if (s.fheScore > best.fheScore) {
        best = s;
      }
    }

    const fheSquaredL2Norm = Number(decodedNorm[0].toFixed(6));
    const expectedSquaredL2Norm = reference?.squaredL2Norm;
    const normAbsError =
      expectedSquaredL2Norm !== undefined
        ? Number(Math.abs(fheSquaredL2Norm - expectedSquaredL2Norm).toFixed(6))
        : undefined;

    const decryptLatencyMs = Number((performance.now() - t0).toFixed(2));

    return {
      scores,
      predictedClassId: best.id,
      predictedClassLabel: best.label,
      fheSquaredL2Norm,
      ...(expectedSquaredL2Norm !== undefined ? { expectedSquaredL2Norm } : {}),
      ...(normAbsError !== undefined ? { normAbsError } : {}),
      ...(reference ? { maxScoreAbsError } : {}),
      decryptLatencyMs,
    };
  } finally {
    encoder?.delete();
    decryptor?.delete();
    normPt.delete();
    resPt.delete();
    normCt.delete();
    resCt.delete();
    secretKey.delete();
  }
}

export interface LiveFheRoundTripMeasurement {
  scheme: typeof FHE_SCHEME;
  library: "node-seal@7.0.0 (Microsoft SEAL 4.1.2 WASM)";
  polyModulusDegree: typeof FHE_POLY_MODULUS_DEGREE;
  securityLevelBits: typeof FHE_SECURITY_LEVEL_BITS;
  coeffModulusBits: readonly number[];
  vectorDimension: number;
  numScoringClasses: number;
  scopeDisclosure: string;
  serverSawPlaintext: false;
  serverSawSecretKey: false;
  embeddingModel: string;
  matrixDigestSha256: string;
  timingsMs: {
    wasmInitMs: number;
    clientKeyGenMs: number;
    clientEncryptMs: number;
    serverDeserializeMs: number;
    serverLinearClassifyMs: number;
    serverNormSquareMs: number;
    serverSerializeMs: number;
    serverTotalEvalMs: number;
    clientDecryptMs: number;
    totalRoundTripMs: number;
  };
  sizesBytes: {
    publicKeyBytes: number;
    relinKeysBytes: number;
    galoisKeysBytes: number;
    inputCiphertextBytes: number;
    resultCiphertextBytes: number;
    normCiphertextBytes: number;
  };
  verification: FheDecryptedResult;
}

/**
 * Executes a full client-encrypt -> server-homomorphic-eval -> client-decrypt round trip
 * with real `node-seal` CKKS ciphertexts and returns measured latencies, byte sizes, and numerical accuracy.
 */
export async function runLiveFheLinearRoundTrip(input?: {
  text?: string;
  vector128?: readonly number[];
}): Promise<LiveFheRoundTripMeasurement> {
  const tAll0 = performance.now();
  const clientBundle = await clientEncryptVector128(input ?? {});
  const serverResult = await serverEvaluateEncryptedLinearScores(
    clientBundle.requestPayload,
  );
  const decrypted = await clientDecryptEvaluationResult({
    secretKeyBase64: clientBundle.secretKeyBase64,
    resultCiphertextBase64: serverResult.resultCiphertextBase64,
    normCiphertextBase64: serverResult.normCiphertextBase64,
    referenceVector128: clientBundle.inputVector128,
  });
  const totalRoundTripMs = Number((performance.now() - tAll0).toFixed(2));

  return {
    scheme: FHE_SCHEME,
    library: "node-seal@7.0.0 (Microsoft SEAL 4.1.2 WASM)",
    polyModulusDegree: FHE_POLY_MODULUS_DEGREE,
    securityLevelBits: FHE_SECURITY_LEVEL_BITS,
    coeffModulusBits: FHE_COEFF_MODULUS_BITS,
    vectorDimension: FHE_VECTOR_DIM,
    numScoringClasses: FHE_SCORING_CLASSES.length,
    scopeDisclosure: FHE_SCOPE_DISCLOSURE,
    serverSawPlaintext: false,
    serverSawSecretKey: false,
    embeddingModel: clientBundle.embeddingModel,
    matrixDigestSha256: serverResult.matrixDigestSha256,
    timingsMs: {
      wasmInitMs: clientBundle.timingsMs.wasmInitMs,
      clientKeyGenMs: clientBundle.timingsMs.keyGenMs,
      clientEncryptMs: clientBundle.timingsMs.encodeAndEncryptMs,
      serverDeserializeMs:
        serverResult.timingsMs.deserializeKeysAndCiphertextMs,
      serverLinearClassifyMs:
        serverResult.timingsMs.homomorphicLinearClassifyMs,
      serverNormSquareMs: serverResult.timingsMs.homomorphicNormSquareMs,
      serverSerializeMs: serverResult.timingsMs.serializeResultMs,
      serverTotalEvalMs: serverResult.timingsMs.totalServerEvalMs,
      clientDecryptMs: decrypted.decryptLatencyMs,
      totalRoundTripMs,
    },
    sizesBytes: {
      publicKeyBytes: clientBundle.sizesBytes.publicKeyBytes,
      relinKeysBytes: clientBundle.sizesBytes.relinKeysBytes,
      galoisKeysBytes: clientBundle.sizesBytes.galoisKeysBytes,
      inputCiphertextBytes: serverResult.sizesBytes.inputCiphertextBytes,
      resultCiphertextBytes: serverResult.sizesBytes.resultCiphertextBytes,
      normCiphertextBytes: serverResult.sizesBytes.normCiphertextBytes,
    },
    verification: decrypted,
  };
}
