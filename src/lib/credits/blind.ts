import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import type { BlindCreditToken } from "@/lib/types";

export const CREDIT_DENOMINATIONS = [1, 5, 20];

const ZERO = BigInt(0);
const ONE = BigInt(1);
const TWO = BigInt(2);
const THREE = BigInt(3);
const RSA_E = BigInt(65537);

/**
 * Distinct coprime public exponents per credit denomination (1 -> 65537, 5 -> 65539, 20 -> 65543)
 * so an attacker cannot blind a high-denomination token and request a low-denomination signature.
 */
const DENOMINATION_EXPONENTS: Record<number, bigint> = {
  1: BigInt(65537),
  5: BigInt(65539),
  20: BigInt(65543),
};

const ALL_DENOMINATION_EXPONENTS = [BigInt(65537), BigInt(65539), BigInt(65543)];

function exponentForDenomination(denomination: number, fallbackE?: string): bigint {
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    throw new Error(`Unsupported credit denomination: ${denomination}`);
  }
  if (denomination === 1 && fallbackE) {
    return hexToBigInt(fallbackE);
  }
  return DENOMINATION_EXPONENTS[denomination] ?? RSA_E;
}

const SMALL_PRIMES = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
  79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
  163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
  241, 251,
].map((p) => BigInt(p));

const MR_BASES = [2, 3, 5, 7, 11, 13, 17, 19].map((b) => BigInt(b));

const keyCache = new Map<
  string,
  { n: string; e: string; d: string; dByDenom: Record<number, string> }
>();

function cleanHex(hex: string): string {
  if (typeof hex !== "string") {
    throw new Error("Expected hex string");
  }
  const trimmed = hex.trim().toLowerCase();
  const withoutPrefix = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  if (!withoutPrefix) return "0";
  if (!/^[0-9a-f]+$/.test(withoutPrefix)) {
    throw new Error("Invalid hex string");
  }
  return withoutPrefix.length % 2 === 1 ? "0" + withoutPrefix : withoutPrefix;
}

function hexToBigInt(hex: string): bigint {
  const cleaned = cleanHex(hex);
  return BigInt("0x" + cleaned);
}

function bigIntToHex(value: bigint): string {
  if (value < ZERO) {
    throw new Error("Cannot serialize negative bigint to hex");
  }
  const hex = value.toString(16);
  return hex.length % 2 === 1 ? "0" + hex : hex;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return hexToBigInt(bytesToHex(bytes));
}

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === ONE) return ZERO;
  let result = ONE;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > ZERO) {
    if ((e & ONE) === ONE) {
      result = (result * b) % mod;
    }
    e >>= ONE;
    b = (b * b) % mod;
  }
  return result;
}

export function gcd(a: bigint, b: bigint): bigint {
  let x = a < ZERO ? -a : a;
  let y = b < ZERO ? -b : b;
  while (y !== ZERO) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

export function modInverse(a: bigint, m: bigint): bigint {
  let oldR = ((a % m) + m) % m;
  let r = m;
  let oldS = ONE;
  let s = ZERO;

  while (r !== ZERO) {
    const q = oldR / r;
    const nextR = oldR - q * r;
    oldR = r;
    r = nextR;

    const nextS = oldS - q * s;
    oldS = s;
    s = nextS;
  }

  if (oldR !== ONE) {
    throw new Error("Modular inverse does not exist");
  }

  return ((oldS % m) + m) % m;
}

function isProbablePrime(n: bigint): boolean {
  if (n < TWO) return false;
  for (let i = 0; i < SMALL_PRIMES.length; i++) {
    const p = SMALL_PRIMES[i];
    if (n === p) return true;
    if (n % p === ZERO) return false;
  }

  let d = n - ONE;
  let s = 0;
  while ((d & ONE) === ZERO) {
    d >>= ONE;
    s++;
  }

  for (let i = 0; i < MR_BASES.length; i++) {
    const a = MR_BASES[i];
    let x = modPow(a, d, n);
    if (x === ONE || x === n - ONE) continue;

    let witnessedComposite = true;
    for (let r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x === n - ONE) {
        witnessedComposite = false;
        break;
      }
    }
    if (witnessedComposite) return false;
  }

  return true;
}

function isCoprimeToAllExponents(pMinusOne: bigint): boolean {
  for (const exp of ALL_DENOMINATION_EXPONENTS) {
    if (pMinusOne % exp === ZERO) return false;
  }
  return true;
}

function deriveDeterministicPrime(seedHex: string, label: string): bigint {
  const ikm = utf8ToBytes("drouter/v1/issuer-seed:" + cleanHex(seedHex));
  const info = utf8ToBytes("drouter/v1/rsa-prime-512:" + label);
  const raw = hkdf(sha256, ikm, undefined, info, 64);
  const candidateBytes = new Uint8Array(raw);
  // Set top two bits so product of two 512-bit primes is always 1024 bits, and bottom bit so it is odd.
  candidateBytes[0] |= 0xc0;
  candidateBytes[63] |= 0x01;

  let candidate = bytesToBigInt(candidateBytes);
  while (true) {
    if (isCoprimeToAllExponents(candidate - ONE) && isProbablePrime(candidate)) {
      return candidate;
    }
    candidate += TWO;
  }
}

function deriveFullIssuerKey(seedHex: string): {
  n: string;
  e: string;
  d: string;
  dByDenom: Record<number, string>;
} {
  const normalizedSeed = cleanHex(seedHex);
  const cached = keyCache.get(normalizedSeed);
  if (cached) return cached;

  const p = deriveDeterministicPrime(normalizedSeed, "p");
  let q = deriveDeterministicPrime(normalizedSeed, "q");
  while (q === p) {
    q += TWO;
    while (!isCoprimeToAllExponents(q - ONE) || !isProbablePrime(q)) {
      q += TWO;
    }
  }

  const n = p * q;
  const phi = (p - ONE) * (q - ONE);
  const d = modInverse(RSA_E, phi);
  const dByDenom: Record<number, string> = {};
  for (const denom of CREDIT_DENOMINATIONS) {
    const exp = exponentForDenomination(denom);
    dByDenom[denom] = bigIntToHex(modInverse(exp, phi));
  }

  const key = {
    n: bigIntToHex(n),
    e: bigIntToHex(RSA_E),
    d: bigIntToHex(d),
    dByDenom,
  };
  keyCache.set(normalizedSeed, key);
  return key;
}

export function deriveIssuerKey(seedHex: string): {
  n: string;
  e: string;
  d: string;
} {
  const { n, e, d } = deriveFullIssuerKey(seedHex);
  return { n, e, d };
}

export function getPublicKey(seedHex: string): {
  n: string;
  e: string;
  denominations: number[];
} {
  const { n, e } = deriveFullIssuerKey(seedHex);
  return {
    n,
    e,
    denominations: [...CREDIT_DENOMINATIONS],
  };
}

/**
 * Full-Domain Hash (FDH) expanding over the full modulus byte length of `n`
 * using HKDF-SHA-256 and rejection/gcd checks so `m` is uniform in Z_n^* (coprime to n, 1 < m < n).
 */
export function hashTokenMessage(
  tokenHex: string,
  denomination: number,
  nHex: string
): bigint {
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    throw new Error(`Unsupported credit denomination: ${denomination}`);
  }
  const cleanN = cleanHex(nHex);
  const n = hexToBigInt(cleanN);
  if (n <= THREE) {
    throw new Error("Invalid RSA modulus n");
  }
  const modulusBytes = Math.max(64, Math.ceil(cleanN.length / 2));
  const normalizedToken = cleanHex(tokenHex);
  const ikm = utf8ToBytes(`${normalizedToken}:${denomination}`);
  const salt = utf8ToBytes(`drouter/v1/credit-fdh-salt:${cleanN}`);
  const info = utf8ToBytes(`drouter/v1/credit-fdh-full:${denomination}`);
  const digest = hkdf(sha256, ikm, salt, info, modulusBytes);

  let m = bytesToBigInt(digest) % n;
  if (m <= ONE) {
    m = TWO;
  }
  while (gcd(m, n) !== ONE) {
    m = (m + ONE) % n;
    if (m <= ONE) m = TWO;
  }
  return m;
}

function randomBlindingFactorHex(byteLength = 128): string {
  if (
    typeof globalThis.crypto === "undefined" ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new Error("CSPRNG unavailable: crypto.getRandomValues is required for blinding");
  }
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  bytes[0] |= 0x01;
  return bytesToHex(bytes);
}

export function blindToken(
  tokenHex: string,
  denomination: number,
  pub: { n: string; e: string },
  rHex?: string
): { blindedHex: string; rHex: string } {
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    throw new Error(`Unsupported credit denomination: ${denomination}`);
  }
  const n = hexToBigInt(pub.n);
  if (n <= THREE) {
    throw new Error("Invalid RSA modulus n");
  }
  const e = exponentForDenomination(denomination, pub.e);
  const m = hashTokenMessage(tokenHex, denomination, pub.n);

  const modulusBytes = Math.max(64, Math.ceil(cleanHex(pub.n).length / 2));
  let chosenRHex = rHex ? cleanHex(rHex) : randomBlindingFactorHex(modulusBytes);
  let r = hexToBigInt(chosenRHex) % n;
  if (r <= ONE) {
    r = THREE;
  }
  while (gcd(r, n) !== ONE) {
    r = (r + ONE) % n;
    if (r <= ONE) r = THREE;
  }
  chosenRHex = bigIntToHex(r);

  const rPowE = modPow(r, e, n);
  const blinded = (m * rPowE) % n;

  return {
    blindedHex: bigIntToHex(blinded),
    rHex: chosenRHex,
  };
}

export function signBlinded(
  blindedHex: string,
  denomination: number,
  seedHex: string
): string {
  if (!CREDIT_DENOMINATIONS.includes(denomination)) {
    throw new Error(`Unsupported credit denomination: ${denomination}`);
  }
  const key = deriveFullIssuerKey(seedHex);
  const n = hexToBigInt(key.n);
  const dHex = key.dByDenom[denomination] ?? key.d;
  const d = hexToBigInt(dHex);
  const mPrime = hexToBigInt(blindedHex);
  if (mPrime <= ONE || mPrime >= n || gcd(mPrime, n) !== ONE) {
    throw new Error("Blinded message out of range or not coprime to modulus");
  }
  const sPrime = modPow(mPrime, d, n);
  return bigIntToHex(sPrime);
}

export function unblindSignature(
  blindSigHex: string,
  rHex: string,
  pub: { n: string; e: string }
): string {
  const n = hexToBigInt(pub.n);
  const sPrime = hexToBigInt(blindSigHex);
  if (sPrime <= ZERO || sPrime >= n) {
    throw new Error("Blind signature out of range");
  }
  const r = hexToBigInt(rHex) % n;
  if (r <= ONE || gcd(r, n) !== ONE) {
    throw new Error("Blinding factor r is not invertible modulo n");
  }
  const rInv = modInverse(r, n);
  const s = (sPrime * rInv) % n;
  return bigIntToHex(s);
}

export function verifyTokenSignature(
  token: BlindCreditToken,
  pub: { n: string; e: string }
): boolean {
  try {
    if (!token || !token.token || !token.signature) return false;
    if (!CREDIT_DENOMINATIONS.includes(token.denomination)) return false;
    const n = hexToBigInt(pub.n);
    const e = exponentForDenomination(token.denomination, pub.e);
    const s = hexToBigInt(token.signature);
    if (s <= ONE || s >= n) return false;

    const expected = hashTokenMessage(token.token, token.denomination, pub.n);
    const actual = modPow(s, e, n);
    return actual === expected;
  } catch {
    return false;
  }
}

export function nullifierFor(tokenHex: string): string {
  const normalized = cleanHex(tokenHex);
  return bytesToHex(
    sha256(utf8ToBytes("drouter/v1/credit-nullifier:" + normalized))
  );
}
