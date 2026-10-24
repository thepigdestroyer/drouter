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

const SMALL_PRIMES = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
  79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
  163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
  241, 251,
].map((p) => BigInt(p));

const MR_BASES = [2, 3, 5, 7, 11, 13, 17, 19].map((b) => BigInt(b));

const keyCache = new Map<string, { n: string; e: string; d: string }>();

function cleanHex(hex: string): string {
  const trimmed = hex.trim().toLowerCase();
  const withoutPrefix = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  if (!withoutPrefix) return "0";
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
    if ((candidate - ONE) % RSA_E !== ZERO && isProbablePrime(candidate)) {
      return candidate;
    }
    candidate += TWO;
  }
}

export function deriveIssuerKey(seedHex: string): {
  n: string;
  e: string;
  d: string;
} {
  const normalizedSeed = cleanHex(seedHex);
  const cached = keyCache.get(normalizedSeed);
  if (cached) return cached;

  const p = deriveDeterministicPrime(normalizedSeed, "p");
  let q = deriveDeterministicPrime(normalizedSeed, "q");
  while (q === p) {
    q += TWO;
    while ((q - ONE) % RSA_E === ZERO || !isProbablePrime(q)) {
      q += TWO;
    }
  }

  const n = p * q;
  const phi = (p - ONE) * (q - ONE);
  const d = modInverse(RSA_E, phi);

  const key = {
    n: bigIntToHex(n),
    e: bigIntToHex(RSA_E),
    d: bigIntToHex(d),
  };
  keyCache.set(normalizedSeed, key);
  return key;
}

export function getPublicKey(seedHex: string): {
  n: string;
  e: string;
  denominations: number[];
} {
  const { n, e } = deriveIssuerKey(seedHex);
  return {
    n,
    e,
    denominations: [...CREDIT_DENOMINATIONS],
  };
}

export function hashTokenMessage(
  tokenHex: string,
  denomination: number,
  nHex: string
): bigint {
  const n = hexToBigInt(nHex);
  const normalizedToken = cleanHex(tokenHex);
  const ikm = utf8ToBytes(`${normalizedToken}:${denomination}`);
  const info = utf8ToBytes("drouter/v1/credit-fdh-512");
  const digest = hkdf(sha256, ikm, undefined, info, 64);
  // Ensure top bit is set so it is a 512-bit integer strictly < 1024-bit n.
  const buf = new Uint8Array(digest);
  buf[0] |= 0x80;
  let m = bytesToBigInt(buf) % n;
  if (m <= ONE) {
    m += TWO;
  }
  return m;
}

function randomBlindingFactorHex(): string {
  const bytes = new Uint8Array(64);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  bytes[0] |= 0x01;
  return bytesToHex(bytes);
}

export function blindToken(
  tokenHex: string,
  denomination: number,
  pub: { n: string; e: string },
  rHex?: string
): { blindedHex: string; rHex: string } {
  const n = hexToBigInt(pub.n);
  const e = hexToBigInt(pub.e);
  const m = hashTokenMessage(tokenHex, denomination, pub.n);

  let chosenRHex = rHex ? cleanHex(rHex) : randomBlindingFactorHex();
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
  const key = deriveIssuerKey(seedHex);
  const n = hexToBigInt(key.n);
  const d = hexToBigInt(key.d);
  const mPrime = hexToBigInt(blindedHex);
  if (mPrime <= ZERO || mPrime >= n) {
    throw new Error("Blinded message out of range");
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
  const r = hexToBigInt(rHex) % n;
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
    const e = hexToBigInt(pub.e);
    const s = hexToBigInt(token.signature);
    if (s <= ZERO || s >= n) return false;

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
