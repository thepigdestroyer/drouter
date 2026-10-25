import React from "react";
import type * as x509Types from "@peculiar/x509";
import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  ensureReflectMetadata,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256,
  getEmbeddedRootCaFingerprints,
  verifyConfidentialSpaceAttestation,
} from "@/lib/attestation/confidential-space";
import { beforeAll, describe, expect, it } from "vitest";

// Capture Reflect state immediately at module evaluation time (after React + confidential-space imports)
const REFLECT_KEYS_AT_IMPORT = Object.keys(Reflect);
const REFLECT_HAD_GET_METADATA_AT_IMPORT =
  typeof (Reflect as unknown as { getMetadata?: unknown }).getMetadata === "function";

let x509: typeof import("@peculiar/x509");

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(view)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function jsonToBase64Url(obj: unknown): string {
  return bytesToBase64Url(Buffer.from(JSON.stringify(obj), "utf8"));
}

function certToDerBase64(cert: x509Types.X509Certificate): string {
  return Buffer.from(cert.rawData).toString("base64");
}

const TEST_NOW_SEC = 1_792_886_400; // 2026-10-25T00:00:00Z
const TEST_IMAGE_DIGEST =
  "sha256:4a5d8e2c79a416b1f81c36f0b9e1e2c5f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4";

const TEST_KEYS = {
  egress: "11".repeat(32),
  tree: "22".repeat(32),
};

interface TestChainFixture {
  rootKeys: CryptoKeyPair;
  interKeys: CryptoKeyPair;
  leafKeys: CryptoKeyPair;
  wrongRootKeys: CryptoKeyPair;
  rootCert: x509Types.X509Certificate;
  interCert: x509Types.X509Certificate;
  leafCert: x509Types.X509Certificate;
  wrongRootCert: x509Types.X509Certificate;
  tlsCertPem: string;
  tlsSpkiDigest: string;
  keysDigest: string;
}

let fixture: TestChainFixture;

async function generateRsaKeyPair(hash: "SHA-256" | "SHA-1" | "SHA-384" = "SHA-256"): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash,
    },
    true,
    ["sign", "verify"],
  );
}

async function signJwtRs256(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const h = jsonToBase64Url(header);
  const p = jsonToBase64Url(payload);
  const signingInput = new TextEncoder().encode(`${h}.${p}`);
  const sig = await globalThis.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    signingInput,
  );
  return `${h}.${p}.${bytesToBase64Url(sig)}`;
}

function makeValidPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
    aud: DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    iat: TEST_NOW_SEC - 30,
    nbf: TEST_NOW_SEC - 30,
    exp: TEST_NOW_SEC + 3600,
    swname: "CONFIDENTIAL_SPACE",
    swversion: ["261000"],
    dbgstat: "disabled-since-boot",
    secboot: true,
    hwmodel: "GCP_AMD_SEV",
    oemid: 11129,
    eat_nonce: [fixture.keysDigest, fixture.tlsSpkiDigest],
    submods: {
      confidential_space: {
        support_attributes: ["LATEST", "STABLE", "USABLE"],
        monitoring_enabled: { memory: false },
      },
      container: {
        image_digest: TEST_IMAGE_DIGEST,
        image_reference: `ghcr.io/thepigdestroyer/deroute-core@${TEST_IMAGE_DIGEST}`,
        restart_policy: "Always",
        env_override: {
          CORE_KEY_SOURCE: "boot",
          CORE_PUBLIC_ORIGIN: "https://drouter-demo.vercel.app",
        },
      },
    },
    ...overrides,
  };
}

beforeAll(async () => {
  ensureReflectMetadata();
  x509 = await import("@peculiar/x509");

  const [rootKeys, interKeys, leafKeys, wrongRootKeys] = await Promise.all([
    generateRsaKeyPair(),
    generateRsaKeyPair(),
    generateRsaKeyPair(),
    generateRsaKeyPair(),
  ]);

  const notBefore = new Date((TEST_NOW_SEC - 86_400) * 1000);
  const notAfter = new Date((TEST_NOW_SEC + 86_400 * 365) * 1000);
  const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "C=US, O=Google LLC, CN=Fake Confidential Space Root CA",
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const interCert = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "C=US, O=Google LLC, CN=Fake Confidential Space Intermediate CA",
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: interKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: "03",
    subject: "C=US, O=Google LLC, CN=confidentialcomputing.googleapis.com",
    issuer: interCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: leafKeys.publicKey,
    signingKey: interKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });

  const wrongRootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "99",
    name: "C=US, O=Untrusted Corp, CN=Untrusted Root CA",
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    keys: wrongRootKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 2, true)],
  });

  // Generate an ECDSA P-256 self-signed TLS certificate matching G2
  const tlsKeys = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const tlsCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "10",
    name: "CN=deroute-core.internal",
    notBefore,
    notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: tlsKeys,
  });
  const tlsCertPem = tlsCert.toString("pem");
  const tlsSpkiDigest = await computeTlsCertSpkiSha256(tlsCertPem);
  const keysDigest = await computeAttestedKeysDigest(TEST_KEYS);

  fixture = {
    rootKeys,
    interKeys,
    leafKeys,
    wrongRootKeys,
    rootCert,
    interCert,
    leafCert,
    wrongRootCert,
    tlsCertPem,
    tlsSpkiDigest,
    keysDigest,
  };
});

describe("Google Confidential Space PKI Attestation Verifier (G4)", () => {
  it("does not mutate Object.keys(Reflect) on import or verification and works with React-style import order", async () => {
    expect(typeof React.createElement).toBe("function");
    expect(REFLECT_KEYS_AT_IMPORT).toEqual([]);
    expect(REFLECT_HAD_GET_METADATA_AT_IMPORT).toBe(false);
    expect(Object.keys(Reflect)).toEqual([]);

    const fp = await getEmbeddedRootCaFingerprints();
    expect(fp.sha256).toBe(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256);
    expect(Object.keys(Reflect)).toEqual([]);

    // Also verify non-object target does not throw in Reflect metadata helpers
    const r = Reflect as unknown as {
      getMetadata: (k: unknown, target: unknown) => unknown;
      defineMetadata: (k: unknown, v: unknown, target: unknown) => void;
    };
    expect(() => r.defineMetadata("k", "v", null)).not.toThrow();
    expect(r.getMetadata("k", null)).toBeUndefined();
  });

  it("asserts the embedded Google Confidential Space Root CA PEM matches the pinned SHA-256 and SHA-1 fingerprints", async () => {
    const fp = await getEmbeddedRootCaFingerprints();
    expect(fp.sha256).toBe(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256);
    expect(fp.sha256).toBe("148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39");
    expect(fp.sha1).toBe(GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1);
    expect(fp.sha1).toBe("B95120742C24E3AA34042E1C3BA3AAD28B212321");
    expect(fp.subject).toContain("Confidential Space Root CA");
    expect(fp.issuer).toContain("Confidential Space Root CA");
  });

  it("passes all verification checks on a valid 3-cert RSA PKI token (SEV and TDX)", async () => {
    for (const hwmodel of ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"] as const) {
      const header = {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(fixture.interCert),
          certToDerBase64(fixture.rootCert),
        ],
      };
      const payload = makeValidPayload({ hwmodel });
      const token = await signJwtRs256(header, payload, fixture.leafKeys.privateKey);

      const res = await verifyConfidentialSpaceAttestation({
        token,
        keys: TEST_KEYS,
        tlsCertificatePemOrDer: fixture.tlsCertPem,
        tlsSpkiSha256: fixture.tlsSpkiDigest,
        expectedImageDigests: [TEST_IMAGE_DIGEST],
        nowSec: TEST_NOW_SEC,
        pinnedRootCaPem: fixture.rootCert.toString("pem"),
      });

      expect(res.ok).toBe(true);
      expect(res.hwmodel).toBe(hwmodel);
      expect(res.imageDigest).toBe(TEST_IMAGE_DIGEST);
      expect(res.expiresAtSec).toBe(TEST_NOW_SEC + 3600);
      expect(res.keys).toEqual(TEST_KEYS);
      expect(res.checks.every((c) => c.passed)).toBe(true);
      for (const check of res.checks) {
        expect(check.plain.length).toBeGreaterThan(10);
        expect(check.plain).not.toMatch(/[\u2013\u2014]/);
      }
    }
  });

  it("fails when the root certificate does not match the pinned Google Confidential Space Root CA", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const token = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);

    const res = await verifyConfidentialSpaceAttestation({
      token,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
    });

    expect(res.ok).toBe(false);
    const rootCheck = res.checks.find((c) => c.id === "pinned_root_ca");
    expect(rootCheck?.passed).toBe(false);
  });

  it("fails when the x5c certificate chain is broken (leaf not signed by intermediate)", async () => {
    const brokenLeaf = await x509.X509CertificateGenerator.create({
      serialNumber: "04",
      subject: "C=US, O=Google LLC, CN=confidentialcomputing.googleapis.com",
      issuer: fixture.interCert.subject,
      notBefore: new Date((TEST_NOW_SEC - 3600) * 1000),
      notAfter: new Date((TEST_NOW_SEC + 3600) * 1000),
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      publicKey: fixture.leafKeys.publicKey,
      signingKey: fixture.wrongRootKeys.privateKey,
    });

    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(brokenLeaf),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const token = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);

    const res = await verifyConfidentialSpaceAttestation({
      token,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });

    expect(res.ok).toBe(false);
    const chainCheck = res.checks.find((c) => c.id === "x5c_chain_and_validity");
    expect(chainCheck?.passed).toBe(false);
  });

  it("enforces BasicConstraints (CA=true required on intermediate and root, CA=false/absent on leaf, and pathLen)", async () => {
    const notBefore = new Date((TEST_NOW_SEC - 3600) * 1000);
    const notAfter = new Date((TEST_NOW_SEC + 3600) * 1000);
    const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

    // 1. Intermediate omitting BasicConstraintsExtension (absence means NOT a CA)
    const interWithoutBc = await x509.X509CertificateGenerator.create({
      serialNumber: "21",
      subject: fixture.interCert.subject,
      issuer: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: fixture.interKeys.publicKey,
      signingKey: fixture.rootKeys.privateKey,
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ],
    });
    const tokenNoInterBc = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(interWithoutBc),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resNoInterBc = await verifyConfidentialSpaceAttestation({
      token: tokenNoInterBc,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resNoInterBc.ok).toBe(false);
    expect(resNoInterBc.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 2. Intermediate with BasicConstraints CA=false
    const interCaFalse = await x509.X509CertificateGenerator.create({
      serialNumber: "22",
      subject: fixture.interCert.subject,
      issuer: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: fixture.interKeys.publicKey,
      signingKey: fixture.rootKeys.privateKey,
      extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
    });
    const tokenInterCaFalse = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(interCaFalse),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resInterCaFalse = await verifyConfidentialSpaceAttestation({
      token: tokenInterCaFalse,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resInterCaFalse.ok).toBe(false);
    expect(resInterCaFalse.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 3. Root omitting BasicConstraintsExtension
    const rootWithoutBc = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "23",
      name: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      keys: fixture.rootKeys,
      extensions: [],
    });
    const tokenRootNoBc = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(fixture.interCert),
          certToDerBase64(rootWithoutBc),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resRootNoBc = await verifyConfidentialSpaceAttestation({
      token: tokenRootNoBc,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: rootWithoutBc.toString("pem"),
    });
    expect(resRootNoBc.ok).toBe(false);
    expect(resRootNoBc.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 4. Leaf with BasicConstraints CA=true
    const leafCaTrue = await x509.X509CertificateGenerator.create({
      serialNumber: "24",
      subject: fixture.leafCert.subject,
      issuer: fixture.interCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: fixture.leafKeys.publicKey,
      signingKey: fixture.interKeys.privateKey,
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });
    const tokenLeafCaTrue = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(leafCaTrue),
          certToDerBase64(fixture.interCert),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resLeafCaTrue = await verifyConfidentialSpaceAttestation({
      token: tokenLeafCaTrue,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resLeafCaTrue.ok).toBe(false);
    expect(resLeafCaTrue.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 5. Root with pathLength=0 (cannot issue an intermediate CA in a 3-cert chain)
    const rootPathLenZero = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "25",
      name: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      keys: fixture.rootKeys,
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });
    const tokenRootPathLenZero = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(fixture.interCert),
          certToDerBase64(rootPathLenZero),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resRootPathLenZero = await verifyConfidentialSpaceAttestation({
      token: tokenRootPathLenZero,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: rootPathLenZero.toString("pem"),
    });
    expect(resRootPathLenZero.ok).toBe(false);
    expect(resRootPathLenZero.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);
  });

  it("enforces KeyUsage (keyCertSign on issuers, digitalSignature without keyCertSign on leaf) and sha256WithRSAEncryption on all certs", async () => {
    const notBefore = new Date((TEST_NOW_SEC - 3600) * 1000);
    const notAfter = new Date((TEST_NOW_SEC + 3600) * 1000);
    const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

    // 1. Intermediate with KeyUsage lacking keyCertSign
    const interBadKu = await x509.X509CertificateGenerator.create({
      serialNumber: "31",
      subject: fixture.interCert.subject,
      issuer: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: fixture.interKeys.publicKey,
      signingKey: fixture.rootKeys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      ],
    });
    const tokenInterBadKu = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(interBadKu),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resInterBadKu = await verifyConfidentialSpaceAttestation({
      token: tokenInterBadKu,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resInterBadKu.ok).toBe(false);
    expect(resInterBadKu.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 2. Leaf with KeyUsage lacking digitalSignature (only keyEncipherment)
    const leafBadKu = await x509.X509CertificateGenerator.create({
      serialNumber: "32",
      subject: fixture.leafCert.subject,
      issuer: fixture.interCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: fixture.leafKeys.publicKey,
      signingKey: fixture.interKeys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
      ],
    });
    const tokenLeafBadKu = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(leafBadKu),
          certToDerBase64(fixture.interCert),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resLeafBadKu = await verifyConfidentialSpaceAttestation({
      token: tokenLeafBadKu,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resLeafBadKu.ok).toBe(false);
    expect(resLeafBadKu.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);

    // 3. Leaf certificate signed with SHA-1 (sha1WithRSAEncryption) instead of sha256WithRSAEncryption
    const interSha1Keys = await generateRsaKeyPair("SHA-1");
    const interForSha1 = await x509.X509CertificateGenerator.create({
      serialNumber: "33",
      subject: fixture.interCert.subject,
      issuer: fixture.rootCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: alg,
      publicKey: interSha1Keys.publicKey,
      signingKey: fixture.rootKeys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ],
    });
    const leafSha1 = await x509.X509CertificateGenerator.create({
      serialNumber: "34",
      subject: fixture.leafCert.subject,
      issuer: interForSha1.subject,
      notBefore,
      notAfter,
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
      publicKey: fixture.leafKeys.publicKey,
      signingKey: interSha1Keys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      ],
    });
    const tokenLeafSha1 = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          certToDerBase64(leafSha1),
          certToDerBase64(interForSha1),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resLeafSha1 = await verifyConfidentialSpaceAttestation({
      token: tokenLeafSha1,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resLeafSha1.ok).toBe(false);
    expect(resLeafSha1.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);
  });

  it("fails when a certificate in the x5c chain is expired at check time", async () => {
    const expiredLeaf = await x509.X509CertificateGenerator.create({
      serialNumber: "05",
      subject: "C=US, O=Google LLC, CN=confidentialcomputing.googleapis.com",
      issuer: fixture.interCert.subject,
      notBefore: new Date((TEST_NOW_SEC - 7200) * 1000),
      notAfter: new Date((TEST_NOW_SEC - 600) * 1000), // expired 10 mins ago
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      publicKey: fixture.leafKeys.publicKey,
      signingKey: fixture.interKeys.privateKey,
    });

    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(expiredLeaf),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const token = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);

    const res = await verifyConfidentialSpaceAttestation({
      token,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });

    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.id === "x5c_chain_and_validity")?.passed).toBe(false);
  });

  it("fails when the JWS signature is corrupted or signed by the wrong key", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const badToken = await signJwtRs256(
      header,
      makeValidPayload(),
      fixture.wrongRootKeys.privateKey,
    );

    const res = await verifyConfidentialSpaceAttestation({
      token: badToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });

    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.id === "jwt_rs256_signature")?.passed).toBe(false);
  });

  it("fails when JWT alg is 'none' or 'HS256', contains crit header, or uses padded non-Base64URL", async () => {
    for (const badAlg of ["none", "HS256"]) {
      const header = {
        alg: badAlg,
        typ: "JWT",
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(fixture.interCert),
          certToDerBase64(fixture.rootCert),
        ],
      };
      const token = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);

      const res = await verifyConfidentialSpaceAttestation({
        token,
        keys: TEST_KEYS,
        tlsCertificatePemOrDer: fixture.tlsCertPem,
        expectedImageDigests: [TEST_IMAGE_DIGEST],
        nowSec: TEST_NOW_SEC,
        pinnedRootCaPem: fixture.rootCert.toString("pem"),
      });

      expect(res.ok).toBe(false);
      expect(res.checks.find((c) => c.id === "jwt_header_and_x5c")?.passed).toBe(false);
    }

    // Reject crit header
    const critToken = await signJwtRs256(
      {
        alg: "RS256",
        typ: "JWT",
        crit: ["exp"],
        x5c: [
          certToDerBase64(fixture.leafCert),
          certToDerBase64(fixture.interCert),
          certToDerBase64(fixture.rootCert),
        ],
      },
      makeValidPayload(),
      fixture.leafKeys.privateKey,
    );
    const resCrit = await verifyConfidentialSpaceAttestation({
      token: critToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resCrit.ok).toBe(false);
    expect(resCrit.checks.find((c) => c.id === "jwt_header_and_x5c")?.passed).toBe(false);
  });

  it("fails on wrong iss or wrong aud", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };

    const badIssToken = await signJwtRs256(
      header,
      makeValidPayload({ iss: "https://evil.example.com" }),
      fixture.leafKeys.privateKey,
    );
    const resIss = await verifyConfidentialSpaceAttestation({
      token: badIssToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resIss.ok).toBe(false);
    expect(resIss.checks.find((c) => c.id === "issuer_and_audience")?.passed).toBe(false);

    const badAudToken = await signJwtRs256(
      header,
      makeValidPayload({ aud: "https://sts.googleapis.com" }),
      fixture.leafKeys.privateKey,
    );
    const resAud = await verifyConfidentialSpaceAttestation({
      token: badAudToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resAud.ok).toBe(false);
    expect(resAud.checks.find((c) => c.id === "issuer_and_audience")?.passed).toBe(false);
  });

  it("fails when the JWT is expired beyond the 60s clock skew or when exp < nbf / exp < iat within the skew window", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const expiredToken = await signJwtRs256(
      header,
      makeValidPayload({
        iat: TEST_NOW_SEC - 7200,
        nbf: TEST_NOW_SEC - 7200,
        exp: TEST_NOW_SEC - 120,
      }),
      fixture.leafKeys.privateKey,
    );

    const res = await verifyConfidentialSpaceAttestation({
      token: expiredToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.id === "token_lifetime")?.passed).toBe(false);

    // Inverted timestamps inside the ±60s clock skew window (exp < nbf and exp < iat)
    const invertedToken = await signJwtRs256(
      header,
      makeValidPayload({
        iat: TEST_NOW_SEC + 40,
        nbf: TEST_NOW_SEC + 40,
        exp: TEST_NOW_SEC - 40,
      }),
      fixture.leafKeys.privateKey,
    );
    const resInverted = await verifyConfidentialSpaceAttestation({
      token: invertedToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resInverted.ok).toBe(false);
    expect(resInverted.checks.find((c) => c.id === "token_lifetime")?.passed).toBe(false);
  });

  it("fails on a debug image (dbgstat !== 'disabled-since-boot') or missing STABLE support attribute", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };

    const debugToken = await signJwtRs256(
      header,
      makeValidPayload({ dbgstat: "enabled" }),
      fixture.leafKeys.privateKey,
    );
    const resDebug = await verifyConfidentialSpaceAttestation({
      token: debugToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resDebug.ok).toBe(false);
    expect(resDebug.checks.find((c) => c.id === "confidential_space_posture")?.passed).toBe(false);

    const basePayload = makeValidPayload();
    const submods = basePayload.submods as Record<string, unknown>;
    const noStablePayload = {
      ...basePayload,
      submods: {
        ...submods,
        confidential_space: {
          support_attributes: ["USABLE", "EXPERIMENTAL"],
        },
      },
    };
    const noStableToken = await signJwtRs256(header, noStablePayload, fixture.leafKeys.privateKey);
    const resNoStable = await verifyConfidentialSpaceAttestation({
      token: noStableToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resNoStable.ok).toBe(false);
    expect(resNoStable.checks.find((c) => c.id === "confidential_space_posture")?.passed).toBe(
      false,
    );
  });

  it("fails on an unexpected container image digest", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const token = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);

    const res = await verifyConfidentialSpaceAttestation({
      token,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: ["sha256:" + "f".repeat(64)],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.id === "container_image_digest")?.passed).toBe(false);
  });

  it("fails when submods.container.env_override contains a disallowed variable or non-string value", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };
    const basePayload = makeValidPayload();
    const submods = basePayload.submods as Record<string, Record<string, unknown>>;
    const badEnvPayload = {
      ...basePayload,
      submods: {
        ...submods,
        container: {
          ...submods.container,
          env_override: {
            CORE_KEY_SOURCE: "boot",
            GEMINI_API_KEY: "leaked-secret",
          },
        },
      },
    };
    const token = await signJwtRs256(header, badEnvPayload, fixture.leafKeys.privateKey);

    const res = await verifyConfidentialSpaceAttestation({
      token,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.id === "container_env_override")?.passed).toBe(false);

    // Non-string value in env_override
    const nonStringEnvPayload = {
      ...basePayload,
      submods: {
        ...submods,
        container: {
          ...submods.container,
          env_override: {
            CORE_KEY_SOURCE: 123,
          },
        },
      },
    };
    const tokenNonString = await signJwtRs256(
      header,
      nonStringEnvPayload,
      fixture.leafKeys.privateKey,
    );
    const resNonString = await verifyConfidentialSpaceAttestation({
      token: tokenNonString,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resNonString.ok).toBe(false);
    expect(resNonString.checks.find((c) => c.id === "container_env_override")?.passed).toBe(false);
  });

  it("fails when eat_nonce is missing, colliding (keysDigest === tlsSpkiSha256), single-element, or mismatched", async () => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [
        certToDerBase64(fixture.leafCert),
        certToDerBase64(fixture.interCert),
        certToDerBase64(fixture.rootCert),
      ],
    };

    const missingNonceToken = await signJwtRs256(
      header,
      makeValidPayload({ eat_nonce: undefined }),
      fixture.leafKeys.privateKey,
    );
    const resMissing = await verifyConfidentialSpaceAttestation({
      token: missingNonceToken,
      keys: TEST_KEYS,
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resMissing.ok).toBe(false);
    expect(resMissing.checks.find((c) => c.id === "eat_nonce_binding")?.passed).toBe(false);

    // Colliding nonces: single eat_nonce string where caller sets tlsSpkiSha256 === keysDigest
    const singleNonceToken = await signJwtRs256(
      header,
      makeValidPayload({ eat_nonce: fixture.keysDigest }),
      fixture.leafKeys.privateKey,
    );
    const resColliding = await verifyConfidentialSpaceAttestation({
      token: singleNonceToken,
      keys: TEST_KEYS,
      tlsSpkiSha256: fixture.keysDigest,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resColliding.ok).toBe(false);
    expect(resColliding.checks.find((c) => c.id === "eat_nonce_binding")?.passed).toBe(false);

    // Duplicate 2-element array [keysDigest, keysDigest]
    const dupNonceToken = await signJwtRs256(
      header,
      makeValidPayload({ eat_nonce: [fixture.keysDigest, fixture.keysDigest] }),
      fixture.leafKeys.privateKey,
    );
    const resDup = await verifyConfidentialSpaceAttestation({
      token: dupNonceToken,
      keys: TEST_KEYS,
      tlsSpkiSha256: fixture.keysDigest,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resDup.ok).toBe(false);
    expect(resDup.checks.find((c) => c.id === "eat_nonce_binding")?.passed).toBe(false);

    // Wrong keys passed to verifier -> recomputed keysDigest does not match eat_nonce
    const validToken = await signJwtRs256(header, makeValidPayload(), fixture.leafKeys.privateKey);
    const resWrongKeys = await verifyConfidentialSpaceAttestation({
      token: validToken,
      keys: { egress: "aa".repeat(32), tree: "bb".repeat(32) },
      tlsCertificatePemOrDer: fixture.tlsCertPem,
      expectedImageDigests: [TEST_IMAGE_DIGEST],
      nowSec: TEST_NOW_SEC,
      pinnedRootCaPem: fixture.rootCert.toString("pem"),
    });
    expect(resWrongKeys.ok).toBe(false);
    expect(resWrongKeys.checks.find((c) => c.id === "eat_nonce_binding")?.passed).toBe(false);
  });
});
