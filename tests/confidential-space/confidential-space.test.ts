import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_PEM,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA1,
  GOOGLE_CONFIDENTIAL_SPACE_ROOT_CA_SHA256,
  getEmbeddedRootCaFingerprints,
  verifyConfidentialSpaceAttestation,
} from "@/lib/attestation/confidential-space";
import * as x509 from "@peculiar/x509";
import { beforeAll, describe, expect, it } from "vitest";

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

function certToDerBase64(cert: x509.X509Certificate): string {
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
  rootCert: x509.X509Certificate;
  interCert: x509.X509Certificate;
  leafCert: x509.X509Certificate;
  wrongRootCert: x509.X509Certificate;
  tlsCertPem: string;
  tlsSpkiDigest: string;
  keysDigest: string;
}

let fixture: TestChainFixture;

async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
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

    // Verify against the real Google Confidential Space Root CA (which differs from fixture.rootCert)
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
    // Sign a leaf certificate with wrongRootKeys instead of interKeys
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
    // Sign with wrongRootKeys instead of leafKeys
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

  it("fails when JWT alg is 'none' or 'HS256'", async () => {
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

  it("fails when the JWT is expired beyond the 60s clock skew", async () => {
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

  it("fails when submods.container.env_override contains a disallowed variable", async () => {
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
  });

  it("fails when eat_nonce is missing or does not match recomputed keysDigest and tlsSpkiDigest", async () => {
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
