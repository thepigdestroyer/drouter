import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  FORENSIC_PROOF_SCHEMA,
  createForensicProofBundle,
  signForensicPopReceipt,
  verifyForensicProofBundleOffline,
} from "@/lib/forensics/bundle";
import type { CheckResult, PopReceipt } from "@/lib/types";

function makePassingChecks(): CheckResult[] {
  return [
    {
      id: "C1",
      label: "Hardware TEE Quote & AMD/Intel Root Cert Chain",
      status: "pass",
      detail: "1,184-byte AMD SEV-SNP report signed by VCEK ECDSA P-384 chained to AMD ARK/ASK.",
    },
    {
      id: "C2",
      label: "Guest Policy Bitmask & TCB Floor",
      status: "pass",
      detail: "Debug=0, Migration=0, SMT=0; TCB bootloader=10, tee=0, snp=25, microcode=219.",
    },
    {
      id: "C3",
      label: "Launch Measurement Matches Reproducible Release",
      status: "pass",
      detail: "48-byte launch digest matches 0x4cf9a81e7b204d91a6c30e…",
    },
    {
      id: "C4",
      label: "Sigstore Rekor Transparency Log Inclusion Proof",
      status: "pass",
      detail: "Fulcio OIDC cert bound to GitHub Actions workflow + Rekor Merkle tree inclusion verified.",
    },
    {
      id: "C5",
      label: "Enclave Ephemeral Key Bound to Hardware REPORT_DATA",
      status: "pass",
      detail: "SHA-256(HPKE_PK || TLS_Cert) matches bytes[0..31] of hardware REPORT_DATA.",
    },
    {
      id: "C6",
      label: "On-Chain Registry Status & Slashing Collateral (Arc Testnet)",
      status: "pass",
      detail: "Node active on DRouterRegistry with 10,000 USDC staked.",
    },
    {
      id: "C7",
      label: "5-of-7 Decentralized Verifier Quorum Ticket",
      status: "pass",
      detail: "5 independent verifier signatures validated over (nodeId, chipId, measurement, epoch).",
    },
  ];
}

function makeEvidenceRegisters(): Record<string, string> {
  return {
    "Enclave host": "kimi-k2-5-1.model.tinfoil.sh",
    "Measurement type": "sev-snp-1184b",
    "Enclave fingerprint": "4cf9a81e7b204d91a6c30e882b17f53c90e1d4a782b6c3019f8e7d6c5b4a3921",
    "Chip ID":
      "859dc53c31d4838d1666c1989b492803165b91a91d2b308e1f0e38c2a0c8f7d99a01b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b878c31",
    "Guest policy": "0x30000 (Debug=0, Migration=0, SMT=0)",
    "Pinned weights": "moonshotai/Kimi-K2.5-Instruct@8f4c2e19a7b3d6054c89e12f7a0b3c5d9e8f1a2b",
    "dm-verity root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  };
}

function makeSignedPopReceipt(): PopReceipt {
  const enclaveIdentitySk = ed25519.utils.randomSecretKey();
  const sessionIdHash = bytesToHex(sha256(utf8ToBytes("session-forensic-test-01")));
  return signForensicPopReceipt(
    {
      nodeId: "0x01",
      sessionIdHash,
      time: 1760000000,
      measurement: "4cf9a81e7b204d91a6c30e882b17f53c90e1d4a782b6c3019f8e7d6c5b4a3921",
    },
    enclaveIdentitySk
  );
}

describe("Verifiable Forensic Proof Bundle Exporter & Standalone Offline Verifier", () => {
  it("creates a self-contained bundle that passes offline verification including embedded PopReceipt Ed25519 verification", () => {
    const popReceipt = makeSignedPopReceipt();
    const bundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Tinfoil Confidential Router #1",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: makeEvidenceRegisters(),
      popReceipt,
      arcAnchorTx: "0x9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
    });

    expect(bundle.schema).toBe(FORENSIC_PROOF_SCHEMA);
    expect(bundle.bundleDigestHex).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.clientSignatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(bundle.clientPublicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.cliVerifyOneLiner).toContain("node -e '");

    // Simulate saving to .drouter-proof.json and parsing back offline
    const roundTripped = JSON.parse(JSON.stringify(bundle));
    const verification = verifyForensicProofBundleOffline(roundTripped);

    expect(verification.valid).toBe(true);
    expect(verification.digestMatches).toBe(true);
    expect(verification.clientSignatureValid).toBe(true);
    expect(verification.popReceiptSignatureValid).toBe(true);
    expect(verification.allChecksPassed).toBe(true);
    expect(verification.reasons).toEqual([]);
  });

  it("detects tampering with any register in evidence", () => {
    const bundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Tinfoil Confidential Router #1",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: makeEvidenceRegisters(),
      popReceipt: makeSignedPopReceipt(),
    });

    const tampered = JSON.parse(JSON.stringify(bundle));
    tampered.evidence["Guest policy"] = "0x30001 (Debug=1)";

    const result = verifyForensicProofBundleOffline(tampered);
    expect(result.valid).toBe(false);
    expect(result.digestMatches).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it("detects tampering with any check in checks (status or detail)", () => {
    const bundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Tinfoil Confidential Router #1",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: makeEvidenceRegisters(),
      popReceipt: makeSignedPopReceipt(),
    });

    // Tamper with C2 status
    const tamperedStatus = JSON.parse(JSON.stringify(bundle));
    tamperedStatus.checks[1].status = "fail";

    const resStatus = verifyForensicProofBundleOffline(tamperedStatus);
    expect(resStatus.valid).toBe(false);
    expect(resStatus.digestMatches).toBe(false);
    expect(resStatus.allChecksPassed).toBe(false);

    // Tamper with C4 detail only
    const tamperedDetail = JSON.parse(JSON.stringify(bundle));
    tamperedDetail.checks[3].detail = "Forged Rekor entry";

    const resDetail = verifyForensicProofBundleOffline(tamperedDetail);
    expect(resDetail.valid).toBe(false);
    expect(resDetail.digestMatches).toBe(false);
  });

  it("detects tampering with any field in popReceipt", () => {
    const bundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Tinfoil Confidential Router #1",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: makeEvidenceRegisters(),
      popReceipt: makeSignedPopReceipt(),
    });

    // Tamper with popReceipt measurement
    const tamperedMeasurement = JSON.parse(JSON.stringify(bundle));
    tamperedMeasurement.popReceipt.measurement =
      "0000000000000000000000000000000000000000000000000000000000000000";

    const resMeasurement = verifyForensicProofBundleOffline(tamperedMeasurement);
    expect(resMeasurement.valid).toBe(false);
    expect(resMeasurement.digestMatches).toBe(false);
    expect(resMeasurement.popReceiptSignatureValid).toBe(false);

    // Tamper with popReceipt signature
    const tamperedSig = JSON.parse(JSON.stringify(bundle));
    tamperedSig.popReceipt.signature = "ff".repeat(64);

    const resSig = verifyForensicProofBundleOffline(tamperedSig);
    expect(resSig.valid).toBe(false);
    expect(resSig.digestMatches).toBe(false);
    expect(resSig.popReceiptSignatureValid).toBe(false);
  });

  it("reports originVerified: false when no pinned key is supplied, and verifies or rejects against a pinned expectedClientPublicKeyHex", () => {
    const clientSk = ed25519.utils.randomSecretKey();
    const clientPkHex = bytesToHex(ed25519.getPublicKey(clientSk));
    const popReceipt = makeSignedPopReceipt();

    const bundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Tinfoil Confidential Router #1",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: makeEvidenceRegisters(),
      popReceipt,
      clientSecretKey: clientSk,
    });

    // Unpinned verification: valid integrity, but originVerified is false
    const unpinned = verifyForensicProofBundleOffline(bundle);
    expect(unpinned.valid).toBe(true);
    expect(unpinned.originVerified).toBe(false);
    expect(unpinned.popOriginVerified).toBe(false);

    // Requiring pinned origin without supplying a key fails
    const strictUnpinned = verifyForensicProofBundleOffline(bundle, {
      requirePinnedOrigin: true,
    });
    expect(strictUnpinned.valid).toBe(false);
    expect(strictUnpinned.originVerified).toBe(false);

    // Pinned verification with matching keys sets originVerified: true and popOriginVerified: true
    const pinnedOk = verifyForensicProofBundleOffline(bundle, {
      expectedClientPublicKeyHex: clientPkHex,
      expectedPopSignerPublicKeyHex: popReceipt.signerPublicKey,
      requirePinnedOrigin: true,
    });
    expect(pinnedOk.valid).toBe(true);
    expect(pinnedOk.originVerified).toBe(true);
    expect(pinnedOk.popOriginVerified).toBe(true);

    // Attacker re-signs a forged bundle with their own keypair: caught by pinned key check
    const attackerSk = ed25519.utils.randomSecretKey();
    const forgedBundle = createForensicProofBundle({
      createdAt: 1760000123000,
      nodeId: "0x01",
      nodeName: "Forged Router",
      nodeKind: "tinfoil",
      modelId: "kimi-k3",
      checks: makePassingChecks(),
      evidence: { ...makeEvidenceRegisters(), "Guest policy": "0x30001 (Debug=1)" },
      popReceipt,
      clientSecretKey: attackerSk,
    });
    const pinnedForged = verifyForensicProofBundleOffline(forgedBundle, {
      expectedClientPublicKeyHex: clientPkHex,
    });
    expect(pinnedForged.valid).toBe(false);
    expect(pinnedForged.originVerified).toBe(false);
    expect(pinnedForged.reasons.some((r) => /expectedClientPublicKeyHex/i.test(r))).toBe(true);
  });
});
