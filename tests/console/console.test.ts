import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  lockVault,
  unlockVaultWithPassphrase,
  updateVaultPayload,
} from "@/lib/auth/vault";
import {
  clearStoredCredits,
  storeCreditTokens,
  storedCreditBalance,
} from "@/lib/credits/client";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import {
  prepareHistoricalTurnText,
  prepareOutboundTurn,
  previewDraftPrivacy,
  restoreUnspentCreditHeader,
} from "@/components/console/send-pipeline";
import { exportSessionProof } from "@/components/console/proof-exporter";
import {
  describeModel,
  formatHiddenDetailsSummary,
  FRIENDLY_MODELS,
} from "@/components/console";
import {
  friendlyFailureReason,
  friendlyRuntimeError,
} from "@/components/visual-trust-dashboard";
import { friendlyCreditFlowError } from "@/components/privacy-bar";
import {
  openSession,
  pickNode,
  registryAndQuorumCheck,
  type RegistryNodeRecord,
  type RegistryResponse,
} from "@/components/session";
import type { CheckResult } from "@/lib/types";

const SAMPLE_NODE: RegistryNodeRecord = {
  id: "0x2696913aef54b88e8338ba4a362549e7c70465faa781aaa12240d20a247df29a",
  key: "tinfoil-router",
  kind: "tinfoil",
  name: "Tinfoil confidential router",
  endpoint: "inference.tinfoil.sh",
  measurement:
    "0x0cdd9e7ac27b90dcb58c7b0be92ff23b1b1092908be240a23ebbf45fb3732da0",
  operator: "0x7a5cCE3386c4D572A9C2891103250fA878838cfB",
  stake: "0.01",
  status: "active",
  region: "us",
  registeredAt: 1792851417,
  lastVerifiedAt: 1792852705,
  lastVerifiedOk: true,
};

const ALL_PASS_CHECKS: CheckResult[] = [
  { id: "C1", label: "Hardware signature chain", status: "pass", detail: "OK" },
  { id: "C2", label: "Approved software", status: "pass", detail: "OK" },
  { id: "C3", label: "HPKE key bound", status: "pass", detail: "OK" },
  { id: "C4", label: "Running code = released", status: "pass", detail: "OK" },
  { id: "C5", label: "Confidential GPUs", status: "pass", detail: "OK" },
  { id: "C6", label: "Registry admission", status: "pass", detail: "OK" },
  { id: "C7", label: "Pinned model", status: "pass", detail: "OK" },
];

describe("console send pipeline (I1 + I2 + I3)", () => {
  beforeEach(() => {
    clearStoredCredits();
    lockVault();
  });

  afterEach(() => {
    clearStoredCredits();
    lockVault();
    vi.restoreAllMocks();
  });

  it("wires preparePrompt with getActiveCustomScrubTerms and restores streamed replies", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: ["Project Helios", "Dana Reyes"],
      createdAt: 1700000000000,
    });

    const scrubber = createSessionScrubber();
    const raw =
      "Email dana.reyes@example.com about Project Helios for Dana Reyes using key sk-prod987654321.";
    const turn = await prepareOutboundTurn(raw, {
      scrubEnabled: true,
      normalizeStyle: true,
      scrubber,
    });

    expect(turn.outboundText).not.toContain("dana.reyes@example.com");
    expect(turn.outboundText).not.toContain("Project Helios");
    expect(turn.outboundText).not.toContain("Dana Reyes");
    expect(turn.outboundText).not.toContain("sk-prod987654321");

    expect(turn.report.redactions.length).toBeGreaterThanOrEqual(4);
    expect(turn.report.customTermsCount).toBe(2);
    expect(turn.report.bucketBytes).toBeGreaterThanOrEqual(4096);
    expect(turn.report.riskBefore).toBeGreaterThan(turn.report.riskAfter);
    expect(turn.creditHeader).toBeNull();
    expect(turn.report.creditAttached).toBe(false);

    // Simulate streamed model response containing placeholders
    const emailPlaceholder = turn.report.redactions.find(
      (r) => r.kind === "EMAIL",
    )?.placeholder;
    const entityPlaceholders = turn.report.redactions.filter(
      (r) => r.kind === "ENTITY",
    );
    expect(emailPlaceholder).toBeDefined();
    expect(entityPlaceholders.length).toBe(2);

    const modelStreamed = `Sent update on ${entityPlaceholders[0].placeholder} to ${entityPlaceholders[1].placeholder} at ${emailPlaceholder}.`;
    const restored = turn.restore(modelStreamed);
    expect(restored).toContain("Project Helios");
    expect(restored).toContain("Dana Reyes");
    expect(restored).toContain("dana.reyes@example.com");
  });

  it("attaches x-drouter-credit from takeCreditHeader when a token is stored and decrements balance", async () => {
    storeCreditTokens([
      {
        token: "aa".repeat(32),
        signature: "bb".repeat(64),
        denomination: 1,
      },
      {
        token: "cc".repeat(32),
        signature: "dd".repeat(64),
        denomination: 1,
      },
    ]);
    expect(storedCreditBalance()).toBe(2);

    const turn = await prepareOutboundTurn("Hello enclave", {
      scrubEnabled: true,
    });

    expect(turn.creditHeader).toBeTruthy();
    expect(turn.report.creditAttached).toBe(true);
    expect(turn.report.creditNullifier).toMatch(/^[0-9a-f]{64}$/);
    expect(turn.creditBalanceAfter).toBe(1);
    expect(storedCreditBalance()).toBe(1);
  });

  it("computes live draft preview via preparePrompt without spending credits", () => {
    storeCreditTokens([
      {
        token: "11".repeat(32),
        signature: "22".repeat(64),
        denomination: 1,
      },
    ]);
    const preview = previewDraftPrivacy(
      "Contact dana.reyes@example.com with colour preferences",
      { scrubEnabled: true, normalizeStyle: true },
    );
    expect(preview.prepared.outboundText).toContain("[EMAIL_1]");
    expect(preview.prepared.outboundText).toContain("color");
    expect(preview.prepared.report.styleChanges).toBeGreaterThanOrEqual(1);
    expect(storedCreditBalance()).toBe(1);
  });

  it("never bypasses preparePrompt even if scrubEnabled is false and prepares resumed historical turns", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: ["Secret Project Alpha"],
      createdAt: 1700000000000,
    });

    const scrubber = createSessionScrubber();
    const turn = await prepareOutboundTurn(
      "Discuss Secret Project Alpha with dana.reyes@example.com about colour",
      { scrubEnabled: false, normalizeStyle: true, scrubber },
    );
    expect(turn.outboundText).not.toContain("Secret Project Alpha");
    expect(turn.outboundText).not.toContain("dana.reyes@example.com");
    expect(turn.outboundText).toContain("color");

    const historical = prepareHistoricalTurnText(
      "Earlier note on Secret Project Alpha at 415-555-0199",
      { normalizeStyle: true, scrubber },
    );
    expect(historical).not.toContain("Secret Project Alpha");
    expect(historical).not.toContain("415-555-0199");
  });

  it("restores unspent credit header back to local wallet if turn fails before streaming", async () => {
    storeCreditTokens([
      {
        token: "ee".repeat(32),
        signature: "ff".repeat(64),
        denomination: 1,
      },
    ]);
    expect(storedCreditBalance()).toBe(1);

    const turn = await prepareOutboundTurn("Hello", { scrubEnabled: true });
    expect(turn.creditHeader).toBeTruthy();
    expect(storedCreditBalance()).toBe(0);

    const refundedBalance = restoreUnspentCreditHeader(turn.creditHeader);
    expect(refundedBalance).toBe(1);
    expect(storedCreditBalance()).toBe(1);
  });
});

describe("plain-language console helpers and jargon-free defaults", () => {
  const BANNED_JARGON = [
    "attestation",
    "attested",
    "enclave",
    "TEE",
    "SEV-SNP",
    "SNP",
    "TDX",
    "HPKE",
    "RFC",
    "Merkle",
    "nullifier",
    "RSA",
    "quorum",
    "Sigstore",
    "Rekor",
    "VCEK",
    "CKKS",
    "FHE",
    "homomorphic",
    "dm-verity",
    "measurement",
    "ciphertext",
    "hash",
    "digest",
    "ECDSA",
    "X25519",
    "PII",
    "OHTTP",
    "SPRT",
    "Arc testnet",
    "relay hop",
    "bucket bytes",
  ];

  it("formats hidden details summary in plain words", () => {
    expect(formatHiddenDetailsSummary(0)).toBe("0 personal details hidden");
    expect(formatHiddenDetailsSummary(1)).toBe("1 personal detail hidden");
    expect(formatHiddenDetailsSummary(2)).toBe("2 personal details hidden");
  });

  it("describes every model in plain words without banned jargon", () => {
    for (const model of Object.values(FRIENDLY_MODELS)) {
      const combined = `${model.name} ${model.summary}`;
      for (const word of BANNED_JARGON) {
        expect(combined.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
    const fallback = describeModel("custom-model");
    expect(fallback.summary).toContain("sealed computer");
  });

  it("produces plain-language failure reasons free of banned jargon", () => {
    const reasons = [
      friendlyFailureReason("Could not load registry", []),
      friendlyFailureReason(null, [
        { id: "C1", label: "Hardware", status: "fail", detail: "bad VCEK" },
      ]),
      friendlyFailureReason(null, [
        { id: "C2", label: "Software", status: "fail", detail: "bad digest" },
      ]),
      friendlyFailureReason(null, [
        { id: "C3", label: "Key", status: "fail", detail: "bad HPKE" },
      ]),
      friendlyFailureReason(null, [
        { id: "C5", label: "GPU", status: "fail", detail: "bad GPU" },
      ]),
      friendlyFailureReason(null, [
        { id: "C6", label: "Registry", status: "fail", detail: "suspended" },
      ]),
    ];

    for (const text of reasons) {
      for (const word of BANNED_JARGON) {
        expect(text.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
  });

  it("produces plain-language runtime and credit errors free of banned jargon", () => {
    const messages = [
      friendlyRuntimeError(
        "Not verified: C3 (HPKE key) failed: enclave digest mismatch",
      ),
      friendlyRuntimeError("Free daily allowance exhausted (402): /api/credits/invoice"),
      friendlyCreditFlowError(
        "No confirmed USDC Transfer log found on Arc testnet for RSA blind claim",
      ),
      friendlyCreditFlowError("Invoice has expired (410)"),
      friendlyCreditFlowError("Invoice has already been claimed (409)"),
    ];
    for (const text of messages) {
      for (const word of BANNED_JARGON) {
        expect(text.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
  });
});

describe("honest registry & quorum checks and failure handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("never invents quorum numbers when /api/transparency lacks verifierSet or ticket", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })),
    );

    const registry: RegistryResponse = {
      source: "arc",
      nodes: [SAMPLE_NODE],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    const c6 = await registryAndQuorumCheck(SAMPLE_NODE, registry);
    expect(c6.id).toBe("C6");
    expect(c6.detail).toContain("quorum ticket unavailable");
    expect(c6.detail).not.toContain("5/7");
  });

  it("marks C6 as fail when node is suspended or stake is below minStake", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("error", { status: 503 })),
    );

    const suspendedNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      status: "suspended",
      stake: "0",
    };
    const registry: RegistryResponse = {
      source: "arc",
      minStake: "0.01",
      nodes: [suspendedNode],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    const c6 = await registryAndQuorumCheck(suspendedNode, registry);
    expect(c6.status).toBe("fail");
    expect(c6.detail).toContain("suspended");
  });

  it("picks model-specific real Tinfoil nodes from /api/registry and rejects simulated nodes", () => {
    const kimiNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      id: "0x37c6b00064a5e5043631e41357f5500152a68198204c336745d6ba7fa0a0bb61",
      key: "tinfoil-kimi-k3",
      modelId: "kimi-k3",
      name: "Tinfoil Kimi K3 enclave",
    };
    const glmNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      id: "0x43c1bcad64147bb5f79acd628765525e02dcb7876bd5682742a5a663f49d88cd",
      key: "tinfoil-glm-5-3",
      modelId: "glm-5-3",
      name: "Tinfoil GLM-5.3 enclave",
    };

    const chosenGlm = pickNode(
      [SAMPLE_NODE, kimiNode, glmNode],
      "tinfoil",
      "glm-5-3",
    );
    expect(chosenGlm?.key).toBe("tinfoil-glm-5-3");
    expect(pickNode([SAMPLE_NODE, kimiNode, glmNode], "sim")).toBeNull();
  });

  it("blocks session opening on non-tinfoil nodes without calling /api/sim", async () => {
    const fetchSpy = vi.fn(
      async (input: RequestInfo | URL) => {
        void input;
        return new Response("error", { status: 503 });
      },
    );
    vi.stubGlobal("fetch", fetchSpy);

    const legacySimNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      kind: "sim",
      name: "Simulated node 1",
      endpoint: "/api/sim/sim-1",
      status: "suspended",
      stake: "0",
    };
    const registry: RegistryResponse = {
      source: "arc",
      minStake: "0.01",
      nodes: [legacySimNode],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    await expect(
      openSession(legacySimNode, registry, () => {}, "kimi-k3"),
    ).rejects.toThrow();

    for (const call of fetchSpy.mock.calls) {
      expect(String(call[0])).not.toContain("/api/sim");
    }
  });
});

describe("forensics proof export action", () => {
  beforeEach(() => {
    lockVault();
  });

  afterEach(() => {
    lockVault();
  });

  it("builds and offline-verifies a valid forensic proof bundle from session state", () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);

    const exported = exportSessionProof(
      {
        node: SAMPLE_NODE,
        model: "kimi-k3",
        checks: ALL_PASS_CHECKS,
        evidence: {
          "Enclave host": "router-0.tinfoil.sh",
          "Enclave fingerprint": SAMPLE_NODE.measurement,
          "Chip ID": "f901a2b3...9912ab01",
        },
        verifyAnchorUrl:
          "https://explorer.testnet.arc.io/tx/0x" + "ab".repeat(32),
      },
      { triggerDownload: false },
    );

    expect(exported.verification.valid).toBe(true);
    expect(exported.verification.digestMatches).toBe(true);
    expect(exported.verification.clientSignatureValid).toBe(true);
    expect(exported.verification.allChecksPassed).toBe(true);
    expect(exported.verification.originVerified).toBe(true);
    expect(exported.bundle.arcAnchorTx).toBe("0x" + "ab".repeat(32));
    expect(exported.filename).toMatch(/\.drouter-proof\.json$/);
  });
});
