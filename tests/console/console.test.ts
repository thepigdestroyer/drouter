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
  prepareOutboundTurn,
  previewDraftPrivacy,
} from "@/components/console/send-pipeline";
import { exportSessionProof } from "@/components/console/proof-exporter";
import {
  openSession,
  registryAndQuorumCheck,
  type RegistryResponse,
} from "@/components/session";
import type { CheckResult, NodeRecord } from "@/lib/types";

const SAMPLE_NODE: NodeRecord = {
  id: "0x2696913aef54b88e8338ba4a362549e7c70465faa781aaa12240d20a247df29a",
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

    const suspendedNode: NodeRecord = {
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

  it("blocks session opening when C6 fails on a simulated node", async () => {
    const suspendedSimNode: NodeRecord = {
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
      nodes: [suspendedSimNode],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    await expect(
      openSession(suspendedSimNode, registry, () => {}, "sim-echo-1"),
    ).rejects.toThrow();
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
